//! Compact PE file layout for editable images: structural invariants (headers, `SizeOfRawData`,
//! `PointerToRawData`, `VirtualSize`, `FileAlignment`), file sizes on small and large fixtures,
//! and incremental edits within raw slack, past a section's raw size (both tail `.bpatch` and
//! middle sections `.bdatap`/`.pdata`/`.reloc`), and past a section's virtual size (full
//! relink), each checked against a fresh link of the edited program.

use blaze_codegen::{
    Arch, CompiledFunction, Init, InstanceKey, RelocKind, Relocs, Static, Target, Unwind,
};
use blaze_ids::ContentId;
use blaze_items::ItemKey;
use object::LittleEndian as LE;
use object::pe;
use object::read::pe::{ImageNtHeaders as _, ImageOptionalHeader as _, PeFile64};

use super::{Change, Image, name};
use crate::digest::Digest;
use crate::{Debug, Format, LinkArgs, Output, OutputKind, Patch};

const TO: &str = "out/app.exe";
const PAGE: u32 = 0x1000;

fn pe_output(incremental: bool) -> Output {
    Output {
        format: Format::Pe,
        arch: Arch::X86_64,
        kind: OutputKind::Executable { entry: "mainCRTStartup".into() },
        interpreter: None,
        platform: None,
        incremental,
        debug: Debug::None,
        live: None,
        tags: 1 << 32,
        stack: None,
        windows_subsystem: false,
        dev_run: None,
        triple: "x86_64-pc-windows-msvc".into(),
        exec_log: false,
        sanitize: blaze_codegen::settings::Sanitize::default(),
        rpaths: Vec::new(),
        link: LinkArgs::default(),
    }
}

fn key_of(id: u32, version: u32, pad: usize) -> InstanceKey {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&id.to_le_bytes());
    bytes[4..8].copy_from_slice(&version.to_le_bytes());
    bytes[8..16].copy_from_slice(&(pad as u64).to_le_bytes());
    InstanceKey(ContentId(bytes))
}

fn static_target(id: u32) -> Target {
    let mut item = [0u8; 32];
    let mut inst = [0u8; 32];
    item[..4].copy_from_slice(&id.to_le_bytes());
    item[31] = 0x51;
    inst[..4].copy_from_slice(&id.to_le_bytes());
    inst[31] = 0x52;
    Target::Static { item: ItemKey(ContentId(item)), instance: ContentId(inst) }
}

fn static_item_inst(id: u32) -> (ItemKey, ContentId) {
    let Target::Static { item, instance } = static_target(id) else { unreachable!() };
    (item, instance)
}

fn make_static(id: u32, bytes: Vec<u8>, mutable: bool) -> Static {
    let (item, instance) = static_item_inst(id);
    Static {
        item,
        instance,
        align: 8,
        init: Init::Bytes { bytes, relocs: Relocs::new() },
        data: Vec::new(),
        mutable,
        thread_local: false,
        section: None,
        imports: Vec::new(),
    }
}

fn make_zero_static(id: u32, size: u64) -> Static {
    let (item, instance) = static_item_inst(id);
    Static {
        item,
        instance,
        align: 16,
        init: Init::Zeroed { size },
        data: Vec::new(),
        mutable: true,
        thread_local: false,
        section: None,
        imports: Vec::new(),
    }
}

fn rel32(at: u32, target: Target) -> blaze_codegen::Relocation {
    blaze_codegen::Relocation { at, kind: RelocKind::PcRel32, target, addend: -4 }
}

/// A function calling `callee` (through its jump-table slot) if given, optionally loading
/// `reads` (a static), returning `version`, padded with `pad` NOPs, with Windows SEH unwind
/// info so `.pdata` tracks every function.
fn make_fn(
    id: u32,
    version: u32,
    callee: Option<InstanceKey>,
    reads: Option<u32>,
    pad: usize,
) -> CompiledFunction {
    let mut code = Vec::with_capacity(32 + pad);
    let mut relocs = Vec::new();
    if let Some(callee) = callee {
        relocs.push(rel32(code.len() as u32 + 1, Target::Function(callee)));
        code.extend_from_slice(&[0xe8, 0, 0, 0, 0]);
    }
    if let Some(static_id) = reads {
        relocs.push(rel32(code.len() as u32 + 3, static_target(static_id)));
        code.extend_from_slice(&[0x48, 0x8d, 0x05, 0, 0, 0, 0]);
    }
    code.push(0xb8);
    code.extend_from_slice(&version.to_le_bytes());
    code.push(0xc3);
    code.resize(code.len() + pad, 0x90);
    CompiledFunction {
        key: key_of(id, version, pad),
        arch: Arch::X86_64,
        align: 16,
        code,
        relocs: relocs.into(),
        data: Vec::new(),
        inlined: Vec::new(),
        side: None,
        unwind: Some(Unwind::Windows { info: vec![1, 0, 0, 0], handler: None, lsda: None }),
        lines: Vec::new(),
        coverage: None,
        profile: None,
    }
}

/// Checks every structural PE invariant of a compact (non-dev-run) PE32+ image.
fn check_pe_structure(bytes: &[u8]) {
    let file = PeFile64::parse(bytes).expect("valid PE32+ image");
    let optional = file.nt_headers().optional_header();
    let sec_align = optional.section_alignment();
    let file_align = optional.file_alignment();
    let headers = optional.size_of_headers();
    assert_eq!(sec_align, PAGE, "SectionAlignment");
    assert_eq!(file_align, PAGE, "FileAlignment");
    assert_eq!(headers % file_align, 0, "SizeOfHeaders aligned to FileAlignment");
    assert!(headers >= PAGE);

    let sections = file.section_table();
    assert!(!sections.is_empty(), "at least one section");

    let mut cursor = headers;
    let mut prev_va_end = headers;
    let mut code = 0u64;
    let mut init_data = 0u64;
    let mut uninit_data = 0u64;

    for section in sections.iter() {
        let name = String::from_utf8_lossy(&section.name).trim_end_matches('\0').to_owned();
        let va = section.virtual_address.get(LE);
        let vsize = section.virtual_size.get(LE);
        let raw = section.size_of_raw_data.get(LE);
        let ptr = section.pointer_to_raw_data.get(LE);
        let flags = section.characteristics.get(LE).0;

        assert_eq!(va % sec_align, 0, "{name}: VirtualAddress {va:#x} not aligned");
        assert!(va >= prev_va_end, "{name}: VirtualAddress {va:#x} overlaps previous {prev_va_end:#x}");
        assert!(vsize > 0, "{name}: empty VirtualSize");
        assert_eq!(raw % file_align, 0, "{name}: SizeOfRawData {raw:#x} not FileAlignment-aligned");
        assert_eq!(ptr % file_align, 0, "{name}: PointerToRawData {ptr:#x} not FileAlignment-aligned");

        let v_aligned = vsize.next_multiple_of(sec_align);
        assert!(
            raw <= v_aligned,
            "{name}: SizeOfRawData {raw:#x} exceeds page-aligned VirtualSize {v_aligned:#x}"
        );
        if raw > 0 {
            assert_eq!(
                ptr, cursor,
                "{name}: PointerToRawData {ptr:#x} is not packed right after previous end {cursor:#x}"
            );
            assert!(
                (ptr as usize) + (raw as usize) <= bytes.len(),
                "{name}: raw range {ptr:#x}..+{raw:#x} past EOF {:#x}",
                bytes.len()
            );
            cursor += raw;
        } else {
            assert_eq!(ptr, 0, "{name}: SizeOfRawData is 0 so PointerToRawData must be 0");
        }
        prev_va_end = va + v_aligned;

        if flags & pe::IMAGE_SCN_MEM_EXECUTE.0 != 0 {
            code += u64::from(raw);
        } else if raw > 0 {
            init_data += u64::from(raw);
        } else {
            uninit_data += u64::from(v_aligned);
        }
    }

    assert_eq!(bytes.len() as u32, cursor, "file length equals packed end of raw sections");
    assert_eq!(optional.size_of_image(), prev_va_end, "SizeOfImage matches last section end");
    assert_eq!(u64::from(optional.size_of_code()), code, "SizeOfCode");
    assert_eq!(u64::from(optional.size_of_initialized_data()), init_data, "SizeOfInitializedData");
    assert_eq!(
        u64::from(optional.size_of_uninitialized_data()),
        uninit_data,
        "SizeOfUninitializedData"
    );

    // Every non-empty data directory lies within a section's virtual range, and the CodeView
    // debug entry's PointerToRawData points at `RSDS` in the file.
    if let Some(dir) = file.data_directory(pe::IMAGE_DIRECTORY_ENTRY_DEBUG) {
        let (rva, size) = (dir.virtual_address.get(LE), dir.size.get(LE));
        if size > 0 {
            assert_eq!(size, 28);
            let entry = rva_bytes(&file, bytes, rva, 28);
            let raw_ptr = u32::from_le_bytes(entry[24..28].try_into().unwrap()) as usize;
            assert_eq!(
                &bytes[raw_ptr..raw_ptr + 4],
                b"RSDS",
                "IMAGE_DEBUG_DIRECTORY.PointerToRawData ({raw_ptr:#x}) points at RSDS"
            );
        }
    }
}

/// Reads `len` bytes at `rva` as the NT loader maps the image (file bytes up to `SizeOfRawData`,
/// zero-filled beyond it up to `VirtualSize`).
fn rva_bytes(file: &PeFile64<'_>, image: &[u8], rva: u32, len: usize) -> Vec<u8> {
    let section = file
        .section_table()
        .iter()
        .find(|it| {
            let va = it.virtual_address.get(LE);
            let span = it.virtual_size.get(LE).max(it.size_of_raw_data.get(LE));
            rva >= va && (rva - va) as usize + len <= span as usize
        })
        .unwrap_or_else(|| panic!("RVA {rva:#x}+{len:#x} is in no section"));
    let within = (rva - section.virtual_address.get(LE)) as usize;
    let raw_size = section.size_of_raw_data.get(LE) as usize;
    let raw_at = section.pointer_to_raw_data.get(LE) as usize;
    let mut out = vec![0u8; len];
    if raw_size > 0 && within < raw_size {
        let take = (raw_size - within).min(len);
        out[..take].copy_from_slice(&image[raw_at + within..raw_at + within + take]);
    }
    out
}

fn rva_u32(file: &PeFile64<'_>, image: &[u8], rva: u32) -> u32 {
    u32::from_le_bytes(rva_bytes(file, image, rva, 4).try_into().unwrap())
}

fn rva_u64(file: &PeFile64<'_>, image: &[u8], rva: u32) -> u64 {
    u64::from_le_bytes(rva_bytes(file, image, rva, 8).try_into().unwrap())
}

/// Follows a `call rel32` at `call_rva` (pointing at the `0xe8` opcode): if it targets a
/// jump-table stub (`ff 25 rel32`, `jmp [rip + cell]`), dereferences the cell and returns the
/// target body's RVA; otherwise returns the direct target RVA.
fn resolve_call(file: &PeFile64<'_>, image: &[u8], call_rva: u32) -> u32 {
    let base = file.nt_headers().optional_header().image_base();
    assert_eq!(rva_bytes(file, image, call_rva, 1)[0], 0xe8, "call opcode at {call_rva:#x}");
    let disp = rva_u32(file, image, call_rva + 1) as i32;
    let target = (call_rva as i64 + 5 + i64::from(disp)) as u32;
    let head = rva_bytes(file, image, target, 6);
    if head[0] == 0xff && head[1] == 0x25 {
        let cell_disp = i32::from_le_bytes(head[2..6].try_into().unwrap());
        let cell_rva = (target as i64 + 6 + i64::from(cell_disp)) as u32;
        let dest = rva_u64(file, image, cell_rva);
        (dest - base) as u32
    } else {
        target
    }
}

/// Follows `lea rax, [rip + disp32]` at `lea_rva` (`48 8d 05 disp32`) and reads `len` bytes.
fn resolve_lea_bytes(file: &PeFile64<'_>, image: &[u8], lea_rva: u32, len: usize) -> Vec<u8> {
    let head = rva_bytes(file, image, lea_rva, 7);
    assert_eq!(&head[..3], &[0x48, 0x8d, 0x05], "lea opcode at {lea_rva:#x}");
    let disp = i32::from_le_bytes(head[3..7].try_into().unwrap());
    let target = (lea_rva as i64 + 7 + i64::from(disp)) as u32;
    rva_bytes(file, image, target, len)
}

/// Every `(begin_rva, end_rva)` entry in the exception directory (`.pdata`).
fn pdata_entries(file: &PeFile64<'_>, image: &[u8]) -> Vec<(u32, u32)> {
    let Some(dir) = file.data_directory(pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION) else {
        return Vec::new();
    };
    let (rva, size) = (dir.virtual_address.get(LE), dir.size.get(LE));
    if size == 0 {
        return Vec::new();
    }
    assert_eq!(size % 12, 0);
    let raw = rva_bytes(file, image, rva, size as usize);
    let entries: Vec<(u32, u32)> = raw
        .chunks_exact(12)
        .map(|it| {
            (
                u32::from_le_bytes(it[0..4].try_into().unwrap()),
                u32::from_le_bytes(it[4..8].try_into().unwrap()),
            )
        })
        .collect();
    assert!(entries.windows(2).all(|w| w[0].1 <= w[1].0), ".pdata entries must be sorted and non-overlapping");
    entries
}

/// Semantic snapshot of a linked two-function PE program (`entry` calling `callee` which reads
/// `static_len` bytes of static data): independent of section offsets or patch placement, so
/// an edited image can be compared directly against a fresh link of the edited program.
#[derive(PartialEq, Eq, Debug)]
struct Observed {
    entry_code: Vec<u8>,
    callee_code: Vec<u8>,
    static_data: Vec<u8>,
    entry_pdata_len: Option<u32>,
    callee_pdata_len: Option<u32>,
    pdata_count: usize,
}

fn observe(image: &[u8], entry_len: usize, callee_len: usize, static_len: usize) -> Observed {
    let file = PeFile64::parse(image).expect("valid PE");
    let entry_rva = file.nt_headers().optional_header().address_of_entry_point();
    let callee_rva = resolve_call(&file, image, entry_rva);
    let mut entry_code = rva_bytes(&file, image, entry_rva, entry_len);
    entry_code[1..5].fill(0);
    let mut callee_code = rva_bytes(&file, image, callee_rva, callee_len);
    let static_data = if static_len > 0 {
        let bytes = resolve_lea_bytes(&file, image, callee_rva, static_len);
        callee_code[3..7].fill(0);
        bytes
    } else {
        Vec::new()
    };
    let entries = pdata_entries(&file, image);
    let pdata_len = |rva: u32| {
        entries.iter().find(|it| it.0 == rva).map(|it| it.1 - it.0)
    };
    Observed {
        entry_code,
        callee_code,
        static_data,
        entry_pdata_len: pdata_len(entry_rva),
        callee_pdata_len: pdata_len(callee_rva),
        pdata_count: entries.len(),
    }
}

fn section_by_name<'a>(file: &'a PeFile64<'a>, want: &str) -> Option<&'a pe::ImageSectionHeader> {
    file.section_table()
        .iter()
        .find(|it| String::from_utf8_lossy(&it.name).trim_end_matches('\0') == want)
}

fn apply_checked(image: &mut Image, staged: crate::Staged, file: &mut Vec<u8>) -> Patch {
    let expected_bytes = {
        // Verify patch result against `Digest::of` and structural PE validity.
        let patch = image.patch(staged).expect("patch");
        patch.apply(file);
        assert_eq!(file.len() as u64, patch.len, "patched file length matches patch.len");
        assert_eq!(Digest::of(file).root(), patch.digest, "Digest::of(patched) == patch.digest");
        check_pe_structure(file);
        patch
    };
    expected_bytes
}

#[test]
fn large_editable_pe_slack_costs_virtual_space_not_disk_bytes() {
    // 2 MiB of code, 1 MiB of rodata, 1 MiB of zero-initialized .bss:
    // virtual slack (.bpatch >= 2 MiB, .bdatap >= 2 MiB, .bss = 1 MiB) totals > 5 MiB,
    // while actual used file bytes are ~3 MiB.
    let entry = make_fn(1, 1, Some(key_of(2, 1, 2 << 20)), None, 0);
    let big_fn = make_fn(2, 1, None, Some(10), 2 << 20);
    let ro = make_static(10, vec![0x5a; 1 << 20], false);
    let bss = make_zero_static(11, 1 << 20);
    let entry2 = make_fn(3, 1, None, Some(11), 0);

    let mut image = Image::new(name(TO), pe_output(true)).unwrap();
    let staged = image
        .stage(Change {
            added: vec![&entry, &big_fn, &entry2],
            statics: vec![&ro, &bss],
            names: vec![("mainCRTStartup".into(), Target::Direct(entry.key))],
            debug_names: vec![
                (entry.key, "mainCRTStartup".into()),
                (big_fn.key, "big_fn".into()),
                (entry2.key, "uses_bss".into()),
            ],
            ..Change::default()
        })
        .unwrap();
    let bytes = image.bytes(staged).unwrap();
    check_pe_structure(&bytes);

    let file = PeFile64::parse(&bytes[..]).unwrap();
    let optional = file.nt_headers().optional_header();
    let bpatch = section_by_name(&file, ".bpatch").expect(".bpatch section");
    let bdatap = section_by_name(&file, ".bdatap").expect(".bdatap section");
    let data = section_by_name(&file, ".data").expect(".data section");

    assert!(bpatch.virtual_size.get(LE) >= (2 << 20), "virtual patch room for 2 MiB code");
    assert_eq!(bpatch.size_of_raw_data.get(LE), 0, "unused .bpatch costs 0 bytes on disk");
    assert_eq!(bpatch.pointer_to_raw_data.get(LE), 0);

    assert!(bdatap.virtual_size.get(LE) >= (2 << 20), "virtual patch data room for 2 MiB data");
    assert_eq!(bdatap.size_of_raw_data.get(LE), 0, "unused .bdatap costs 0 bytes on disk");
    assert_eq!(bdatap.pointer_to_raw_data.get(LE), 0);

    assert!(data.virtual_size.get(LE) >= (1 << 20), ".data virtual size includes 1 MiB .bss");
    assert!(data.size_of_raw_data.get(LE) <= 16 << 10, ".bss takes no raw bytes in .data");

    assert!(
        optional.size_of_image() >= (8 << 20),
        "virtual image carries > 8 MiB ({:#x})",
        optional.size_of_image()
    );
    assert!(
        bytes.len() < (3 << 20) + (256 << 10),
        "compact file should be ~3.1 MiB, got {} bytes",
        bytes.len()
    );
}

#[test]
fn small_incremental_pe_is_compact_compared_to_virtual_size() {
    let f1 = make_fn(1, 1, Some(key_of(2, 1, 0)), None, 0);
    let f2 = make_fn(2, 1, None, None, 0);
    let mut image = Image::new(name(TO), pe_output(true)).unwrap();
    let staged = image
        .stage(Change {
            added: vec![&f1, &f2],
            names: vec![("mainCRTStartup".into(), Target::Direct(f1.key))],
            ..Change::default()
        })
        .unwrap();
    let bytes = image.bytes(staged).unwrap();
    check_pe_structure(&bytes);

    let file = PeFile64::parse(&bytes[..]).unwrap();
    assert!(
        bytes.len() <= 64 << 10,
        "tiny incremental PE should be <= 64 KiB on disk, got {} bytes",
        bytes.len()
    );
    assert!(
        file.nt_headers().optional_header().size_of_image() >= 256 << 10,
        "virtual image still carries growth room"
    );
}

#[test]
fn pe_edits_within_slack_past_raw_and_past_virtual_match_fresh_links() {
    // Base image with a 128 KiB padding function so `.text` is substantial (and `.bpatch` has
    // >= 128 KiB of virtual room) while we test small patch writes vs the base image size.
    let anchor = make_fn(100, 1, None, None, 128 << 10);
    let mut data_val = make_static(1, vec![0x11; 16], true);
    let f_callee_1 = make_fn(2, 1, None, Some(1), 0);
    let f_entry = make_fn(1, 1, Some(f_callee_1.key), None, 0);

    let fresh_link = |callee: &CompiledFunction,
                      extra_fns: &[CompiledFunction],
                      st: &Static|
     -> Vec<u8> {
        let entry = make_fn(1, 1, Some(callee.key), None, 0);
        let mut img = Image::new(name(TO), pe_output(true)).unwrap();
        let mut added = vec![&entry, callee, &anchor];
        added.extend(extra_fns.iter());
        let staged = img
            .stage(Change {
                added,
                statics: vec![st],
                names: vec![("mainCRTStartup".into(), Target::Direct(entry.key))],
                ..Change::default()
            })
            .unwrap();
        let bytes = img.bytes(staged).unwrap();
        check_pe_structure(&bytes);
        bytes
    };

    let mut image = Image::new(name(TO), pe_output(true)).unwrap();
    let mut file = Vec::new();
    let staged = image
        .stage(Change {
            added: vec![&f_entry, &f_callee_1, &anchor],
            statics: vec![&data_val],
            names: vec![("mainCRTStartup".into(), Target::Direct(f_entry.key))],
            ..Change::default()
        })
        .unwrap();
    let p0 = apply_checked(&mut image, staged, &mut file);
    assert!(p0.full);
    assert_eq!(
        observe(&file, f_entry.code.len(), f_callee_1.code.len(), 16),
        observe(&fresh_link(&f_callee_1, &[], &data_val), f_entry.code.len(), f_callee_1.code.len(), 16)
    );

    // 1. Edit 1 puts `f_callee_2` into `.bpatch` (0 -> 4 KiB raw); Edit 2 grows it within
    //    that same 4 KiB raw page (`SizeOfRawData` and `file.len` stay unchanged!).
    let f_callee_2 = make_fn(2, 2, None, Some(1), 32);
    let staged = image
        .stage(Change {
            added: vec![&f_callee_2],
            removed: vec![f_callee_1.key],
            slots: vec![(f_callee_1.key, f_callee_2.key)],
            ..Change::default()
        })
        .unwrap();
    let p1 = apply_checked(&mut image, staged, &mut file);
    assert!(!p1.full);
    assert_eq!(
        observe(&file, f_entry.code.len(), f_callee_2.code.len(), 16),
        observe(&fresh_link(&f_callee_2, &[], &data_val), f_entry.code.len(), f_callee_2.code.len(), 16)
    );
    let len_after_p1 = file.len();

    let f_callee_3 = make_fn(2, 3, None, Some(1), 512);
    let staged = image
        .stage(Change {
            added: vec![&f_callee_3],
            removed: vec![f_callee_2.key],
            slots: vec![(f_callee_1.key, f_callee_3.key)],
            ..Change::default()
        })
        .unwrap();
    let p2 = apply_checked(&mut image, staged, &mut file);
    assert!(!p2.full);
    assert_eq!(file.len(), len_after_p1, "growth within raw slack keeps file length");
    assert!(p2.written() < 16 << 10, "within-slack edit writes little: {} bytes", p2.written());
    assert_eq!(
        observe(&file, f_entry.code.len(), f_callee_3.code.len(), 16),
        observe(&fresh_link(&f_callee_3, &[], &data_val), f_entry.code.len(), f_callee_3.code.len(), 16)
    );

    // 2a. Edit beyond tail section `.bpatch`'s raw size (grow by 12 KiB): appends to `.bpatch`,
    //     zero earlier sections move, write is proportional to the edit, NOT the 128 KiB base!
    let text_ptr_before = section_by_name(&PeFile64::parse(&file[..]).unwrap(), ".text")
        .unwrap()
        .pointer_to_raw_data
        .get(LE);
    let f_callee_4 = make_fn(2, 4, None, Some(1), 12 << 10);
    let staged = image
        .stage(Change {
            added: vec![&f_callee_4],
            removed: vec![f_callee_3.key],
            slots: vec![(f_callee_1.key, f_callee_4.key)],
            ..Change::default()
        })
        .unwrap();
    let p3 = apply_checked(&mut image, staged, &mut file);
    assert!(!p3.full);
    assert!(file.len() >= len_after_p1 + (12 << 10), ".bpatch raw data grew");
    assert_eq!(
        section_by_name(&PeFile64::parse(&file[..]).unwrap(), ".text")
            .unwrap()
            .pointer_to_raw_data
            .get(LE),
        text_ptr_before,
        ".text did not shift when .bpatch grew"
    );
    assert!(
        p3.written() < 32 << 10,
        "tail growth writes only the edit and headers, not the base image: {} bytes",
        p3.written()
    );
    assert_eq!(
        observe(&file, f_entry.code.len(), f_callee_4.code.len(), 16),
        observe(&fresh_link(&f_callee_4, &[], &data_val), f_entry.code.len(), f_callee_4.code.len(), 16)
    );

    // 2b. Edit beyond middle sections' raw size:
    //     - replace static 1 with a 12 KiB static in `.bdatap` (shifts `.bpatch` after it), AND
    //     - add 400 new framed functions so `.pdata` grows past 4 KiB (shifts `.reloc`,
    //       `.bdatap`, `.bpatch`!).
    //     Must still patch in place (no full relink), match fresh link, keep `.text` untouched,
    //     and roll back cleanly to the exact bytes before!
    let before_middle = file.clone();
    let (item1, inst1) = static_item_inst(1);
    data_val = make_static(1, vec![0x42; 12 << 10], true);
    let f_callee_5 = make_fn(2, 5, None, Some(1), 64);
    let extra_fns: Vec<CompiledFunction> =
        (0..400u32).map(|i| make_fn(1000 + i, 1, None, None, 0)).collect();
    let mut added: Vec<&CompiledFunction> = vec![&f_callee_5];
    added.extend(extra_fns.iter());
    let staged = image
        .stage(Change {
            added,
            removed: vec![f_callee_4.key],
            slots: vec![(f_callee_1.key, f_callee_5.key)],
            statics: vec![&data_val],
            removed_statics: vec![(item1, inst1)],
            ..Change::default()
        })
        .unwrap();
    let p4 = apply_checked(&mut image, staged, &mut file);
    assert!(!p4.full, "growing .pdata and .bdatap past raw size patches in place");
    assert_eq!(
        section_by_name(&PeFile64::parse(&file[..]).unwrap(), ".text")
            .unwrap()
            .pointer_to_raw_data
            .get(LE),
        text_ptr_before,
        ".text stays put when middle tail sections grow"
    );
    let parsed_p4 = PeFile64::parse(&file[..]).unwrap();
    let pdata_sec = section_by_name(&parsed_p4, ".pdata").unwrap();
    let bdatap_sec = section_by_name(&parsed_p4, ".bdatap").unwrap();
    assert!(pdata_sec.size_of_raw_data.get(LE) >= 2 * PAGE, ".pdata outgrew 1 page");
    assert!(bdatap_sec.size_of_raw_data.get(LE) >= 3 * PAGE, ".bdatap outgrew 0 -> >= 12 KiB");
    assert_eq!(
        observe(&file, f_entry.code.len(), f_callee_5.code.len(), 12 << 10),
        observe(
            &fresh_link(&f_callee_5, &extra_fns, &data_val),
            f_entry.code.len(),
            f_callee_5.code.len(),
            12 << 10,
        )
    );

    // Rollback across a middle-section growth restores the exact previous file.
    let mut disk = super::Disk::default();
    disk.files.insert(name(TO), {
        let mut s = super::Sparse::default();
        s.len = file.len() as u64;
        s.write(0, &file);
        s
    });
    disk.roll_back(&mut image).unwrap();
    let restored = super::contents(disk.file(TO));
    assert_eq!(restored, before_middle, "rollback after middle-section growth restores exact bytes");

    // 3. Edit beyond `.bpatch`'s virtual size -> refused (`needs_scratch`), then full relink
    //    produces a fresh compact PE matching a fresh link of the edited program.
    let bpatch_vsize = section_by_name(&PeFile64::parse(&before_middle[..]).unwrap(), ".bpatch")
        .unwrap()
        .virtual_size
        .get(LE) as usize;
    let huge_callee = make_fn(2, 6, None, Some(1), bpatch_vsize + 8192);
    let err = image
        .stage(Change {
            added: vec![&huge_callee],
            removed: vec![f_callee_4.key],
            slots: vec![(f_callee_1.key, huge_callee.key)],
            ..Change::default()
        })
        .err()
        .expect("exceeding .bpatch VirtualSize must refuse");
    assert!(err.no_room().is_some(), "overflowing virtual room asks for scratch relink: {err}");

    let old_static = make_static(1, vec![0x11; 16], true);
    let f_entry_relinked = make_fn(1, 1, Some(huge_callee.key), None, 0);
    let mut relinked = Image::new(name(TO), pe_output(true)).unwrap();
    let staged = relinked
        .stage(Change {
            added: vec![&f_entry_relinked, &huge_callee, &anchor],
            statics: vec![&old_static],
            names: vec![("mainCRTStartup".into(), Target::Direct(f_entry_relinked.key))],
            ..Change::default()
        })
        .unwrap();
    let mut relinked_file = Vec::new();
    let p_full = apply_checked(&mut relinked, staged, &mut relinked_file);
    assert!(p_full.full);
    let relinked_pe = PeFile64::parse(&relinked_file[..]).unwrap();
    assert_eq!(
        section_by_name(&relinked_pe, ".bpatch").unwrap().size_of_raw_data.get(LE),
        0,
        "after full relink, .bpatch raw data resets to 0"
    );
    assert_eq!(
        observe(&relinked_file, f_entry_relinked.code.len(), huge_callee.code.len(), 16),
        observe(
            &fresh_link(&huge_callee, &[], &old_static),
            f_entry_relinked.code.len(),
            huge_callee.code.len(),
            16,
        )
    );
}
