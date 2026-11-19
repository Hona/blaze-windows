//! Delay-loaded imports (`/DELAYLOAD:dll`): the DLL is loaded, and each of its functions found,
//! on the first call to it, by `delayimp.lib`'s `__delayLoadHelper2`, rather than by the
//! loader before `main` (rune-desktop delay-loads 13 DLLs to start faster).
//!
//! The core decides imports as it does for any DLL: a delay-loaded function is an import with
//! a GOT cell (`__imp_X`, in `.rdata`, which the loader makes read-only) and a thunk. Its
//! DLL is left out of the import directory, and the writer makes, for each function:
//!
//! - its GOT cell holding the address of a stub `T_X: jmp [rip + DIAT_X]` ([`DELAY_CODE`]),
//!   which the loader slides (a base relocation);
//! - its delay IAT cell `DIAT_X` ([`DELAY_DATA`], writable: the helper writes it) holding the
//!   address of `L_X: lea rax, [rip + DIAT_X]; lea r11, [rip + descriptor]; jmp tail`, so the
//!   first call loads it and every later one jumps through `DIAT_X` to it;
//! - its delay INT entry (a hint and name, or an ordinal), parallel to the IAT, which the
//!   helper reads by the cell's index.
//!
//! Each DLL has an `ImgDelayDescr` (RVA-based, `grAttrs` 1) naming its name, its `HMODULE`
//! cell, its IAT and its INT, in an array the delay import directory points at, ended by a
//! null one. `tail` is `__blaze_delay_tailmerge`, one function for every DLL (the descriptor
//! comes in `r11`), in an object the link makes ([`tailmerge_object`]) with its unwind info,
//! as link.exe makes a `__tailMerge_<dll>` for each: it saves the argument registers, calls
//! `__delayLoadHelper2(descriptor, cell)` and jumps to what it returns.
//!
//! Data cannot be delay-loaded (link.exe: LNK1194): an import of data from such a DLL is an
//! error naming it.

use super::coff::ImportName;
use super::image::Buf;
use super::{Pe, error};
use crate::LinkError;
use crate::model::{Class, Counts, Holds, Placed, SymbolKind};
use blaze_format::cursor::Put;

/// The writer's regions: the stubs and load thunks (code), the delay IATs and `HMODULE`
/// cells (writable data), the descriptors, INTs and names (read-only data).
pub(crate) const DELAY_CODE: &str = "pe.delay.code";
pub(crate) const DELAY_DATA: &str = "pe.delay.data";
pub(crate) const DELAY: &str = "pe.delay";

/// The tail-merge function the link's made object defines, and the helper it calls.
pub(crate) const TAILMERGE: &str = "__blaze_delay_tailmerge";
pub(crate) const HELPER: &str = "__delayLoadHelper2";

const DESCRIPTOR: u64 = 32;
/// `T_X` (6 bytes) then `L_X` (7 + 7 + 5), 32-aligned for each function's pair.
const THUNKS: u64 = 32;

/// The sizes the regions may need, from the counts: every import and library may be delayed.
pub(super) fn synthetic(counts: &Counts) -> Vec<(Class, u64)> {
    let (imports, libraries) = (counts.imports, counts.libraries);
    vec![
        (Class::Synthetic(DELAY_CODE), imports * THUNKS),
        (Class::Synthetic(DELAY_DATA), libraries * 16 + imports * 8),
        (
            Class::Synthetic(DELAY),
            ((libraries + 1) * DESCRIPTOR)
                + (imports + libraries) * 8
                + imports * 4
                + counts.import_names
                + counts.library_names
                + libraries,
        ),
    ]
}

/// Whether the DLL `name` is delay-loaded, its name ASCII case ignored as the loader's is.
pub(super) fn delayed(pe: &Pe, name: &str) -> bool {
    pe.output.link.pe.delay_load.iter().any(|it| it.eq_ignore_ascii_case(name))
}

/// One delay-loaded function: its GOT cell, and its import.
#[derive(Clone, Copy)]
struct Function {
    cell: u64,
    import: u32,
}

/// What the writer makes of the delayed imports: each region's bytes, the GOT cells' values
/// in the file (`encode`), and the addresses the loader slides.
pub(super) struct Tables {
    pub code: Vec<u8>,
    pub data: Vec<u8>,
    pub rdata: Vec<u8>,
    /// `(GOT cell, its stub's address)`, by address.
    pub cells: Vec<(u64, u64)>,
    /// The GOT cells and the delay IAT cells: each holds an address of the image.
    pub rebase: Vec<u64>,
    /// The delay import directory: the descriptors' address and size, when any DLL is used.
    pub directory: Option<(u64, u64)>,
}

/// The delayed DLLs' functions, by DLL (in the order `placed.libraries` has them), each
/// DLL's in its GOT cells' order.
fn functions(pe: &Pe, placed: &Placed<'_>) -> Result<Vec<(u32, Vec<Function>)>, LinkError> {
    let mut by_dll: Vec<(u32, Vec<Function>)> = Vec::new();
    for cell in placed.got {
        let Holds::Import(import) = cell.holds else { continue };
        let it = placed.imports.get(import as usize).ok_or_else(|| {
            error(format_args!("the GOT cell at {:#x} holds import {import}, which there isn't", cell.addr))
        })?;
        let Some(library) = it.library else { continue };
        let dll = &placed.libraries[library as usize].name;
        if !delayed(pe, dll) {
            continue;
        }
        if it.kind != SymbolKind::Function {
            return Err(error(format_args!(
                "`{}` is data that {dll} exports, and {dll} is delay-loaded (`/DELAYLOAD`): only \
                 functions can be (link.exe: LNK1194)",
                it.name
            )));
        }
        match by_dll.iter_mut().find(|it| it.0 == library) {
            Some((_, functions)) => functions.push(Function { cell: cell.addr, import }),
            None => by_dll.push((library, vec![Function { cell: cell.addr, import }])),
        }
    }
    by_dll.sort_by_key(|it| it.0);
    for (_, functions) in &mut by_dll {
        functions.sort_by_key(|it| it.cell);
    }
    Ok(by_dll)
}

/// The regions' addresses, when the image has them.
fn region(placed: &Placed<'_>, name: &'static str) -> Result<u64, LinkError> {
    placed
        .region(&Class::Synthetic(name))
        .map(|(_, it)| it.addr)
        .ok_or_else(|| error(format_args!("delay-loaded imports and no {name} region")))
}

fn rva(placed: &Placed<'_>, addr: u64) -> Result<u32, LinkError> {
    addr.checked_sub(placed.plan.base)
        .and_then(|it| u32::try_from(it).ok())
        .ok_or_else(|| error(format_args!("a delay-load table at {addr:#x} is outside the image")))
}

/// A 32-bit displacement from the end of a field at `field` (of `len` bytes after it in its
/// instruction) to `target`.
fn rel32(field: u64, after: u64, target: u64) -> Result<u32, LinkError> {
    let from = field + 4 + after;
    i32::try_from(target as i64 - from as i64)
        .map(|it| it as u32)
        .map_err(|_| error(format_args!("a delay-load thunk at {field:#x} does not reach {target:#x}")))
}

/// The delayed imports' tables (none when no DLL is delay-loaded).
pub(super) fn tables(pe: &Pe, placed: &Placed<'_>) -> Result<Option<Tables>, LinkError> {
    if pe.output.link.pe.delay_load.is_empty() {
        return Ok(None);
    }
    let dlls = functions(pe, placed)?;
    let (code_at, data_at, rdata_at) =
        (region(placed, DELAY_CODE)?, region(placed, DELAY_DATA)?, region(placed, DELAY)?);
    let mut tables = Tables {
        code: Vec::new(),
        data: Vec::new(),
        rdata: Vec::new(),
        cells: Vec::new(),
        rebase: Vec::new(),
        directory: None,
    };
    if dlls.is_empty() {
        return Ok(Some(tables));
    }
    let tail = (placed.symbol)(TAILMERGE).ok_or_else(|| {
        error(format_args!("delay-loaded imports and no `{TAILMERGE}`: the link makes it with every `/DELAYLOAD`"))
    })?;
    if (placed.symbol)(HELPER).is_none() {
        return Err(error(format_args!(
            "delay-loaded imports and no `{HELPER}`: give the link `delayimp.lib`, as link.exe needs it \
             (LNK2019)"
        )));
    }
    let count: usize = dlls.iter().map(|it| it.1.len()).sum();
    // The read-only region: descriptors, then each DLL's INT, then hint/names, then names.
    let descriptors = (dlls.len() as u64 + 1) * DESCRIPTOR;
    let mut names = Vec::with_capacity(count);
    for (_, functions) in &dlls {
        for function in functions {
            let it = &placed.imports[function.import as usize];
            names.push(ImportName::parse(&it.name, it.version.as_deref()).map_err(error)?);
        }
    }
    let ints = (count + dlls.len()) as u64 * 8;
    let hint_names: u64 = names
        .iter()
        .map(|it| match it {
            ImportName::Name { name, .. } => (2 + name.len() as u64 + 1).next_multiple_of(2),
            ImportName::Ordinal(_) => 0,
        })
        .sum();
    let (int_at, hint_at, dll_name_at) =
        (rdata_at + descriptors, rdata_at + descriptors + ints, rdata_at + descriptors + ints + hint_names);
    // The data region: each DLL's HMODULE cell, then its IAT and a zero cell.
    let mut rdata = Buf::with_capacity((descriptors + ints + hint_names) as usize + 256);
    let mut data = Buf::with_capacity(dlls.len() * 16 + count * 8);
    let mut code = Buf::with_capacity(count * THUNKS as usize);
    let (mut int, mut dll_name) = (int_at, dll_name_at);
    for (index, (library, functions)) in dlls.iter().enumerate() {
        let descriptor = rdata_at + index as u64 * DESCRIPTOR;
        let hmodule = data_at + data.len();
        data.put_u64(0);
        let iat = data_at + data.len();
        rdata.put_u32(1);
        rdata.put_u32(rva(placed, dll_name)?);
        rdata.put_u32(rva(placed, hmodule)?);
        rdata.put_u32(rva(placed, iat)?);
        rdata.put_u32(rva(placed, int)?);
        rdata.put_u32(0);
        rdata.put_u32(0);
        rdata.put_u32(0);
        for function in functions {
            let cell = data_at + data.len();
            let stub = code_at + code.len();
            let load = stub + 6;
            // T_X: jmp [rip + DIAT_X]
            code.put_bytes(&[0xff, 0x25]);
            code.put_u32(rel32(stub + 2, 0, cell)?);
            // L_X: lea rax, [rip + DIAT_X]; lea r11, [rip + descriptor]; jmp tail
            code.put_bytes(&[0x48, 0x8d, 0x05]);
            code.put_u32(rel32(load + 3, 0, cell)?);
            code.put_bytes(&[0x4c, 0x8d, 0x1d]);
            code.put_u32(rel32(load + 10, 0, descriptor)?);
            code.put_u8(0xe9);
            code.put_u32(rel32(load + 15, 0, tail)?);
            let padded = code.0.len().next_multiple_of(THUNKS as usize);
            code.0.resize(padded, 0xcc);
            data.put_u64(load);
            tables.rebase.push(cell);
            tables.cells.push((function.cell, stub));
            tables.rebase.push(function.cell);
            int += 8;
        }
        data.put_u64(0);
        int += 8;
        dll_name += placed.libraries[*library as usize].name.len() as u64 + 1;
    }
    rdata.put_bytes(&[0; DESCRIPTOR as usize]);
    // The INTs, as the import directory's lookup tables are.
    let mut hint_offset = hint_at;
    let mut at = 0;
    for (_, functions) in &dlls {
        for _ in functions {
            match names[at] {
                ImportName::Ordinal(ordinal) => {
                    rdata.put_u64(object::pe::IMAGE_ORDINAL_FLAG64 | u64::from(ordinal))
                }
                ImportName::Name { name, .. } => {
                    rdata.put_u64(u64::from(rva(placed, hint_offset)?));
                    hint_offset += (2 + name.len() as u64 + 1).next_multiple_of(2);
                }
            }
            at += 1;
        }
        rdata.put_u64(0);
    }
    for name in &names {
        if let ImportName::Name { hint, name } = *name {
            rdata.put_u16(hint);
            rdata.string(name);
            rdata.0.resize(rdata.len().next_multiple_of(2) as usize, 0);
        }
    }
    for (library, _) in &dlls {
        rdata.string(&placed.libraries[*library as usize].name);
    }
    tables.code = code.0;
    tables.data = data.0;
    tables.rdata = rdata.0;
    tables.cells.sort_unstable();
    tables.rebase.sort_unstable();
    tables.directory = Some((rdata_at, descriptors));
    Ok(Some(tables))
}

/// `__blaze_delay_tailmerge`: `rax` is the delay IAT cell, `r11` the DLL's descriptor. It
/// saves the argument registers (rcx, rdx, r8, r9 in the caller's home space; xmm0-xmm5, for
/// `vectorcall`), calls `__delayLoadHelper2(descriptor, cell)`, restores them and jumps to the
/// function it returns. The stack at entry is 8 off 16 (the call's return address): 0x88 more
/// aligns it for the saves and the call, with the callee's 0x20 of home space.
const TAILMERGE_CODE: &[u8] = &[
    0x48, 0x89, 0x4c, 0x24, 0x08, // mov [rsp+8], rcx
    0x48, 0x89, 0x54, 0x24, 0x10, // mov [rsp+0x10], rdx
    0x4c, 0x89, 0x44, 0x24, 0x18, // mov [rsp+0x18], r8
    0x4c, 0x89, 0x4c, 0x24, 0x20, // mov [rsp+0x20], r9
    0x48, 0x81, 0xec, 0x88, 0x00, 0x00, 0x00, // sub rsp, 0x88: the prolog's end, 27
    0x66, 0x0f, 0x7f, 0x44, 0x24, 0x20, // movdqa [rsp+0x20], xmm0
    0x66, 0x0f, 0x7f, 0x4c, 0x24, 0x30, // movdqa [rsp+0x30], xmm1
    0x66, 0x0f, 0x7f, 0x54, 0x24, 0x40, // movdqa [rsp+0x40], xmm2
    0x66, 0x0f, 0x7f, 0x5c, 0x24, 0x50, // movdqa [rsp+0x50], xmm3
    0x66, 0x0f, 0x7f, 0x64, 0x24, 0x60, // movdqa [rsp+0x60], xmm4
    0x66, 0x0f, 0x7f, 0x6c, 0x24, 0x70, // movdqa [rsp+0x70], xmm5
    0x48, 0x89, 0xc2, // mov rdx, rax
    0x4c, 0x89, 0xd9, // mov rcx, r11
    0xe8, 0x00, 0x00, 0x00, 0x00, // call __delayLoadHelper2 (REL32 at 70)
    0x66, 0x0f, 0x6f, 0x44, 0x24, 0x20, // movdqa xmm0, [rsp+0x20]
    0x66, 0x0f, 0x6f, 0x4c, 0x24, 0x30, // movdqa xmm1, [rsp+0x30]
    0x66, 0x0f, 0x6f, 0x54, 0x24, 0x40, // movdqa xmm2, [rsp+0x40]
    0x66, 0x0f, 0x6f, 0x5c, 0x24, 0x50, // movdqa xmm3, [rsp+0x50]
    0x66, 0x0f, 0x6f, 0x64, 0x24, 0x60, // movdqa xmm4, [rsp+0x60]
    0x66, 0x0f, 0x6f, 0x6c, 0x24, 0x70, // movdqa xmm5, [rsp+0x70]
    0x48, 0x81, 0xc4, 0x88, 0x00, 0x00, 0x00, // add rsp, 0x88
    0x48, 0x8b, 0x4c, 0x24, 0x08, // mov rcx, [rsp+8]
    0x48, 0x8b, 0x54, 0x24, 0x10, // mov rdx, [rsp+0x10]
    0x4c, 0x8b, 0x44, 0x24, 0x18, // mov r8, [rsp+0x18]
    0x4c, 0x8b, 0x4c, 0x24, 0x20, // mov r9, [rsp+0x20]
    0xff, 0xe0, // jmp rax
];
/// Where the call's displacement is.
const HELPER_CALL: u32 = 70;
/// Its `UNWIND_INFO`: version 1, a prolog of 27 bytes, one `UWOP_ALLOC_LARGE` of 0x88 (two
/// slots: the operation at the prolog's end, then the size in 8-byte units).
const TAILMERGE_UNWIND: [u8; 8] = [0x01, 27, 2, 0, 27, 0x01, 0x11, 0x00];

/// The COFF object of [`TAILMERGE`]: its code (`.text$mn`, a `REL32` to [`HELPER`]), its unwind
/// info (`.xdata`) and its `.pdata` entry, so an exception the helper raises (a DLL or
/// function not found) unwinds through it.
pub(crate) fn tailmerge_object() -> Vec<u8> {
    const HEADER: usize = 20;
    const SECTION: usize = 40;
    const RELOCATION: usize = 10;
    let code = TAILMERGE_CODE;
    let text_at = HEADER + 3 * SECTION;
    let text_relocs = text_at + code.len();
    let xdata_at = text_relocs + RELOCATION;
    let pdata_at = xdata_at + TAILMERGE_UNWIND.len();
    let pdata_relocs = pdata_at + 12;
    let symbols_at = pdata_relocs + 3 * RELOCATION;
    let mut out: Vec<u8> = Vec::with_capacity(symbols_at + 9 * 18 + 64);
    out.put_u16(object::pe::IMAGE_FILE_MACHINE_AMD64.0);
    out.put_u16(3);
    out.put_u32(0);
    out.put_u32(symbols_at as u32);
    // Three section symbols with their definitions, the function, the helper.
    out.put_u32(8);
    out.put_u16(0);
    out.put_u16(0);
    let section = |out: &mut Vec<u8>, name: &[u8; 8], size: usize, at: usize, relocs: (usize, usize), flags: u32| {
        out.put_bytes(name);
        out.put_u32(0);
        out.put_u32(0);
        out.put_u32(size as u32);
        out.put_u32(at as u32);
        out.put_u32(if relocs.1 > 0 { relocs.0 as u32 } else { 0 });
        out.put_u32(0);
        out.put_u16(relocs.1 as u16);
        out.put_u16(0);
        out.put_u32(flags);
    };
    use object::pe as p;
    let read = (p::IMAGE_SCN_CNT_INITIALIZED_DATA | p::IMAGE_SCN_MEM_READ).0;
    section(
        &mut out,
        b".text$mn",
        code.len(),
        text_at,
        (text_relocs, 1),
        (p::IMAGE_SCN_CNT_CODE | p::IMAGE_SCN_MEM_EXECUTE | p::IMAGE_SCN_MEM_READ).0
            | p::IMAGE_SCN_ALIGN_16BYTES.0,
    );
    section(&mut out, b".xdata\0\0", TAILMERGE_UNWIND.len(), xdata_at, (0, 0), read | p::IMAGE_SCN_ALIGN_4BYTES.0);
    section(&mut out, b".pdata\0\0", 12, pdata_at, (pdata_relocs, 3), read | p::IMAGE_SCN_ALIGN_4BYTES.0);
    out.put_bytes(code);
    // The call's REL32 against the helper (symbol 7), its implicit addend 0.
    out.put_u32(HELPER_CALL);
    out.put_u32(7);
    out.put_u16(p::IMAGE_REL_AMD64_REL32.0);
    out.put_bytes(&TAILMERGE_UNWIND);
    // The function's start, end and unwind info: ADDR32NB against the sections' symbols.
    out.put_u32(0);
    out.put_u32(code.len() as u32);
    out.put_u32(0);
    for (at, symbol) in [(0u32, 0u32), (4, 0), (8, 2)] {
        out.put_u32(at);
        out.put_u32(symbol);
        out.put_u16(p::IMAGE_REL_AMD64_ADDR32NB.0);
    }
    let symbol = |out: &mut Vec<u8>, name: &[u8; 8], number: u16, typ: u16, class: u8, aux: Option<(usize, usize)>| {
        out.put_bytes(name);
        out.put_u32(0);
        out.put_u16(number);
        out.put_u16(typ);
        out.put_u8(class);
        out.put_u8(u8::from(aux.is_some()));
        if let Some((size, relocs)) = aux {
            out.put_u32(size as u32);
            out.put_u16(relocs as u16);
            out.put_u16(0);
            out.put_u32(0);
            out.put_u16(0);
            out.put_u8(0);
            out.put_bytes(&[0; 3]);
        }
    };
    let stat = p::IMAGE_SYM_CLASS_STATIC.0;
    let ext = p::IMAGE_SYM_CLASS_EXTERNAL.0;
    symbol(&mut out, b".text$mn", 1, 0, stat, Some((code.len(), 1)));
    symbol(&mut out, b".xdata\0\0", 2, 0, stat, Some((TAILMERGE_UNWIND.len(), 0)));
    symbol(&mut out, b".pdata\0\0", 3, 0, stat, Some((12, 3)));
    // Long names, in the string table: 4 zero bytes, then their offset.
    let mut strings: Vec<u8> = Vec::new();
    let long = |strings: &mut Vec<u8>, name: &str| -> [u8; 8] {
        let offset = 4 + strings.len() as u32;
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        let mut out = [0; 8];
        out[4..].copy_from_slice(&offset.to_le_bytes());
        out
    };
    let function = long(&mut strings, TAILMERGE);
    let helper = long(&mut strings, HELPER);
    symbol(&mut out, &function, 1, 0x20, ext, None);
    symbol(&mut out, &helper, 0, 0x20, ext, None);
    out.put_u32(4 + strings.len() as u32);
    out.extend_from_slice(&strings);
    out
}
