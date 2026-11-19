//! An image's PDB (docs/v2/plan/design/pdb.md): what std's backtrace (dbghelp), cdb, WinDbg
//! and Visual Studio read a Windows program's function names, lines, types, parameters, locals
//! and inline frames from. It is the side file of a PE image ([`crate::beside`]): named
//! `<stem>.pdb` by the image's CodeView record, which carries the image's build id as its GUID
//! and age 1, as the PDB's info stream does.
//!
//! An MSF 7.0 file of 4 KiB blocks: the superblock, the two free block maps of each interval,
//! the streams, then the stream directory and the block that lists the directory's blocks.
//! The PDB info stream is always block 3, so the build id is at a fixed place ([`GUID_AT`]).
//!
//! Its streams:
//! - the PDB info stream (stream 1), naming `/names`;
//! - TPI (stream 2) and TPI hash (stream 6): content-deduplicated CodeView type records for
//!   Rust types (primitives, pointers/references, structs, tuples, MSVC-shaped union+discriminant
//!   enums, arrays, slices and `&str`, procedures) and merged C/C++ types;
//! - DBI (stream 3): module 0 (`blaze`) for Rust functions plus one module per native C/C++
//!   object with CodeView debug info, section contributions, section map, source files and
//!   the image's section headers stream;
//! - IPI (stream 4) and IPI hash (stream 7): content-deduplicated item IDs (`LF_FUNC_ID` for
//!   inlinees and merged C/C++ item IDs);
//! - `/names` (stream 5): source file paths;
//! - globals (stream 8, `S_PROCREF`/`S_LPROCREF` GSI hash), publics (stream 9, `S_PUB32` for
//!   native functions with GSI hash and address map), symbol records (stream 10), section
//!   headers (stream 11);
//! - module 0 (`blaze`, stream 12): `S_OBJNAME`, `S_COMPILE3` (Rust), per-function `S_GPROC32`
//!   slots (`S_FRAMEPROC`, `S_LOCAL` + `S_DEFRANGE_*`, `S_BLOCK32`, nested `S_INLINESITE`..
//!   `S_INLINESITE_END`, `S_END`), then C13 subsections (`DEBUG_S_FILECHKSMS`,
//!   `DEBUG_S_INLINEELINES`, per-function `DEBUG_S_LINES`).
//!
//! A link's change patches the file ([`Model::patch`], docs/v2/plan/design/pdb.md): each Rust
//! function's procedure slot and line table slot live in module 0 with `S_SKIP`/`DEBUG_S_IGNORE`
//! room; TPI and IPI are append-only so existing `TypeIndex`es never move. A typical body edit
//! rewrites only the edited function's records and touches zero bytes of TPI/IPI or native
//! modules.

use std::alloc::Global;

use blaze_codegen::InstanceKey;
use blaze_codegen::debug::{FunctionDebug, Local, LocalPlace};
use blaze_hash::HashMap;

use crate::beside::{Func, Inlined, Lined};

pub(crate) mod cv;
pub(crate) mod types;

use cv::{
    CV_AMD64_RBP, DEBUG_S_FILECHKSMS, DEBUG_S_IGNORE, DEBUG_S_INLINEELINES, DEBUG_S_LINES,
    FrameBase, LOCAL_IS_OPTIMIZED_OUT, LOCAL_IS_PARAM, MAX_DEFRANGE, S_BLOCK32, S_COMPILE3,
    S_DEFRANGE_FRAMEPOINTER_REL, S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE, S_DEFRANGE_REGISTER,
    S_DEFRANGE_REGISTER_REL, S_DEFRANGE_REGISTER_REL_INDIR, S_DEFRANGE_SUBFIELD_REGISTER, S_END,
    S_FRAMEPROC, S_GPROC32, S_INLINESITE, S_INLINESITE_END, S_LOCAL, S_OBJNAME, S_PROCREF,
    S_PUB32, S_SKIP,
};
use types::TypeTable;

pub(crate) const BLOCK: usize = 4096;
const MAGIC: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";

/// The PDB info stream's first block: after the superblock and the first interval's two free
/// block maps.
const INFO_BLOCK: usize = 3;
/// Where the PDB holds its GUID, the build id: the info stream's version, signature and age
/// come first.
pub(crate) const GUID_AT: usize = INFO_BLOCK * BLOCK + 12;

// Fixed stream numbers. Native C/C++ module streams follow starting at `STREAMS`.
const INFO: u16 = 1;
const TPI: u16 = 2;
const DBI: u16 = 3;
const IPI: u16 = 4;
const NAMES: u16 = 5;
const TPI_HASH: u16 = 6;
const IPI_HASH: u16 = 7;
const GLOBALS: u16 = 8;
const PUBLICS: u16 = 9;
const RECORDS: u16 = 10;
const SECTION_HEADERS: u16 = 11;
const MODULE: u16 = 12;
const STREAMS: usize = 13;
const NONE: u16 = 0xffff;

const CV_CFL_RUST: u32 = 0x15;
const CV_CFL_X64: u16 = 0xd0;
const CV_SIGNATURE_C13: u32 = 4;
/// `CV_PUBSYMFLAGS`: a function.
const PUBLIC_FUNCTION: u32 = 2;
/// The line CodeView gives code that has none (LLVM's and MSVC's "hidden" line).
const NO_LINE: u32 = 0xf0_0f00;
const STATEMENT: u32 = 0x8000_0000;
/// The buckets of a GSI hash (`IPHR_HASH`).
const GSI_BUCKETS: usize = 4096;

/// The image a PDB describes, as its headers say: what places a function in a section.
pub(crate) struct Headers {
    base: u64,
    stamp: u32,
    /// Each section header's 40 bytes, in order.
    sections: Vec<[u8; 40]>,
}

impl Headers {
    /// Read from the image's file, which `exe` copies from (`exe(at, out)`).
    pub(crate) fn read(exe: &impl Fn(u64, &mut [u8])) -> Result<Headers, String> {
        let mut dos = [0u8; 64];
        exe(0, &mut dos);
        if &dos[..2] != b"MZ" {
            return Err("the image has no DOS header".into()); // alloc: error path
        }
        let nt = u64::from(u32::from_le_bytes(dos[60..64].try_into().unwrap()));
        let mut head = [0u8; 24 + 112];
        exe(nt, &mut head);
        if &head[..4] != b"PE\0\0" {
            return Err("the image has no PE signature".into()); // alloc: error path
        }
        let count = usize::from(u16::from_le_bytes([head[6], head[7]]));
        let stamp = u32::from_le_bytes(head[8..12].try_into().unwrap());
        let optional = u64::from(u16::from_le_bytes([head[20], head[21]]));
        if u16::from_le_bytes([head[24], head[25]]) != 0x20b {
            return Err("the image is not PE32+".into()); // alloc: error path
        }
        let base = u64::from_le_bytes(head[48..56].try_into().unwrap());
        let mut sections = Vec::with_capacity(count);
        for n in 0..count as u64 {
            let mut header = [0u8; 40];
            exe(nt + 24 + optional + 40 * n, &mut header);
            sections.push(header);
        }
        Ok(Headers { base, stamp, sections })
    }

    /// The section (1-based) and offset in it of the address `addr`.
    pub(crate) fn place(&self, addr: u64) -> Option<(u16, u32)> {
        let rva = addr.checked_sub(self.base).unwrap_or(addr);
        self.sections.iter().enumerate().find_map(|(n, it)| {
            let size = u64::from(u32_at(it, 8)).max(u64::from(u32_at(it, 16)));
            let start = u64::from(u32_at(it, 12));
            (start..start + size).contains(&rva).then(|| ((n + 1) as u16, (rva - start) as u32))
        })
    }
}

pub(crate) fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

/// Whether two section tables describe the same virtual layout: same count, names, virtual
/// addresses, virtual sizes and protection bits (only `SizeOfRawData` / `PointerToRawData`
/// and non-code `CNT_*_DATA` bits may differ when a compact PE image's sections grow on disk).
fn same_virtual_sections(a: &[[u8; 40]], b: &[[u8; 40]]) -> bool {
    const RWX: u32 = 0xe000_0000;
    const EXEC: u32 = 0x2000_0000;
    a.len() == b.len()
        && a.iter().zip(b).all(|(x, y)| {
            let (fx, fy) = (u32_at(x, 36), u32_at(y, 36));
            x[..16] == y[..16]
                && (fx & RWX) == (fy & RWX)
                && (fx & EXEC == 0 || fx == fy)
        })
}

/// The hash the PDB's tables are searched by (`hashStringV1`, Microsoft's `LHashPbCb`).
pub(crate) fn hash_v1(name: &[u8]) -> u32 {
    let mut result = 0u32;
    let mut words = name.chunks_exact(4);
    for word in &mut words {
        result ^= u32::from_le_bytes(word.try_into().unwrap());
    }
    let mut rest = words.remainder();
    if rest.len() >= 2 {
        result ^= u32::from(u16::from_le_bytes([rest[0], rest[1]]));
        rest = &rest[2..];
    }
    if let [byte] = rest {
        result ^= u32::from(*byte);
    }
    result |= 0x2020_2020;
    result ^= result >> 11;
    result ^ (result >> 16)
}

/// A little-endian byte buffer.
#[derive(Default)]
struct Out(Vec<u8>);

impl Out {
    fn u8(&mut self, it: u8) -> &mut Out {
        self.0.push(it);
        self
    }
    fn u16(&mut self, it: u16) -> &mut Out {
        self.0.extend_from_slice(&it.to_le_bytes());
        self
    }
    fn u32(&mut self, it: u32) -> &mut Out {
        self.0.extend_from_slice(&it.to_le_bytes());
        self
    }
    fn i32(&mut self, it: i32) -> &mut Out {
        self.0.extend_from_slice(&it.to_le_bytes());
        self
    }
    fn bytes(&mut self, it: &[u8]) -> &mut Out {
        self.0.extend_from_slice(it);
        self
    }
    /// A NUL-terminated string.
    fn string(&mut self, it: &str) -> &mut Out {
        self.0.extend_from_slice(it.as_bytes());
        self.0.push(0);
        self
    }
    fn align(&mut self, to: usize) -> &mut Out {
        while self.0.len() % to != 0 {
            self.0.push(0);
        }
        self
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn set_u32(&mut self, at: usize, it: u32) {
        self.0[at..at + 4].copy_from_slice(&it.to_le_bytes());
    }
}

/// A symbol record: its kind and body, given a length and padded to 4 bytes.
fn record(out: &mut Out, kind: u16, body: impl FnOnce(&mut Out)) {
    let start = out.len();
    out.u16(0).u16(kind);
    body(out);
    out.align(4);
    let len = (out.len() - start - 2) as u16;
    out.0[start..start + 2].copy_from_slice(&len.to_le_bytes());
}

/// A string table with its hash (`/names`, and the DBI's EC names): `strings` each once, in
/// order, at the offsets it gives back in that order.
fn string_table(strings: &[&str]) -> (Vec<u8>, Vec<u32>) {
    let mut buffer = Out::default();
    buffer.u8(0);
    let mut offsets = Vec::with_capacity(strings.len());
    for it in strings {
        offsets.push(buffer.len() as u32);
        buffer.string(it);
    }
    let buckets = (strings.len() * 4 / 3 + 1).max(1);
    let mut table = vec![0u32; buckets];
    for (it, offset) in strings.iter().zip(&offsets) {
        let start = hash_v1(it.as_bytes()) as usize % buckets;
        let slot = (0..buckets).map(|step| (start + step) % buckets).find(|at| table[*at] == 0);
        table[slot.expect("a bucket per string and one more")] = *offset;
    }
    let mut out = Out::default();
    out.u32(0xeffe_effe).u32(1).u32(buffer.len() as u32).bytes(&buffer.0);
    out.u32(buckets as u32);
    for it in table {
        out.u32(it);
    }
    out.u32(strings.len() as u32);
    (out.0, offsets)
}

/// The PDB info stream: its version, the image's time stamp, age 1 and build id, `/names`
/// by name, and the feature VC140.
fn info(stamp: u32, id: &[u8; 16]) -> Vec<u8> {
    let mut out = Out::default();
    out.u32(20000404).u32(stamp).u32(1).bytes(id);
    // The named stream map: its names, then a hash table of (name offset, stream).
    out.u32(7).bytes(b"/names\0");
    let capacity = 8;
    let bucket = u32::from(hash_v1(b"/names") as u16) % capacity;
    out.u32(1).u32(capacity);
    out.u32(1).u32(1 << bucket);
    out.u32(0);
    out.u32(0).u32(u32::from(NAMES));
    out.u32(20140508);
    out.0
}

/// A GSI hash of `records`, each `(name, offset in the symbol record stream)`: the records by
/// bucket (counted into place), each bucket in the readers' order of names.
fn gsi(records: &[(&str, u32)]) -> Vec<u8> {
    let bucket_of: Vec<u16> = records
        .iter()
        .map(|(name, _)| (hash_v1(name.as_bytes()) as usize % GSI_BUCKETS) as u16)
        .collect();
    let mut starts = vec![0u32; GSI_BUCKETS + 1];
    for it in &bucket_of {
        starts[usize::from(*it) + 1] += 1;
    }
    for n in 0..GSI_BUCKETS {
        starts[n + 1] += starts[n];
    }
    let mut cursor = starts.clone();
    let mut sorted = vec![0u32; records.len()];
    for (n, it) in bucket_of.iter().enumerate() {
        let at = &mut cursor[usize::from(*it)];
        sorted[*at as usize] = n as u32;
        *at += 1;
    }
    let mut bitmap = [0u32; (GSI_BUCKETS + 32) / 32];
    let mut offsets = Vec::new();
    for bucket in 0..GSI_BUCKETS {
        let run = &mut sorted[starts[bucket] as usize..starts[bucket + 1] as usize];
        if run.is_empty() {
            continue;
        }
        run.sort_unstable_by(|a, b| {
            let (a, b) = (&records[*a as usize], &records[*b as usize]);
            gsi_cmp(a.0, b.0).then(a.1.cmp(&b.1))
        });
        bitmap[bucket / 32] |= 1 << (bucket % 32);
        offsets.push(starts[bucket] * 12);
    }
    let mut out =
        Out(Vec::with_capacity(16 + 8 * records.len() + 4 * (bitmap.len() + offsets.len())));
    out.u32(u32::MAX).u32(0xeffe_0000 + 19990810).u32(records.len() as u32 * 8);
    out.u32((bitmap.len() + offsets.len()) as u32 * 4);
    for n in &sorted {
        out.u32(records[*n as usize].1 + 1).u32(1);
    }
    for it in bitmap {
        out.u32(it);
    }
    for it in offsets {
        out.u32(it);
    }
    out.0
}

/// The order of names in a GSI bucket (`gsiRecordCmp`): shorter first, then ASCII without
/// case, else by bytes.
fn gsi_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    if a.len() != b.len() {
        return a.len().cmp(&b.len());
    }
    let (x, y) = (a.as_bytes(), b.as_bytes());
    if !(a.is_ascii() && b.is_ascii()) {
        return x.cmp(y);
    }
    match x.iter().zip(y).position(|(p, q)| p != q) {
        None => Ordering::Equal,
        Some(at) => (x[at..].iter().map(u8::to_ascii_lowercase))
            .cmp(y[at..].iter().map(u8::to_ascii_lowercase)),
    }
}

/// A function as the PDB places it: its name, section, offset and size, its rows, optional
/// locals/types/scopes, and resolved inlined sites.
struct Placed<'a> {
    key: InstanceKey,
    name: std::borrow::Cow<'a, str>,
    section: u16,
    offset: u32,
    size: u32,
    lines: std::ops::Range<usize>,
    debug: Option<&'a FunctionDebug>,
    inlined: std::ops::Range<usize>,
}

/// Where a function's records are in the PDB last given: its procedure slot (from `S_GPROC32`
/// through `S_END` plus any trailing `S_SKIP` slack up to `sym_cap`), its line table slot,
/// and its `S_PROCREF` in the symbol record stream.
#[derive(Clone, Debug)] // clone: tests' models
struct Slot {
    sym_at: u32,
    sym_cap: u32,
    /// 0 for a function with no rows.
    line_at: u32,
    line_cap: u32,
    ref_at: u32,
    name: String,
    /// Its section, offset and size.
    place: (u16, u32, u32),
}

/// Why a patch stopped: the file is laid out whole, for this reason.
pub(crate) type Whole = &'static str;

/// A PDB as last given ([`Model::new`] lays one out whole, [`Model::patch`] brings it to a
/// link's change): its streams' bytes and blocks, the module stream's room, TPI and IPI type
/// tables, inlinee lines table, each function's slots by key, and what the tables that index
/// them are made of.
pub(crate) struct Model {
    headers: Headers,
    id: [u8; 16],
    streams: Vec<Vec<u8>>,
    blocks: Vec<Vec<u32>>,
    /// Blocks in the file, those no stream holds, the directory's and the block map.
    count: u32,
    free: Vec<u32>,
    directory: Vec<u32>,
    block_map: u32,
    /// Content-deduplicated TPI (types) and IPI (item IDs / inlinee `LF_FUNC_ID`s).
    tpi: TypeTable,
    ipi: TypeTable,
    /// Module 0 (`blaze`) stream layout:
    /// - symbols: `4..sym_end` with room to `sym_cap` (an `S_SKIP`);
    /// - files (`DEBUG_S_FILECHKSMS`): `files_at..files_at + 8*files_cap`;
    /// - inlinee lines (`DEBUG_S_INLINEELINES`): `inlinees_hdr..c13_at` (`12 + 12*inlinees_cap`);
    /// - line tables: `c13_at..c13_end` with room to `c13_cap` (a `DEBUG_S_IGNORE`).
    sym_end: usize,
    sym_cap: usize,
    files_at: usize,
    files_cap: usize,
    inlinees_hdr: usize,
    inlinees_cap: usize,
    c13_at: usize,
    c13_end: usize,
    c13_cap: usize,
    files: Vec<String>,
    file_of: HashMap<String, u32, Global>,
    /// Module 0's `DEBUG_S_INLINEELINES` entries: `(inlinee_ipi_id, file_checksum_offset, line)`.
    inlinees: Vec<(u32, u32, u32)>,
    inlinee_of: HashMap<u32, usize, Global>,
    /// By key.
    slots: Vec<(InstanceKey, Slot)>,
    /// Every procedure's place, sorted: what DBI's section contributions are runs of.
    spans: Vec<(u16, u32, u32)>,
    /// The functions of no code, sorted: they have no records.
    empty: Vec<InstanceKey>,
    /// The native code's functions the publics name, as a hash: a change of them lays out
    /// whole.
    natives: u64,
}

/// The room a region keeps past what it holds: a quarter, and at least `least` bytes.
fn room(used: usize, least: usize) -> usize {
    (used / 4).max(least).next_multiple_of(4)
}

/// A hash of the native functions' names and addresses.
fn natives_hash(natives: &[(&str, u64)]) -> u64 {
    let mut hasher = blaze_ids::Hasher::new("blaze v2 pdb natives");
    for (name, addr) in natives {
        hasher.part(name.as_bytes()).update(&addr.to_le_bytes());
    }
    u64::from_le_bytes(hasher.finish().0[..8].try_into().unwrap())
}

/// `S_SKIP` over `len` bytes of `bytes` at `at`: room readers step over.
fn skip(bytes: &mut [u8], at: usize, len: usize) {
    debug_assert!(len >= 4 && len % 4 == 0);
    bytes[at..at + 2].copy_from_slice(&((len - 2) as u16).to_le_bytes());
    bytes[at + 2..at + 4].copy_from_slice(&S_SKIP.to_le_bytes());
    bytes[at + 4..at + len].fill(0);
}

/// A `DEBUG_S_IGNORE` subsection over `len` bytes at `at`.
fn ignore(bytes: &mut [u8], at: usize, len: usize) {
    debug_assert!(len >= 8 && len % 4 == 0);
    bytes[at..at + 4].copy_from_slice(&DEBUG_S_IGNORE.to_le_bytes());
    bytes[at + 4..at + 8].copy_from_slice(&((len - 8) as u32).to_le_bytes());
    bytes[at + 8..at + len].fill(0);
}

/// One resolved inlined site ready for emission inside a procedure.
struct PreparedInline<'a> {
    parent: Option<u32>,
    inlinee_id: u32,
    reg_file_id: u32,
    reg_base_line: u32,
    call_file_idx: u32,
    call_line: u32,
    ranges: &'a [(u32, u32)],
}

/// Encodes one function's procedure record (`S_GPROC32` through its matching `S_END`),
/// including `S_FRAMEPROC`, parameters/locals (`S_LOCAL` + `S_DEFRANGE_*`), lexical blocks
/// (`S_BLOCK32`), and nested inline frames (`S_INLINESITE`..`S_INLINESITE_END`), as placed at
/// `proc_at` in module 0.
///
/// Writes into `outer_rows` the line rows for the function's `DEBUG_S_LINES` (outer call site
/// lines for inlined ranges, own lines for non-inlined ranges).
#[allow(clippy::too_many_arguments)]
fn encode_procedure(
    out: &mut Out,
    proc_at: usize,
    function: &Placed<'_>,
    rows: &[(u32, u32, u32)],
    inlined_sites: &[PreparedInline<'_>],
    tpi: &mut TypeTable,
    outer_rows: &mut Vec<(u32, u32, u32)>,
) {
    outer_rows.clear();

    // Lower the function's Rust types (if any) into TPI and build its LF_PROCEDURE type.
    let (type_map, frame_base, param_tis) = match function.debug {
        Some(dbg) => {
            let map = types::lower_rust_types(tpi, &dbg.types);
            let fb = cv::decode_frame_base(&dbg.frame_base);
            let params: Vec<u32> = dbg
                .locals
                .iter()
                .filter(|l| l.param)
                .map(|l| l.ty.and_then(|i| map.get(i as usize).copied()).unwrap_or(cv::T_VOID))
                .collect();
            (map, fb, params)
        }
        None => (Vec::new(), None, Vec::new()),
    };
    let proc_ti = tpi.intern_procedure(cv::T_VOID, &param_tis);
    let proc_flags: u8 = if frame_base.is_some_and(|fb| fb.cv_reg == CV_AMD64_RBP) { 1 } else { 0 };

    let gproc_rel = out.len();
    record(out, S_GPROC32, |out| {
        out.u32(0).u32(0).u32(0); // pParent, pEnd, pNext
        out.u32(function.size).u32(0).u32(function.size).u32(proc_ti);
        out.u32(function.offset).u16(function.section).u8(proc_flags).string(&function.name);
    });

    // S_FRAMEPROC tells the debugger which register is the local/param frame pointer.
    if let Some(fb) = frame_base
        && fb.encoded != 0
    {
        let flags = (fb.encoded << 14) | (fb.encoded << 16);
        record(out, S_FRAMEPROC, |out| {
            out.u32(0).u32(0).u32(0).u32(0).u32(0).u16(0).u32(flags);
        });
    }

    // Parameters, locals and lexical scopes.
    if let Some(dbg) = function.debug
        && !dbg.locals.is_empty()
    {
        emit_locals_and_scopes(out, proc_at, gproc_rel, function, dbg, &type_map, frame_base);
    }

    // Inline frames and outer DEBUG_S_LINES rows.
    if inlined_sites.is_empty() {
        outer_rows.extend_from_slice(rows);
    } else {
        emit_inlines_and_outer_rows(
            out,
            proc_at,
            gproc_rel,
            function,
            rows,
            inlined_sites,
            outer_rows,
        );
    }

    let end_rel = out.len();
    record(out, S_END, |_| {});
    // S_GPROC32's pEnd points to its closing S_END.
    out.set_u32(gproc_rel + 8, (proc_at + end_rel) as u32);
}

fn emit_locals_and_scopes(
    out: &mut Out,
    proc_at: usize,
    gproc_rel: usize,
    function: &Placed<'_>,
    dbg: &FunctionDebug,
    type_map: &[u32],
    frame_base: Option<FrameBase>,
) {
    let full_range = [(0u32, function.size)];
    // Top-level parameters and locals (scope == None).
    for local in dbg.locals.iter().filter(|l| l.scope.is_none()) {
        emit_local(out, local, type_map, frame_base, function, &full_range, true);
    }
    if dbg.scopes.is_empty() {
        return;
    }
    // Build parent -> children map and mark scopes that transitively own any local.
    let n = dbg.scopes.len();
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut roots: Vec<usize> = Vec::new();
    for (i, scope) in dbg.scopes.iter().enumerate() {
        match scope.parent.map(|p| p as usize).filter(|&p| p < i) {
            Some(p) => children[p].push(i),
            None => roots.push(i),
        }
    }
    let mut has_locals = vec![false; n];
    for local in &dbg.locals {
        if let Some(s) = local.scope.map(|s| s as usize).filter(|&s| s < n) {
            has_locals[s] = true;
        }
    }
    for i in (0..n).rev() {
        if has_locals[i]
            && let Some(p) = dbg.scopes[i].parent.map(|p| p as usize).filter(|&p| p < i)
        {
            has_locals[p] = true;
        }
    }
    for root in roots {
        emit_scope_tree(
            out,
            proc_at,
            gproc_rel,
            root,
            function,
            dbg,
            type_map,
            frame_base,
            &children,
            &has_locals,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_scope_tree(
    out: &mut Out,
    proc_at: usize,
    parent_rel: usize,
    scope_idx: usize,
    function: &Placed<'_>,
    dbg: &FunctionDebug,
    type_map: &[u32],
    frame_base: Option<FrameBase>,
    children: &[Vec<usize>],
    has_locals: &[bool],
) {
    if !has_locals[scope_idx] {
        return;
    }
    let scope = &dbg.scopes[scope_idx];
    let clipped: Vec<(u32, u32)> = scope
        .ranges
        .iter()
        .filter_map(|&(from, to)| {
            let to = to.min(function.size);
            (from < to).then_some((from, to))
        })
        .collect();
    if clipped.is_empty() {
        return;
    }
    // Single contiguous range -> S_BLOCK32 .. S_END; multiple disjoint ranges -> emit directly in
    // enclosing scope with per-range S_DEFRANGE records.
    if let &[(from, to)] = clipped.as_slice() {
        let block_rel = out.len();
        record(out, S_BLOCK32, |out| {
            out.u32((proc_at + parent_rel) as u32); // pParent
            out.u32(0); // pEnd (patched below)
            out.u32(to - from); // CodeSize
            out.u32(function.offset + from); // CodeOffset
            out.u16(function.section); // Segment
            out.string(""); // Name
        });
        for local in dbg.locals.iter().filter(|l| l.scope == Some(scope_idx as u32)) {
            emit_local(out, local, type_map, frame_base, function, &clipped, true);
        }
        for &child in &children[scope_idx] {
            emit_scope_tree(
                out,
                proc_at,
                block_rel,
                child,
                function,
                dbg,
                type_map,
                frame_base,
                children,
                has_locals,
            );
        }
        let end_rel = out.len();
        record(out, S_END, |_| {});
        out.set_u32(block_rel + 8, (proc_at + end_rel) as u32);
    } else {
        for local in dbg.locals.iter().filter(|l| l.scope == Some(scope_idx as u32)) {
            emit_local(out, local, type_map, frame_base, function, &clipped, false);
        }
        for &child in &children[scope_idx] {
            emit_scope_tree(
                out,
                proc_at,
                parent_rel,
                child,
                function,
                dbg,
                type_map,
                frame_base,
                children,
                has_locals,
            );
        }
    }
}

fn emit_local(
    out: &mut Out,
    local: &Local,
    type_map: &[u32],
    frame_base: Option<FrameBase>,
    function: &Placed<'_>,
    scope_ranges: &[(u32, u32)],
    full_scope_ok: bool,
) {
    let ty_ti = local.ty.and_then(|i| type_map.get(i as usize).copied()).unwrap_or(cv::T_VOID);
    let base_flags = if local.param { LOCAL_IS_PARAM } else { 0 };

    match &local.place {
        LocalPlace::Frame(offset) => {
            let Ok(off32) = i32::try_from(*offset) else {
                emit_s_local(out, ty_ti, base_flags | LOCAL_IS_OPTIMIZED_OUT, &local.name);
                return;
            };
            if let Some(fb) = frame_base {
                emit_s_local(out, ty_ti, base_flags, &local.name);
                if fb.encoded != 0 && full_scope_ok {
                    record(out, S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE, |out| {
                        out.i32(off32);
                    });
                } else {
                    let loc = if fb.encoded != 0 {
                        cv::CvLocation::FrameRel { offset: off32 }
                    } else {
                        cv::CvLocation::RegRel {
                            reg: fb.cv_reg,
                            offset: off32,
                            subfield_offset: None,
                        }
                    };
                    for &(from, to) in scope_ranges {
                        emit_defrange(out, loc, function, from, to);
                    }
                }
            } else {
                emit_s_local(out, ty_ti, base_flags | LOCAL_IS_OPTIMIZED_OUT, &local.name);
            }
        }
        LocalPlace::Ranges(ranges) => {
            let mut entries: Vec<(u32, u32, cv::CvLocation)> = Vec::new();
            for (from, to, expr) in ranges {
                let end = (*to).min(function.size);
                if *from >= end {
                    continue;
                }
                for loc in cv::translate_dwarf_expr(expr, frame_base) {
                    entries.push((*from, end, loc));
                }
            }
            if entries.is_empty() {
                emit_s_local(out, ty_ti, base_flags | LOCAL_IS_OPTIMIZED_OUT, &local.name);
                return;
            }
            emit_s_local(out, ty_ti, base_flags, &local.name);
            for (from, to, loc) in entries {
                emit_defrange(out, loc, function, from, to);
            }
        }
    }
}

fn emit_s_local(out: &mut Out, typind: u32, flags: u16, name: &str) {
    record(out, S_LOCAL, |out| {
        out.u32(typind).u16(flags).string(name);
    });
}

fn emit_defrange(
    out: &mut Out,
    loc: cv::CvLocation,
    function: &Placed<'_>,
    from: u32,
    to: u32,
) {
    let mut at = from;
    while at < to {
        let len = (to - at).min(MAX_DEFRANGE);
        let off_start = function.offset + at;
        let isect = function.section;
        let cb = len as u16;
        match loc {
            cv::CvLocation::Register { reg, subfield_offset: None } => {
                record(out, S_DEFRANGE_REGISTER, |out| {
                    out.u16(reg).u16(0).u32(off_start).u16(isect).u16(cb);
                });
            }
            cv::CvLocation::Register { reg, subfield_offset: Some(sub) } => {
                record(out, S_DEFRANGE_SUBFIELD_REGISTER, |out| {
                    out.u16(reg).u16(0).u32(sub).u32(off_start).u16(isect).u16(cb);
                });
            }
            cv::CvLocation::FrameRel { offset } => {
                record(out, S_DEFRANGE_FRAMEPOINTER_REL, |out| {
                    out.i32(offset).u32(off_start).u16(isect).u16(cb);
                });
            }
            cv::CvLocation::RegRel { reg, offset, subfield_offset } => {
                let flags = match subfield_offset {
                    Some(sub) => cv::DEFRANGE_IS_SUBFIELD | (sub << cv::DEFRANGE_OFFSET_SHIFT),
                    None => 0,
                };
                record(out, S_DEFRANGE_REGISTER_REL, |out| {
                    out.u16(reg).u16(flags).i32(offset).u32(off_start).u16(isect).u16(cb);
                });
            }
            cv::CvLocation::RegRelIndir { reg, base_offset, udt_offset } => {
                record(out, S_DEFRANGE_REGISTER_REL_INDIR, |out| {
                    out.u16(reg)
                        .u16(0)
                        .i32(base_offset)
                        .i32(udt_offset)
                        .u32(off_start)
                        .u16(isect)
                        .u16(cb);
                });
            }
        }
        at += len;
    }
}

/// Splits line rows against inlined site boundaries so:
/// - `outer_rows` gets each non-inlined row as-is and each inlined sub-interval at the
///   outermost inlinee's call site (what CodeView `DEBUG_S_LINES` expects);
/// - each `S_INLINESITE` gets binary annotations mapping its code sub-intervals to its own
///   source lines (or its child's call site line for nested inlines);
/// - nested `S_INLINESITE` .. `S_INLINESITE_END` trees are emitted with valid `pParent`/`pEnd`.
fn emit_inlines_and_outer_rows(
    out: &mut Out,
    proc_at: usize,
    gproc_rel: usize,
    function: &Placed<'_>,
    rows: &[(u32, u32, u32)],
    sites: &[PreparedInline<'_>],
    outer_rows: &mut Vec<(u32, u32, u32)>,
) {
    let n = sites.len();
    // Collect all cut points: row starts + every inline range boundary, clamped to function.size.
    let mut cuts: Vec<u32> = Vec::with_capacity(rows.len() + n * 2 + 1);
    for &(at, _, _) in rows {
        if at < function.size {
            cuts.push(at);
        }
    }
    for site in sites {
        for &(from, to) in site.ranges {
            let from = from.min(function.size);
            let to = to.min(function.size);
            if from < to {
                cuts.push(from);
                cuts.push(to);
            }
        }
    }
    if function.size > 0 {
        cuts.push(function.size);
    }
    cuts.sort_unstable();
    cuts.dedup();

    // Per-site spans `(start, len, file_checksum_offset, line)`.
    let mut site_spans: Vec<Vec<(u32, u32, u32, u32)>> = vec![Vec::new(); n];
    let push_span = |spans: &mut Vec<(u32, u32, u32, u32)>, start: u32, len: u32, file: u32, line: u32| {
        match spans.last_mut() {
            Some(last) if last.0 + last.1 == start && last.2 == file && last.3 == line => {
                last.1 += len;
            }
            _ => spans.push((start, len, file, line)),
        }
    };
    let push_outer = |outer: &mut Vec<(u32, u32, u32)>, at: u32, file_idx: u32, line: u32| {
        if outer.last().is_none_or(|last| (last.1, last.2) != (file_idx, line)) {
            outer.push((at, file_idx, line));
        }
    };

    let mut row_cursor = 0usize;
    for pair in cuts.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        if a >= b {
            continue;
        }
        while row_cursor + 1 < rows.len() && rows[row_cursor + 1].0 <= a {
            row_cursor += 1;
        }
        let active_row = rows.get(row_cursor).copied().filter(|r| r.0 <= a);
        // Deepest inlined site covering `a` (children follow parents in `sites`).
        let innermost = (0..n).rev().find(|&i| sites[i].ranges.iter().any(|&(f, t)| a >= f && a < t));
        match innermost {
            None => {
                if let Some((_, file_idx, line)) = active_row {
                    push_outer(outer_rows, a, file_idx, line);
                }
            }
            Some(inner) => {
                // Walk up parent chain to find outermost site and attribute each ancestor to
                // its direct child's call site.
                let mut cur = inner;
                let (inner_file_id, inner_line) = match active_row {
                    Some((_, f, l)) => (f * 8, l),
                    None => (sites[inner].reg_file_id, sites[inner].reg_base_line),
                };
                push_span(&mut site_spans[inner], a, b - a, inner_file_id, inner_line);
                let mut steps = 0;
                while let Some(p) = sites[cur].parent.map(|p| p as usize).filter(|&p| p < cur) {
                    push_span(
                        &mut site_spans[p],
                        a,
                        b - a,
                        sites[cur].call_file_idx * 8,
                        sites[cur].call_line,
                    );
                    cur = p;
                    steps += 1;
                    if steps > n {
                        break;
                    }
                }
                push_outer(outer_rows, a, sites[cur].call_file_idx, sites[cur].call_line);
            }
        }
    }

    // Build parent -> children tree and emit nested S_INLINESITE .. S_INLINESITE_END.
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut roots: Vec<usize> = Vec::new();
    for (i, site) in sites.iter().enumerate() {
        match site.parent.map(|p| p as usize).filter(|&p| p < i) {
            Some(p) => children[p].push(i),
            None => roots.push(i),
        }
    }
    for root in roots {
        emit_inline_tree(out, proc_at, gproc_rel, root, sites, &site_spans, &children);
    }
}

fn emit_inline_tree(
    out: &mut Out,
    proc_at: usize,
    parent_rel: usize,
    idx: usize,
    sites: &[PreparedInline<'_>],
    site_spans: &[Vec<(u32, u32, u32, u32)>],
    children: &[Vec<usize>],
) {
    let site = &sites[idx];
    let spans = &site_spans[idx];
    if spans.is_empty() && children[idx].is_empty() {
        return;
    }
    let annotations = cv::encode_inline_annotations(site.reg_file_id, site.reg_base_line, spans);
    let site_rel = out.len();
    record(out, S_INLINESITE, |out| {
        out.u32((proc_at + parent_rel) as u32); // pParent
        out.u32(0); // pEnd (patched below)
        out.u32(site.inlinee_id); // Inlinee (IPI ItemId)
        out.bytes(&annotations);
    });
    for &child in &children[idx] {
        emit_inline_tree(out, proc_at, site_rel, child, sites, site_spans, children);
    }
    let end_rel = out.len();
    record(out, S_INLINESITE_END, |_| {});
    out.set_u32(site_rel + 8, (proc_at + end_rel) as u32);
}

/// A function's line table: a `DEBUG_S_LINES` subsection of its rows (`(offset, file, line)`,
/// by offset), each file's run a block.
fn line_table(out: &mut Out, function: &Placed<'_>, rows: &[(u32, u32, u32)]) {
    let size_at = out.len() + 4;
    out.u32(DEBUG_S_LINES).u32(0);
    let start = out.len();
    out.u32(function.offset).u16(function.section).u16(0).u32(function.size);
    for run in rows.chunk_by(|a, b| a.1 == b.1) {
        out.u32(run[0].1 * 8).u32(run.len() as u32).u32(12 + 8 * run.len() as u32);
        for &(at, _, line) in run {
            let line = match line {
                0 => NO_LINE,
                line => line.min(0xff_ffff),
            };
            out.u32(at).u32(line | STATEMENT);
        }
    }
    let size = out.len() - start;
    out.set_u32(size_at, size as u32);
}

/// A line slot's room past `len` bytes: none, or at least a subsection header.
fn line_cap(len: usize) -> usize {
    let cap = len + room(len, 16);
    if cap - len < 8 { len + 8 } else { cap }
}

/// A function's `S_PROCREF`: its procedure at `sym_at` of 1-based module `module`.
fn reference(out: &mut Out, sym_at: u32, module: u16, name: &str) {
    record(out, S_PROCREF, |out| {
        out.u32(0).u32(sym_at).u16(module).string(name);
    });
}

/// The functions `functions` as the image places them; an unnamed one is named by its
/// address.
fn place<'a>(headers: &Headers, functions: &'a [Func<'a>]) -> Result<Vec<Placed<'a>>, String> {
    let mut out = Vec::with_capacity(functions.len());
    for function in functions {
        if function.size == 0 {
            continue;
        }
        let Some((section, offset)) = headers.place(function.addr) else {
            // alloc: error path
            return Err(format!(
                "a function at {:#x} is in no section of the image: no PDB describes it",
                function.addr
            ));
        };
        let name = match function.name {
            Some(name) => std::borrow::Cow::Borrowed(name),
            // alloc: once per unnamed function placed
            None => std::borrow::Cow::Owned(format!("blaze_fn_{:x}", function.addr)),
        };
        out.push(Placed {
            key: function.key,
            name,
            section,
            offset,
            size: function.size as u32,
            lines: function.lines.start as usize..function.lines.end as usize,
            debug: function.debug,
            inlined: function.inlined.start as usize..function.inlined.end as usize,
        });
    }
    Ok(out)
}

impl Model {
    /// The PDB of the image whose headers are `headers` and build id `id`, of its Rust
    /// `functions`, `lines`, `inlined` sites (with `inline_ranges`), and of its native code's
    /// functions `natives` by name and address: laid out whole, with room to patch.
    pub(crate) fn new(
        headers: Headers,
        id: [u8; 16],
        functions: &[Func<'_>],
        lines: &[Lined<'_>],
        inlined: &[Inlined<'_>],
        inline_ranges: &[(u32, u32)],
        natives: &[(&str, u64)],
    ) -> Result<Model, String> {
        // alloc: below, once per PDB laid out whole: its streams and the model
        let placed = place(&headers, functions)?;
        let mut model = Model {
            headers,
            id,
            streams: vec![Vec::new(); STREAMS],
            blocks: vec![Vec::new(); STREAMS],
            count: 0,
            free: Vec::new(),
            directory: Vec::new(),
            block_map: 0,
            tpi: TypeTable::new(),
            ipi: TypeTable::new(),
            sym_end: 0,
            sym_cap: 0,
            files_at: 0,
            files_cap: 0,
            inlinees_hdr: 0,
            inlinees_cap: 0,
            c13_at: 0,
            c13_end: 0,
            c13_cap: 0,
            files: Vec::new(),
            file_of: HashMap::with_capacity_in(64, Global),
            inlinees: Vec::new(),
            inlinee_of: HashMap::new_in(Global),
            slots: Vec::with_capacity(placed.len()),
            spans: placed.iter().map(|it| (it.section, it.offset, it.size)).collect(),
            empty: functions.iter().filter(|it| it.size == 0).map(|it| it.key).collect(),
            natives: natives_hash(natives),
        };
        let row_files = model.files_of(lines);
        // Also intern every file referenced by inlined call sites and inlinee declarations.
        for site in inlined {
            model.intern_file(site.call_file);
            if let Some(decl) = site.decl_file {
                model.intern_file(decl);
            }
        }

        // Module 0 (`blaze`): symbols with room, file checksums with room, inlinee lines with
        // room, and per-function line tables with room.
        let names_len: usize = placed.iter().map(|it| it.name.len()).sum();
        let mut module =
            Out(Vec::with_capacity(names_len * 5 / 4 + 100 * placed.len() + 10 * lines.len()));
        module.u32(CV_SIGNATURE_C13);
        record(&mut module, S_OBJNAME, |out| {
            out.u32(0).string("blaze");
        });
        record(&mut module, S_COMPILE3, |out| {
            out.u32(CV_CFL_RUST).u16(CV_CFL_X64);
            for _ in 0..8 {
                out.u16(0);
            }
            out.string("blaze");
        });

        let mut syms = Vec::with_capacity(placed.len());
        let mut rows: Vec<(u32, u32, u32)> = Vec::new();
        let mut all_outer_rows: Vec<Vec<(u32, u32, u32)>> = Vec::with_capacity(placed.len());
        for function in &placed {
            Model::rows(lines, &row_files, function, &mut rows);
            let prepared_inlines =
                model.prepare_inlines(function, &rows, inlined, inline_ranges);
            let at = module.len();
            let mut outer = Vec::new();
            encode_procedure(
                &mut module,
                at,
                function,
                &rows,
                &prepared_inlines,
                &mut model.tpi,
                &mut outer,
            );
            syms.push((at as u32, (module.len() - at) as u32));
            all_outer_rows.push(outer);
        }
        model.sym_end = module.len();
        let sym_room = room(model.sym_end, 4096);
        module.0.resize(model.sym_end + sym_room, 0);
        model.sym_cap = module.len();
        skip(&mut module.0, model.sym_end, sym_room);

        // DEBUG_S_FILECHKSMS with room.
        model.files_cap = model.files.len() + room(model.files.len(), 64);
        module.u32(DEBUG_S_FILECHKSMS).u32(0);
        model.files_at = module.len();
        module.0.resize(model.files_at + model.files_cap * 8, 0);

        // DEBUG_S_INLINEELINES with room.
        model.inlinees_hdr = module.len();
        model.inlinees_cap = model.inlinees.len() + room(model.inlinees.len(), 32);
        module.0.resize(model.inlinees_hdr + 12 + model.inlinees_cap * 12, 0);

        // Per-function DEBUG_S_LINES slots with room.
        model.c13_at = module.len();
        let mut line_slots = Vec::with_capacity(placed.len());
        for (function, outer) in placed.iter().zip(&all_outer_rows) {
            if outer.is_empty() {
                line_slots.push((0, 0));
                continue;
            }
            let at = module.len();
            line_table(&mut module, function, outer);
            let len = module.len() - at;
            let cap = line_cap(len);
            module.0.resize(at + cap, 0);
            if cap > len {
                ignore(&mut module.0, at + len, cap - len);
            }
            line_slots.push((at as u32, cap as u32));
        }
        model.c13_end = module.len();
        let c13_room = room(model.c13_end - model.c13_at, 4096);
        module.0.resize(model.c13_end + c13_room, 0);
        model.c13_cap = module.len();
        ignore(&mut module.0, model.c13_end, c13_room);
        module.u32(0);
        model.streams[usize::from(MODULE)] = module.0;
        model.write_files();
        model.write_inlinees();

        // The symbol record stream: natives' publics, then Rust procedures' references.
        let mut records = Out::default();
        let mut publics = Vec::with_capacity(natives.len());
        for (name, addr) in natives {
            let Some((section, offset)) = model.headers.place(*addr) else { continue };
            let at = records.len() as u32;
            record(&mut records, S_PUB32, |out| {
                out.u32(PUBLIC_FUNCTION).u32(offset).u16(section).string(name);
            });
            publics.push((section, offset, *name, at));
        }
        for ((function, (sym_at, sym_cap)), (line_at, line_cap)) in
            placed.iter().zip(syms).zip(line_slots)
        {
            let ref_at = records.len() as u32;
            reference(&mut records, sym_at, 1, &function.name);
            let place = (function.section, function.offset, function.size);
            let slot = Slot {
                sym_at,
                sym_cap,
                line_at,
                line_cap,
                ref_at,
                name: function.name.clone().into_owned(),
                place,
            };
            model.slots.push((function.key, slot));
        }
        model.slots.sort_unstable_by_key(|it| it.0);
        model.spans.sort_unstable();
        model.empty.sort_unstable();
        model.empty.dedup();
        if model.slots.windows(2).any(|it| it[0].0 == it[1].0) {
            return Err("two functions of one key: no PDB describes both".into()); // alloc: error path
        }
        model.streams[usize::from(RECORDS)] = records.0;
        let hash = gsi(&publics.iter().map(|it| (it.2, it.3)).collect::<Vec<_>>());
        publics.sort_unstable_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)).then_with(|| a.2.cmp(b.2)));
        let mut stream = Out::default();
        stream.u32(hash.len() as u32).u32(publics.len() as u32 * 4);
        stream.u32(0).u32(0).u16(0).u16(0).u32(0).u32(0);
        stream.bytes(&hash);
        for it in &publics {
            stream.u32(it.3);
        }
        model.streams[usize::from(PUBLICS)] = stream.0;
        model.streams[usize::from(GLOBALS)] = model.globals();
        model.streams[usize::from(DBI)] = model.dbi();
        model.streams[usize::from(INFO)] = info(model.headers.stamp, &model.id);
        model.streams[usize::from(TPI)] = model.tpi.stream_bytes(TPI_HASH);
        model.streams[usize::from(TPI_HASH)] = model.tpi.hash_stream_bytes();
        model.streams[usize::from(IPI)] = model.ipi.stream_bytes(IPI_HASH);
        model.streams[usize::from(IPI_HASH)] = model.ipi.hash_stream_bytes();
        model.streams[usize::from(SECTION_HEADERS)] =
            model.headers.sections.iter().flatten().copied().collect();
        model.lay_out();
        Ok(model)
    }

    fn intern_file(&mut self, file: &str) -> u32 {
        if let Some(&n) = self.file_of.get(file) {
            return n;
        }
        let n = self.files.len() as u32;
        // alloc: once per file named
        self.files.push(file.to_owned());
        self.file_of.insert(file.to_owned(), n);
        n
    }

    /// Interns an inlinee `(inlinee_ipi_id, file_id, base_line)` into module 0's
    /// `DEBUG_S_INLINEELINES` table, returning the registered `(file_id, base_line)` (so all
    /// `S_INLINESITE`s for one inlinee share the same base file/line in the module).
    fn intern_inlinee(&mut self, inlinee_id: u32, file_id: u32, base_line: u32) -> (u32, u32) {
        if let Some(&idx) = self.inlinee_of.get(&inlinee_id) {
            let (_, reg_file, reg_line) = self.inlinees[idx];
            return (reg_file, reg_line);
        }
        let idx = self.inlinees.len();
        self.inlinees.push((inlinee_id, file_id, base_line));
        self.inlinee_of.insert(inlinee_id, idx);
        (file_id, base_line)
    }

    fn prepare_inlines<'a>(
        &mut self,
        function: &Placed<'_>,
        rows: &[(u32, u32, u32)],
        inlined: &[Inlined<'_>],
        inline_ranges: &'a [(u32, u32)],
    ) -> Vec<PreparedInline<'a>> {
        if function.inlined.is_empty() {
            return Vec::new();
        }
        let sites = &inlined[function.inlined.clone()];
        let void_proc = self.tpi.intern_procedure(cv::T_VOID, &[]);
        let mut out = Vec::with_capacity(sites.len());
        for site in sites {
            let call_file_idx = self.intern_file(site.call_file);
            let ranges = &inline_ranges[site.ranges.start as usize..site.ranges.end as usize];
            let inlinee_id = self.ipi.intern_func_id(void_proc, site.callee);
            // Prefer the inlinee's declaration file & line; fall back to its first row inside
            // its ranges, then its call site.
            let (base_file_idx, base_line) = match site.decl_file {
                Some(decl_file) => (self.intern_file(decl_file), site.decl_line),
                None => rows
                    .iter()
                    .find(|&&(at, _, _)| ranges.iter().any(|&(f, t)| at >= f && at < t))
                    .map(|&(_, f, l)| (f, l))
                    .unwrap_or((call_file_idx, site.call_line)),
            };
            let (reg_file_id, reg_base_line) =
                self.intern_inlinee(inlinee_id, base_file_idx * 8, base_line);
            out.push(PreparedInline {
                parent: site.parent,
                inlinee_id,
                reg_file_id,
                reg_base_line,
                call_file_idx,
                call_line: site.call_line,
                ranges,
            });
        }
        out
    }

    /// Each row's file, the files each once in the order first named, added to the model's.
    fn files_of(&mut self, lines: &[Lined<'_>]) -> Vec<u32> {
        let mut row_files = Vec::with_capacity(lines.len());
        let mut last: Option<(&str, u32)> = None;
        for row in lines {
            let n = match last {
                Some((file, n)) if std::ptr::eq(file, row.file) || file == row.file => n,
                _ => self.intern_file(row.file),
            };
            last = Some((row.file, n));
            row_files.push(n);
        }
        row_files
    }

    /// `function`'s rows as `(offset, file, line)`, by offset, into `rows`.
    fn rows(
        lines: &[Lined<'_>],
        row_files: &[u32],
        function: &Placed<'_>,
        rows: &mut Vec<(u32, u32, u32)>,
    ) {
        rows.clear();
        rows.extend(function.lines.clone().map(|at| (lines[at].at, row_files[at], lines[at].line)));
        if !rows.is_sorted_by_key(|it| it.0) {
            rows.sort_by_key(|it| it.0);
        }
    }

    /// The files' entries and `/names`: each a name in `/names` and no checksum, then the room
    /// as one subsection to step over.
    fn write_files(&mut self) {
        let files: Vec<&str> = self.files.iter().map(String::as_str).collect();
        let (names, offsets) = string_table(&files);
        let module = &mut self.streams[usize::from(MODULE)];
        let at = self.files_at;
        module[at - 4..at].copy_from_slice(&(offsets.len() as u32 * 8).to_le_bytes());
        for (n, offset) in offsets.iter().enumerate() {
            module[at + 8 * n..at + 8 * n + 4].copy_from_slice(&offset.to_le_bytes());
            module[at + 8 * n + 4..at + 8 * n + 8].fill(0);
        }
        let used = at + 8 * offsets.len();
        let end = at + 8 * self.files_cap;
        if end > used {
            ignore(module, used, end - used);
        }
        self.streams[usize::from(NAMES)] = names;
    }

    /// Module 0's `DEBUG_S_INLINEELINES` subsection and its trailing `DEBUG_S_IGNORE` room.
    fn write_inlinees(&mut self) {
        let module = &mut self.streams[usize::from(MODULE)];
        let hdr = self.inlinees_hdr;
        let region_end = hdr + 12 + self.inlinees_cap * 12;
        if self.inlinees.is_empty() {
            ignore(module, hdr, region_end - hdr);
            return;
        }
        let body_len = 4 + 12 * self.inlinees.len() as u32;
        module[hdr..hdr + 4].copy_from_slice(&DEBUG_S_INLINEELINES.to_le_bytes());
        module[hdr + 4..hdr + 8].copy_from_slice(&body_len.to_le_bytes());
        module[hdr + 8..hdr + 12].copy_from_slice(&0u32.to_le_bytes()); // CV_INLINEE_SOURCE_LINE_SIGNATURE
        for (i, &(inlinee, file_id, line)) in self.inlinees.iter().enumerate() {
            let at = hdr + 12 + 12 * i;
            module[at..at + 4].copy_from_slice(&inlinee.to_le_bytes());
            module[at + 4..at + 8].copy_from_slice(&file_id.to_le_bytes());
            module[at + 8..at + 12].copy_from_slice(&line.to_le_bytes());
        }
        let used = hdr + 12 + 12 * self.inlinees.len();
        if region_end > used {
            ignore(module, used, region_end - used);
        }
    }

    /// The globals: a hash of every procedure's reference.
    fn globals(&self) -> Vec<u8> {
        let refs: Vec<(&str, u32)> =
            self.slots.iter().map(|(_, it)| (it.name.as_str(), it.ref_at)).collect();
        gsi(&refs)
    }

    /// DBI: the module, its section contributions (runs of its procedures that touch), the
    /// section map, its files, the EC names and the debug header naming the section headers.
    fn dbi(&self) -> Vec<u8> {
        let mut runs: Vec<(u16, u32, u32)> = Vec::new();
        for &(section, offset, size) in &self.spans {
            match runs.last_mut() {
                Some(last) if last.0 == section && last.1 + last.2 >= offset => {
                    last.2 = last.2.max(offset + size - last.1);
                }
                _ => runs.push((section, offset, size)),
            }
        }
        let headers = &self.headers;
        let characteristics = |section: u16| {
            headers.sections.get(usize::from(section) - 1).map_or(0, |it| u32_at(it, 36))
        };
        let contribution = |out: &mut Out, (section, offset, size): (u16, u32, u32)| {
            out.u16(section).u16(0).u32(offset).u32(size);
            out.u32(if section == NONE { 0 } else { characteristics(section) });
            out.u16(0).u16(0).u32(0).u32(0);
        };
        let file_count = self.files.len().min(usize::from(u16::MAX)) as u16;
        let mut modules = Out::default();
        modules.u32(0);
        contribution(&mut modules, runs.first().copied().unwrap_or((NONE, 0, 0)));
        modules.u16(0).u16(MODULE).u32(self.sym_cap as u32).u32(0).u32((self.c13_cap - self.sym_cap) as u32);
        modules.u16(file_count).u16(0).u32(0).u32(0).u32(0);
        modules.string("blaze").string("blaze").align(4);

        let mut contributions = Out::default();
        contributions.u32(0xeffe_0000 + 19970605);
        for run in &runs {
            contribution(&mut contributions, *run);
        }

        let count = headers.sections.len() as u16 + 1;
        let mut map = Out::default();
        map.u16(count).u16(count);
        for (n, header) in headers.sections.iter().enumerate() {
            let flags = u32_at(header, 36);
            let mut it = 0x100 | 0x8;
            if flags & 0x4000_0000 != 0 {
                it |= 1;
            }
            if flags & 0x8000_0000 != 0 {
                it |= 2;
            }
            if flags & 0x2000_0000 != 0 {
                it |= 4;
            }
            map.u16(it)
                .u16(0)
                .u16(0)
                .u16(n as u16 + 1)
                .u16(NONE)
                .u16(NONE)
                .u32(0)
                .u32(u32_at(header, 8));
        }
        map.u16(0x208).u16(0).u16(0).u16(count).u16(NONE).u16(NONE).u32(0).u32(u32::MAX);

        let mut sources = Out::default();
        sources.u16(1).u16(file_count).u16(0).u16(file_count);
        let mut source_names = Out::default();
        for it in &self.files {
            sources.u32(source_names.len() as u32);
            source_names.string(it);
        }
        sources.bytes(&source_names.0).align(4);

        let (ec, _) = string_table(&[]);
        let mut optional = Out::default();
        for n in 0..11 {
            optional.u16(if n == 5 { SECTION_HEADERS } else { NONE });
        }

        let mut dbi = Out::default();
        dbi.u32(u32::MAX).u32(19990903).u32(1);
        dbi.u16(GLOBALS).u16(0x8000 | 14 << 8 | 11).u16(PUBLICS).u16(0).u16(RECORDS).u16(0);
        dbi.u32(modules.len() as u32).u32(contributions.len() as u32).u32(map.len() as u32);
        dbi.u32(sources.len() as u32).u32(0).u32(0).u32(optional.len() as u32).u32(ec.len() as u32);
        dbi.u16(0).u16(0x8664).u32(0);
        dbi.bytes(&modules.0).bytes(&contributions.0).bytes(&map.0).bytes(&sources.0);
        dbi.bytes(&ec).bytes(&optional.0);
        dbi.0
    }

    /// Takes a block for a stream: a free one, else the next past the file's end that is no
    /// interval's free block map.
    fn take(&mut self) -> u32 {
        if let Some(it) = self.free.pop() {
            return it;
        }
        while is_map(self.count as usize) {
            self.count += 1;
        }
        self.count += 1;
        self.count - 1
    }

    /// Every stream's blocks, the directory and the block map, from scratch: stream 1 at
    /// [`INFO_BLOCK`].
    fn lay_out(&mut self) {
        self.count = INFO_BLOCK as u32;
        self.free.clear();
        let nstreams = self.streams.len();
        let order = std::iter::once(1).chain((0..nstreams).filter(|it| *it != 1));
        for n in order {
            let need = self.streams[n].len().div_ceil(BLOCK);
            self.blocks[n] = (0..need).map(|_| self.take()).collect();
        }
        let need = self.directory_bytes().len().div_ceil(BLOCK);
        self.directory = (0..need).map(|_| self.take()).collect();
        self.block_map = self.take();
        self.close_interval();
    }

    /// Every interval the file reaches has its free block maps in the file.
    fn close_interval(&mut self) {
        let last = (self.count as usize - 1) / BLOCK;
        self.count = self.count.max((last * BLOCK + 3) as u32);
    }

    fn directory_bytes(&self) -> Vec<u8> {
        let mut out = Out::default();
        out.u32(self.streams.len() as u32);
        for it in &self.streams {
            out.u32(it.len() as u32);
        }
        for it in &self.blocks {
            for block in it {
                out.u32(*block);
            }
        }
        out.0
    }

    /// The free block maps' bytes of interval `k`: a bit per block, set for a free one.
    fn map_block(&self, k: usize) -> Vec<u8> {
        let mut bits = vec![0xffu8; BLOCK];
        let count = self.count as usize;
        for (n, byte) in bits.iter_mut().enumerate() {
            let first = (k * BLOCK + n) * 8;
            if first >= count {
                break;
            }
            for bit in 0..8 {
                if first + bit < count {
                    *byte &= !(1 << bit);
                }
            }
        }
        for it in &self.free {
            let (n, bit) = (*it as usize / 8, *it as usize % 8);
            if n / BLOCK == k {
                bits[n % BLOCK] |= 1 << bit;
            }
        }
        bits
    }

    fn superblock(&self, directory: usize) -> Vec<u8> {
        let mut head = Out::default();
        head.bytes(MAGIC).u32(BLOCK as u32).u32(1).u32(self.count).u32(directory as u32);
        head.u32(0).u32(self.block_map);
        head.0
    }

    /// The whole file.
    pub(crate) fn file(&self) -> Vec<u8> {
        let mut file = vec![0u8; self.count as usize * BLOCK];
        let mut put = |block: u32, bytes: &[u8]| {
            let at = block as usize * BLOCK;
            file[at..at + bytes.len()].copy_from_slice(bytes);
        };
        for (stream, blocks) in self.streams.iter().zip(&self.blocks) {
            for (chunk, block) in stream.chunks(BLOCK).zip(blocks) {
                put(*block, chunk);
            }
        }
        let directory = self.directory_bytes();
        for (chunk, block) in directory.chunks(BLOCK).zip(&self.directory) {
            put(*block, chunk);
        }
        let map: Vec<u8> = self.directory.iter().flat_map(|it| it.to_le_bytes()).collect();
        put(self.block_map, &map);
        for k in 0..=(self.count as usize - 1) / BLOCK {
            let bits = self.map_block(k);
            put((k * BLOCK + 1) as u32, &bits);
            put((k * BLOCK + 2) as u32, &bits);
        }
        put(0, &self.superblock(directory.len()));
        file
    }

    /// Brings the PDB to a link's change: `functions` (with `lines`, `inlined`, `inline_ranges`)
    /// are those the link added or changed, `gone` those it removed, `count` how many the image
    /// has now; `natives` the native functions when they may have changed.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn patch(
        &mut self,
        headers: Headers,
        id: [u8; 16],
        functions: &[Func<'_>],
        lines: &[Lined<'_>],
        inlined: &[Inlined<'_>],
        inline_ranges: &[(u32, u32)],
        gone: &[InstanceKey],
        count: usize,
        natives: Option<&[(&str, u64)]>,
    ) -> Result<Result<Vec<(u64, Vec<u8>)>, Whole>, String> {
        if !same_virtual_sections(&self.headers.sections, &headers.sections)
            || headers.base != self.headers.base
        {
            return Ok(Err("the image's sections moved"));
        }
        if natives.is_some_and(|it| natives_hash(it) != self.natives) {
            return Ok(Err("the native code's functions changed"));
        }
        let placed = place(&headers, functions)?;
        // alloc: below, once per patch: the edit's records and the stream ranges written
        let mut dirty: Vec<(usize, std::ops::Range<usize>)> = Vec::new();
        let files_before = self.files.len();
        let inlinees_before = self.inlinees.len();
        let tpi_bytes_before = self.tpi.record_bytes();
        let ipi_bytes_before = self.ipi.record_bytes();
        let records_before = self.streams[usize::from(RECORDS)].len();
        let directory_before = self.directory_bytes();
        let row_files = self.files_of(lines);
        for site in inlined {
            self.intern_file(site.call_file);
            if let Some(decl) = site.decl_file {
                self.intern_file(decl);
            }
        }
        if self.files.len() > self.files_cap {
            return Ok(Err("the files' entries have no room"));
        }
        let mut names_changed = false;
        let mut refs_changed = false;
        for key in gone {
            if let Ok(at) = self.empty.binary_search(key) {
                self.empty.remove(at);
                continue;
            }
            let Ok(at) = self.slots.binary_search_by_key(key, |it| it.0) else {
                return Ok(Err("a function the link removed has no record"));
            };
            self.drop_slot(at, &mut dirty);
            names_changed = true;
        }
        for function in functions.iter().filter(|it| it.size == 0) {
            if let Ok(at) = self.slots.binary_search_by_key(&function.key, |it| it.0) {
                self.drop_slot(at, &mut dirty);
                names_changed = true;
            }
            if let Err(at) = self.empty.binary_search(&function.key) {
                self.empty.insert(at, function.key);
            }
        }
        for function in &placed {
            if let Ok(at) = self.empty.binary_search(&function.key) {
                self.empty.remove(at);
            }
        }
        let mut rows = Vec::new();
        let mut outer_rows = Vec::new();
        let mut out = Out::default();
        for function in &placed {
            Model::rows(lines, &row_files, function, &mut rows);
            let prepared_inlines =
                self.prepare_inlines(function, &rows, inlined, inline_ranges);
            if self.inlinees.len() > self.inlinees_cap {
                return Ok(Err("the inlinee lines have no room"));
            }
            let found = self.slots.binary_search_by_key(&function.key, |it| it.0);
            let old = found
                .ok()
                .map(|at| (self.slots[at].1.sym_at as usize, self.slots[at].1.sym_cap as usize));
            let guess_at = old.map_or(self.sym_end, |it| it.0);
            out.0.clear();
            encode_procedure(
                &mut out,
                guess_at,
                function,
                &rows,
                &prepared_inlines,
                &mut self.tpi,
                &mut outer_rows,
            );
            let module = &mut self.streams[usize::from(MODULE)];
            let (sym_at, sym_cap) = match old {
                Some((at, cap)) if out.len() <= cap => {
                    if out.len() < cap {
                        let used = out.len();
                        out.0.resize(cap, 0);
                        skip(&mut out.0, used, cap - used);
                    }
                    (at, cap)
                }
                _ => {
                    if let Some((at, cap)) = old {
                        skip(module, at, cap);
                        dirty.push((usize::from(MODULE), at..at + cap));
                    }
                    if self.sym_end + out.len() + 4 > self.sym_cap {
                        return Ok(Err("the module's symbols have no room"));
                    }
                    let at = self.sym_end;
                    if at != guess_at {
                        out.0.clear();
                        encode_procedure(
                            &mut out,
                            at,
                            function,
                            &rows,
                            &prepared_inlines,
                            &mut self.tpi,
                            &mut outer_rows,
                        );
                    }
                    let cap = out.len();
                    self.sym_end += cap;
                    skip(module, self.sym_end, self.sym_cap - self.sym_end);
                    dirty.push((usize::from(MODULE), self.sym_end..self.sym_end + 4));
                    (at, cap)
                }
            };
            if module[sym_at..sym_at + sym_cap] != out.0[..] {
                module[sym_at..sym_at + sym_cap].copy_from_slice(&out.0);
                dirty.push((usize::from(MODULE), sym_at..sym_at + sym_cap));
            }
            // The line table: in its slot when it fits, else at the start of the room.
            let old_lines = found
                .ok()
                .map(|at| (self.slots[at].1.line_at as usize, self.slots[at].1.line_cap as usize));
            let (line_at, line_cap) = if outer_rows.is_empty() {
                if let Some((at, cap)) = old_lines.filter(|it| it.1 != 0) {
                    ignore(module, at, cap);
                    dirty.push((usize::from(MODULE), at..at + cap));
                }
                (0, 0)
            } else {
                out.0.clear();
                line_table(&mut out, function, &outer_rows);
                let len = out.len();
                let (at, cap) = match old_lines {
                    Some((at, cap)) if cap != 0 && (len == cap || len + 8 <= cap) => (at, cap),
                    _ => {
                        if let Some((at, cap)) = old_lines.filter(|it| it.1 != 0) {
                            ignore(module, at, cap);
                            dirty.push((usize::from(MODULE), at..at + cap));
                        }
                        let cap = line_cap(len);
                        if self.c13_end + cap + 8 > self.c13_cap {
                            return Ok(Err("the module's line tables have no room"));
                        }
                        let at = self.c13_end;
                        self.c13_end += cap;
                        ignore(module, self.c13_end, self.c13_cap - self.c13_end);
                        dirty.push((usize::from(MODULE), self.c13_end..self.c13_end + 8));
                        (at, cap)
                    }
                };
                module[at..at + len].copy_from_slice(&out.0);
                if cap > len {
                    ignore(module, at + len, cap - len);
                }
                dirty.push((usize::from(MODULE), at..at + cap));
                (at as u32, cap as u32)
            };
            // Its reference: in place when the name is the same, else a new one.
            match found {
                Ok(at) => {
                    let slot = &mut self.slots[at].1;
                    if slot.name != function.name {
                        names_changed = true;
                        refs_changed = true;
                        slot.name = function.name.clone().into_owned();
                        slot.ref_at = Model::push_reference(
                            &mut self.streams[usize::from(RECORDS)],
                            sym_at as u32,
                            1,
                            &slot.name,
                        );
                    } else if slot.sym_at != sym_at as u32 {
                        let records = &mut self.streams[usize::from(RECORDS)];
                        let at = slot.ref_at as usize + 8;
                        records[at..at + 4].copy_from_slice(&(sym_at as u32).to_le_bytes());
                        dirty.push((usize::from(RECORDS), at..at + 4));
                    }
                    slot.sym_at = sym_at as u32;
                    slot.sym_cap = sym_cap as u32;
                    let (old, new) = (slot.place, (function.section, function.offset, function.size));
                    slot.place = new;
                    slot.line_at = line_at;
                    slot.line_cap = line_cap;
                    if old != new {
                        self.unspan(old);
                        self.span(new);
                    }
                }
                Err(at) => {
                    names_changed = true;
                    refs_changed = true;
                    let name = function.name.clone().into_owned();
                    let ref_at = Model::push_reference(
                        &mut self.streams[usize::from(RECORDS)],
                        sym_at as u32,
                        1,
                        &name,
                    );
                    let place = (function.section, function.offset, function.size);
                    self.slots.insert(
                        at,
                        (
                            function.key,
                            Slot {
                                sym_at: sym_at as u32,
                                sym_cap: sym_cap as u32,
                                line_at,
                                line_cap,
                                ref_at,
                                name,
                                place,
                            },
                        ),
                    );
                    self.span(place);
                }
            }
        }
        if self.slots.len() + self.empty.len() != count {
            return Ok(Err("the records number other than the image's functions"));
        }
        if self.files.len() != files_before {
            self.write_files();
            dirty.push((usize::from(MODULE), self.files_at - 4..self.files_at + 8 * self.files_cap));
        }
        if self.inlinees.len() != inlinees_before {
            self.write_inlinees();
            let region_end = self.inlinees_hdr + 12 + self.inlinees_cap * 12;
            dirty.push((usize::from(MODULE), self.inlinees_hdr..region_end));
        }

        // The tables made of every function: the globals when the names changed; DBI when a
        // contribution or a file did; the embedded PE section headers when a compact section's
        // raw size or file offset grew in place; TPI/IPI when new types or inlinees were added.
        let mut whole_streams: Vec<usize> = Vec::new();
        let mut resized: Vec<usize> = Vec::new();
        let sections_changed = headers.sections != self.headers.sections;
        if sections_changed {
            self.streams[usize::from(SECTION_HEADERS)] =
                headers.sections.iter().flatten().copied().collect();
            whole_streams.push(usize::from(SECTION_HEADERS));
        }
        self.headers = headers;

        // TPI and IPI: append-only, so unchanged edits write zero bytes to either stream or
        // their hash streams. When new types/inlinees were interned, update only the 56-byte
        // header, appended tail and companion hash stream.
        if self.tpi.record_bytes() != tpi_bytes_before {
            let header = self.tpi.header(TPI_HASH);
            let stream = &mut self.streams[usize::from(TPI)];
            stream[..56].copy_from_slice(&header);
            let old_len = stream.len();
            stream.extend_from_slice(self.tpi.tail_since(tpi_bytes_before));
            let new_len = stream.len();
            resized.push(usize::from(TPI));
            dirty.push((usize::from(TPI), 0..56));
            dirty.push((usize::from(TPI), old_len..new_len));
            self.streams[usize::from(TPI_HASH)] = self.tpi.hash_stream_bytes();
            whole_streams.push(usize::from(TPI_HASH));
        }
        if self.ipi.record_bytes() != ipi_bytes_before {
            let header = self.ipi.header(IPI_HASH);
            let stream = &mut self.streams[usize::from(IPI)];
            stream[..56].copy_from_slice(&header);
            let old_len = stream.len();
            stream.extend_from_slice(self.ipi.tail_since(ipi_bytes_before));
            let new_len = stream.len();
            resized.push(usize::from(IPI));
            dirty.push((usize::from(IPI), 0..56));
            dirty.push((usize::from(IPI), old_len..new_len));
            self.streams[usize::from(IPI_HASH)] = self.ipi.hash_stream_bytes();
            whole_streams.push(usize::from(IPI_HASH));
        }
        if names_changed || refs_changed {
            self.streams[usize::from(GLOBALS)] = self.globals();
            whole_streams.push(usize::from(GLOBALS));
        }
        let dbi = self.dbi();
        if dbi != self.streams[usize::from(DBI)] {
            self.streams[usize::from(DBI)] = dbi;
            whole_streams.push(usize::from(DBI));
        }
        if self.files.len() != files_before {
            whole_streams.push(usize::from(NAMES));
        }
        let records = self.streams[usize::from(RECORDS)].len();
        if records != records_before {
            resized.push(usize::from(RECORDS));
            dirty.push((usize::from(RECORDS), records_before..records));
        }
        if id != self.id {
            self.id = id;
            self.streams[usize::from(INFO)] = info(self.headers.stamp, &id);
            whole_streams.push(usize::from(INFO));
        }
        Ok(Ok(self.writes(dirty, whole_streams, resized, directory_before)))
    }

    /// Takes out the slots of `self.slots[at]`: its procedure stepped over, its line table
    /// ignored, its place unspanned; its reference left unreferenced.
    fn drop_slot(&mut self, at: usize, dirty: &mut Vec<(usize, std::ops::Range<usize>)>) {
        let (_, slot) = self.slots.remove(at);
        self.unspan(slot.place);
        let module = &mut self.streams[usize::from(MODULE)];
        skip(module, slot.sym_at as usize, slot.sym_cap as usize);
        dirty.push((
            usize::from(MODULE),
            slot.sym_at as usize..(slot.sym_at + slot.sym_cap) as usize,
        ));
        if slot.line_cap != 0 {
            ignore(module, slot.line_at as usize, slot.line_cap as usize);
            dirty.push((
                usize::from(MODULE),
                slot.line_at as usize..(slot.line_at + slot.line_cap) as usize,
            ));
        }
    }

    fn span(&mut self, place: (u16, u32, u32)) {
        let at = self.spans.partition_point(|it| *it < place);
        self.spans.insert(at, place);
    }

    fn unspan(&mut self, place: (u16, u32, u32)) {
        let at = self.spans.partition_point(|it| *it < place);
        debug_assert_eq!(self.spans.get(at), Some(&place), "a procedure's place is spanned");
        self.spans.remove(at);
    }

    /// Appends a reference to the symbol record stream: its offset.
    fn push_reference(records: &mut Vec<u8>, sym_at: u32, module: u16, name: &str) -> u32 {
        let at = records.len() as u32;
        let mut out = Out(std::mem::take(records));
        reference(&mut out, sym_at, module, name);
        *records = out.0;
        at
    }

    /// The file's writes for `dirty` ranges of streams, `whole` streams written anew and
    /// `resized` ones (each may have grown or shrunk): each stream's blocks made to fit it,
    /// and the directory, block map, free block maps and superblock when the directory the
    /// file holds (`directory_before`) is not the streams' any more.
    fn writes(
        &mut self,
        mut dirty: Vec<(usize, std::ops::Range<usize>)>,
        whole: Vec<usize>,
        resized: Vec<usize>,
        directory_before: Vec<u8>,
    ) -> Vec<(u64, Vec<u8>)> {
        let count_before = self.count;
        for n in whole.iter().chain(&resized) {
            let need = self.streams[*n].len().div_ceil(BLOCK);
            while self.blocks[*n].len() > need {
                let it = self.blocks[*n].pop().unwrap();
                self.free.push(it);
            }
            while self.blocks[*n].len() < need {
                let it = self.take();
                self.blocks[*n].push(it);
            }
        }
        for n in &whole {
            dirty.push((*n, 0..self.streams[*n].len()));
        }
        // alloc: once per patch, the writes
        let mut writes: Vec<(u64, Vec<u8>)> = Vec::new();
        dirty.sort_unstable_by_key(|it| (it.0, it.1.start));
        let mut merged: Vec<(usize, std::ops::Range<usize>)> = Vec::new();
        for (n, range) in dirty {
            match merged.last_mut() {
                Some((m, last)) if *m == n && range.start <= last.end => {
                    last.end = last.end.max(range.end);
                }
                _ => merged.push((n, range)),
            }
        }
        for (n, range) in merged {
            let stream = &self.streams[n];
            let mut at = range.start;
            while at < range.end.min(stream.len()) {
                let block = self.blocks[n][at / BLOCK] as usize;
                let end = range.end.min((at / BLOCK + 1) * BLOCK).min(stream.len());
                writes.push(((block * BLOCK + at % BLOCK) as u64, stream[at..end].to_vec()));
                at = end;
            }
        }
        let directory = self.directory_bytes();
        if directory != directory_before || self.count != count_before {
            let need = directory.len().div_ceil(BLOCK);
            if need != self.directory.len() {
                self.free.extend(self.directory.drain(..));
                self.free.push(self.block_map);
                self.directory = (0..need).map(|_| self.take()).collect();
                self.block_map = self.take();
            }
            self.close_interval();
            for (chunk, block) in directory.chunks(BLOCK).zip(&self.directory) {
                writes.push((*block as u64 * BLOCK as u64, chunk.to_vec()));
            }
            let map: Vec<u8> = self.directory.iter().flat_map(|it| it.to_le_bytes()).collect();
            writes.push((u64::from(self.block_map) * BLOCK as u64, map));
            for k in 0..=(self.count as usize - 1) / BLOCK {
                let bits = self.map_block(k);
                writes.push(((k * BLOCK + 1) as u64 * BLOCK as u64, bits.clone()));
                writes.push(((k * BLOCK + 2) as u64 * BLOCK as u64, bits));
            }
            writes.push((0, self.superblock(directory.len())));
        }
        writes.sort_unstable_by_key(|it| it.0);
        writes
    }

    /// The file's length.
    pub(crate) fn len(&self) -> u64 {
        u64::from(self.count) * BLOCK as u64
    }

    /// The bytes it holds.
    pub(crate) fn held(&self) -> u64 {
        (self.streams.iter().map(Vec::capacity).sum::<usize>()
            + self.tpi.held()
            + self.ipi.held()
            + self
                .slots
                .iter()
                .map(|it| size_of::<(InstanceKey, Slot)>() + it.1.name.capacity())
                .sum::<usize>()) as u64
    }
}

/// Whether block `n` is one of an interval's free block maps.
fn is_map(n: usize) -> bool {
    matches!(n % BLOCK, 1 | 2)
}

#[cfg(test)]
mod tests;
