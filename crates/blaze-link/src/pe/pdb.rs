//! An image's PDB (docs/v2/plan/design/pdb.md): what std's backtrace (dbghelp), cdb and
//! Visual Studio read a Windows program's function names and lines from. It is the side file
//! of a PE image ([`crate::beside`]): named `<stem>.pdb` by the image's CodeView record, which
//! carries the image's build id as its GUID and age 1, as the PDB's info stream does.
//!
//! An MSF 7.0 file of 4 KiB blocks: the superblock, the two free block maps of each interval,
//! the streams, then the stream directory and the block that lists the directory's blocks.
//! The PDB info stream is always block 3, so the build id is at a fixed place
//! ([`GUID_AT`]). Its streams:
//!
//! - the PDB info stream, naming `/names`;
//! - TPI and IPI with no records: procedures say type 0, and there are no locals;
//! - DBI: one module, `blaze`, of every Rust function, its section contributions, the section
//!   map, its files, and the image's section headers as a stream of their own;
//! - the module's stream: `S_OBJNAME`, `S_COMPILE3` (Rust), an `S_GPROC32` and `S_END` per
//!   function, then the C13 subsections, its files' entries and a line table per function;
//! - globals (an `S_PROCREF` per Rust function) and publics (an `S_PUB32` per native
//!   function, with their hash and address map), whose records are in the symbol record
//!   stream; a Rust function needs no public (dbghelp and cdb find it by its procedure);
//! - `/names`, the file names.
//!
//! Native code's own debug info (`.debug$S`) is not merged: its functions are publics alone,
//! named as its objects name them.
//!
//! A link's change patches the file ([`Model::patch`], docs/v2/plan/design/pdb.md): each
//! function's procedure and line table are a slot in the module stream, with room after the
//! last (an `S_SKIP`, a `DEBUG_S_IGNORE`), so an edit rewrites its own slots in place, or
//! moves them into the room and leaves its old ones to be stepped over; the tables made of
//! every function are written again only when what they are made of changed.

use blaze_codegen::InstanceKey;

use crate::beside::{Func, Lined};

pub(crate) const BLOCK: usize = 4096;
const MAGIC: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";

/// The PDB info stream's first block: after the superblock and the first interval's two free
/// block maps.
const INFO_BLOCK: usize = 3;
/// Where the PDB holds its GUID, the build id: the info stream's version, signature and age
/// come first.
pub(crate) const GUID_AT: usize = INFO_BLOCK * BLOCK + 12;

// Stream numbers.
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

// Symbol record kinds (cvinfo.h).
const S_END: u16 = 0x0006;
const S_OBJNAME: u16 = 0x1101;
const S_PUB32: u16 = 0x110e;
const S_GPROC32: u16 = 0x1110;
const S_PROCREF: u16 = 0x1125;
const S_COMPILE3: u16 = 0x113c;
const CV_CFL_RUST: u32 = 0x15;
const CV_CFL_X64: u16 = 0xd0;
const CV_SIGNATURE_C13: u32 = 4;
const DEBUG_S_LINES: u32 = 0xf2;
const DEBUG_S_FILECHKSMS: u32 = 0xf4;
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
    fn place(&self, addr: u64) -> Option<(u16, u32)> {
        let rva = addr.checked_sub(self.base).unwrap_or(addr);
        self.sections.iter().enumerate().find_map(|(n, it)| {
            let size = u64::from(u32_at(it, 8)).max(u64::from(u32_at(it, 16)));
            let start = u64::from(u32_at(it, 12));
            (start..start + size).contains(&rva).then(|| ((n + 1) as u16, (rva - start) as u32))
        })
    }
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
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

/// A TPI or IPI stream of no records, its hash in the (empty) stream `hash`.
fn types(hash: u16) -> Vec<u8> {
    let mut out = Out::default();
    out.u32(20040203).u32(56).u32(0x1000).u32(0x1000).u32(0);
    out.u16(hash).u16(NONE).u32(4).u32(0x3ffff);
    for _ in 0..6 {
        out.u32(0);
    }
    out.0
}

/// A GSI hash of `records`, each `(name, offset in the symbol record stream)`: the records by
/// bucket (counted into place), each bucket in the readers' order of names.
fn gsi(records: &[(&str, u32)]) -> Vec<u8> {
    let bucket_of: Vec<u16> =
        records.iter().map(|(name, _)| (hash_v1(name.as_bytes()) as usize % GSI_BUCKETS) as u16).collect();
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
    let mut out = Out(Vec::with_capacity(16 + 8 * records.len() + 4 * (bitmap.len() + offsets.len())));
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
    // Bytes that are the same are the same without case: from the first that differs.
    match x.iter().zip(y).position(|(p, q)| p != q) {
        None => Ordering::Equal,
        Some(at) => (x[at..].iter().map(u8::to_ascii_lowercase)).cmp(y[at..].iter().map(u8::to_ascii_lowercase)),
    }
}
/// A function as the PDB places it: its name, section, offset and size, and its rows (indexes
/// into the rows given).
struct Placed<'a> {
    key: InstanceKey,
    name: std::borrow::Cow<'a, str>,
    section: u16,
    offset: u32,
    size: u32,
    lines: std::ops::Range<usize>,
}

/// Where a function's records are in the PDB last given: its procedure and `S_END` in the
/// module stream, its line table with the room after it, and its `S_PROCREF` in the symbol
/// record stream.
#[derive(Clone, Debug)] // clone: tests' models
struct Slot {
    sym_at: u32,
    sym_len: u32,
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
/// link's change): its streams' bytes and blocks, the module stream's room, each function's
/// slots by key, and what the tables that index them are made of.
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
    /// The module stream: symbols are `4..sym_end` with room to `sym_cap` (an `S_SKIP`); the
    /// files' entries (`files.len()` of them, room for `files_cap`) start at `files_at`; the
    /// line tables are `c13_at..c13_end` with room to `c13_cap` (a `DEBUG_S_IGNORE`).
    sym_end: usize,
    sym_cap: usize,
    files_at: usize,
    files_cap: usize,
    c13_at: usize,
    c13_end: usize,
    c13_cap: usize,
    files: Vec<String>,
    file_of: blaze_hash::HashMap<String, u32, std::alloc::Global>,
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

const S_SKIP: u16 = 0x0007;
const DEBUG_S_IGNORE: u32 = 0x8000_0000;

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

/// A function's procedure and `S_END`, as at `at` of the module stream.
fn procedure(out: &mut Out, at: usize, function: &Placed<'_>) {
    let start = out.len();
    record(out, S_GPROC32, |out| {
        out.u32(0).u32(0).u32(0);
        out.u32(function.size).u32(0).u32(function.size).u32(0);
        out.u32(function.offset).u16(function.section).u8(0).string(&function.name);
    });
    let end_at = out.len();
    record(out, S_END, |_| {});
    // The procedure's `End`: where its `S_END` is.
    out.set_u32(start + 8, (at + end_at - start) as u32);
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

/// A function's `S_PROCREF`: its procedure at `sym_at` of module 1.
fn reference(out: &mut Out, sym_at: u32, name: &str) {
    record(out, S_PROCREF, |out| {
        out.u32(0).u32(sym_at).u16(1).string(name);
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
        });
    }
    Ok(out)
}

impl Model {
    /// The PDB of the image whose headers are `headers` and build id `id`, of its Rust
    /// `functions` and their `lines`, and of its native code's functions `natives` by name and
    /// address, which publics name: laid out whole, with room to patch.
    pub(crate) fn new(
        headers: Headers,
        id: [u8; 16],
        functions: &[Func<'_>],
        lines: &[Lined<'_>],
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
            sym_end: 0,
            sym_cap: 0,
            files_at: 0,
            files_cap: 0,
            c13_at: 0,
            c13_end: 0,
            c13_cap: 0,
            files: Vec::new(),
            file_of: blaze_hash::HashMap::with_capacity_in(64, std::alloc::Global),
            slots: Vec::with_capacity(placed.len()),
            spans: placed.iter().map(|it| (it.section, it.offset, it.size)).collect(),
            empty: functions.iter().filter(|it| it.size == 0).map(|it| it.key).collect(),
            natives: natives_hash(natives),
        };
        let row_files = model.files_of(lines);

        // The module: its symbols with room, its files' entries with room, its line tables
        // with room.
        let names_len: usize = placed.iter().map(|it| it.name.len()).sum();
        let mut module = Out(Vec::with_capacity(names_len * 5 / 4 + 100 * placed.len() + 10 * lines.len()));
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
        for function in &placed {
            let at = module.len();
            procedure(&mut module, at, function);
            syms.push((at as u32, (module.len() - at) as u32));
        }
        model.sym_end = module.len();
        let sym_room = room(model.sym_end, 4096);
        module.0.resize(model.sym_end + sym_room, 0);
        model.sym_cap = module.len();
        skip(&mut module.0, model.sym_end, sym_room);
        model.files_cap = model.files.len() + room(model.files.len(), 64);
        module.u32(DEBUG_S_FILECHKSMS).u32(0);
        model.files_at = module.len();
        module.0.resize(model.files_at + model.files_cap * 8, 0);
        model.c13_at = module.len();
        let mut rows: Vec<(u32, u32, u32)> = Vec::new();
        let mut line_slots = Vec::with_capacity(placed.len());
        for function in &placed {
            if function.lines.is_empty() {
                line_slots.push((0, 0));
                continue;
            }
            Model::rows(lines, &row_files, function, &mut rows);
            let at = module.len();
            line_table(&mut module, function, &rows);
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

        // The symbol record stream: the natives' publics, then the procedures' references.
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
        for ((function, (sym_at, sym_len)), (line_at, line_cap)) in placed.iter().zip(syms).zip(line_slots) {
            let ref_at = records.len() as u32;
            reference(&mut records, sym_at, &function.name);
            let place = (function.section, function.offset, function.size);
            let slot = Slot { sym_at, sym_len, line_at, line_cap, ref_at, name: function.name.clone().into_owned(), place };
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
        model.streams[usize::from(TPI)] = types(TPI_HASH);
        model.streams[usize::from(IPI)] = types(IPI_HASH);
        model.streams[usize::from(SECTION_HEADERS)] = model.headers.sections.iter().flatten().copied().collect();
        model.lay_out();
        Ok(model)
    }

    /// Each row's file, the files each once in the order first named, added to the model's.
    fn files_of(&mut self, lines: &[Lined<'_>]) -> Vec<u32> {
        let mut row_files = Vec::with_capacity(lines.len());
        let mut last: Option<(&str, u32)> = None;
        for row in lines {
            let n = match last {
                Some((file, n)) if std::ptr::eq(file, row.file) || file == row.file => n,
                _ => match self.file_of.get(row.file) {
                    Some(n) => *n,
                    None => {
                        let n = self.files.len() as u32;
                        // alloc: once per file named
                        self.files.push(row.file.to_owned());
                        self.file_of.insert(row.file.to_owned(), n);
                        n
                    }
                },
            };
            last = Some((row.file, n));
            row_files.push(n);
        }
        row_files
    }

    /// `function`'s rows as `(offset, file, line)`, by offset, into `rows`.
    fn rows(lines: &[Lined<'_>], row_files: &[u32], function: &Placed<'_>, rows: &mut Vec<(u32, u32, u32)>) {
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
        ignore(module, used, at + 8 * self.files_cap - used);
        self.streams[usize::from(NAMES)] = names;
    }

    /// The globals: a hash of every procedure's reference.
    fn globals(&self) -> Vec<u8> {
        let refs: Vec<(&str, u32)> = self.slots.iter().map(|(_, it)| (it.name.as_str(), it.ref_at)).collect();
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
        let characteristics =
            |section: u16| headers.sections.get(usize::from(section) - 1).map_or(0, |it| u32_at(it, 36));
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
            map.u16(it).u16(0).u16(0).u16(n as u16 + 1).u16(NONE).u16(NONE).u32(0).u32(u32_at(header, 8));
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
        let order = std::iter::once(1).chain((0..STREAMS).filter(|it| *it != 1));
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
        out.u32(STREAMS as u32);
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

    /// Brings the PDB to a link's change: `functions` (with `lines`) are those the link added
    /// or changed, `gone` those it removed, `count` how many the image has now; `natives` the
    /// native functions when they may have changed. The file's writes, by offset, or why it is
    /// laid out whole. On `Err` the model is not the file's: the caller lays it out whole.
    pub(crate) fn patch(
        &mut self,
        headers: Headers,
        id: [u8; 16],
        functions: &[Func<'_>],
        lines: &[Lined<'_>],
        gone: &[InstanceKey],
        count: usize,
        natives: Option<&[(&str, u64)]>,
    ) -> Result<Result<Vec<(u64, Vec<u8>)>, Whole>, String> {
        if headers.sections != self.headers.sections || headers.base != self.headers.base {
            return Ok(Err("the image's sections moved"));
        }
        if natives.is_some_and(|it| natives_hash(it) != self.natives) {
            return Ok(Err("the native code's functions changed"));
        }
        let placed = place(&headers, functions)?;
        // alloc: below, once per patch: the edit's records and the stream ranges written
        let mut dirty: Vec<(usize, std::ops::Range<usize>)> = Vec::new();
        let files_before = self.files.len();
        let records_before = self.streams[usize::from(RECORDS)].len();
        // The directory as the file holds it: every stream's size and blocks before the patch.
        let directory_before = self.directory_bytes();
        let row_files = self.files_of(lines);
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
        // A function of no code has no records: only its key is kept, so the records and those
        // number the image's functions.
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
        let mut out = Out::default();
        for function in &placed {
            let found = self.slots.binary_search_by_key(&function.key, |it| it.0);
            let module = &mut self.streams[usize::from(MODULE)];
            // The procedure: in its slot when it fits, else at the start of the room.
            let old = found.ok().map(|at| (self.slots[at].1.sym_at as usize, self.slots[at].1.sym_len as usize));
            out.0.clear();
            procedure(&mut out, old.map_or(self.sym_end, |it| it.0), function);
            let sym_at = match old {
                Some((at, len)) if len == out.len() => at,
                _ => {
                    if let Some((at, len)) = old {
                        skip(module, at, len);
                        dirty.push((usize::from(MODULE), at..at + len));
                    }
                    if self.sym_end + out.len() + 4 > self.sym_cap {
                        return Ok(Err("the module's symbols have no room"));
                    }
                    let at = self.sym_end;
                    out.0.clear();
                    procedure(&mut out, at, function);
                    self.sym_end += out.len();
                    skip(module, self.sym_end, self.sym_cap - self.sym_end);
                    dirty.push((usize::from(MODULE), self.sym_end..self.sym_end + 4));
                    at
                }
            };
            if module[sym_at..sym_at + out.len()] != out.0[..] {
                module[sym_at..sym_at + out.len()].copy_from_slice(&out.0);
                dirty.push((usize::from(MODULE), sym_at..sym_at + out.len()));
            }
            let sym_len = out.len() as u32;
            // The line table: in its slot when it fits, else at the start of the room.
            let old_lines = found.ok().map(|at| (self.slots[at].1.line_at as usize, self.slots[at].1.line_cap as usize));
            let (line_at, line_cap) = if function.lines.is_empty() {
                if let Some((at, cap)) = old_lines.filter(|it| it.1 != 0) {
                    ignore(module, at, cap);
                    dirty.push((usize::from(MODULE), at..at + cap));
                }
                (0, 0)
            } else {
                Model::rows(lines, &row_files, function, &mut rows);
                out.0.clear();
                line_table(&mut out, function, &rows);
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
                        slot.ref_at = Model::push_reference(&mut self.streams[usize::from(RECORDS)], sym_at as u32, &slot.name);
                    } else if slot.sym_at != sym_at as u32 {
                        let records = &mut self.streams[usize::from(RECORDS)];
                        let at = slot.ref_at as usize + 8;
                        records[at..at + 4].copy_from_slice(&(sym_at as u32).to_le_bytes());
                        dirty.push((usize::from(RECORDS), at..at + 4));
                    }
                    slot.sym_at = sym_at as u32;
                    slot.sym_len = sym_len;
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
                    let ref_at = Model::push_reference(&mut self.streams[usize::from(RECORDS)], sym_at as u32, &name);
                    let place = (function.section, function.offset, function.size);
                    self.slots.insert(at, (function.key, Slot { sym_at: sym_at as u32, sym_len, line_at, line_cap, ref_at, name, place }));
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
        // The tables made of every function: the globals when the names changed; DBI when a
        // contribution or a file did.
        let mut whole_streams: Vec<usize> = Vec::new();
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
        // New references: the records appended, the stream's blocks fitted to it.
        let mut resized = Vec::new();
        let records = self.streams[usize::from(RECORDS)].len();
        if records != records_before {
            resized.push(usize::from(RECORDS));
            dirty.push((usize::from(RECORDS), records_before..records));
        }
        if id != self.id {
            self.id = id;
            self.streams[usize::from(INFO)] = info(headers.stamp, &id);
            whole_streams.push(usize::from(INFO));
        }
        self.headers = headers;
        Ok(Ok(self.writes(dirty, whole_streams, resized, directory_before)))
    }

    /// Takes out the slots of `self.slots[at]`: its procedure stepped over, its line table
    /// ignored, its place unspanned; its reference left unreferenced.
    fn drop_slot(&mut self, at: usize, dirty: &mut Vec<(usize, std::ops::Range<usize>)>) {
        let (_, slot) = self.slots.remove(at);
        self.unspan(slot.place);
        let module = &mut self.streams[usize::from(MODULE)];
        skip(module, slot.sym_at as usize, slot.sym_len as usize);
        dirty.push((usize::from(MODULE), slot.sym_at as usize..(slot.sym_at + slot.sym_len) as usize));
        if slot.line_cap != 0 {
            ignore(module, slot.line_at as usize, slot.line_cap as usize);
            dirty.push((usize::from(MODULE), slot.line_at as usize..(slot.line_at + slot.line_cap) as usize));
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
    fn push_reference(records: &mut Vec<u8>, sym_at: u32, name: &str) -> u32 {
        let at = records.len() as u32;
        let mut out = Out(std::mem::take(records));
        reference(&mut out, sym_at, name);
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
                Some((m, last)) if *m == n && range.start <= last.end => last.end = last.end.max(range.end),
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
            + self.slots.iter().map(|it| size_of::<(InstanceKey, Slot)>() + it.1.name.capacity()).sum::<usize>())
            as u64
    }
}

/// Whether block `n` is one of an interval's free block maps.
fn is_map(n: usize) -> bool {
    matches!(n % BLOCK, 1 | 2)
}

#[cfg(test)]
mod tests;
