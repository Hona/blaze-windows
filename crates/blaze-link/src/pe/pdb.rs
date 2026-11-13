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
//! - publics (`S_PUB32` per function, with their hash and address map) and globals (an
//!   `S_PROCREF` per function), whose records are in the symbol record stream;
//! - `/names`, the file names.
//!
//! The file is written whole by each link. Native code's own debug info (`.debug$S`) is not
//! merged: its functions are publics alone, named as its objects name them.

use std::fmt::Write as _;

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
/// A function as the PDB places it.
struct Placed<'a> {
    name: &'a str,
    section: u16,
    offset: u32,
    size: u32,
    /// Its rows: indexes into the rows given.
    lines: std::ops::Range<usize>,
}

/// The PDB of the image whose headers are `headers` and build id `id`, of its Rust
/// `functions` and their `lines`, and of its native code's functions `natives` by name and
/// address, named by publics alone.
pub(crate) fn write(
    headers: &Headers,
    id: &[u8; 16],
    functions: &[Func<'_>],
    lines: &[Lined<'_>],
    natives: &[(&str, u64)],
) -> Result<Vec<u8>, String> {
    // alloc: below, once per PDB written: its streams and the file
    let mut placed = Vec::with_capacity(functions.len());
    let mut unnamed = String::new();
    let mut names = Vec::new();
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
        if function.name.is_none() {
            names.push(unnamed.len());
            write!(unnamed, "blaze_fn_{:x}", function.addr).unwrap();
        }
        placed.push((function, section, offset));
    }
    let mut cursor = 0;
    let placed: Vec<Placed<'_>> = placed
        .iter()
        .map(|(function, section, offset)| {
            let name = match function.name {
                Some(name) => name,
                None => {
                    let start = names[cursor];
                    cursor += 1;
                    let end = names.get(cursor).copied().unwrap_or(unnamed.len());
                    &unnamed[start..end]
                }
            };
            let rows = function.lines.start as usize..function.lines.end as usize;
            Placed { name, section: *section, offset: *offset, size: function.size as u32, lines: rows }
        })
        .collect();

    // The files, each once, in the order first named, and each row's: a function's rows are
    // mostly of the file of the row before.
    let mut files: Vec<&str> = Vec::new();
    let mut file_of: blaze_hash::HashMap<&str, u32, std::alloc::Global> =
        blaze_hash::HashMap::with_capacity_in(64, std::alloc::Global);
    let mut row_files: Vec<u32> = Vec::with_capacity(lines.len());
    let mut last: Option<(&str, u32)> = None;
    for row in lines {
        let n = match last {
            Some((file, n)) if std::ptr::eq(file, row.file) || file == row.file => n,
            _ => *file_of.entry(row.file).or_insert_with(|| {
                files.push(row.file);
                files.len() as u32 - 1
            }),
        };
        last = Some((row.file, n));
        row_files.push(n);
    }
    let (names_stream, name_offsets) = string_table(&files);

    // The module: its symbols, then its C13 subsections.
    let names_len: usize = placed.iter().map(|it| it.name.len()).sum();
    let mut module = Out(Vec::with_capacity(names_len + 80 * placed.len() + 8 * lines.len()));
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
    let mut procedures = Vec::with_capacity(placed.len());
    for function in &placed {
        let start = module.len();
        record(&mut module, S_GPROC32, |out| {
            out.u32(0).u32(0).u32(0);
            out.u32(function.size).u32(0).u32(function.size).u32(0);
            out.u32(function.offset).u16(function.section).u8(0).string(function.name);
        });
        let end_at = module.len();
        record(&mut module, S_END, |_| {});
        // The procedure's `End`: where its `S_END` is.
        module.set_u32(start + 8, end_at as u32);
        procedures.push(start as u32);
    }
    let symbols = module.len();
    // The files' entries: each a name in `/names` and no checksum, 8 bytes.
    module.u32(DEBUG_S_FILECHKSMS).u32(files.len() as u32 * 8);
    for offset in &name_offsets {
        module.u32(*offset).u8(0).u8(0).u16(0);
    }
    // A function's rows as `(offset, file, line)`, by offset.
    let mut rows: Vec<(u32, u32, u32)> = Vec::new();
    for function in &placed {
        if function.lines.is_empty() {
            continue;
        }
        rows.clear();
        rows.extend(function.lines.clone().map(|at| (lines[at].at, row_files[at], lines[at].line)));
        if !rows.is_sorted_by_key(|it| it.0) {
            rows.sort_by_key(|it| it.0);
        }
        let size_at = module.len() + 4;
        module.u32(DEBUG_S_LINES).u32(0);
        let start = module.len();
        module.u32(function.offset).u16(function.section).u16(0).u32(function.size);
        for run in rows.chunk_by(|a, b| a.1 == b.1) {
            module.u32(run[0].1 * 8).u32(run.len() as u32).u32(12 + 8 * run.len() as u32);
            for &(at, _, line) in run {
                let line = match line {
                    0 => NO_LINE,
                    line => line.min(0xff_ffff),
                };
                module.u32(at).u32(line | STATEMENT);
            }
        }
        let size = module.len() - start;
        module.set_u32(size_at, size as u32);
        module.align(4);
    }
    let c13 = module.len() - symbols;
    module.u32(0);

    // The symbol record stream: the publics, then the globals' references.
    let mut records = Out::default();
    let mut publics = Vec::with_capacity(placed.len());
    for function in &placed {
        let at = records.len() as u32;
        record(&mut records, S_PUB32, |out| {
            out.u32(PUBLIC_FUNCTION).u32(function.offset).u16(function.section).string(function.name);
        });
        publics.push((function.name, at));
    }
    // Native functions: a public each, and no procedure.
    let mut native = Vec::with_capacity(natives.len());
    for (name, addr) in natives {
        let Some((section, offset)) = headers.place(*addr) else { continue };
        let at = records.len() as u32;
        record(&mut records, S_PUB32, |out| {
            out.u32(PUBLIC_FUNCTION).u32(offset).u16(section).string(name);
        });
        native.push((section, offset, *name, at));
    }
    let mut globals = Vec::with_capacity(placed.len());
    for (function, procedure) in placed.iter().zip(&procedures) {
        let at = records.len() as u32;
        record(&mut records, S_PROCREF, |out| {
            out.u32(0).u32(*procedure).u16(1).string(function.name);
        });
        globals.push((function.name, at));
    }
    let globals_stream = gsi(&globals);
    let hash = {
        let mut all = publics.clone();
        all.extend(native.iter().map(|it| (it.2, it.3)));
        gsi(&all)
    };
    let mut by_address: Vec<(u16, u32, &str, u32)> =
        placed.iter().zip(&publics).map(|(it, public)| (it.section, it.offset, it.name, public.1)).collect();
    by_address.extend(native.iter().copied());
    by_address.sort_unstable_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)).then_with(|| a.2.cmp(b.2)));
    let mut publics_stream = Out::default();
    publics_stream.u32(hash.len() as u32).u32(by_address.len() as u32 * 4);
    publics_stream.u32(0).u32(0).u16(0).u16(0).u32(0).u32(0);
    publics_stream.bytes(&hash);
    for it in &by_address {
        publics_stream.u32(it.3);
    }

    // The section contributions: runs of the module's functions that touch.
    let mut runs: Vec<(u16, u32, u32)> = Vec::new();
    let mut spans: Vec<(u16, u32, u32)> = placed.iter().map(|it| (it.section, it.offset, it.size)).collect();
    spans.sort_unstable();
    for (section, offset, size) in spans {
        match runs.last_mut() {
            Some(last) if last.0 == section && last.1 + last.2 >= offset => {
                last.2 = last.2.max(offset + size - last.1);
            }
            _ => runs.push((section, offset, size)),
        }
    }
    let characteristics =
        |section: u16| headers.sections.get(usize::from(section) - 1).map_or(0, |it| u32_at(it, 36));
    let contribution = |out: &mut Out, (section, offset, size): (u16, u32, u32)| {
        out.u16(section).u16(0).u32(offset).u32(size).u32(characteristics(section));
        out.u16(0).u16(0).u32(0).u32(0);
    };

    let mut modules = Out::default();
    modules.u32(0);
    contribution(&mut modules, runs.first().copied().unwrap_or((NONE, 0, 0)));
    modules.u16(0).u16(MODULE).u32(symbols as u32).u32(0).u32(c13 as u32);
    modules.u16(files.len().min(usize::from(u16::MAX)) as u16).u16(0).u32(0).u32(0).u32(0);
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
    let file_count = files.len().min(usize::from(u16::MAX)) as u16;
    sources.u16(1).u16(file_count).u16(0).u16(file_count);
    let mut source_names = Out::default();
    for it in &files {
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

    let section_headers: Vec<u8> = headers.sections.iter().flatten().copied().collect();
    let mut streams: Vec<Vec<u8>> = vec![Vec::new(); STREAMS];
    streams[usize::from(INFO)] = info(headers.stamp, id);
    streams[usize::from(TPI)] = types(TPI_HASH);
    streams[usize::from(DBI)] = dbi.0;
    streams[usize::from(IPI)] = types(IPI_HASH);
    streams[usize::from(NAMES)] = names_stream;
    streams[usize::from(GLOBALS)] = globals_stream;
    streams[usize::from(PUBLICS)] = publics_stream.0;
    streams[usize::from(RECORDS)] = records.0;
    streams[usize::from(SECTION_HEADERS)] = section_headers;
    streams[usize::from(MODULE)] = module.0;
    Ok(msf(&streams))
}

/// Whether block `n` is one of an interval's free block maps.
fn is_map(n: usize) -> bool {
    matches!(n % BLOCK, 1 | 2)
}

/// The MSF file of `streams`, stream 1 at [`INFO_BLOCK`].
fn msf(streams: &[Vec<u8>]) -> Vec<u8> {
    let mut next = INFO_BLOCK;
    let mut take = |count: usize| -> Vec<u32> {
        (0..count)
            .map(|_| {
                while is_map(next) {
                    next += 1;
                }
                next += 1;
                (next - 1) as u32
            })
            .collect()
    };
    let mut blocks: Vec<Vec<u32>> = vec![Vec::new(); streams.len()];
    let order = std::iter::once(1).chain((0..streams.len()).filter(|it| *it != 1));
    for n in order {
        blocks[n] = take(streams[n].len().div_ceil(BLOCK));
    }
    let mut directory = Out::default();
    directory.u32(streams.len() as u32);
    for it in streams {
        directory.u32(it.len() as u32);
    }
    for it in &blocks {
        for block in it {
            directory.u32(*block);
        }
    }
    let directory_blocks = take(directory.len().div_ceil(BLOCK));
    let block_map = take(1)[0];
    let mut count = next;
    // Every interval the file reaches has its free block maps in the file.
    let last_interval = (count - 1) / BLOCK;
    count = count.max(last_interval * BLOCK + 3);
    let mut file = vec![0u8; count * BLOCK];
    let mut put = |block: u32, bytes: &[u8]| {
        let at = block as usize * BLOCK;
        file[at..at + bytes.len()].copy_from_slice(bytes);
    };
    for (stream, blocks) in streams.iter().zip(&blocks) {
        for (chunk, block) in stream.chunks(BLOCK).zip(blocks) {
            put(*block, chunk);
        }
    }
    for (chunk, block) in directory.0.chunks(BLOCK).zip(&directory_blocks) {
        put(*block, chunk);
    }
    let map: Vec<u8> = directory_blocks.iter().flat_map(|it| it.to_le_bytes()).collect();
    put(block_map, &map);
    // The free block maps: a bit per block, set for a free one; every block of the file is
    // used, and the bits past it are free. Interval `k`'s map holds bytes `k * BLOCK..` of it.
    for k in 0..=last_interval {
        let mut bits = vec![0xffu8; BLOCK];
        for (n, byte) in bits.iter_mut().enumerate() {
            let first = (k * BLOCK + n) * 8;
            for bit in 0..8 {
                if first + bit < count {
                    *byte &= !(1 << bit);
                }
            }
        }
        put((k * BLOCK + 1) as u32, &bits);
        put((k * BLOCK + 2) as u32, &bits);
    }
    let mut head = Out::default();
    head.bytes(MAGIC).u32(BLOCK as u32).u32(1).u32(count as u32).u32(directory.len() as u32);
    head.u32(0).u32(block_map);
    put(0, &head.0);
    file
}

#[cfg(test)]
mod tests;
