use std::collections::{BTreeMap, BTreeSet};

use blaze_codegen::InstanceKey;
use blaze_codegen::debug::{
    Aggregate, BaseEncoding, DebugType, EnumTag, EnumVariant, Field, FunctionDebug, Local,
    LocalPlace, Scope,
};

use super::cv;
use super::*;

/// The headers of an image based at `0x1_4000_0000` with `.text` at RVA 0x1000 (0x3000
/// bytes) and `.rdata` at 0x4000.
fn exe() -> Vec<u8> {
    let mut out = vec![0u8; 0x400];
    out[..2].copy_from_slice(b"MZ");
    out[60..64].copy_from_slice(&0x80u32.to_le_bytes());
    out[0x80..0x84].copy_from_slice(b"PE\0\0");
    let file = 0x84;
    out[file..file + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    out[file + 2..file + 4].copy_from_slice(&2u16.to_le_bytes());
    out[file + 4..file + 8].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    out[file + 16..file + 18].copy_from_slice(&240u16.to_le_bytes());
    let optional = file + 20;
    out[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    out[optional + 24..optional + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
    let mut section = optional + 240;
    for (name, rva, size, flags) in [
        (b".text\0\0\0", 0x1000u32, 0x3000u32, 0x6000_0020u32),
        (b".rdata\0\0", 0x4000, 0x800, 0x4000_0040),
    ] {
        out[section..section + 8].copy_from_slice(name);
        out[section + 8..section + 12].copy_from_slice(&size.to_le_bytes());
        out[section + 12..section + 16].copy_from_slice(&rva.to_le_bytes());
        out[section + 36..section + 40].copy_from_slice(&flags.to_le_bytes());
        section += 40;
    }
    out
}

fn headers(file: &[u8]) -> Headers {
    Headers::read(&|at: u64, out: &mut [u8]| {
        let at = at as usize;
        let end = (at + out.len()).min(file.len());
        out[..end - at].copy_from_slice(&file[at..end]);
    })
    .unwrap()
}

fn key(n: u32) -> InstanceKey {
    let mut bytes = [0x5a; 32];
    bytes[..4].copy_from_slice(&n.to_le_bytes());
    InstanceKey(blaze_ids::ContentId(bytes))
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn i32_at(bytes: &[u8], at: usize) -> i32 {
    i32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

/// An MSF file's streams, read as a reader of the format does: its superblock, the block
/// map, the directory.
fn streams(file: &[u8]) -> Vec<Vec<u8>> {
    assert_eq!(&file[..32], MAGIC);
    let word = |at: usize| u32_at(file, at) as usize;
    assert_eq!(word(32), BLOCK);
    let count = word(40);
    assert_eq!(file.len(), count * BLOCK, "the file is its blocks");
    let directory_len = word(44);
    let map = word(52) * BLOCK;
    let mut directory = Vec::new();
    for n in 0..directory_len.div_ceil(BLOCK) {
        let block = word(map + 4 * n);
        assert!(block < count && !is_map(block));
        directory.extend_from_slice(&file[block * BLOCK..(block + 1) * BLOCK]);
    }
    let streams = u32_at(&directory, 0) as usize;
    let sizes: Vec<usize> = (0..streams).map(|n| u32_at(&directory, 4 + 4 * n) as usize).collect();
    let mut at = 4 + 4 * streams;
    sizes
        .iter()
        .map(|size| {
            let mut out = Vec::new();
            for _ in 0..size.div_ceil(BLOCK) {
                let block = u32_at(&directory, at) as usize;
                at += 4;
                assert!(block < count && !is_map(block), "block {block}");
                out.extend_from_slice(&file[block * BLOCK..(block + 1) * BLOCK]);
            }
            out.truncate(*size);
            out
        })
        .collect()
}

/// The symbol records of `bytes`: each `(kind, body)`.
fn symbols(mut bytes: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    while bytes.len() >= 4 {
        let len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
        let kind = u16::from_le_bytes([bytes[2], bytes[3]]);
        out.push((kind, bytes[4..2 + len].to_vec()));
        assert_eq!((2 + len) % 4, 0, "a record of kind {kind:#x} is 4-aligned");
        bytes = &bytes[2 + len..];
    }
    out
}

fn name_in(body: &[u8], at: usize) -> String {
    let end = body[at..].iter().position(|it| *it == 0).unwrap();
    String::from_utf8(body[at..at + end].to_vec()).unwrap()
}

/// Independent reader of a TPI or IPI stream + its companion hash stream: validates the 56-byte
/// header, every record's length and 4-byte alignment, every hash bucket value, and every
/// `IndexOffsetBuffer` checkpoint.
struct ParsedTypes {
    /// Raw records `(kind, body)` indexed by `ti - 0x1000`.
    records: Vec<(u16, Vec<u8>)>,
    /// Complete UDT definitions by name (so forward references can be resolved).
    complete_udts: BTreeMap<String, u32>,
}

impl ParsedTypes {
    fn parse(stream: &[u8], hash_stream: &[u8], expected_hash_stream: u16) -> Result<Self, String> {
        if stream.len() < 56 {
            return Err(format!("TPI/IPI stream truncated: {} bytes", stream.len()));
        }
        if u32_at(stream, 0) != 20040203 || u32_at(stream, 4) != 56 {
            return Err("bad TPI/IPI header version or size".into());
        }
        let ti_begin = u32_at(stream, 8);
        let ti_end = u32_at(stream, 12);
        let rec_bytes = u32_at(stream, 16) as usize;
        if ti_begin != cv::FIRST_NON_SIMPLE || ti_end < ti_begin {
            return Err(format!("bad TypeIndex range {ti_begin:#x}..{ti_end:#x}"));
        }
        if 56 + rec_bytes != stream.len() {
            return Err(format!(
                "TPI/IPI record bytes {rec_bytes} + 56 != stream len {}",
                stream.len()
            ));
        }
        if u16_at(stream, 20) != expected_hash_stream {
            return Err(format!("unexpected hash stream index {}", u16_at(stream, 20)));
        }
        let buckets = u32_at(stream, 28);
        let hash_val_off = u32_at(stream, 32) as usize;
        let hash_val_len = u32_at(stream, 36) as usize;
        let idx_off_off = u32_at(stream, 40) as usize;
        let idx_off_len = u32_at(stream, 44) as usize;

        let count = (ti_end - ti_begin) as usize;
        if hash_val_len != count * 4 {
            return Err(format!("hash value buffer len {hash_val_len} != {}*4", count));
        }
        if hash_val_off + hash_val_len > hash_stream.len()
            || idx_off_off + idx_off_len > hash_stream.len()
        {
            return Err("TPI/IPI hash stream out of bounds".into());
        }

        let data = &stream[56..];
        let mut at = 0usize;
        let mut records = Vec::with_capacity(count);
        let mut offsets = Vec::with_capacity(count);
        let mut complete_udts = BTreeMap::new();
        while at < data.len() {
            if at + 4 > data.len() {
                return Err(format!("truncated type record at {at}"));
            }
            let len = usize::from(u16_at(data, at));
            let kind = u16_at(data, at + 2);
            let full_len = 2 + len;
            if full_len % 4 != 0 || at + full_len > data.len() {
                return Err(format!(
                    "bad type record at {at}: kind={kind:#x} full_len={full_len}"
                ));
            }
            let full = &data[at..at + full_len];
            let body = &data[at + 4..at + full_len];
            let idx = records.len();
            let got_hash = u32_at(hash_stream, hash_val_off + idx * 4);
            let want_hash = cv::hash_type_record(full) % buckets;
            if got_hash != want_hash {
                return Err(format!(
                    "TPI/IPI hash mismatch at ti={:#x}: got {got_hash}, want {want_hash}",
                    ti_begin + idx as u32
                ));
            }
            let ti = ti_begin + idx as u32;
            if matches!(kind, cv::LF_STRUCTURE | cv::LF_CLASS | cv::LF_UNION | cv::LF_ENUM) {
                let props = u16_at(body, 2);
                if props & cv::OPT_FORWARD_REF == 0 {
                    let name_at = match kind {
                        cv::LF_STRUCTURE | cv::LF_CLASS => {
                            let (_, n) = cv::read_numeric(&body[16..])
                                .ok_or("bad struct size numeric leaf")?;
                            16 + n
                        }
                        cv::LF_UNION => {
                            let (_, n) = cv::read_numeric(&body[8..])
                                .ok_or("bad union size numeric leaf")?;
                            8 + n
                        }
                        cv::LF_ENUM => 12,
                        _ => unreachable!(),
                    };
                    complete_udts.insert(name_in(body, name_at), ti);
                }
            }
            offsets.push(at as u32);
            records.push((kind, body.to_vec()));
            at += full_len;
        }
        if records.len() != count {
            return Err(format!("TPI/IPI record count {} != header {count}", records.len()));
        }
        if idx_off_len % 8 != 0 {
            return Err("index offset buffer not 8-byte aligned".into());
        }
        for n in 0..idx_off_len / 8 {
            let ti = u32_at(hash_stream, idx_off_off + n * 8);
            let off = u32_at(hash_stream, idx_off_off + n * 8 + 4);
            let idx = (ti - ti_begin) as usize;
            if offsets.get(idx).copied() != Some(off) {
                return Err(format!(
                    "index offset entry ({ti:#x}, {off}) != actual {:?}",
                    offsets.get(idx)
                ));
            }
        }
        Ok(ParsedTypes { records, complete_udts })
    }

    fn get(&self, ti: u32) -> Option<(u16, &[u8])> {
        let idx = ti.checked_sub(cv::FIRST_NON_SIMPLE)? as usize;
        let (kind, body) = self.records.get(idx)?;
        Some((*kind, body.as_slice()))
    }

    /// Canonical, TypeIndex-independent structural string for `ti` so patched vs fresh PDBs can
    /// be compared semantically regardless of TypeIndex numbering.
    fn describe(&self, ti: u32) -> Result<String, String> {
        self.describe_inner(ti, &mut BTreeSet::new())
    }

    fn describe_inner(&self, ti: u32, seen: &mut BTreeSet<u32>) -> Result<String, String> {
        if ti < cv::FIRST_NON_SIMPLE {
            return Ok(match ti {
                cv::T_VOID => "void".into(),
                cv::T_BOOL08 => "bool".into(),
                cv::T_CHAR32 => "char".into(),
                cv::T_SCHAR => "i8".into(),
                cv::T_SHORT => "i16".into(),
                cv::T_INT4 => "i32".into(),
                cv::T_INT8 => "i64".into(),
                cv::T_INT16 => "i128".into(),
                cv::T_UCHAR => "u8".into(),
                cv::T_USHORT => "u16".into(),
                cv::T_UINT4 => "u32".into(),
                cv::T_UINT8 => "u64".into(),
                cv::T_UINT16 => "u128".into(),
                cv::T_REAL16 => "f16".into(),
                cv::T_REAL32 => "f32".into(),
                cv::T_REAL64 => "f64".into(),
                cv::T_REAL128 => "f128".into(),
                other => format!("simple({other:#x})"),
            });
        }
        let (kind, body) = self.get(ti).ok_or_else(|| format!("dangling TypeIndex {ti:#x}"))?;
        if !seen.insert(ti) {
            return Ok(format!("rec({kind:#x})"));
        }
        let out = match kind {
            cv::LF_POINTER => {
                let referent = u32_at(body, 0);
                let attrs = u32_at(body, 4);
                let inner = self.describe_inner(referent, seen)?;
                format!("ptr({attrs:#x},{inner})")
            }
            cv::LF_ARRAY => {
                let elem = u32_at(body, 0);
                let idx = u32_at(body, 4);
                let (bytes, _) = cv::read_numeric(&body[8..]).ok_or("bad LF_ARRAY size")?;
                let inner = self.describe_inner(elem, seen)?;
                let idx_s = self.describe_inner(idx, seen)?;
                format!("array({inner};bytes={bytes};idx={idx_s})")
            }
            cv::LF_STRUCTURE | cv::LF_CLASS => {
                let count = u16_at(body, 0);
                let props = u16_at(body, 2);
                let fl = u32_at(body, 4);
                let (size, n) = cv::read_numeric(&body[16..]).ok_or("bad struct size")?;
                let name = name_in(body, 16 + n);
                if props & cv::OPT_FORWARD_REF != 0 {
                    if let Some(&complete) = self.complete_udts.get(&name) {
                        format!("fwd({name}->complete={})", self.complete_udts.contains_key(&name) && complete >= cv::FIRST_NON_SIMPLE)
                    } else {
                        format!("fwd({name})")
                    }
                } else {
                    let fields = self.describe_fieldlist(fl, seen)?;
                    format!("struct({name},sz={size},n={count},props={props:#x},[{fields}])")
                }
            }
            cv::LF_UNION => {
                let count = u16_at(body, 0);
                let props = u16_at(body, 2);
                let fl = u32_at(body, 4);
                let (size, n) = cv::read_numeric(&body[8..]).ok_or("bad union size")?;
                let name = name_in(body, 8 + n);
                if props & cv::OPT_FORWARD_REF != 0 {
                    format!("fwd_union({name})")
                } else {
                    let fields = self.describe_fieldlist(fl, seen)?;
                    format!("union({name},sz={size},n={count},props={props:#x},[{fields}])")
                }
            }
            cv::LF_ENUM => {
                let count = u16_at(body, 0);
                let props = u16_at(body, 2);
                let underlying = u32_at(body, 4);
                let fl = u32_at(body, 8);
                let name = name_in(body, 12);
                let under = self.describe_inner(underlying, seen)?;
                let items = self.describe_fieldlist(fl, seen)?;
                format!("enum({name},under={under},n={count},props={props:#x},[{items}])")
            }
            cv::LF_PROCEDURE => {
                let ret = u32_at(body, 0);
                let param_count = u16_at(body, 6);
                let arglist = u32_at(body, 8);
                let args = self.describe_inner(arglist, seen)?;
                let ret_s = self.describe_inner(ret, seen)?;
                format!("fn({args})->{ret_s}[{param_count}]")
            }
            cv::LF_ARGLIST => {
                let count = u32_at(body, 0) as usize;
                let mut parts = Vec::with_capacity(count);
                for i in 0..count {
                    parts.push(self.describe_inner(u32_at(body, 4 + i * 4), seen)?);
                }
                parts.join(",")
            }
            cv::LF_FUNC_ID => {
                let func_ty = u32_at(body, 4);
                let name = name_in(body, 8);
                format!("func_id({name},ty={func_ty:#x})")
            }
            other => format!("leaf({other:#x})"),
        };
        seen.remove(&ti);
        Ok(out)
    }

    fn describe_fieldlist(&self, fl: u32, seen: &mut BTreeSet<u32>) -> Result<String, String> {
        if fl == 0 {
            return Ok(String::new());
        }
        let mut parts = Vec::new();
        let mut cur = fl;
        let mut hops = 0;
        loop {
            hops += 1;
            if hops > 128 {
                return Err("LF_INDEX cycle in LF_FIELDLIST".into());
            }
            let (kind, body) =
                self.get(cur).ok_or_else(|| format!("bad LF_FIELDLIST ti {cur:#x}"))?;
            if kind != cv::LF_FIELDLIST {
                return Err(format!("expected LF_FIELDLIST, got {kind:#x}"));
            }
            let mut at = 0usize;
            let mut cont = None;
            while at < body.len() {
                if body[at] >= 0xf0 {
                    let pad = usize::from(body[at] & 0x0f);
                    at += pad.max(1);
                    continue;
                }
                let sub = u16_at(body, at);
                at += 2;
                match sub {
                    cv::LF_MEMBER => {
                        let _attrs = u16_at(body, at);
                        let fty = u32_at(body, at + 2);
                        let (off, n) =
                            cv::read_numeric(&body[at + 6..]).ok_or("bad LF_MEMBER offset")?;
                        let name = name_in(body, at + 6 + n);
                        at += 6 + n + name.len() + 1;
                        let ty_s = self.describe_inner(fty, seen)?;
                        parts.push(format!("{name}@{off}:{ty_s}"));
                    }
                    cv::LF_ENUMERATE => {
                        let _attrs = u16_at(body, at);
                        let (val, n) =
                            cv::read_numeric(&body[at + 2..]).ok_or("bad LF_ENUMERATE val")?;
                        let name = name_in(body, at + 2 + n);
                        at += 2 + n + name.len() + 1;
                        parts.push(format!("{name}={val}"));
                    }
                    cv::LF_NESTTYPE => {
                        let _pad = u16_at(body, at);
                        let nty = u32_at(body, at + 2);
                        let name = name_in(body, at + 6);
                        at += 6 + name.len() + 1;
                        let ty_s = self.describe_inner(nty, seen)?;
                        parts.push(format!("nested({name}={ty_s})"));
                    }
                    cv::LF_INDEX => {
                        let _pad = u16_at(body, at);
                        cont = Some(u32_at(body, at + 2));
                        at += 6;
                    }
                    other => return Err(format!("unknown LF_FIELDLIST member {other:#x}")),
                }
            }
            match cont {
                Some(next) => cur = next,
                None => break,
            }
        }
        Ok(parts.join(";"))
    }
}

/// Decodes `S_INLINESITE` binary annotations into `(code_offset, len, file_name, line)`.
fn decode_annotations(
    mut data: &[u8],
    base_file: u32,
    base_line: u32,
    files: &[String],
) -> Result<Vec<(u32, u32, String, u32)>, String> {
    let mut out = Vec::new();
    let mut code_off: u32 = 0;
    let mut file_off: u32 = base_file;
    let mut line: i64 = i64::from(base_line);
    while !data.is_empty() {
        let Some(op) = cv::decode_compressed_u32(&mut data) else { break };
        if op == cv::BA_EOF {
            break;
        }
        match op {
            cv::BA_CODE_OFFSET => {
                code_off = cv::decode_compressed_u32(&mut data).ok_or("truncated CodeOffset")?;
            }
            cv::BA_CHANGE_CODE_OFFSET => {
                let d = cv::decode_compressed_u32(&mut data).ok_or("truncated ChangeCodeOffset")?;
                code_off += d;
            }
            cv::BA_CHANGE_CODE_LENGTH => {
                let len =
                    cv::decode_compressed_u32(&mut data).ok_or("truncated ChangeCodeLength")?;
                let file = files
                    .get((file_off / 8) as usize)
                    .ok_or_else(|| format!("bad inline file offset {file_off}"))?
                    .clone();
                out.push((code_off, len, file, line as u32));
                code_off += len;
            }
            cv::BA_CHANGE_FILE => {
                file_off = cv::decode_compressed_u32(&mut data).ok_or("truncated ChangeFile")?;
            }
            cv::BA_CHANGE_LINE_OFFSET => {
                let raw =
                    cv::decode_compressed_u32(&mut data).ok_or("truncated ChangeLineOffset")?;
                line += i64::from(cv::decode_signed_operand(raw));
            }
            other => return Err(format!("unexpected binary annotation opcode {other}")),
        }
    }
    Ok(out)
}

/// Canonical representation of one local variable read back from a PDB.
#[derive(Clone, PartialEq, Eq, Debug)]
struct SaidLocal {
    name: String,
    flags: u16,
    ty: String,
    scope: Option<(u32, u32)>,
    ranges: Vec<String>,
}

/// Canonical representation of one inlined site tree node read back from a PDB.
#[derive(Clone, PartialEq, Eq, Debug)]
struct SaidInline {
    callee: String,
    spans: Vec<(u32, u32, String, u32)>,
    children: Vec<SaidInline>,
}

/// Canonical representation of one procedure read back from a PDB.
#[derive(Clone, PartialEq, Eq, Debug)]
struct SaidProc {
    place: (u16, u32, u32),
    proc_ty: String,
    frame_flags: Option<u32>,
    lines: Vec<(u32, String, u32)>,
    locals: Vec<SaidLocal>,
    inlines: Vec<SaidInline>,
}

/// What a PDB says of its functions, read as an independent reader of the format reads it.
type Said = BTreeMap<String, SaidProc>;

fn said(pdb: &[u8]) -> Result<Said, String> {
    let streams = streams(pdb);
    let tpi = ParsedTypes::parse(
        &streams[usize::from(TPI)],
        &streams[usize::from(TPI_HASH)],
        TPI_HASH,
    )?;
    let ipi = ParsedTypes::parse(
        &streams[usize::from(IPI)],
        &streams[usize::from(IPI_HASH)],
        IPI_HASH,
    )?;

    let dbi = &streams[usize::from(DBI)];
    let (symbol_bytes, c13_bytes) = (u32_at(dbi, 64 + 36) as usize, u32_at(dbi, 64 + 44) as usize);
    let module = &streams[usize::from(MODULE)];

    // Parse C13 first so we have file names and DEBUG_S_INLINEELINES for S_INLINESITE decoding.
    let names = &streams[usize::from(NAMES)];
    let c13 = &module[symbol_bytes..symbol_bytes + c13_bytes];
    let (mut at, mut files) = (0, Vec::new());
    let mut inlinee_lines: BTreeMap<u32, (u32, u32)> = BTreeMap::new();
    let mut rows: BTreeMap<(u16, u32), Vec<(u32, String, u32)>> = BTreeMap::new();
    while at < c13.len() {
        let (kind, len) = (u32_at(c13, at), u32_at(c13, at + 4) as usize);
        let body = &c13[at + 8..at + 8 + len];
        match kind {
            DEBUG_S_FILECHKSMS => {
                files = body
                    .chunks(8)
                    .map(|it| name_in(&names[12..], u32_at(it, 0) as usize))
                    .collect();
            }
            DEBUG_S_INLINEELINES => {
                let sig = u32_at(body, 0);
                if sig != 0 {
                    return Err(format!("unexpected inlinee lines signature {sig}"));
                }
                for entry in body[4..].chunks_exact(12) {
                    let id = u32_at(entry, 0);
                    let file_id = u32_at(entry, 4);
                    let line = u32_at(entry, 8);
                    if inlinee_lines.insert(id, (file_id, line)).is_some() {
                        return Err(format!("duplicate inlinee {id:#x} in DEBUG_S_INLINEELINES"));
                    }
                }
            }
            DEBUG_S_LINES => {
                let place = (u16_at(body, 4), u32_at(body, 0));
                let mut block = 12;
                let into = rows.entry(place).or_default();
                if !into.is_empty() {
                    return Err(format!("two line tables at {place:?}"));
                }
                while block < body.len() {
                    let (file, count) =
                        (u32_at(body, block) as usize / 8, u32_at(body, block + 4) as usize);
                    for n in 0..count {
                        let row = block + 12 + 8 * n;
                        into.push((
                            u32_at(body, row),
                            files[file].clone(),
                            u32_at(body, row + 4) & 0xff_ffff,
                        ));
                    }
                    block += u32_at(body, block + 8) as usize;
                }
            }
            DEBUG_S_IGNORE => {}
            other => return Err(format!("a C13 subsection of kind {other:#x}")),
        }
        at += (8 + len).next_multiple_of(4);
    }

    // Parse module symbols including nested blocks, locals, defranges, and inline sites.
    let mut procedures: BTreeMap<u32, (String, SaidProc)> = BTreeMap::new();
    let mut at = 4usize;
    while at < symbol_bytes {
        let len = usize::from(u16_at(module, at));
        let kind = u16_at(module, at + 2);
        let body = &module[at + 4..at + 2 + len];
        match kind {
            S_GPROC32 => {
                let proc_at = at as u32;
                let end = u32_at(body, 4) as usize;
                if u16_at(module, end + 2) != S_END {
                    return Err(format!("the procedure at {at} ends at {end}, which is no S_END"));
                }
                let proc_ty = tpi.describe(u32_at(body, 24))?;
                let place = (u16_at(body, 32), u32_at(body, 28), u32_at(body, 12));
                let name = name_in(body, 35);

                let mut frame_flags = None;
                let mut locals: Vec<SaidLocal> = Vec::new();
                let mut inlines: Vec<SaidInline> = Vec::new();
                let mut block_stack: Vec<(u32, u32, Option<(u32, u32)>)> = Vec::new();
                let mut inline_stack: Vec<(u32, u32, SaidInline)> = Vec::new();

                let mut cur = at + 2 + len;
                while cur < end {
                    let rlen = usize::from(u16_at(module, cur));
                    let rkind = u16_at(module, cur + 2);
                    let rbody = &module[cur + 4..cur + 2 + rlen];
                    match rkind {
                        S_FRAMEPROC => {
                            frame_flags = Some(u32_at(rbody, 22));
                        }
                        S_BLOCK32 => {
                            let parent = u32_at(rbody, 0);
                            let bend = u32_at(rbody, 4);
                            let expected_parent =
                                block_stack.last().map_or(proc_at, |b| b.0);
                            if parent != expected_parent {
                                return Err(format!(
                                    "S_BLOCK32 at {cur} has parent {parent}, expected {expected_parent}"
                                ));
                            }
                            if u16_at(module, bend as usize + 2) != S_END {
                                return Err(format!("S_BLOCK32 at {cur} ends at {bend} != S_END"));
                            }
                            let code_size = u32_at(rbody, 8);
                            let code_off = u32_at(rbody, 12);
                            block_stack.push((
                                cur as u32,
                                bend,
                                Some((code_off - place.1, code_size)),
                            ));
                        }
                        S_END => {
                            let Some((_, bend, _)) = block_stack.pop() else {
                                return Err(format!("stray S_END at {cur} inside proc {proc_at}"));
                            };
                            if bend != cur as u32 {
                                return Err(format!("S_END at {cur} != block end {bend}"));
                            }
                        }
                        S_LOCAL => {
                            let lti = u32_at(rbody, 0);
                            let flags = u16_at(rbody, 4);
                            let lname = name_in(rbody, 6);
                            let ty = tpi.describe(lti)?;
                            let scope = block_stack.last().and_then(|b| b.2);
                            locals.push(SaidLocal {
                                name: lname,
                                flags,
                                ty,
                                scope,
                                ranges: Vec::new(),
                            });
                        }
                        S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE => {
                            let off = i32_at(rbody, 0);
                            locals
                                .last_mut()
                                .ok_or("defrange without S_LOCAL")?
                                .ranges
                                .push(format!("fp_full({off})"));
                        }
                        S_DEFRANGE_FRAMEPOINTER_REL => {
                            let off = i32_at(rbody, 0);
                            let start = u32_at(rbody, 4) - place.1;
                            let sec = u16_at(rbody, 8);
                            let cb = u16_at(rbody, 10);
                            locals
                                .last_mut()
                                .ok_or("defrange without S_LOCAL")?
                                .ranges
                                .push(format!("fp({off},{sec}:{start}+{cb})"));
                        }
                        S_DEFRANGE_REGISTER => {
                            let reg = u16_at(rbody, 0);
                            let start = u32_at(rbody, 4) - place.1;
                            let sec = u16_at(rbody, 8);
                            let cb = u16_at(rbody, 10);
                            locals
                                .last_mut()
                                .ok_or("defrange without S_LOCAL")?
                                .ranges
                                .push(format!("reg({reg},{sec}:{start}+{cb})"));
                        }
                        S_DEFRANGE_SUBFIELD_REGISTER => {
                            let reg = u16_at(rbody, 0);
                            let sub = u32_at(rbody, 4);
                            let start = u32_at(rbody, 8) - place.1;
                            let sec = u16_at(rbody, 12);
                            let cb = u16_at(rbody, 14);
                            locals
                                .last_mut()
                                .ok_or("defrange without S_LOCAL")?
                                .ranges
                                .push(format!("subreg({reg}+@{sub},{sec}:{start}+{cb})"));
                        }
                        S_DEFRANGE_REGISTER_REL => {
                            let reg = u16_at(rbody, 0);
                            let flags = u16_at(rbody, 2);
                            let off = i32_at(rbody, 4);
                            let start = u32_at(rbody, 8) - place.1;
                            let sec = u16_at(rbody, 12);
                            let cb = u16_at(rbody, 14);
                            locals
                                .last_mut()
                                .ok_or("defrange without S_LOCAL")?
                                .ranges
                                .push(format!("regrel({reg},{flags:#x},{off},{sec}:{start}+{cb})"));
                        }
                        S_DEFRANGE_REGISTER_REL_INDIR => {
                            let reg = u16_at(rbody, 0);
                            let off = i32_at(rbody, 4);
                            let udt = i32_at(rbody, 8);
                            let start = u32_at(rbody, 12) - place.1;
                            let sec = u16_at(rbody, 16);
                            let cb = u16_at(rbody, 18);
                            locals
                                .last_mut()
                                .ok_or("defrange without S_LOCAL")?
                                .ranges
                                .push(format!("indir({reg},{off},{udt},{sec}:{start}+{cb})"));
                        }
                        S_INLINESITE => {
                            let parent = u32_at(rbody, 0);
                            let iend = u32_at(rbody, 4);
                            let inlinee = u32_at(rbody, 8);
                            let expected_parent =
                                inline_stack.last().map_or(proc_at, |s| s.0);
                            if parent != expected_parent {
                                return Err(format!(
                                    "S_INLINESITE at {cur} parent {parent} != expected {expected_parent}"
                                ));
                            }
                            if u16_at(module, iend as usize + 2) != S_INLINESITE_END {
                                return Err(format!(
                                    "S_INLINESITE at {cur} end {iend} != S_INLINESITE_END"
                                ));
                            }
                            let (ikind, ibody) = ipi
                                .get(inlinee)
                                .ok_or_else(|| format!("dangling inlinee IPI {inlinee:#x}"))?;
                            if ikind != cv::LF_FUNC_ID {
                                return Err(format!("inlinee {inlinee:#x} is {ikind:#x}, not LF_FUNC_ID"));
                            }
                            let callee = name_in(ibody, 8);
                            let &(base_file, base_line) = inlinee_lines
                                .get(&inlinee)
                                .ok_or_else(|| format!("inlinee {inlinee:#x} ({callee}) missing from DEBUG_S_INLINEELINES"))?;
                            let spans =
                                decode_annotations(&rbody[12..], base_file, base_line, &files)?;
                            inline_stack.push((
                                cur as u32,
                                iend,
                                SaidInline { callee, spans, children: Vec::new() },
                            ));
                        }
                        S_INLINESITE_END => {
                            let Some((_, iend, node)) = inline_stack.pop() else {
                                return Err(format!("stray S_INLINESITE_END at {cur}"));
                            };
                            if iend != cur as u32 {
                                return Err(format!("S_INLINESITE_END at {cur} != expected {iend}"));
                            }
                            match inline_stack.last_mut() {
                                Some(parent) => parent.2.children.push(node),
                                None => inlines.push(node),
                            }
                        }
                        other => return Err(format!("unexpected nested symbol {other:#x} at {cur}")),
                    }
                    cur += 2 + rlen;
                }
                if !block_stack.is_empty() || !inline_stack.is_empty() {
                    return Err(format!("unclosed nested scope inside proc {name}"));
                }
                procedures.insert(
                    proc_at,
                    (
                        name,
                        SaidProc {
                            place,
                            proc_ty,
                            frame_flags,
                            lines: Vec::new(),
                            locals,
                            inlines,
                        },
                    ),
                );
                // Jump past the procedure's closing S_END.
                let end_len = usize::from(u16_at(module, end));
                at = end + 2 + end_len;
                continue;
            }
            S_SKIP | S_OBJNAME | S_COMPILE3 => {}
            other => return Err(format!("a symbol of kind {other:#x} at {at}")),
        }
        at += 2 + len;
    }

    let mut out = Said::new();
    for (name, mut proc) in procedures.values().cloned() {
        proc.lines = rows.remove(&(proc.place.0, proc.place.1)).unwrap_or_default();
        if out.insert(name.clone(), proc).is_some() {
            return Err(format!("two procedures named {name}"));
        }
    }
    if !rows.is_empty() {
        return Err(format!("line tables of no procedure: {:?}", rows.keys().collect::<Vec<_>>()));
    }

    // The globals: each record a reference to the procedure of its name.
    let (globals, records) = (&streams[usize::from(GLOBALS)], &streams[usize::from(RECORDS)]);
    let count = u32_at(globals, 8) as usize / 8;
    let mut referenced = BTreeSet::new();
    for n in 0..count {
        let at = u32_at(globals, 16 + 8 * n) as usize - 1;
        let body = &records[at + 4..];
        let (sym, name) = (u32_at(body, 4), name_in(body, 10));
        match procedures.get(&sym) {
            Some((it, _)) if *it == name => {}
            other => {
                return Err(format!("the reference {name} names the procedure at {sym}: {other:?}"));
            }
        }
        referenced.insert(name);
    }
    if referenced.len() != out.len() {
        return Err(format!("{} references of {} procedures", referenced.len(), out.len()));
    }
    Ok(out)
}

/// The PDB of two Rust functions: what each stream says of them is what was written, read
/// as a reader of the format reads it.
#[test]
fn a_pdb_holds_its_functions_names_places_and_lines() {
    let file = exe();
    let lines = [
        Lined { at: 0, file: "src/main.rs", line: 3, column: 1 },
        Lined { at: 4, file: "src/lib.rs", line: 10, column: 1 },
        Lined { at: 0, file: "src/main.rs", line: 20, column: 1 },
    ];
    let functions = [
        Func {
            key: key(1),
            addr: 0x1_4000_1010,
            size: 8,
            name: Some("app::main"),
            lines: 0..2,
            debug: None,
            inlined: 0..0,
        },
        Func {
            key: key(2),
            addr: 0x1_4000_2000,
            size: 16,
            name: None,
            lines: 2..3,
            debug: None,
            inlined: 0..0,
        },
    ];
    let id = [7u8; 16];
    let pdb = Model::new(
        headers(&file),
        id,
        &functions,
        &lines,
        &[],
        &[],
        &[("main", 0x1_4000_1100)],
    )
    .unwrap()
    .file();
    assert_eq!(&pdb[GUID_AT..GUID_AT + 16], &id, "the build id at its fixed place");
    let streams = streams(&pdb);
    assert_eq!(streams.len(), STREAMS);
    let info = &streams[usize::from(INFO)];
    assert_eq!((u32_at(info, 0), u32_at(info, 4), u32_at(info, 8)), (20000404, 0x1234_5678, 1));
    assert_eq!(
        &pdb[INFO_BLOCK * BLOCK..INFO_BLOCK * BLOCK + 12],
        &info[..12],
        "block 3 is the info stream"
    );

    let dbi = &streams[usize::from(DBI)];
    assert_eq!(u32_at(dbi, 0), u32::MAX);
    assert_eq!(u16_at(dbi, 58), 0x8664);
    let module_at = 64;
    assert_eq!(u16_at(dbi, module_at + 34), MODULE);
    let symbol_bytes = u32_at(dbi, module_at + 36) as usize;
    let c13_bytes = u32_at(dbi, module_at + 44) as usize;
    let module = &streams[usize::from(MODULE)];
    assert_eq!(u32_at(module, 0), CV_SIGNATURE_C13);
    assert_eq!(module.len(), symbol_bytes + c13_bytes + 4);
    let records = symbols(&module[4..symbol_bytes]);
    let procedures: Vec<(String, u32, u16, u32)> = records
        .iter()
        .filter(|it| it.0 == S_GPROC32)
        .map(|(_, body)| (name_in(body, 35), u32_at(body, 28), u16_at(body, 32), u32_at(body, 12)))
        .collect();
    assert_eq!(
        procedures,
        [("app::main".to_owned(), 0x10, 1, 8), ("blaze_fn_140002000".to_owned(), 0x1000, 1, 16)]
    );

    let got = said(&pdb).unwrap();
    assert_eq!(
        got["app::main"].lines,
        [(0, "src/main.rs".to_owned(), 3), (4, "src/lib.rs".to_owned(), 10)]
    );
    assert_eq!(got["blaze_fn_140002000"].lines, [(0, "src/main.rs".to_owned(), 20)]);

    let publics = &streams[usize::from(PUBLICS)];
    let (hash, map) = (u32_at(publics, 0) as usize, u32_at(publics, 4) as usize);
    assert_eq!(map, 4);
    let records = &streams[usize::from(RECORDS)];
    let at = u32_at(publics, 28 + hash) as usize;
    assert_eq!(u16_at(records, at + 2), S_PUB32);
    assert_eq!(name_in(&records[at + 4..], 10), "main");
}

/// Rust types (primitives, pointers/refs, structs, tuples, direct & niche enums as MSVC
/// union+discriminant, arrays, `&str`, `Vec`, cyclic struct), parameters, locals, scopes,
/// and all location forms (frame-relative, register, register-relative, indirect, ranged).
#[test]
fn a_pdb_describes_rust_types_locals_and_locations() {
    let file = exe();
    // Build a rich type table exercising every Rust type shape required by B7:
    // 0: u8, 1: i32, 2: usize, 3: bool, 4: char, 5: f64
    // 6: *const u8, 7: &str { data_ptr: *const u8 @ 0, length: usize @ 8 }
    // 8: [i32; 4] (16 bytes)
    // 9: Point { x: i32 @ 0, y: i32 @ 4 }
    // 10: (i32, bool) { __0: i32 @ 0, __1: bool @ 4 }
    // 11: Color (fieldless enum: Red=0, Green=1, Blue=2)
    // 12: MyEnum (direct tagged enum: Empty=0, Val(i32)=1, Pair{a:i32, b:u8}=2)
    // 13: Option<&str> (niche enum, tag at offset 0 size 8: None=0, Some(__0: &str))
    // 14: *mut i32, 15: Vec<i32> { ptr: *mut i32 @ 0, cap: usize @ 8, len: usize @ 16 }
    // 16: *const Node (cycle!), 17: Node { val: i32 @ 0, next: *const Node @ 8 }
    let types = vec![
        DebugType::Base { name: "u8".into(), size: 1, encoding: BaseEncoding::Unsigned },
        DebugType::Base { name: "i32".into(), size: 4, encoding: BaseEncoding::Signed },
        DebugType::Base { name: "usize".into(), size: 8, encoding: BaseEncoding::Unsigned },
        DebugType::Base { name: "bool".into(), size: 1, encoding: BaseEncoding::Bool },
        DebugType::Base { name: "char".into(), size: 4, encoding: BaseEncoding::Char },
        DebugType::Base { name: "f64".into(), size: 8, encoding: BaseEncoding::Float },
        DebugType::Pointer { name: "*const u8".into(), to: Some(0) },
        DebugType::Struct(Aggregate {
            name: "&str".into(),
            size: 16,
            fields: vec![
                Field { name: "data_ptr".into(), offset: 0, ty: 6 },
                Field { name: "length".into(), offset: 8, ty: 2 },
            ],
        }),
        DebugType::Array { of: 1, len: 4 },
        DebugType::Struct(Aggregate {
            name: "app::Point".into(),
            size: 8,
            fields: vec![
                Field { name: "x".into(), offset: 0, ty: 1 },
                Field { name: "y".into(), offset: 4, ty: 1 },
            ],
        }),
        DebugType::Struct(Aggregate {
            name: "(i32, bool)".into(),
            size: 8,
            fields: vec![
                Field { name: "__0".into(), offset: 0, ty: 1 },
                Field { name: "__1".into(), offset: 4, ty: 3 },
            ],
        }),
        DebugType::Names {
            name: "app::Color".into(),
            size: 1,
            names: vec![("Red".into(), 0), ("Green".into(), 1), ("Blue".into(), 2)],
        },
        DebugType::Enum {
            of: Aggregate { name: "app::MyEnum".into(), size: 12, fields: vec![] },
            tag: Some(EnumTag { offset: 0, size: 4, states: false }),
            variants: vec![
                EnumVariant { name: "Empty".into(), tag: Some(0), fields: vec![] },
                EnumVariant {
                    name: "Val".into(),
                    tag: Some(1),
                    fields: vec![Field { name: "__0".into(), offset: 4, ty: 1 }],
                },
                EnumVariant {
                    name: "Pair".into(),
                    tag: Some(2),
                    fields: vec![
                        Field { name: "a".into(), offset: 4, ty: 1 },
                        Field { name: "b".into(), offset: 8, ty: 0 },
                    ],
                },
            ],
        },
        DebugType::Enum {
            of: Aggregate { name: "core::option::Option<&str>".into(), size: 16, fields: vec![] },
            tag: Some(EnumTag { offset: 0, size: 8, states: false }),
            variants: vec![
                EnumVariant { name: "None".into(), tag: Some(0), fields: vec![] },
                EnumVariant {
                    name: "Some".into(),
                    tag: None,
                    fields: vec![Field { name: "__0".into(), offset: 0, ty: 7 }],
                },
            ],
        },
        DebugType::Pointer { name: "*mut i32".into(), to: Some(1) },
        DebugType::Struct(Aggregate {
            name: "alloc::vec::Vec<i32>".into(),
            size: 24,
            fields: vec![
                Field { name: "ptr".into(), offset: 0, ty: 14 },
                Field { name: "cap".into(), offset: 8, ty: 2 },
                Field { name: "len".into(), offset: 16, ty: 2 },
            ],
        }),
        DebugType::Pointer { name: "*const app::Node".into(), to: Some(17) },
        DebugType::Struct(Aggregate {
            name: "app::Node".into(),
            size: 16,
            fields: vec![
                Field { name: "val".into(), offset: 0, ty: 1 },
                Field { name: "next".into(), offset: 8, ty: 16 },
            ],
        }),
    ];

    let dbg = FunctionDebug {
        frame_base: vec![0x56], // DW_OP_reg6 = RBP
        types,
        scopes: vec![Scope { parent: None, ranges: vec![(8, 48)] }],
        locals: vec![
            // Parameter in RCX over [0..16), then frame -8 over [16..64).
            Local {
                name: "pt".into(),
                param: true,
                ty: Some(9),
                place: LocalPlace::Ranges(vec![
                    (0, 16, vec![0x52]),         // DW_OP_reg2 = RCX
                    (16, 64, vec![0x91, 0x78]),  // DW_OP_fbreg(-8)
                ]),
                scope: None,
            },
            // Indirect parameter at *(RBP - 16) + 0.
            Local {
                name: "text".into(),
                param: true,
                ty: Some(7),
                place: LocalPlace::Ranges(vec![(0, 64, vec![0x91, 0x70, 0x06])]), // fbreg(-16), deref
                scope: None,
            },
            // Frame-relative full scope locals.
            Local {
                name: "nums".into(),
                param: false,
                ty: Some(15),
                place: LocalPlace::Frame(-40),
                scope: None,
            },
            Local {
                name: "choice".into(),
                param: false,
                ty: Some(12),
                place: LocalPlace::Frame(-56),
                scope: Some(0),
            },
            Local {
                name: "opt_s".into(),
                param: false,
                ty: Some(13),
                place: LocalPlace::Frame(-72),
                scope: Some(0),
            },
            Local {
                name: "arr".into(),
                param: false,
                ty: Some(8),
                place: LocalPlace::Ranges(vec![(8, 48, vec![0x77, 0x20])]), // DW_OP_breg7(+32) = [RSP+32]
                scope: Some(0),
            },
            Local {
                name: "tup".into(),
                param: false,
                ty: Some(10),
                place: LocalPlace::Frame(-80),
                scope: None,
            },
            Local {
                name: "col".into(),
                param: false,
                ty: Some(11),
                place: LocalPlace::Frame(-84),
                scope: None,
            },
            Local {
                name: "node".into(),
                param: false,
                ty: Some(17),
                place: LocalPlace::Frame(-104),
                scope: None,
            },
            Local {
                name: "ch".into(),
                param: false,
                ty: Some(4),
                place: LocalPlace::Frame(-108),
                scope: None,
            },
            Local {
                name: "pi".into(),
                param: false,
                ty: Some(5),
                place: LocalPlace::Frame(-120),
                scope: None,
            },
        ],
        inlined: vec![],
    };

    let lines = [Lined { at: 0, file: "src/main.rs", line: 10, column: 1 }];
    let functions = [
        Func {
            key: key(1),
            addr: 0x1_4000_1000,
            size: 64,
            name: Some("app::demo"),
            lines: 0..1,
            debug: Some(&dbg),
            inlined: 0..0,
        },
        // Second function with identical types verifies TPI content deduplication.
        Func {
            key: key(2),
            addr: 0x1_4000_1100,
            size: 64,
            name: Some("app::demo2"),
            lines: 0..1,
            debug: Some(&dbg),
            inlined: 0..0,
        },
    ];
    let model1 = Model::new(headers(&file), [1; 16], &functions[..1], &lines, &[], &[], &[]).unwrap();
    let tpi_count_one = model1.tpi.count();
    let model2 = Model::new(headers(&file), [1; 16], &functions, &lines, &[], &[], &[]).unwrap();
    assert_eq!(
        model2.tpi.count(),
        tpi_count_one,
        "identical types across functions deduplicate to the same TPI records"
    );

    let pdb = model2.file();
    let parsed = said(&pdb).expect("structural PDB parse must pass");
    let demo = &parsed["app::demo"];
    assert_eq!(demo.frame_flags, Some((2 << 14) | (2 << 16)), "S_FRAMEPROC encodes RBP");
    assert!(demo.proc_ty.contains("app::Point") && demo.proc_ty.contains("&str"));
    assert_eq!(demo.locals.len(), 11);

    let find = |name: &str| demo.locals.iter().find(|l| l.name == name).unwrap();
    assert_eq!(find("pt").flags, cv::LOCAL_IS_PARAM);
    assert_eq!(find("pt").ranges, ["reg(330,1:0+16)", "fp(-8,1:16+48)"]);
    assert!(find("pt").ty.contains("struct(app::Point,sz=8") && find("pt").ty.contains("x@0:i32") && find("pt").ty.contains("y@4:i32"));

    assert_eq!(find("text").flags, cv::LOCAL_IS_PARAM);
    assert_eq!(find("text").ranges, ["indir(334,-16,0,1:0+64)"]);
    assert!(find("text").ty.contains("data_ptr@0:ptr(") && find("text").ty.contains("length@8:u64"));

    assert_eq!(find("nums").ranges, ["fp_full(-40)"]);
    assert!(find("nums").ty.contains("alloc::vec::Vec<i32>,sz=24"));

    assert_eq!(find("choice").scope, Some((8, 40)));
    assert!(find("choice").ty.starts_with("union(app::MyEnum,sz=12"));
    assert!(find("choice").ty.contains("app::MyEnum::Discriminant"));
    assert!(find("choice").ty.contains("Empty=0;Val=1;Pair=2"));
    assert!(find("choice").ty.contains("app::MyEnum::Pair") && find("choice").ty.contains("a@4:i32") && find("choice").ty.contains("b@8:u8"));

    assert!(find("opt_s").ty.starts_with("union(core::option::Option<&str>,sz=16"));
    assert!(find("opt_s").ty.contains("None=0"));
    assert!(find("opt_s").ty.contains("__0@0:struct(&str"));

    assert_eq!(find("arr").ranges, ["regrel(335,0x0,32,1:8+40)"]);
    assert_eq!(find("arr").ty, "array(i32;bytes=16;idx=u64)");
    assert!(find("tup").ty.contains("__0@0:i32;__1@4:bool"));
    assert!(find("col").ty.contains("enum(app::Color,under=u8") && find("col").ty.contains("Red=0;Green=1;Blue=2"));
    assert!(find("node").ty.contains("fwd(app::Node->complete=true)"));
    assert_eq!(find("ch").ty, "char");
    assert_eq!(find("pi").ty, "f64");
}

/// Nested inline frames (`caller -> mid -> leaf`): verifies IPI `LF_FUNC_ID`,
/// `DEBUG_S_INLINEELINES`, nested `S_INLINESITE`..`S_INLINESITE_END` with decoded binary
/// annotations, and outer `DEBUG_S_LINES` attributed to `caller`'s call site.
#[test]
fn a_pdb_describes_nested_inline_frames_and_call_site_lines() {
    let file = exe();
    // caller [0..40):
    //   0..8   main.rs:29  (outer)
    //   8..16  mid.rs:19   (inlined mid, called from main.rs:30)
    //  16..28  leaf.rs:10  (inlined leaf inside mid, called from mid.rs:20)
    //  28..32  mid.rs:21   (back in mid)
    //  32..40  main.rs:31  (back in caller)
    let lines = [
        Lined { at: 0, file: "src/main.rs", line: 29, column: 1 },
        Lined { at: 8, file: "src/mid.rs", line: 19, column: 1 },
        Lined { at: 16, file: "src/leaf.rs", line: 10, column: 1 },
        Lined { at: 28, file: "src/mid.rs", line: 21, column: 1 },
        Lined { at: 32, file: "src/main.rs", line: 31, column: 1 },
    ];
    let inline_ranges = [(8u32, 32u32), (16u32, 28u32)];
    let inlined = [
        Inlined {
            parent: None,
            callee: "app::mid",
            call_file: "src/main.rs",
            call_line: 30,
            decl_file: Some("src/mid.rs"),
            decl_line: 18,
            ranges: 0..1,
        },
        Inlined {
            parent: Some(0),
            callee: "app::leaf",
            call_file: "src/mid.rs",
            call_line: 20,
            decl_file: Some("src/leaf.rs"),
            decl_line: 9,
            ranges: 1..2,
        },
    ];
    let functions = [Func {
        key: key(1),
        addr: 0x1_4000_1000,
        size: 40,
        name: Some("app::caller"),
        lines: 0..5,
        debug: None,
        inlined: 0..2,
    }];
    let pdb =
        Model::new(headers(&file), [2; 16], &functions, &lines, &inlined, &inline_ranges, &[])
            .unwrap()
            .file();
    let parsed = said(&pdb).expect("structural parse with inline frames");
    let caller = &parsed["app::caller"];
    // Outer DEBUG_S_LINES maps the entire inlined region [8..32) to caller's call site main.rs:30!
    assert_eq!(
        caller.lines,
        [
            (0, "src/main.rs".to_owned(), 29),
            (8, "src/main.rs".to_owned(), 30),
            (32, "src/main.rs".to_owned(), 31),
        ]
    );
    // Nested S_INLINESITE tree: mid contains leaf!
    assert_eq!(caller.inlines.len(), 1);
    let mid = &caller.inlines[0];
    assert_eq!(mid.callee, "app::mid");
    assert_eq!(
        mid.spans,
        [
            (8, 8, "src/mid.rs".to_owned(), 19),
            (16, 12, "src/mid.rs".to_owned(), 20), // call site of leaf!
            (28, 4, "src/mid.rs".to_owned(), 21),
        ]
    );
    assert_eq!(mid.children.len(), 1);
    let leaf = &mid.children[0];
    assert_eq!(leaf.callee, "app::leaf");
    assert_eq!(leaf.spans, [(16, 12, "src/leaf.rs".to_owned(), 10)]);
}

/// `hashStringV1`'s values for names LLVM's tests and the format's readers agree on: the
/// case of ASCII letters does not change the hash, and a name's tail of 1 to 3 bytes counts.
#[test]
fn the_name_hash_folds_case_and_counts_every_byte() {
    assert_eq!(hash_v1(b"/names"), hash_v1(b"/NAMES"));
    assert_ne!(hash_v1(b"abcd"), hash_v1(b"abcde"));
    assert_ne!(hash_v1(b"abcde"), hash_v1(b"abcdef"));
    assert_ne!(hash_v1(b"abcdef"), hash_v1(b"abcdefg"));
}

/// A PDB past the first interval of 4096 blocks keeps every interval's free block maps out
/// of its streams and in its file.
#[test]
fn a_pdb_past_an_interval_keeps_its_free_block_maps() {
    let file = exe();
    let lines: Vec<Lined<'_>> = (0..60_000 * 32)
        .map(|n| Lined { at: n % 32, file: "src/main.rs", line: n + 1, column: 1 })
        .collect();
    let functions: Vec<Func<'_>> = (0..60_000u32)
        .map(|n| Func {
            key: key(n),
            addr: 0x1_4000_1000 + u64::from(n % 0x3000),
            size: 1,
            name: Some("f"),
            lines: (n * 32)..(n * 32 + 32),
            debug: None,
            inlined: 0..0,
        })
        .collect();
    let pdb = Model::new(headers(&file), [1; 16], &functions, &lines, &[], &[], &[]).unwrap().file();
    assert!(
        pdb.len() / BLOCK > BLOCK,
        "the test needs more than one interval: {} blocks",
        pdb.len() / BLOCK
    );
    let streams = streams(&pdb);
    assert_eq!(streams.len(), STREAMS);
}

/// How long a PDB of a program of rune-desktop's size takes and how big it is: 400,000
/// functions of 10 rows in 2,000 files, named as rustc's v0 names are long. Not a check:
/// `cargo test --release -p blaze-link --lib a_desktop_sized_pdb -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement"]
fn a_desktop_sized_pdb() {
    let file = exe();
    let files: Vec<String> =
        (0..2000).map(|n| format!("C:\\Users\\dev\\src\\crate{}\\src\\module{n}.rs", n % 300)).collect();
    let names: Vec<String> = (0..400_000)
        .map(|n| format!("_RNvMs{n}_NtCsajBxKdOt8Cw_16opencode_desktop4viewNtB5_4View6render{n}"))
        .collect();
    let lines: Vec<Lined<'_>> = (0..4_000_000u32)
        .map(|n| Lined {
            at: (n % 10) * 4,
            file: &files[(n / 10) as usize % 2000],
            line: n % 5000 + 1,
            column: 1,
        })
        .collect();
    let functions: Vec<Func<'_>> = (0..400_000u32)
        .map(|n| Func {
            key: key(n),
            addr: 0x1_4000_1000 + u64::from(n % 0x2f00),
            size: 40,
            name: Some(&names[n as usize]),
            lines: (n * 10)..(n * 10 + 10),
            debug: None,
            inlined: 0..0,
        })
        .collect();
    let started = std::time::Instant::now();
    let pdb =
        Model::new(headers(&file), [1; 16], &functions, &lines, &[], &[], &[]).unwrap().file();
    eprintln!(
        "{} functions: {:.3} s, {:.1} MB",
        functions.len(),
        started.elapsed().as_secs_f64(),
        pdb.len() as f64 / 1e6
    );
}

#[derive(Clone, Debug)]
struct TestFunc {
    addr: u64,
    size: u64,
    name: String,
    rows: Vec<(u32, u32, u32)>,
    debug: Option<FunctionDebug>,
    inlined: Vec<(Option<u32>, String, u32, u32, Option<(u32, u32)>, Vec<(u32, u32)>)>,
}

/// A program of functions by number: each its address, size, name, rows, optional locals/types
/// and optional nested inline frames.
#[derive(Clone, Debug, Default)]
struct Program {
    funcs: BTreeMap<u32, TestFunc>,
    next: u64,
}

const FILES: [&str; 4] = ["src/a.rs", "src/b.rs", "src/c.rs", "src/d.rs"];

fn make_debug(seed: u8, size: u32) -> Option<FunctionDebug> {
    if seed % 4 == 0 {
        return None;
    }
    let kind = seed % 3;
    let types = match kind {
        0 => vec![
            DebugType::Base { name: "i32".into(), size: 4, encoding: BaseEncoding::Signed },
            DebugType::Struct(Aggregate {
                name: format!("app::S{}", seed % 5),
                size: 8,
                fields: vec![
                    Field { name: "a".into(), offset: 0, ty: 0 },
                    Field { name: "b".into(), offset: 4, ty: 0 },
                ],
            }),
        ],
        1 => vec![
            DebugType::Base { name: "u8".into(), size: 1, encoding: BaseEncoding::Unsigned },
            DebugType::Base { name: "usize".into(), size: 8, encoding: BaseEncoding::Unsigned },
            DebugType::Pointer { name: "*const u8".into(), to: Some(0) },
            DebugType::Struct(Aggregate {
                name: "&str".into(),
                size: 16,
                fields: vec![
                    Field { name: "data_ptr".into(), offset: 0, ty: 2 },
                    Field { name: "length".into(), offset: 8, ty: 1 },
                ],
            }),
        ],
        _ => vec![
            DebugType::Base { name: "i32".into(), size: 4, encoding: BaseEncoding::Signed },
            DebugType::Enum {
                of: Aggregate { name: format!("app::E{}", seed % 4), size: 8, fields: vec![] },
                tag: Some(EnumTag { offset: 0, size: 4, states: false }),
                variants: vec![
                    EnumVariant { name: "Zero".into(), tag: Some(0), fields: vec![] },
                    EnumVariant {
                        name: "One".into(),
                        tag: Some(1),
                        fields: vec![Field { name: "__0".into(), offset: 4, ty: 0 }],
                    },
                ],
            },
        ],
    };
    let top_ty = (types.len() - 1) as u32;
    let mut locals = vec![Local {
        name: "arg".into(),
        param: true,
        ty: Some(top_ty),
        place: if seed & 1 == 0 {
            LocalPlace::Frame(-8)
        } else {
            LocalPlace::Ranges(vec![(0, size, vec![0x52])]) // RCX
        },
        scope: None,
    }];
    let scopes = if size >= 12 {
        locals.push(Local {
            name: "inner".into(),
            param: false,
            ty: Some(0),
            place: LocalPlace::Frame(-16 - i64::from(seed % 3) * 8),
            scope: Some(0),
        });
        vec![Scope { parent: None, ranges: vec![(4, size - 4)] }]
    } else {
        vec![]
    };
    Some(FunctionDebug { frame_base: vec![0x56], types, scopes, locals, inlined: vec![] })
}

impl Program {
    /// Function `n` made again from `seed`: a new place, size, rows, locals/types and inlines.
    fn make(&mut self, n: u32, seed: u8, name: Option<String>) {
        self.next += 64;
        let size = 16 + 4 * u64::from(seed % 7);
        let rows: Vec<(u32, u32, u32)> = (0..u32::from(seed % 6))
            .map(|row| (row * 2, u32::from(seed.wrapping_add(row as u8)) % 4, 10 + u32::from(seed) + row))
            .collect();
        let name = name
            .or_else(|| self.funcs.get(&n).map(|it| it.name.clone()))
            .unwrap_or_else(|| format!("app::f{n}"));
        let debug = make_debug(seed, size as u32);
        let inlined = if seed % 3 == 1 && !rows.is_empty() && size >= 16 {
            let mut sites = vec![(
                None,
                format!("app::inl{}", seed % 5),
                u32::from(seed % 4),
                50 + u32::from(seed % 20),
                Some((u32::from((seed + 1) % 4), 5 + u32::from(seed % 10))),
                vec![(2u32, (size as u32).min(12))],
            )];
            if seed % 2 == 1 && size >= 20 {
                sites.push((
                    Some(0),
                    format!("app::leaf{}", seed % 3),
                    u32::from((seed + 1) % 4),
                    12,
                    Some((u32::from((seed + 2) % 4), 3)),
                    vec![(4u32, 8u32)],
                ));
            }
            sites
        } else {
            vec![]
        };
        self.funcs.insert(
            n,
            TestFunc {
                addr: 0x1_4000_1000 + self.next % 0x2f00,
                size,
                name,
                rows,
                debug,
                inlined,
            },
        );
    }

    fn input(
        &self,
        only: Option<&[u32]>,
    ) -> (Vec<Func<'_>>, Vec<Lined<'_>>, Vec<Inlined<'_>>, Vec<(u32, u32)>) {
        let (mut functions, mut lines, mut inlined, mut inline_ranges) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for (n, f) in &self.funcs {
            if only.is_some_and(|it| !it.contains(n)) {
                continue;
            }
            let start = lines.len() as u32;
            lines.extend(f.rows.iter().map(|(at, file, line)| Lined {
                at: *at,
                file: FILES[*file as usize],
                line: *line,
                column: 1,
            }));
            let inl_start = inlined.len() as u32;
            for (parent, callee, call_file, call_line, decl, ranges) in &f.inlined {
                let r_start = inline_ranges.len() as u32;
                inline_ranges.extend_from_slice(ranges);
                inlined.push(Inlined {
                    parent: *parent,
                    callee,
                    call_file: FILES[*call_file as usize],
                    call_line: *call_line,
                    decl_file: decl.map(|(df, _)| FILES[df as usize]),
                    decl_line: decl.map_or(0, |(_, dl)| dl),
                    ranges: r_start..inline_ranges.len() as u32,
                });
            }
            functions.push(Func {
                key: key(*n),
                addr: f.addr,
                size: f.size,
                name: Some(&f.name),
                lines: start..lines.len() as u32,
                debug: f.debug.as_ref(),
                inlined: inl_start..inlined.len() as u32,
            });
        }
        (functions, lines, inlined, inline_ranges)
    }
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Edit(u8, u8),
    Add(u8, u8),
    Remove(u8),
    Rename(u8),
    /// The function's code becomes none.
    Empty(u8),
}

fn op(tape: &blaze_sim::Tape) -> Op {
    let n = tape.int_in(0..=11u8, "function");
    let seed = tape.int::<u8>("body");
    match tape.int_in(0..=6u8, "edit kind") {
        0..=2 => Op::Edit(n, seed),
        3 => Op::Add(n, seed),
        4 => Op::Remove(n),
        5 => Op::Rename(n),
        _ => Op::Empty(n),
    }
}

/// How a test's patch is applied: as it is, or missing one of its writes (the oracle's
/// control).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Plant {
    None,
    DropsAWrite,
}

/// `ops` applied one link each, the PDB patched by each link's change (or laid out whole when
/// the model asks); after each, the file reads as the PDB of the same program laid out whole,
/// across procedures, places, outer lines, TPI/IPI hashes, locals, types, scopes, and inline
/// frames.
fn refines(ops: &[Op], plant: Plant) -> Result<(), String> {
    let image = exe();
    let mut program = Program::default();
    for n in 0..4 {
        program.make(n, n as u8 * 3 + 1, None);
    }
    let (functions, lines, inlined, inline_ranges) = program.input(None);
    let mut model = Model::new(
        headers(&image),
        [1; 16],
        &functions,
        &lines,
        &inlined,
        &inline_ranges,
        &[("main", 0x1_4000_1100)],
    )?;
    let mut file = model.file();
    for (step, op) in ops.iter().enumerate() {
        let (changed, gone): (Vec<u32>, Vec<u32>) = match *op {
            Op::Edit(n, seed) if program.funcs.contains_key(&u32::from(n)) => {
                program.make(u32::from(n), seed, None);
                (vec![u32::from(n)], vec![])
            }
            Op::Add(n, seed) if !program.funcs.contains_key(&u32::from(n)) => {
                program.make(u32::from(n), seed, None);
                (vec![u32::from(n)], vec![])
            }
            Op::Remove(n) if program.funcs.remove(&u32::from(n)).is_some() => {
                (vec![], vec![u32::from(n)])
            }
            Op::Empty(n) if program.funcs.contains_key(&u32::from(n)) => {
                let it = program.funcs.get_mut(&u32::from(n)).unwrap();
                it.size = 0;
                it.rows.clear();
                it.inlined.clear();
                (vec![u32::from(n)], vec![])
            }
            Op::Rename(n) if program.funcs.contains_key(&u32::from(n)) => {
                let name = format!("app::renamed{step}::f{n}");
                program.make(u32::from(n), step as u8, Some(name));
                (vec![u32::from(n)], vec![])
            }
            _ => continue,
        };
        let (functions, lines, inlined, inline_ranges) = program.input(Some(&changed));
        let gone: Vec<InstanceKey> = gone.into_iter().map(key).collect();
        let id = [step as u8 + 2; 16];
        match model.patch(
            headers(&image),
            id,
            &functions,
            &lines,
            &inlined,
            &inline_ranges,
            &gone,
            program.funcs.len(),
            None,
        )? {
            Ok(mut writes) => {
                if plant == Plant::DropsAWrite && writes.len() > 1 {
                    writes.remove(0);
                }
                file.resize(model.len() as usize, 0);
                for (at, bytes) in writes {
                    file[at as usize..at as usize + bytes.len()].copy_from_slice(&bytes);
                }
            }
            Err(_) => {
                let (functions, lines, inlined, inline_ranges) = program.input(None);
                model = Model::new(
                    headers(&image),
                    id,
                    &functions,
                    &lines,
                    &inlined,
                    &inline_ranges,
                    &[("main", 0x1_4000_1100)],
                )?;
                file = model.file();
            }
        }
        let (functions, lines, inlined, inline_ranges) = program.input(None);
        let fresh = Model::new(
            headers(&image),
            id,
            &functions,
            &lines,
            &inlined,
            &inline_ranges,
            &[("main", 0x1_4000_1100)],
        )?
        .file();
        let (patched, whole) = (said(&file)?, said(&fresh)?);
        if patched != whole {
            return Err(format!(
                "after {op:?}: the patched PDB says {patched:?}, the whole one {whole:?}"
            ));
        }
        if file[GUID_AT..GUID_AT + 16] != id {
            return Err(format!("after {op:?}: the PDB carries another build id"));
        }
    }
    Ok(())
}

/// The refinement: after any sequence of edits (bodies, locals, types, inlined calls, added,
/// removed and renamed functions, a function's code made none), the PDB patched by each link's
/// change reads as the one laid out whole from the same program.
#[test]
fn a_pdb_kept_by_patches_reads_as_one_laid_out_whole() {
    blaze_sim::check(blaze_sim::Config::cases(200), |tape| {
        refines(&tape.vec(0..=24, "edits", op), Plant::None)
    });
}

/// The oracle's control: a patch applied without one of its writes is caught.
#[test]
fn the_oracle_catches_a_patch_missing_a_write() {
    let ops = [Op::Edit(1, 9), Op::Edit(2, 30), Op::Add(7, 4)];
    assert_eq!(refines(&ops, Plant::None), Ok(()));
    assert!(refines(&ops, Plant::DropsAWrite).is_err(), "the oracle missed a lost write");
}

/// A body edit writes its function's records and the tables that name them, not the file:
/// among 2,000 functions (with locals, types, and inline frames), an edit using existing types
/// writes a few blocks and leaves TPI/IPI untouched.
#[test]
fn a_body_edit_writes_blocks_not_the_file() {
    let image = exe();
    let mut program = Program::default();
    for n in 0..2000 {
        program.make(n, (n % 200) as u8, None);
    }
    let (functions, lines, inlined, inline_ranges) = program.input(None);
    let mut model =
        Model::new(headers(&image), [1; 16], &functions, &lines, &inlined, &inline_ranges, &[])
            .unwrap();
    let whole = model.file().len();
    let tpi_before = model.tpi.record_bytes();
    let ipi_before = model.ipi.record_bytes();
    // Edit function 700 with a seed whose types and inlinees already exist in the program.
    program.make(700, 3, None);
    let (functions, lines, inlined, inline_ranges) = program.input(Some(&[700]));
    let writes = model
        .patch(
            headers(&image),
            [2; 16],
            &functions,
            &lines,
            &inlined,
            &inline_ranges,
            &[],
            2000,
            None,
        )
        .unwrap()
        .unwrap();
    let written: usize = writes.iter().map(|it| it.1.len()).sum();
    assert_eq!(model.tpi.record_bytes(), tpi_before, "existing types were deduplicated");
    assert_eq!(model.ipi.record_bytes(), ipi_before, "existing inlinees were deduplicated");
    assert!(
        written <= 6 * BLOCK,
        "{written} bytes written of a {whole}-byte PDB: {:?}",
        writes.iter().map(|it| (it.0, it.1.len())).collect::<Vec<_>>()
    );
}

/// How long an edit's patch of a desktop-sized PDB takes and what it writes. Not a check:
/// `cargo test --release -p blaze-link --lib a_desktop_sized_patch -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement"]
fn a_desktop_sized_patch() {
    let image = exe();
    let mut program = Program::default();
    for n in 0..400_000 {
        program.make(
            n,
            (n % 251) as u8,
            Some(format!("_RNvMs{n}_NtCsajBxKdOt8Cw_16opencode_desktop4viewNtB5_4View6render{n}")),
        );
    }
    let (functions, lines, inlined, inline_ranges) = program.input(None);
    let started = std::time::Instant::now();
    let mut model =
        Model::new(headers(&image), [1; 16], &functions, &lines, &inlined, &inline_ranges, &[])
            .unwrap();
    let whole = model.file();
    eprintln!("whole: {:.3} s, {:.1} MB", started.elapsed().as_secs_f64(), whole.len() as f64 / 1e6);
    for (step, n) in [123_456u32, 7, 399_999].into_iter().enumerate() {
        program.make(n, 200 + step as u8, None);
        let (functions, lines, inlined, inline_ranges) = program.input(Some(&[n]));
        let started = std::time::Instant::now();
        let writes = model
            .patch(
                headers(&image),
                [2 + step as u8; 16],
                &functions,
                &lines,
                &inlined,
                &inline_ranges,
                &[],
                400_000,
                None,
            )
            .unwrap()
            .unwrap();
        let written: usize = writes.iter().map(|it| it.1.len()).sum();
        eprintln!(
            "edit {n}: {:.6} s, {written} bytes in {} writes",
            started.elapsed().as_secs_f64(),
            writes.len()
        );
    }
}
