use blaze_codegen::InstanceKey;

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
    for (name, rva, size, flags) in [(b".text\0\0\0", 0x1000u32, 0x3000u32, 0x6000_0020u32), (b".rdata\0\0", 0x4000, 0x800, 0x4000_0040)] {
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
        Func { key: key(1), addr: 0x1_4000_1010, size: 8, name: Some("app::main"), lines: 0..2 },
        Func { key: key(2), addr: 0x1_4000_2000, size: 16, name: None, lines: 2..3 },
    ];
    let id = [7u8; 16];
    let pdb = Model::new(headers(&file), id, &functions, &lines, &[("main", 0x1_4000_1100)]).unwrap().file();
    assert_eq!(&pdb[GUID_AT..GUID_AT + 16], &id, "the build id at its fixed place");
    let streams = streams(&pdb);
    assert_eq!(streams.len(), STREAMS);
    let info = &streams[usize::from(INFO)];
    assert_eq!((u32_at(info, 0), u32_at(info, 4), u32_at(info, 8)), (20000404, 0x1234_5678, 1));
    assert_eq!(&pdb[INFO_BLOCK * BLOCK..INFO_BLOCK * BLOCK + 12], &info[..12], "block 3 is the info stream");

    let dbi = &streams[usize::from(DBI)];
    assert_eq!(u32_at(dbi, 0), u32::MAX);
    assert_eq!(u16::from_le_bytes([dbi[58], dbi[59]]), 0x8664);
    // The module's descriptor names its stream and its sizes.
    let module_at = 64;
    assert_eq!(u16::from_le_bytes([dbi[module_at + 34], dbi[module_at + 35]]), MODULE);
    let symbol_bytes = u32_at(dbi, module_at + 36) as usize;
    let c13_bytes = u32_at(dbi, module_at + 44) as usize;
    let module = &streams[usize::from(MODULE)];
    assert_eq!(u32_at(module, 0), CV_SIGNATURE_C13);
    assert_eq!(module.len(), symbol_bytes + c13_bytes + 4);
    let records = symbols(&module[4..symbol_bytes]);
    let procedures: Vec<(String, u32, u16, u32)> = records
        .iter()
        .filter(|it| it.0 == S_GPROC32)
        .map(|(_, body)| (name_in(body, 35), u32_at(body, 28), u16::from_le_bytes([body[32], body[33]]), u32_at(body, 12)))
        .collect();
    assert_eq!(
        procedures,
        [("app::main".to_owned(), 0x10, 1, 8), ("blaze_fn_140002000".to_owned(), 0x1000, 1, 16)]
    );
    // Each procedure's `End` is the offset of an `S_END`.
    let mut at = 4;
    for (kind, body) in &records {
        if *kind == S_GPROC32 {
            let end = u32_at(body, 4) as usize;
            assert_eq!(u16::from_le_bytes([module[end + 2], module[end + 3]]), S_END);
        }
        at += 4 + body.len();
    }
    assert_eq!(at, symbol_bytes);

    // The lines: per function, its section, offset and rows by file.
    let names = &streams[usize::from(NAMES)];
    let name_at = |offset: u32| name_in(&names[12..], offset as usize);
    let c13 = &module[symbol_bytes..symbol_bytes + c13_bytes];
    let mut at = 0;
    let mut checksums = Vec::new();
    let mut rows = Vec::new();
    while at < c13.len() {
        let (kind, len) = (u32_at(c13, at), u32_at(c13, at + 4) as usize);
        let body = &c13[at + 8..at + 8 + len];
        match kind {
            DEBUG_S_FILECHKSMS => checksums = body.chunks(8).map(|it| name_at(u32_at(it, 0))).collect(),
            DEBUG_S_LINES => {
                let (offset, section) = (u32_at(body, 0), u16::from_le_bytes([body[4], body[5]]));
                let mut block = 12;
                while block < body.len() {
                    let (file, count) = (u32_at(body, block) as usize / 8, u32_at(body, block + 4) as usize);
                    for n in 0..count {
                        let row = block + 12 + 8 * n;
                        let line = u32_at(body, row + 4) & 0xff_ffff;
                        rows.push((section, offset + u32_at(body, row), checksums[file].clone(), line));
                    }
                    block += u32_at(body, block + 8) as usize;
                }
            }
            DEBUG_S_IGNORE => {}
            other => panic!("a C13 subsection of kind {other:#x}"),
        }
        at += (8 + len).next_multiple_of(4);
    }
    assert_eq!(
        rows,
        [
            (1, 0x10, "src/main.rs".to_owned(), 3),
            (1, 0x14, "src/lib.rs".to_owned(), 10),
            (1, 0x1000, "src/main.rs".to_owned(), 20)
        ]
    );

    // The publics: the native functions', in the address map by place; Rust's are the
    // module's procedures and the globals' references.
    let publics = &streams[usize::from(PUBLICS)];
    let (hash, map) = (u32_at(publics, 0) as usize, u32_at(publics, 4) as usize);
    assert_eq!(map, 4);
    let records = &streams[usize::from(RECORDS)];
    let named: Vec<String> = (0..1)
        .map(|n| {
            let at = u32_at(publics, 28 + hash + 4 * n) as usize;
            assert_eq!(u16::from_le_bytes([records[at + 2], records[at + 3]]), S_PUB32);
            name_in(&records[at + 4..], 10)
        })
        .collect();
    assert_eq!(named, ["main"]);
    // The GSI hash: one record of 8 bytes.
    assert_eq!(u32_at(publics, 28 + 8), 8);
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
    let lines: Vec<Lined<'_>> =
        (0..60_000 * 32).map(|n| Lined { at: n % 32, file: "src/main.rs", line: n + 1, column: 1 }).collect();
    let functions: Vec<Func<'_>> = (0..60_000u32)
        .map(|n| Func {
            key: key(n),
            addr: 0x1_4000_1000 + u64::from(n % 0x3000),
            size: 1,
            name: Some("f"),
            lines: (n * 32)..(n * 32 + 32),
        })
        .collect();
    let pdb = Model::new(headers(&file), [1; 16], &functions, &lines, &[]).unwrap().file();
    assert!(pdb.len() / BLOCK > BLOCK, "the test needs more than one interval: {} blocks", pdb.len() / BLOCK);
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
    let files: Vec<String> = (0..2000).map(|n| format!("C:\\Users\\dev\\src\\crate{}\\src\\module{n}.rs", n % 300)).collect();
    let names: Vec<String> = (0..400_000).map(|n| format!("_RNvMs{n}_NtCsajBxKdOt8Cw_16opencode_desktop4viewNtB5_4View6render{n}")).collect();
    let lines: Vec<Lined<'_>> = (0..4_000_000u32)
        .map(|n| Lined { at: (n % 10) * 4, file: &files[(n / 10) as usize % 2000], line: n % 5000 + 1, column: 1 })
        .collect();
    let functions: Vec<Func<'_>> = (0..400_000u32)
        .map(|n| Func {
            key: key(n),
            addr: 0x1_4000_1000 + u64::from(n % 0x2f00),
            size: 40,
            name: Some(&names[n as usize]),
            lines: (n * 10)..(n * 10 + 10),
        })
        .collect();
    let started = std::time::Instant::now();
    let pdb = Model::new(headers(&file), [1; 16], &functions, &lines, &[]).unwrap().file();
    eprintln!("{} functions: {:.3} s, {:.1} MB", functions.len(), started.elapsed().as_secs_f64(), pdb.len() as f64 / 1e6);
}
/// What a PDB says of its functions, read as a reader of the format reads it: each procedure
/// `(name, section, offset, size)` with its rows `(offset in the function, file, line)`, and
/// the globals' names, each a reference to a procedure of its name.
type Said = std::collections::BTreeMap<String, ((u16, u32, u32), Vec<(u32, String, u32)>)>;

fn said(pdb: &[u8]) -> Result<Said, String> {
    let streams = streams(pdb);
    let dbi = &streams[usize::from(DBI)];
    let (symbol_bytes, c13_bytes) = (u32_at(dbi, 64 + 36) as usize, u32_at(dbi, 64 + 44) as usize);
    let module = &streams[usize::from(MODULE)];
    let mut procedures = std::collections::BTreeMap::new();
    let mut at = 4;
    while at < symbol_bytes {
        let len = usize::from(u16::from_le_bytes([module[at], module[at + 1]]));
        let kind = u16::from_le_bytes([module[at + 2], module[at + 3]]);
        let body = &module[at + 4..at + 2 + len];
        match kind {
            S_GPROC32 => {
                let end = u32_at(body, 4) as usize;
                if u16::from_le_bytes([module[end + 2], module[end + 3]]) != S_END {
                    return Err(format!("the procedure at {at} ends at {end}, which is no S_END"));
                }
                let place = (u16::from_le_bytes([body[32], body[33]]), u32_at(body, 28), u32_at(body, 12));
                procedures.insert(at as u32, (name_in(body, 35), place));
            }
            S_END | S_SKIP | S_OBJNAME | S_COMPILE3 => {}
            other => return Err(format!("a symbol of kind {other:#x} at {at}")),
        }
        at += 2 + len;
    }
    let names = &streams[usize::from(NAMES)];
    let c13 = &module[symbol_bytes..symbol_bytes + c13_bytes];
    let (mut at, mut files) = (0, Vec::new());
    let mut rows: std::collections::BTreeMap<(u16, u32), Vec<(u32, String, u32)>> = Default::default();
    while at < c13.len() {
        let (kind, len) = (u32_at(c13, at), u32_at(c13, at + 4) as usize);
        let body = &c13[at + 8..at + 8 + len];
        match kind {
            DEBUG_S_FILECHKSMS => files = body.chunks(8).map(|it| name_in(&names[12..], u32_at(it, 0) as usize)).collect(),
            DEBUG_S_LINES => {
                let place = (u16::from_le_bytes([body[4], body[5]]), u32_at(body, 0));
                let mut block = 12;
                let into = rows.entry(place).or_default();
                if !into.is_empty() {
                    return Err(format!("two line tables at {place:?}"));
                }
                while block < body.len() {
                    let (file, count) = (u32_at(body, block) as usize / 8, u32_at(body, block + 4) as usize);
                    for n in 0..count {
                        let row = block + 12 + 8 * n;
                        into.push((u32_at(body, row), files[file].clone(), u32_at(body, row + 4) & 0xff_ffff));
                    }
                    block += u32_at(body, block + 8) as usize;
                }
            }
            DEBUG_S_IGNORE => {}
            other => return Err(format!("a C13 subsection of kind {other:#x}")),
        }
        at += (8 + len).next_multiple_of(4);
    }
    let mut out = Said::new();
    for (name, place) in procedures.values() {
        let lines = rows.remove(&(place.0, place.1)).unwrap_or_default();
        if out.insert(name.clone(), (*place, lines)).is_some() {
            return Err(format!("two procedures named {name}"));
        }
    }
    if !rows.is_empty() {
        return Err(format!("line tables of no procedure: {:?}", rows.keys().collect::<Vec<_>>()));
    }
    // The globals: each record a reference to the procedure of its name.
    let (globals, records) = (&streams[usize::from(GLOBALS)], &streams[usize::from(RECORDS)]);
    let count = u32_at(globals, 8) as usize / 8;
    let mut referenced = std::collections::BTreeSet::new();
    for n in 0..count {
        let at = u32_at(globals, 16 + 8 * n) as usize - 1;
        let body = &records[at + 4..];
        let (sym, name) = (u32_at(body, 4), name_in(body, 10));
        match procedures.get(&sym) {
            Some((it, _)) if *it == name => {}
            other => return Err(format!("the reference {name} names the procedure at {sym}: {other:?}")),
        }
        referenced.insert(name);
    }
    if referenced.len() != out.len() {
        return Err(format!("{} references of {} procedures", referenced.len(), out.len()));
    }
    Ok(out)
}

/// A program of functions by number: each its address, size, name and rows.
#[derive(Clone, Debug, Default)]
struct Program {
    funcs: std::collections::BTreeMap<u32, (u64, u64, String, Vec<(u32, u32, u32)>)>,
    next: u64,
}

const FILES: [&str; 4] = ["src/a.rs", "src/b.rs", "src/c.rs", "src/d.rs"];

impl Program {
    /// Function `n` made again from `seed`: a new place, size and rows.
    fn make(&mut self, n: u32, seed: u8, name: Option<String>) {
        self.next += 64;
        let size = 8 + 4 * u64::from(seed % 7);
        let rows = (0..u32::from(seed % 6)).map(|row| (row * 2, u32::from(seed.wrapping_add(row as u8)) % 4, 10 + u32::from(seed) + row)).collect();
        let name = name.or_else(|| self.funcs.get(&n).map(|it| it.2.clone())).unwrap_or_else(|| format!("app::f{n}"));
        self.funcs.insert(n, (0x1_4000_1000 + self.next % 0x2f00, size, name, rows));
    }

    fn input(&self, only: Option<&[u32]>) -> (Vec<Func<'_>>, Vec<Lined<'_>>) {
        let (mut functions, mut lines) = (Vec::new(), Vec::new());
        for (n, (addr, size, name, rows)) in &self.funcs {
            if only.is_some_and(|it| !it.contains(n)) {
                continue;
            }
            let start = lines.len() as u32;
            lines.extend(rows.iter().map(|(at, file, line)| Lined { at: *at, file: FILES[*file as usize], line: *line, column: 1 }));
            functions.push(Func { key: key(*n), addr: *addr, size: *size, name: Some(name), lines: start..lines.len() as u32 });
        }
        (functions, lines)
    }
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Edit(u8, u8),
    Add(u8, u8),
    Remove(u8),
    Rename(u8),
}

#[hegel::composite]
fn op(tc: &hegel::TestCase) -> Op {
    use hegel::generators as gs;
    let n = tc.draw(gs::integers::<u8>().max_value(11));
    let seed = tc.draw(gs::integers::<u8>());
    match tc.draw(gs::integers::<u8>().max_value(5)) {
        0..=2 => Op::Edit(n, seed),
        3 => Op::Add(n, seed),
        4 => Op::Remove(n),
        _ => Op::Rename(n),
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
/// the model asks); after each, the file reads as the PDB of the same program laid out whole.
fn refines(ops: &[Op], plant: Plant) -> Result<(), String> {
    let image = exe();
    let mut program = Program::default();
    for n in 0..4 {
        program.make(n, n as u8 * 3, None);
    }
    let (functions, lines) = program.input(None);
    let mut model = Model::new(headers(&image), [1; 16], &functions, &lines, &[("main", 0x1_4000_1100)])?;
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
            Op::Remove(n) if program.funcs.remove(&u32::from(n)).is_some() => (vec![], vec![u32::from(n)]),
            Op::Rename(n) if program.funcs.contains_key(&u32::from(n)) => {
                let name = format!("app::renamed{step}::f{n}");
                program.make(u32::from(n), step as u8, Some(name));
                (vec![u32::from(n)], vec![])
            }
            _ => continue,
        };
        let (functions, lines) = program.input(Some(&changed));
        let gone: Vec<InstanceKey> = gone.into_iter().map(key).collect();
        let id = [step as u8 + 2; 16];
        match model.patch(headers(&image), id, &functions, &lines, &gone, program.funcs.len(), None)? {
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
                let (functions, lines) = program.input(None);
                model = Model::new(headers(&image), id, &functions, &lines, &[("main", 0x1_4000_1100)])?;
                file = model.file();
            }
        }
        let (functions, lines) = program.input(None);
        let fresh = Model::new(headers(&image), id, &functions, &lines, &[("main", 0x1_4000_1100)])?.file();
        let (patched, whole) = (said(&file)?, said(&fresh)?);
        if patched != whole {
            return Err(format!("after {op:?}: the patched PDB says {patched:?}, the whole one {whole:?}"));
        }
        if file[GUID_AT..GUID_AT + 16] != id {
            return Err(format!("after {op:?}: the PDB carries another build id"));
        }
    }
    Ok(())
}

/// The refinement: after any sequence of edits (bodies, added, removed and renamed
/// functions), the PDB patched by each link's change reads as the one laid out whole from the
/// same program: the same procedures, places, rows and references.
#[hegel::test(test_cases = 200)]
fn a_pdb_kept_by_patches_reads_as_one_laid_out_whole(tc: hegel::TestCase) {
    use hegel::generators as gs;
    let ops: Vec<Op> = tc.draw(gs::vecs(op()).max_size(24));
    if let Err(why) = refines(&ops, Plant::None) {
        panic!("{why}");
    }
}

/// The oracle's control: a patch applied without one of its writes is caught.
#[test]
fn the_oracle_catches_a_patch_missing_a_write() {
    let ops = [Op::Edit(1, 9), Op::Edit(2, 30), Op::Add(7, 4)];
    assert_eq!(refines(&ops, Plant::None), Ok(()));
    assert!(refines(&ops, Plant::DropsAWrite).is_err(), "the oracle missed a lost write");
}

/// A body edit writes its function's records and the tables that name them, not the file:
/// among 2,000 functions, an edit's writes are a few blocks.
#[test]
fn a_body_edit_writes_blocks_not_the_file() {
    let image = exe();
    let mut program = Program::default();
    for n in 0..2000 {
        program.make(n, (n % 200) as u8, None);
    }
    let (functions, lines) = program.input(None);
    let mut model = Model::new(headers(&image), [1; 16], &functions, &lines, &[]).unwrap();
    let whole = model.file().len();
    program.make(700, 3, None);
    let (functions, lines) = program.input(Some(&[700]));
    let writes = model.patch(headers(&image), [2; 16], &functions, &lines, &[], 2000, None).unwrap().unwrap();
    let written: usize = writes.iter().map(|it| it.1.len()).sum();
    assert!(written <= 6 * BLOCK, "{written} bytes written of a {whole}-byte PDB: {:?}", writes.iter().map(|it| (it.0, it.1.len())).collect::<Vec<_>>());
}