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

fn key(n: u8) -> InstanceKey {
    InstanceKey(blaze_ids::ContentId([n; 32]))
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
    let pdb = write(&headers(&file), &id, &functions, &lines).unwrap();
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

    // The publics: a record per function, in the address map by place.
    let publics = &streams[usize::from(PUBLICS)];
    let (hash, map) = (u32_at(publics, 0) as usize, u32_at(publics, 4) as usize);
    assert_eq!(map, 8);
    let records = &streams[usize::from(RECORDS)];
    let named: Vec<String> = (0..2)
        .map(|n| {
            let at = u32_at(publics, 28 + hash + 4 * n) as usize;
            assert_eq!(u16::from_le_bytes([records[at + 2], records[at + 3]]), S_PUB32);
            name_in(&records[at + 4..], 10)
        })
        .collect();
    assert_eq!(named, ["app::main", "blaze_fn_140002000"]);
    // The GSI hash: two records, each the offset of its record plus one.
    assert_eq!(u32_at(publics, 28 + 8), 16);
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
            key: key(1),
            addr: 0x1_4000_1000 + u64::from(n % 0x3000),
            size: 1,
            name: Some("f"),
            lines: (n * 32)..(n * 32 + 32),
        })
        .collect();
    let pdb = write(&headers(&file), &[1; 16], &functions, &lines).unwrap();
    assert!(pdb.len() / BLOCK > BLOCK, "the test needs more than one interval: {} blocks", pdb.len() / BLOCK);
    let streams = streams(&pdb);
    assert_eq!(streams.len(), STREAMS);
}
