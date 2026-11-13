use super::super::{ASKED, coff_requests::Records};
use super::*;
use blaze_cas::{Handle, Store};
use blaze_core::{
    Effect, FileName, run_until_idle,
    sim::{Faults, Sim},
};
use blaze_ids::ContentId;
use std::sync::Arc;

fn drive(sim: &mut Sim, store: &mut Store, effects: &mut Vec<Effect>) {
    run_until_idle(sim, effects, |done, more| {
        store.complete(done, more);
    })
    .unwrap();
    assert!(store.ready(), "{:?}", store.broken());
}

fn open(sim: &mut Sim) -> Store {
    let mut effects = Vec::new();
    let mut store = Store::open(
        blaze_cas::Config {
            dir: FileName::new("store").unwrap(),
            layers: Vec::new(),
            tags: 1 << 40,
            load_tags: 2 << 40,
            loader: blaze_cas::Loader::Pumped,
            sharing: blaze_core::Sharing::Blocks,
        },
        &mut effects,
    );
    drive(sim, &mut store, &mut effects);
    store
}

fn flush(sim: &mut Sim, store: &mut Store) {
    let mut effects = Vec::new();
    store.flush(&mut effects);
    drive(sim, store, &mut effects);
}

const PRODUCER: ContentId = ContentId([42; 32]);

fn fixture_lib(value: u8) -> Vec<u8> {
    use object::{
        SymbolFlags, SymbolKind, SymbolScope,
        write::{StandardSection, Symbol, SymbolSection},
    };
    let mut b = Builder::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let text = b.section_id(StandardSection::Text);
    let at = b.append_section_data(text, &[0xb8, value, 0, 0, 0, 0xc3], 16);
    b.add_symbol(Symbol {
        name: "mainCRTStartup".into(),
        value: at,
        size: 6,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    crate::pe::tests::archive(&[("start.obj", b.write().unwrap(), &["mainCRTStartup"])])
}

/// Full link of the located inputs; compare the actual PE and PDB, not just their build IDs.
fn link(cache: &Cache, answers: &Answers, search: &[PathBuf]) -> (Vec<u8>, Vec<u8>) {
    let mut out = executable(cache, answers, "x86_64-pc-windows-msvc").unwrap();
    out.debug = Debug::Beside;
    out.link.inputs.push("app.obj".into());
    let line = locate_plain(cache, answers, &out, &[], search).unwrap();
    let read: Vec<Arc<[u8]>> =
        line.iter().map(|it| std::fs::read(&it.path).unwrap().into()).collect();
    let natives = line
        .iter()
        .zip(&read)
        .enumerate()
        .map(|(order, (it, bytes))| crate::Native {
            name: &it.name,
            id: ContentId::of("native test", bytes),
            bytes,
            kind: it.kind,
            order: order as u32,
        })
        .collect();
    let mut image = crate::Image::new(FileName::new("out/app.exe").unwrap(), out).unwrap();
    let staged = image.stage(crate::Change { natives, ..Default::default() }).unwrap();
    let pe = image.bytes(staged).unwrap();
    let pdb = image.debug_file().unwrap().unwrap().apply(Format::Pe, None).unwrap();
    (pe, pdb)
}

#[test]
fn restored_requests_resolve_current_paths_and_link_the_fresh_pe_and_pdb_bytes() {
    let dir = temp("coff-restore");
    let earlier = dir.join("first");
    let search = [earlier.clone()];
    let lib = "entry.lib";
    let obj = coff("/DEFAULTLIB:entry");
    touch(&dir.join("app.obj"), &obj);
    touch(&dir.join(lib), &fixture_lib(1));
    let answers = Answers::new().var("LIB", dir.to_str().unwrap());
    let mut sim = Sim::new(1, Faults::default());
    let first = {
        let mut store = open(&mut sim);
        let handle = Handle::new(&mut store, "/".into());
        let cache = Cache::new();
        assert!(cache.records.set(Records { store: &handle, producer: PRODUCER }).is_ok());
        let first = link(&cache, &answers, &search);
        flush(&mut sim, &mut store);
        first
    };
    sim.crash();
    let mut store = open(&mut sim);
    let handle = Handle::new(&mut store, "/".into());
    let records = Records { store: &handle, producer: PRODUCER };
    let id = ContentId::of(ASKED, &obj);
    assert_eq!(
        records.requests("app.obj", id, || panic!("durable hit parsed COFF")).unwrap(),
        [(String::new(), lib.to_owned())]
    );
    // No path in the record: a previously absent library now shadows the first build's.
    touch(&earlier.join(lib), &fixture_lib(2));
    let cache = Cache::new();
    assert!(cache.records.set(records).is_ok());
    let restored = link(&cache, &answers, &search);
    let fresh = link(&Cache::new(), &answers, &search);
    assert_ne!(first.0, fresh.0, "a different native function must change the PE");
    assert_eq!(restored, fresh);
    std::fs::remove_dir_all(dir).unwrap();
}

/// A power cut before flush may lose the record, not change the requests of a given
/// input. Only a changed input or producer, or a lost put, may call the COFF parser.
#[hegel::test(test_cases = 24)]
fn after_a_restart_a_record_only_answers_for_its_input_and_producer(tc: hegel::TestCase) {
    use hegel::generators as gs;
    let mut sim = Sim::new(tc.draw(gs::integers::<u64>()), Faults::default());
    let flushed = tc.draw(gs::booleans());
    let edited = tc.draw(gs::booleans());
    let upgraded = tc.draw(gs::booleans());
    let input = coff("/DEFAULTLIB:one");
    {
        let mut store = open(&mut sim);
        let handle = Handle::new(&mut store, "/".into());
        Records { store: &handle, producer: PRODUCER }
            .requests("f.obj", ContentId::of(ASKED, &input), || {
                crate::pe::asked_libraries("f.obj", &input)
            })
            .unwrap();
        if flushed {
            flush(&mut sim, &mut store);
        }
    }
    sim.crash();
    let mut store = open(&mut sim);
    let handle = Handle::new(&mut store, "/".into());
    let producer = if upgraded { ContentId([9; 32]) } else { PRODUCER };
    let input = if edited { coff("/DEFAULTLIB:two") } else { input };
    let fresh = crate::pe::asked_libraries("f.obj", &input).unwrap();
    let mut parsed = false;
    let restored = Records { store: &handle, producer }
        .requests("f.obj", ContentId::of(ASKED, &input), || {
            parsed = true;
            crate::pe::asked_libraries("f.obj", &input)
        })
        .unwrap();
    assert_eq!(restored, fresh);
    if edited || upgraded || flushed {
        assert_eq!(parsed, edited || upgraded);
    }
}
