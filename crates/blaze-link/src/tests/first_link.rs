//! A first PE link of many objects and archives is the same bytes on any number of workers:
//! symbol resolution, COMDAT selection, archive search and section collection run in parallel,
//! and each must decide as the serial link does.

use std::sync::Arc;

use blaze_codegen::Target;
use blaze_ids::ContentId;
use object::write::{Comdat, Object as Builder, Relocation, Symbol as Def, SymbolId, SymbolSection};
use object::{
    Architecture, BinaryFormat, ComdatKind, Endianness, RelocationFlags, SectionKind, SymbolFlags,
    SymbolKind, SymbolScope, pe,
};

use super::natives::{archive, windows};
use super::{CALLER, Change, Image, Native, NativeKind, function, key, name, rel32};

const OBJECTS: usize = 40;
const FUNCTIONS: usize = 48;
const ARCHIVES: usize = 4;
const MEMBERS: usize = 96;
const MEMBER_FUNCTIONS: usize = 4;
const COMDATS: usize = 160;
const COMDATS_PER_OBJECT: usize = 24;

/// A small fixed-seed generator: the inputs are the same on every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// One COFF object under construction: each function in its own section, as rustc and
/// cl `/Gy` write them, calling `calls` through `IMAGE_REL_AMD64_REL32`.
struct Coff {
    b: Builder<'static>,
    names: std::collections::HashMap<String, SymbolId>,
}

impl Coff {
    fn new() -> Coff {
        Coff {
            b: Builder::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little),
            names: Default::default(),
        }
    }

    fn undefined(&mut self, name: &str) -> SymbolId {
        if let Some(it) = self.names.get(name) {
            return *it;
        }
        let id = self.b.add_symbol(Def {
            name: name.as_bytes().to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Undefined,
            flags: SymbolFlags::None,
        });
        self.names.insert(name.to_string(), id);
        id
    }

    fn function(&mut self, name: &str, calls: &[String], comdat: bool) {
        let section = self.b.add_section(Vec::new(), b".text$mn".to_vec(), SectionKind::Text);
        let mut code = Vec::new();
        for _ in calls {
            code.extend_from_slice(&[0xe8, 0, 0, 0, 0]);
        }
        code.push(0xc3);
        self.b.append_section_data(section, &code, 16);
        let symbol = self.b.add_symbol(Def {
            name: name.as_bytes().to_vec(),
            value: 0,
            size: code.len() as u64,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(section),
            flags: SymbolFlags::None,
        });
        self.names.insert(name.to_string(), symbol);
        if comdat {
            self.b.add_comdat(Comdat { kind: ComdatKind::Any, symbol, sections: vec![section] });
        }
        for (at, callee) in calls.iter().enumerate() {
            let target = self.undefined(callee);
            self.b
                .add_relocation(
                    section,
                    Relocation {
                        offset: 5 * at as u64 + 1,
                        symbol: target,
                        addend: 0,
                        flags: RelocationFlags::Coff { typ: pe::IMAGE_REL_AMD64_REL32 },
                    },
                )
                .unwrap();
        }
    }

    fn bytes(self) -> Vec<u8> {
        self.b.write().unwrap()
    }
}

fn object_fn(o: usize, f: usize) -> String {
    format!("o{o}_f{f}")
}

fn member_fn(a: usize, m: usize, f: usize) -> String {
    format!("a{a}_m{m}_f{f}")
}

fn comdat_fn(c: usize) -> String {
    format!("c{c}")
}

/// Any function the inputs define: an object's, a COMDAT one, or an archive member's.
fn any_callee(rng: &mut Rng) -> String {
    match rng.below(10) {
        0..=4 => object_fn(rng.below(OBJECTS), rng.below(FUNCTIONS)),
        5..=6 => comdat_fn(rng.below(COMDATS)),
        _ => member_fn(rng.below(ARCHIVES), rng.below(MEMBERS), rng.below(MEMBER_FUNCTIONS)),
    }
}

/// A member calls only members of its own or a later archive, as a link line orders them,
/// and some members are never asked for.
fn member_callee(rng: &mut Rng, a: usize) -> String {
    let to = a + rng.below(ARCHIVES - a);
    member_fn(to, rng.below(MEMBERS), rng.below(MEMBER_FUNCTIONS))
}

/// The link line: objects first, then archives, each `(file, bytes, kind)`.
fn inputs() -> Vec<(String, Arc<[u8]>, NativeKind)> {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut line = Vec::new();
    for o in 0..OBJECTS {
        let mut coff = Coff::new();
        for f in 0..FUNCTIONS {
            let calls: Vec<String> = (0..rng.below(4)).map(|_| any_callee(&mut rng)).collect();
            coff.function(&object_fn(o, f), &calls, false);
        }
        // Each COMDAT is in several objects, its copies the same name with other bodies'
        // callees: which copy is kept decides what the image holds.
        for _ in 0..COMDATS_PER_OBJECT {
            let c = rng.below(COMDATS);
            if coff.names.contains_key(&comdat_fn(c)) {
                continue;
            }
            let calls: Vec<String> = (0..rng.below(3)).map(|_| any_callee(&mut rng)).collect();
            coff.function(&comdat_fn(c), &calls, true);
        }
        line.push((format!("C:\\build\\deps\\o{o}.o"), coff.bytes().into(), NativeKind::Object));
    }
    // Every COMDAT is defined somewhere, so every name resolves.
    let mut last = Coff::new();
    for c in 0..COMDATS {
        last.function(&comdat_fn(c), &[], true);
    }
    line.push(("C:\\build\\deps\\comdats.o".to_string(), last.bytes().into(), NativeKind::Object));
    for a in 0..ARCHIVES {
        let mut members = Vec::new();
        for m in 0..MEMBERS {
            let mut coff = Coff::new();
            for f in 0..MEMBER_FUNCTIONS {
                let calls: Vec<String> =
                    (0..rng.below(3)).map(|_| member_callee(&mut rng, a)).collect();
                coff.function(&member_fn(a, m, f), &calls, false);
            }
            let defines: Vec<String> = (0..MEMBER_FUNCTIONS).map(|f| member_fn(a, m, f)).collect();
            members.push((format!("m{m}.obj"), coff.bytes(), defines));
        }
        let view: Vec<(&str, &[u8], Vec<&str>)> = members
            .iter()
            .map(|(n, b, d)| (n.as_str(), b.as_slice(), d.iter().map(String::as_str).collect()))
            .collect();
        let view: Vec<(&str, &[u8], &[&str])> =
            view.iter().map(|(n, b, d)| (*n, *b, d.as_slice())).collect();
        line.push((
            format!("C:\\build\\deps\\liba{a}.rlib"),
            archive(&view).into(),
            NativeKind::Archive { whole: false },
        ));
    }
    line
}

/// The image bytes of a first link of `line` on a pool of `workers`.
fn link(line: &[(String, Arc<[u8]>, NativeKind)], workers: usize, incremental: bool) -> Vec<u8> {
    let pool =
        blaze_graph::pool::Pool::new(&blaze_graph::topology::Topology::flat(workers), false)
            .unwrap();
    pool.install(|| {
        let start = function(
            1,
            &CALLER,
            vec![rel32(1, Target::Extern(object_fn(0, 0)))],
        );
        let mut output = windows();
        output.incremental = incremental;
        let mut image = Image::new(name(super::TO), output).unwrap();
        let change = Change {
            added: vec![&start],
            names: vec![("mainCRTStartup".into(), Target::Direct(key(1)))],
            debug_names: vec![(key(1), "start".into())],
            natives: line
                .iter()
                .enumerate()
                .map(|(at, (file, bytes, kind))| Native {
                    id: ContentId::of("first_link", bytes),
                    name: file,
                    bytes,
                    kind: *kind,
                    order: at as u32,
                })
                .collect(),
            ..Change::default()
        };
        let staged = image.stage(change).unwrap_or_else(|e| panic!("{e}"));
        image.bytes(staged).unwrap_or_else(|e| panic!("{e}"))
    })
}

fn assert_same(serial: &[u8], other: &[u8], workers: usize) {
    if serial == other {
        return;
    }
    let at = serial.iter().zip(other).position(|(a, b)| a != b).unwrap_or(serial.len().min(other.len()));
    panic!(
        "{workers} workers wrote other bytes than one: {} and {} bytes, first difference at {at:#x}",
        serial.len(),
        other.len()
    );
}

#[test]
fn a_first_pe_link_is_the_same_bytes_serial_and_parallel() {
    let line = inputs();
    for incremental in [false, true] {
        let serial = link(&line, 1, incremental);
        assert_same(&serial, &link(&line, 8, incremental), 8);
    }
}

#[test]
fn a_first_pe_link_is_the_same_bytes_on_any_number_of_workers() {
    let line = inputs();
    let serial = link(&line, 1, false);
    let mut counts = vec![2, 3, 4, 5, 7, 11, 16, 2, 13];
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    for at in (1..counts.len()).rev() {
        counts.swap(at, rng.below(at + 1));
    }
    for workers in counts {
        assert_same(&serial, &link(&line, workers, false), workers);
    }
}
