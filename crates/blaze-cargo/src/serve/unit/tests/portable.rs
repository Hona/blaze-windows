//! Content keys ([`super::super::portable`]): a unit's record key and what its record is
//! written as are the same for the same sources in another directory, under another home and
//! machine directory; a difference that matters still gives another key; and a record that
//! holds a directory is told apart.

use std::sync::Arc;

use blaze_units::{
    query::{BuildConfig, Command, Invocation, Mount, Origin, Units},
    schema::{Mode, UnitDep, UnitGraph},
};

use super::{
    super::{
        compile,
        portable::{PLANTED_PATH, Places},
    },
    HOST, one_maker, package, plan, target, unit,
};

/// Where one build of the two-crate workspace is: its checkout, and the daemon's own
/// directories (its home's build directory, the machine's shared one, its programs).
#[derive(Clone, Copy)]
struct Where {
    checkout: &'static str,
    home: &'static str,
    machine: &'static str,
}

/// A checkout under one user's home, and the same sources in a longer path under another's,
/// on another machine directory: no directory of one is a directory of the other, and they
/// differ in length (a length prefix would tell them apart).
const FIRST: Where = Where { checkout: "/home/a/w", home: "/home/a/.blaze", machine: "/home/a/.cache/blaze" };
const SECOND: Where = Where {
    checkout: "/Users/someone-else/src/checkouts/w",
    home: "/Users/someone-else/Library/blaze",
    machine: "/Users/someone-else/Library/Caches/blaze",
};

impl Where {
    fn target(&self) -> String {
        format!("{}/build/0123", self.home)
    }

    fn places(&self) -> Places {
        Places::of_daemon(
            Some(self.checkout),
            Some(&self.target()),
            Some(&format!("{}/std/m", self.machine)),
            Some(&format!("{}/tools", self.home)),
            Some(&format!("{}/bin/blaze", self.home)),
            Some(&format!("{}/sources", self.home)),
        )
    }
}

/// A workspace of two path packages lowered at `at`: `a` (unit 0), a library, and `b`
/// (unit 1), a library that depends on it.
struct Checkout {
    lowered: blaze_lower::Lowered,
    units: Units,
    places: Places,
}

const A: &str = "pub fn shown(x: u32) -> u32 { hidden(x) }\nfn hidden(x: u32) -> u32 { x + 1 }\n";
const B: &str = "pub fn twice(x: u32) -> u32 { a::shown(a::shown(x)) }\n";

fn checkout(at: Where, a: &str, b: &str) -> Checkout {
    let root = at.checkout;
    let tree = blaze_query::MemTree::default();
    let view = tree.root(&[
        ("a/Cargo.toml", b"[package]\nname = \"a\"\n".as_slice()),
        ("a/src/lib.rs", a.as_bytes()),
        ("b/Cargo.toml", b"[package]\nname = \"b\"\n".as_slice()),
        ("b/src/lib.rs", b.as_bytes()),
    ]);
    let id = |name: &str| format!("path+file://{root}/{name}#0.1.0");
    let lib = |name: &str| {
        unit(&id(name), target(name, "lib", &format!("{root}/{name}/src/lib.rs")), Mode::Build, &[])
    };
    let mut b_unit = lib("b");
    b_unit.dependencies = vec![UnitDep {
        index: 0,
        extern_crate_name: "a".to_owned(),
        public: None,
        noprelude: None,
        nounused: None,
        dev: false,
        gpu: false,
    }];
    let target_dir = at.target();
    let planned = |name: &str, extra: &str| {
        let mut planned = plan(extra, &[]);
        planned.env = vec![
            ("CARGO_MANIFEST_DIR".to_owned(), format!("{root}/{name}")),
            ("CARGO_MANIFEST_PATH".to_owned(), format!("{root}/{name}/Cargo.toml")),
        ];
        planned.outputs = vec![
            format!("{target_dir}/debug/deps/lib{name}{extra}.rlib"),
            format!("{target_dir}/debug/deps/{name}{extra}.d"),
        ];
        planned
    };
    let units = Units {
        graph: UnitGraph { version: 1, units: vec![lib("a"), b_unit], roots: vec![1] },
        plans: vec![planned("a", "-0001"), planned("b", "-0002")],
        packages: vec![
            package(&id("a"), "a", &format!("{root}/a")),
            package(&id("b"), "b", &format!("{root}/b")),
        ],
        lock: None,
        warnings: Vec::new(),
        notes: Vec::new(),
        target_dir: target_dir.clone(), // clone: a test's path
        build_dir: target_dir,
        finished: String::new(),
        link_dirs: Vec::new(),
        native: Vec::new(),
    };
    let config = BuildConfig {
        invocation: Invocation {
            command: Command::Build,
            args: Vec::new(),
            root: root.to_owned(),
            cwd: root.to_owned(),
            env: Vec::new(),
            files: Vec::new(),
        },
        mounts: vec![Mount { at: root.to_owned(), origin: Origin::View, under: String::new() }],
        host: HOST.to_owned(),
        library: "/rustc/abc/library".to_owned(),
        std: format!("{}/std/m", at.machine),
        builds: format!("{}/build", at.home),
        sources: format!("{}/sources", at.home),
        blaze: String::new(),
    };
    let lowered = blaze_lower::lower(blaze_lower::Lower {
        units: &units,
        config: &config,
        files: &tree,
        root: view,
        host_cpu: None,
        sealed: &blaze_lower::unsealed(&units),
    }, blaze_item_hash::reads::mark_boundaries, blaze_memo::Reads::Kept)
    .unwrap();
    let places = at.places();
    // clone: the test's places, told the front end as the daemon tells it
    lowered.set_port(Arc::new(places.port()));
    Checkout { lowered, units, places }
}

impl Checkout {
    /// Unit `unit`'s record key, as [`compile`] makes it for a build: its whole one, and its
    /// narrow one where its crate has a narrowed identity.
    fn keys(&mut self, unit: usize, change: impl Fn(&mut Change)) -> (blaze_cas::Key, Option<blaze_cas::Key>) {
        let whole = self.lowered.identity(unit).unwrap();
        let narrow = self.lowered.narrowed(unit).map(|it| it.code);
        let mut changed = Change {
            unit: self.units.graph.units[unit].clone(), // clone: a test's unit
            plan: self.units.plans[unit].clone(),       // clone: a test's plan
            makers: one_maker(),
        };
        change(&mut changed);
        let key = |identity| {
            compile::RecordInputs {
                identity,
                places: &self.places,
                unit: compile::KeyedUnit::among(&changed.unit, |at| Ok(&self.units.graph.units[at])).unwrap(),
                plan: &changed.plan,
                run_env: &[("CARGO".to_owned(), self.places_launcher())],
                script_check_cfgs: Vec::new(),
                script_link_args: Vec::new(),
                linked_rustflag_libs: Vec::new(),
                makers: changed.makers,
                kind: compile::keyed_kind(crate::serve::work::JobKind::Build, &changed.unit),
                goal: compile::goal_byte(blaze_api::Goal::Edit),
                build: 0,
                verified: false,
                reached: false,
                pgo: None,
                lint_profile: None,
                layout: None,
            }
            .key(unit)
            .unwrap()
        };
        (key(whole), narrow.map(key))
    }

    /// The launcher's real path, as a unit's run environment names it (`CARGO`).
    fn places_launcher(&self) -> String {
        let ported = b"\0l";
        String::from_utf8(self.places.real(ported).unwrap().into_owned()).unwrap()
    }
}

/// What a test changes of one unit's key inputs.
struct Change {
    unit: blaze_units::schema::Unit,
    plan: blaze_units::query::UnitPlan,
    makers: crate::serve::RecordMakers,
}

/// The invariant: a unit's record key is a function of what the unit is made from and never
/// of where its checkout, its build directory, the machine's shared directory or blaze's
/// programs are. Two checkouts of the same sources, in directories of other names and lengths
/// under other homes, make the same whole key and the same narrow key for every unit.
///
/// Control: with the workspace's path planted back into the key ([`PLANTED_PATH`]), the same
/// comparison fails.
#[test]
fn a_unit_is_keyed_the_same_in_another_directory_under_another_home() {
    let same = || {
        let (mut first, mut second) = (checkout(FIRST, A, B), checkout(SECOND, A, B));
        (0..2).all(|unit| first.keys(unit, |_| {}) == second.keys(unit, |_| {}))
    };
    assert!(same(), "the same sources in two directories under two homes: one key a unit");
    PLANTED_PATH.set(true);
    let planted = same();
    PLANTED_PATH.set(false);
    assert!(!planted, "the workspace's path put back into the key must tell the two checkouts apart");
}

/// The other way (rule keys-cover-every-input): each thing a unit's output depends on still
/// moves its key once paths are written against the build's directories, one changed at a
/// time, in one checkout and across two.
#[test]
fn what_a_unit_is_made_from_still_moves_its_key() {
    let mut base = checkout(FIRST, A, B);
    let unchanged = base.keys(1, |_| {});
    let mut differs = |what: &str, change: &dyn Fn(&mut Change)| {
        let mut other = checkout(SECOND, A, B);
        let changed = other.keys(1, change);
        assert_ne!(changed.0, unchanged.0, "{what}: the whole key");
        assert_ne!(changed.1, unchanged.1, "{what}: the narrow key");
    };
    differs("another target", &|it| it.unit.platform = Some("aarch64-unknown-linux-gnu".to_owned()));
    differs("another feature set", &|it| it.unit.features.push("extra".to_owned()));
    differs("another profile", &|it| it.unit.profile.opt_level = "3".to_owned());
    differs("another cfg", &|it| it.plan.cfgs.push("--cfg=extra".to_owned()));
    differs("another rustflag", &|it| it.plan.rustflags.push("-Cdebug-assertions=off".to_owned()));
    differs("another front end", &|it| {
        it.makers.front_end = blaze_ids::ContentId::of("blaze v2 cargo test record makers", b"other");
    });
    differs("another code generator", &|it| {
        it.makers.codegen = blaze_ids::ContentId::of("blaze v2 cargo test record makers", b"other");
    });
    differs("another maker of records", &|it| {
        it.makers.record = blaze_ids::ContentId::of("blaze v2 cargo test record makers", b"other");
    });
    // A path that is under no directory of the build is a path the unit depends on.
    differs("a library directory outside the build's", &|it| {
        it.plan.rustflags.push("-L".to_owned());
        it.plan.rustflags.push("/opt/vendor/lib".to_owned());
    });
    // A file of the workspace moved to another name in it.
    differs("another path in the workspace", &|it| {
        let dir = it.plan.env[0].1.clone(); // clone: a test's path
        it.plan.env[0].1 = format!("{dir}-renamed");
    });
    // The sources: a byte of its own, and of the crate it depends on.
    let mut own = checkout(SECOND, A, &B.replace("a::shown(x)", "x"));
    assert_ne!(own.keys(1, |_| {}).0, unchanged.0, "a changed source byte of its own");
    let mut dependency = checkout(SECOND, &A.replace("x: u32) -> u32 { hidden", "x: u32) -> u64 { hidden"), B);
    let moved = dependency.keys(1, |_| {});
    assert_ne!(moved.0, unchanged.0, "a changed signature of the crate it depends on: the whole key");
    assert_ne!(moved.1, unchanged.1, "a changed signature of the crate it depends on: the narrow key");
}

/// How the roots sit to each other is in the key: a build directory inside the checkout and
/// one outside it give a relative path from one to the other that is another string, which a
/// unit's output may hold.
#[test]
fn a_build_directory_placed_otherwise_is_another_key() {
    let inside = Where { home: "/home/a/w/.blaze", ..FIRST };
    let (mut outside, mut inside) = (checkout(FIRST, A, B), checkout(inside, A, B));
    assert_ne!(outside.keys(1, |_| {}).0, inside.keys(1, |_| {}).0);
}

/// Every string of an encoded value is written against the directories and written back
/// ([`Places::cbor`], [`Places::cbor_real`]): the same value in two checkouts is the same
/// bytes, which hold no directory, and each checkout reads its own paths back.
#[test]
fn a_value_is_written_against_the_directories_and_back() {
    let value = |at: Where| {
        let mut planned = plan("-0001", &[]);
        planned.outputs = vec![format!("{}/debug/deps/liba-0001.rlib", at.target())];
        planned.out_dir = Some(format!("{}/debug/build/a-0001/out", at.target()));
        planned.env = vec![
            ("CARGO_MANIFEST_DIR".to_owned(), format!("{}/a", at.checkout)),
            ("LD_LIBRARY_PATH".to_owned(), format!("{}/debug/deps:{}/std/m/lib", at.target(), at.machine)),
            ("PKG".to_owned(), format!("path+file://{}/a#0.1.0", at.checkout)),
        ];
        blaze_protocol::cbor::to_vec(&planned).unwrap()
    };
    let (first, second) = (FIRST.places(), SECOND.places());
    let written = |places: &Places, at: Where| {
        let mut out = Vec::new();
        places.cbor(&value(at), &mut out).unwrap();
        out
    };
    let kept = written(&first, FIRST);
    assert_eq!(kept, written(&second, SECOND), "one value, two checkouts: the same bytes");
    assert!(!first.tied(&kept) && !second.tied(&kept), "and no directory of either in them");
    for (places, at) in [(&first, FIRST), (&second, SECOND)] {
        let mut back = Vec::new();
        places.cbor_real(&kept, &mut back).unwrap();
        assert_eq!(back, value(at), "read back against a build's directories: its own paths");
    }
    // A directory where no path starts is left, and found.
    let mut odd = Vec::new();
    let text = format!("-I{}/include", FIRST.checkout);
    first.cbor(&blaze_protocol::cbor::to_vec(&text).unwrap(), &mut odd).unwrap();
    assert!(first.tied(&odd), "a directory after a path byte is not written against, and ties what holds it");
    // Bytes that are no value are refused, never passed through.
    assert!(first.cbor(&[0x9f, 0x01, 0xff], &mut Vec::new()).is_err(), "an indefinite array");
    assert!(first.cbor(&[0x62, b'a'], &mut Vec::new()).is_err(), "a string cut short");
    assert!(first.cbor(&[0x01, 0x01], &mut Vec::new()).is_err(), "bytes after the value");
    // A placeholder of a directory the reading build has none of is an error.
    let none = Places::of_daemon(Some("/w"), Some("relative"), Some(""), None, None, None);
    assert!(none.cbor_real(&kept, &mut Vec::new()).is_err());
}

/// A library's file names its package against the directories: the same crate built in two
/// checkouts writes the same bytes (determinism across directories, for the one output a
/// library unit writes besides its dep-info).
#[test]
fn a_library_file_is_the_same_bytes_in_another_directory() {
    let bytes = |at: Where| {
        let front = checkout(at, A, B);
        compile::crate_record(&front.units.graph.units[0], &front.places, None, &[])
    };
    let (first, second) = (bytes(FIRST), bytes(SECOND));
    assert_eq!(first, second);
    assert!(!FIRST.places().tied(&first));
}

/// Which records are tied to where they were made: a record's own key is asked first, then
/// its key here, and two builds whose directories differ ask different keys here.
#[test]
fn a_tied_record_is_under_its_key_here() {
    let base = blaze_cas::Key(blaze_ids::ContentId::of("blaze v2 cargo test record makers", b"base"));
    let (first, second) = (FIRST.places(), SECOND.places());
    assert_ne!(first.here(base), base);
    assert_ne!(first.here(base), second.here(base), "another checkout never asks this one's");
    assert_eq!(first.here(base), FIRST.places().here(base), "the same directories: the same key");
    let moved = Where { machine: "/var/cache/blaze", ..FIRST };
    assert_ne!(first.here(base), moved.places().here(base), "each directory is in it");
}

#[cfg(windows)]
#[test]
fn windows_places_convert_host_roots_port_run_env_and_detect_all_leaks() {
    use std::path::Path;
    let first = Places::new(
        "/C:/Users/Alice/w",
        "/C:/Users/Alice/.blaze/build/0123",
        "/C:/Users/Alice/.cache/blaze/std/m",
        Path::new(r"C:\Users\Alice\.blaze\tools"),
        Path::new(r"C:\Users\Alice\.blaze\bin\blaze.exe"),
        Path::new(r"C:\Users\Alice\.blaze\sources"),
    );
    let second = Places::new(
        "/D:/work/bob/checkouts/w",
        "/D:/work/bob/blaze/build/0123",
        "/D:/work/bob/cache/blaze/std/m",
        Path::new(r"D:\work\bob\blaze\tools"),
        Path::new(r"D:\work\bob\blaze\bin\blaze.exe"),
        Path::new(r"D:\work\bob\blaze\sources"),
    );

    assert_eq!(&*first.real(b"\0l").unwrap(), b"/C:/Users/Alice/.blaze/bin/blaze.exe");
    assert_eq!(&*first.real(b"\0hl").unwrap(), br"C:\Users\Alice\.blaze\bin\blaze.exe");

    let value = |ws_d: &str, tgt_d: &str, ws_h: &str, tgt_h: &str, launcher_h: &str| {
        let mut planned = plan("-0001", &[]);
        planned.outputs = vec![format!("{tgt_d}/debug/deps/liba-0001.rlib")];
        planned.env = vec![
            ("CARGO".to_owned(), launcher_h.to_owned()),
            ("CARGO_MANIFEST_DIR".to_owned(), format!(r"{ws_h}\a")),
            ("PATH".to_owned(), format!(r"{tgt_h}\debug\deps;{tgt_h}\debug")),
            ("PKG".to_owned(), format!("path+file://{ws_d}/a#0.1.0")),
        ];
        blaze_protocol::cbor::to_vec(&planned).unwrap()
    };
    let a = value(
        "/C:/Users/Alice/w",
        "/C:/Users/Alice/.blaze/build/0123",
        r"C:\Users\Alice\w",
        r"C:\Users\Alice\.blaze\build\0123",
        r"C:\Users\Alice\.blaze\bin\blaze.exe",
    );
    let b = value(
        "/D:/work/bob/checkouts/w",
        "/D:/work/bob/blaze/build/0123",
        r"D:\work\bob\checkouts\w",
        r"D:\work\bob\blaze\build\0123",
        r"D:\work\bob\blaze\bin\blaze.exe",
    );
    let (mut kept_a, mut kept_b) = (Vec::new(), Vec::new());
    first.cbor(&a, &mut kept_a).unwrap();
    second.cbor(&b, &mut kept_b).unwrap();
    assert_eq!(kept_a, kept_b, "mixed daemon/host CBOR must port identically across Windows checkouts");
    assert!(!first.tied(&kept_a) && !second.tied(&kept_b), "no directory of either checkout in ported bytes");

    let mut back_b = Vec::new();
    second.cbor_real(&kept_a, &mut back_b).unwrap();
    assert_eq!(back_b, b, "cbor_real restores both daemon outputs and native host run_env");

    // Native, daemon, forward-slashed and UTF-16LE spellings all tie the record.
    let wide: Vec<u8> = r"C:\Users\Alice\w".encode_utf16().flat_map(u16::to_le_bytes).collect();
    for leak in [
        br"-IC:\Users\Alice\w\inc".as_slice(),
        b"-IC:/Users/Alice/w/inc",
        b"-I/C:/Users/Alice/w/inc",
        &wide,
    ] {
        assert!(first.tied(leak), "Places::tied missed Windows leak: {:?}", String::from_utf8_lossy(leak));
    }

    // `of_host` (used by `serve::packs::home_places`) converts host paths into daemon+host roots.
    let home = Places::of_host(
        None,
        Some(Path::new(r"C:\Users\Alice\.blaze\build")),
        Some(Path::new(r"C:\Users\Alice\AppData\Local\blaze\std")),
        None,
        None,
        Some(Path::new(r"C:\Users\Alice\.blaze\sources")),
    );
    assert!(home.tied(br"C:\Users\Alice\.blaze\sources\registry\foo"));
    assert!(home.tied(b"/C:/Users/Alice/.blaze/sources/registry/foo"));
    let wide_src: Vec<u8> =
        r"C:\Users\Alice\.blaze\sources".encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert!(home.tied(&wide_src));
}
