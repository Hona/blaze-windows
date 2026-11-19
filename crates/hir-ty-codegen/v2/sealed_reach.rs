//! Sealed code's reach records (`frontend/described/reach.rs`, backlog B11) across projects,
//! restarts and an edit of sealed code: a second project on the same home and a restarted
//! daemon describe none of the sealed functions their program reaches and read the store once
//! where the walk enters sealed code, not once a function; a change of sealed code's sources
//! misses, and the build is the one with no store.
//!
//! Each build is a fresh database (fresh interners and memo) over the same content-addressed
//! store, as a new project in a warm daemon, a restart and a second home are. The sealed crate
//! (`kernel`, standing for the standard library) is read from its image, as std is.

use std::sync::Arc;

use blaze_format::Aligned;
use hir_def::deps::{ImageBuf, ImageStore, Mode, Which};

use super::*;

/// The key every image of the tests is made with.
const BUILD: ContentId = ContentId([7; 32]);

/// The length of the sealed crate's chain of calls: what the walk reaches of it.
const CHAIN: usize = 40;

/// Images in memory, which refuses a second put of a key with other bytes as the store does.
struct Images {
    values: Lock<blaze_hash::HashMap<ContentId, Arc<Aligned>, std::alloc::Global>>,
}

impl Default for Images {
    fn default() -> Images {
        Images {
            values: Lock::new("test.sealed_reach.images", blaze_hash::HashMap::new_in(std::alloc::Global)),
        }
    }
}

impl ImageStore for Images {
    fn get(&self, key: &ContentId) -> Result<Option<ImageBuf>, String> {
        Ok(self.values.lock().get(key).map(|it| it.clone() as ImageBuf))
    }

    fn reads_now(&self, _: &base_db::Env, _: &[u8]) -> Result<ContentId, String> {
        Err("the fixture runs no proc macro, so no expansion read is asked".to_owned())
    }

    fn put(&self, key: ContentId, value: Vec<u8>) -> Result<(), String> {
        let mut values = self.values.lock();
        match values.get(&key) {
            Some(kept) if kept[..] != value[..] => Err(format!("{key:?} kept with other bytes")),
            Some(_) => Ok(()),
            None => {
                values.insert(key, Arc::new(Aligned::copy_from(&value)));
                Ok(())
            }
        }
    }

    fn pages(&self, key: &ContentId) -> Result<Option<Arc<dyn hir_def::deps::PageSource>>, String> {
        // A test's store holds each value whole: no part of one is read alone.
        Ok(hir_def::deps::whole_pages(self.get(key)?, std::alloc::Global))
    }

    // dyn: `ImageStore::for_each`'s signature, one call per batch of crates
    fn for_each(&self, count: usize, task: &(dyn Fn(usize) + Sync)) {
        (0..count).for_each(task);
    }
}

/// The store, counting each read a walk makes of it.
struct Counting<'a> {
    store: &'a MemoryStore,
    reads: AtomicUsize,
}

impl Records for Counting<'_> {
    fn read(&self, key: &Key, read: &mut dyn FnMut(&[u8])) -> Result<bool, String> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        Records::read(self.store, key, read)
    }
}

impl Lookup for Counting<'_> {
    fn read(&self, key: &Key) -> Result<Option<&[u8]>, String> {
        Lookup::read(self.store, key)
    }
}

/// A project named `project` whose `entry` calls into the sealed crate `kernel`, a chain of
/// [`CHAIN`] functions whose last gives `leaf`.
fn source(project: &str, leaf: u32) -> String {
    let mut kernel = String::new();
    for at in 0..CHAIN {
        let next = match at + 1 == CHAIN {
            true => format!("x ^ {leaf}"),
            false => format!("s{}(x) ^ {at}", at + 1),
        };
        kernel += &format!("#[inline(never)] pub fn s{at}(x: u32) -> u32 {{ {next} }}\n");
    }
    format!(
        "//- minicore: sized, copy\n\
         //- /main.rs crate:{project} deps:kernel new_source_root:local\n\
         pub fn entry(x: u32) -> u32 {{ kernel::print(x) }}\n\
         //- /lib.rs crate:kernel new_source_root:library\n\
         #[inline(never)] pub fn print(x: u32) -> u32 {{ s0(x) }}\n\
         {kernel}"
    )
}

fn kernel_of(db: &Db) -> base_db::Crate {
    *base_db::all_crates(db)
        .iter()
        .find(|it| it.extra_data(db).display_name.as_ref().is_some_and(|it| it.to_string() == "kernel"))
        .expect("the fixture's `kernel`")
}

/// A database of `text` that reads `kernel` from its image, as a build reads std: made by a
/// database that resolved it, the first time its sources are seen.
fn imaged(text: &str, images: &Images) -> Db {
    let fresh = || {
        let mut db = fixture::db(text).into_db();
        let mut edit = db.edit();
        blaze_item_hash::identity::give_build(&mut edit, BUILD);
        _ = edit.commit();
        let crates: Vec<base_db::Crate> = base_db::all_crates(&db).iter().copied().collect();
        let (served, found) = hir_def::deps::serve(&db, &crates, BUILD, images, Mode::Serve)
            .unwrap_or_else(|why| panic!("serving the fixture's images: {why}"));
        if !found.is_empty() {
            let mut edit = db.edit();
            for (krate, image) in found {
                let krate_id = served.keys[&krate.key(edit.db())];
                hir_def::deps::give_image(&mut edit, krate, krate_id, image);
            }
            _ = edit.commit();
        }
        (db, served)
    };
    let (db, served) = fresh();
    if served.hits.contains(&kernel_of(&db).key(&db)) {
        return db;
    }
    hir_def::deps::store(&db, &served, images, Which::Sealed)
        .unwrap_or_else(|why| panic!("storing the fixture's images: {why:?}"));
    let (db, served) = fresh();
    assert!(
        served.hits.contains(&kernel_of(&db).key(&db)),
        "premise: `kernel` is read from its image"
    );
    db
}

/// One build of `text`'s `entry` in a fresh database over `store` (`None`: no store), with
/// how many reads its walk made of the store; what it made is committed to the store.
fn build(text: &str, images: &Images, store: Option<&MemoryStore>) -> (Built, usize) {
    let db = imaged(text, images);
    let hashes = HashSource::Items(ItemHashes::new(Box::new(|_| None)));
    let pol = policy(OptLevel::O3);
    let front = HirFrontend::new(Databases::new(&db), hashes, BuildTime::default()).with_policy(&pol);
    let roots: Vec<(HirInstance, Origin)> = front.with(|db| {
        let krate = fixture::test_crate(db);
        let entry = hir_def::test_items::function(db, krate, "entry");
        vec![(front.root(entry), front.origin(db, krate))]
    });
    let empty = MemoryStore::default();
    let counting = Counting { store: store.unwrap_or(&empty), reads: AtomicUsize::new(0) };
    let machine = StubMachine::default();
    let memo = Memo::new();
    let build = Build::new(&machine, &front, &pol, &memo);
    let mut build = match store {
        Some(_) => build.recording(&counting),
        None => build,
    };
    let built = build.run(&roots, &counting).unwrap_or_else(|errs| panic!("build failed: {errs:?}"));
    if let Some(store) = store {
        store.commit(&built.puts);
        store.commit(&built.shared);
    }
    (built, counting.reads.load(Ordering::Relaxed))
}

/// What the walk reached of the sealed crate: [`CHAIN`] functions and `print`.
const SEALED: usize = CHAIN + 1;

/// The invariant: a second project on the same home (another workspace crate, the same sealed
/// crate) describes only its own function, takes every sealed one from the records the first
/// project left, and reads the store a few times, not once a sealed function: once for its
/// own function's record and once where it enters sealed code. A restart of the first project
/// (a fresh database over the same store) describes none. Each build is the one with no store.
#[test]
fn a_second_project_and_a_restart_describe_no_sealed_function_and_read_its_reach_once() {
    let images = Images::default();
    let store = MemoryStore::default();
    let first = source("main", 1);
    let (cold, _) = build(&first, &images, Some(&store));
    assert!(cold.walk.described > SEALED, "premise: the cold build describes everything");
    // Each sealed function's describe record and one reach record, from where `entry` enters.
    assert_eq!(cold.shared.len(), SEALED + 1, "the sealed layer's records: {}", cold.shared.len());

    let second = source("hello2", 1);
    let (other, reads) = build(&second, &images, Some(&store));
    let (fresh, _) = build(&second, &images, None);
    assert_eq!(
        other.walk.described, 1,
        "a second project describes its own `entry` alone (found {}, reached {})",
        other.walk.found, other.walk.reached
    );
    assert_eq!(other.walk.found, other.walk.reached - 1);
    assert!(other.walk.reached > SEALED, "premise: the walk reached the sealed chain");
    // Its own function's traced record (a few reads of its read list and answer), and one
    // reach record: never one read a sealed function ([`CHAIN`] of them).
    assert!(reads <= 8, "a second project read the store {reads} times, not once a sealed function");
    assert!(other.shared.is_empty(), "nothing sealed is made again: {}", other.shared.len());
    assert_eq!(function_signature_map(&other), function_signature_map(&fresh));

    let (restart, reads) = build(&first, &images, Some(&store));
    assert_eq!(restart.walk.described, 0, "a restart describes nothing (found {})", restart.walk.found);
    assert_eq!(restart.walk.found, restart.walk.reached);
    assert!(reads <= 8, "a restart read the store {reads} times, not once a sealed function");
    assert_eq!(function_signature_map(&restart), function_signature_map(&cold));
}

/// The invariant: an edit of sealed code's sources (the chain's last function) makes another
/// image of the sealed crate, so its reach record and every describe record of it miss: the
/// build describes the sealed chain again, and is the build of the edited sources with no store.
/// The cause removed (rule 23): with the sources as they were, the same store gives a build
/// that describes none of it.
#[test]
fn a_change_of_sealed_sources_misses_the_reach_record_and_builds_as_with_no_store() {
    let images = Images::default();
    let store = MemoryStore::default();
    let (cold, _) = build(&source("main", 1), &images, Some(&store));
    assert!(cold.walk.described > SEALED, "premise: the cold build describes everything");

    let edited = source("hello2", 2);
    let (after, _) = build(&edited, &images, Some(&store));
    let (fresh, _) = build(&edited, &images, None);
    assert!(
        after.walk.described >= SEALED,
        "an edit of the sealed crate describes its chain again ({} described)",
        after.walk.described
    );
    assert_eq!(function_signature_map(&after), function_signature_map(&fresh));
    assert_eq!(after.shared.len(), SEALED + 1, "the edited crate's records are made anew");

    let (unedited, _) = build(&source("hello3", 1), &images, Some(&store));
    assert_eq!(unedited.walk.described, 1, "the control: the sources as they were describe none of it");
}
