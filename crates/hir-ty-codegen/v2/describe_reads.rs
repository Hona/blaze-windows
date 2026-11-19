//! Captured code-walk / describe dependency tests across separate databases (daemon restarts).
//!
//! Proves both directions required for sound durable describes:
//! - Valid restart hit: after a restart (fresh database, fresh memo, only the content-addressed
//!   store surviving) with nothing changed or an edit elsewhere, unchanged functions reuse both
//!   their traced describe records and compiled templates without running `code_walk` or compiling.
//! - Stale-callee miss: when an `#[inline]` callee's body changes while the daemon is down, the
//!   unchanged caller's traced describe misses (even if `code_walk` was a warm memo hit when
//!   captured), so the caller is redescribed and recompiled with its new call target.
//! - Planted-bug control: dropping `code_walk` reads causes the stale describe to be served,
//!   which the oracle against a fresh no-store build catches.

use std::{
    collections::BTreeMap,
    ops::ControlFlow,
    sync::atomic::{AtomicUsize, Ordering},
};

use blaze_cas::Key;
use blaze_codegen::{
    CompiledFunction, InstanceKey, RelocKind, Relocation, Static, Target, Unit,
    backend::{Emitted, FrontRef, Import, Prepare, Shape},
    driver::{Build, Built, Lookup, Put, Records},
    fold,
    memo::Memo,
    plan::{OptLevel, Origin},
    settings::Spec,
    summary::{Attrs, Call, Hint, Imports, Summary},
    template::Refs,
};
use blaze_core::lock::Lock;
use blaze_ids::{ContentId, Hasher};
use blaze_item_hash::{Bodies, identity::set_build};
use blaze_items::key::item_key;
use blaze_query::db::{Database as _, capture_reads};
use hir_expand::fixture;
use hir_ty::body_store::{BodyFacts, Classified, Step};

use super::*;
use crate::v2::{ItemHashes, tests::policy};

#[derive(Default, PartialEq, Eq, Debug)]
struct Census {
    // One count per visited read, not one count per executed query. Sorted for --nocapture.
    reads: BTreeMap<&'static str, [usize; 4]>,
    // In walk order, not sorted. Only direct function refs in this all-monomorphic fixture.
    calls: Vec<ItemKey>,
}

#[blaze_query::tracked(returns(ref))]
fn census(db: &Db, func: FunctionId, requester: Origin, facing: Facing) -> Census {
    let instance = root_in(db, func);
    let front = facing.front(db).unwrap();
    let (answer, reads) = capture_reads(db, || front.described(db, &instance, &requester, facing.world));
    let answer = answer.expect("the fixture's caller describes");
    let mut census = Census::default();
    for reference in answer.refs {
        if let FrontRef::Function(instance) = reference {
            let target = instance.function().expect("a direct call, not a shim");
            census.calls.push(item_key(db, ItemId::Function(target)));
        }
    }
    let storage = db.storage();
    let _: Option<()> =
        reads.expect("the fixture describe must be shareable").for_each_read(storage, |read| {
            let name = storage.read_name(read.key, read.kind);
            // The existing classifier's most permissive step: Infer and Mir can both be
            // prerequisites. Its covered/fact counts are candidates, NOT evidence of safety
            // for codegen, whose outputs also contain names, positions and references.
            let class = Bodies.classify(db, func.into(), Step::Borrowck, read.key, read.kind, name);
            let index = match class {
                Classified::Covered => 0,
                Classified::Fact(_) | Classified::Scan(_) => 1,
                Classified::Refused => 2,
                Classified::Through => 3,
            };
            census.reads.entry(name).or_default()[index] += 1;
            ControlFlow::Continue(())
        });
    census
}

#[test]
fn an_unchanged_callers_body_identity_cannot_validate_its_walk() {
    // As in the_walk_lists_what_inlined_code_calls. Change only the inlinable callee's body.
    // Two separate databases: compare the calls by item key, never by the databases' IDs.
    let revision = |next: &str, other: &str| {
        let text = format!(
            "//- minicore: sized, copy\n\
             #[inline(never)] pub fn left(x: u32) -> u32 {{ x ^ 7 }}\n\
             #[inline(never)] pub fn right(x: u32) -> u32 {{ x ^ 11 }}\n\
             #[inline] pub fn mid(x: u32) -> u32 {{ {next}(x) }}\n\
             pub fn caller(x: u32) -> u32 {{ mid(x) }}"
        );
        let mut db = fixture::db(&text).into_db();
        set_build(&mut db, ContentId([7; 32]));
        let hashes = HashSource::Items(ItemHashes::new(Box::new(|_| None)));
        let front = HirFrontend::new(Databases::new(&db), hashes, BuildTime::default())
            .with_policy(&policy(OptLevel::O3));
        front.with(|db| {
            let krate = fixture::test_crate(db);
            let func = |name| hir_def::test_items::function(db, krate, name);
            let caller = func("caller");
            let identity = Bodies.identity(db, caller.into()).expect("the caller's body identity");
            let measured = census(db, caller, front.origin(db, krate), front.facing(None));
            eprintln!("{next}: describe reads (covered, fact, refused, through): {:?}", measured.reads);
            let unknown = measured.reads.get("code_walk").expect("the describe read code_walk");
            assert!(unknown[2] > 0, "the missing walk fact has changed: {unknown:?}");
            let calls = |name| measured.calls.contains(&item_key(db, ItemId::Function(func(name))));
            assert!(calls(next));
            assert!(!calls(other));
            (identity, measured.calls.clone())
        })
    };
    let (before, old_calls) = revision("left", "right");
    let (after, new_calls) = revision("right", "left");
    assert_eq!(before, after, "the edit changed no input of the caller's body identity");
    assert_ne!(old_calls, new_calls, "serving the old walk would name the wrong function");
}

/// Content-addressed in-memory store surviving across simulated daemon restarts.
/// Holds only `(Key, bytes)` pairs committed from `Built::puts` — no database IDs.
struct MemoryStore {
    entries: Lock<BTreeMap<Key, Vec<u8>>>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        MemoryStore { entries: Lock::new("test.describe_reads.store", BTreeMap::new()) }
    }
}

impl MemoryStore {
    fn commit(&self, puts: &[Put]) {
        let mut entries = self.entries.lock();
        for put in puts {
            if let Some(prev) = entries.get(&put.key) {
                assert_eq!(
                    prev, &put.bytes,
                    "store key {:x} received two different values (rule 21)",
                    put.key.0
                );
            } else {
                entries.insert(put.key, put.bytes.clone());
            }
        }
    }
}

impl Records for MemoryStore {
    fn read(&self, key: &Key, read: &mut dyn FnMut(&[u8])) -> Result<bool, String> {
        let bytes = self.entries.lock().get(key).cloned();
        match bytes {
            Some(bytes) => {
                read(&bytes);
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

impl Lookup for MemoryStore {
    fn read(&self, key: &Key) -> Result<Option<&[u8]>, String> {
        // Leak in test-only memory store so `Lookup::read`'s borrowed lifetime matches CAS.
        let bytes = self.entries.lock().get(key).cloned();
        Ok(bytes.map(|b| &*Box::leak(b.into_boxed_slice())))
    }
}

/// Deterministic stub backend for `Build::run` over the real `HirFrontend` and `hir-ty-mir`
/// inliner: works with or without LLVM enabled, records exact compile counts, and emits one
/// relocation per reference so call targets are observable in `Built::functions`.
#[derive(Default)]
struct StubMachine<'db> {
    compiled: AtomicUsize,
    _db: std::marker::PhantomData<&'db Db>,
}

struct StubPrepared {
    code: [u8; 32],
    refs: usize,
}

impl<'db> Prepare for StubMachine<'db> {
    type Frontend = HirFrontend<'db>;
    type Prepared = StubPrepared;
    type Export = [u8; 32];

    fn prepare(
        &self,
        _frontend: &Self::Frontend,
        unit: &Unit,
        _spec: &Spec,
        _instance: &HirInstance,
        refs: &Refs,
    ) -> Result<(Shape, Self::Prepared), CodegenError> {
        let mut h = Hasher::new("blaze test stub machine shape 1");
        h.id(&unit.instance.code.0)
            .id(&unit.instance.args)
            .update(&(refs.len() as u64).to_le_bytes());
        let id = h.finish();
        Ok((Shape::of(unit, &id.0), StubPrepared { code: id.0, refs: refs.len() }))
    }

    fn summarize(
        &self,
        unit: &Unit,
        _spec: &Spec,
        prepared: &mut Self::Prepared,
        refs: &Refs,
    ) -> Result<(Summary, Self::Export), CodegenError> {
        let calls = refs
            .iter()
            .filter_map(|it| match it {
                Target::Function(key) | Target::Direct(key) => {
                    Some(Call { callee: *key, count: 1, args: Vec::new() })
                }
                _ => None,
            })
            .collect();
        Ok((
            Summary {
                key: unit.instance.key(),
                size: 16,
                hint: Hint::Never,
                calls,
                addressed: Vec::new(),
                params: 0,
                unused: Vec::new(),
                attrs: Attrs::default(),
                body: Attrs::default(),
                external: true,
            },
            prepared.code,
        ))
    }

    fn emit(
        &self,
        unit: &Unit,
        _spec: &Spec,
        prepared: StubPrepared,
        refs: &Refs,
        _imports: Option<(&Imports, &[Import<'_, Self::Export>])>,
    ) -> Result<Emitted, CodegenError> {
        self.compiled.fetch_add(1, Ordering::Relaxed);
        let mut code = Vec::with_capacity(32 + 8 * prepared.refs);
        code.extend_from_slice(&prepared.code);
        let mut relocs = Vec::with_capacity(prepared.refs);
        for target in refs.iter() {
            let offset = code.len() as u32;
            code.extend_from_slice(&[0u8; 8]);
            relocs.push(Relocation {
                at: offset,
                kind: RelocKind::PcRel32,
                target: target.clone(),
                addend: -4,
            });
        }
        Ok(Emitted {
            function: CompiledFunction {
                key: unit.instance.key(),
                arch: unit.arch,
                align: 16,
                code,
                relocs: relocs.into(),
                data: Vec::new(),
                unwind: None,
                lines: Vec::new(),
                coverage: None,
                profile: None,
                inlined: Vec::new(),
                side: None,
            },
            side: None,
            extra: Vec::new(),
        })
    }

    fn masked(&self, _: &Unit, _: &Self::Prepared, _: &Refs) -> Option<fold::Masked> {
        None
    }

    fn merge(
        &self,
        _: &fold::Group,
        _: Vec<(&Unit, &Spec, Self::Prepared, &Refs)>,
    ) -> Result<fold::Merged, CodegenError> {
        unreachable!("folding is disabled in stub policy")
    }

    fn compile_static(
        &self,
        _: &Self::Frontend,
        _: &Spec,
        _: &HirStatic,
        _: &Refs,
    ) -> Result<Static, CodegenError> {
        unreachable!("fixture has no statics")
    }
}

fn fixture_source(mid_target: &str, other_val: u32) -> String {
    format!(
        "//- minicore: sized, copy\n\
         #[inline(never)] pub fn left(x: u32) -> u32 {{ x ^ 7 }}\n\
         #[inline(never)] pub fn right(x: u32) -> u32 {{ x ^ 11 }}\n\
         #[inline] pub fn mid(x: u32) -> u32 {{ {mid_target}(x) }}\n\
         #[inline(never)] pub fn caller(x: u32) -> u32 {{ mid(x) }}\n\
         #[inline(never)] pub fn other(x: u32) -> u32 {{ x ^ {other_val} }}\n\
         pub fn entry(x: u32) -> u32 {{ caller(x) ^ other(x) }}"
    )
}

fn is_named(debug_name: &str, short: &str) -> bool {
    debug_name == short
        || debug_name.strip_suffix(short).is_some_and(|prefix| prefix.ends_with("::"))
}

/// Runs a full `Build` over a brand-new database (fresh interners, fresh `Memo`, no kept walk)
/// against `store` (`None` for a fresh empty-store reference build) starting from `root_names`.
/// Returns `(built, compiled, debug_names_of_caller_targets)`.
fn run_in_fresh_db(
    text: &str,
    root_names: &[&str],
    store: Option<&MemoryStore>,
    warm_code_walk_first: bool,
) -> (Built, usize, Vec<String>) {
    let mut db = fixture::db(text).into_db();
    set_build(&mut db, ContentId([7; 32]));
    let hashes = HashSource::Items(ItemHashes::new(Box::new(|_| None)));
    let pol = policy(OptLevel::O3);
    let front = HirFrontend::new(Databases::new(&db), hashes, BuildTime::default()).with_policy(&pol);
    let roots: Vec<(HirInstance, Origin)> = front.with(|db| {
        let krate = fixture::test_crate(db);
        let func = |name| hir_def::test_items::function(db, krate, name);
        let origin = front.origin(db, krate);
        if warm_code_walk_first {
            let caller = front.root(func("caller"));
            // Warm `code_walk`'s memo before `Build::run` so capture must descend through a memo hit.
            let _ = refs::walk(db, &caller, refs::Walking::plain(true))
                .expect("warm code_walk succeeds");
        }
        root_names.iter().map(|name| (front.root(func(name)), origin)).collect()
    });
    let empty = MemoryStore::default();
    let lookup = store.unwrap_or(&empty);
    let machine = StubMachine::default();
    let memo = Memo::new();
    let build = Build::new(&machine, &front, &pol, &memo);
    let mut build = match store {
        Some(store) => build.recording(store),
        None => build,
    };
    let built = build
        .run(&roots, lookup)
        .unwrap_or_else(|errs| panic!("build failed: {errs:?}"));
    // Extract the debug names of every function referenced by `caller`'s compiled relocations.
    let name_of = |key: InstanceKey| -> Option<String> {
        built.debug_names.iter().find(|(k, _)| *k == key).map(|(_, n)| n.clone())
    };
    let caller_key = built
        .debug_names
        .iter()
        .find(|(_, name)| is_named(name, "caller"))
        .map(|(k, _)| *k)
        .expect("`caller` is in the build");
    let caller_fn = built
        .functions
        .iter()
        .find(|it| it.key == caller_key)
        .expect("`caller` compiled function is present");
    let mut caller_targets: Vec<String> = caller_fn
        .relocs
        .targets()
        .iter()
        .filter_map(|t| match t {
            Target::Function(k) | Target::Direct(k) => name_of(*k),
            _ => None,
        })
        .collect();
    caller_targets.sort();
    caller_targets.dedup();
    (built, machine.compiled.load(Ordering::Relaxed), caller_targets)
}

fn function_signature_map(built: &Built) -> BTreeMap<String, Vec<u8>> {
    let mut map = BTreeMap::new();
    for f in &built.functions {
        let name = built
            .debug_names
            .iter()
            .find(|(k, _)| *k == f.key)
            .map(|(_, n)| n.clone())
            .unwrap_or_else(|| format!("{:?}", f.key));
        map.insert(name, f.code.clone());
    }
    map
}

/// Verifies directly that `traced::capture_facts` classifies every read of `caller`'s describe
/// (with zero refusals) and captures `mid`'s `BodyMir` fact even on a warm `code_walk` memo hit.
#[test]
fn traced_capture_classifies_all_code_walk_reads_and_includes_inlined_callee_mir() {
    let v1 = fixture_source("left", 1);
    let mut db = fixture::db(&v1).into_db();
    set_build(&mut db, ContentId([7; 32]));
    let hashes = HashSource::Items(ItemHashes::new(Box::new(|_| None)));
    let pol = policy(OptLevel::O3);
    let front = HirFrontend::new(Databases::new(&db), hashes, BuildTime::default()).with_policy(&pol);
    front.with(|db| {
        let krate = fixture::test_crate(db);
        let func = |name| hir_def::test_items::function(db, krate, name);
        let caller_fn = func("caller");
        let mid_fn = func("mid");
        let caller = front.root(caller_fn);
        let origin = front.origin(db, krate);
        // Warm `code_walk` first so capture proves descent through a memo hit.
        let _ = refs::walk(db, &caller, refs::Walking::plain(true)).expect("warm walk");
        let mut scratch = Vec::new();
        let ((desc, captured), _) = blaze_query::db::witnessed(db, &mut scratch, || {
            capture_reads(db, || front.described(db, &caller, &origin, None))
        });
        assert!(desc.is_ok(), "caller describes");
        let reads = captured.expect("describe reads must be shareable");
        let facts = described::traced::capture_facts(db, krate, Some(caller_fn.into()), reads)
            .unwrap_or_else(|refused| {
                panic!("traced describe refused read `{refused}` for `caller`")
            });
        let mid_mir = described::traced::DescribeFact::BodyMir(
            blaze_item_hash::values::body_key(db, mid_fn.into()),
        );
        assert!(
            facts.contains(&mid_mir),
            "captured facts must contain inlined callee `mid`'s BodyMir: {facts:?}"
        );
    });
}

/// Direction 1 (valid restart hit): after a daemon restart (fresh DB, fresh memo, only the store
/// surviving), with nothing changed zero functions are described or compiled; with an edit to an
/// unrelated function (`other`), unchanged functions (`caller`, `mid`, `left`) hit their traced
/// describe records and compiled templates, and only `other` is compiled.
#[test]
fn a_restart_with_an_edit_elsewhere_reuses_described_and_compiled_functions() {
    let store = MemoryStore::default();
    let v1 = fixture_source("left", 1);
    let roots = &["caller", "other"];

    // First daemon: cold build populates traced describe records and compiled templates.
    let (cold, cold_compiled, cold_targets) = run_in_fresh_db(&v1, roots, Some(&store), false);
    assert!(cold_compiled > 0, "cold build must compile functions");
    assert!(
        cold_targets.iter().any(|n| is_named(n, "left")),
        "cold `caller` must inline `mid` and call `left`: {cold_targets:?}"
    );
    store.commit(&cold.puts);

    // Restart 1: nothing changed at all -> zero describes, zero compiles.
    let (restart_same, same_compiled, same_targets) =
        run_in_fresh_db(&v1, roots, Some(&store), false);
    assert_eq!(
        restart_same.walk.described, 0,
        "unchanged restart should describe 0 functions (found={}, reached={})",
        restart_same.walk.found, restart_same.walk.reached
    );
    assert_eq!(restart_same.walk.found, restart_same.walk.reached);
    assert_eq!(same_compiled, 0, "unchanged restart should compile 0 functions");
    assert_eq!(same_targets, cold_targets);
    assert_eq!(function_signature_map(&restart_same), function_signature_map(&cold));

    // Restart 2: edit `other` elsewhere -> unchanged `caller`/`left` hit, only `other` compiles.
    let v2 = fixture_source("left", 2);
    let (restart_edit, edit_compiled, edit_targets) =
        run_in_fresh_db(&v2, roots, Some(&store), false);
    let (fresh_v2, _, fresh_targets) = run_in_fresh_db(&v2, roots, None, false);
    assert_eq!(
        edit_compiled, 1,
        "restart with edit only in `other` should compile only `other`, got {edit_compiled} \
         (described={}, found={}, reached={})",
        restart_edit.walk.described, restart_edit.walk.found, restart_edit.walk.reached
    );
    assert_eq!(
        restart_edit.walk.described, 1,
        "only `other` should miss its traced describe record"
    );
    assert!(restart_edit.walk.found >= 2, "unchanged functions must hit traced describe records");
    assert_eq!(edit_targets, fresh_targets);
    assert_eq!(function_signature_map(&restart_edit), function_signature_map(&fresh_v2));
}

/// Direction 2 (stale-callee miss): when an `#[inline]` callee (`mid`) changes while the daemon
/// is down, the unchanged caller's traced describe misses its captured `BodyMir(mid)` dependency,
/// so the caller is redescribed and recompiled to call `right` instead of `left`.
#[test]
fn a_restart_after_an_inlined_callee_changes_misses_and_recompiles_the_caller() {
    let store = MemoryStore::default();
    let v1 = fixture_source("left", 1);
    let roots = &["entry"];
    let (cold, _, cold_targets) = run_in_fresh_db(&v1, roots, Some(&store), false);
    assert!(cold_targets.iter().any(|n| is_named(n, "left")), "{cold_targets:?}");
    assert!(!cold_targets.iter().any(|n| is_named(n, "right")), "{cold_targets:?}");
    store.commit(&cold.puts);

    // Daemon down -> `mid` edited to call `right` instead of `left`; `caller`'s text is unchanged.
    let v2 = fixture_source("right", 1);
    let (restarted, compiled, targets) = run_in_fresh_db(&v2, roots, Some(&store), false);
    let (fresh_v2, _, fresh_targets) = run_in_fresh_db(&v2, roots, None, false);
    assert!(compiled >= 1, "caller must be recompiled after its inlined callee changed");
    assert!(
        targets.iter().any(|n| is_named(n, "right")),
        "restarted `caller` must call `right` after `mid` changed: {targets:?}"
    );
    assert!(
        !targets.iter().any(|n| is_named(n, "left")),
        "restarted `caller` must not retain stale call to `left`: {targets:?}"
    );
    assert_eq!(targets, fresh_targets);
    assert_eq!(function_signature_map(&restarted), function_signature_map(&fresh_v2));
}

/// Warm memo hit capture: even when `code_walk` is already memoized in DB 1 before the traced
/// describe record is captured, `for_each_read_through` descends through `code_walk`'s kept
/// edges and records `BodyMir(mid)`, so a subsequent restart with `mid` changed still misses.
#[test]
fn capturing_walk_dependencies_succeeds_even_on_a_code_walk_memo_hit() {
    let store = MemoryStore::default();
    let v1 = fixture_source("left", 1);
    let roots = &["entry"];
    let (cold, _, _) = run_in_fresh_db(&v1, roots, Some(&store), true);
    store.commit(&cold.puts);

    let v2 = fixture_source("right", 1);
    let (restarted, compiled, targets) = run_in_fresh_db(&v2, roots, Some(&store), false);
    let (fresh_v2, _, fresh_targets) = run_in_fresh_db(&v2, roots, None, false);
    assert!(compiled >= 1, "caller must be recompiled even when DB 1 captured on a code_walk memo hit");
    assert_eq!(targets, fresh_targets);
    assert!(targets.iter().any(|n| is_named(n, "right")), "{targets:?}");
    assert!(!targets.iter().any(|n| is_named(n, "left")), "{targets:?}");
    assert_eq!(function_signature_map(&restarted), function_signature_map(&fresh_v2));
}

/// Planted-bug control: dropping `code_walk` dependencies from the captured read-list causes
/// the restarted build to serve the stale `caller` calling `left`, which the oracle catches.
#[test]
fn the_oracle_catches_dropped_code_walk_dependencies() {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            described::traced::planted::DROP_WALK_READS.set(false);
        }
    }
    let store = MemoryStore::default();
    let v1 = fixture_source("left", 1);
    let roots = &["entry"];
    {
        let _reset = Reset;
        described::traced::planted::DROP_WALK_READS.set(true);
        let (cold, _, _) = run_in_fresh_db(&v1, roots, Some(&store), false);
        store.commit(&cold.puts);
    }

    let v2 = fixture_source("right", 1);
    let (_, _, planted_targets) = run_in_fresh_db(&v2, roots, Some(&store), false);
    let (_, _, fresh_targets) = run_in_fresh_db(&v2, roots, None, false);
    assert_ne!(
        planted_targets, fresh_targets,
        "planted bug dropping code_walk reads must serve stale targets that the oracle catches"
    );
    assert!(
        planted_targets.iter().any(|n| is_named(n, "left")),
        "planted bug should have served stale `left`: {planted_targets:?}"
    );
}

/// Layout and integrity checks for traced describe answers (rule 26): foreign magic, mismatched
/// key, and truncated payloads are refused by name.
#[test]
fn a_traced_describe_record_with_bad_layout_or_key_is_refused_by_name() {
    let key = ContentId([0x42; 32]);
    let other = ContentId([0x99; 32]);
    let mut valid = Vec::new();
    valid.extend_from_slice(b"bztd0001");
    valid.extend_from_slice(&key.0);
    valid.extend_from_slice(b"payload");
    assert_eq!(described::traced::open_answer(&valid, &key).unwrap(), b"payload");

    let mut wrong_magic = valid.clone();
    wrong_magic[7] = b'0';
    let err = described::traced::open_answer(&wrong_magic, &key).unwrap_err();
    assert!(err.contains("bztd0001"), "{err}");

    let err = described::traced::open_answer(&valid, &other).unwrap_err();
    assert!(err.contains("does not match"), "{err}");

    assert!(described::traced::open_answer(&valid[..10], &key).is_err());
}
