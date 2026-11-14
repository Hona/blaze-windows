//! R7 decision fixture. Capture the inputs of a successful describe, including the edges to
//! warm memos. Counting just the queries that *ran* loses those edges. This module is test-only:
//! neither a durable hit nor a new record format is enabled by the census.

use std::{collections::BTreeMap, ops::ControlFlow};

use blaze_codegen::{backend::FrontRef, plan::OptLevel};
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
    reads: BTreeMap<&'static str, [usize; 3]>,
    // In walk order, not sorted. Only direct function refs in this all-monomorphic fixture.
    calls: Vec<ItemKey>,
}

#[blaze_query::tracked(returns(ref))]
fn census(db: &Db, func: FunctionId, requester: Origin, facing: Facing) -> Census {
    let instance = root_in(db, func);
    let (described, reads) = capture_reads(db, || fresh_describe(db, &instance, requester, facing));
    let Memoed::Described(Ok(answer)) = described else { panic!("{func:?}: {described:?}") };
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
                Classified::Fact(_) => 1,
                Classified::Refused => 2,
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
            eprintln!("{next}: describe reads (covered, fact, refused): {:?}", measured.reads);
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
