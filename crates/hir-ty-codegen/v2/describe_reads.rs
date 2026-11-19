//! R7 decision fixture. Capture the inputs of a successful describe, including the edges to
//! warm memos. Counting just the queries that *ran* loses those edges. This module is test-only:
//! neither a durable hit nor a new record format is enabled by the census.

use std::collections::BTreeMap;

use blaze_codegen::{backend::FrontRef, plan::OptLevel};
use blaze_item_hash::{Bodies, identity::give_build, reads::mark_boundaries};
use blaze_items::key::item_key;
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

fn census(db: &Db, func: FunctionId, requester: Origin, facing: Facing) -> Census {
    let instance = root_in(db, func);
    let front = facing.front(db).unwrap();
    let memo = blaze_memo::Database::memo(db);
    let (answer, reads) =
        blaze_memo::record(memo, || front.described(db, &instance, &requester, facing.world))
            .expect("the fixture database keeps reads");
    let answer = answer.expect("the fixture's caller describes");
    let mut census = Census::default();
    for reference in answer.refs {
        if let FrontRef::Function(instance) = reference {
            let target = instance.function().expect("a direct call, not a shim");
            census.calls.push(item_key(db, ItemId::Function(target)));
        }
    }
    for read in reads {
        let name = read.kind().name();
        // The existing classifier's most permissive step: Infer and Mir can both be
        // prerequisites. Its covered/fact counts are candidates, NOT evidence of safety
        // for codegen, whose outputs also contain names, positions and references.
        let class = Bodies.fact_of(db, func.into(), Step::Borrowck, read);
        let index = match class {
            Classified::Covered => 0,
            Classified::Fact(_) | Classified::Scan(..) => 1,
            Classified::Refused(_) => 2,
        };
        census.reads.entry(name).or_default()[index] += 1;
    }
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
        let mut db = fixture::db_with_boundaries(&text, mark_boundaries, blaze_memo::Reads::Kept)
            .into_db();
        let mut edit = db.edit();
        give_build(&mut edit, ContentId([7; 32]));
        _ = edit.commit();
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
            let refused: usize = measured.reads.values().map(|c| c[2]).sum();
            assert!(
                refused > 0,
                "the describe must read inputs outside the caller's body identity: {:?}",
                measured.reads
            );
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
