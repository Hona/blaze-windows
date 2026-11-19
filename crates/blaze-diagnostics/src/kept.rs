//! A sweep of one memo a member (a body, a piece) of a crate's check.
//!
//! On the session memo (blaze-memo) there is no changed set to sweep from: the memo is not the
//! incremental mechanism (docs/v2/plan/design/front-end-on-memo.md, decision 3), and a member's
//! memo carried in its crate's arena answers its ask from the arena. So every sweep asks every
//! member's memo, at once on the database's workers, then reads them in the members' order.
//! Reuse across edits is the host's, on body records (docs/v2/plan/design/host.md).

use std::{alloc::Global, hash::Hash};

use base_db::Db;
use blaze_hash::HashSet;
use blaze_mem::Tag;

/// What a sweep did: the members whose memo said "not clean", in the members' order, and its
/// work, which its span names.
#[derive(Debug)]
pub(crate) struct Swept<M> {
    pub(crate) unclean: Vec<M>,
    /// The members held.
    pub(crate) held: usize,
    /// The members whose memo was asked.
    pub(crate) asked: usize,
    /// Of those, the members named as changed: none on the session memo.
    pub(crate) named: usize,
    /// Whether every member was asked: always, on the session memo.
    pub(crate) whole: bool,
}

/// The sweep of `members` keyed by `key` in `db`: `clean` is the memo's ask (whether the
/// member is clean). Asks run at once on the database's workers, then are read in the members'
/// order.
pub(crate) fn sweep<K, M>(
    db: &Db,
    _key: K,
    members: &[M],
    clean: impl Fn(&Db, M) -> bool + Sync,
) -> Swept<M>
where
    M: Copy + Eq + Hash + Send + Sync + 'static,
{
    db.run_all(Tag::Diagnostics, members.len(), |db, at| {
        clean(db, members[at]);
    });
    let mut unclean_set: HashSet<M, Global> = HashSet::new_in(Global);
    for &member in members {
        if !clean(db, member) {
            unclean_set.insert(member);
        }
    }
    // In the members' order: what the check lints for what it says, in rustc's order.
    let unclean: Vec<M> = members.iter().copied().filter(|it| unclean_set.contains(it)).collect();
    Swept { unclean, held: members.len(), asked: members.len(), named: 0, whole: true }
}
