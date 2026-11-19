//! A sweep of one memo a member (a body, a piece) of a crate's check, from the last sweep of
//! the same key: what `hir::check::bodies`' kept check is for its plan, for every other sweep
//! of the check (docs/v2/plan/design/incremental-walk.md, "The changed set from the engine").
//!
//! A sweep with nothing kept asks every member's memo. It keeps, beside the database, the view
//! it asked them in, its members and those whose memo said "not clean". The next sweep of the
//! same key asks the engine which memos changed since that view
//! ([`blaze_query::db::plumbing::changed_ids_since`], through the memo's `changed_since`) and
//! asks only those, the members not clean before (their findings are not kept) and the members
//! new since; every other member's answer is the kept one, clean, with no ask. So a check after
//! a one-body edit asks the memos the edit reached, not the crate's: until 2026-11-19 each body
//! lint pass asked all 11,368 memos of opencode-desktop's binary on every check, a verification
//! each.
//!
//! Why the kept answer is right (rule keys-cover-every-input). The engine records every read
//! of each memo's run, so its changed set since the kept view names every memo whose value is
//! another; a member it does not name had in this view the value it had then, and "clean" is
//! the only value kept. Every member was asked in the kept view or is new and asked now. A
//! database made again has another nonce, so nothing kept. Where the engine cannot name the
//! changed set there is no sweep: the kept sweep goes back as it was and the check panics with
//! why, as `hir::check::bodies` does (rule no-fallback).
//!
//! Memory only: it names the database's IDs, and a restart begins with nothing kept.

use std::{alloc::Global, any::Any, hash::Hash};

use base_db::{Db, Nonce};
use blaze_core::lock::Lock;
use blaze_hash::HashSet;
use blaze_mem::Tag;
use blaze_query::db::{Changed, Id, View};

/// How many kept sweeps a process holds: the least recently used goes when one more is made.
/// As `hir::check::bodies`' `KEPT_CHECKS`: past every workspace's crates times its sweeps.
const KEPT_SWEEPS: usize = 4096;

/// One kept sweep: its key, the database it is of and the view it asked in.
struct Entry<K, M> {
    key: K,
    database: Nonce,
    view: View,
    members: HashSet<M, Global>,
    unclean: HashSet<M, Global>,
}

/// The kept sweeps, each an [`Entry`] of its own key and member type beside its database, the
/// last used last.
#[expect(
    blaze::process_static,
    reason = "an LRU capped at KEPT_SWEEPS, as hir's kept checks: the database should own them once base-db can name hir's ids"
)]
static KEPT: Lock<Vec<(Nonce, Box<dyn Any + Send>)>> = Lock::new("diagnostics.kept", Vec::new());

/// What a sweep did: the members whose memo said "not clean", in the members' order, and its
/// work, which its span names and a test holds to the edit.
#[derive(Debug)]
pub(crate) struct Swept<M> {
    pub(crate) unclean: Vec<M>,
    /// The members held.
    pub(crate) held: usize,
    /// The members whose memo was asked.
    pub(crate) asked: usize,
    /// Of those, the members the engine named as changed since the kept sweep.
    pub(crate) named: usize,
    /// Whether nothing was kept, so every member was asked.
    pub(crate) whole: bool,
}

fn take<K, M>(key: &K, database: Nonce) -> Option<Entry<K, M>>
where
    K: Eq + Send + 'static,
    M: Send + 'static,
{
    let mut all = KEPT.lock();
    let at = all.iter().position(|(of, it)| {
        *of == database && it.downcast_ref::<Entry<K, M>>().is_some_and(|it| it.key == *key)
    })?;
    let entry = all.remove(at).1.downcast::<Entry<K, M>>().expect("found as an entry of this type");
    Some(*entry)
}

/// Lets go of every sweep kept of `database`, of every key and member type: the control of a
/// test that the kept sweep is what keeps an edit's asks small (its next sweep asks every
/// member, as a sweep with nothing kept does).
#[cfg(test)]
pub(crate) fn forget(database: Nonce) {
    KEPT.lock().retain(|it| it.0 != database);
}

fn put<K, M>(entry: Entry<K, M>)
where
    K: Send + 'static,
    M: Send + 'static,
{
    let mut all = KEPT.lock();
    if all.len() >= KEPT_SWEEPS {
        all.remove(0);
    }
    // alloc: once a sweep, one entry per database, crate and key
    all.push((entry.database, Box::new(entry)));
}

/// The sweep of `members` keyed by `key` in `db`: `clean` is the memo's ask (whether the
/// member is clean), `changed_since` the memo's changed set since a view, and `member_of` the
/// member of a changed key's ID, `None` for a key of another sweep (another gate, another
/// crate). Asks run at once on the database's workers, then are read in the members' order.
///
/// # Panics
///
/// With the engine's reason, when a sweep is kept of `key` and the engine cannot name what
/// changed since it.
pub(crate) fn sweep<K, M>(
    db: &Db,
    key: K,
    members: &[M],
    changed_since: impl FnOnce(View) -> Changed<Id>,
    member_of: impl Fn(Id) -> Option<M>,
    clean: impl Fn(&Db, M) -> bool + Sync,
) -> Swept<M>
where
    K: Clone + Eq + Send + std::fmt::Debug + 'static,
    M: Copy + Eq + Hash + Send + Sync + 'static,
{
    let (database, view) = db.nonce_and_revision();
    let kept = take::<K, M>(&key, database);
    let whole = kept.is_none();
    let mut named = 0;
    // alloc: once a sweep, a word per member asked
    let asked: Vec<M> = match kept {
        None => members.to_vec(),
        Some(kept) => {
            let changed = match changed_since(kept.view) {
                Changed::Keys(ids) => ids,
                Changed::Unknown(why) => {
                    let since = kept.view;
                    put(kept);
                    panic!(
                        "the sweep {key:?} holds a kept sweep of view {} and the query engine \
                         cannot name what changed since it: {why} (blaze_diagnostics::kept, \
                         rule no-fallback)",
                        since.as_u64()
                    );
                }
            };
            let mut ask: HashSet<M, Global> = HashSet::new_in(Global);
            for id in changed {
                if let Some(member) = member_of(id)
                    && kept.members.contains(&member)
                    && ask.insert(member)
                {
                    named += 1;
                }
            }
            ask.extend(kept.unclean.iter().copied());
            members
                .iter()
                .copied()
                .filter(|it| ask.contains(it) || !kept.members.contains(it))
                .collect()
        }
    };
    db.run_all(Tag::Diagnostics, asked.len(), |db, at| {
        clean(db, asked[at]);
    });
    let mut unclean_set: HashSet<M, Global> = HashSet::new_in(Global);
    for &member in &asked {
        if !clean(db, member) {
            unclean_set.insert(member);
        }
    }
    // In the members' order: what the check lints for what it says, in rustc's order.
    let unclean: Vec<M> = members.iter().copied().filter(|it| unclean_set.contains(it)).collect();
    let mut held: HashSet<M, Global> = HashSet::new_in(Global);
    held.extend(members.iter().copied());
    put(Entry { key, database, view, members: held, unclean: unclean_set });
    Swept { unclean, held: members.len(), asked: asked.len(), named, whole }
}
