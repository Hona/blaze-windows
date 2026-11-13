//! The optimistic reads in flight ([`Pool::read_optimistic`](super::Pool::read_optimistic)), so
//! a give-back can take pages out of the address space only once none can still copy them.
//!
//! On Windows a page given back stays committed, charged against the machine's commit limit,
//! unless it is decommitted, and a decommitted page faults when read. An optimistic read copies a
//! page it saw `Loaded` without a pin, so a decommit must wait for every read that may have seen
//! a page `Loaded` before the sweep moved it to `Evicting`. A read that looks at the word after
//! that move sees `Evicting` and copies nothing.
//!
//! The reader's side costs two plain stores to a line of its thread's own: each thread holds a
//! slot of [`SLOTS`] ([`enter`]), whose `entered` it bumps before it reads a word and whose
//! `left` it bumps after its copy ([`Inside`]'s drop). A thread that finds every slot taken
//! shares the last one with atomic adds. The give-back's side ([`drain`]) moves its words first,
//! then makes every thread's earlier stores seen (`FlushProcessWriteBuffers` on Windows, the
//! barrier Linux's `membarrier` gives: the reader's side then needs no fence of its own), reads
//! each slot's `entered`, and waits until each `left` reached it: every read that entered before
//! the move has left. One that entered after it reads `Evicting` and leaves without copying.
//!
//! The wait is bounded ([`DRAIN_TRIES`]): a read preempted inside its copy keeps the batch's pages
//! committed (given back as before, and decommitted the next time they are), never a fault.

use std::{
    cell::Cell,
    sync::atomic::{AtomicBool, AtomicU64, Ordering, compiler_fence},
};

/// Slots: a daemon's threads that read the pool (its workers and its loop) and some more.
pub(crate) const SLOTS: usize = 128;

/// The last slot, which threads that found no free one share.
const SHARED: usize = SLOTS - 1;

/// How many times [`drain`] looks at the slots before it gives up on a decommit: each look a
/// spin hint, then a yield, so about a millisecond on a busy machine.
pub(crate) const DRAIN_TRIES: u32 = 2048;

#[repr(align(128))]
struct Slot {
    taken: AtomicBool,
    entered: AtomicU64,
    left: AtomicU64,
}

static READERS: [Slot; SLOTS] = [const {
    Slot { taken: AtomicBool::new(false), entered: AtomicU64::new(0), left: AtomicU64::new(0) }
}; SLOTS];

/// A thread's slot, let go as the thread ends.
struct Lease(Cell<usize>);

impl Drop for Lease {
    fn drop(&mut self) {
        let at = self.0.get();
        if at != SHARED && at < SLOTS {
            READERS[at].taken.store(false, Ordering::Release);
        }
    }
}

thread_local! {
    static MINE: Lease = const { Lease(Cell::new(usize::MAX)) };
}

/// The calling thread's slot, taken on its first read.
fn mine() -> usize {
    MINE.try_with(|lease| {
        let at = lease.0.get();
        if at != usize::MAX {
            return at;
        }
        let taken = (0..SHARED)
            .find(|&at| {
                READERS[at]
                    .taken
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            })
            .unwrap_or(SHARED);
        lease.0.set(taken);
        taken
    })
    // A thread past its thread-locals' end reads in the shared slot.
    .unwrap_or(SHARED)
}

/// One optimistic read in flight: it left once dropped.
#[derive(Debug)]
pub(crate) struct Inside {
    slot: usize,
}

/// An optimistic read begins: before it reads any state word.
pub(crate) fn enter() -> Inside {
    let slot = mine();
    let it = &READERS[slot];
    match slot {
        // Only this thread writes its slot: a load and a store, no locked add.
        SHARED => _ = it.entered.fetch_add(1, Ordering::Relaxed),
        _ => it.entered.store(it.entered.load(Ordering::Relaxed) + 1, Ordering::Relaxed),
    }
    // The store above before the word's load below, as the compiler emits them; the give-back's
    // barrier makes the hardware's order the program's ([`drain`]).
    compiler_fence(Ordering::SeqCst);
    Inside { slot }
}

impl Drop for Inside {
    fn drop(&mut self) {
        let it = &READERS[self.slot];
        // Release: the copy's loads before it, so a give-back that sees it sees them done.
        match self.slot {
            SHARED => _ = it.left.fetch_add(1, Ordering::Release),
            _ => it.left.store(it.left.load(Ordering::Relaxed) + 1, Ordering::Release),
        }
    }
}

/// Whether no optimistic read this thread began is in flight now: the simulation's drain and its
/// oracle, which run every reader on one thread (other tests' threads read in slots of their
/// own).
#[cfg(test)]
pub(crate) fn none_inside_here() -> bool {
    let it = &READERS[mine()];
    it.left.load(Ordering::Acquire) >= it.entered.load(Ordering::Acquire)
}

/// Waits, at most [`DRAIN_TRIES`] looks, until every optimistic read that entered before now
/// has left; whether they all did. The caller moved the words of the pages it gives back away
/// from `Loaded` first: a read that enters after this call's barrier sees that and copies
/// nothing.
pub(crate) fn drain() -> bool {
    blaze_mem::racy::process_fence();
    let mut entered = [0u64; SLOTS];
    for (seen, it) in entered.iter_mut().zip(&READERS) {
        *seen = it.entered.load(Ordering::Acquire);
    }
    let mut tries = 0;
    for (seen, it) in entered.iter().zip(&READERS) {
        while it.left.load(Ordering::Acquire) < *seen {
            tries += 1;
            if tries >= DRAIN_TRIES {
                return false;
            }
            // Not a wait for an event: a read in flight copies at most a page, so the loop
            // spins, yielding past the first looks, and gives up at its bound.
            match tries < 64 {
                true => std::hint::spin_loop(),
                false => std::thread::yield_now(),
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    /// The invariant: a drain says every read that entered before it left only once each has;
    /// a read in flight on another thread keeps it from saying so (it gives up at its bound),
    /// and the same read let go no longer does. The control is its first half.
    #[test]
    fn a_drain_waits_for_the_reads_that_entered_before_it() {
        let (entered, left) = (std::sync::mpsc::channel(), std::sync::mpsc::channel::<()>());
        let reader = std::thread::spawn(move || {
            let inside = super::enter();
            entered.0.send(()).unwrap();
            left.1.recv().unwrap();
            drop(inside);
        });
        entered.1.recv().unwrap();
        assert!(!super::drain(), "a read in flight on another thread was not waited for");
        left.0.send(()).unwrap();
        reader.join().unwrap();
        // Other tests' reads come and go meanwhile: one drain of a few must see none.
        let drained = (0..100).any(|_| {
            super::drain() || {
                std::thread::sleep(std::time::Duration::from_millis(5));
                false
            }
        });
        assert!(drained, "the read let go is still waited for");
    }
}
