//! What the daemon does when its footprint passes its ceiling: it gives memory back in rungs,
//! each cheaper to make again than the next, and measures between them; it exits
//! ([`blaze_core::exit::Exit::MemoryCeiling`], 77) only once every rung was tried and the
//! footprint is still past the ceiling. A build that is slower because it made again what was
//! let go is a build; one that dies is not (docs/v2/plan/design/memory.md, "Giving memory back").
//!
//! The rungs, in order ([`Rung`]):
//!
//! 1. [`Rung::Purge`]: the allocators' freed pages (`raw::memory::purge`). Makes nothing again.
//! 2. [`Rung::Images`]: the linked images kept between builds that no running program maps.
//!    The next link of each is a link from scratch.
//! 3. [`Rung::Compiled`]: what kept front ends hold of compiled code: codegen's kept walks,
//!    every MIR body and constant value. Made again from their memos when read.
//! 4. [`Rung::Values`]: every evictable value of the kept front ends (inference and the
//!    weighed query values). Made again from their memos when read, and backdated.
//!
//! Two halves: [`Ladder`], a sans-IO core the ceiling guard's thread steps with each reading,
//! and [`Channel`], how that thread asks the daemon's loop (which alone owns the kept front
//! ends and images) for a rung and hears it done. A loop that does not answer within
//! [`ANSWER_WITHIN`] is passed over: the guard measures and goes on, so a stuck loop still ends
//! at the ceiling within a bounded time (rule `bounded-progress`).

use std::{
    sync::atomic::{AtomicU8, AtomicU64, Ordering},
    time::Duration,
};

/// The rungs, in the order they are asked.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub(crate) enum Rung {
    Purge = 1,
    Images = 2,
    Compiled = 3,
    Values = 4,
}

impl Rung {
    pub(crate) const ALL: [Rung; 4] = [Rung::Purge, Rung::Images, Rung::Compiled, Rung::Values];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Rung::Purge => "the allocators' freed pages",
            Rung::Images => "the linked images kept between builds",
            Rung::Compiled => "the kept front ends' compiled code (codegen's walks, MIR, constants)",
            Rung::Values => "the kept front ends' evictable values (inference and weighed queries)",
        }
    }

    fn of(byte: u8) -> Option<Rung> {
        Rung::ALL.into_iter().find(|it| *it as u8 == byte)
    }
}

/// How long the guard waits for the loop to answer a rung before it measures anyway.
pub(crate) const ANSWER_WITHIN: Duration = Duration::from_secs(5);

/// How long the guard waits, past every rung, for running builds asked to give back at their
/// next write (their readers end first) before it ends the daemon.
pub(crate) const RUNNING_WITHIN: Duration = Duration::from_secs(60);

/// What a look at the footprint against the ceiling asks for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Step {
    /// Under the ceiling: nothing.
    Under,
    /// Past it: give back this rung, then look again.
    Give(Rung),
    /// Past it with every rung given since it was last under: the daemon ends.
    Exit,
}

/// The ladder's state between looks: the rungs given since the footprint was last at or under
/// the ceiling. A core: no clock, no IO.
///
/// The invariant: from a look under the ceiling on, the rungs are asked in [`Rung::ALL`]'s
/// order, each at most once, one per look past the ceiling, and [`Step::Exit`] comes only at a
/// look past the ceiling after all four were asked. Any look at or under the ceiling starts
/// the ladder again from the first rung.
#[derive(Default, Debug)]
pub(crate) struct Ladder {
    given: usize,
}

impl Ladder {
    #[blaze::pure]
    pub(crate) fn look(&mut self, footprint: u64, ceiling: u64) -> Step {
        if ceiling == 0 || footprint <= ceiling {
            self.given = 0;
            return Step::Under;
        }
        match Rung::ALL.get(self.given) {
            Some(&rung) => {
                self.given += 1;
                Step::Give(rung)
            }
            None => Step::Exit,
        }
    }

    /// The rungs given since the footprint was last under the ceiling.
    pub(crate) fn given(&self) -> &'static [Rung] {
        &Rung::ALL[..self.given]
    }
}

impl Given {
    /// Both gives summed: one rung over every kept front end.
    pub(crate) fn add(&mut self, other: Given) {
        self.images += other.images;
        self.image_bytes += other.image_bytes;
        self.fronts += other.fronts;
        self.values += other.values;
        self.walked += other.walked;
        self.query_bytes += other.query_bytes;
        self.builds += other.builds;
    }
}

/// What the loop gave back for one rung, said to the next build's client and in the log.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) struct Given {
    /// Kept link images dropped.
    pub(crate) images: usize,
    /// Their bytes as they counted themselves.
    pub(crate) image_bytes: u64,
    /// Kept front ends whose values went.
    pub(crate) fronts: usize,
    /// Values let go (MIR, constants, inference, weighed values).
    pub(crate) values: usize,
    /// Functions codegen's kept walks held.
    pub(crate) walked: usize,
    /// What the kept front ends' query storage held less after the give.
    pub(crate) query_bytes: u64,
    /// Running builds asked to give back at their next write.
    pub(crate) builds: usize,
}

/// The guard thread's question to the loop and the loop's answer: one rung at a time.
pub(crate) struct Channel {
    /// The rung asked, 0 for none.
    asked: AtomicU8,
    /// Each ask's number, and the number of the last one the loop answered.
    ask_seq: AtomicU64,
    done_seq: AtomicU64,
    /// What the loop's answers gave back since the last build took them, for that build's client.
    #[expect(clippy::disallowed_types, reason = "a few notes a ceiling event, taken once a build")]
    notes: blaze_core::lock::Lock<Vec<String>>,
    /// Running builds asked to give back and not yet done ([`Channel::asked_running`]).
    running: std::sync::atomic::AtomicUsize,
}

/// The daemon's one channel.
pub(crate) static CHANNEL: Channel = Channel::new();

impl Channel {
    #[expect(clippy::disallowed_types, reason = "makes the lock its field allows")]
    pub(crate) const fn new() -> Channel {
        Channel {
            asked: AtomicU8::new(0),
            ask_seq: AtomicU64::new(0),
            done_seq: AtomicU64::new(0),
            notes: blaze_core::lock::Lock::new("serve.relief.notes", Vec::new()),
            running: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// The guard asks `rung` of the loop: the ticket [`Channel::answered`] reaches once the
    /// loop answered it.
    pub(crate) fn ask(&self, rung: Rung) -> u64 {
        self.asked.store(rung as u8, Ordering::Release);
        self.ask_seq.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Whether the ask of ticket `ticket` was answered.
    pub(crate) fn answered(&self, ticket: u64) -> bool {
        self.done_seq.load(Ordering::Acquire) >= ticket
    }

    /// On the loop, once a turn: the rung asked and not answered yet, if any.
    pub(crate) fn pending(&self) -> Option<(u64, Rung)> {
        let seq = self.ask_seq.load(Ordering::Acquire);
        if seq <= self.done_seq.load(Ordering::Acquire) {
            return None;
        }
        Rung::of(self.asked.load(Ordering::Acquire)).map(|rung| (seq, rung))
    }

    /// On the loop: ticket `seq`'s rung was given, `given` of it.
    pub(crate) fn answer(&self, seq: u64, rung: Rung, given: Given) {
        if let Some(note) = note(rung, given) {
            self.notes.lock().push(note);
        }
        self.done_seq.fetch_max(seq, Ordering::AcqRel);
    }

    /// The guard measured the footprint under the ceiling again after `rungs`: said once.
    pub(crate) fn relieved(&self, rungs: &[Rung], footprint: u64, ceiling: u64) {
        let gib = |bytes: u64| bytes as f64 / f64::from(1u32 << 30);
        // alloc: once per ceiling event
        self.notes.lock().push(format!(
            "memory: blaze's footprint passed its ceiling of {:.2} GiB and is back at {:.2} GiB after it let go of \
             {}; what was let go is made again as builds read it",
            gib(ceiling),
            gib(footprint),
            rungs.iter().map(|it| it.name()).collect::<Vec<_>>().join(", then "),
        ));
    }

    /// Running builds were asked to give back at their next write (`Given::builds`).
    pub(crate) fn asked_running(&self, builds: usize) {
        self.running.fetch_add(builds, Ordering::AcqRel);
    }

    /// Running builds asked and not yet given back: what the guard waits for, at most
    /// [`RUNNING_WITHIN`], before it ends the daemon.
    pub(crate) fn running_pending(&self) -> usize {
        self.running.load(Ordering::Acquire)
    }

    /// A running build gave back `rung` of its front end at its write: `freed` bytes of query
    /// storage. Said to the client of the next build that ends.
    pub(crate) fn note_running(&self, rung: Rung, freed: u64) {
        let _ = self.running.fetch_update(Ordering::AcqRel, Ordering::Acquire, |it| it.checked_sub(1));
        let mib = freed as f64 / f64::from(1u32 << 20);
        // alloc: once per running build's give past the ceiling
        self.notes.lock().push(format!(
            "memory: past its ceiling, a running build let go of {} ({mib:.0} MiB of query storage); it is made \
             again from its memos when read",
            rung.name()
        ));
    }

    /// What the loop gave back since the last take, for a build's client to be told.
    pub(crate) fn take_notes(&self) -> Vec<String> {
        std::mem::take(&mut *self.notes.lock())
    }
}

/// What the client is told of one rung's give: none for a purge, which makes nothing again.
fn note(rung: Rung, given: Given) -> Option<String> {
    let mib = |bytes: u64| bytes as f64 / f64::from(1u32 << 20);
    match rung {
        Rung::Purge => None,
        Rung::Images if given.images > 0 => Some(format!(
            "memory: past its ceiling, blaze let go of {} kept linked images ({:.0} MiB); each is linked from scratch next",
            given.images,
            mib(given.image_bytes)
        )),
        Rung::Compiled | Rung::Values if given.fronts == 0 && given.builds > 0 => None,
        Rung::Compiled | Rung::Values if given.fronts > 0 => Some(format!(
            "memory: past its ceiling, blaze let go of {} of {} kept front ends ({} values, {} walked functions, \
             {:.0} MiB of query storage); they are made again from their memos when read",
            rung.name(),
            given.fronts,
            given.values,
            given.walked,
            mib(given.query_bytes),
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    /// The order: past the ceiling, each look asks the next rung, purge first, values last,
    /// and only the look after all four exits.
    #[test]
    fn rungs_are_given_in_order_and_exit_comes_only_after_all_of_them() {
        let mut ladder = Ladder::default();
        let over = |ladder: &mut Ladder| ladder.look(11 * GIB, 10 * GIB);
        assert_eq!(over(&mut ladder), Step::Give(Rung::Purge));
        assert_eq!(over(&mut ladder), Step::Give(Rung::Images));
        assert_eq!(over(&mut ladder), Step::Give(Rung::Compiled));
        assert_eq!(over(&mut ladder), Step::Give(Rung::Values));
        assert_eq!(ladder.given(), &Rung::ALL);
        assert_eq!(over(&mut ladder), Step::Exit, "still over after every rung: the daemon ends");
        assert_eq!(over(&mut ladder), Step::Exit);
    }

    /// A rung that brings the footprint under the ceiling stops the ladder there: no exit, no
    /// dearer rung, and the next overshoot starts again from the purge.
    #[test]
    fn a_rung_that_brings_the_footprint_under_ends_the_ladder_and_the_next_starts_over() {
        let mut ladder = Ladder::default();
        assert_eq!(ladder.look(11 * GIB, 10 * GIB), Step::Give(Rung::Purge));
        assert_eq!(ladder.look(11 * GIB, 10 * GIB), Step::Give(Rung::Images));
        assert_eq!(ladder.look(9 * GIB, 10 * GIB), Step::Under);
        assert!(ladder.given().is_empty());
        assert_eq!(ladder.look(10 * GIB, 10 * GIB), Step::Under, "at the ceiling is not past it");
        assert_eq!(ladder.look(12 * GIB, 10 * GIB), Step::Give(Rung::Purge));
    }

    /// The invariant over every sequence of six looks above or below: a rung is asked only past
    /// the ceiling, in order, once each since the last look under; exit only after all four.
    /// Control: a ladder that exits on the first look past the ceiling (the guard before this)
    /// is caught.
    #[test]
    fn over_any_run_of_looks_exit_follows_every_rung() {
        fn oracle(look: &dyn Fn(&mut Ladder, bool) -> Step) -> Option<String> {
            for run in 0..64u32 {
                let mut ladder = Ladder::default();
                let mut since_under: Vec<Rung> = Vec::new();
                for at in 0..6 {
                    let over = run >> at & 1 == 1;
                    let step = look(&mut ladder, over);
                    match (over, step) {
                        (false, Step::Under) => since_under.clear(),
                        (true, Step::Give(rung)) => {
                            if Some(&rung) != Rung::ALL.get(since_under.len()) {
                                return Some(format!("run {run}: gave {rung:?} after {since_under:?}"));
                            }
                            since_under.push(rung);
                        }
                        (true, Step::Exit) if since_under.len() == Rung::ALL.len() => {}
                        (over, step) => {
                            return Some(format!("run {run}: {step:?} at a look over={over} after {since_under:?}"));
                        }
                    }
                }
            }
            None
        }
        let real = |ladder: &mut Ladder, over: bool| ladder.look(if over { 2 } else { 1 }, 1);
        assert_eq!(oracle(&real), None);
        let exits_at_once = |_: &mut Ladder, over: bool| if over { Step::Exit } else { Step::Under };
        assert!(oracle(&exits_at_once).is_some(), "the control: exit at the first overshoot is caught");
    }

    /// The channel: an ask is pending on the loop until answered, its answer reaches the guard's
    /// ticket, and a give of images is told to the next build's client once.
    #[test]
    fn the_loop_answers_an_ask_and_the_client_is_told_what_went() {
        let channel = Channel::new();
        assert_eq!(channel.pending(), None);
        let ticket = channel.ask(Rung::Images);
        assert!(!channel.answered(ticket));
        let (seq, rung) = channel.pending().expect("asked");
        assert_eq!(rung, Rung::Images);
        channel.answer(seq, rung, Given { images: 3, image_bytes: 300 << 20, ..Given::default() });
        assert!(channel.answered(ticket));
        assert_eq!(channel.pending(), None);
        let notes = channel.take_notes();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("3 kept linked images") && notes[0].contains("300 MiB"), "{}", notes[0]);
        assert!(channel.take_notes().is_empty(), "told once");
        let ticket = channel.ask(Rung::Purge);
        let (seq, rung) = channel.pending().unwrap();
        channel.answer(seq, rung, Given::default());
        assert!(channel.answered(ticket));
        assert!(channel.take_notes().is_empty(), "a purge makes nothing again: nothing to tell");
    }

    /// A running build asked to give back is pending until its write gives back, and is then
    /// told to the next client; a give with no ask never goes below none.
    #[test]
    fn a_running_build_asked_is_pending_until_its_write_gives_back() {
        let channel = Channel::new();
        channel.asked_running(2);
        assert_eq!(channel.running_pending(), 2);
        channel.note_running(Rung::Compiled, 64 << 20);
        assert_eq!(channel.running_pending(), 1);
        channel.note_running(Rung::Compiled, 0);
        channel.note_running(Rung::Compiled, 0);
        assert_eq!(channel.running_pending(), 0, "never below none");
        let notes = channel.take_notes();
        assert_eq!(notes.len(), 3);
        assert!(notes[0].contains("64 MiB"), "{}", notes[0]);
    }
}
