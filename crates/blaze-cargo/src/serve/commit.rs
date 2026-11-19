//! Windows' private commit is the process charge, not its working set. The guard lasts
//! exactly as long as the engine's state lock, including a host serving in process. No
//! worker or allocator asks the guard for admission.

use std::{sync::mpsc, thread, time::Duration};

use anyhow::Context as _;
use blaze_core::exit::Exit;

pub(super) const VAR: &str = "BLAZE_DAEMON_MEMORY_GB";

pub(super) struct Guard {
    quit: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<()>>,
}

fn limit(value: &str) -> anyhow::Result<u64> {
    let bytes = value.trim().parse::<f64>().unwrap_or(f64::NAN) * (1u64 << 30) as f64;
    anyhow::ensure!((1.0..u64::MAX as f64).contains(&bytes), "{VAR} {value:?}: expected a positive limit in GiB");
    Ok(bytes as u64)
}

impl Guard {
    pub(super) fn arm() -> anyhow::Result<Self> {
        let used = crate::raw::memory::own_footprint_now().context("reading the engine's private commit")?;
        // Keep room for the system as well as this process. The effective page-file
        // availability is already constrained by an enclosing Windows job, if any.
        let available = blaze_mem::address_capacity()?.available_commit;
        let ceiling = used.saturating_add(available - available.div_ceil(8));
        let ceiling = match std::env::var(VAR) {
            Ok(text) => ceiling.min(limit(&text)?),
            Err(std::env::VarError::NotPresent) => ceiling,
            Err(error) => anyhow::bail!("{VAR}: {error}"),
        };
        let (quit, stop) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("blaze-commit-guard".into())
            .spawn(move || guard(ceiling, &stop, &super::relief::CHANNEL))
            .context("starting the private commit guard")?;
        Ok(Self { quit, worker: Some(worker) })
    }
}

/// The guard's loop: every 100 ms a reading of the private commit; past the ceiling, the next
/// rung of [`super::relief::Ladder`] (a purge on this thread, the rest asked of the daemon's
/// loop and waited for at most [`super::relief::ANSWER_WITHIN`], then a purge so what they
/// freed leaves the commit), and the daemon ends only once every rung was given and the
/// commit is still past the ceiling. A reading the system refuses ends it at once: nothing
/// can then say the ceiling holds.
fn guard(ceiling: u64, stop: &mpsc::Receiver<()>, channel: &super::relief::Channel) {
    use super::{pulse::CeilingLook, relief::{Ladder, Rung, Step}};
    let mut ladder = Ladder::default();
    let mut watch = super::pulse::CeilingWatch::default();
    // Whether this overshoot already waited for running builds' releases before its exit.
    let mut waited_running = false;
    loop {
        let Some(bytes) = crate::raw::memory::own_footprint_now() else {
            super::said::logged!(ERROR, "blaze serve: pid {} stopped: its private commit could not be read, so no memory ceiling holds", std::process::id());
            std::process::exit(Exit::MemoryCeiling.code());
        };
        let was = ladder.given();
        match ladder.look(bytes, ceiling) {
            Step::Under => {
                waited_running = false;
                if !was.is_empty() {
                    super::said::logged!(WARN, "blaze serve: private commit {bytes} bytes, back under its limit of {ceiling} after giving back {was:?}");
                    channel.relieved(was, bytes, ceiling);
                }
                if matches!(watch.look(bytes, ceiling), CeilingLook::Near | CeilingLook::Eased) {
                    super::said::logged!(WARN, "blaze serve: private commit {bytes} bytes, limit {ceiling} bytes");
                }
            }
            Step::Give(rung) => {
                super::said::logged!(WARN, "blaze serve: private commit {bytes} bytes past its limit of {ceiling}: giving back {}", rung.name());
                if rung != Rung::Purge {
                    let ticket = channel.ask(rung);
                    let deadline = std::time::Instant::now() + super::relief::ANSWER_WITHIN;
                    while !channel.answered(ticket) && std::time::Instant::now() < deadline {
                        if stop.recv_timeout(Duration::from_millis(10)) != Err(mpsc::RecvTimeoutError::Timeout) {
                            return;
                        }
                    }
                    if !channel.answered(ticket) {
                        super::said::logged!(WARN, "blaze serve: the loop did not give back {} within {:?}: measuring anyway", rung.name(), super::relief::ANSWER_WITHIN);
                    }
                }
                crate::raw::memory::purge();
                // Measured again at once: the next look is the next rung or the end.
                continue;
            }
            Step::Exit if !waited_running && channel.running_pending() > 0 => {
                // Running builds were asked to give back at their next write: their readers
                // end first. Wait for them, bounded, then look once more.
                waited_running = true;
                super::said::logged!(WARN, "blaze serve: private commit {bytes} bytes past its limit of {ceiling} after every rung: waiting at most {:?} for {} running builds to give back", super::relief::RUNNING_WITHIN, channel.running_pending());
                let deadline = std::time::Instant::now() + super::relief::RUNNING_WITHIN;
                while channel.running_pending() > 0 && std::time::Instant::now() < deadline {
                    if stop.recv_timeout(Duration::from_millis(50)) != Err(mpsc::RecvTimeoutError::Timeout) {
                        return;
                    }
                }
                crate::raw::memory::purge();
                continue;
            }
            Step::Exit => {
                super::said::logged!(ERROR, "blaze serve: pid {} stopped at its memory ceiling: private commit {bytes} bytes, limit {ceiling} bytes, after giving back every rung ({:?})", std::process::id(), Rung::ALL);
                super::daemon::log_memory(&blaze_mem::tag::snapshot());
                std::process::exit(Exit::MemoryCeiling.code());
            }
        }
        if stop.recv_timeout(Duration::from_millis(100)) != Err(mpsc::RecvTimeoutError::Timeout) {
            break;
        }
    }
}

/// The front-end tags whose weighed (`lru`) query values are kept under a byte cap on Windows.
const VALUE_TAGS: [blaze_mem::Tag; 4] =
    [blaze_mem::Tag::Parse, blaze_mem::Tag::Nameres, blaze_mem::Tag::Expand, blaze_mem::Tag::Infer];

/// Each [`VALUE_TAGS`] tag's cap on its weighed values for a machine of `physical` bytes: a
/// thirty-second of it, at least 256 MiB. On a 32 GB machine 1 GiB a tag.
pub(super) fn value_budget(physical: u64) -> u64 {
    (physical / 32).max(256 << 20)
}

/// Caps the weighed query values of the front-end tags ([`value_budget`]): with no cap (none
/// set since admission's budgets went, 2026-11-13) a storage keeps every parse tree, body,
/// source map and expansion of every crate a build touched, and its values grow with the
/// workspace; under one, each view boundary lets go of the least recently verified past it,
/// made again from their memos when read. Windows only, where every committed byte is charged:
/// the other systems keep what they did. A cap set already (a test's) is kept.
pub(super) fn set_value_budgets() -> anyhow::Result<()> {
    let physical = blaze_mem::address_capacity()?.physical;
    let each = value_budget(physical);
    // `mir`'s values are let go only when asked: its cap is read by a write mid-build
    // (`unit::release_mir_past_cap`), never by the storage's passes.
    for tag in VALUE_TAGS.into_iter().chain([blaze_mem::Tag::Mir]) {
        if blaze_mem::tag::budget(tag) == u64::MAX {
            blaze_mem::tag::set_budget(tag, each);
        }
    }
    Ok(())
}

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.quit.send(());
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_machines_value_budget_is_a_thirty_second_of_it_with_a_floor() {
        assert_eq!(value_budget(32 << 30), 1 << 30, "a 32 GiB machine caps each tag at 1 GiB");
        assert_eq!(value_budget(4 << 30), 256 << 20, "the floor holds on a small machine");
    }

    /// The "still over" exit: a guard armed below what the process already commits gives back
    /// every rung (no loop answers here, so each waits its bound), measures it still over, and
    /// only then ends the process with 77, saying every rung was tried.
    #[test]
    fn an_engine_over_its_commit_limit_stops_even_if_the_loop_is_stuck() {
        const CHILD: &str = "BLAZE_TEST_COMMIT_GUARD";
        if std::env::var_os(CHILD).is_some() {
            let _guard = Guard::arm().unwrap();
            thread::park_timeout(Duration::from_secs(60));
            panic!("a guard armed below this process's existing private commit did not stop it");
        }
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "serve::commit::tests::an_engine_over_its_commit_limit_stops_even_if_the_loop_is_stuck", "--nocapture"])
            .env(CHILD, "1").env(VAR, "0.000001").output().unwrap();
        assert_eq!(result.status.code(), Some(Exit::MemoryCeiling.code()));
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(stderr.contains("private commit"), "{stderr}");
        assert!(stderr.contains("after giving back every rung"), "exit only after the ladder: {stderr}");
        for rung in super::super::relief::Rung::ALL {
            assert!(stderr.contains(rung.name()), "rung {rung:?} was tried before the exit: {stderr}");
        }
    }

    /// A loop that answers: the guard asks it each of the loop's rungs in order (images, then
    /// compiled code, then values), each answered within the bound, and exits only after the
    /// last, still over. The child's "loop" records each rung it is asked into stderr.
    #[test]
    fn the_guard_asks_an_answering_loop_for_each_rung_in_order_before_it_exits() {
        use super::super::relief::{CHANNEL, Given};
        const CHILD: &str = "BLAZE_TEST_COMMIT_GUARD_LOOP";
        if std::env::var_os(CHILD).is_some() {
            thread::spawn(|| loop {
                if let Some((seq, rung)) = CHANNEL.pending() {
                    eprintln!("loop asked: {rung:?}");
                    CHANNEL.answer(seq, rung, Given::default());
                }
                thread::sleep(Duration::from_millis(5));
            });
            let _guard = Guard::arm().unwrap();
            thread::park_timeout(Duration::from_secs(60));
            panic!("the guard did not stop the process");
        }
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "serve::commit::tests::the_guard_asks_an_answering_loop_for_each_rung_in_order_before_it_exits", "--nocapture"])
            .env(CHILD, "1").env(VAR, "0.000001").output().unwrap();
        assert_eq!(result.status.code(), Some(Exit::MemoryCeiling.code()));
        let stderr = String::from_utf8_lossy(&result.stderr);
        let at = |what: &str| stderr.find(what).unwrap_or_else(|| panic!("no `{what}` in: {stderr}"));
        assert!(at("loop asked: Images") < at("loop asked: Compiled"), "{stderr}");
        assert!(at("loop asked: Compiled") < at("loop asked: Values"), "{stderr}");
        assert!(at("loop asked: Values") < at("after giving back every rung"), "{stderr}");
        assert!(!stderr.contains("measuring anyway"), "an answering loop is never passed over: {stderr}");
    }
}
