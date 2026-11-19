//! Memory pressure on Windows ([`crate::Effect::Pressure`]): what the daemon is told when memory
//! is short, so it holds admission at what it holds, asks its front ends for a release and
//! purges, before any process of the machine is refused memory (docs/memory-budget.md,
//! section 7, "Pressure").
//!
//! Windows refuses memory by commit, not by what is resident: every process's committed pages
//! count against one commit limit (RAM plus the page files), and an allocation past it fails
//! whatever is free. A machine whose builds share that limit runs out of commit long before RAM:
//! on 2026-11-14 a desktop build stopped with 1.3 GiB of commit left on a machine of 93 GB. So
//! the watch says pressure when the commit left is short ([`pressed`]), and also when the
//! memory manager says physical memory is low (`LowMemoryResourceNotification`), which is what
//! macOS's warning and Linux's PSI stand for.
//!
//! Neither has an event of its own to wait on that a completion port can carry, so a thread of
//! the watch's looks every [`LOOK`] and posts the watch's tag to the driver's port
//! ([`super::sys::KEY_PRESSURE`]) while either holds, at most once a [`TELL_EVERY`]: as a PSI
//! trigger fires each window memory stays short.


use std::{
    io,
    os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use windows_sys::Win32::System::{
    Memory::{CreateMemoryResourceNotification, LowMemoryResourceNotification, QueryMemoryResourceNotification},
    SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX},
};

use crate::{
    Tag,
    wait::{Clock as _, Deadline, Monotonic, Parker},
};

/// How often the watch looks at the machine's commit.
pub(super) const LOOK: Duration = Duration::from_millis(250);

/// The least time between two tellings while memory stays short.
pub(super) const TELL_EVERY: Duration = Duration::from_secs(1);

/// The least commit left under which the machine is pressed, whatever its limit.
const PRESSED_LEAST: u64 = 4 << 30;

/// The least commit left under which it is critically pressed.
const CRITICAL_LEAST: u64 = 2 << 30;

/// The machine's commit at one look, in bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct Commit {
    /// What every process may commit in all: RAM and the page files.
    pub limit: u64,
    /// What every process has committed.
    pub total: u64,
}

/// Whether memory is short at one look, and whether critically: the commit left under a
/// sixteenth of the limit (at least 4 GiB) is pressure, under a thirty-second (at least 2 GiB)
/// critical; low physical memory as the memory manager says it is pressure.
pub(super) fn pressed(commit: Commit, low_physical: bool) -> Option<bool> {
    let left = commit.limit.saturating_sub(commit.total);
    if left < (commit.limit / 32).max(CRITICAL_LEAST) {
        return Some(true);
    }
    (left < (commit.limit / 16).max(PRESSED_LEAST) || low_physical).then_some(false)
}

/// The machine's commit now: `GlobalMemoryStatusEx`'s page file is the commit limit, its
/// available bytes what is left of it.
#[allow(unsafe_code, reason = "GlobalMemoryStatusEx writes a record of integers")]
pub(super) fn commit_now() -> io::Result<Commit> {
    // SAFETY: all zeros is a valid record of integers, whose length is set as the call asks.
    let mut status: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    status.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
    // SAFETY: a live record of the length the call is told.
    if unsafe { GlobalMemoryStatusEx(&mut status) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Commit { limit: status.ullTotalPageFile, total: status.ullTotalPageFile.saturating_sub(status.ullAvailPageFile) })
}

/// One watch of memory pressure: its thread, stopped as it is dropped.
pub(super) struct Watch {
    shared: Arc<Shared>,
    thread: Option<std::thread::JoinHandle<()>>,
}

struct Shared {
    stop: AtomicBool,
    parker: Parker,
}

impl Watch {
    /// The watch of `tag`, its thread posting to `port`.
    #[allow(unsafe_code, reason = "CreateMemoryResourceNotification hands back a handle to own")]
    pub(super) fn start(port: Arc<super::sys::Port>, tag: Tag) -> io::Result<Watch> {
        // SAFETY: no pointers; a null handle is its failure.
        let low = unsafe { CreateMemoryResourceNotification(LowMemoryResourceNotification) };
        if low.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a handle the call just made, owned here alone.
        let low = unsafe { OwnedHandle::from_raw_handle(low) };
        commit_now()?;
        // alloc: setup, once per watch.
        let shared = Arc::new(Shared { stop: AtomicBool::new(false), parker: Parker::new() });
        let theirs = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            // alloc: setup, once per watch.
            .name("blaze-pressure".to_owned())
            .spawn(move || watch(&theirs, &low, &port, tag))?;
        Ok(Watch { shared, thread: Some(thread) })
    }
}

/// The watch's thread: a look each [`LOOK`], a telling while memory is short.
#[allow(unsafe_code, reason = "QueryMemoryResourceNotification writes one BOOL")]
fn watch(shared: &Shared, low: &OwnedHandle, port: &super::sys::Port, tag: Tag) {
    let clock = Monotonic::new();
    let mut told: Option<Duration> = None;
    loop {
        if shared.stop.load(Ordering::Acquire) {
            return;
        }
        let mut state = 0;
        // SAFETY: the watch's own notification handle, open for its life, and one BOOL.
        let low_physical = unsafe { QueryMemoryResourceNotification(low.as_raw_handle(), &mut state) } != 0 && state != 0;
        // A look that cannot read the commit says nothing: the next looks again.
        let now = clock.now();
        if let Ok(commit) = commit_now()
            && let Some(critical) = pressed(commit, low_physical)
            && told.is_none_or(|at| now.saturating_sub(at) >= TELL_EVERY)
        {
            told = Some(now);
            if port.post(super::sys::KEY_PRESSURE, u32::from(critical), tag.0 as usize).is_err() {
                return;
            }
        }
        let next = Deadline::after(clock.now(), LOOK);
        if shared.parker.park("the machine's commit and memory, looked at again", Some(next), &clock).is_err() {
            return;
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        self.shared.parker.unpark();
        // The thread parks for a look at most, and sees the stop as it wakes.
        if let Some(thread) = self.thread.take() {
            _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Commit, pressed};

    const GIB: u64 = 1 << 30;

    /// The invariant: pressure is the commit left under a sixteenth of the limit (at least 4
    /// GiB), critical under a thirty-second (at least 2 GiB), or low physical memory; plenty of
    /// commit left with physical memory not low is none.
    #[test]
    fn pressure_is_the_commit_left_short_or_low_physical_memory() {
        let machine = |left: u64| Commit { limit: 173 * GIB, total: 173 * GIB - left };
        assert_eq!(pressed(machine(60 * GIB), false), None);
        assert_eq!(pressed(machine(60 * GIB), true), Some(false));
        assert_eq!(pressed(machine(10 * GIB), false), Some(false), "under 173/16 GiB");
        assert_eq!(pressed(machine(5 * GIB), false), Some(true), "under 173/32 GiB");
        let small = |left: u64| Commit { limit: 16 * GIB, total: 16 * GIB - left };
        assert_eq!(pressed(small(5 * GIB), false), None);
        assert_eq!(pressed(small(3 * GIB), false), Some(false), "under the 4 GiB floor");
        assert_eq!(pressed(small(GIB), false), Some(true), "under the 2 GiB floor");
        assert_eq!(pressed(Commit { limit: GIB, total: 2 * GIB }, false), Some(true), "past the limit");
    }

    /// The machine's commit reads, and is within its limit.
    #[test]
    fn the_machine_says_its_commit() {
        let commit = super::commit_now().expect("the machine's commit");
        assert!(commit.limit > 0 && commit.total > 0 && commit.total <= commit.limit + commit.limit / 8, "{commit:?}");
    }
}
