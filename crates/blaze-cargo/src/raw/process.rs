//! Processes: whether one runs, how a child ended, ending a worker's process group, the
//! action of `SIGPIPE`, the CPU time used, and on Windows the handles a child inherits. std
//! has none of these: each is the one system call that does it.

#[cfg(any(unix, windows))]
use std::time::Duration;

/// Whether the process `pid` runs: one this process may not signal (`EPERM`, another user's)
/// runs too; only `ESRCH` says it does not (review round 5, L3).
#[cfg(unix)]
pub fn alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else { return false };
    // SAFETY: `kill` takes no pointer, so no memory of this process is at stake whatever `pid`
    // is, and a signal of 0 is delivered to nothing: it only asks whether `pid` may be sent one.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// When the process `pid` started, in the unit the machine's memory ledger keeps
/// (`blaze_graph::ledger::Process::start`), so that a pid the system gave again is told from
/// the process that had it: field 22 of `/proc/<pid>/stat`, clock ticks after boot. `None` when
/// no process has `pid`, or only a zombie (it holds no memory).
#[cfg(target_os = "linux")]
pub fn started(pid: u32) -> std::io::Result<Option<u64>> {
    // alloc: a path, once a pid a ledger turn asks of
    let path = format!("/proc/{pid}/stat");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ESRCH) =>
        {
            return Ok(None);
        }
        Err(error) => {
            // alloc: the error's message
            return Err(std::io::Error::new(error.kind(), format!("{path}: {error}")));
        }
    };
    // Field 2, the command, is in parentheses and may hold any byte, `)` and spaces too: the
    // fields after it start after its last `)`, field 3 (the state) first, field 22 the 20th.
    let mut fields = text.rfind(')').map(|at| text[at + 1..].split_ascii_whitespace());
    let state = fields.as_mut().and_then(Iterator::next);
    let start = fields.as_mut().and_then(|it| it.nth(18)).and_then(|it| it.parse::<u64>().ok());
    match (state, start) {
        (Some("Z" | "X"), _) => Ok(None),
        (Some(_), Some(start)) => Ok(Some(start)),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            // alloc: the error's message
            format!("{path}: no start time in field 22 of `{}`", text.trim_end()),
        )),
    }
}

/// When the process `pid` started, in the unit the machine's memory ledger keeps
/// (`blaze_graph::ledger::Process::start`), so that a pid the system gave again is told from
/// the process that had it: `proc_pidinfo`'s `PROC_PIDTBSDINFO`, microseconds since the
/// epoch. `None` when no process has `pid`, only a zombie does, or another user's process does
/// (`EPERM`: then it is not the daemon of this user that had it).
#[cfg(target_os = "macos")]
#[allow(clippy::cast_possible_wrap, reason = "the size of a small C struct")]
pub fn started(pid: u32) -> std::io::Result<Option<u64>> {
    let Ok(pid) = libc::c_int::try_from(pid) else { return Ok(None) };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: `proc_bsdinfo` is a C struct of integers and byte arrays, for which all-zero
    // bytes is a valid value.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a live local of `size` bytes that the call writes and does not keep.
    let got =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size) };
    if got == size {
        return Ok(Some(info.pbi_start_tvsec.saturating_mul(1_000_000) + info.pbi_start_tvusec));
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH | libc::EPERM) => Ok(None),
        _ => Err(std::io::Error::new(
            error.kind(),
            // alloc: the error's message
            format!(
                "proc_pidinfo(PROC_PIDTBSDINFO) of pid {pid} gave {got} of {size} bytes: {error}"
            ),
        )),
    }
}

/// Where blaze reads no process's start time: an error naming it, never a guess.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub fn started(pid: u32) -> std::io::Result<Option<u64>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        // alloc: the error's message
        format!(
            "blaze reads when a process (pid {pid}) started only on Linux and macOS, not {}",
            std::env::consts::OS
        ),
    ))
}

/// Waits at most `long` for `fd` to be readable, or closed at its other end: whether it is.
/// The wait is one deadline on a clock made here, so an interrupted or early return waits only
/// for what is left of `long` (`blaze_core::wait`).
#[cfg(unix)]
pub fn readable_within(fd: std::os::fd::BorrowedFd<'_>, long: Duration) -> std::io::Result<bool> {
    use std::os::fd::AsRawFd as _;

    use blaze_core::wait::{self, Clock as _, Deadline, Monotonic, Waited};
    let clock = Monotonic::new();
    let deadline = Deadline::after(clock.now(), long);
    let mut watched = [libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 }];
    match wait::readable("a descriptor to be readable", &mut watched, Some(deadline), &clock) {
        Ok(Waited::Ready(_)) => Ok(true),
        Ok(Waited::Deadline) => Ok(false),
        Err(error) => Err(std::io::Error::other(error)),
    }
}

/// Waits at most `long` for the process `pid` to end, on the kernel's word that it did (a
/// pidfd), not by asking again and again: whether it ended. Any process this one may see is
/// waited for, not only a child; one that is gone, or ended and not yet waited for by its
/// parent, has ended.
#[cfg(target_os = "linux")]
pub fn ended_within(pid: u32, long: Duration) -> std::io::Result<bool> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

    use blaze_core::wait::{self, Clock as _, Deadline, Monotonic, Waited};
    let Ok(pid) = libc::pid_t::try_from(pid) else { return Ok(true) };
    // SAFETY: pidfd_open takes a number and flags and reads no memory of this process; the
    // descriptor it gives is owned below.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ESRCH) { Ok(true) } else { Err(error) };
    }
    // SAFETY: the descriptor just opened, which nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) };
    // A pidfd is readable once its process has ended: a poll of it on this thread's wait ring.
    let clock = Monotonic::new();
    let deadline = Deadline::after(clock.now(), long);
    match wait::pollable(
        "a process to end (its pidfd)",
        fd.as_raw_fd(),
        libc::POLLIN,
        Some(deadline),
        &clock,
    ) {
        Ok(Waited::Ready(_)) => Ok(true),
        Ok(Waited::Deadline) => Ok(false),
        Err(error) => Err(std::io::Error::other(error)),
    }
}

/// Waits at most `long` for the process `pid` to end, on the kernel's word that it did
/// (kqueue's `EVFILT_PROC`), not by asking again and again: whether it ended. Any process this
/// one may see is waited for, not only a child; one that is gone has ended.
#[cfg(all(unix, not(target_os = "linux")))]
pub fn ended_within(pid: u32, long: Duration) -> std::io::Result<bool> {
    use std::os::fd::{AsFd as _, AsRawFd as _, FromRawFd as _, OwnedFd};
    let Ok(pid) = usize::try_from(pid) else { return Ok(true) };
    // SAFETY: takes nothing and reads no memory of this process; the descriptor it gives is
    // owned below.
    let queue = unsafe { libc::kqueue() };
    if queue < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the descriptor just opened, which nothing else owns.
    let queue = unsafe { OwnedFd::from_raw_fd(queue) };
    // SAFETY: all zeros is a `kevent` of nothing, its fields then set.
    let mut change: libc::kevent = unsafe { std::mem::zeroed() };
    change.ident = pid;
    change.filter = libc::EVFILT_PROC;
    change.flags = libc::EV_ADD | libc::EV_ONESHOT;
    change.fflags = libc::NOTE_EXIT;
    // SAFETY: registers the one live `change`, read only, and asks for no event back: a null
    // list of none and no timeout are allowed.
    #[expect(
        clippy::disallowed_methods,
        reason = "registers a change only: with no event list kevent returns at once and does not wait (rule deadline-waits)"
    )]
    let registered = unsafe {
        libc::kevent(queue.as_raw_fd(), &change, 1, std::ptr::null_mut(), 0, std::ptr::null())
    };
    if registered < 0 {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ESRCH) { Ok(true) } else { Err(error) };
    }
    // A kqueue is readable once an event it watches has come.
    readable_within(queue.as_fd(), long)
}

/// Waits at most `long` for the process `pid` to end, on the kernel's word that it did (its
/// process handle signalled), not by asking again and again: whether it ended. Any process this
/// one may open is waited for, not only a child; one that is gone has ended.
#[cfg(windows)]
pub fn ended_within(pid: u32, long: Duration) -> std::io::Result<bool> {
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use windows_sys::Win32::{
        Foundation::{ERROR_INVALID_PARAMETER, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::Threading::{INFINITE, OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject},
    };
    // SAFETY: `OpenProcess` takes no pointer; any `pid` is either opened or refused with null.
    // The handle it opens is owned below, so it is closed once.
    let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if process.is_null() {
        let error = std::io::Error::last_os_error();
        // No process has the pid (and no handle holds one that had it): it ended.
        let gone = error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32);
        return if gone { Ok(true) } else { Err(error) };
    }
    // SAFETY: `process` is an open handle that nothing else owns: `OpenProcess` just made it.
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    // Rounded up, and short of `INFINITE`: a wait of less than a millisecond left is one.
    let ms =
        u32::try_from(long.as_micros().div_ceil(1000)).unwrap_or(INFINITE - 1).min(INFINITE - 1);
    // SAFETY: the handle is open for as long as `process` lives, which outlives the call.
    match unsafe { WaitForSingleObject(process.as_raw_handle(), ms) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => Err(std::io::Error::last_os_error()),
    }
}

/// `command` run to its end as `blaze run` runs a program on Windows, where no process can
/// become another (cargo's `exec_replace`): started suspended, put in a job object of its own
/// that ends every process still in it when this one ends (`KILL_ON_JOB_CLOSE`, so a program
/// and what it started never outlive a `blaze run` that was killed; one that asks to leave the
/// job may, `BREAKAWAY_OK`), then resumed and waited for. Started suspended, nothing it starts
/// runs before it is in the job. Meanwhile this process ignores the console's Ctrl-C and
/// Ctrl-Break: the program, on the same console, gets them and answers them itself, and the
/// command ends with the code it ends with.
#[cfg(windows)]
pub fn run_held(command: &mut std::process::Command) -> std::io::Result<std::process::ExitStatus> {
    use std::os::windows::{
        io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
        process::{ChildExt as _, CommandExt as _},
    };
    use windows_sys::{
        Win32::System::{
            Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler},
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JobObjectExtendedLimitInformation, SetInformationJobObject,
            },
            Threading::{CREATE_SUSPENDED, ResumeThread},
        },
        core::BOOL,
    };
    unsafe extern "system" fn interrupted(event: u32) -> BOOL {
        BOOL::from(event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT)
    }
    // SAFETY: no attributes and no name: the call reads no memory of this process. The handle
    // it makes is owned below, so it is closed once, as this process ends at the latest.
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: as above: `CreateJobObjectW` just made it, and nothing else owns it.
    let job = unsafe { OwnedHandle::from_raw_handle(job) };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK;
    // SAFETY: `limits` is a live local of the size the call is told, read and not kept.
    if unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `interrupted` is a function for the life of the process, as the handler must be.
    if unsafe { SetConsoleCtrlHandler(Some(interrupted), 1) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut child = command.creation_flags(CREATE_SUSPENDED).spawn()?;
    // SAFETY: both handles are open while `job` and `child` live, across the call.
    let held = unsafe { AssignProcessToJobObject(job.as_raw_handle(), child.as_raw_handle()) };
    // SAFETY: as above, the child's main thread, suspended once by its creation.
    if held == 0 || unsafe { ResumeThread(child.main_thread_handle().as_raw_handle()) } == u32::MAX
    {
        let error = std::io::Error::last_os_error();
        // It never ran: ended where it stands, and its exit waited for so nothing outlives it.
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    child.wait()
}
/// Waits for the child `pid` to exit without reaping it (`waitid` with `WNOWAIT`), so its
/// `std::process::Child` still waits for it and its pid is no other process's until then: a
/// test executable's exit, waited for apart from its output (`cli::live`). A `pid` that is no
/// child of this process (one already reaped) is refused with `ECHILD`. On Linux the wait is
/// `IORING_OP_WAITID` on this thread's wait ring.
#[cfg(target_os = "linux")]
pub fn wait_exited(pid: u32) -> std::io::Result<()> {
    let clock = blaze_core::wait::Monotonic::new();
    let pid =
        libc::pid_t::try_from(pid).map_err(|_| std::io::Error::from_raw_os_error(libc::ECHILD))?;
    // wakes: the kernel, at the test executable's exit (`waitid`): the pid is this process's child
    match blaze_core::wait::exited("a test executable's exit", pid, None, &clock) {
        Ok(_) => Ok(()),
        Err(error) => Err(std::io::Error::from(error)),
    }
}

/// As on Linux, with a blocking `waitid`.
#[cfg(all(unix, not(target_os = "linux")))]
pub fn wait_exited(pid: u32) -> std::io::Result<()> {
    loop {
        // SAFETY: `siginfo_t` is a C struct of integers and unions of them, for which all-zero
        // bytes is a valid value.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is a live local the call writes and does not keep; `waitid` takes no
        // other pointer, and `WNOWAIT` changes nothing of the child it waits for.
        if unsafe {
            libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT)
        } == 0
        {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Waits for the process `pid` to exit. A child's pid is no other process's while its
/// `std::process::Child` holds its handle, which the caller's does until it waited.
#[cfg(windows)]
pub fn wait_exited(pid: u32) -> std::io::Result<()> {
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use windows_sys::Win32::{
        Foundation::WAIT_OBJECT_0,
        System::Threading::{INFINITE, OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject},
    };
    // SAFETY: `OpenProcess` takes no pointer; any `pid` is either opened or refused with null.
    // The handle it opens is owned below, so it is closed once.
    let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if process.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `process` is an open handle that nothing else owns: `OpenProcess` just made it.
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    // SAFETY: the handle is open for as long as `process` lives, which outlives the call.
    #[expect(
        clippy::disallowed_methods,
        reason = "a child's exit has no deadline and `blaze_core::wait` has no handle wait yet: child waits move to the driver in deadline-waits step 5 (docs/v2/plan/design/deadline-waits.md)"
    )]
    let ended = unsafe { WaitForSingleObject(process.as_raw_handle(), INFINITE) };
    match ended {
        WAIT_OBJECT_0 => Ok(()),
        _ => Err(std::io::Error::last_os_error()),
    }
}

#[cfg(not(any(unix, windows)))]
pub fn wait_exited(pid: u32) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!("waiting for process {pid} to exit is not built for this platform"),
    ))
}

/// How a child of this process ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reaped {
    Code(i32),
    Signal(i32),
}

/// How `pid` ended, waited for, when it is a child of this process that ended; `None` when
/// it runs, or is no child of this one (whose end only its parent hears).
#[cfg(unix)]
pub fn reap(pid: u32) -> Option<Reaped> {
    let pid = libc::pid_t::try_from(pid).ok()?;
    let mut status = 0;
    // SAFETY: `status` is live for the call to write. `WNOHANG` returns at once; a `pid` that
    // is no child of this process is refused (`ECHILD`) and touches nothing. A child waited
    // for here is one no `std::process::Child` of this process waits for again: the one the
    // CLI starts the daemon as is dropped once spawned.
    if unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } != pid {
        return None;
    }
    Some(match libc::WIFSIGNALED(status) {
        true => Reaped::Signal(libc::WTERMSIG(status)),
        false => Reaped::Code(libc::WEXITSTATUS(status)),
    })
}

/// Whether the process `pid` runs.
#[cfg(windows)]
pub fn alive(pid: u32) -> bool {
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use windows_sys::Win32::{
        Foundation::{ERROR_ACCESS_DENIED, GetLastError, WAIT_TIMEOUT},
        System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject},
    };
    // SAFETY: `OpenProcess` takes no pointer; any `pid` is either opened or refused with null.
    // The handle it opens is owned below, so it is closed once.
    let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if process.is_null() {
        // One this process may not open (another user's) runs; any other refusal says it does
        // not (review round 5, L3).
        // SAFETY: reads this thread's last error, set by the `OpenProcess` just above.
        return unsafe { GetLastError() } == ERROR_ACCESS_DENIED;
    }
    // SAFETY: `process` is an open handle that nothing else owns: `OpenProcess` just made it.
    // Were it owned twice, it would be closed twice, the second time maybe another's handle.
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    // SAFETY: the handle is open for as long as `process` lives, which outlives the call; a
    // wait of no time only asks whether the process ended.
    #[expect(
        clippy::disallowed_methods,
        reason = "a timeout of 0 asks whether the process ended and never blocks, so no deadline applies (rule deadline-waits)"
    )]
    let ended = unsafe { WaitForSingleObject(process.as_raw_handle(), 0) };
    ended == WAIT_TIMEOUT
}

#[cfg(not(any(unix, windows)))]
pub fn alive(_: u32) -> bool {
    false
}

/// Ends the process group `child` leads (a worker started in a group of its own, with the
/// processes it started), while `child` has not exited: one that has exited has nothing to
/// kill, and once it is waited for its pid may be another's.
#[cfg(unix)]
pub fn kill_group(child: &mut std::process::Child) {
    if let (Ok(None), Ok(group)) = (child.try_wait(), libc::pid_t::try_from(child.id())) {
        // SAFETY: `killpg` takes no pointer, so no memory of this process is at stake. That
        // the group is the worker's is upheld by `child` not having been waited for, checked
        // just above: until it is, its pid is not given to another process.
        unsafe { libc::killpg(group, libc::SIGKILL) };
    }
}

/// Sends SIGINT to this process's own process group, as a terminal's Ctrl-C does: what the
/// live view does when raw mode made Ctrl-C a key (`cli/live.rs`), so the test executables
/// it runs, which share the group, end as they would have. The daemon runs in a group of its
/// own and is not reached.
#[cfg(unix)]
pub fn interrupt_own_group() {
    // SAFETY: `kill` takes no pointer, so no memory of this process is at stake; pid 0 is
    // this process's own group, and this process's SIGINT handler (`serve::signals::catch`)
    // only sets a flag.
    unsafe { libc::kill(0, libc::SIGINT) };
}

/// Off unix nothing is sent: a console in raw mode delivers Ctrl-C to no process, so the test
/// executables under way are not interrupted by it.
#[cfg(not(unix))]
pub fn interrupt_own_group() {}

/// Has a write to a pipe whose reader is gone end the process quietly, as `SIGPIPE`'s
/// default action does, where std ignores the signal so that the write fails with `EPIPE`.
/// Not for a process that writes to sockets: a reset from the other end would end it.
#[cfg(unix)]
pub fn die_on_closed_pipe() {
    // SAFETY: `signal` with `SIG_DFL` installs no handler of this process's, so no code of it
    // ever runs in a signal's context, and it is one atomic change to the process, sound from
    // any thread. What it changes is how a later write to a closed pipe ends: the process ends,
    // which is no undefined behavior.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
}

/// Has the process `command` starts inherit `fd` under its own number: it is cleared of
/// close-on-exec in the child alone, so no other process this one starts gets it.
#[cfg(unix)]
pub fn inherit_in_child(command: &mut std::process::Command, fd: std::os::fd::RawFd) {
    use std::os::unix::process::CommandExt as _;
    // SAFETY: runs in the child between its fork and its exec, and calls only `fcntl`, which
    // is async-signal-safe and touches no memory; `fd` is open there, the child's copy of the
    // parent's, as the caller keeps it open until the spawn.
    unsafe {
        command.pre_exec(move || match libc::fcntl(fd, libc::F_SETFD, 0) {
            -1 => Err(std::io::Error::last_os_error()),
            _ => Ok(()),
        })
    };
}

/// A descriptor of this process's own for what `fd` names: one this process was started with
/// open (a program that became this one by `exec` left it so, and named it on the command
/// line). It is a duplicate, close-on-exec, so it is owned by nothing else whatever `fd` is,
/// and `fd` itself is made close-on-exec too: no program this process starts gets either. An
/// error for a number that is no open descriptor, or one of the three standard streams.
#[cfg(unix)]
pub fn inherited(fd: std::os::fd::RawFd) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd as _;
    if fd <= libc::STDERR_FILENO {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("descriptor {fd} is a standard stream's number, or none"),
        ));
    }
    // SAFETY: `fcntl` with `F_DUPFD_CLOEXEC` reads and writes no memory of this process; on a
    // number that is no open descriptor it fails with `EBADF`, which is the error below.
    let own = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, libc::STDERR_FILENO + 1) };
    if own == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `own` is a descriptor the call above just made, which nothing else knows of, so
    // this value is its one owner.
    let own = unsafe { std::os::fd::OwnedFd::from_raw_fd(own) };
    // SAFETY: as the first call: no memory is read or written, and `fd` is open (it was
    // duplicated). Whoever owns `fd`, a flag that closes it in programs started later takes
    // nothing from this process.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(own)
}

/// Whose CPU time [`cpu_time`] reads.
#[cfg(unix)]
#[derive(Clone, Copy)]
pub enum Whose {
    /// This process's own.
    Itself,
    /// That of its children which it waited for, and theirs.
    Waited,
}

/// The user and system CPU time `whose` had; None where the kernel says nothing of it.
#[cfg(unix)]
pub fn cpu_time(whose: Whose) -> Option<Duration> {
    cpu_times(whose).map(|(user, system)| user + system)
}

/// The user CPU time `whose` had, and its system CPU time, apart: what a build's row says the
/// daemon spent (`builds.daemon_user_ns`); None where the kernel says nothing of it.
#[cfg(unix)]
pub fn cpu_times(whose: Whose) -> Option<(Duration, Duration)> {
    let who = match whose {
        Whose::Itself => libc::RUSAGE_SELF,
        Whose::Waited => libc::RUSAGE_CHILDREN,
    };
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: `usage` is a live, writable `rusage`, and an `rusage` is all `getrusage` writes;
    // a smaller buffer would be written past its end.
    if unsafe { libc::getrusage(who, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: an `rusage` is integers alone, for which the zeros `usage` began as are a value,
    // and `getrusage` wrote another over them. A type with a niche (a reference, an enum) would
    // have no such value in its zeros, and reading it would be undefined.
    let usage = unsafe { usage.assume_init() };
    let time = |it: libc::timeval| {
        let micros = Duration::from_micros(u64::try_from(it.tv_usec).unwrap_or(0));
        Duration::from_secs(u64::try_from(it.tv_sec).unwrap_or(0)) + micros
    };
    Some((time(usage.ru_utime), time(usage.ru_stime)))
}

/// The ticks of the clock in a second, the unit of `/proc/<pid>/stat`'s times.
#[cfg(target_os = "linux")]
pub fn clock_ticks() -> Option<u64> {
    // SAFETY: `sysconf` takes no pointer and reads a constant of the system; a name it does
    // not know is answered with -1, which is refused below.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    u64::try_from(ticks).ok().filter(|it| *it > 0)
}

/// Validate the two handles of a thin client handover. Duplicate rather than adopting a
/// command-line integer: a forged command line cannot take ownership of a handle the engine
/// already owns. Inherited originals stay open until this short-lived command exits.
#[cfg(windows)]
pub fn handed(
    socket_number: i32,
    file: i32,
) -> std::io::Result<(uds_windows::UnixStream, std::fs::File)> {
    use std::os::windows::io::{FromRawHandle, FromRawSocket};
    use windows_sys::Win32::{
        Foundation::*,
        Networking::WinSock::*,
        Storage::FileSystem::{FILE_TYPE_DISK, GetFileType},
        System::Threading::{GetCurrentProcess, GetCurrentProcessId},
    };
    let invalid = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "expected an inherited AF_UNIX stream and an inherited answer file",
        )
    };
    let sock = usize::try_from(socket_number).map_err(|_| invalid())?;
    let file = usize::try_from(file).map_err(|_| invalid())? as HANDLE;
    for h in [file, sock as HANDLE] {
        let mut flags = 0;
        // SAFETY: inspect the kernel's handle table, writing a valid DWORD; refuse handles not inherited.
        if unsafe { GetHandleInformation(h, &mut flags) } == 0 || flags & HANDLE_FLAG_INHERIT == 0 {
            return Err(invalid());
        }
    }
    // SAFETY: GetFileType validates the handle. Clear inheritance before any child starts.
    if unsafe { GetFileType(file) } != FILE_TYPE_DISK {
        return Err(invalid());
    }
    let mut info = WSAPROTOCOL_INFOW::default();
    // SAFETY: the provider validates socket; info is initialized writable storage.
    // Initialize Winsock in the receiving process before asking it about an inherited socket.
    static WINSOCK: std::sync::OnceLock<i32> = std::sync::OnceLock::new();
    let started = *WINSOCK.get_or_init(|| {
        let mut data = WSADATA::default();
        unsafe { WSAStartup(0x0202, &mut data) }
    });
    if started != 0 {
        return Err(std::io::Error::from_raw_os_error(started));
    }
    if unsafe { WSADuplicateSocketW(sock, GetCurrentProcessId(), &mut info) } != 0
        || info.iAddressFamily != i32::from(AF_UNIX)
        || info.iSocketType != SOCK_STREAM
    {
        return Err(invalid());
    }
    let dup = unsafe {
        WSASocketW(-1, -1, -1, &info, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT)
    };
    if dup == INVALID_SOCKET {
        return Err(std::io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    // SAFETY: dup is a new owned socket (not the input integer).
    let stream = unsafe { uds_windows::UnixStream::from_raw_socket(dup as _) };
    let mut copy = std::ptr::null_mut();
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            file,
            GetCurrentProcess(),
            &mut copy,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: DuplicateHandle returned a new owned file handle.
    let file_copy = unsafe { std::fs::File::from_raw_handle(copy) };
    for h in [file, sock as HANDLE] {
        if unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok((stream, file_copy))
}

/// A process started detached ([`spawn_detached`]): its handle, owned, and its process ID.
#[cfg(windows)]
pub struct Detached {
    process: std::os::windows::io::OwnedHandle,
    pub pid: u32,
}

#[cfg(windows)]
impl Detached {
    /// How it ended, `None` while it runs.
    pub fn ended(&self) -> std::io::Result<Option<u32>> {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::{
            Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
            System::Threading::{GetExitCodeProcess, WaitForSingleObject},
        };
        // SAFETY: the handle is open while `self` lives; a wait of 0 asks and does not wait.
        #[expect(clippy::disallowed_methods, reason = "a wait of no time: whether it ended")]
        match unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } {
            WAIT_TIMEOUT => return Ok(None),
            WAIT_OBJECT_0 => {}
            _ => return Err(std::io::Error::last_os_error()),
        }
        let mut code = 0;
        // SAFETY: as above; `code` is a live local the call writes.
        if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Some(code))
    }
}

/// Whether a process this one starts may leave the job this one is in, and must say so: a
/// process in a job is started in it, and ends with it where it kills on close (a terminal's,
/// an IDE's, a CI runner's, `blaze run`'s), unless it is started with
/// `CREATE_BREAKAWAY_FROM_JOB`, which the job allows or refuses (`BREAKAWAY_OK`); one that
/// allows `SILENT_BREAKAWAY_OK` starts every child outside it. `Ok(false)` where it is in no
/// job, or one whose children leave it unasked; an error naming the job's refusal where it is
/// in one that lets none leave: a daemon started there would end with the command that
/// started it.
#[cfg(windows)]
fn breakaway() -> std::io::Result<bool> {
    use windows_sys::Win32::System::{
        JobObjects::{
            IsProcessInJob, JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            QueryInformationJobObject,
        },
        Threading::GetCurrentProcess,
    };
    let mut in_job = 0;
    // SAFETY: the current process's pseudo-handle, no job named (any job), and a live local
    // the call writes.
    if unsafe { IsProcessInJob(GetCurrentProcess(), std::ptr::null_mut(), &mut in_job) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if in_job == 0 {
        return Ok(false);
    }
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    // SAFETY: no handle asks of the job this process is in; `limits` is a live local of the
    // size the call is told, which it writes.
    if unsafe {
        QueryInformationJobObject(
            std::ptr::null_mut(),
            JobObjectExtendedLimitInformation,
            (&raw mut limits).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let flags = limits.BasicLimitInformation.LimitFlags;
    if flags & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK != 0 {
        return Ok(false);
    }
    if flags & JOB_OBJECT_LIMIT_BREAKAWAY_OK != 0 {
        return Ok(true);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "this command runs in a Windows job object that lets no process it starts leave it \
         (no JOB_OBJECT_LIMIT_BREAKAWAY_OK), so a daemon it started would end with it: start \
         the daemon (`blaze serve`) outside that job, or allow breakaway in it",
    ))
}

/// Starts `program` with the arguments `args` makes of the number the child has `keep` under,
/// in `dir`, detached from this console (`DETACHED_PROCESS`, a
/// process group of its own, no window), out of this process's job where that must be asked
/// ([`breakaway`]), with no standard input, `log` its standard output and error, and `keep`
/// the one other handle it inherits. Every handle it inherits is named
/// (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`), so none of this command's (a pipe whoever started
/// it reads, which would then wait for the daemon to end) is, and nothing of this process is
/// changed meanwhile. The environment is this process's.
#[cfg(windows)]
pub fn spawn_detached(
    program: &std::path::Path,
    args: impl FnOnce(usize) -> Vec<std::ffi::OsString>,
    dir: &std::path::Path,
    log: &std::fs::File,
    keep: std::os::windows::io::BorrowedHandle<'_>,
) -> std::io::Result<Detached> {
    use std::os::windows::{
        ffi::OsStrExt as _,
        io::{AsHandle as _, AsRawHandle as _, FromRawHandle as _, OwnedHandle},
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW,
        CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DETACHED_PROCESS,
        DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
        InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION,
        STARTF_USESTDHANDLES, STARTUPINFOEXW, UpdateProcThreadAttribute,
    };
    let away = breakaway()?;
    // Inheritable copies of what it is given, closed here once it started: the originals stay
    // this process's alone.
    let inheritable =
        |handle: std::os::windows::io::BorrowedHandle<'_>| -> std::io::Result<OwnedHandle> {
            use windows_sys::Win32::{
                Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle},
                System::Threading::GetCurrentProcess,
            };
            let mut copy = std::ptr::null_mut();
            // SAFETY: `handle` is open while borrowed; the copy is this process's, written to a
            // live local and owned below, so closed once.
            let duplicated = unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    handle.as_raw_handle(),
                    GetCurrentProcess(),
                    &mut copy,
                    0,
                    1,
                    DUPLICATE_SAME_ACCESS,
                )
            };
            if duplicated == 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: as above, the copy just made.
            Ok(unsafe { OwnedHandle::from_raw_handle(copy) })
        };
    let nul = std::fs::File::open("NUL")?;
    let (input, output, kept) =
        (inheritable(nul.as_handle())?, inheritable(log.as_handle())?, inheritable(keep)?);
    let mut handles = [input.as_raw_handle(), output.as_raw_handle(), kept.as_raw_handle()];
    let mut size = 0;
    // SAFETY: a size query: no list is given, and `size` is a live local it writes.
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size) };
    // alloc: once per daemon started, the attribute list's room (`u64`s, for its alignment).
    let mut list = vec![0u64; size.div_ceil(8)];
    let attributes = list.as_mut_ptr().cast();
    // SAFETY: `list` is `size` bytes, live and exclusive, for one attribute.
    if unsafe { InitializeProcThreadAttributeList(attributes, 1, 0, &mut size) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the list was just initialized for one attribute; `handles` outlives the call that
    // starts the process, which reads it, and the list is deleted after that.
    let listed = unsafe {
        UpdateProcThreadAttribute(
            attributes,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            handles.as_mut_ptr().cast(),
            size_of_val(&handles),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    };
    let started = (|| {
        if listed == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // An inherited handle has its number in the child: the copy's.
        let args = args(handles[2] as usize);
        let mut line = blaze_core::create_process::command_line(program, &args)?;
        let program: Vec<u16> = program.as_os_str().encode_wide().chain([0]).collect();
        let dir: Vec<u16> = dir.as_os_str().encode_wide().chain([0]).collect();
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = handles[0];
        startup.StartupInfo.hStdOutput = handles[1];
        startup.StartupInfo.hStdError = handles[1];
        startup.lpAttributeList = attributes;
        let flags = DETACHED_PROCESS
            | CREATE_NEW_PROCESS_GROUP
            | CREATE_NO_WINDOW
            | CREATE_UNICODE_ENVIRONMENT
            | EXTENDED_STARTUPINFO_PRESENT
            | if away { CREATE_BREAKAWAY_FROM_JOB } else { 0 };
        let mut info = PROCESS_INFORMATION::default();
        // SAFETY: every pointer is to a live, NUL-ended buffer of this frame or the startup
        // information above, whose list names open inheritable handles; `line` is writable,
        // as the call needs; no environment is given (this process's is), and `info` is a
        // live local it writes.
        if unsafe {
            CreateProcessW(
                program.as_ptr(),
                line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                flags,
                std::ptr::null(),
                dir.as_ptr(),
                &startup.StartupInfo,
                &mut info,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: both handles were just made by the call, and nothing else owns them.
        let (process, _thread) = unsafe {
            (
                OwnedHandle::from_raw_handle(info.hProcess),
                OwnedHandle::from_raw_handle(info.hThread),
            )
        };
        Ok(Detached { process, pid: info.dwProcessId })
    })();
    // SAFETY: the list was initialized above, and the call that read it has returned.
    unsafe { DeleteProcThreadAttributeList(attributes) };
    started
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_is_alive() {
        if cfg!(any(unix, windows)) {
            assert!(alive(std::process::id()));
        }
    }

    #[cfg(unix)]
    #[test]
    fn this_process_used_some_cpu() {
        let mut spin = 0u64;
        for it in 0..1_000_000u64 {
            spin = std::hint::black_box(spin.wrapping_add(it));
        }
        assert!(cpu_time(Whose::Itself).is_some_and(|it| it > Duration::ZERO));
        assert!(cpu_time(Whose::Waited).is_some());
    }

    /// A child that runs until its standard input is closed.
    #[cfg(unix)]
    fn until_closed() -> std::process::Child {
        std::process::Command::new("/bin/sh")
            .args(["-c", "read line"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn a_wait_for_a_process_ends_on_its_exit_not_its_limit() {
        let mut child = until_closed();
        let stdin = child.stdin.take().unwrap();
        let started = std::time::Instant::now();
        std::thread::scope(|scope| {
            scope.spawn(move || {
                blaze_graph::spin::busy(Duration::from_millis(100));
                drop(stdin);
            });
            assert!(ended_within(child.id(), Duration::from_secs(60)).unwrap());
        });
        assert!(started.elapsed() < Duration::from_secs(10), "ended after {:?}", started.elapsed());
        child.wait().unwrap();
        assert!(
            ended_within(child.id(), Duration::from_secs(60)).unwrap(),
            "one reaped and gone has ended"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_wait_for_a_process_that_runs_on_gives_up_at_its_limit() {
        let mut child = until_closed();
        let started = std::time::Instant::now();
        assert!(!ended_within(child.id(), Duration::from_millis(50)).unwrap());
        assert!(started.elapsed() >= Duration::from_millis(50));
        drop(child.stdin.take());
        child.wait().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_pipe_is_readable_once_written_or_closed_and_not_before() {
        use std::{io::Write as _, os::fd::AsFd as _};
        let (reader, mut writer) = std::io::pipe().unwrap();
        assert!(!readable_within(reader.as_fd(), Duration::from_millis(20)).unwrap());
        writer.write_all(b"\n").unwrap();
        assert!(readable_within(reader.as_fd(), Duration::from_secs(60)).unwrap());
        let (reader, writer) = std::io::pipe().unwrap();
        drop(writer);
        let started = std::time::Instant::now();
        assert!(readable_within(reader.as_fd(), Duration::from_secs(60)).unwrap());
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_clock_ticks() {
        assert!(clock_ticks().is_some());
    }
    /// The invariant: a process started detached writes its output to the log it is given, runs
    /// in the directory it is given, and has the one other handle it is given under the number
    /// it is told: what it writes there is read here, and the pipe ends as it does (no other
    /// copy of its writer is left open, here or there). The process is this test binary, run
    /// as [`detached_child`] (PowerShell, detached, ends at once with 0 and runs nothing).
    #[cfg(windows)]
    #[test]
    fn a_detached_process_has_its_log_its_directory_and_the_handle_it_is_told() {
        use std::{io::Read as _, os::windows::io::AsHandle as _};
        let dir = std::env::temp_dir().join(format!("blaze-detached-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = std::fs::File::create(dir.join("log.txt")).unwrap();
        let (mut ready, said) = std::io::pipe().unwrap();
        let args = |handle: usize| {
            std::fs::write(dir.join("handle.txt"), handle.to_string()).unwrap();
            ["--exact", "raw::process::tests::detached_child", "--ignored", "--nocapture"]
                .map(Into::into)
                .to_vec()
        };
        let child =
            spawn_detached(&std::env::current_exe().unwrap(), args, &dir, &log, said.as_handle())
                .unwrap();
        drop(said);
        let mut heard = Vec::new();
        ready.read_to_end(&mut heard).unwrap();
        assert_eq!(heard, b"\n");
        assert!(ended_within(child.pid, Duration::from_secs(30)).unwrap());
        assert_eq!(child.ended().unwrap(), Some(0));
        drop(log);
        let logged = std::fs::read_to_string(dir.join("log.txt")).unwrap();
        assert!(logged.contains(&format!("in {}", dir.display())), "{logged}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [`a_detached_process_has_its_log_its_directory_and_the_handle_it_is_told`]'s child: says
    /// its directory, and writes a line on the handle whose number is in `handle.txt` there.
    #[cfg(windows)]
    #[test]
    #[ignore = "run by a_detached_process_has_its_log_its_directory_and_the_handle_it_is_told"]
    fn detached_child() {
        use std::{io::Write as _, os::windows::io::FromRawHandle as _};
        let Ok(number) = std::fs::read_to_string("handle.txt") else { return };
        println!("in {}", std::env::current_dir().unwrap().display());
        let handle =
            number.trim().parse::<usize>().unwrap() as windows_sys::Win32::Foundation::HANDLE;
        // SAFETY: the handle the parent made this process inherit under this number, for this.
        let mut pipe = unsafe { std::fs::File::from_raw_handle(handle) };
        pipe.write_all(b"\n").unwrap();
    }
}
