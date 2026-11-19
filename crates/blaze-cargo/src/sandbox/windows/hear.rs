//! The Windows side of [`crate::sandbox::told`]: the pipe a run's processes tell its launcher
//! on, the thread that hears it while the run runs, the count of the processes the run's job
//! held, and a process's own message ([`tell`]) and console host ([`console_host`]).
//!
//! The pipe is a named pipe the launcher makes outside the container, in message mode, so one
//! write is one message whoever writes it, with one instance and remote clients refused; the
//! launcher opens its one client end itself, inheritably, and hands it to the program in its
//! attribute list ([`super::Made`]), closing its own copy once the program is made. When every
//! process that held it has ended, a read says the pipe is broken: that is the end of what the
//! run told. A copy held past the run's job (none is made, but nothing here relies on it) is
//! bounded: once the job is gone the thread is asked to stop and its read cancelled
//! ([`Hearing::heard`]).

use std::{
    ffi::OsStr,
    ptr::{null, null_mut},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use windows_sys::{
    Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS},
    Win32::{
        Foundation::{
            ERROR_BROKEN_PIPE, ERROR_MORE_DATA, ERROR_OPERATION_ABORTED, ERROR_PIPE_CONNECTED,
            GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
        },
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_TYPE_PIPE, GetFileType, OPEN_EXISTING,
            PIPE_ACCESS_INBOUND, ReadFile, WriteFile,
        },
        System::{
            IO::CancelSynchronousIo,
            JobObjects::{
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
                QueryInformationJobObject,
            },
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_MESSAGE,
                PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_WAIT,
            },
            Threading::{GetCurrentProcess, WaitForSingleObject},
        },
    },
};

use super::{Handle, failed, wide};
use crate::sandbox::told::{self, Told};

/// What the pipe buffers of one run's messages before a writer waits for the thread to read.
const BUFFERED: u32 = 64 << 10;

/// How long the launcher waits, once the run's job is gone, for the thread to hear the pipe
/// end; then it is asked to stop.
const ENDS: Duration = Duration::from_secs(2);

/// How many times a stopped thread's read is cancelled, [`ENDS`]'s tenth apart, before the
/// launcher leaves it: a read issued just after a cancel is not cancelled by it.
const CANCELS: u32 = 10;

/// `PROCESSINFOCLASS` `ProcessConsoleHostProcess` (ntpsapi.h): the number of the process that
/// hosts the console of the process asked about, its two low bits flags.
const PROCESS_CONSOLE_HOST_PROCESS: PROCESSINFOCLASS = 49;

/// What the thread heard.
#[derive(Default)]
pub(super) struct Heard {
    pub(super) told: Vec<Told>,
    /// Why each message that is not one was refused.
    pub(super) refused: Vec<String>,
    /// Why not everything told was heard.
    pub(super) failed: Option<String>,
}

/// The pipe of one run and the thread hearing it.
pub(super) struct Hearing {
    stop: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<Heard>,
}

/// A run's pipe: its server end, read by [`Hearing`], and its client end, inheritable, which the
/// program is handed.
pub(super) fn pipe() -> Result<(Handle, Handle), String> {
    static SERIAL: AtomicU64 = AtomicU64::new(0);
    let name = format!(
        r"\\.\pipe\blaze-told-{}-{}",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed)
    ); // alloc: once a traced run, its pipe's name
    let name = wide(OsStr::new(&name), "the told pipe's name")?;
    // SAFETY: `name` ends in NUL (`wide`); a null security attribute is the default security,
    // which lets this user alone open it. The handle it gives, or INVALID_HANDLE_VALUE, is
    // checked, then owned by the `Handle`.
    let server = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            0,
            BUFFERED,
            0,
            null(),
        )
    };
    if server == INVALID_HANDLE_VALUE {
        return Err(failed("making the pipe a run's processes tell on", "CreateNamedPipeW"));
    }
    let server = Handle(server);
    let inherit = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: `name` ends in NUL, `inherit` is a live SECURITY_ATTRIBUTES whose length says so;
    // the handle it gives, or INVALID_HANDLE_VALUE, is checked, then owned by the `Handle`.
    let client = unsafe {
        CreateFileW(name.as_ptr(), GENERIC_WRITE, 0, &inherit, OPEN_EXISTING, 0, null_mut())
    };
    if client == INVALID_HANDLE_VALUE {
        return Err(failed("opening the pipe a run's processes tell on", "CreateFileW"));
    }
    let client = Handle(client);
    // SAFETY: `server` owns the pipe's server end; no overlapped. Its client just opened, so
    // this says ERROR_PIPE_CONNECTED at once.
    let connected = unsafe { ConnectNamedPipe(server.0, null_mut()) };
    // SAFETY: reads the calling thread's last error, nothing else.
    if connected == 0 && unsafe { GetLastError() } != ERROR_PIPE_CONNECTED {
        return Err(failed("connecting the pipe a run's processes tell on", "ConnectNamedPipe"));
    }
    Ok((server, client))
}

impl Hearing {
    /// Hears `server` on a thread of its own until every process that can tell has ended.
    pub(super) fn start(server: Handle) -> Result<Hearing, String> {
        let stop = Arc::new(AtomicBool::new(false));
        let raw = server.0 as usize;
        std::mem::forget(server);
        let stopped = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("blaze-told".to_owned()) // alloc: once a traced run
            .spawn(move || {
                // The thread owns the server end from here: closed as it ends.
                let server = Handle(raw as HANDLE);
                hear(&server, &stopped)
            })
            .map_err(|error| format!("starting the thread that hears a run's processes: {error}"))?; // alloc: error path
        Ok(Hearing { stop, thread })
    }

    /// What was heard, once the run's job is gone: every process that held the pipe has ended,
    /// so the thread hears it end within [`ENDS`]; past that it is stopped.
    pub(super) fn heard(self) -> Heard {
        use std::os::windows::io::AsRawHandle as _;
        let thread = self.thread.as_raw_handle() as HANDLE;
        if !ended_within(thread, ENDS) {
            self.stop.store(true, Ordering::Release);
            let mut left = true;
            for _ in 0..CANCELS {
                // SAFETY: `thread` is the live thread `self.thread` owns, not joined yet; the
                // call cancels its synchronous read, or finds none.
                unsafe { CancelSynchronousIo(thread) };
                if ended_within(thread, ENDS / CANCELS) {
                    left = false;
                    break;
                }
            }
            if left {
                // Left to end with the process: what it holds is a pipe and its buffer.
                return Heard {
                    failed: Some(format!(
                        "the pipe they tell on stayed open {ENDS:?} past the run's job, and its read could not be ended"
                    )), // alloc: error path
                    ..Heard::default()
                };
            }
        }
        match self.thread.join() {
            Ok(heard) => heard,
            Err(_) => Heard {
                failed: Some("the thread hearing them panicked".to_owned()), // alloc: error path
                ..Heard::default()
            },
        }
    }
}

/// Whether `thread` ended within `long`.
fn ended_within(thread: HANDLE, long: Duration) -> bool {
    let ms = u32::try_from(long.as_millis()).unwrap_or(u32::MAX - 1);
    // SAFETY: `thread` is a live thread handle its `JoinHandle` owns for the call.
    #[expect(
        clippy::disallowed_methods,
        reason = "`blaze_core::wait` has no handle wait yet (deadline-waits step 5); the wait has its own short deadline"
    )]
    let waited = unsafe { WaitForSingleObject(thread, ms) };
    waited == WAIT_OBJECT_0
}

/// Reads `server`'s messages until the pipe ends (every client closed), it is stopped, or a read
/// fails.
fn hear(server: &Handle, stop: &AtomicBool) -> Heard {
    let mut heard = Heard::default();
    // alloc: once a traced run, the read buffer and the message being put together
    let mut buffer = vec![0u8; BUFFERED as usize];
    let mut message = Vec::new();
    let mut held = 0usize;
    loop {
        if stop.load(Ordering::Acquire) {
            heard.failed.get_or_insert_with(|| {
                format!("the pipe they tell on stayed open {ENDS:?} past the run's job") // alloc: error path
            });
            break;
        }
        let mut read = 0u32;
        // SAFETY: `server` owns the pipe's server end, read synchronously; `buffer` is a live,
        // exclusive buffer of the length the call is told, `read` a live u32 for it to set.
        let ok = unsafe {
            ReadFile(server.0, buffer.as_mut_ptr(), buffer.len() as u32, &mut read, null_mut())
        };
        // SAFETY: reads the calling thread's last error, nothing else.
        let error = if ok == 0 { unsafe { GetLastError() } } else { 0 };
        if ok != 0 || error == ERROR_MORE_DATA {
            held += read as usize;
            if held > told::MOST {
                // Read on and dropped, so no writer waits on a full pipe for ever.
                heard.failed.get_or_insert_with(|| format!("more than the {} bytes a run may tell", told::MOST)); // alloc: error path
                message.clear();
                continue;
            }
            message.extend_from_slice(&buffer[..read as usize]);
            if error != ERROR_MORE_DATA {
                match Told::decode(&message) {
                    Ok(it) => heard.told.push(it),
                    Err(why) => heard.refused.push(why),
                }
                message.clear();
            }
            continue;
        }
        match error {
            ERROR_BROKEN_PIPE => break,
            ERROR_OPERATION_ABORTED if stop.load(Ordering::Acquire) => continue,
            _ => {
                heard.failed.get_or_insert_with(|| {
                    format!("reading the pipe they tell on: {}", std::io::Error::from_raw_os_error(error as i32)) // alloc: error path
                });
                break;
            }
        }
    }
    heard
}

/// How many processes `job` ever held, ended ones too.
pub(super) fn total(job: &Handle) -> Result<u32, String> {
    let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    // SAFETY: JobObjectBasicAccountingInformation names a
    // JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, and `info` is a live, exclusive one of the size the
    // call is told, which it writes and nothing more; a null length out-pointer is allowed.
    // `job` owns an open job handle.
    let asked = unsafe {
        QueryInformationJobObject(
            job.0,
            JobObjectBasicAccountingInformation,
            (&raw mut info).cast(),
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            null_mut(),
        )
    };
    match asked {
        0 => Err(failed("counting the processes of the run's job", "QueryInformationJobObject")),
        _ => Ok(info.TotalProcesses),
    }
}

/// Sends `message` as one write on the pipe `handle` names, inherited from the launcher.
pub(crate) fn tell(handle: u64, message: &[u8]) -> Result<(), String> {
    let handle = handle as usize as HANDLE;
    // SAFETY: takes a handle and reads no memory; a number that is no handle of this process
    // says FILE_TYPE_UNKNOWN.
    if unsafe { GetFileType(handle) } != FILE_TYPE_PIPE {
        return Err(format!("{} names no pipe of this process", told::VAR)); // alloc: error path
    }
    let length = u32::try_from(message.len())
        .map_err(|_| format!("a message of {} bytes, more than one write sends", message.len()))?; // alloc: error path
    let mut written = 0u32;
    // SAFETY: `handle` is a pipe of this process, just checked, written synchronously and not
    // closed here; `message` is live for the call and read only, `written` a live u32 for it to
    // set. A pipe the variable names wrongly gets these bytes and nothing else.
    let ok = unsafe { WriteFile(handle, message.as_ptr(), length, &mut written, null_mut()) };
    if ok == 0 {
        return Err(failed("telling the launcher what this process read", "WriteFile"));
    }
    if written != length {
        return Err(format!("telling the launcher what this process read: {written} of {length} bytes written")); // alloc: error path
    }
    Ok(())
}

/// The number of the process that hosts this process's console, when it has one.
pub(crate) fn console_host() -> Option<u32> {
    let mut value = 0usize;
    // SAFETY: the pseudo-handle names this process and is never closed; `value` is a live,
    // exclusive ULONG_PTR of the size the call is told, which ProcessConsoleHostProcess writes
    // and nothing more; a null length out-pointer is allowed.
    let status = unsafe {
        NtQueryInformationProcess(
            GetCurrentProcess(),
            PROCESS_CONSOLE_HOST_PROCESS,
            (&raw mut value).cast(),
            size_of::<usize>() as u32,
            null_mut(),
        )
    };
    if status < 0 {
        return None;
    }
    u32::try_from(value & !3).ok().filter(|it| *it != 0)
}
