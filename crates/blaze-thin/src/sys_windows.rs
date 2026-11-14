//! A Windows handover inherits exactly five handles. Unlike exec, the parent stays alive
//! until its child exits. The answer file has no persistent name after the last close.

use blaze_core::wait::{self, Deadline, Monotonic, Once, WaitError, Waited};
use blaze_thin::handover::{Began, Held};
use std::{
    ffi::OsString,
    fs::OpenOptions,
    io::{self, Write},
    os::windows::{
        ffi::OsStrExt,
        fs::OpenOptionsExt,
        io::{AsRawHandle, AsRawSocket, FromRawHandle, OwnedHandle},
    },
    path::Path,
    process::{Command, ExitCode},
};
use uds_windows::UnixStream;
use windows_sys::Win32::{
    Foundation::*,
    Networking::WinSock::*,
    Storage::FileSystem::FILE_FLAG_DELETE_ON_CLOSE,
    System::{Console::*, Threading::*},
};

pub(super) fn readable(
    s: &UnixStream,
    what: &'static str,
    until: Deadline,
    clock: &Monotonic,
) -> Result<Waited<()>, WaitError> {
    let mut fd = WSAPOLLFD { fd: s.as_raw_socket() as _, events: POLLRDNORM, revents: 0 };
    wait::until(what, clock, until.finite(), |left| {
        let ms = left.map_or(-1, |d| d.as_nanos().div_ceil(1_000_000).min(i32::MAX as _) as i32);
        // SAFETY: one borrowed open socket, one writable poll descriptor.
        match unsafe { WSAPoll(&mut fd, 1, ms) } {
            0 => Ok(Once::TimedOut),
            1 => Ok(Once::Ready(())),
            _ => Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() })),
        }
    })
}

/// Absolute QPC ticks, the time base an external launch timer also reads. Instant's epoch
/// is private to std; this clock is comparable across the parent and child processes.
pub(super) fn counter() -> i64 {
    let mut at = 0;
    // SAFETY: QPC writes one i64 and is always supported on Windows x64.
    unsafe { windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut at) };
    at
}

pub(super) fn run(cmd: &mut Command) -> io::Result<ExitCode> {
    let status = cmd.status()?;
    Ok(code(status.code().unwrap_or(101) as u32))
}
fn code(value: u32) -> ExitCode {
    use std::os::windows::process::ExitCodeExt;
    ExitCode::from_raw(value)
}

fn inheritable(raw: HANDLE) -> io::Result<OwnedHandle> {
    let mut copy = std::ptr::null_mut();
    // SAFETY: the kernel validates raw; only a successful duplication yields an owner.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            raw,
            GetCurrentProcess(),
            &mut copy,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(copy) })
}

pub(super) fn handover(
    stream: &UnixStream,
    held: Held<'_>,
    engine: &Path,
    state: &Path,
    words: &[OsString],
    id: u64,
) -> Result<ExitCode, String> {
    let bytes = held.write()?;
    let start = || -> io::Result<ExitCode> {
        let path = state.join(format!("thin-{}.answer", std::process::id()));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_DELETE_ON_CLOSE)
            .open(&path)?;
        file.write_all(&bytes)?;
        let file = inheritable(file.as_raw_handle())?;
        let socket = stream.try_clone()?;
        let sock = socket.as_raw_socket() as HANDLE;
        // SAFETY: only the Winsock duplicate, private to this single-threaded launcher, is made inheritable.
        if unsafe { SetHandleInformation(sock, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut handles = vec![sock, file.as_raw_handle()];
        let mut stdio = Vec::new();
        let mut std_handles = [std::ptr::null_mut(); 3];
        for (i, which) in
            [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE].into_iter().enumerate()
        {
            // SAFETY: inspect each standard handle. Preserve closed streams as null.
            let h = unsafe { GetStdHandle(which) };
            if h != INVALID_HANDLE_VALUE && !h.is_null() {
                let owned = inheritable(h)?;
                std_handles[i] = owned.as_raw_handle();
                handles.push(owned.as_raw_handle());
                stdio.push(owned);
            }
        }
        let began = Began {
            socket: (sock as usize).try_into().map_err(io::Error::other)?,
            file: (file.as_raw_handle() as usize).try_into().map_err(io::Error::other)?,
            id,
        };
        let args = began.words().into_iter().chain(words.iter().cloned()).collect::<Vec<_>>();
        let mut line = blaze_core::create_process::command_line(engine, &args)?;
        let exe = engine.as_os_str().encode_wide().chain([0]).collect::<Vec<_>>();
        let mut size = 0;
        // SAFETY: sizing call; the subsequent aligned buffer holds the initialized list until spawn returns.
        unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size) };
        let mut buf = vec![0usize; size.div_ceil(size_of::<usize>())];
        let list = buf.as_mut_ptr().cast();
        if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let spawn = || -> io::Result<OwnedHandle> {
            // SAFETY: handles and list are live for the entire CreateProcess call, only the explicitly listed handles pass.
            if unsafe {
                UpdateProcThreadAttribute(
                    list,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as _,
                    handles.as_ptr().cast(),
                    size_of_val(handles.as_slice()),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut si = STARTUPINFOEXW::default();
            si.lpAttributeList = list;
            si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as _;
            si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            [si.StartupInfo.hStdInput, si.StartupInfo.hStdOutput, si.StartupInfo.hStdError] =
                std_handles;
            let mut pi = PROCESS_INFORMATION::default();
            // SAFETY: both strings are NUL terminated, command line writable, output points to initialized storage.
            if unsafe {
                CreateProcessW(
                    exe.as_ptr(),
                    line.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    1,
                    EXTENDED_STARTUPINFO_PRESENT,
                    std::ptr::null(),
                    std::ptr::null(),
                    &si.StartupInfo,
                    &mut pi,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: these two handles were returned by this spawn and now have one owner each.
            let _thread = unsafe { OwnedHandle::from_raw_handle(pi.hThread) };
            Ok(unsafe { OwnedHandle::from_raw_handle(pi.hProcess) })
        };
        let mut spawn = spawn;
        let process = spawn();
        unsafe { DeleteProcThreadAttributeList(list) };
        let process = process?;
        wait::signaled(
            "the engine finishing the thin command",
            process.as_raw_handle(),
            None,
            &Monotonic::new(),
        )
        .map_err(io::Error::other)?;
        let mut exit = 0;
        // SAFETY: process is still open, exit is writable.
        if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut exit) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(code(exit))
    };
    start().map_err(|e| format!("{}: {e}", engine.display()))
}
