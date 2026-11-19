//! What the system says of the terminal, the clock and the user's directories, with no call
//! of std's that asks it.

/// The columns of the terminal standard error is, None when it is none.
#[cfg(unix)]
pub fn stderr_columns() -> Option<u16> {
    let mut size = libc::winsize { ws_row: 0, ws_col: 0, ws_xpixel: 0, ws_ypixel: 0 };
    // SAFETY: `TIOCGWINSZ` writes one `winsize` through its third argument, which `&raw mut size`
    // is for the call; on failure it writes nothing and `size` stays zeros.
    let got = unsafe { libc::ioctl(libc::STDERR_FILENO, libc::TIOCGWINSZ, &raw mut size) };
    (got == 0 && size.ws_col > 0).then_some(size.ws_col)
}

/// The columns and rows of the terminal standard error is, None when it is none.
#[cfg(unix)]
pub fn stderr_size() -> Option<(u16, u16)> {
    let mut size = libc::winsize { ws_row: 0, ws_col: 0, ws_xpixel: 0, ws_ypixel: 0 };
    // SAFETY: `TIOCGWINSZ` writes one `winsize` through its third argument, which `&raw mut size`
    // is for the call; on failure it writes nothing and `size` stays zeros.
    let got = unsafe { libc::ioctl(libc::STDERR_FILENO, libc::TIOCGWINSZ, &raw mut size) };
    (got == 0 && size.ws_col > 0 && size.ws_row > 0).then_some((size.ws_col, size.ws_row))
}

/// The terminal standard error is stops echoing the keys typed into it; what puts it back is
/// returned, None when stderr is no terminal or its settings can't be read. Its line
/// discipline is otherwise left as it is: Ctrl-C still interrupts, and what is typed still
/// reaches whoever reads the terminal next.
#[cfg(unix)]
pub fn stderr_echo_off() -> Option<libc::termios> {
    // SAFETY: `termios` is plain integers and arrays of them, for which zeroes are a value.
    let mut now: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: `tcgetattr` writes one `termios` through its second argument, which `&raw mut
    // now` is for the call; on failure it writes nothing.
    if unsafe { libc::tcgetattr(libc::STDERR_FILENO, &raw mut now) } != 0 {
        return None;
    }
    let saved = now;
    now.c_lflag &= !libc::ECHO;
    // SAFETY: `tcsetattr` reads one `termios` through its third argument, live for the call.
    (unsafe { libc::tcsetattr(libc::STDERR_FILENO, libc::TCSANOW, &raw const now) } == 0)
        .then_some(saved)
}

/// The terminal standard error is as `saved` has it ([`stderr_echo_off`]'s).
#[cfg(unix)]
pub fn stderr_restore(saved: &libc::termios) {
    // SAFETY: `tcsetattr` reads one `termios` through its third argument, live for the call;
    // a failure leaves the terminal as it is, and there is no one to tell.
    unsafe { libc::tcsetattr(libc::STDERR_FILENO, libc::TCSANOW, std::ptr::from_ref(saved)) };
}

/// The step of the coarse real-time clock, which the kernel stamps the files it writes with.
#[cfg(target_os = "linux")]
pub fn coarse_clock_step() -> Option<std::time::Duration> {
    let mut tick = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `tick` is a live, writable `timespec`, all `clock_getres` writes; a clock the
    // kernel does not know is refused.
    match unsafe { libc::clock_getres(libc::CLOCK_REALTIME_COARSE, &raw mut tick) } {
        0 => Some(std::time::Duration::new(tick.tv_sec as u64, tick.tv_nsec as u32)),
        _ => None,
    }
}

/// The bytes free to this user on the file system `path` is on (`statvfs`'s available blocks
/// by its fragment size), None when it can't be asked (`path` is no C string, or `statvfs`
/// refuses it).
#[cfg(unix)]
pub fn free_bytes(path: &std::path::Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt as _;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `statvfs` is integers only, for which all-zero bytes are a valid value.
    let mut fs: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `path` is a nul-terminated string borrowed for the call, which only reads it, and
    // `fs` is a live, exclusive `struct statvfs` for the call to fill, and nothing else.
    let done = unsafe { libc::statvfs(path.as_ptr(), &raw mut fs) };
    #[allow(clippy::unnecessary_cast, reason = "the fields' widths differ by platform")]
    let free = (fs.f_bavail as u64).saturating_mul(fs.f_frsize as u64);
    (done == 0).then_some(free)
}

/// The bytes free to this user on the volume `path` is on (`GetDiskFreeSpaceExW`'s, which
/// counts this user's quota), None when it can't be asked.
#[cfg(windows)]
pub fn free_bytes(path: &std::path::Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt as _;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect(); // alloc: once per doctor
    let mut free = 0u64;
    // SAFETY: `wide` is a NUL-terminated path live for the call, which only reads it; `free`
    // is a live, exclusive `u64` it writes; the other two counts are not asked for (null).
    let done = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &raw mut free,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    (done != 0).then_some(free)
}

/// What the registry says of the paths Microsoft Defender does not scan.
#[cfg(windows)]
#[derive(Debug)]
pub enum Exclusions {
    /// No key of Defender's is there: it is not installed, or another antivirus replaced it.
    NoDefender,
    /// The excluded paths, as written (they may hold `%VARIABLE%`s), of the user's settings
    /// and of policy.
    Read(Vec<String>),
    /// The keys are there and this user may not read them (only an administrator may).
    Unreadable,
}

/// The paths Defender excludes from its scans, from the value names of
/// `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths` and of its policy twin.
#[cfg(windows)]
pub fn defender_exclusions() -> Exclusions {
    use windows_sys::Win32::{
        Foundation::{ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS},
        System::Registry::{HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, RegCloseKey, RegEnumValueW, RegOpenKeyExW},
    };
    const KEYS: [&str; 2] = [
        r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
        r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths",
    ];
    let mut paths = Vec::new(); // alloc: once per doctor
    let (mut found, mut denied) = (false, false);
    for key in KEYS {
        let wide: Vec<u16> = key.encode_utf16().chain([0]).collect(); // alloc: once per key
        let mut handle: HKEY = std::ptr::null_mut();
        // SAFETY: a predefined root key, a NUL-terminated subkey live for the call, and a live
        // `HKEY` it writes on success.
        let opened = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, wide.as_ptr(), 0, KEY_READ | KEY_WOW64_64KEY, &raw mut handle) };
        match opened {
            ERROR_SUCCESS => found = true,
            ERROR_FILE_NOT_FOUND => continue,
            ERROR_ACCESS_DENIED => {
                found = true;
                denied = true;
                continue;
            }
            _ => {
                denied = true;
                continue;
            }
        }
        let mut name = [0u16; 1024];
        for index in 0..10_000u32 {
            let mut len = name.len() as u32;
            // SAFETY: an open key; `name` is writable for `len` UTF-16 units, the count it
            // writes back; type and data are not asked for (null).
            let got = unsafe {
                RegEnumValueW(
                    handle,
                    index,
                    name.as_mut_ptr(),
                    &raw mut len,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if got != ERROR_SUCCESS {
                // ERROR_NO_MORE_ITEMS, or one too long to be a path: either ends the list.
                break;
            }
            let len = (len as usize).min(name.len());
            paths.push(String::from_utf16_lossy(&name[..len])); // alloc: a path a value
        }
        // SAFETY: the key opened above, closed once.
        unsafe { RegCloseKey(handle) };
    }
    match (found, denied) {
        (false, false) => Exclusions::NoDefender,
        (_, true) if paths.is_empty() => Exclusions::Unreadable,
        _ => Exclusions::Read(paths),
    }
}

/// The per-user cache directory of macOS, as the system names it.
#[cfg(target_os = "macos")]
pub fn user_cache_dir() -> Option<std::ffi::OsString> {
    use std::os::unix::ffi::OsStrExt as _;
    let mut buffer = [0u8; 1024];
    // SAFETY: `confstr` writes at most the length it is given, `buffer.len()`, to the pointer,
    // and `buffer` is writable for all of it; a length past the buffer's would have it write
    // past its end. What it says is bounds-checked against the buffer below.
    let len = unsafe {
        libc::confstr(libc::_CS_DARWIN_USER_CACHE_DIR, buffer.as_mut_ptr().cast(), buffer.len())
    };
    if len == 0 || len > buffer.len() {
        return None;
    }
    Some(std::ffi::OsStr::from_bytes(&buffer[..len - 1]).to_owned())
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    fn the_coarse_clock_steps() {
        assert!(super::coarse_clock_step().is_some_and(|it| !it.is_zero()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_user_has_a_cache_dir() {
        assert!(super::user_cache_dir().is_some_and(|it| !it.is_empty()));
    }

    #[cfg(unix)]
    #[test]
    fn columns_are_some_or_none_never_zero() {
        assert_ne!(super::stderr_columns(), Some(0));
    }
}
