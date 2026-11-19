//! Locks on files that only other lockers see: what `stdx::file_lock::Locked` takes.
//!
//! On Unix a lock (`flock`) is advisory: it stops another `flock` and no read or write. On
//! Windows std's `File::lock` is `LockFileEx` of the whole file, and a byte range locked there
//! is mandatory: every read and write of it through any other handle fails, this process's own
//! included (`ERROR_LOCK_VIOLATION`, os error 33). A download's partial file, locked so a
//! second download of the same pin does not resume it, then could not be read back to be
//! checked. So on Windows the lock is of one byte at the last offset a file can have, which no
//! read or write ever reaches: lockers exclude each other as with `flock`, and the bytes stay
//! free to every handle.

use std::{fs::File, io};

/// What [`lock`] asks for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Shared,
    Exclusive,
}

/// `file` locked as `mode` asks, waiting for another holder to let go when `wait`: `Ok(false)`
/// when it would have to wait and `wait` is false.
pub fn lock(file: &File, mode: Mode, wait: bool) -> io::Result<bool> {
    imp::lock(file, mode, wait)
}

/// The lock [`lock`] took of `file` let go of.
pub fn unlock(file: &File) -> io::Result<()> {
    imp::unlock(file)
}

#[cfg(windows)]
#[allow(unsafe_code, reason = "LockFileEx and UnlockFileEx of an open handle, each one call")]
mod imp {
    use std::{fs::File, io, os::windows::io::AsRawHandle as _};

    use windows_sys::Win32::{
        Foundation::{ERROR_IO_PENDING, ERROR_LOCK_VIOLATION},
        Storage::FileSystem::{
            LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, UnlockFileEx,
        },
        System::IO::OVERLAPPED,
    };

    use super::Mode;

    /// The one byte locked: the last offset a file can have, past any byte read or written.
    const AT: u64 = u64::MAX - 1;

    fn at() -> OVERLAPPED {
        // SAFETY: all zeros is a valid OVERLAPPED (no event, offset 0) of plain integers.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.Anonymous.Anonymous.Offset = AT as u32;
        overlapped.Anonymous.Anonymous.OffsetHigh = (AT >> 32) as u32;
        overlapped
    }

    pub(super) fn lock(file: &File, mode: Mode, wait: bool) -> io::Result<bool> {
        let mut flags = 0;
        if mode == Mode::Exclusive {
            flags |= LOCKFILE_EXCLUSIVE_LOCK;
        }
        if !wait {
            flags |= LOCKFILE_FAIL_IMMEDIATELY;
        }
        let mut overlapped = at();
        // SAFETY: an open handle and an OVERLAPPED that outlives the call. A handle opened for
        // overlapped IO returns `ERROR_IO_PENDING` for a lock that waits, which no handle std
        // opens is.
        let locked = unsafe { LockFileEx(file.as_raw_handle(), flags, 0, 1, 0, &mut overlapped) };
        if locked != 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error().map(|it| it as u32) {
            Some(ERROR_LOCK_VIOLATION) if !wait => Ok(false),
            Some(ERROR_IO_PENDING) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a file opened for overlapped IO cannot be locked by waiting",
            )),
            _ => Err(error),
        }
    }

    pub(super) fn unlock(file: &File) -> io::Result<()> {
        let mut overlapped = at();
        // SAFETY: an open handle and an OVERLAPPED that outlives the call.
        if unsafe { UnlockFileEx(file.as_raw_handle(), 0, 1, 0, &mut overlapped) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(not(windows))]
mod imp {
    use std::{
        fs::{File, TryLockError},
        io,
    };

    use super::Mode;

    pub(super) fn lock(file: &File, mode: Mode, wait: bool) -> io::Result<bool> {
        #[allow(
            clippy::disallowed_methods,
            reason = "the one place a file is locked: stdx's Locked unlocks it as it drops"
        )]
        let tried = match (mode, wait) {
            (Mode::Exclusive, true) => file.lock().map_err(TryLockError::Error),
            (Mode::Shared, true) => file.lock_shared().map_err(TryLockError::Error),
            (Mode::Exclusive, false) => file.try_lock(),
            (Mode::Shared, false) => file.try_lock_shared(),
        };
        match tried {
            Ok(()) => Ok(true),
            Err(TryLockError::WouldBlock) => Ok(false),
            Err(TryLockError::Error(error)) => Err(error),
        }
    }

    pub(super) fn unlock(file: &File) -> io::Result<()> {
        file.unlock()
    }
}

#[cfg(test)]
mod tests;
