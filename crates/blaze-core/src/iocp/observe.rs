//! An observer's handles on Windows: every handle the driver opens on something it only looks
//! at (a stamp, a directory's listing, a whole file read, a name asked of a reference number)
//! holds a read-handle oplock from its open on.
//!
//! NTFS refuses to rename or remove a directory while any handle is open on a file or
//! directory under it, whatever that handle shares (`ERROR_ACCESS_DENIED`). A plain handle of
//! the watch's on `p/.tmpX/CACHEDIR.TAG`, open for the microseconds a stamp or a name takes,
//! failed cargo's rename of `p/.tmpX` to `p/target` (its atomic making of `target`, I32): blaze
//! and another program could not share a directory. A handle under a handle-caching oplock is
//! not in the way: the rename breaks the oplock, waits until the holder closes, and goes on
//! (1-2 ms measured on Windows 11 26100), which is how the system's indexer looks at files. An
//! observer closes as its look ends, so it never acknowledges a break: it ends sooner than one.
//!
//! The oplock is asked in the open itself (`NtCreateFile` with `FILE_OPEN_REQUIRING_OPLOCK`,
//! then `FSCTL_REQUEST_OPLOCK` for read and handle caching), so no rename meets the handle
//! between the two. It needs an overlapped handle, so every look on an [`Observed`] is a call
//! that answers at once (an information query) or an overlapped one waited on here
//! (`blaze_core::wait::signaled`): a read, a listing.

use std::{io, sync::atomic::AtomicU64, sync::atomic::Ordering};

use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FILE_INFORMATION_CLASS, FILE_OPEN, FILE_OPEN_BY_FILE_ID, FILE_OPEN_FOR_BACKUP_INTENT,
            FILE_OPEN_REPARSE_POINT, FILE_OPEN_REQUIRING_OPLOCK, NtCreateFile,
            NtQueryDirectoryFile,
        },
    },
    Win32::{
        Foundation::{
            CloseHandle, ERROR_HANDLE_EOF, ERROR_IO_PENDING, HANDLE, NTSTATUS, OBJ_CASE_INSENSITIVE,
            RtlNtStatusToDosError, STATUS_NO_MORE_FILES, STATUS_PENDING, UNICODE_STRING,
        },
        Storage::FileSystem::{
            FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, ReadFile,
        },
        System::{
            IO::{DeviceIoControl, GetOverlappedResult, IO_STATUS_BLOCK, OVERLAPPED},
            Ioctl::{
                FSCTL_REQUEST_OPLOCK, OPLOCK_LEVEL_CACHE_HANDLE, OPLOCK_LEVEL_CACHE_READ,
                REQUEST_OPLOCK_CURRENT_VERSION, REQUEST_OPLOCK_INPUT_BUFFER,
                REQUEST_OPLOCK_INPUT_FLAG_REQUEST, REQUEST_OPLOCK_OUTPUT_BUFFER,
            },
            Threading::{CreateEventW, ResetEvent},
        },
    },
};

use super::sys;
use crate::wait::{self, Deadline, Monotonic, Waited};

/// How long a closed observer waits for its oplock's request to end: the close ends it at
/// once, so this bounds a kernel that does not, never a wait that happens.
const CLOSED_WITHIN: std::time::Duration = std::time::Duration::from_secs(5);

/// Oplock requests whose end a close did not bring within [`CLOSED_WITHIN`]: their buffers are
/// kept for the kernel, never freed under it.
static KEPT_FOR_THE_KERNEL: AtomicU64 = AtomicU64::new(0);

/// What an observer opens.
#[derive(Clone, Copy)]
pub(super) enum At<'a> {
    /// A path as [`sys::path`] makes it: verbatim (`\\?\`), NUL-terminated.
    Path(&'a [u16]),
    /// A reference number on the volume of `root`, an open handle there.
    Id { root: HANDLE, id: u128 },
}

/// How an observer opens what it looks at.
#[derive(Clone, Copy)]
pub(super) struct Open {
    /// What it asks: at least `FILE_READ_ATTRIBUTES`, without which no oplock is granted.
    pub access: u32,
    /// A link or junction itself, not what it names.
    pub link_itself: bool,
}

/// An observer's handle, under its read-handle oplock until it is dropped.
pub(super) struct Observed {
    handle: HANDLE,
    /// `None` only as it is dropped.
    oplock: Option<Box<Oplock>>,
}

/// What the kernel writes as the oplock's request ends: kept where it is until then.
struct Oplock {
    overlapped: OVERLAPPED,
    output: REQUEST_OPLOCK_OUTPUT_BUFFER,
    event: HANDLE,
}

// SAFETY: the handle and the event are the observer's alone, used from one thread at a time;
// the kernel's writes into `oplock` are synchronised by its event.
unsafe impl Send for Observed {}

/// `status` as the Win32 error it maps to.
fn status_error(status: NTSTATUS) -> io::Error {
    // SAFETY: a pure mapping of a number.
    io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32)
}

/// An event of the caller's, manual-reset, unsignaled.
fn event() -> io::Result<HANDLE> {
    // SAFETY: no security attributes or name.
    let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    if event.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(event)
}

/// Opens `at` as `how` asks, with a read-handle oplock taken in the same call. The error is
/// the system's, unnamed: the caller names the file. A file another holds under an oplock this
/// one would break (a writer's own caching) is `ERROR_CANNOT_BREAK_OPLOCK`: looked at again once
/// that writer's change is told.
pub(super) fn open(at: At<'_>, how: Open) -> io::Result<Observed> {
    let mut nt;
    let id;
    let (name, root, mut options, attributes) = match at {
        At::Path(wide) => {
            // `\\?\C:\x` is `\??\C:\x` to the kernel; the same for `\\?\UNC\`.
            let verbatim = [b'\\', b'\\', b'?', b'\\'].map(u16::from);
            let path = wide.strip_suffix(&[0]).unwrap_or(wide);
            if !path.starts_with(&verbatim) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "an observed path is verbatim (\\\\?\\)",
                ));
            }
            nt = NAME.take();
            nt.clear();
            nt.extend_from_slice(path);
            nt[1] = u16::from(b'?');
            (nt.as_mut_ptr(), std::ptr::null_mut(), 0, OBJ_CASE_INSENSITIVE)
        }
        At::Id { root, id: number } => {
            id = number.to_le_bytes();
            nt = Vec::new();
            (id.as_ptr().cast_mut().cast::<u16>(), root, FILE_OPEN_BY_FILE_ID, 0)
        }
    };
    let bytes = match at {
        At::Path(_) => nt.len() * 2,
        At::Id { .. } => 16,
    };
    let unicode = UNICODE_STRING { Length: bytes as u16, MaximumLength: bytes as u16, Buffer: name };
    let object = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root,
        ObjectName: &unicode,
        Attributes: attributes,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    options |= FILE_OPEN_REQUIRING_OPLOCK | FILE_OPEN_FOR_BACKUP_INTENT;
    if how.link_itself {
        options |= FILE_OPEN_REPARSE_POINT;
    }
    // SAFETY: all zeros is a valid status block.
    let mut status_block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let mut handle: HANDLE = std::ptr::null_mut();
    // SAFETY: `object` names a live string of the length it says (the path's units or the
    // reference number's 16 bytes) and, by number, an open root handle of the caller's; the
    // handle and the status block are live for the call to write. No synchronous option: the
    // handle is overlapped, as an oplock needs.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            how.access,
            &object,
            &mut status_block,
            std::ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            options,
            std::ptr::null(),
            0,
        )
    };
    NAME.set(nt);
    if status < 0 {
        return Err(status_error(status));
    }
    let mut oplock = match Oplock::take() {
        Ok(oplock) => oplock,
        Err(error) => {
            // SAFETY: the handle NtCreateFile just made, closed once.
            unsafe { CloseHandle(handle) };
            return Err(error);
        }
    };
    let input = REQUEST_OPLOCK_INPUT_BUFFER {
        StructureVersion: REQUEST_OPLOCK_CURRENT_VERSION as u16,
        StructureLength: size_of::<REQUEST_OPLOCK_INPUT_BUFFER>() as u16,
        RequestedOplockLevel: OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE,
        Flags: REQUEST_OPLOCK_INPUT_FLAG_REQUEST,
    };
    // SAFETY: an overlapped handle, the input read during the call, and an output record and
    // `OVERLAPPED` in the box, which stays where it is until the request ends ([`Drop`]).
    let ok = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_REQUEST_OPLOCK,
            (&raw const input).cast(),
            size_of::<REQUEST_OPLOCK_INPUT_BUFFER>() as u32,
            (&raw mut oplock.output).cast(),
            size_of::<REQUEST_OPLOCK_OUTPUT_BUFFER>() as u32,
            std::ptr::null_mut(),
            &raw mut oplock.overlapped,
        )
    };
    // Granted, the request waits for the oplock's break or close; one that ended at once was
    // refused, and the handle is then in another's way: no look is made through it.
    let refused = match (ok, sys::last()) {
        (0, ERROR_IO_PENDING) => return Ok(Observed { handle, oplock: Some(oplock) }),
        (0, code) => io::Error::from_raw_os_error(code as i32),
        _ => io::Error::other("FSCTL_REQUEST_OPLOCK ended at once: the oplock was not granted"),
    };
    // SAFETY: the handle NtCreateFile made, closed once; no request of it is pending.
    unsafe { CloseHandle(handle) };
    Oplock::give(oplock);
    Err(refused)
}

/// The whole file at `wide` (verbatim, NUL-terminated), read through an observer: what
/// `Effect::ReadAll` reads.
pub(super) fn read_whole(wide: &[u16]) -> io::Result<Vec<u8>> {
    open(At::Path(wide), Open { access: FILE_READ_DATA | FILE_READ_ATTRIBUTES, link_itself: false })?
        .read_whole()
}

impl Observed {
    pub(super) fn raw(&self) -> HANDLE {
        self.handle
    }

    /// The whole file, read from its start until a read comes back short: its length asked
    /// first, so a file that does not grow meanwhile is one read.
    pub(super) fn read_whole(&self) -> io::Result<Vec<u8>> {
        let size = usize::try_from(super::files::size(self.handle)?).unwrap_or(usize::MAX);
        // alloc: the bytes read, `Done::Read`'s payload, which the reads write in place.
        let mut bytes = Vec::with_capacity(size.saturating_add(1));
        let done = Waiter::new()?;
        loop {
            if bytes.len() == bytes.capacity() {
                // alloc: the file grew after its length was asked.
                bytes.reserve(bytes.capacity().max(4096));
            }
            let room = (bytes.capacity() - bytes.len()).min(u32::MAX as usize);
            let at = bytes.len() as u64;
            // SAFETY: all zeros is a valid `OVERLAPPED`; its offset and event are set below.
            let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
            overlapped.Anonymous.Anonymous.Offset = at as u32;
            overlapped.Anonymous.Anonymous.OffsetHigh = (at >> 32) as u32;
            overlapped.hEvent = done.event;
            // SAFETY: the `Vec`'s spare room, `room` bytes, and `overlapped` stay where they
            // are until the read has ended: `done.wait` returns only then.
            let ok = unsafe {
                ReadFile(
                    self.handle,
                    bytes.spare_capacity_mut().as_mut_ptr().cast(),
                    room as u32,
                    std::ptr::null_mut(),
                    &mut overlapped,
                )
            };
            let got = match done.wait(self.handle, &overlapped, ok, "a read of an observed file") {
                Ok(got) => got as usize,
                Err(error) if error.raw_os_error() == Some(ERROR_HANDLE_EOF as i32) => 0,
                Err(error) => return Err(error),
            };
            // SAFETY: the read wrote `got` bytes, at most `room`, from the start of the room.
            unsafe { bytes.set_len(bytes.len() + got.min(room)) };
            if got < room {
                return Ok(bytes);
            }
        }
    }

    /// The next entries of the directory into `buffer` (`class`'s records, 8-aligned), from the
    /// first where `restart`: `false` once there are no more.
    pub(super) fn list(&self, buffer: &mut [u64], class: FILE_INFORMATION_CLASS, restart: bool) -> io::Result<bool> {
        let done = Waiter::new()?;
        // SAFETY: all zeros is a valid status block.
        let mut status_block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
        let length = u32::try_from(buffer.len() * 8).unwrap_or(u32::MAX);
        // SAFETY: an open directory handle, the buffer of the length given and the status
        // block, which stay where they are until the query has ended: its event is waited on
        // below whenever it pends.
        let mut status = unsafe {
            NtQueryDirectoryFile(
                self.handle,
                done.event,
                None,
                std::ptr::null(),
                &mut status_block,
                buffer.as_mut_ptr().cast(),
                length,
                class,
                false,
                std::ptr::null(),
                restart,
            )
        };
        if status == STATUS_PENDING {
            done.signaled("a listing of an observed directory")?;
            // SAFETY: the query ended (its event is set), so the kernel wrote its status.
            status = unsafe { status_block.Anonymous.Status };
        }
        match status {
            STATUS_NO_MORE_FILES => Ok(false),
            status if status < 0 => Err(status_error(status)),
            _ => Ok(true),
        }
    }
}

impl Drop for Observed {
    fn drop(&mut self) {
        // SAFETY: the handle `open` made, closed once; the close ends the oplock's request.
        unsafe { CloseHandle(self.handle) };
        let Some(oplock) = self.oplock.take() else { return };
        let clock = Monotonic::new();
        let deadline = Deadline::after(wait::Clock::now(&clock), CLOSED_WITHIN);
        let ended = wait::signaled(
            "the end of a closed observer's oplock request",
            oplock.event,
            Some(deadline),
            &clock,
        );
        if !matches!(ended, Ok(Waited::Ready(()))) {
            // The kernel may still write the request's record: keep it, never free it under it.
            KEPT_FOR_THE_KERNEL.fetch_add(1, Ordering::Relaxed);
            std::mem::forget(oplock);
            return;
        }
        Oplock::give(oplock);
    }
}
thread_local! {
    /// The kernel's name of the path a look on this thread opens, its buffer kept.
    static NAME: std::cell::Cell<Vec<u16>> = const { std::cell::Cell::new(Vec::new()) };
    /// Ended oplock requests of this thread's looks, their events kept, for the next looks: a
    /// warm look allocates nothing.
    static SPARE: std::cell::RefCell<Vec<Box<Oplock>>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// The most ended requests a thread keeps.
const SPARE_MOST: usize = 8;

impl Oplock {
    /// An ended request of this thread's, its event unsignaled, or a new one.
    fn take() -> io::Result<Box<Oplock>> {
        let mut oplock = match SPARE.with_borrow_mut(Vec::pop) {
            Some(oplock) => {
                // SAFETY: the request's own event, which no call names now.
                sys::check(unsafe { ResetEvent(oplock.event) })?;
                oplock
            }
            // alloc: a request, once per thread up to `SPARE_MOST` looks at once.
            None => Box::new(Oplock { event: event()?, ..Oplock::spent() }),
        };
        // SAFETY: all zeros is a valid `OVERLAPPED` and output record.
        oplock.overlapped = unsafe { std::mem::zeroed() };
        oplock.output = unsafe { std::mem::zeroed() };
        oplock.overlapped.hEvent = oplock.event;
        Ok(oplock)
    }

    /// `oplock`, ended, kept for this thread's next look, or let go.
    fn give(oplock: Box<Oplock>) {
        let kept = SPARE.with_borrow_mut(|spare| {
            let room = spare.len() < SPARE_MOST;
            if room {
                spare.push(oplock);
                return None;
            }
            Some(oplock)
        });
        if let Some(oplock) = kept {
            // SAFETY: the request's own event; the request has ended.
            unsafe { CloseHandle(oplock.event) };
        }
    }

    /// A request that never was, in the place of one kept for the kernel.
    fn spent() -> Oplock {
        // SAFETY: all zeros is a valid `OVERLAPPED` and output record; a null event is closed
        // by no one.
        Oplock { overlapped: unsafe { std::mem::zeroed() }, output: unsafe { std::mem::zeroed() }, event: std::ptr::null_mut() }
    }
}

/// The event one overlapped look on an observer waits on.
struct Waiter {
    event: HANDLE,
}

impl Waiter {
    fn new() -> io::Result<Waiter> {
        Ok(Waiter { event: event()? })
    }

    fn signaled(&self, what: &'static str) -> io::Result<()> {
        match wait::signaled(what, self.event, None, &Monotonic::new()) {
            Ok(_) => Ok(()),
            Err(error) => Err(io::Error::other(error.to_string())),
        }
    }

    /// What the overlapped call that returned `ok` on `handle` with `overlapped` transferred,
    /// once it has ended.
    fn wait(&self, handle: HANDLE, overlapped: &OVERLAPPED, ok: i32, what: &'static str) -> io::Result<u32> {
        if ok == 0 && sys::last() != ERROR_IO_PENDING {
            return Err(io::Error::last_os_error());
        }
        if ok == 0 {
            self.signaled(what)?;
        }
        let mut got = 0u32;
        // SAFETY: the call ended (it returned done, or its event is set), so this only reads
        // its result.
        sys::check(unsafe { GetOverlappedResult(handle, overlapped, &mut got, 0) })?;
        Ok(got)
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        // SAFETY: the event `new` made; every call that named it has ended.
        unsafe { CloseHandle(self.event) };
    }
}

/// Oplock requests kept for the kernel past their close ([`KEPT_FOR_THE_KERNEL`]).
#[cfg(test)]
pub(super) fn kept_for_the_kernel() -> u64 {
    KEPT_FOR_THE_KERNEL.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use std::os::windows::io::AsRawHandle as _;

    use super::*;

    /// A directory of its own under the system's temporary directory, removed after.
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("blaze-observe-{name}-{}", std::process::id()));
        _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".tmpX")).unwrap();
        std::fs::write(dir.join(".tmpX/CACHEDIR.TAG"), b"Signature: 8a477f597d28d172789f06886806bc55\n").unwrap();
        dir
    }

    /// The invariant: a handle the driver looks through is never in the way of another
    /// program's rename of a directory above it (I32: cargo makes `target` by renaming a
    /// temporary sibling holding `CACHEDIR.TAG`). The rename waits for the observer to close
    /// and goes on. The control: a plain handle, sharing everything, fails the same rename with
    /// `ERROR_ACCESS_DENIED`, which is what cargo met.
    #[test]
    fn a_rename_above_an_observed_file_waits_for_it_where_a_plain_handle_fails_it() {
        let dir = scratch("rename");
        let plain = std::fs::File::open(dir.join(".tmpX/CACHEDIR.TAG")).unwrap();
        let refused = std::fs::rename(dir.join(".tmpX"), dir.join("target")).unwrap_err();
        assert_eq!(refused.raw_os_error(), Some(5), "the control: {refused}");
        drop(plain);

        let wide = sys::path(&dir.join(".tmpX/CACHEDIR.TAG")).unwrap();
        let observed = open(At::Path(&wide), Open { access: FILE_READ_ATTRIBUTES | FILE_READ_DATA, link_itself: true }).unwrap();
        assert_eq!(observed.read_whole().unwrap().len(), 44);
        let (from, to) = (dir.join(".tmpX"), dir.join("target"));
        let renamer = std::thread::spawn(move || std::fs::rename(from, to));
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!renamer.is_finished(), "the rename waits for the observer to close");
        drop(observed);
        renamer.join().unwrap().unwrap();
        assert!(dir.join("target/CACHEDIR.TAG").is_file());
        assert_eq!(kept_for_the_kernel(), 0);
        _ = std::fs::remove_dir_all(&dir);
    }

    /// The same of a file opened by its reference number, as the journal's names are asked, and
    /// of a directory listed: neither is in the way of a rename above it.
    #[test]
    fn a_name_asked_by_number_and_a_listing_are_not_in_the_way_of_a_rename() {
        let dir = scratch("by-id");
        let root = std::fs::File::open(&dir).unwrap_or_else(|_| {
            use std::os::windows::fs::OpenOptionsExt as _;
            std::fs::OpenOptions::new().read(true).custom_flags(0x0200_0000).open(&dir).unwrap()
        });
        let file = std::fs::File::open(dir.join(".tmpX/CACHEDIR.TAG")).unwrap();
        let mut info = windows_sys::Win32::Storage::FileSystem::FILE_ID_INFO::default();
        // SAFETY: an open handle and room for the class's record.
        let ok = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandleEx(
                file.as_raw_handle(),
                windows_sys::Win32::Storage::FileSystem::FileIdInfo,
                (&raw mut info).cast(),
                size_of_val(&info) as u32,
            )
        };
        assert_ne!(ok, 0);
        drop(file);
        let id = u128::from_le_bytes(info.FileId.Identifier);
        let named = open(At::Id { root: root.as_raw_handle(), id }, Open { access: FILE_READ_ATTRIBUTES, link_itself: true }).unwrap();
        let wide = sys::path(&dir.join(".tmpX")).unwrap();
        let listed = open(At::Path(&wide), Open { access: FILE_READ_ATTRIBUTES | 1, link_itself: false }).unwrap();
        let mut buffer = vec![0u64; 1024];
        let class = windows_sys::Wdk::Storage::FileSystem::FileIdBothDirectoryInformation;
        assert!(listed.list(&mut buffer, class, true).unwrap(), "a listing has `.`, `..` and the file");
        let (from, to) = (dir.join(".tmpX"), dir.join("target"));
        let renamer = std::thread::spawn(move || std::fs::rename(from, to));
        std::thread::sleep(std::time::Duration::from_millis(50));
        drop(named);
        drop(listed);
        renamer.join().unwrap().unwrap();
        drop(root);
        _ = std::fs::remove_dir_all(&dir);
    }
}