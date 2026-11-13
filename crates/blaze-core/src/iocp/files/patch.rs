//! The lease is a missing public name. Persist its removal **before** touching the
//! file; persist all changed bytes before restoring the name. A crash can leave the
//! base, a missing output, or the complete result, but never a public half-patch.

use super::*;
use std::{
    fs::File,
    io::{Seek as _, SeekFrom, Write as _},
    os::windows::io::AsRawHandle as _,
    path::Path,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_DISPOSITION_INFO, FileDispositionInfo,
    GetFileInformationByHandle,
};

pub(crate) fn try_patch(
    path: &Path,
    len: u64,
    delta: &[(u64, Vec<u8>)],
    whole: &[(u64, Vec<u8>)],
) -> io::Result<bool> {
    apply(path, len, delta, whole, |_| {})
}

fn apply(
    path: &Path,
    len: u64,
    delta: &[(u64, Vec<u8>)],
    whole: &[(u64, Vec<u8>)],
    mut phase: impl FnMut(&str),
) -> io::Result<bool> {
    let name = path.to_string_lossy();
    let wide = sys::path(path)?;
    // SAFETY: an existing file, opened without following a reparse point. No other
    // data or delete handle can coexist, including a running PE image's writer.
    let handle = match crate::lock::io_wait("open output exclusively", &name, || {
        sys::owned(unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE | DELETE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        })
    }) {
        Ok(h) => h,
        Err(e) if matches!(e.raw_os_error(), Some(2 | 3 | 5 | 32)) => return Ok(false),
        Err(e) => return Err(e),
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the live file and room for the complete structure.
    sys::check(unsafe { GetFileInformationByHandle(handle.as_raw_handle(), &mut info) })?;
    if info.nNumberOfLinks != 1
        || info.dwFileAttributes
            & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY)
            != 0
    {
        return Ok(false);
    }
    let mut file = File::from(handle);
    let raw = file.as_raw_handle();
    // Share denial alone cannot detect an orphaned read-only view. Classic (NOT
    // POSIX) disposition refuses an outstanding section, even one with no file handle.
    // A process death between marking and clearing removes a disposable build output.
    let disposition = |delete| {
        let arg = FILE_DISPOSITION_INFO { DeleteFile: delete };
        // SAFETY: a live DELETE handle and the exact structure for FileDispositionInfo.
        sys::check(unsafe {
            SetFileInformationByHandle(
                raw,
                FileDispositionInfo,
                (&raw const arg).cast(),
                size_of_val(&arg) as u32,
            )
        })
    };
    match crate::lock::io_wait("exclude detached views", &name, || disposition(true)) {
        Ok(()) => crate::lock::io_wait("clear disposition", &name, || disposition(false))?,
        Err(e) if matches!(e.raw_os_error(), Some(5 | 32 | 1224)) => return Ok(false),
        Err(e) => return Err(e),
    }
    if !crate::lock::io_wait("verify prospective bytes", &name, || -> io::Result<bool> {
        // SAFETY: exclusive custody, no writes until the temporary validation view drops.
        let base = unsafe { crate::fs::Mapped::map(&file) }?;
        crate::fs::matches_patch(base.bytes(), len, delta, whole)
    })? {
        return Ok(false);
    }
    let stage = crate::fs::temporary_next_to(path);
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    crate::lock::io_wait("detach base", &name, || rename_handle(raw, &stage, 0))?;
    // durable: the old public name must not roll back over partially changed sectors.
    crate::lock::io_wait("persist detached name", &name, || crate::fs::sync_dir(dir))?;
    phase("detached");
    file.set_len(len)?;
    for (at, bytes) in delta {
        file.seek(SeekFrom::Start(*at))?;
        file.write_all(bytes)?;
        phase("range");
    }
    // durable: publication cannot outrun any byte of the result.
    crate::lock::io_wait("persist patched bytes", &name, || file.sync_all())?;
    phase("synced");
    crate::lock::io_wait("return patched file", &name, || rename_handle(raw, path, 0))?;
    crate::lock::io_wait("persist returned name", &name, || crate::fs::sync_dir(dir))?;
    phase("published");
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, process::Command};

    // In a subprocess so every handle closes at the injected point, without unwinding.
    #[test]
    fn custody_crash_child() {
        let Some(path) = std::env::var_os("BLAZE_TEST_PATCH_TARGET") else { return };
        let target = std::env::var("BLAZE_TEST_PATCH_PHASE").unwrap();
        let patch = [(1, vec![8]), (4, vec![9])];
        let expected = [(0, vec![1, 8, 3, 4, 9])];
        assert!(
            apply(Path::new(&path), 5, &patch, &expected, |phase| {
                if target == phase {
                    std::process::exit(37)
                }
            })
            .unwrap()
        );
    }

    #[test]
    fn a_process_death_in_a_patch_leaves_no_torn_public_name() {
        let root = std::env::temp_dir().join(format!("blaze-patch-death-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("app.exe");
        for phase in ["detached", "range", "synced", "published"] {
            fs::write(&path, [1, 2, 3, 4, 5]).unwrap();
            let killed = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "iocp::files::patch::tests::custody_crash_child"])
                .env("BLAZE_TEST_PATCH_TARGET", &path)
                .env("BLAZE_TEST_PATCH_PHASE", phase)
                .output()
                .unwrap();
            assert_eq!(
                killed.status.code(),
                Some(37),
                "{phase}: {}",
                String::from_utf8_lossy(&killed.stdout)
            );
            if phase == "published" {
                assert_eq!(fs::read(&path).unwrap(), [1, 8, 3, 4, 9]);
            } else {
                assert_eq!(fs::read(&path).unwrap_err().kind(), io::ErrorKind::NotFound);
            }
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn changed_bytes_links_and_orphaned_read_views_are_not_patch_bases() {
        let root = std::env::temp_dir().join(format!("blaze-patch-base-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("out");
        fs::write(&path, b"abcd").unwrap();
        let delta = [(1, vec![b'x'])];
        assert!(!try_patch(&path, 4, &delta, &[(0, b"axcy".to_vec())]).unwrap());
        let patch = || try_patch(&path, 4, &delta, &[(0, b"axcd".to_vec())]).unwrap();
        let other = root.join("other");
        fs::hard_link(&path, &other).unwrap();
        assert!(!patch());
        fs::remove_file(other).unwrap();
        // Make a read-only section with NO remaining file handle, as an external reader can.
        use std::os::windows::io::FromRawHandle as _;
        use windows_sys::Win32::System::Memory::{
            CreateFileMappingW, FILE_MAP_READ, MapViewOfFile, PAGE_READONLY, UnmapViewOfFile,
        };
        let file = File::open(&path).unwrap();
        // SAFETY: live file; valid unnamed read-only section, zero means the file's actual size.
        let section = unsafe {
            CreateFileMappingW(
                file.as_raw_handle(),
                std::ptr::null(),
                PAGE_READONLY,
                0,
                0,
                std::ptr::null(),
            )
        };
        assert!(!section.is_null());
        let section = unsafe { OwnedHandle::from_raw_handle(section) };
        let view = unsafe { MapViewOfFile(section.as_raw_handle(), FILE_MAP_READ, 0, 0, 0) };
        assert!(!view.Value.is_null());
        drop((section, file));
        assert!(!patch());
        assert_eq!(fs::read(&path).unwrap(), b"abcd");
        assert_ne!(unsafe { UnmapViewOfFile(view) }, 0);
        assert!(patch());
        assert_eq!(fs::read(&path).unwrap(), b"axcd");
        fs::remove_dir_all(root).unwrap();
    }
}
