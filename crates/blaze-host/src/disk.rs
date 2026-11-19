//! The real [`Files`]: `lstat`, `read` and a variable's value, under a root. The thin IO driver
//! of [`crate::outside`]; no decision is made here.

use std::{
    alloc::Global,
    io::{self, Read},
    path::{Path, PathBuf},
};
#[cfg(unix)]
use std::{
    ffi::OsStr,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
};

use blaze_core::Stamp;

use crate::outside::{Files, FilesError};

/// The files under `root`, and the process's variables.
pub struct Disk {
    root: PathBuf,
}

impl Disk {
    pub fn new(root: impl Into<PathBuf>) -> Disk {
        Disk { root: root.into() }
    }

    fn path(&self, path: &[u8]) -> PathBuf {
        #[cfg(unix)]
        {
            self.root.join(Path::new(OsStr::from_bytes(path)))
        }
        #[cfg(windows)]
        {
            let text = String::from_utf8_lossy(path);
            if text.starts_with('/') {
                blaze_core::platform::path::host(&text)
            } else {
                self.root.join(Path::new(text.as_ref()))
            }
        }
    }
}

fn errno(call: &'static str, error: &io::Error) -> FilesError {
    FilesError { call, errno: error.raw_os_error().unwrap_or(0) }
}

impl Files for Disk {
    fn stamp(&self, path: &[u8]) -> Result<Stamp, FilesError> {
        #[cfg(unix)]
        {
            match std::fs::symlink_metadata(self.path(path)) {
                Ok(meta) => Ok(Stamp {
                    ino: meta.ino(),
                    size: meta.size(),
                    mtime_ns: (meta.mtime() as u64).saturating_mul(1_000_000_000).saturating_add(meta.mtime_nsec() as u64),
                    ctime_ns: (meta.ctime() as u64).saturating_mul(1_000_000_000).saturating_add(meta.ctime_nsec() as u64),
                    mode: meta.mode(),
                }),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Stamp::GONE),
                Err(error) => Err(errno("lstat", &error)),
            }
        }
        #[cfg(windows)]
        {
            match blaze_core::fs::stamp(&self.path(path)) {
                Ok(stamp) => Ok(stamp),
                Err(error)
                    if matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory)
                        || matches!(error.raw_os_error(), Some(2 | 3 | 123 | 161 | 267)) =>
                {
                    Ok(Stamp::GONE)
                }
                Err(error) => Err(errno("lstat", &error)),
            }
        }
    }

    fn read(&self, path: &[u8], out: &mut Vec<u8, Global>) -> Result<(), FilesError> {
        out.clear();
        let mut file = std::fs::File::open(self.path(path)).map_err(|error| errno("open", &error))?;
        // Into the answerer's one buffer, kept across asks: no allocation once it has grown.
        file.read_to_end(out).map_err(|error| errno("read", &error))?;
        Ok(())
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "an outside read of a request (`env!`): the variable's value now is the answer the certificate is checked against, not configuration"
    )]
    fn var(&self, name: &[u8], out: &mut Vec<u8, Global>) -> Result<bool, FilesError> {
        out.clear();
        #[cfg(unix)]
        let found = std::env::var_os(OsStr::from_bytes(name));
        #[cfg(windows)]
        let found = std::str::from_utf8(name).ok().and_then(std::env::var_os);
        match found {
            Some(value) => {
                #[cfg(unix)]
                out.extend_from_slice(value.as_bytes());
                #[cfg(windows)]
                out.extend_from_slice(value.as_encoded_bytes());
                Ok(true)
            }
            None => Ok(false),
        }
    }
}
