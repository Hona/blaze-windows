//! Whether the files of a volume can share blocks, asked once of the volume a store or a
//! build directory is on: what decides how an output gets to its path
//! (docs/v2/plan/design/clone-out.md, "Volumes that share no blocks").
//!
//! [`crate::Effect::Clone`] makes a file that shares another's blocks, or fails: nothing
//! copies instead. So a state machine that places files is told, before it asks for any, what
//! the volume can do ([`Sharing`]), and on a volume that cannot it never asks for a clone: it
//! writes the bytes it holds where they go. The choice is the volume's, made once, and never
//! a clone tried and a copy made when it fails (rule no-fallback).
//!
//! - Windows: the volume's `FILE_SUPPORTS_BLOCK_REFCOUNTING` flag (`GetVolumeInformationByHandleW`),
//!   one open of the directory for its attributes: set on ReFS (a Dev Drive among them),
//!   clear on NTFS, FAT and network shares.
//! - Linux and macOS: no flag says it for every file system (XFS shares blocks only when made
//!   with `reflink=1`, and ext4 never), so a clone is made, of a file of five bytes the probe
//!   writes under the directory, and both files are removed: `FICLONE` or `clonefile` either
//!   shares or is refused with the error a clone of an output would get.
//! - WASI: none can (`fs::wasi`'s clone is refused).

use std::{io, path::Path};

/// Whether files on a volume can share blocks.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Sharing {
    /// A clone shares blocks (ReFS, APFS, Btrfs, XFS made with reflinks, bcachefs, ZFS 2.2):
    /// [`crate::Effect::Clone`] works, and copies nothing.
    Blocks,
    /// No two files share a block (NTFS, ext4, tmpfs, most network file systems): a clone is
    /// refused, so a file's bytes are written where it goes.
    Unshared,
}

impl Sharing {
    /// What a span or a status line says of it.
    pub fn name(self) -> &'static str {
        match self {
            Sharing::Blocks => "shares blocks",
            Sharing::Unshared => "shares no blocks",
        }
    }
}

/// What [`volume`] found of a volume.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Volume {
    /// The file system, as the system names it (`NTFS`, `ReFS`; `xfs (magic ...)`).
    pub system: String,
    pub sharing: Sharing,
}

/// The volume `path` is on, judged by the nearest of it and its ancestors that exists (a
/// directory not made yet is made on its parent's volume). An error names the path.
pub fn volume(path: &Path) -> io::Result<Volume> {
    let mut at = path;
    loop {
        match std::fs::symlink_metadata(at) {
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                at = at.parent().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        // alloc: an error path.
                        format!("no ancestor of {} exists to say its volume", path.display()),
                    )
                })?;
            }
            Err(error) => return Err(named(at, error)),
        }
    }
    let (system, shares) = ask(at).map_err(|error| named(at, error))?;
    let sharing = if shares { Sharing::Blocks } else { Sharing::Unshared };
    Ok(Volume { system, sharing })
}

fn named(path: &Path, error: io::Error) -> io::Error {
    // alloc: an error path.
    io::Error::new(error.kind(), format!("the volume of {}: {error}", path.display()))
}

#[cfg(windows)]
fn ask(at: &Path) -> io::Result<(String, bool)> {
    crate::iocp::files::volume(at)
}

#[cfg(unix)]
fn ask(at: &Path) -> io::Result<(String, bool)> {
    let dir = match std::fs::metadata(at)?.is_dir() {
        true => at,
        false => at.parent().unwrap_or(at),
    };
    let system = crate::fs::volume_of(dir);
    let word: u64 = std::random::random(..);
    // alloc: the probe's two names, once per volume asked.
    let stem = format!(".blaze-sharing.{}.{word:016x}", std::process::id());
    let (from, to) = (dir.join(format!("{stem}.from")), dir.join(format!("{stem}.to")));
    std::fs::write(&from, b"blaze")?;
    let cloned = crate::fs::clone(&from, &to);
    // The probe's files go whatever the clone did; one not there is no error.
    _ = std::fs::remove_file(&to);
    _ = std::fs::remove_file(&from);
    match cloned {
        Ok(()) => Ok((system, true)),
        // What `fs::clone` says of a file system that refuses to share: the error a clone of
        // an output would get.
        Err(error) if error.kind() == io::ErrorKind::Unsupported => Ok((system, false)),
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "wasi")]
fn ask(_: &Path) -> io::Result<(String, bool)> {
    Ok(("WASI".into(), false))
}

#[cfg(test)]
mod tests;
