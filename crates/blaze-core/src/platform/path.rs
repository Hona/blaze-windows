//! The one boundary between the daemon's names of paths and the system's.
//!
//! The daemon names every path from one root, `/`-separated (docs/platforms.md, "Paths"): on
//! Unix that is the system's own absolute path; on Windows the volume is the first part,
//! `C:\a\b` named `/C:/a/b` (the drive letter upper-cased) and `\\server\share\a` named
//! `/UNC/server/share/a`. That one-root model is what the VFS's mounts, the keys and the
//! wire carry, the same on every system.
//!
//! The system never opens such a name: on Windows `Path::new("/C:/a")` is a path from the
//! root of the *current* drive, `\C:\a`, which `is_absolute` calls relative and every call
//! opens wrongly. So a name goes to the system only through [`host`], and a path comes from
//! the system only through [`daemon`]: nothing else converts between them.

use std::path::{Path, PathBuf};

/// What [`daemon`] refuses: a path that is not absolute, or (on Windows, or anywhere the
/// wire carries it) not UTF-8.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PathError {
    /// The path as the system shows it.
    pub path: String,
    pub why: &'static str,
}

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the path {} {}", self.path, self.why)
    }
}

impl std::error::Error for PathError {}

/// The daemon's name of `path`, an absolute path as the system gives it: on Windows
/// `C:\a` (or `c:/a`, or `\\?\C:\a`) is `/C:/a`, and `\\server\share\a` (or
/// `\\?\UNC\server\share\a`) is `/UNC/server/share/a`. Nothing is resolved or looked up:
/// `.` and `..` stay as they are written, and the case of every part but the drive letter is
/// the caller's.
///
/// # Errors
///
/// A path that is not UTF-8, which the daemon cannot name, and one that is not absolute (on
/// Windows also `C:a`, relative to a drive's current directory, and `\a`, from the root of
/// the current drive): each names the path.
pub fn daemon(path: &Path) -> Result<String, PathError> {
    let Some(text) = path.to_str() else {
        // alloc: an error path
        return Err(PathError { path: path.display().to_string(), why: "is not UTF-8, which the daemon can't name" });
    };
    // alloc: an error path
    daemon_of(text).ok_or_else(|| PathError { path: text.to_owned(), why: "is not absolute" })
}

/// [`daemon`] of a path's text, or `None` where it is not absolute.
#[cfg(windows)]
fn daemon_of(text: &str) -> Option<String> {
    // alloc: the name, which the caller owns
    let slashed = |rest: &str| rest.replace('\\', "/");
    // Verbatim (`\\?\`) and device (`\\.\`) prefixes name the same file without one.
    let plain = text
        .strip_prefix(r"\\?\")
        .or_else(|| text.strip_prefix(r"\\.\"))
        .or_else(|| text.strip_prefix("//?/"));
    if let Some(rest) = plain {
        if let Some(unc) = rest.strip_prefix(r"UNC\").or_else(|| rest.strip_prefix("UNC/")) {
            return share(&slashed(unc));
        }
        return drive(&slashed(rest));
    }
    let text = slashed(text);
    match text.strip_prefix("//") {
        Some(unc) => share(&unc),
        None => drive(&text),
    }
}

/// `C:/a` as `/C:/a`: a drive letter, its colon and the root after it.
#[cfg(windows)]
fn drive(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let rooted = bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/';
    let bare = bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if bare {
        // `C:` alone is the drive's current directory: relative.
        return None;
    }
    // alloc: the name, which the caller owns
    rooted.then(|| format!("/{}{}", char::from(bytes[0].to_ascii_uppercase()), &text[1..]))
}

/// `server/share/a` as `/UNC/server/share/a`: a server and a share, both named.
#[cfg(windows)]
fn share(text: &str) -> Option<String> {
    let mut parts = text.splitn(3, '/');
    let (server, share) = (parts.next()?, parts.next()?);
    if server.is_empty() || share.is_empty() {
        return None;
    }
    // alloc: the name, which the caller owns
    Some(match parts.next() {
        Some(rest) => format!("/UNC/{server}/{share}/{rest}"),
        None => format!("/UNC/{server}/{share}"),
    })
}

#[cfg(not(windows))]
fn daemon_of(text: &str) -> Option<String> {
    // alloc: the name, which the caller owns
    Path::new(text).is_absolute().then(|| text.to_owned())
}

/// The system's path of `name`, a path the daemon named: [`daemon`]'s inverse. On Windows
/// `/C:/a` is `C:\a`, `/C:` the drive's root `C:\`, and `/UNC/server/share/a` is
/// `\\server\share\a`; std adds the verbatim prefix a path past `MAX_PATH` needs where it opens
/// one. A name that is none of these (a relative one) comes back as written, with `\`
/// between its parts, so a check that it is absolute still refuses it.
pub fn host(name: &str) -> PathBuf {
    host_of(name)
}

#[cfg(windows)]
fn host_of(name: &str) -> PathBuf {
    let bytes = name.as_bytes();
    if bytes.len() >= 3 && bytes[0] == b'/' && bytes[1].is_ascii_alphabetic() && bytes[2] == b':' {
        let rest = &name[3..];
        let rest = if rest.is_empty() { "/" } else { rest };
        // alloc: the path, which the caller owns
        return PathBuf::from(format!("{}:{}", char::from(bytes[1]), rest.replace('/', "\\")));
    }
    if let Some(unc) = name.strip_prefix("/UNC/") {
        // alloc: the path, which the caller owns
        return PathBuf::from(format!(r"\\{}", unc.replace('/', "\\")));
    }
    // alloc: the path, which the caller owns
    PathBuf::from(name.replace('/', "\\"))
}

#[cfg(not(windows))]
fn host_of(name: &str) -> PathBuf {
    // alloc: the path, which the caller owns
    PathBuf::from(name)
}

#[cfg(test)]
mod tests;
