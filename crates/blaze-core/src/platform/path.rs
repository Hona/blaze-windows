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

use std::{
    borrow::Cow,
    fmt,
    ops::Deref,
    path::{Path, PathBuf},
};

/// A path as the daemon names it: UTF-8, `/`-rooted, `/`-separated, with no NUL byte and no
/// `\`. On Unix this matches the host path; on Windows it is `/C:/...` or `/UNC/server/share/...`.
///
/// Intentionally does **not** implement `AsRef<Path>`: a daemon name cannot be passed directly to
/// `std::fs` or `Command` without crossing the boundary through [`DaemonPath::to_host`] or
/// [`DaemonPath::try_host`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct DaemonPath<'a>(&'a str);

impl<'a> DaemonPath<'a> {
    /// Validates `text` as a daemon name: starts with `/`, contains no NUL byte and no `\`.
    pub fn parse(text: &'a str) -> Option<DaemonPath<'a>> {
        (text.starts_with('/') && !text.as_bytes().contains(&0) && !text.contains('\\'))
            .then_some(DaemonPath(text))
    }

    pub fn as_str(self) -> &'a str {
        self.0
    }

    /// Trims trailing `/` separators while preserving `"/"` itself.
    pub fn trim_end_slash(self) -> DaemonPath<'a> {
        let trimmed = self.0.trim_end_matches('/');
        DaemonPath(if trimmed.is_empty() { "/" } else { trimmed })
    }

    /// Whether this is `"/"` itself.
    pub fn is_root(self) -> bool {
        self.trim_end_slash().0 == "/"
    }

    /// Whether this is the root of the filesystem or (on Windows) a bare drive (`/C:`) or UNC
    /// share (`/UNC/server/share`) root, which cannot serve as a portable checkout/build root.
    pub fn is_volume_root(self) -> bool {
        let trimmed = self.trim_end_slash().0;
        if trimmed == "/" {
            return true;
        }
        #[cfg(windows)]
        {
            is_windows_volume_root(trimmed)
        }
        #[cfg(not(windows))]
        {
            false
        }
    }

    /// Lexical parent directory on `/`, or `None` for `"/"`.
    pub fn parent(self) -> Option<DaemonPath<'a>> {
        let trimmed = self.trim_end_slash().0;
        if trimmed == "/" {
            return None;
        }
        let (parent, _) = trimmed.rsplit_once('/')?;
        Some(DaemonPath(if parent.is_empty() { "/" } else { parent }))
    }

    /// Joins `rel` lexically with `/` (never `\`). If `rel` is itself a valid daemon name,
    /// returns `rel`.
    pub fn join(self, rel: &str) -> DaemonPathBuf {
        if let Some(abs) = DaemonPath::parse(rel) {
            return abs.to_owned();
        }
        let rel = rel.trim_start_matches('/');
        let base = self.trim_end_slash().0;
        if rel.is_empty() {
            return DaemonPathBuf(self.0.to_owned()); // alloc: owned joined path
        }
        if base == "/" {
            return DaemonPathBuf(format!("/{rel}")); // alloc: owned joined path
        }
        DaemonPathBuf(format!("{base}/{rel}")) // alloc: owned joined path
    }

    /// Strips `base` by whole `/`-separated components; returns `""` when equal.
    pub fn strip_prefix(self, base: DaemonPath<'_>) -> Option<&'a str> {
        let base = base.trim_end_slash().0;
        if base == "/" {
            return self.0.strip_prefix('/');
        }
        let rest = self.0.strip_prefix(base)?;
        if rest.is_empty() {
            Some("")
        } else {
            rest.strip_prefix('/')
        }
    }

    /// Whether `self` is equal to or under `base` by whole `/`-separated components.
    pub fn starts_with(self, base: DaemonPath<'_>) -> bool {
        self.strip_prefix(base).is_some()
    }

    /// Converts to an owned [`DaemonPathBuf`].
    pub fn to_owned(self) -> DaemonPathBuf {
        DaemonPathBuf(self.0.to_owned()) // alloc: caller requested ownership
    }

    /// Converts to the host OS path ([`host`]).
    pub fn to_host(self) -> HostPathBuf {
        HostPathBuf(host_of(self.0))
    }

    /// Converts to the host OS path only when this daemon name addresses a real absolute host
    /// location on the current OS: always on Unix; on Windows only for `/X:` / `/X:/...` drives
    /// and `/UNC/<server>/<share>` shares (never virtual mounts like `/rustc/...` or synthetic
    /// Unix names like `/w/pkg`).
    pub fn try_host(self) -> Option<HostPathBuf> {
        #[cfg(windows)]
        {
            windows_host_of(self.0).map(|s| HostPathBuf(PathBuf::from(s)))
        }
        #[cfg(not(windows))]
        {
            Some(HostPathBuf(PathBuf::from(self.0)))
        }
    }

    /// On Windows, the native `\`-separated host spelling of a non-root drive or UNC daemon name
    /// without trailing `\` (`"/C:/Users/a/w"` -> `Some("C:\\Users\\a\\w")`), for portable root
    /// matching and leak detection. `None` on Unix (where the daemon name is already the host
    /// spelling) or for non-host/volume-root daemon names.
    pub fn host_spelling(self) -> Option<String> {
        #[cfg(windows)]
        {
            if self.is_volume_root() {
                return None;
            }
            let host = windows_host_of(self.0)?;
            let trimmed = host.trim_end_matches('\\');
            (!trimmed.is_empty()).then(|| trimmed.to_owned()) // alloc: host spelling of a root
        }
        #[cfg(not(windows))]
        {
            let _ = self;
            None
        }
    }
}

impl fmt::Display for DaemonPath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// Owned [`DaemonPath`]: a validated `/`-rooted daemon name. Intentionally does **not** implement
/// `AsRef<Path>`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct DaemonPathBuf(String);

impl DaemonPathBuf {
    /// Parses `text` as a daemon name.
    pub fn parse(text: impl Into<String>) -> Option<DaemonPathBuf> {
        let text = text.into();
        DaemonPath::parse(&text)?;
        Some(DaemonPathBuf(text))
    }

    /// Converts an absolute host path to its daemon name ([`daemon`]).
    pub fn from_host(path: &Path) -> Result<DaemonPathBuf, PathError> {
        Ok(DaemonPathBuf(daemon(path)?))
    }

    pub fn as_daemon(&self) -> DaemonPath<'_> {
        DaemonPath(&self.0)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn to_host(&self) -> HostPathBuf {
        self.as_daemon().to_host()
    }

    pub fn try_host(&self) -> Option<HostPathBuf> {
        self.as_daemon().try_host()
    }
}

impl fmt::Display for DaemonPathBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A native host filesystem path, safe to hand to `std::fs` and `Command`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct HostPath<'a>(&'a Path);

impl<'a> HostPath<'a> {
    pub fn new(path: &'a Path) -> HostPath<'a> {
        HostPath(path)
    }

    pub fn as_path(self) -> &'a Path {
        self.0
    }

    /// Converts this host path to its daemon name ([`daemon`]).
    pub fn to_daemon(self) -> Result<DaemonPathBuf, PathError> {
        DaemonPathBuf::from_host(self.0)
    }
}

impl AsRef<Path> for HostPath<'_> {
    fn as_ref(&self) -> &Path {
        self.0
    }
}

impl Deref for HostPath<'_> {
    type Target = Path;

    fn deref(&self) -> &Path {
        self.0
    }
}

/// Owned [`HostPath`]: a native host filesystem path.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct HostPathBuf(PathBuf);

impl HostPathBuf {
    pub fn new(path: PathBuf) -> HostPathBuf {
        HostPathBuf(path)
    }

    pub fn as_host(&self) -> HostPath<'_> {
        HostPath(&self.0)
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }

    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }

    /// Converts this host path to its daemon name ([`daemon`]).
    pub fn to_daemon(&self) -> Result<DaemonPathBuf, PathError> {
        DaemonPathBuf::from_host(&self.0)
    }
}

impl AsRef<Path> for HostPathBuf {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Deref for HostPathBuf {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl From<PathBuf> for HostPathBuf {
    fn from(path: PathBuf) -> HostPathBuf {
        HostPathBuf(path)
    }
}

impl From<HostPathBuf> for PathBuf {
    fn from(path: HostPathBuf) -> PathBuf {
        path.0
    }
}

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

/// Converts a Windows daemon name (`/C:/a`, `/C:`, `/UNC/server/share/a`) into its native
/// host path string (`C:\a`, `C:\`, `\\server\share\a`), returning `None` for any name that does
/// not address a Windows drive or UNC share (such as `/home/a`, `/rustc/...`, `/C:rel`, or
/// `/UNC/server`).
#[cfg(any(windows, test))]
pub(crate) fn windows_host_of(name: &str) -> Option<String> {
    let bytes = name.as_bytes();
    if bytes.len() >= 3
        && bytes[0] == b'/'
        && bytes[1].is_ascii_alphabetic()
        && bytes[2] == b':'
        && (bytes.len() == 3 || bytes[3] == b'/')
    {
        let rest = if bytes.len() == 3 { "/" } else { &name[3..] };
        // alloc: the path, which the caller owns
        return Some(format!("{}:{}", char::from(bytes[1]), rest.replace('/', "\\")));
    }
    if let Some(unc) = name.strip_prefix("/UNC/") {
        let mut parts = unc.splitn(3, '/');
        let (server, share) = (parts.next()?, parts.next()?);
        if server.is_empty() || share.is_empty() {
            return None;
        }
        // alloc: the path, which the caller owns
        return Some(format!(r"\\{}", unc.replace('/', "\\")));
    }
    None
}

/// Whether `trimmed` (a daemon name without trailing `/`) is a Windows drive root (`/C:`) or UNC
/// share root (`/UNC/server/share`).
#[cfg(any(windows, test))]
fn is_windows_volume_root(trimmed: &str) -> bool {
    let bytes = trimmed.as_bytes();
    if bytes.len() == 3 && bytes[0] == b'/' && bytes[1].is_ascii_alphabetic() && bytes[2] == b':' {
        return true;
    }
    if let Some(unc) = trimmed.strip_prefix("/UNC/") {
        let mut parts = unc.split('/');
        let (server, share, rest) = (parts.next(), parts.next(), parts.next());
        return server.is_some_and(|it| !it.is_empty())
            && share.is_some_and(|it| !it.is_empty())
            && rest.is_none();
    }
    false
}

#[cfg(windows)]
fn host_of(name: &str) -> PathBuf {
    if let Some(native) = windows_host_of(name) {
        return PathBuf::from(native);
    }
    // alloc: the path, which the caller owns
    PathBuf::from(name.replace('/', "\\"))
}

#[cfg(not(windows))]
fn host_of(name: &str) -> PathBuf {
    // alloc: the path, which the caller owns
    PathBuf::from(name)
}

/// Converts `path` to a host path when it holds a Windows daemon name (`/C:/...` or
/// `/UNC/server/share/...`); returns `path` borrowed otherwise (including on Unix, for already
/// host-native Windows paths, and for synthetic `/...` names that do not name a Windows volume).
pub fn host_if_daemon(path: &Path) -> Cow<'_, Path> {
    #[cfg(windows)]
    {
        if let Some(native) =
            path.to_str().and_then(DaemonPath::parse).and_then(DaemonPath::try_host)
        {
            return Cow::Owned(native.into_path_buf());
        }
    }
    Cow::Borrowed(path)
}

/// Whether `path` names the same filesystem location as its `std::fs::canonicalize` result
/// `canonical` (no symlinks, junctions, `..`, or casing mismatch), accounting for Windows'
/// verbatim `\\?\` prefix that `canonicalize` adds.
pub fn canonical_matches(path: &Path, canonical: &Path) -> bool {
    #[cfg(windows)]
    {
        match (daemon(path), daemon(canonical)) {
            (Ok(a), Ok(b)) => a.trim_end_matches('/') == b.trim_end_matches('/'),
            _ => canonical == path,
        }
    }
    #[cfg(not(windows))]
    {
        canonical == path
    }
}

/// A symbolic link's target as the daemon's trees keep it, from the target's text as the
/// system read it (`std::fs::read_link`): `/`-separated, and absolute only where it starts
/// with `/`, the one test every reader of a tree's links makes on every system. On Windows
/// `..\x` is `../x` and an absolute target (`C:\x`, `\\?\C:\x`, `\\server\share\x`) is its
/// daemon name ([`daemon`]: `/C:/x`, `/UNC/server/share/x`), so a link out of the tree is
/// refused, or resolved against the mounts, as on Unix; `\x` (the current drive's root) is
/// `/x`, out of the tree and so refused; a drive-relative `C:x` stays relative text. On Unix
/// the bytes are the link's own: `C:x` and `a\b` are names there.
pub fn link_target(target: &str) -> String {
    link_target_of(target)
}

#[cfg(windows)]
fn link_target_of(target: &str) -> String {
    // alloc: the target, which the caller owns
    daemon_of(target).unwrap_or_else(|| target.replace('\\', "/"))
}

#[cfg(not(windows))]
fn link_target_of(target: &str) -> String {
    // alloc: the target, which the caller owns
    target.to_owned()
}

#[cfg(test)]
mod tests;
