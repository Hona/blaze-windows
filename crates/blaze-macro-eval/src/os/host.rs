//! A path a macro names, as the host's file system takes it, and back.
//!
//! The walk ([`super::files::walk`]) names every path as the daemon does: absolute, `/`
//! separated, one root. On Windows a drive is the first part of that one root (`/C:/Users/a`),
//! as wasi-libc and the daemon's VFS both name it, and the system opens it at
//! [`blaze_core::platform::path::host`]'s name, `C:\Users\a`; a UNC share is
//! `/UNC/server/share/...`. Any other first part (`/etc`) names nothing on Windows: it is not a
//! path from the current drive's root, which a macro has no business with.
//!
//! A macro may also name a path as Windows spells it, from a variable rustc's process would
//! have been given as Windows spells it (`C:\Users\a\pkg`, `C:/Users/a/pkg`,
//! `\\?\C:\Users\a\pkg`): on a Windows host [`guest_path`] reads that as the walk's
//! `/C:/Users/a/pkg` ([`blaze_core::platform::path::daemon`]), so it is walked, checked against
//! the roots and keyed as the same path.

use std::{borrow::Cow, path::Path};

/// The host's name of the walk's absolute `path`, or `None` when it names nothing on this
/// host (on Windows, `/` itself or a first part that is no drive and no `UNC`).
pub(super) fn on_host(path: &str) -> Option<Cow<'_, Path>> {
    if !cfg!(windows) {
        return Some(Cow::Borrowed(Path::new(path)));
    }
    let first = path.strip_prefix('/')?.split('/').next()?;
    let drive = matches!(first.as_bytes(), [letter, b':'] if letter.is_ascii_alphabetic());
    (drive || first == "UNC").then(|| Cow::Owned(blaze_core::platform::path::host(path)))
}

/// `path` as the macro named it, in the walk's spelling: on a Windows host a path Windows
/// calls absolute is the walk's `/C:/a` or `/UNC/server/share/a`, and in any other every `\`
/// is a `/`, as Windows reads it. Elsewhere, `path` as it is.
pub(crate) fn guest_path(path: &str) -> Cow<'_, str> {
    if !cfg!(windows) {
        return Cow::Borrowed(path);
    }
    // A drive-relative path (`C:a`) and a rooted one with no drive (`\a`) depend on a current
    // directory per drive, which a macro's process has none of: `\` read as `/`, the first is
    // relative to the working directory and the second to `/`.
    match blaze_core::platform::path::daemon(Path::new(path)) {
        Ok(name) => Cow::Owned(name),
        Err(_) if path.contains('\\') => Cow::Owned(path.replace('\\', "/")),
        Err(_) => Cow::Borrowed(path),
    }
}

/// Where a link the host read points, in the walk's spelling: an absolute target as the walk
/// names it (on Windows `C:\a` and `\\?\C:\a` are `/C:/a`), a relative one with `/` between
/// its parts. `None` when it is not UTF-8.
pub(super) fn link_target(target: &Path) -> Option<Cow<'_, str>> {
    Some(guest_path(target.to_str()?))
}
