//! A path a macro names, as the host's file system takes it, and back.
//!
//! The walk ([`super::files::walk`]) names every path as the daemon does: absolute, `/`
//! separated, one root. On Windows a drive is the first part of that one root (`/C:/Users/a`),
//! as wasi-libc and the daemon's VFS both name it, and the host's own name of it is
//! `\\?\C:\Users\a`: verbatim, so a path past `MAX_PATH` opens too and nothing in it is
//! reinterpreted (the walk has resolved each `.` and `..` already). A UNC share is
//! `/UNC/server/share/...`, the host's `\\?\UNC\server\share\...`. Any other first part
//! (`/etc`) names nothing on Windows.
//!
//! A macro may also name a path as Windows spells it, from a variable rustc's process would
//! have been given as Windows spells it (`C:\Users\a\pkg`, `C:/Users/a/pkg`,
//! `\\?\C:\Users\a\pkg`): on a Windows host [`guest_path`] reads that as the walk's
//! `/C:/Users/a/pkg`, so it is walked, checked against the roots and keyed as the same path.
//!
//! windows: `blaze_core::platform::path` (lane host) is the daemon's one conversion; this is
//! the same rule, kept here until it lands.

use std::{
    borrow::Cow,
    path::{Path, PathBuf},
};

/// Whether the host spells paths as Windows does.
pub(super) const WINDOWS: bool = cfg!(windows);

/// The host's name of the walk's absolute `path`, or `None` when it names nothing on this
/// host (on Windows, `/` itself or a first part that is no drive and no `UNC`).
pub(super) fn on_host(path: &str) -> Option<Cow<'_, Path>> {
    if WINDOWS { windows_host(path).map(|it| Cow::Owned(PathBuf::from(it))) } else { Some(Cow::Borrowed(Path::new(path))) }
}

/// [`on_host`] on Windows, as text: `/C:/a/b` is `\\?\C:\a\b`, `/C:` is `\\?\C:\`, and
/// `/UNC/s/share/a` is `\\?\UNC\s\share\a`.
pub(super) fn windows_host(path: &str) -> Option<String> {
    let rest = path.strip_prefix('/')?;
    let (first, below) = rest.split_once('/').unwrap_or((rest, ""));
    let below = below.trim_end_matches('/');
    let mut host = String::with_capacity(path.len() + 8);
    if is_drive(first) {
        host.push_str(r"\\?\");
        host.push(first.as_bytes()[0].to_ascii_uppercase() as char);
        host.push_str(r":\");
    } else if first == "UNC" {
        let mut parts = below.splitn(3, '/');
        let (Some(server), Some(share)) = (parts.next(), parts.next()) else { return None };
        if server.is_empty() || share.is_empty() {
            return None;
        }
        host.push_str(r"\\?\UNC\");
        host.push_str(server);
        host.push('\\');
        host.push_str(share);
        if let Some(more) = parts.next().filter(|it| !it.is_empty()) {
            host.push('\\');
            push_parts(&mut host, more);
        }
        return Some(host);
    } else {
        return None;
    }
    push_parts(&mut host, below);
    Some(host)
}

fn push_parts(host: &mut String, parts: &str) {
    for (n, part) in parts.split('/').filter(|it| !it.is_empty()).enumerate() {
        if n > 0 {
            host.push('\\');
        }
        host.push_str(part);
    }
}

/// Whether `part` is a drive: one ASCII letter and `:`.
fn is_drive(part: &str) -> bool {
    matches!(part.as_bytes(), [letter, b':'] if letter.is_ascii_alphabetic())
}

/// `path` as the macro named it, in the walk's spelling: on a Windows host a path Windows
/// calls absolute (`C:\a`, `C:/a`, `\\?\C:\a`, `\\server\share\a`) is the walk's `/C:/a` or
/// `/UNC/server/share/a`, and every `\` is a `/`, as Windows reads it in any path. Elsewhere,
/// and for every other path, `path` as it is.
pub(crate) fn guest_path(path: &str) -> Cow<'_, str> {
    if !WINDOWS { Cow::Borrowed(path) } else { windows_guest_path(path) }
}

/// [`guest_path`] on Windows.
pub(super) fn windows_guest_path(path: &str) -> Cow<'_, str> {
    // A drive-relative path (`C:a`) and a rooted one with no drive (`\a`) depend on a current
    // directory per drive, which a macro's process has none of: left as they are, `\` read as
    // `/`, so the first is relative to the working directory and the second to `/`.
    let unprefixed = path
        .strip_prefix(r"\\?\")
        .or_else(|| path.strip_prefix(r"\??\"))
        .or_else(|| path.strip_prefix("//?/"));
    let (drive, rest) = match unprefixed {
        Some(rest) => match rest.strip_prefix("UNC\\").or_else(|| rest.strip_prefix("UNC/")) {
            Some(share) => return Cow::Owned(format!("/UNC/{}", share.replace('\\', "/"))),
            None => (true, rest),
        },
        None => (false, path),
    };
    let bytes = rest.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && (bytes.len() == 2 || matches!(bytes[2], b'/' | b'\\')) {
        let letter = (bytes[0].to_ascii_uppercase()) as char;
        return Cow::Owned(format!("/{letter}:{}", rest[2..].replace('\\', "/")));
    }
    if !drive && let Some(share) = path.strip_prefix(r"\\").or_else(|| path.strip_prefix("//")) {
        return Cow::Owned(format!("/UNC/{}", share.replace('\\', "/")));
    }
    match rest.contains('\\') {
        true => Cow::Owned(rest.replace('\\', "/")),
        false => Cow::Borrowed(rest),
    }
}

/// Where a link the host read points, in the walk's spelling: an absolute target as the walk
/// names it (on Windows `C:\a` and `\\?\C:\a` are `/C:/a`), a relative one with `/` between
/// its parts. `None` when it is not UTF-8.
pub(super) fn link_target(target: &Path) -> Option<Cow<'_, str>> {
    let text = target.to_str()?;
    Some(guest_path(text))
}
