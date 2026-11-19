//! A command's environment as blaze carries it: the variables a client reads of its own
//! process and sends with a request, which the daemon looks names up in, merges cargo's over
//! and keys runs by.
//!
//! On Windows a variable's name is one in any case: `Path` and `PATH` are one variable, which
//! the system and every program look up without regard to case, and which a process's
//! environment holds once. blaze compares names exactly (`PATH`, `CARGO_HOME`, `RUSTFLAGS`),
//! sorts and merges them by their bytes and keys runs by them, so each name is carried in one
//! form: upper case, as Windows compares them ([`name`]). Then a lookup of `PATH` finds the
//! user's `Path`, what cargo sets over a variable replaces it whatever case the user gave it
//! (two of one name in a child's block, the first wins, which was the user's), and a shell that
//! spells a name another way keys no run apart. Python's `os.environ` carries names the same
//! way on Windows. On Unix a name is its bytes, and is carried as it is.

use std::{
    borrow::Cow,
    ffi::{OsStr, OsString},
};

/// `name` as blaze carries it: on Windows each character in upper case where that is one
/// character (as the system compares names, `RtlUpcaseUnicodeChar`), elsewhere as it is.
pub fn name(name: &str) -> Cow<'_, str> {
    match os_name(OsStr::new(name)) {
        Cow::Borrowed(_) => Cow::Borrowed(name),
        // The Windows upcase table maps one non-surrogate to one non-surrogate and
        // leaves surrogates alone. A well-formed name stays well-formed.
        Cow::Owned(name) => Cow::Owned(name.into_string().expect("upcasing text preserves UTF-16")),
    }
}

/// The comparison key of a variable in the child's environment block. Unlike a Unicode
/// string uppercase, Windows compares one UTF-16 unit at a time, even in a surrogate pair.
pub fn os_name(name: &OsStr) -> Cow<'_, OsStr> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
        if name.encode_wide().any(|unit| upper_unit(unit) != unit) {
            // alloc: the changed name and its UTF-16 units, once per mixed-case input.
            let units: Vec<_> = name.encode_wide().map(upper_unit).collect();
            return Cow::Owned(OsString::from_wide(&units));
        }
    }
    Cow::Borrowed(name)
}

/// One unit of a Windows environment name. The non-Windows arm is for the portable
/// CreateProcess encoder; a real Windows launch and key use the OS's own upcase table.
pub(crate) fn upper_unit(unit: u16) -> u16 {
    if unit < 128 {
        return u16::from((unit as u8).to_ascii_uppercase());
    }
    #[cfg(windows)]
    #[allow(unsafe_code, reason = "the OS's case table, one scalar argument and result, no pointers")]
    {
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn RtlUpcaseUnicodeChar(source: u16) -> u16;
        }
        // SAFETY: every u16 is a valid WCHAR, including an unpaired surrogate.
        unsafe { RtlUpcaseUnicodeChar(unit) }
    }
    #[cfg(not(windows))]
    {
        let Some(c) = char::from_u32(u32::from(unit)) else { return unit };
        let mut up = c.to_uppercase();
        match (up.next(), up.next()) {
            (Some(one), None) => u16::try_from(u32::from(one)).unwrap_or(unit),
            _ => unit,
        }
    }
}

/// The environment `vars` (a process's own, in its order) as a request carries it: each name
/// as [`name`] says, sorted by name, the first of a name kept as the system's own lookup keeps
/// it. A variable that is not UTF-8 is refused by its name alone, never its value.
pub fn captured(
    vars: impl Iterator<Item = (OsString, OsString)>,
) -> Result<Vec<(String, String)>, String> {
    // alloc: the request's environment, once a command.
    let mut env = Vec::with_capacity(vars.size_hint().0);
    let refused = |named: &str| {
        format!(
            "the environment variable `{named}` is not UTF-8, which a request to the daemon can't carry"
        )
    };
    for (given, value) in vars {
        match (given.into_string(), value.into_string()) {
            (Ok(given), Ok(value)) => env.push((name(&given).into_owned(), value)),
            (Ok(given), Err(_)) => return Err(refused(&given)),
            (Err(given), _) => return Err(refused(&given.to_string_lossy())),
        }
    }
    Ok(sorted(env))
}

/// `env` with each name as [`name`] says, sorted by name, the first of a name kept: an
/// environment a caller gave, carried as one read here is.
pub fn carried(env: Vec<(String, String)>) -> Vec<(String, String)> {
    sorted(env.into_iter().map(|(given, value)| (name(&given).into_owned(), value)).collect())
}

fn sorted(mut env: Vec<(String, String)>) -> Vec<(String, String)> {
    // Stable: of two of one name, the first given stays first and is kept.
    env.sort_by(|a, b| a.0.cmp(&b.0));
    env.dedup_by(|later, first| later.0 == first.0);
    env
}

#[cfg(test)]
mod tests;
