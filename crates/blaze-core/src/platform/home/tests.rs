use std::{ffi::OsString, path::PathBuf};

use super::*;

fn env(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<OsString> {
    move |name| pairs.iter().find(|(key, _)| *key == name).map(|(_, value)| OsString::from(*value))
}

/// `BLAZE_HOME` names every directory but the machine's, which the daemon compares by volume,
/// and which a `BLAZE_HOME` alone leaves unnamed.
#[test]
fn blaze_home_is_every_directory() {
    #[cfg(windows)]
    let (vars, home, machine) =
        (&[("BLAZE_HOME", r"D:\b"), ("LOCALAPPDATA", r"C:\Users\u\AppData\Local")][..], r"D:\b", r"C:\Users\u\AppData\Local\blaze");
    #[cfg(not(windows))]
    let (vars, home, machine) = (&[("BLAZE_HOME", "/b"), ("HOME", "/u")][..], "/b", "/u/.cache/blaze");
    let found = homes(env(vars)).unwrap();
    let home = PathBuf::from(home);
    assert_eq!((&found.root, &found.home), (&home, &home));
    assert_eq!(found.socket, home.join("v2.sock"));
    assert_eq!(found.machine, Some(PathBuf::from(machine)));
    assert!(found.named);
}

/// Windows: everything under `%LOCALAPPDATA%\blaze`, whatever `HOME` Git Bash sets, so a
/// command from either shell finds the one daemon.
#[cfg(windows)]
#[test]
fn on_windows_blaze_lives_in_local_app_data_and_home_is_not_read() {
    let local = PathBuf::from(r"C:\Users\u\AppData\Local\blaze");
    for vars in [
        &[("LOCALAPPDATA", r"C:\Users\u\AppData\Local")][..],
        &[("LOCALAPPDATA", r"C:\Users\u\AppData\Local"), ("HOME", "/c/Users/u"), ("BLAZE_HOME", "")][..],
        &[("LOCALAPPDATA", r"C:\Users\u\AppData\Local"), ("XDG_CACHE_HOME", r"C:\x"), ("USERPROFILE", r"C:\Users\u")][..],
    ] {
            let found = homes(env(vars)).unwrap();
        assert_eq!((&found.root, &found.home), (&local, &local), "{vars:?}");
        assert_eq!(found.machine.as_ref(), Some(&local));
        assert_eq!(found.socket, local.join("v2.sock"));
        assert!(!found.named);
    }
    let none = homes(env(&[("HOME", "/c/Users/u")])).unwrap_err();
    assert!(none.contains("LOCALAPPDATA"), "{none}");
}

/// Unix, as blaze has always found them: the cache directory, `~/.blaze`, and the runtime
/// directory's socket where there is one.
#[cfg(not(windows))]
#[test]
fn on_unix_the_root_is_the_cache_and_the_home_is_dot_blaze() {
    let found = homes(env(&[("HOME", "/u")])).unwrap();
    assert_eq!(found.root, PathBuf::from("/u/.cache/blaze"));
    assert_eq!(found.home, PathBuf::from("/u/.blaze"));
    assert_eq!(found.socket, PathBuf::from("/u/.cache/blaze/v2.sock"));
    let found =
        homes(env(&[("HOME", "/u"), ("XDG_CACHE_HOME", "/c"), ("XDG_RUNTIME_DIR", "/run/1")])).unwrap();
    assert_eq!(found.root, PathBuf::from("/c/blaze"));
    assert_eq!(found.socket, PathBuf::from("/run/1/blaze/v2.sock"));
    assert!(homes(env(&[])).is_err());
}

/// With `BLAZE_HOME` alone, as in a build script's or a CI job's sparse environment, blaze has
/// every directory but the machine's.
#[test]
fn blaze_home_alone_is_enough() {
    let found = homes(env(&[("BLAZE_HOME", "b")])).unwrap();
    assert_eq!(found.root, PathBuf::from("b"));
    assert_eq!(found.machine, None);
}