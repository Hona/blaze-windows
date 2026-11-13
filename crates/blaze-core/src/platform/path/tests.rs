use std::path::Path;

use super::*;

/// The invariant: every absolute path the system gives has one daemon name, and [`host`] of
/// that name is a path the system calls absolute and that names the same file: the round trip
/// gives back the path as std reads it (its components), and the name round-trips exactly.
#[test]
fn an_absolute_path_and_its_daemon_name_round_trip() {
    #[cfg(windows)]
    let cases: &[(&str, &str, &str)] = &[
        (r"C:\Users\a\b.rs", "/C:/Users/a/b.rs", r"C:\Users\a\b.rs"),
        (r"c:\Users\a", "/C:/Users/a", r"C:\Users\a"),
        ("D:/blaze-win/home", "/D:/blaze-win/home", r"D:\blaze-win\home"),
        (r"D:\", "/D:/", r"D:\"),
        (r"\\?\C:\a\very\long", "/C:/a/very/long", r"C:\a\very\long"),
        (r"\\server\share\x\y", "/UNC/server/share/x/y", r"\\server\share\x\y"),
        (r"\\server\share", "/UNC/server/share", r"\\server\share"),
        (r"\\?\UNC\server\share\x", "/UNC/server/share/x", r"\\server\share\x"),
    ];
    #[cfg(unix)]
    let cases: &[(&str, &str, &str)] =
        &[("/home/a/b.rs", "/home/a/b.rs", "/home/a/b.rs"), ("/", "/", "/")];
    for &(given, named, back) in cases {
        let name = daemon(Path::new(given)).unwrap_or_else(|why| panic!("{given}: {why}"));
        assert_eq!(name, named, "the daemon's name of {given}");
        let host = host(&name);
        assert_eq!(host, Path::new(back), "the system's path of {name}");
        assert!(host.is_absolute(), "{} is absolute", host.display());
        assert_eq!(daemon(&host).as_deref(), Ok(named), "{name} round-trips");
    }
}

/// A path that names no file without a current directory is refused, naming it: never given
/// a daemon name that would look absolute.
#[test]
fn a_relative_path_has_no_daemon_name() {
    #[cfg(windows)]
    let relative: &[&str] = &[r"a\b", "C:a", "C:", r"\a\b", "/a/b", r"\\server", ""];
    #[cfg(unix)]
    let relative: &[&str] = &["a/b", "", "./a"];
    for &given in relative {
        let refused = daemon(Path::new(given)).expect_err(given);
        assert_eq!(refused.path, given);
        assert!(refused.to_string().contains("is not absolute"), "{refused}");
    }
}

/// The cause the boundary exists for, held: on Windows std reads the daemon's name itself as a
/// path from the current drive's root, relative, so nothing may open it unconverted.
#[cfg(windows)]
#[test]
fn a_daemon_name_is_no_absolute_path_to_the_system() {
    assert!(!Path::new("/C:/Users").is_absolute());
    assert!(host("/C:/Users").is_absolute());
    let here = std::env::current_dir().unwrap();
    let name = daemon(&here).unwrap();
    assert!(std::fs::metadata(host(&name)).unwrap().is_dir(), "{name} opens as {}", here.display());
}

/// A name the daemon would never give (relative) is handed back as written, so a caller's
/// check that it is absolute still refuses it.
#[test]
fn a_relative_name_stays_relative() {
    assert!(!host("a/b").is_absolute());
}
