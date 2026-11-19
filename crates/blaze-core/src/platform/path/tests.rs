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
        ("D:/scratch/home", "/D:/scratch/home", r"D:\scratch\home"),
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

#[test]
fn daemon_path_lexical_operations_never_use_backslashes() {
    let manifest = DaemonPath::parse("/C:/Users/a/ws/pkg/Cargo.toml").unwrap();
    let dir = manifest.parent().unwrap();
    assert_eq!(dir.as_str(), "/C:/Users/a/ws/pkg");
    let lean = dir.join("lean");
    assert_eq!(lean.as_str(), "/C:/Users/a/ws/pkg/lean");
    let root = DaemonPath::parse("/C:/Users/a/ws").unwrap();
    assert_eq!(lean.as_daemon().strip_prefix(root), Some("pkg/lean"));
    assert!(lean.as_daemon().starts_with(root));
    assert!(!DaemonPath::parse("/C:/Users/a/ws2").unwrap().starts_with(root));
    assert_eq!(DaemonPath::parse("/").unwrap().parent(), None);
    assert!(DaemonPath::parse(r"C:\Users\a").is_none());
    assert!(DaemonPath::parse("/a\0b").is_none());
    assert!(DaemonPath::parse("relative/path").is_none());
}

#[test]
fn windows_daemon_names_distinguish_volumes_and_non_host_paths() {
    assert_eq!(windows_host_of("/C:/Users/a/ws").as_deref(), Some(r"C:\Users\a\ws"));
    assert_eq!(windows_host_of("/C:").as_deref(), Some(r"C:\"));
    assert_eq!(windows_host_of("/UNC/srv/share/a").as_deref(), Some(r"\\srv\share\a"));
    assert_eq!(windows_host_of("/UNC/srv/share").as_deref(), Some(r"\\srv\share"));
    assert_eq!(windows_host_of("/C:rel"), None);
    assert_eq!(windows_host_of("/UNC/srv"), None);
    assert_eq!(windows_host_of("/home/a/ws"), None);
    assert!(is_windows_volume_root("/C:"));
    assert!(is_windows_volume_root("/UNC/srv/share"));
    assert!(!is_windows_volume_root("/C:/a"));
    assert!(!is_windows_volume_root("/UNC/srv/share/a"));
}

#[cfg(windows)]
#[test]
fn typed_daemon_and_host_paths_convert_at_the_one_boundary() {
    let win = DaemonPath::parse("/C:/Users/a/ws").unwrap();
    assert!(!win.is_volume_root());
    assert_eq!(win.host_spelling().as_deref(), Some(r"C:\Users\a\ws"));
    assert_eq!(win.try_host().unwrap().as_path(), Path::new(r"C:\Users\a\ws"));
    assert_eq!(win.to_host().to_daemon().unwrap().as_str(), "/C:/Users/a/ws");

    assert!(DaemonPath::parse("/C:/").unwrap().is_volume_root());
    assert_eq!(DaemonPath::parse("/C:/").unwrap().host_spelling(), None);
    assert!(DaemonPath::parse("/UNC/srv/share").unwrap().is_volume_root());
    assert_eq!(DaemonPath::parse("/UNC/srv/share").unwrap().host_spelling(), None);

    let synthetic = DaemonPath::parse("/home/a/w").unwrap();
    assert!(!synthetic.is_volume_root());
    assert_eq!(synthetic.try_host(), None);
    assert_eq!(synthetic.host_spelling(), None);
    assert_eq!(&*host_if_daemon(Path::new("/home/a/w")), Path::new("/home/a/w"));
    assert_eq!(&*host_if_daemon(Path::new("/C:/Users/a/ws")), Path::new(r"C:\Users\a\ws"));
    assert_eq!(&*host_if_daemon(Path::new(r"C:\Users\a\ws")), Path::new(r"C:\Users\a\ws"));

    assert!(canonical_matches(Path::new(r"C:\Users\a\ws"), Path::new(r"\\?\C:\Users\a\ws")));
    assert!(!canonical_matches(Path::new(r"C:\Users\a\link"), Path::new(r"\\?\C:\Users\a\real")));
}

/// The invariant of [`link_target`]: a link's target is absolute in a tree exactly where it
/// starts with `/`, on every system; on Windows each spelling of an absolute target is its
/// daemon name and each relative one its `/`-separated text. The control is Unix: its bytes
/// are the link's own, `\` and a drive-like `C:` included.
#[test]
fn a_link_target_is_absolute_in_a_tree_only_where_it_starts_with_a_slash() {
    #[cfg(windows)]
    let cases: &[(&str, &str)] = &[
        (r"..\lib.rs", "../lib.rs"),
        (r"src\lib.rs", "src/lib.rs"),
        ("src/lib.rs", "src/lib.rs"),
        (r"C:\outside\x.rs", "/C:/outside/x.rs"),
        ("c:/outside", "/C:/outside"),
        (r"\\?\C:\outside", "/C:/outside"),
        (r"\\server\share\x", "/UNC/server/share/x"),
        // Drive-relative: no daemon name, relative text. Current-drive-rooted: out of the
        // tree, so `/`-rooted and refused there.
        ("C:x", "C:x"),
        (r"\x", "/x"),
    ];
    #[cfg(unix)]
    let cases: &[(&str, &str)] =
        &[("../lib.rs", "../lib.rs"), (r"a\b", r"a\b"), ("C:x", "C:x"), ("/etc/x", "/etc/x")];
    for &(given, kept) in cases {
        assert_eq!(link_target(given), kept, "the tree's target of a link to {given}");
    }
}
