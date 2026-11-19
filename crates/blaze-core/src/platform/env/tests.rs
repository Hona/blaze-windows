use super::*;

fn vars(it: &[(&str, &str)]) -> impl Iterator<Item = (OsString, OsString)> {
    it.iter().map(|(name, value)| (OsString::from(name), OsString::from(value))).collect::<Vec<_>>().into_iter()
}

/// The invariant, on Windows: names are carried in upper case, sorted, one of each in any
/// case, the first the process gave kept (the one its own lookup finds); values as they are.
#[cfg(windows)]
#[test]
fn a_name_is_carried_once_in_upper_case_and_the_first_given_is_kept() {
    let env = captured(vars(&[
        ("Path", r"C:\Windows"),
        ("windir", r"C:\Windows"),
        ("PATH", "second"),
        ("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        ("straße", "x"),
        ("=C:", r"C:\w"),
    ]))
    .unwrap();
    assert_eq!(
        env,
        [
            ("=C:", r"C:\w"),
            ("PATH", r"C:\Windows"),
            ("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
            ("STRAßE", "x"),
            ("WINDIR", r"C:\Windows"),
        ]
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
    );
    assert_eq!(name("PATH"), Cow::Borrowed("PATH"));
    assert_eq!(carried(vec![("Rustflags".into(), "-g".into())]), [("RUSTFLAGS".to_owned(), "-g".to_owned())]);
}

/// On Unix a name is its bytes: `Path` and `PATH` are two variables, each carried as given.
#[cfg(unix)]
#[test]
fn a_name_is_carried_as_it_is() {
    let env = captured(vars(&[("Path", "a"), ("PATH", "b"), ("PATH", "c")])).unwrap();
    assert_eq!(env, [("PATH".to_owned(), "b".to_owned()), ("Path".to_owned(), "a".to_owned())]);
}

#[cfg(windows)]
#[test]
fn a_name_that_is_not_utf8_is_refused_by_its_name() {
    use std::os::windows::ffi::OsStringExt as _;
    let bad = OsString::from_wide(&[0xD800]);
    let refused = captured([(OsString::from("GOOD"), bad)].into_iter()).unwrap_err();
    assert!(refused.contains("`GOOD`"), "{refused}");
}
