use super::*;

fn developer() -> Developer {
    Developer {
        install: PathBuf::from(r"C:\VS"),
        tools: "14.44.35207".to_owned(),
        kits: PathBuf::from(r"C:\Kits\10"),
        sdk: "10.0.26100.0".to_owned(),
    }
}

fn get<'a>(vars: &'a [(OsString, OsString)], name: &str) -> &'a str {
    vars.iter().find(|(it, _)| it == name).unwrap_or_else(|| panic!("{name}")).1.to_str().unwrap()
}

#[test]
fn a_target_is_named_as_a_developer_prompt_names_it() {
    assert_eq!(arch("x86_64-pc-windows-msvc"), Some("x64"));
    assert_eq!(arch("i686-pc-windows-msvc"), Some("x86"));
    assert_eq!(arch("aarch64-pc-windows-msvc"), Some("arm64"));
    assert!(targets("x86_64-pc-windows-msvc"));
    assert!(!targets("x86_64-pc-windows-gnu"));
    assert!(!targets("wasm32-wasip1"));
    assert!(!targets("riscv64gc-pc-windows-msvc"));
}

/// The refinement: the variables are vcvarsall.bat's for the same tools, SDK and
/// architectures (its output on this layout, read by hand from `vcvars64.bat`'s `set`), the
/// prompt's `PATH` in front of the one it is given.
#[cfg(windows)]
#[test]
fn the_variables_are_a_developer_prompts() {
    let vars = developer().variables("x64", "x64", Some(&OsString::from(r"C:\Windows"))).unwrap();
    assert_eq!(get(&vars, "VSINSTALLDIR"), r"C:\VS\");
    assert_eq!(get(&vars, "VCINSTALLDIR"), r"C:\VS\VC\");
    assert_eq!(get(&vars, "VCToolsInstallDir"), r"C:\VS\VC\Tools\MSVC\14.44.35207\");
    assert_eq!(get(&vars, "WindowsSDKVersion"), r"10.0.26100.0\");
    assert_eq!(get(&vars, "VSCMD_ARG_TGT_ARCH"), "x64");
    assert_eq!(
        get(&vars, "LIB"),
        r"C:\VS\VC\Tools\MSVC\14.44.35207\lib\x64;C:\Kits\10\Lib\10.0.26100.0\ucrt\x64;C:\Kits\10\Lib\10.0.26100.0\um\x64"
    );
    assert!(get(&vars, "INCLUDE").starts_with(
        r"C:\VS\VC\Tools\MSVC\14.44.35207\include;C:\Kits\10\Include\10.0.26100.0\ucrt;"
    ));
    assert_eq!(
        get(&vars, "PATH"),
        r"C:\VS\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64;C:\Kits\10\bin\10.0.26100.0\x64;C:\Windows"
    );
    let cross = developer().variables("x64", "arm64", None).unwrap();
    assert_eq!(
        get(&cross, "PATH"),
        r"C:\VS\VC\Tools\MSVC\14.44.35207\bin\Hostx64\arm64;C:\VS\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64;C:\Kits\10\bin\10.0.26100.0\x64"
    );
}

/// The invariant of [`found`]'s cache: what was found stands exactly while every read stands
/// as it did and `ProgramFiles(x86)` and `KitsRoot10` are the same; any one changed read (an
/// SDK added to `Include`, a Visual Studio update rewriting its `state.json`, a removed
/// `cl.exe`) finds again. Control: a cache that compares nothing would keep all four.
#[test]
fn what_was_found_stands_until_a_read_changes() {
    use std::time::{Duration, SystemTime};
    let at = |secs: u64| Some((10, SystemTime::UNIX_EPOCH + Duration::from_secs(secs)));
    let reads = vec![
        (PathBuf::from(r"C:\Data\_Instances"), at(1)),
        (PathBuf::from(r"C:\Data\_Instances\a\state.json"), at(2)),
        (PathBuf::from(r"C:\Kits\10\Include"), at(3)),
        (PathBuf::from(r"C:\VS\cl.exe"), at(4)),
    ];
    let kept = Kept {
        developer: developer(),
        programs: OsString::from(r"C:\PF86"),
        kits_root: PathBuf::from(r"C:\Kits\10"),
        reads: reads.clone(),
    };
    let now = |reads: &[(PathBuf, Stood)]| {
        let reads = reads.to_vec();
        move |path: &Path| reads.iter().find(|it| it.0 == path).and_then(|it| it.1)
    };
    let (programs, kits) = (std::ffi::OsStr::new(r"C:\PF86"), Path::new(r"C:\Kits\10"));
    assert!(kept.still(programs, kits, now(&reads)), "nothing changed");
    assert!(!kept.still(std::ffi::OsStr::new(r"D:\PF86"), kits, now(&reads)));
    assert!(!kept.still(programs, Path::new(r"D:\Kits\10"), now(&reads)));
    for changed in 0..reads.len() {
        let mut moved = reads.clone();
        moved[changed].1 = at(100);
        assert!(!kept.still(programs, kits, now(&moved)), "read {changed} moved");
        let mut gone = reads.clone();
        gone[changed].1 = None;
        assert!(!kept.still(programs, kits, now(&gone)), "read {changed} gone");
    }
}

/// On a machine with the tools, [`found`] twice is [`find`] once: the same answer, kept.
#[cfg(windows)]
#[test]
fn found_twice_is_find_once() {
    match (find(), found(), found()) {
        (Ok(fresh), Ok(first), Ok(second)) => {
            assert_eq!(fresh, first);
            assert_eq!(first, second);
        }
        (Err(why), ..) => eprintln!("no MSVC here: {why}"),
        other => panic!("find and found disagree: {other:?}"),
    }
}

/// On a machine with Visual Studio's C++ tools, they are found whole; on one without, the
/// error names what is missing.
#[cfg(windows)]
#[test]
fn the_tools_are_found_whole_or_the_error_says_what_is_missing() {
    match find() {
        Ok(found) => {
            assert!(found.vc_tools().join(r"bin\Hostx64\x64\cl.exe").is_file());
            assert!(found.kits.join("Include").join(&found.sdk).join(r"um\windows.h").is_file());
        }
        Err(why) => {
            assert!(why.contains("vswhere") || why.contains("KitsRoot10") || why.contains(r"\"), "{why}");
            eprintln!("no MSVC here: {why}");
        }
    }
}
