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
