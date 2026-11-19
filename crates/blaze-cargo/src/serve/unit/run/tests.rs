#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use blaze_codegen::{
    Arch,
    plan::{Mode, OptLevel, Override, Policy, Profile},
    settings::{DebugInfo, Panic, Pgo, Relocation, Sanitize, Toolchain},
};
use blaze_ids::ContentId;

use super::{Launch, NOT_IN_PROCESS, launch_of};

fn policy(level: OptLevel) -> Policy {
    Policy {
        toolchain: Toolchain {
            id: ContentId([1; 32]),
            target: "x86_64-unknown-linux-gnu".to_owned(),
            arch: Arch::X86_64,
            cpu: "x86-64".to_owned(),
            features: Vec::new(),
            cranelift: "0.136".to_owned(),
            llvm: Some("23.1".to_owned()),
            stencils: None,
            frame_pointers: true,
            relocation: Relocation::Pic,
        },
        profile: Profile {
            opt_level: level,
            overflow_checks: true,
            debug_assertions: true,
            debuginfo: DebugInfo::Full,
            panic: Panic::Unwind,
            packages: BTreeMap::new(),
            build_override: Override::default(),
            stencils: false,
        },
        mode: Mode::Output,
        fold: true,
        sanitize: Sanitize::default(),
        pgo: Pgo::None,
        proc_macro_bridge: false,
        report: false,
        fuel: false,
        heap_to_stack: false,
    }
}

/// Why a test binary of a platform the dev runtime has no std build for is no dev executable
/// ([`super::inproc::not_in_process`]).
const NO_RUNTIME: &str = "it links no dev runtime (`blaze_inproc_rt`, the start hook): its standard library, for \
    `x86_64-pc-windows-msvc` under profile `dev`, was built without it";

#[test]
fn a_dev_process_that_is_no_dev_executable_says_why_and_what_blaze_lacks() {
    for (profile, level) in [
        ("dev", OptLevel::O0),
        ("test", OptLevel::O0),
        ("dev", OptLevel::O1),
        ("mine", OptLevel::O0),
    ] {
        let why = launch_of(profile, "app", &policy(level), Some(NO_RUNTIME)).unwrap_err();
        assert_eq!(
            why,
            format!(
                "`app` runs under profile `{profile}`, so on the daemon's code memory, and can't: {NO_RUNTIME}. {NOT_IN_PROCESS}"
            )
        );
    }
}

#[test]
fn a_release_process_starts_from_its_file() {
    for (profile, level) in [
        ("release", OptLevel::O3),
        ("bench", OptLevel::O3),
        ("release", OptLevel::O0),
        ("dev", OptLevel::O2),
        ("small", OptLevel::Z),
    ] {
        assert_eq!(
            launch_of(profile, "app", &policy(level), Some(NO_RUNTIME)),
            Ok(Launch::File),
            "{profile}"
        );
    }
}

#[test]
fn a_dev_executable_runs_on_the_daemons_code_memory() {
    // `codegen::policy` makes a build live exactly when its unit is a dev executable
    // (`inproc::runs_in_process`): a dev binary or test binary of either profile starts in
    // process, never from its file.
    for (profile, level) in [("dev", OptLevel::O0), ("test", OptLevel::O0), ("test", OptLevel::O1)]
    {
        let mut live = policy(level);
        live.mode = Mode::Live;
        assert_eq!(launch_of(profile, "app", &live, None), Ok(Launch::InProcess), "{profile}");
    }
}

#[test]
fn a_dev_executable_whose_build_is_not_live_is_an_error_not_a_file() {
    let why = launch_of("test", "app", &policy(OptLevel::O0), None).unwrap_err();
    assert!(why.contains("`app`") && why.contains("not live"), "{why}");
}

/// On Windows, `Path` and `PATH` name the same variable: `process_env` joins the build's DLL
/// search directories onto the existing `Path` without leaving duplicate entries.
#[test]
fn process_env_joins_case_insensitive_path_on_windows() {
    use blaze_api::{Artifact, ArtifactKind, CrateType, TargetKind, UnitProfile, UnitTarget};
    let artifact = Artifact {
        package: "path+file:///w#app@0.1.0".into(),
        kind: ArtifactKind::Bin,
        path: "/w/target/debug/app.exe".into(),
        content: ContentId([0; 32]),
        manifest_path: "/w/Cargo.toml".into(),
        target: UnitTarget {
            kind: TargetKind::Bin,
            crate_types: vec![CrateType::Bin],
            name: "app".into(),
            src_path: "/w/src/main.rs".into(),
            edition: "2024".into(),
            doc: false,
            doctest: false,
            test: false,
        },
        profile: UnitProfile {
            opt_level: "0".into(),
            debuginfo: 2,
            debug_assertions: true,
            overflow_checks: true,
            test: false,
        },
        features: Vec::new(),
        filenames: vec!["/w/target/debug/app.exe".into()],
        executable: Some("/w/target/debug/app.exe".into()),
        fresh: false,
        runner: Vec::new(),
        env: vec![
            ("PATH".into(), r"C:\w\target\debug\deps;C:\w\target\debug".into()),
            ("OUT_DIR".into(), r"C:\w\target\debug\build\out".into()),
        ],
        harness: true,
    };
    let job = vec![
        ("Path".to_owned(), r"C:\Windows\System32;C:\Windows".to_owned()),
        ("out_dir".to_owned(), r"C:\stale".to_owned()),
    ];
    let env = super::process_env(&job, &artifact, "windows");
    let paths: Vec<_> = env
        .iter()
        .filter(|(k, _)| k.to_string_lossy().eq_ignore_ascii_case("PATH"))
        .collect();
    assert_eq!(paths.len(), 1, "no duplicate Path/PATH entry: {env:?}");
    assert_eq!(
        paths[0].1.to_string_lossy(),
        r"C:\w\target\debug\deps;C:\w\target\debug;C:\Windows\System32;C:\Windows"
    );
    let out_dirs: Vec<_> = env
        .iter()
        .filter(|(k, _)| k.to_string_lossy().eq_ignore_ascii_case("OUT_DIR"))
        .collect();
    assert_eq!(out_dirs.len(), 1, "no duplicate out_dir/OUT_DIR entry: {env:?}");
    assert_eq!(out_dirs[0].1.to_string_lossy(), r"C:\w\target\debug\build\out");
}
