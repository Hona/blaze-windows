//! The PE linker's run tier: objects the MSVC toolchain compiled (`pe_run/*.c`, `*.cpp`, built
//! by `pe_run/build.ps1`), linked by blaze with the machine's MSVC and Windows SDK libraries as
//! [`crate::target::locate`] finds them, then loaded and run. A structural test of an image
//! says what the writer meant; only the NT loader says whether the image is one.
//!
//! Each program checks itself and exits 0 (or the code its source says), and prints a line the
//! test compares.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use blaze_ids::ContentId;

use blaze_codegen::NativeLib;

use super::{Change, Disk, Image, Native, contents, name};
use crate::{Debug, LinkError, Output, OutputKind};

const TRIPLE: &str = "x86_64-pc-windows-msvc";

fn fixture(file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("tests").join("pe_run").join(file)
}

/// An executable's output (a DLL's when `dll` names it), with `inputs` given as link.exe's
/// bare input files.
fn output(dll: Option<&str>, inputs: &[&str]) -> Output {
    let shared = dll.map(|it| (it.to_owned(), Vec::new()));
    let mut output = crate::target::output(TRIPLE, shared, Debug::None, false).unwrap();
    // The effects' tags the simulated disk checks (`Disk::run`).
    output.tags = 1 << 32;
    output.link.inputs = inputs.iter().map(|it| fixture(it)).collect();
    output
}

/// The image `output` links: its link line located as a build locates it, read whole.
fn link(output: Output) -> Result<Vec<u8>, LinkError> {
    link_with(output, &[])
}

/// The image `output` links with `libs` after the inputs, as the link arguments' libraries are.
fn link_with(mut output: Output, libs: &[NativeLib]) -> Result<Vec<u8>, LinkError> {
    let crates = [crate::target::CrateLibs { libs, search: &[] }];
    let located = crate::target::locate(&mut output, &crates, &[], Path::new("unused"))?;
    let read: Vec<(String, Arc<[u8]>, crate::NativeKind)> = located
        .into_iter()
        .map(|it| {
            let bytes: Arc<[u8]> = match it.made {
                Some((_, made)) => made,
                None => std::fs::read(&it.path).unwrap().into(),
            };
            (it.name, bytes, it.kind)
        })
        .collect();
    let natives = read
        .iter()
        .enumerate()
        .map(|(at, (name, bytes, kind))| Native {
            id: ContentId::of("blaze-link pe run", bytes),
            name,
            bytes,
            kind: *kind,
            order: at as u32,
        })
        .collect();
    let to = match &output.kind {
        OutputKind::Executable { .. } => "out/app.exe",
        OutputKind::Shared { .. } => "out/app.dll",
    };
    let mut image = Image::new(name(to), output)?;
    let mut disk = Disk::default();
    disk.link(&mut image, Change { natives, ..Change::default() })?;
    Ok(contents(disk.file(to)))
}

/// A directory of the test's own, made empty; what the test ran stays there after it, for
/// `dumpbin` and a debugger.
fn scratch(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("blaze-link-pe-run").join(test);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Runs `exe` with `args`: its exit code and what it printed.
fn run(exe: &Path, args: &[&str]) -> (i32, String) {
    let out = Command::new(exe).args(args).output().unwrap_or_else(|e| panic!("{}: {e}", exe.display()));
    let printed = String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n");
    let code = out.status.code().unwrap_or_else(|| panic!("{}: {}", exe.display(), out.status));
    // An NTSTATUS (0xC0000005, 0xC0000135, ...) is a crash or a loader refusal.
    assert!(
        code >= 0,
        "{} ended with {:#x}; it printed {printed:?}, stderr {:?}",
        exe.display(),
        code as u32,
        String::from_utf8_lossy(&out.stderr)
    );
    (code, printed)
}

/// The image's data directories, `(rva, size)` by index.
fn directories(bytes: &[u8]) -> Vec<(u32, u32)> {
    use object::LittleEndian as LE;
    let file = object::read::pe::PeFile64::parse(bytes).unwrap();
    file.data_directories().iter().map(|it| (it.virtual_address.get(LE), it.size.get(LE))).collect()
}

/// That an image the CRT links has what link.exe gives it: the CRT's load configuration (the
/// loader's security cookie, the guard's fields), whose directory size is the size its first
/// field states, and the exception directory.
fn has_crt_directories(bytes: &[u8]) {
    let dirs = directories(bytes);
    let (config, exceptions) =
        (dirs[object::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG], dirs[object::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION]);
    assert!(config.0 != 0 && config.1 >= 0x94, "the load configuration: {config:x?}");
    let stated = u32::from_le_bytes(bytes[config.0 as usize..][..4].try_into().unwrap());
    assert_eq!(stated, config.1, "the load configuration's own size");
    assert!(exceptions.1 > 0 && exceptions.1 % 12 == 0, "the exception directory: {exceptions:x?}");
}

/// Links `inputs` into an executable, writes it in its own directory and runs it.
fn linked_run(test: &str, inputs: &[&str], args: &[&str]) -> (i32, String) {
    let bytes = link(output(None, inputs)).unwrap_or_else(|e| panic!("{test}: {e}"));
    has_crt_directories(&bytes);
    let dir = scratch(test);
    let exe = dir.join(format!("{test}.exe"));
    std::fs::write(&exe, &bytes).unwrap();
    run(&exe, args)
}

#[test]
fn a_c_console_program_with_the_dynamic_crt_runs() {
    let (code, printed) = linked_run("hello_md", &["hello_md.obj"], &["x"]);
    assert_eq!((code, printed.as_str()), (42, "hello from x, 2 args\npid set\nrelocated yes\n"));
}

#[test]
fn a_c_console_program_with_the_static_crt_runs() {
    let (code, printed) = linked_run("hello_mt", &["hello_mt.obj"], &[]);
    assert_eq!((code, printed.as_str()), (42, "hello from nobody, 1 args\npid set\nrelocated yes\n"));
}

#[test]
fn cpp_exceptions_and_static_initialisers_run_with_the_dynamic_crt() {
    assert_eq!(linked_run("cpp_md", &["cpp_md.obj"], &[]), (0, "cpp ok 42 10\n".into()));
}

#[test]
fn cpp_exceptions_and_static_initialisers_run_with_the_static_crt() {
    assert_eq!(linked_run("cpp_mt", &["cpp_mt.obj"], &[]), (0, "cpp ok 42 10\n".into()));
}

#[test]
fn thread_locals_and_a_tls_callback_run() {
    assert_eq!(linked_run("tls", &["tls.obj"], &[]), (0, "tls 100 0 1 4\n".into()));
}

#[test]
fn code_built_with_guard_cf_and_gs_runs() {
    assert_eq!(linked_run("cfg", &["cfg.obj"], &[]), (0, "cfg 22 7\n".into()));
}

/// `output` with link.exe's arguments `args` applied, as a build script gives them, and the
/// libraries they add.
fn with_args(mut output: Output, args: &[&str]) -> (Output, Vec<NativeLib>) {
    let given: Vec<crate::args::GivenArg> = args
        .iter()
        .map(|it| crate::args::GivenArg {
            arg: (*it).to_owned(),
            from: crate::args::ArgFrom::BuildScript { package: "run 0.0.0".into() },
        })
        .collect();
    let applied = crate::args::apply(&mut output, &[], &given).unwrap();
    assert!(applied.search.is_empty(), "{applied:?}");
    (output, applied.libs)
}

#[test]
fn a_gui_program_entered_at_main_crt_startup_runs_without_a_console() {
    let (output, libs) =
        with_args(output(None, &["gui.obj"]), &["/SUBSYSTEM:WINDOWS", "/ENTRY:mainCRTStartup"]);
    let bytes = link_with(output, &libs).unwrap();
    has_crt_directories(&bytes);
    let file = object::read::pe::PeFile64::parse(&bytes[..]).unwrap();
    let optional = &file.nt_headers().optional_header;
    use object::read::pe::ImageOptionalHeader as _;
    assert_eq!(optional.subsystem(), object::pe::IMAGE_SUBSYSTEM_WINDOWS_GUI);
    let dir = scratch("gui");
    std::fs::write(dir.join("gui.exe"), &bytes).unwrap();
    assert_eq!(run(&dir.join("gui.exe"), &[]), (0, "gui without a console\n".into()));
}

/// Two `.res` files of a GUI program merged into its resources, which it reads back as the
/// loader and the shell do (`pe_run/res.c`): the manifest's common controls 6 and per-monitor
/// DPI, the icon, data by name and number, a string in the second file's language, the version.
/// Without the resources it fails every check (`res.c` exits 127), as link.exe's does.
#[test]
fn resources_of_two_res_files_are_the_programs_and_its_manifest_is_applied() {
    let (gui, libs) = with_args(
        output(None, &["res.obj"]),
        &[&fixture("app.res").to_string_lossy(), &fixture("more.res").to_string_lossy(), "/SUBSYSTEM:WINDOWS", "/ENTRY:mainCRTStartup"],
    );
    let bytes = link_with(gui, &libs).unwrap();
    let dirs = directories(&bytes);
    assert!(dirs[object::pe::IMAGE_DIRECTORY_ENTRY_RESOURCE].1 > 0, "{dirs:x?}");
    let dir = scratch("res");
    std::fs::write(dir.join("res.exe"), &bytes).unwrap();
    assert_eq!(run(&dir.join("res.exe"), &[]), (0, "res 0\n".into()));

    // The same program without them: the checks fail, so they read what the link put there.
    let bytes = link(output(None, &["res.obj"])).unwrap();
    std::fs::write(dir.join("bare.exe"), &bytes).unwrap();
    assert_eq!(run(&dir.join("bare.exe"), &[]), (127, "res 127\n".into()));
}

/// `/DELAYLOAD` of three DLLs with `delayimp.lib` (`pe_run/delay.c`): none in the import
/// directory, each loaded by its first call, and the helper's exception for one not there
/// unwinds through the tail merge to the program's `__except`.
#[test]
fn delay_loaded_dlls_load_on_first_call_and_a_missing_one_raises() {
    let (delayed, libs) = with_args(
        output(None, &["delay.obj", "nosuch.lib"]),
        &["/DELAYLOAD:comctl32.dll", "/DELAYLOAD:version.dll", "/DELAYLOAD:NOSUCH.dll", "delayimp.lib"],
    );
    let bytes = link_with(delayed, &libs).unwrap();
    has_crt_directories(&bytes);
    let dlls = dlls(&bytes);
    for it in ["comctl32.dll", "version.dll", "nosuch.dll"] {
        assert!(!dlls.contains(&it.to_owned()), "{it} is imported at load: {dlls:?}");
    }
    let dirs = directories(&bytes);
    assert_eq!(dirs[object::pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].1, 4 * 32, "{dirs:x?}");
    let dir = scratch("delay");
    std::fs::write(dir.join("delay.exe"), &bytes).unwrap();
    assert_eq!(run(&dir.join("delay.exe"), &[]), (0, "delay 0\n".into()));
}

/// The DLLs an image imports from, lowercased, in its import directory's order.
fn dlls(bytes: &[u8]) -> Vec<String> {
    use object::LittleEndian as LE;
    let file = object::read::pe::PeFile64::parse(bytes).unwrap();
    let table = file.import_table().unwrap().expect("an import directory");
    let mut descriptors = table.descriptors().unwrap();
    let mut out = Vec::new();
    while let Some(it) = descriptors.next().unwrap() {
        out.push(String::from_utf8_lossy(table.name(it.name.get(LE)).unwrap()).to_ascii_lowercase());
    }
    out
}

/// rune-desktop's C runtime: the VC runtime static (`+crt-static`, objects built `/MT`), the
/// UCRT the system's DLL (`/NODEFAULTLIB:libucrt.lib /DEFAULTLIB:ucrt.lib`). The image imports
/// the UCRT's API sets and no `VCRUNTIME140.dll`.
#[test]
fn the_static_vc_runtime_with_the_dynamic_ucrt_runs() {
    let mut output = output(None, &["hello_mt.obj"]);
    output.link.pe.crt_static = true;
    let (output, libs) = with_args(output, &["/NODEFAULTLIB:libucrt.lib", "/DEFAULTLIB:ucrt.lib"]);
    let bytes = link_with(output, &libs).unwrap();
    has_crt_directories(&bytes);
    let dlls = dlls(&bytes);
    assert!(dlls.iter().any(|it| it.starts_with("api-ms-win-crt-")), "{dlls:?}");
    assert!(!dlls.iter().any(|it| it.starts_with("vcruntime")), "{dlls:?}");
    let dir = scratch("hybrid_crt");
    std::fs::write(dir.join("hybrid.exe"), &bytes).unwrap();
    let (code, printed) = run(&dir.join("hybrid.exe"), &[]);
    assert_eq!((code, printed.as_str()), (42, "hello from nobody, 1 args\npid set\nrelocated yes\n"));
}

/// A crate asking for the dynamic VC runtime in a `+crt-static` link is refused by name.
#[test]
fn a_crate_asking_for_the_other_vc_runtime_is_refused() {
    let mut output = output(None, &["hello_mt.obj"]);
    output.link.pe.crt_static = true;
    let msvcrt = NativeLib {
        name: "msvcrt".into(),
        kind: blaze_codegen::NativeLibKind::Dylib,
        verbatim: false,
        imports: Vec::new(),
    };
    let error = link_with(output, &[msvcrt]).unwrap_err();
    assert!(error.what.contains("`msvcrt`") && error.what.contains("LNK2038"), "{error}");
}

#[test]
fn an_executable_runs_with_the_dll_it_imports_from() {
    let dll = link(output(Some("runlib.dll"), &["dll.obj"])).unwrap();
    let exe = link(output(None, &["usedll.obj", "runlib.lib"])).unwrap();
    has_crt_directories(&dll);
    has_crt_directories(&exe);
    let dir = scratch("usedll");
    std::fs::write(dir.join("runlib.dll"), &dll).unwrap();
    std::fs::write(dir.join("usedll.exe"), &exe).unwrap();
    let ran = run(&dir.join("usedll.exe"), &[]);
    assert_eq!(ran, (0, "dll 42 found\n".into()));
}
