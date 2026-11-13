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
fn link(mut output: Output) -> Result<Vec<u8>, LinkError> {
    let located = crate::target::locate(&mut output, &[], &[], Path::new("unused"))?;
    let read: Vec<(String, Arc<[u8]>, crate::NativeKind)> = located
        .into_iter()
        .map(|it| {
            let bytes: Arc<[u8]> = std::fs::read(&it.path).unwrap().into();
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
