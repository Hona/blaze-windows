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
fn link_with(output: Output, libs: &[NativeLib]) -> Result<Vec<u8>, LinkError> {
    link_image(output, libs).map(|it| it.0)
}

/// [`link_with`]'s file, and the image it is of.
fn link_image(mut output: Output, libs: &[NativeLib]) -> Result<(Vec<u8>, Image), LinkError> {
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
    Ok((contents(disk.file(to)), image))
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

/// A `raw-dylib` DLL delay-loaded, as rune-desktop has them (`windows-link`'s raw-dylib
/// imports of DLLs its build script also gives `/DELAYLOAD`): `comctl32` and `version` reached
/// through the import libraries the link makes, not the SDK's (`/NODEFAULTLIB` takes those
/// out), and delayed alike.
#[test]
fn raw_dylib_imports_are_delay_loaded_too() {
    let raw = |dll: &str, symbols: &[&str]| NativeLib {
        name: dll.into(),
        kind: blaze_codegen::NativeLibKind::RawDylib,
        verbatim: false,
        imports: symbols
            .iter()
            .map(|it| blaze_codegen::RawImport { symbol: (*it).into(), ordinal: None, data: false })
            .collect(),
    };
    let (delayed, mut libs) = with_args(
        output(None, &["delay.obj", "nosuch.lib"]),
        &[
            "/NODEFAULTLIB:comctl32.lib",
            "/NODEFAULTLIB:version.lib",
            "/DELAYLOAD:comctl32.dll",
            "/DELAYLOAD:version.dll",
            "/DELAYLOAD:nosuch.dll",
            "delayimp.lib",
        ],
    );
    libs.insert(0, raw("comctl32", &["InitCommonControlsEx"]));
    libs.insert(1, raw("version", &["GetFileVersionInfoSizeW"]));
    let bytes = link_with(delayed, &libs).unwrap();
    assert!(!dlls(&bytes).iter().any(|it| it == "comctl32.dll" || it == "version.dll"));
    let dir = scratch("raw_delay");
    std::fs::write(dir.join("delay.exe"), &bytes).unwrap();
    assert_eq!(run(&dir.join("delay.exe"), &[]), (0, "delay 0\n".into()));
}

/// The first file under `build` (cargo's `target\debug\build`) at `<crate>-<hash>\out\<file>`.
fn built(build: &Path, krate: &str, file: &str) -> PathBuf {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(build)
        .unwrap_or_else(|e| panic!("{}: {e}", build.display()))
        .filter_map(|it| it.ok().map(|it| it.path()))
        .filter(|it| {
            it.file_name().and_then(|it| it.to_str()).is_some_and(|it| {
                it.strip_prefix(krate).and_then(|rest| rest.strip_prefix('-')).is_some_and(|hash| {
                    hash.len() == 16 && hash.bytes().all(|b| b.is_ascii_hexdigit())
                })
            })
        })
        .map(|it| it.join("out").join(file))
        .filter(|it| it.is_file())
        .collect();
    dirs.sort();
    dirs.into_iter().next().unwrap_or_else(|| panic!("no {krate}-*\\out\\{file} under {}", build.display()))
}

/// rune-desktop's native libraries as cargo built them (`BLAZE_RUNE_NATIVES` names its
/// `target\debug\build`; Ghostty's is `GHOSTTY_VT_LIB`, else the build script's cache in
/// `%LOCALAPPDATA%\seer\ghostty-vt`), linked as the desktop is: `+crt-static` with the UCRT's
/// DLL, its 13 `/DELAYLOAD`s and `delayimp.lib`, `/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup`, its
/// `.res`, with an entry that calls into each (`pe_run/natives.c`): SQLite, Luau's C++ with a
/// Lua error thrown as a C++ exception, mimalloc on a second thread, zstd, ring's and BLAKE3's
/// assembly, Ghostty's VT. Then run. Without `BLAZE_RUNE_NATIVES` it says so and checks nothing:
/// the libraries are a build's, outside the repository.
#[test]
fn rune_desktops_native_libraries_link_and_run() {
    let Some(build) = std::env::var_os("BLAZE_RUNE_NATIVES").map(PathBuf::from) else {
        eprintln!(
            "skipped: BLAZE_RUNE_NATIVES is not set (rune-desktop's target\\debug\\build after a cargo build)"
        );
        return;
    };
    let ghostty = match std::env::var_os("GHOSTTY_VT_LIB") {
        Some(it) => PathBuf::from(it),
        None => {
            let cache = Path::new(&std::env::var_os("LOCALAPPDATA").unwrap()).join("seer").join("ghostty-vt");
            std::fs::read_dir(&cache)
                .unwrap_or_else(|e| panic!("{}: {e}", cache.display()))
                .filter_map(|it| it.ok().map(|it| it.path().join("ghostty-vt-static.lib")))
                .find(|it| it.is_file())
                .unwrap_or_else(|| panic!("no ghostty-vt-static.lib in {}", cache.display()))
        }
    };
    let luau = built(&build, "mlua-sys", "luau-build\\luauvm.lib");
    let luau = luau.parent().unwrap();
    let mut libs: Vec<PathBuf> = vec![
        built(&build, "libsqlite3-sys", "sqlite3.lib"),
        built(&build, "libmimalloc-sys", "mimalloc.lib"),
        built(&build, "zstd-sys", "zstd.lib"),
        built(&build, "ring", "ring_core_0_17_14_.lib"),
        built(&build, "blake3", "blake3_sse2_sse41_avx2_assembly.lib"),
        ghostty,
    ];
    for it in ["luauvm", "luaucompiler", "luauast", "luaucommon", "luaubytecode", "luauconfig", "luaurequire", "luaucustom", "luauinliner"] {
        libs.push(luau.join(format!("{it}.lib")));
    }
    let res = built(&build, "opencode-desktop", "main_res.res");
    let mut args: Vec<String> = libs.iter().map(|it| it.to_string_lossy().into_owned()).collect();
    args.push(res.to_string_lossy().into_owned());
    for it in ["/NODEFAULTLIB:libucrt.lib", "/DEFAULTLIB:ucrt.lib", "/SUBSYSTEM:WINDOWS", "/ENTRY:mainCRTStartup"] {
        args.push(it.into());
    }
    for dll in [
        "comctl32", "uiautomationcore", "wintrust", "crypt32", "setupapi", "ws2_32", "winmm", "oleaut32", "ole32",
        "shell32", "dwrite", "dxgi", "psapi",
    ] {
        args.push(format!("/DELAYLOAD:{dll}.dll"));
    }
    for it in ["delayimp.lib", "userenv.lib", "ntdll.lib", "bcrypt.lib", "advapi32.lib"] {
        args.push(it.into());
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut desktop = output(None, &["natives.obj"]);
    desktop.link.pe.crt_static = true;
    let (desktop, libs) = with_args(desktop, &args);
    let bytes = link_with(desktop, &libs).unwrap_or_else(|e| panic!("{e}"));
    has_crt_directories(&bytes);
    let dlls = dlls(&bytes);
    assert!(!dlls.iter().any(|it| it == "comctl32.dll" || it == "ws2_32.dll" || it.starts_with("vcruntime")), "{dlls:?}");
    let dir = scratch("rune_natives");
    std::fs::write(dir.join("natives.exe"), &bytes).unwrap();
    assert_eq!(run(&dir.join("natives.exe"), &[]), (0, "natives 0\n".into()));
}

/// A library a member asks for (`/DEFAULTLIB`) goes on the line after every library the link
/// names, as link.exe searches them: Ghostty's Zig-built archive defines `_fltused`, and so does
/// LIBCMT, which an earlier library's members ask for; found right after the first, LIBCMT's
/// was taken too and the link failed with a duplicate (`rune_desktops_native_libraries_link_and_run`).
#[test]
fn default_libraries_are_searched_after_the_named_ones() {
    use object::write::{Object as Builder, Symbol as Def, SymbolSection};
    use object::{Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind, SymbolScope};
    let object = |defines: &str, directives: &str| {
        let mut b = Builder::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
        let text = b.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
        let at = b.append_section_data(text, &[0xc3], 16);
        b.add_symbol(Def {
            name: defines.as_bytes().to_vec(),
            value: at,
            size: 1,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(text),
            flags: SymbolFlags::None,
        });
        let drectve = b.add_section(Vec::new(), b".drectve".to_vec(), SectionKind::Linker);
        b.append_section_data(drectve, directives.as_bytes(), 1);
        b.write().unwrap()
    };
    let dir = scratch("default_order");
    let write = |file: &str, defines: &str, directives: &str| {
        let member = object(defines, directives);
        let bytes = super::natives::archive(&[(&format!("{defines}.obj"), &member, &[defines])]);
        std::fs::write(dir.join(file), bytes).unwrap();
        dir.join(file).to_string_lossy().into_owned()
    };
    let first = write("first.lib", "first_fn", " /DEFAULTLIB:dflt.lib");
    let second = write("second.lib", "second_fn", "");
    write("dflt.lib", "dflt_fn", "");
    let lib = |name: &str| NativeLib {
        name: name.into(),
        kind: blaze_codegen::NativeLibKind::Static { whole: false, bundle: false },
        verbatim: true,
        imports: Vec::new(),
    };
    let mut output = output(None, &[]);
    let libs = [lib(&first), lib(&second)];
    let search = [dir.clone()];
    let crates = [crate::target::CrateLibs { libs: &libs, search: &[] }];
    let located = crate::target::locate(&mut output, &crates, &search, Path::new("unused")).unwrap();
    let files: Vec<String> = located
        .iter()
        .map(|it| it.path.file_name().unwrap().to_string_lossy().to_ascii_lowercase())
        .collect();
    assert_eq!(files, ["first.lib", "second.lib", "dflt.lib"]);
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

/// A DLL's import library as blaze writes it (`Image::import_library`, what rustc writes as a
/// `cdylib`'s `.dll.lib`) links the importer as `lib.exe`'s does: its function and its data.
#[test]
fn a_dlls_own_import_library_links_its_importer() {
    let (dll, image) = link_image(output(Some("runlib.dll"), &["dll.obj"]), &[]).unwrap();
    let library = image.import_library().unwrap().expect("a DLL's import library");
    let dir = scratch("implib");
    std::fs::write(dir.join("runlib.dll"), &dll).unwrap();
    std::fs::write(dir.join("runlib.lib"), &library).unwrap();
    let importer = output(None, &["usedll.obj"]);
    let lib = NativeLib {
        name: dir.join("runlib.lib").to_string_lossy().into_owned(),
        kind: blaze_codegen::NativeLibKind::Dylib,
        verbatim: true,
        imports: Vec::new(),
    };
    let exe = link_with(importer, &[lib]).unwrap();
    std::fs::write(dir.join("usedll.exe"), &exe).unwrap();
    assert_eq!(run(&dir.join("usedll.exe"), &[]), (0, "dll 42 found\n".into()));
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
