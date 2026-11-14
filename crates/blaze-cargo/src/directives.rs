//! What a build script in the sandbox may tell cargo. A script is code from anywhere, and what
//! it prints goes into every rustc and linker run of its package and of what links it: a
//! `rustc-link-search` into the home directory, a `rustc-link-arg` that loads a plugin into
//! the linker, or a `rustc-env` that overrides `CARGO_PKG_VERSION` reaches past the sandbox it
//! ran in. So the directives of a sandboxed run are checked before cargo reads them
//! ([`refused`]), and one that breaks a rule fails the build, naming the script, the line and
//! the rule (`blaze explain sandbox:link-dir`, [`blaze_report::rules`]):
//!
//! - `rustc-link-search` and `rustc-flags`' `-L`: a directory inside the script's `OUT_DIR`,
//!   its package, the target directory's build directory (the `OUT_DIR`s of its dependencies,
//!   which `DEP_*` names), a system directory ([`SYSTEM`], and what the workspace adds in
//!   `build-script-link-dirs`), or a layout of blaze's own store of pinned native inputs
//!   ([`Ran::native`]).
//! - `rustc-link-arg` (and its `-bins`, `-bin=`, `-tests`, `-benches`, `-examples` and
//!   `-cdylib` forms): one of [`LINK_ARGS`], one of [`LINK_ARG_PREFIXES`] with one value that
//!   is no further linker word, or an rpath to a directory `rustc-link-search` may name. For an
//!   MSVC target, also an option of [`MSVC_OPTIONS`] (`/NAME` or `-NAME`, of any case) with
//!   the value its rule takes, and a library or an object, a `.res` or a `.def` named by
//!   itself: a library's bare name, or a file in a directory `rustc-link-search` may name.
//! - `rustc-env`: not a variable cargo gives a crate itself, nor one rustc, rustdoc or cargo
//!   reads when building it ([`given_by_cargo`]).
//!
//! What counting these rules over the bench corpus found (590 scripts, 2026-10-27) decided
//! their edges: no
//! `rustc-link-search` outside those directories, `-pthread` and an rpath into the Nix store
//! the only link arguments outside the list, and `CARGO_COMMIT_HASH` (cargo's own build) the
//! only `CARGO_*` a script set, which cargo never sets for a crate.
//!
//! A run outside the sandbox, which its workspace took out by name, is not checked: it can do
//! anything anyway.
//!
//! On a Windows host the system's directories are those of the toolchain the linker searches
//! anyway: each directory of the script's `LIB` (what a developer prompt sets, and what
//! `link.exe` and blaze's linker search), and the trees Visual Studio and the Windows SDK
//! install into ([`windows_system_dirs`]). A directory is compared as Windows compares it:
//! `C:\a`, `c:/a`, `\\?\C:\a` and the daemon's `/C:/a` are one, whatever the case of a letter.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

/// The system's directories of libraries, which the linker searches anyway: naming one adds
/// nothing a script could not link already. The Nix store is the closure a script's tools
/// come from; Homebrew's prefixes and Apple's SDKs are where a Mac's libraries are.
pub const SYSTEM: [&str; 11] = [
    "/usr/lib",
    "/usr/lib64",
    "/usr/local/lib",
    "/lib",
    "/lib64",
    "/nix/store",
    "/opt/homebrew/lib",
    "/opt/homebrew/opt",
    "/usr/local/opt",
    "/Library/Developer/CommandLineTools/SDKs",
    "/Applications/Xcode.app/Contents/Developer/Platforms",
];

/// The link arguments a script may give, whole: what changes how the output is linked, never
/// which program links it or what it loads.
pub const LINK_ARGS: [&str; 20] = [
    "-pthread",
    "-rdynamic",
    "-nostartfiles",
    "-Wl,--as-needed",
    "-Wl,--no-as-needed",
    "-Wl,--gc-sections",
    "-Wl,--export-dynamic",
    "-Wl,-z,relro",
    "-Wl,-z,now",
    "-Wl,-z,noexecstack",
    "-Wl,-z,nodelete",
    "-Wl,-undefined,dynamic_lookup",
    "-Wl,-dead_strip",
    "-Wl,-headerpad_max_install_names",
    "-headerpad_max_install_names",
    "-Wl,-z,defs",
    // pyo3's `extension-module` on macOS: two arguments, `-undefined` then its value. Neither
    // names a path, and blaze's linker reads `dynamic_lookup` only after `-undefined`.
    "-undefined",
    "dynamic_lookup",
    // Apple's: load every member of an archive that defines an Objective-C class or category.
    "-ObjC",
    "-Wl,-ObjC",
];

/// The link arguments a script may give with a value of its own after the prefix: a symbol
/// or a pattern of symbols to export, a library's own name, a version script. The value is
/// one word of the linker's ([`one_value`]). `--export-dynamic-symbol` only adds names the
/// image already defines to its dynamic symbol table, as `--export-dynamic` adds them all:
/// it loads nothing and names no file (evm2-jit gives `__revmc_builtin_*` so, for the code
/// its JIT makes to find them).
const LINK_ARG_PREFIXES: [&str; 6] = [
    "-Wl,--export-dynamic-symbol=",
    "-Wl,--export-dynamic-symbol,",
    "-Wl,-soname,",
    "-Wl,-install_name,@rpath/",
    "-Wl,-exported_symbol,",
    "-Wl,--version-script=",
];

/// Where a script ran, which decides what its directives may name.
pub struct Ran<'a> {
    pub package_dir: &'a Path,
    pub out_dir: &'a Path,
    /// The system directories the workspace allows besides [`SYSTEM`].
    pub link_dirs: &'a [PathBuf],
    /// blaze's store of pinned native inputs, `<BLAZE_HOME>/native`, when the daemon has a
    /// home: each `sha256-<digest>` directly under it is the read-only unpacking of the
    /// archive of that digest, which blaze laid out whole (docs/cargo.md, "Pinned native
    /// inputs"), so one may be searched and be an rpath as a directory of `/nix/store` may,
    /// whichever workspace pinned it: a machine whose only LLVM is the one blaze fetched
    /// points `LLVM_SYS_231_PREFIX` at it.
    pub native: Option<&'a Path>,
    /// The host's own directories of libraries beside [`SYSTEM`]: on Windows the toolchain's
    /// ([`windows_system_dirs`]).
    pub system: &'a [PathBuf],
    /// Whether the script's package is built for an MSVC target, whose linker takes
    /// [`MSVC_OPTIONS`] and files named on its line.
    pub msvc: bool,
    /// Whether the host spells paths as Windows does: `\` a separator, a drive first, and a
    /// letter's case no difference ([`Spelling`]).
    pub windows: bool,
}

/// A path as one spelling a directive's path is compared in: `/` between its parts, each `.`
/// and `..` resolved; on a Windows host an absolute path as the daemon names it (`/C:/a`,
/// `/UNC/server/share/a`) and ASCII letters lowered, as Windows compares names. Only
/// compared, never opened.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Spelling {
    parts: Vec<String>,
    absolute: bool,
}

impl Spelling {
    fn of(path: &str, windows: bool) -> Spelling {
        let path = match windows {
            true => windows_spelling(path),
            false => std::borrow::Cow::Borrowed(path),
        };
        let absolute = path.starts_with('/');
        let mut parts: Vec<String> = Vec::new();
        for part in path.split('/') {
            match part {
                "" | "." => {}
                ".." if absolute || parts.last().is_some_and(|it| it != "..") => {
                    parts.pop();
                }
                part if windows => parts.push(part.to_ascii_lowercase()),
                part => parts.push(part.to_owned()),
            }
        }
        Spelling { parts, absolute }
    }

    fn starts_with(&self, root: &Spelling) -> bool {
        self.absolute == root.absolute && self.parts.starts_with(&root.parts)
    }

    /// Whether a relative path climbs out of where it starts.
    fn climbs(&self) -> bool {
        !self.absolute && self.parts.first().is_some_and(|it| it == "..")
    }
}

/// `path` as the daemon names it on Windows ([`blaze_core::platform::path::daemon`]: `C:\a`
/// and `\\?\C:\a` are `/C:/a`, `\\server\share` is `/UNC/server/share`), and a relative one
/// with `/` between its parts, as Windows reads `\` in any path.
fn windows_spelling(path: &str) -> std::borrow::Cow<'_, str> {
    match blaze_core::platform::path::daemon(Path::new(path)) {
        Ok(name) => name.into(),
        Err(_) if path.contains('\\') => path.replace('\\', "/").into(),
        Err(_) => path.into(),
    }
}

impl Ran<'_> {
    fn spelling(&self, path: &Path) -> Spelling {
        Spelling::of(&path.to_string_lossy(), self.windows)
    }

    /// The target directory's build directory, whose subdirectories are every package's
    /// `OUT_DIR`: `<build>/<package>-<hash>/out` or `<build>/<package>/<hash>/out`.
    fn build_dir(&self) -> Option<Spelling> {
        let mut out = self.spelling(self.out_dir);
        let is_build = |it: &Spelling| it.parts.last().is_some_and(|it| it == "build");
        for _ in 0..2 {
            out.parts.pop()?;
        }
        if is_build(&out) {
            return Some(out);
        }
        out.parts.pop()?;
        is_build(&out).then_some(out)
    }

    /// Whether `rustc-link-search` may name `dir`.
    fn may_search(&self, dir: &str) -> bool {
        self.may_search_spelt(&Spelling::of(dir, self.windows))
    }

    /// Whether the linker may read the file `file` (a library, an object, a resource, a
    /// manifest or a module definition named on its line): one in a directory
    /// `rustc-link-search` may name.
    fn may_read(&self, file: &str) -> bool {
        let mut file = Spelling::of(file, self.windows);
        file.parts.pop().is_some() && self.may_search_spelt(&file)
    }

    fn may_search_spelt(&self, dir: &Spelling) -> bool {
        if !dir.absolute {
            // A relative one is relative to where rustc runs, the package's directory.
            return !dir.climbs();
        }
        if self.in_native_layout(dir) {
            return true;
        }
        let paths = [self.out_dir, self.package_dir]
            .into_iter()
            .chain(self.system.iter().map(PathBuf::as_path))
            .chain(self.link_dirs.iter().map(PathBuf::as_path))
            .map(|it| self.spelling(it));
        let system = SYSTEM.iter().map(|it| Spelling::of(it, self.windows));
        paths.chain(self.build_dir()).chain(system).any(|it| dir.starts_with(&it))
    }

    /// Whether `dir`, normalized, is a layout of [`Self::native`] or inside one: under a
    /// `sha256-` and 64 lowercase hex digits directly below the store, never the store itself
    /// or what a layout under way leaves beside the layouts.
    fn in_native_layout(&self, dir: &Spelling) -> bool {
        let Some(store) = self.native.map(|it| self.spelling(it)) else { return false };
        if !dir.starts_with(&store) {
            return false;
        }
        dir.parts.get(store.parts.len()).and_then(|it| it.strip_prefix("sha256-")).is_some_and(
            |hex| hex.len() == 64 && hex.bytes().all(|it| matches!(it, b'0'..=b'9' | b'a'..=b'f')),
        )
    }

    /// Why the link argument `arg` is refused, `None` when it is not.
    fn link_arg_refused(&self, arg: &str) -> Option<String> {
        if self.msvc
            && let Some(verdict) = self.msvc_arg(arg)
        {
            return verdict.err();
        }
        let rpath =
            ["-Wl,-rpath,", "-Wl,-rpath=", "-Wl,-R"].iter().find_map(|it| arg.strip_prefix(it));
        if let Some(dir) = rpath {
            let relative = ["$ORIGIN", "@loader_path", "@executable_path"];
            return match relative.iter().any(|it| dir.starts_with(it)) || self.may_search(dir) {
                true => None,
                false => Some(format!("an rpath to `{dir}`, which is none of {}", self.places())),
            };
        }
        let known = LINK_ARGS.contains(&arg)
            || LINK_ARG_PREFIXES.iter().any(|it| arg.strip_prefix(it).is_some_and(one_value))
            || arg.strip_prefix("-l").is_some_and(|name| {
                !name.is_empty()
                    && name.chars().all(|it| it.is_ascii_alphanumeric() || "_+.-".contains(it))
            });
        (!known).then(|| {
            format!("a link argument that is not one a build script may give ({})", allowed_args())
        })
    }

    fn places(&self) -> String {
        "the script's OUT_DIR, its package, the build directory, a system directory, a layout \
         of blaze's pinned native inputs or one `build-script-link-dirs` names"
            .to_owned()
    }

    /// The verdict on `arg` for an MSVC linker: `None` when it is no MSVC form (a `-` word no
    /// option of [`MSVC_OPTIONS`] names, which the other rules judge), else whether it may be
    /// given and why not.
    fn msvc_arg(&self, arg: &str) -> Option<Result<(), String>> {
        let Some(option) = arg.strip_prefix('/').or_else(|| arg.strip_prefix('-')) else {
            return Some(self.msvc_file(arg));
        };
        let (name, value) = match option.split_once(':') {
            Some((name, value)) => (name, Some(value)),
            None => (option, None),
        };
        let upper = name.to_ascii_uppercase();
        let Some((_, takes)) = MSVC_OPTIONS.iter().find(|(it, _)| *it == upper) else {
            // `-pthread` and the like are the other rules'; a `/` word is an MSVC option
            // whatever it is.
            return arg.starts_with('/').then(|| {
                Err(format!(
                    "`/{name}`, an MSVC link option that is not one a build script may give ({})",
                    allowed_msvc_options()
                ))
            });
        };
        let wrong = |what: &str| Err(format!("`/{upper}` {what}"));
        Some(match (takes, value) {
            (Takes::Nothing, None) => Ok(()),
            (Takes::Nothing, Some(_)) => wrong("takes no value"),
            (Takes::OptionalWord | Takes::OptionalLibrary, None) => Ok(()),
            (Takes::Word | Takes::Text | Takes::File | Takes::Library | Takes::Dir, None) => {
                wrong("takes a value after `:`")
            }
            (Takes::Word | Takes::OptionalWord, Some(value)) => match word(value) {
                true => Ok(()),
                false => wrong(&format!(
                    "takes a name, a number or a list of them, not `{value}`: no path, space or \
                     quote"
                )),
            },
            (Takes::Text, Some(value)) => match value.contains(['/', '\\']) {
                false => Ok(()),
                true => wrong(&format!("takes text that names no path, not `{value}`")),
            },
            (Takes::File, Some(value)) => match self.may_read(value) {
                true => Ok(()),
                false => wrong(&format!("names `{value}`, a file in none of {}", self.places())),
            },
            (Takes::Library | Takes::OptionalLibrary, Some(value)) => self.msvc_library(value),
            (Takes::Dir, Some(value)) => match self.may_search(value) {
                true => Ok(()),
                false => wrong(&format!("names `{value}`, which is none of {}", self.places())),
            },
        })
    }

    /// A file named on an MSVC linker's line by itself: a library (`delayimp.lib`, a name the
    /// linker looks for on its search path, or a path), or an object, a compiled resource or a
    /// module definition in a directory `rustc-link-search` may name.
    fn msvc_file(&self, arg: &str) -> Result<(), String> {
        let lower = arg.to_ascii_lowercase();
        if lower.ends_with(".lib") || lower.ends_with(".a") {
            return self.msvc_library(arg);
        }
        if !MSVC_FILES.iter().any(|it| lower.ends_with(it)) {
            return Err(format!(
                "`{arg}`, which is neither an MSVC link option nor a library, object, resource or \
                 module definition ({})",
                allowed_msvc_options()
            ));
        }
        match self.may_read(arg) {
            true => Ok(()),
            false => Err(format!("`{arg}`, a file in none of {}", self.places())),
        }
    }

    /// A library on an MSVC linker's line: its bare name, which the linker finds on the search
    /// path the rules hold, or a path to one where `rustc-link-search` may go.
    fn msvc_library(&self, library: &str) -> Result<(), String> {
        let path = library.contains(['/', '\\', ':']);
        match (path, path && self.may_read(library) || !path && word(library)) {
            (_, true) => Ok(()),
            (true, false) => {
                Err(format!("the library `{library}`, a file in none of {}", self.places()))
            }
            (false, false) => Err(format!("the library `{library}`, which is no library's name")),
        }
    }
}

/// What an MSVC link option takes after its `:`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Takes {
    /// No value: `/NOLOGO`.
    Nothing,
    /// One [`word`] or a `,` list of them: a name, a symbol, a number, a section's attributes.
    Word,
    /// A [`Takes::Word`], or no value: `/DEBUG`, `/DEBUG:FULL`.
    OptionalWord,
    /// Text that names no path: `/MANIFESTUAC:"level='asInvoker' uiAccess='false'"`.
    Text,
    /// A file the linker reads, in a directory `rustc-link-search` may name.
    File,
    /// A library: its name, or a path to one as [`Takes::File`].
    Library,
    /// A [`Takes::Library`], or no value: `/NODEFAULTLIB` alone takes every default away.
    OptionalLibrary,
    /// A directory the linker searches, one `rustc-link-search` may name.
    Dir,
}

/// The MSVC link options a build script may give (rune-desktop's `/SUBSYSTEM`, `/ENTRY` and
/// `/DELAYLOAD`, tauri's `/MANIFEST:EMBED`, `/MANIFESTINPUT` and `/WX`, the hybrid CRT's
/// `/NODEFAULTLIB` and `/DEFAULTLIB`), by name, with what each takes: what changes how the
/// image is linked, never which program links it, nor a file it writes (`/OUT`, `/PDB`,
/// `/IMPLIB`, `/MAP:`, `/MANIFESTFILE` are none of these) or reads outside the places a search
/// may go. `windows/link` reads each of them (`blaze-link`'s `Spelling::Msvc`). Sorted.
pub const MSVC_OPTIONS: [(&str, Takes); 43] = [
    ("ALTERNATENAME", Takes::Word),
    ("BASE", Takes::Word),
    ("CETCOMPAT", Takes::OptionalWord),
    ("DEBUG", Takes::OptionalWord),
    ("DEBUGTYPE", Takes::Word),
    ("DEF", Takes::File),
    ("DEFAULTLIB", Takes::Library),
    ("DELAY", Takes::Word),
    ("DELAYLOAD", Takes::Word),
    ("DYNAMICBASE", Takes::OptionalWord),
    ("ENTRY", Takes::Word),
    ("EXPORT", Takes::Word),
    ("FIXED", Takes::OptionalWord),
    ("FORCE", Takes::OptionalWord),
    ("GUARD", Takes::Word),
    ("HEAP", Takes::Word),
    ("HIGHENTROPYVA", Takes::OptionalWord),
    ("IGNORE", Takes::Word),
    ("INCLUDE", Takes::Word),
    ("INCREMENTAL", Takes::OptionalWord),
    ("LARGEADDRESSAWARE", Takes::OptionalWord),
    ("LIBPATH", Takes::Dir),
    ("MANIFEST", Takes::OptionalWord),
    ("MANIFESTDEPENDENCY", Takes::Text),
    ("MANIFESTINPUT", Takes::File),
    ("MANIFESTUAC", Takes::Text),
    ("MERGE", Takes::Word),
    ("NATVIS", Takes::File),
    ("NODEFAULTLIB", Takes::OptionalLibrary),
    ("NOLOGO", Takes::Nothing),
    ("NXCOMPAT", Takes::OptionalWord),
    ("OPT", Takes::Word),
    ("OSVERSION", Takes::Word),
    ("RELEASE", Takes::Nothing),
    ("SAFESEH", Takes::OptionalWord),
    ("SECTION", Takes::Word),
    ("STACK", Takes::Word),
    ("STUB", Takes::File),
    ("SUBSYSTEM", Takes::Word),
    ("TSAWARE", Takes::OptionalWord),
    ("VERSION", Takes::Word),
    ("WHOLEARCHIVE", Takes::OptionalLibrary),
    ("WX", Takes::OptionalWord),
];

/// What an MSVC linker reads when it is named by itself on its line, besides a library
/// (`.lib`, `.a`): an object, a compiled resource (winresource's `resource.res`), and an
/// export file.
const MSVC_FILES: [&str; 4] = [".obj", ".o", ".res", ".exp"];

/// Whether `value` is one word or a `,` list of words an MSVC option takes: a name, a symbol
/// (C++'s `?f@@YAXXZ`), a number, `.rdata=.text`. No path: no `/`, `\` or `:`; no space or
/// quote, which would make it more words of the line.
fn word(value: &str) -> bool {
    !value.is_empty()
        && !value.contains(['/', '\\', ':', '"', '\''])
        && !value.chars().any(char::is_whitespace)
}

fn allowed_msvc_options() -> String {
    let names: Vec<String> = MSVC_OPTIONS.iter().map(|(name, _)| format!("`/{name}`")).collect();
    format!(
        "{}, and a library, object, resource or export file in a directory the search may name",
        names.join(", ")
    )
}

/// The directories a Windows host's linker searches anyway, from a script's environment `env`:
/// each of `LIB`'s, which a developer prompt sets for the toolchain it chose, and the trees
/// Visual Studio and the Windows SDK install into (`ProgramFiles`, `ProgramFiles(x86)`), where
/// `cc` finds the toolchain by itself (vswhere, the registry) and names, for one, ATL's `lib`.
/// Names compare as Windows compares them ([`Spelling`]).
pub fn windows_system_dirs(env: &[(OsString, OsString)]) -> Vec<PathBuf> {
    let var = |name: &str| {
        env.iter().rev().find(|(it, _)| it.eq_ignore_ascii_case(name)).map(|(_, value)| value)
    };
    // alloc: once per run checked, a few directories
    let mut dirs = Vec::new();
    if let Some(lib) = var("LIB") {
        dirs.extend(
            lib.to_string_lossy().split(';').filter(|it| !it.is_empty()).map(PathBuf::from),
        );
    }
    for root in ["ProgramFiles", "ProgramFiles(x86)"] {
        let Some(root) = var(root) else { continue };
        for tree in ["Microsoft Visual Studio", "Windows Kits"] {
            dirs.push(Path::new(root).join(tree));
        }
    }
    dirs
}

/// Whether a value after a prefix is one word of the linker's that names no path above where
/// it is. `-Wl,` splits at every comma, so a value with one is more words: after
/// `-Wl,-soname,x` a `,--plugin,/tmp/p.so` or a `,-rpath,/home/u` would be an option of its
/// own that no rule here read.
fn one_value(value: &str) -> bool {
    !value.is_empty() && !value.contains(',') && !value.split('/').any(|it| it == "..")
}

fn allowed_args() -> String {
    let mut all: Vec<String> = LINK_ARGS.iter().map(|it| format!("`{it}`")).collect();
    all.extend(LINK_ARG_PREFIXES.iter().map(|it| format!("`{it}...`")));
    all.push("`-lNAME`".to_owned());
    all.push("an rpath to `$ORIGIN` or to a directory `rustc-link-search` may name".to_owned());
    all.join(", ")
}

/// The variables, sorted, that cargo gives a crate's compilation or that rustc, rustdoc or cargo
/// read at run time when building a crate, from their source at the pinned nightly
/// (rust-lang/rust 16d1ffac17ad, its cargo at cad07cf8e597). Left out: what only bootstrap
/// (`src/bootstrap`), tests or tidy read, what the compiler's own build bakes in with
/// `option_env!` or `env!` (`RUSTC_VERIFY_LLVM_IR`, `RUSTC_INSTALL_BINDIR`), what only rustc's
/// build scripts read (`RUSTC_WINDOWS_RC`), and what cargo gives only build scripts
/// (`RUSTC_LINKER`).
pub const GIVEN: [&str; 47] = [
    // cargo `src/lib.rs` (`CARGO_ENV`), `src/compiler/compilation.rs`.
    "CARGO",
    "CARGO_BIN_NAME",
    "CARGO_CRATE_NAME",
    // The jobserver crate's `Client::configure`, which cargo calls on each rustc.
    "CARGO_MAKEFLAGS",
    "CARGO_MANIFEST_DIR",
    "CARGO_MANIFEST_PATH",
    // cargo `src/compiler/mod.rs`.
    "CARGO_PRIMARY_PACKAGE",
    // Unstable in cargo's "Environment variables Cargo sets for crates"; not set at this commit.
    "CARGO_RUSTC_CURRENT_DIR",
    // cargo `src/compiler/mod.rs`.
    "CARGO_SBOM_PATH",
    "CARGO_TARGET_TMPDIR",
    // cargo `src/compiler/mod.rs`.
    "OUT_DIR",
    "RUSTC",
    // `compiler/rustc_feature/src/lib.rs`, cargo `src/compiler/custom_build.rs`.
    "RUSTC_BOOTSTRAP",
    // `compiler/rustc_driver_impl/src/lib.rs`.
    "RUSTC_BREAK_ON_ICE",
    // `compiler/rustc_session/src/session.rs`.
    "RUSTC_CTFE_BACKTRACE",
    // `compiler/rustc_span/src/def_id.rs`, `compiler/rustc_incremental/src/persist/file_format.rs`.
    "RUSTC_FORCE_RUSTC_VERSION",
    // `compiler/rustc_session/src/config.rs`.
    "RUSTC_GRAPHVIZ_FONT",
    // `compiler/rustc_driver_impl/src/lib.rs`.
    "RUSTC_ICE",
    // `compiler/rustc_driver_impl/src/lib.rs` into `compiler/rustc_log/src/lib.rs`
    // (`LoggerConfig::from_env`), `compiler/rustc_session/src/session.rs`.
    "RUSTC_LOG",
    "RUSTC_LOG_BACKTRACE",
    "RUSTC_LOG_COLOR",
    "RUSTC_LOG_ENTRY_EXIT",
    "RUSTC_LOG_FORMAT_JSON",
    "RUSTC_LOG_LINES",
    "RUSTC_LOG_OUTPUT_TARGET",
    "RUSTC_LOG_THREAD_IDS",
    "RUSTC_LOG_WRAPTREE",
    // `compiler/rustc_driver_impl/src/lib.rs`, `compiler/rustc_ast/src/attr/version.rs`.
    "RUSTC_OVERRIDE_VERSION_STRING",
    // cargo `src/context/mod.rs` (`maybe_get_tool`).
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTC_WRAPPER",
    "RUSTDOC",
    // cargo `src/compiler/build_context/target_info.rs`.
    "RUSTDOCFLAGS",
    // `src/librustdoc/doctest.rs`, `src/librustdoc/doctest/runner.rs`.
    "RUSTDOC_DOCTEST_BIN_PATH",
    "RUSTDOC_DOCTEST_RUN_NB_TEST",
    // cargo `src/ops/cargo_compile/mod.rs`.
    "RUSTDOC_FLAGS",
    // `src/librustdoc/lib.rs` into `compiler/rustc_log/src/lib.rs` (`LoggerConfig::from_env`).
    "RUSTDOC_LOG",
    "RUSTDOC_LOG_BACKTRACE",
    "RUSTDOC_LOG_COLOR",
    "RUSTDOC_LOG_ENTRY_EXIT",
    "RUSTDOC_LOG_FORMAT_JSON",
    "RUSTDOC_LOG_LINES",
    "RUSTDOC_LOG_OUTPUT_TARGET",
    "RUSTDOC_LOG_THREAD_IDS",
    "RUSTDOC_LOG_WRAPTREE",
    "RUSTFLAGS",
    // `compiler/rustc_driver_impl/src/lib.rs`, `compiler/rustc_lint/src/non_local_def.rs`.
    "UNSTABLE_RUSTDOC_TEST_LINE",
    "UNSTABLE_RUSTDOC_TEST_PATH",
];

/// Whether `name` is one a script's `rustc-env` may not set: one of [`GIVEN`], or what cargo
/// gives a crate under `CARGO_PKG_` and `CARGO_BIN_EXE_`. What cargo gives only build scripts
/// (`CARGO_CFG_*`, `CARGO_FEATURE_*`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_MANIFEST_LINKS`) is not
/// one: a crate has it only when its script forwards it, as rav1e's does. Nor is
/// `CARGO_COMMIT_HASH`, which cargo's build sets for cargo, or a `RUSTC_*` no tool reads, such
/// as rust-analyzer's `RUSTC_VERSION`.
pub fn given_by_cargo(name: &str) -> bool {
    const PREFIXES: [&str; 2] = ["CARGO_PKG_", "CARGO_BIN_EXE_"];
    GIVEN.binary_search(&name).is_ok() || PREFIXES.iter().any(|it| name.starts_with(it))
}

/// The directory of a search path, without its kind (`native=`, `framework=`, ...).
fn search_dir(value: &str) -> &str {
    match value.split_once('=') {
        Some(("native" | "crate" | "dependency" | "framework" | "all", dir)) => dir,
        _ => value,
    }
}

/// One line a sandboxed script printed that a rule refuses.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Refused {
    /// The rule's id ([`blaze_report::rules`]): `sandbox:link-dir`, `sandbox:link-arg` or
    /// `sandbox:rustc-env`.
    pub rule: &'static str,
    /// The line, whole.
    pub line: String,
    /// Why, with code in backticks.
    pub why: String,
}

/// Each line of `stdout` a run `ran` printed that its rules refuse, with why.
pub fn refused(stdout: &[u8], ran: &Ran<'_>) -> Vec<Refused> {
    let mut out = Vec::new();
    for line in String::from_utf8_lossy(stdout).lines() {
        let line = line.trim();
        let data = match (line.strip_prefix("cargo::"), line.strip_prefix("cargo:")) {
            (Some(data), _) => data,
            (None, Some(data)) if blaze_build_script::output::has_reserved_prefix(data) => data,
            _ => continue,
        };
        let Some((key, value)) = data.split_once('=') else { continue };
        let value = value.trim_end();
        let (rule, why) = match key {
            "rustc-link-search" => (
                "sandbox:link-dir",
                (!ran.may_search(search_dir(value)))
                    .then(|| format!("a library directory that is none of {}", ran.places())),
            ),
            "rustc-flags" => {
                let mut flags = value.split_whitespace();
                let mut why = None;
                while let Some(flag) = flags.next() {
                    let Some(rest) = flag.strip_prefix("-L") else { continue };
                    let dir = match rest.is_empty() {
                        true => flags.next().unwrap_or_default(),
                        false => rest,
                    };
                    if !ran.may_search(search_dir(dir)) {
                        why = Some(format!("`-L {dir}`, which is none of {}", ran.places()));
                    }
                }
                ("sandbox:link-dir", why)
            }
            "rustc-link-arg-bin" => (
                "sandbox:link-arg",
                value.split_once('=').and_then(|(_, arg)| ran.link_arg_refused(arg)),
            ),
            "rustc-link-arg"
            | "rustc-link-arg-bins"
            | "rustc-link-arg-tests"
            | "rustc-link-arg-benches"
            | "rustc-link-arg-examples"
            | "rustc-link-arg-cdylib"
            | "rustc-cdylib-link-arg" => ("sandbox:link-arg", ran.link_arg_refused(value)),
            "rustc-env" => (
                "sandbox:rustc-env",
                value.split_once('=').filter(|(name, _)| given_by_cargo(name)).map(|(name, _)| {
                    format!("`{name}`, which cargo gives the crate or the toolchain acts on itself")
                }),
            ),
            _ => continue,
        };
        if let Some(why) = why {
            out.push(Refused { rule, line: line.to_owned(), why }); // alloc: a refusal's, once
        }
    }
    out
}

/// The report of a build a script of `package` broke the rules of, `at` naming the script:
/// each line refused and why, under the first's rule, and the ways out.
pub fn refused_report(
    package: &str,
    at: blaze_report::Text,
    refused: &[Refused],
) -> blaze_report::Report {
    use blaze_report::{Fix, Report, Text};
    let what = match refused.len() {
        1 => "a directive",
        _ => "directives",
    };
    let headline =
        Text::new().words("a build script printed ").words(what).words(" its sandbox refuses");
    let mut report = Report::error(headline).at(at);
    if let Some(first) = refused.first() {
        report = report.rule(first.rule);
    }
    for it in refused {
        let mut text = Text::new().code(&it.line).words(": ");
        text.0.extend(Text::marked(&it.why).0);
        report = report.fact("refused", text);
    }
    if refused.iter().any(|it| it.rule == "sandbox:link-dir") {
        report = report.fix(Fix::note(
            Text::new()
                .words("a directory of the system it links from goes in ")
                .code("build-script-link-dirs = [...]")
                .words(" under ")
                .code("[workspace.metadata.blaze.sandbox]")
                .words(" in the workspace's root manifest"),
        ));
    }
    report.fix(Fix::note(
        Text::new()
            .words("a script that needs more runs outside the sandbox: ")
            .code(&format!("unsandboxed-build-scripts = [\"{package}\"]")) // alloc: a refusal's, once
            .words(" there"),
    ))
}

/// The directories every workspace's scripts may name on this machine, beside a workspace's
/// own: `build-script-link-dirs` under `[sandbox]` in blaze's settings (`config.toml` in its
/// home, [`blaze_manifest::user_config`]), as [`link_dirs`] reads a workspace's. Where a
/// library of the machine is (a cache a script fills, rune-desktop's Ghostty under
/// `%LOCALAPPDATA%\seer\ghostty-vt`) is the machine's to say, not each checkout's: `${NAME}/rest`
/// names one under a variable of the script's environment. Read as a run is checked, as the
/// store of pinned native inputs is found ([`Ran::native`]). Empty with no home or no file.
pub fn machine_link_dirs(
    env: &[(std::ffi::OsString, std::ffi::OsString)],
) -> Result<Vec<PathBuf>, String> {
    let Some(home) = blaze_manifest::user_config::home() else { return Ok(Vec::new()) };
    machine_link_dirs_in(&blaze_manifest::user_config::file(&home), env)
}

/// [`machine_link_dirs`] of the settings `file`.
fn machine_link_dirs_in(
    file: &Path,
    env: &[(std::ffi::OsString, std::ffi::OsString)],
) -> Result<Vec<PathBuf>, String> {
    use blaze_manifest::user_config::{UserConfigError, read, section};
    const KEY: &str = "sandbox.build-script-link-dirs";
    let Some(table) = read(file).map_err(|it| it.to_string())? else { return Ok(Vec::new()) };
    let Some(sandbox) = section(&table, file, "sandbox").map_err(|it| it.to_string())? else {
        return Ok(Vec::new());
    };
    let Some(value) = sandbox.get("build-script-link-dirs") else { return Ok(Vec::new()) };
    let wrong = || UserConfigError::setting(file, KEY, "a list of directories", value).to_string();
    let dirs = value.as_array().ok_or_else(wrong)?;
    let dirs: Vec<String> = dirs
        .iter()
        .map(|it| it.as_str().map(str::to_owned).ok_or_else(wrong))
        .collect::<Result<_, _>>()?;
    for dir in &dirs {
        if !dir.starts_with("${") && !Spelling::of(dir, cfg!(windows)).absolute {
            return Err(format!(
                "{} sets `{KEY}` to a list with `{dir}`, which is no absolute directory",
                file.display()
            ));
        }
    }
    link_dirs(&dirs, env).map_err(|it| format!("{}: {it}", file.display()))
}

/// The workspace's `build-script-link-dirs` as a script started in `env` may name them: an
/// entry `${NAME}/rest` is the variable `NAME`'s value then `/rest` (a machine's install of
/// what the script links, which the manifest can't spell: `${LLVM_SYS_231_PREFIX}/lib`), any
/// other entry as it is. An error names a variable the script was not given, or one that is
/// no absolute path.
pub fn link_dirs(
    dirs: &[String],
    env: &[(std::ffi::OsString, std::ffi::OsString)],
) -> Result<Vec<PathBuf>, String> {
    dirs.iter()
        .map(|dir| {
            let Some((name, rest)) = dir.strip_prefix("${").and_then(|it| it.split_once('}')) else {
                return Ok(PathBuf::from(dir));
            };
            let Some((_, value)) = env.iter().find(|(it, _)| it == name) else {
                return Err(format!(
                    "`{dir}` of `build-script-link-dirs` names `{name}`, which the build script's environment does not set"
                ));
            };
            let value = Path::new(value);
            if !Spelling::of(&value.to_string_lossy(), cfg!(windows)).absolute {
                return Err(format!(
                    "`{dir}` of `build-script-link-dirs`: `{name}` is `{}`, which is no absolute path",
                    value.display()
                ));
            }
            Ok(blaze_manifest::paths::normalize_path(&value.join(rest.trim_start_matches('/'))))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A run on a Unix host for a Unix target, whatever the host the test runs on: the rules
    /// are text, compared as the run's host would.
    fn ran() -> Ran<'static> {
        Ran {
            package_dir: Path::new("/src/pkg"),
            out_dir: Path::new("/t/debug/build/pkg/0123/out"),
            link_dirs: Vec::<PathBuf>::leak(vec!["/opt/vendor/lib".into()]), // alloc: a test's, leaked
            native: Some(Path::new("/home/u/.blaze/native")),
            system: &[],
            msvc: false,
            windows: false,
        }
    }

    fn refused_lines(stdout: &str) -> Vec<String> {
        refused(stdout.as_bytes(), &ran()).into_iter().map(|it| it.line).collect()
    }

    #[test]
    fn link_search_stays_in_the_build_the_package_and_the_system() {
        let stdout = "cargo:rustc-link-search=native=/t/debug/build/pkg/0123/out/lib\n\
                      cargo:rustc-link-search=/t/debug/build/zlib/4567/out/lib\n\
                      cargo::rustc-link-search=native=/usr/lib/x86_64-linux-gnu\n\
                      cargo:rustc-link-search=/nix/store/abc-openssl-3/lib\n\
                      cargo:rustc-link-search=/opt/vendor/lib/x\n\
                      cargo:rustc-link-search=native=vendored\n\
                      cargo:rustc-link-search=native=/home/u/.ssh\n\
                      cargo:rustc-link-search=/usr/lib/../../home/u\n\
                      cargo:rustc-link-search=../outside\n\
                      cargo:rustc-flags=-L /etc -lfoo\n";
        assert_eq!(
            refused_lines(stdout),
            [
                "cargo:rustc-link-search=native=/home/u/.ssh",
                "cargo:rustc-link-search=/usr/lib/../../home/u",
                "cargo:rustc-link-search=../outside",
                "cargo:rustc-flags=-L /etc -lfoo",
            ]
        );
    }

    #[test]
    fn link_args_are_the_list_and_rpaths_where_search_may_go() {
        let stdout = "cargo:rustc-link-arg=-pthread\n\
                      cargo:rustc-link-arg=-ObjC\n\
                      cargo:rustc-link-arg-bins=-Wl,-rpath,$ORIGIN/../lib\n\
                      cargo:rustc-link-arg=-Wl,-rpath,/nix/store/abc-libva/lib\n\
                      cargo:rustc-cdylib-link-arg=-Wl,-soname,libx.so.1\n\
                      cargo:rustc-link-arg=-lstdc++\n\
                      cargo:rustc-link-arg=-ObjC\n\
                      cargo:rustc-link-arg-bins=-Wl,-ObjC\n\
                      cargo:rustc-link-arg=-fuse-ld=/tmp/evil\n\
                      cargo:rustc-link-arg=-Wl,-rpath,/home/u/lib\n\
                      cargo:rustc-link-arg=-Wl,--version-script=../../etc/x\n\
                      cargo::rustc-link-arg-bin=tool=-Wl,-plugin,/tmp/p.so\n";
        assert_eq!(
            refused_lines(stdout),
            [
                "cargo:rustc-link-arg=-fuse-ld=/tmp/evil",
                "cargo:rustc-link-arg=-Wl,-rpath,/home/u/lib",
                "cargo:rustc-link-arg=-Wl,--version-script=../../etc/x",
                "cargo::rustc-link-arg-bin=tool=-Wl,-plugin,/tmp/p.so",
            ]
        );
    }

    /// evm2-jit's `-Wl,--export-dynamic-symbol,__revmc_builtin_*` is a pattern of symbols to
    /// export, in either spelling; a value that goes on into another linker word is refused
    /// whatever prefix it follows.
    #[test]
    fn a_prefixed_link_arg_has_one_value_and_no_further_linker_word() {
        let stdout = "cargo:rustc-link-arg=-Wl,--export-dynamic-symbol,__revmc_builtin_*\n\
                      cargo:rustc-link-arg=-Wl,--export-dynamic-symbol=__revmc_builtin_*\n\
                      cargo:rustc-cdylib-link-arg=-Wl,-soname,libx.so.1\n\
                      cargo:rustc-link-arg=-Wl,--version-script=exports.map\n\
                      cargo:rustc-link-arg=-Wl,--export-dynamic-symbol,x,--plugin,/tmp/p.so\n\
                      cargo:rustc-link-arg=-Wl,--export-dynamic-symbol=x,-rpath,/home/u\n\
                      cargo:rustc-cdylib-link-arg=-Wl,-soname,libx.so,-rpath,/home/u/lib\n\
                      cargo:rustc-link-arg=-Wl,--export-dynamic-symbol,\n";
        assert_eq!(
            refused_lines(stdout),
            [
                "cargo:rustc-link-arg=-Wl,--export-dynamic-symbol,x,--plugin,/tmp/p.so",
                "cargo:rustc-link-arg=-Wl,--export-dynamic-symbol=x,-rpath,/home/u",
                "cargo:rustc-cdylib-link-arg=-Wl,-soname,libx.so,-rpath,/home/u/lib",
                "cargo:rustc-link-arg=-Wl,--export-dynamic-symbol,",
            ]
        );
    }

    /// A layout of blaze's own store of pinned native inputs may be searched and be an rpath
    /// (llvm-sys, pointed at the LLVM blaze fetched, prints its `lib`); the store itself, a
    /// name beside the layouts and another home's store may not. With no store named, none is.
    #[test]
    fn a_layout_of_the_native_store_may_be_searched_and_nothing_beside_it() {
        let digest = "918ef5bdb006b29b96d8f87dbbbac422593c6abf916cb7ad9afed17672648087";
        let stdout = format!(
            "cargo:rustc-link-search=native=/home/u/.blaze/native/sha256-{digest}/lib\n\
             cargo:rustc-link-arg=-Wl,-rpath,/home/u/.blaze/native/sha256-{digest}/lib\n\
             cargo:rustc-link-search=native=/home/u/.blaze/native\n\
             cargo:rustc-link-search=native=/home/u/.blaze/native/sha256-{digest}.new/lib\n\
             cargo:rustc-link-search=native=/home/u/.blaze/native/sha256-{digest}/../../../.ssh\n\
             cargo:rustc-link-search=native=/home/other/.blaze/native/sha256-{digest}/lib\n"
        );
        assert_eq!(
            refused_lines(&stdout),
            [
                "cargo:rustc-link-search=native=/home/u/.blaze/native".to_owned(),
                format!(
                    "cargo:rustc-link-search=native=/home/u/.blaze/native/sha256-{digest}.new/lib"
                ),
                format!(
                    "cargo:rustc-link-search=native=/home/u/.blaze/native/sha256-{digest}/../../../.ssh"
                ),
                format!(
                    "cargo:rustc-link-search=native=/home/other/.blaze/native/sha256-{digest}/lib"
                ),
            ]
        );
        let none = Ran { native: None, ..ran() };
        assert_eq!(refused(stdout.as_bytes(), &none).len(), 6, "with no store, each is refused");
    }

    #[test]
    fn rustc_env_may_not_set_what_cargo_gives() {
        let stdout = "cargo:rustc-env=CARGO_COMMIT_HASH=ea2d978\n\
                      cargo:rustc-env=GIT_HASH=abc\n\
                      cargo:rustc-env=CARGO_PKG_VERSION=9.9.9\n\
                      cargo::rustc-env=RUSTC_BOOTSTRAP=1\n\
                      cargo:rustc-env=CARGO_MAKEFLAGS=-j1\n\
                      cargo:rustc-env-like=CARGO_PKG_NAME\n\
                      cargo:CARGO_PKG_NAME=metadata, not a directive\n";
        assert_eq!(
            refused_lines(stdout),
            [
                "cargo:rustc-env=CARGO_PKG_VERSION=9.9.9",
                "cargo::rustc-env=RUSTC_BOOTSTRAP=1",
                "cargo:rustc-env=CARGO_MAKEFLAGS=-j1",
            ]
        );
    }

    #[test]
    fn rustc_env_may_forward_what_cargo_gives_only_scripts() {
        let stdout = "cargo:rustc-env=CARGO_CFG_TARGET_FEATURE=aes,crc,neon\n\
                      cargo:rustc-env=CARGO_ENCODED_RUSTFLAGS=\n\
                      cargo::rustc-env=CARGO_FEATURE_ASM=1\n\
                      cargo:rustc-env=CARGO_MANIFEST_LINKS=z\n";
        assert_eq!(refused_lines(stdout), Vec::<String>::new());
    }

    #[test]
    fn given_is_sorted_for_its_binary_search() {
        assert!(GIVEN.windows(2).all(|it| it[0] < it[1]), "{GIVEN:?}");
    }

    #[test]
    fn rustc_env_may_not_set_what_the_toolchain_reads() {
        for name in ["RUSTC_BOOTSTRAP", "RUSTC_LOG", "RUSTDOC_DOCTEST_RUN_NB_TEST"] {
            assert!(given_by_cargo(name), "{name}");
        }
        for name in GIVEN {
            assert!(given_by_cargo(name), "{name}");
        }
    }

    #[test]
    fn rustc_env_may_set_rustc_names_no_tool_reads() {
        for name in ["RUSTC_VERSION", "RUSTC_SEMVER", "RUSTDOC_FOO_BAR", "RUSTC_X"] {
            assert!(!given_by_cargo(name), "{name}");
        }
        assert!(refused(b"cargo::rustc-env=RUSTC_VERSION=1\n", &ran()).is_empty());
        assert_eq!(
            refused_lines("cargo::rustc-env=RUSTC_BOOTSTRAP=1\n"),
            ["cargo::rustc-env=RUSTC_BOOTSTRAP=1"]
        );
    }

    #[test]
    fn the_report_names_the_script_each_line_and_the_rule() {
        let refused =
            refused(b"cargo:rustc-link-search=/root/x\ncargo:rustc-env=RUSTFLAGS=-Cx\n", &ran());
        assert_eq!(
            refused.iter().map(|it| it.rule).collect::<Vec<_>>(),
            ["sandbox:link-dir", "sandbox:rustc-env"]
        );
        let at =
            blaze_report::Text::new().words("build script of ").package("evil-sys", Some("0.1.0"));
        let report = refused_report("evil-sys", at, &refused);
        assert_eq!(report.rule.as_deref(), Some("sandbox:link-dir"));
        assert_eq!(report.subject(), Some("evil-sys"));
        let flat = report.flat();
        assert!(
            flat.contains("`cargo:rustc-link-search=/root/x`") && flat.contains("`RUSTFLAGS`"),
            "{flat}"
        );
        assert!(
            flat.contains("build-script-link-dirs")
                && flat.contains("unsandboxed-build-scripts = [\"evil-sys\"]"),
            "{flat}"
        );
        assert!(
            blaze_report::rules::find("sandbox:link-dir").is_some()
                && blaze_report::rules::find("sandbox:rustc-env").is_some()
        );
    }

    /// A link dir under a variable is where the script's environment puts it, and the search it
    /// prints there is allowed; an unset or relative variable is an error naming it, never a
    /// dir left out. (Unix paths, joined as the host joins them: on Unix.)
    #[cfg(unix)]
    #[test]
    fn a_link_dir_under_a_variable_is_where_the_scripts_environment_puts_it() {
        use std::ffi::OsString;
        let env = |value: &str| -> Vec<(OsString, OsString)> {
            vec![("LLVM_SYS_231_PREFIX".into(), value.into())]
        };
        let dirs = ["${LLVM_SYS_231_PREFIX}/lib".to_owned(), "/opt/vendor/lib".to_owned()];
        let found = link_dirs(&dirs, &env("/m/llvm-23.1.4")).unwrap();
        assert_eq!(found, [PathBuf::from("/m/llvm-23.1.4/lib"), PathBuf::from("/opt/vendor/lib")]);
        let ran = Ran { link_dirs: &found, ..ran() };
        assert!(refused(b"cargo:rustc-link-search=native=/m/llvm-23.1.4/lib\n", &ran).is_empty());
        assert!(!refused(b"cargo:rustc-link-search=native=/m/other/lib\n", &ran).is_empty());

        let unset = link_dirs(&dirs, &[]).unwrap_err();
        assert!(
            unset.contains("`LLVM_SYS_231_PREFIX`") && unset.contains("does not set"),
            "{unset}"
        );
        let relative = link_dirs(&dirs, &env("llvm")).unwrap_err();
        assert!(relative.contains("no absolute path"), "{relative}");
    }

    /// A run on a Windows host for `x86_64-pc-windows-msvc`, its package and `OUT_DIR` named as
    /// the daemon names them, with the toolchain of a developer prompt in its `LIB`.
    fn windows_ran(system: &'static [PathBuf]) -> Ran<'static> {
        Ran {
            package_dir: Path::new("/C:/src/app"),
            out_dir: Path::new("/C:/src/target/debug/build/app-0123/out"),
            link_dirs: &[],
            native: Some(Path::new("/C:/Users/u/.blaze/native")),
            system,
            msvc: true,
            windows: true,
        }
    }

    fn windows_system() -> &'static [PathBuf] {
        let env: Vec<(OsString, OsString)> = vec![
            (
                "Lib".into(),
                r"C:\msvc\VC\Tools\MSVC\14.52\lib\x64;C:\Kits\10\Lib\10.0.26100.0\um\x64;".into(),
            ),
            ("ProgramFiles".into(), r"C:\Program Files".into()),
            ("ProgramFiles(x86)".into(), r"C:\Program Files (x86)".into()),
        ];
        Vec::leak(windows_system_dirs(&env)) // alloc: a test's, leaked
    }

    /// A Windows path is compared as Windows compares it: any separator, any spelling of the
    /// drive, any case. The package, `OUT_DIR`, the build directory, `LIB` and the Visual Studio
    /// and SDK trees may be searched; the home, another drive and a `..` out may not.
    #[cfg(windows)]
    #[test]
    fn a_windows_link_search_is_compared_as_windows_compares_it() {
        let ran = windows_ran(windows_system());
        let stdout = "cargo:rustc-link-search=native=C:\\src\\target\\debug\\build\\app-0123\\out\n\
                      cargo:rustc-link-search=native=c:/SRC/target/debug/build/zlib-4567/out/lib\n\
                      cargo:rustc-link-search=native=\\\\?\\C:\\src\\app\\vendor\\lib\n\
                      cargo:rustc-link-search=native=/C:/src/app/lib\n\
                      cargo:rustc-link-search=native=C:\\msvc\\VC\\Tools\\MSVC\\14.52\\lib\\x64\n\
                      cargo:rustc-link-search=native=C:\\Program Files\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Tools\\MSVC\\14.44.35207\\atlmfc\\lib\\x64\n\
                      cargo:rustc-link-search=native=C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.26100.0\\um\\x64\n\
                      cargo:rustc-link-search=native=vendor\\lib\n\
                      cargo:rustc-link-search=native=C:\\Users\\u\\AppData\\Local\\seer\\ghostty-vt\\abc\n\
                      cargo:rustc-link-search=native=D:\\src\\app\n\
                      cargo:rustc-link-search=native=C:\\src\\app\\..\\..\\Users\\u\n\
                      cargo:rustc-link-search=native=..\\outside\n";
        let lines: Vec<String> =
            refused(stdout.as_bytes(), &ran).into_iter().map(|it| it.line).collect();
        assert_eq!(
            lines,
            [
                "cargo:rustc-link-search=native=C:\\Users\\u\\AppData\\Local\\seer\\ghostty-vt\\abc",
                "cargo:rustc-link-search=native=D:\\src\\app",
                "cargo:rustc-link-search=native=C:\\src\\app\\..\\..\\Users\\u",
                "cargo:rustc-link-search=native=..\\outside",
            ]
        );
        // Without the toolchain's directories (no developer prompt, a host other than Windows),
        // a search into them is refused like any other.
        let bare = windows_ran(&[]);
        let msvc = "cargo:rustc-link-search=native=C:\\msvc\\VC\\Tools\\MSVC\\14.52\\lib\\x64\n";
        assert_eq!(refused(msvc.as_bytes(), &bare).len(), 1);
    }

    /// rune-desktop's `apps/desktop` and tauri's link options, winresource's `.res` and a
    /// library by name pass; a file the linker would write, a program it would load, a file
    /// outside the places a search may go and an option no rule names are refused.
    #[cfg(windows)]
    #[test]
    fn msvc_link_args_are_the_options_and_files_the_rules_name() {
        let ran = windows_ran(windows_system());
        let given = "cargo:rustc-link-arg-bin=opencode-desktop=/SUBSYSTEM:WINDOWS\n\
                     cargo:rustc-link-arg-bin=opencode-desktop=/ENTRY:mainCRTStartup\n\
                     cargo:rustc-link-arg-bin=opencode-desktop=/DELAYLOAD:comctl32.dll\n\
                     cargo:rustc-link-arg-bin=opencode-desktop=delayimp.lib\n\
                     cargo:rustc-link-arg-bins=/MANIFEST:EMBED\n\
                     cargo:rustc-link-arg-bins=/MANIFESTINPUT:C:\\src\\app\\assets\\app.manifest\n\
                     cargo:rustc-link-arg=/WX\n\
                     cargo:rustc-link-arg=/subsystem:console,6.0\n\
                     cargo:rustc-link-arg=-STACK:8388608\n\
                     cargo:rustc-link-arg=/NODEFAULTLIB:libucrt.lib\n\
                     cargo:rustc-link-arg=/NODEFAULTLIB\n\
                     cargo:rustc-link-arg=/DEFAULTLIB:ucrt.lib\n\
                     cargo:rustc-link-arg=/WHOLEARCHIVE:C:\\src\\target\\debug\\build\\app-0123\\out\\glue.lib\n\
                     cargo:rustc-link-arg=/DEBUG:FULL\n\
                     cargo:rustc-link-arg=/OPT:REF,ICF\n\
                     cargo:rustc-link-arg=/NOLOGO\n\
                     cargo:rustc-link-arg=/INCREMENTAL:NO\n\
                     cargo:rustc-link-arg=/MANIFESTUAC:level='asInvoker' uiAccess='false'\n\
                     cargo:rustc-link-arg=C:\\src\\target\\debug\\build\\app-0123\\out\\resource.res\n\
                     cargo:rustc-link-arg=/LIBPATH:C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.26100.0\\um\\x64\n\
                     cargo:rustc-link-arg=-lstdc++\n";
        let refused_lines = |stdout: &str| -> Vec<String> {
            refused(stdout.as_bytes(), &ran).into_iter().map(|it| it.line).collect()
        };
        assert_eq!(refused_lines(given), Vec::<String>::new());
        let bad = "cargo:rustc-link-arg=/OUT:C:\\Windows\\evil.exe\n\
                   cargo:rustc-link-arg=/PDB:C:\\Users\\u\\x.pdb\n\
                   cargo:rustc-link-arg=/MANIFESTFILE:C:\\Users\\u\\m\n\
                   cargo:rustc-link-arg=/DELAYLOAD:..\\evil.dll\n\
                   cargo:rustc-link-arg=/ENTRY\n\
                   cargo:rustc-link-arg=/NOLOGO:YES\n\
                   cargo:rustc-link-arg=/DEFAULTLIB:C:\\Users\\u\\evil.lib\n\
                   cargo:rustc-link-arg=C:\\Users\\u\\evil.res\n\
                   cargo:rustc-link-arg=/MANIFESTINPUT:D:\\m.manifest\n\
                   cargo:rustc-link-arg=/LIBPATH:C:\\Users\\u\n\
                   cargo:rustc-link-arg=C:\\tools\\plugin.dll\n\
                   cargo:rustc-link-arg=/MANIFESTDEPENDENCY:C:\\x\n";
        assert_eq!(refused_lines(bad), bad.lines().collect::<Vec<_>>());
        // The same options on a target whose linker is not MSVC's are no option of its.
        let unix = "cargo:rustc-link-arg=/SUBSYSTEM:WINDOWS\n";
        assert_eq!(refused(unix.as_bytes(), &ran_unix_target()).len(), 1);
    }

    fn ran_unix_target() -> Ran<'static> {
        Ran { msvc: false, ..windows_ran(&[]) }
    }

    #[test]
    fn the_msvc_options_are_sorted_and_upper_case() {
        assert!(MSVC_OPTIONS.windows(2).all(|it| it[0].0 < it[1].0), "{MSVC_OPTIONS:?}");
        assert!(MSVC_OPTIONS.iter().all(|(it, _)| it.bytes().all(|b| b.is_ascii_uppercase())));
    }

    /// rune-desktop's terminal links Ghostty's library from the machine's cache under
    /// `%LOCALAPPDATA%`: a workspace that names it under a variable (`${LOCALAPPDATA}/seer`)
    /// lets the search there and nowhere beside it.
    #[cfg(windows)]
    #[test]
    fn a_windows_link_dir_under_a_variable_is_where_the_scripts_environment_puts_it() {
        let env: Vec<(OsString, OsString)> =
            vec![("LOCALAPPDATA".into(), r"C:\Users\u\AppData\Local".into())];
        let found = link_dirs(&["${LOCALAPPDATA}/seer/ghostty-vt".to_owned()], &env).unwrap();
        let ran = Ran { link_dirs: &found, ..windows_ran(&[]) };
        let ok =
            "cargo:rustc-link-search=native=C:\\Users\\u\\AppData\\Local\\seer\\ghostty-vt\\0f3a\n";
        assert!(refused(ok.as_bytes(), &ran).is_empty());
        let beside = "cargo:rustc-link-search=native=C:\\Users\\u\\AppData\\Local\\other\n";
        assert_eq!(refused(beside.as_bytes(), &ran).len(), 1);
    }

    /// blaze's settings name the machine's own library directories for every workspace: a
    /// search there passes with no workspace saying so, one beside it does not; a setting that
    /// is no list of directories, or names a relative one, is an error naming the file and the
    /// key; no file is no directory.
    #[test]
    fn the_machines_settings_name_its_library_directories() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config.toml");
        assert_eq!(machine_link_dirs_in(&file, &[]).unwrap(), Vec::<PathBuf>::new());
        let root = if cfg!(windows) { r"C:\cache" } else { "/cache" };
        let env: Vec<(OsString, OsString)> = vec![("CACHE".into(), root.into())];
        std::fs::write(
            &file,
            "[sandbox]\nbuild-script-link-dirs = [\"${CACHE}/seer/ghostty-vt\"]\n",
        )
        .unwrap();
        let found = machine_link_dirs_in(&file, &env).unwrap();
        let ran = Ran { link_dirs: &found, windows: cfg!(windows), ..ran() };
        let search =
            |dir: &str| refused(format!("cargo:rustc-link-search=native={dir}\n").as_bytes(), &ran);
        let inside = format!("{root}/seer/ghostty-vt/0f3a");
        assert!(search(&inside).is_empty(), "{inside}");
        assert_eq!(search(&format!("{root}/other")).len(), 1);
        std::fs::write(&file, "[sandbox]\nbuild-script-link-dirs = \"/x\"\n").unwrap();
        let error = machine_link_dirs_in(&file, &env).unwrap_err();
        assert!(
            error.contains("sandbox.build-script-link-dirs") && error.contains("config.toml"),
            "{error}"
        );
        std::fs::write(&file, "[sandbox]\nbuild-script-link-dirs = [\"lib\"]\n").unwrap();
        assert!(machine_link_dirs_in(&file, &env).unwrap_err().contains("no absolute directory"));
    }
}
