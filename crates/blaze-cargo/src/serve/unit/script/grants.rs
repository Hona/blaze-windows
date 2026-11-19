//! What a build script is given of the machine besides its package, its `OUT_DIR` and the
//! toolchain, by the project or by whoever runs blaze (docs/cargo.md, "A build script's tools
//! and caches"): the programs it runs from the command's `PATH` (`build-script-tools`), and the
//! directories it keeps across runs (`build-script-caches`, `BLAZE_SCRIPT_CACHES`).
//!
//! A project names a tool and a cache, never a place: the tool is the file the caller's own
//! `PATH` finds, and the project's cache is a directory of blaze's home of that checkout alone,
//! so no checkout can grant its scripts a file of the machine it chose, nor write into another
//! checkout's cache. Where the caller names the same cache, the caller's directory is the one.

use std::path::{Path, PathBuf};

use blaze_api::ApiError;
use blaze_ids::Hasher;

/// The directory of blaze's home that holds every checkout's declared caches.
const CACHES: &str = "script-caches";

/// The programs `names` (the workspace's `build-script-tools`) as the command's `PATH` in
/// `env` (the caller's environment, never the project's `[env]`) finds them, each the file a
/// build script may read and run, and the file it runs in turn where it is a Scoop shim. A name
/// no directory of `PATH` has is refused, naming it and the way on.
pub(super) fn declared_tools(
    names: &[String],
    env: &[(String, String)],
) -> Result<Vec<PathBuf>, ApiError> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let windows = cfg!(windows);
    let path = env
        .iter()
        .find(|(name, _)| if windows { name.eq_ignore_ascii_case("PATH") } else { name == "PATH" })
        .map(|(_, value)| value.as_str())
        .unwrap_or("");
    let refused = |what: String| ApiError::new(what, Some("build-script-tools".to_owned()));
    let mut granted: Vec<PathBuf> = Vec::new(); // alloc: a workspace's few tools, once a run
    for name in names {
        let found = find_tool(name, path, windows, |it| it.is_file()).ok_or_else(|| {
            refused(format!(
                "the workspace's `build-script-tools` names `{name}`, which no directory of the \
                 command's PATH has: install it, or put its directory on PATH"
            ))
        })?;
        let mut files = vec![found.clone()]; // alloc: as above; clone: the path as found and as resolved
        let shim = found.with_extension("shim");
        if windows && shim.is_file() {
            let text = std::fs::read_to_string(&shim)
                .map_err(|error| refused(format!("{}: {error}", shim.display())))?;
            let target = shim_target(&text).ok_or_else(|| {
                refused(format!("{}: a Scoop shim with no `path = ...` line", shim.display()))
            })?;
            files.push(shim);
            files.push(PathBuf::from(target));
        }
        for file in files {
            let resolved = std::fs::canonicalize(&file)
                .map_err(|error| refused(format!("`{name}`: {}: {error}", file.display())))?;
            if !resolved.is_file() {
                return Err(refused(format!(
                    "`{name}`: {} is no file a script may be given",
                    resolved.display()
                )));
            }
            granted.push(file);
            granted.push(resolved);
        }
    }
    granted.sort();
    granted.dedup();
    Ok(granted)
}

/// The file `name` is in the first directory of `path` (a `PATH` value) that has it, as the
/// system's own search finds it: on Windows `name` itself where it has an extension, else
/// `name` with `.com`, `.exe`, `.bat` then `.cmd` (the default `PATHEXT`), `;` between the
/// directories and quotes around one ignored; elsewhere `name`, `:` between them. Sans-IO but
/// `is_file`.
pub(super) fn find_tool(
    name: &str,
    path: &str,
    windows: bool,
    is_file: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    let (separator, extensions): (char, &[&str]) = match windows {
        true if !name.contains('.') => (';', &[".com", ".exe", ".bat", ".cmd"]),
        true => (';', &[""]),
        false => (':', &[""]),
    };
    // Joined as the system the search is for joins, whatever system this runs on.
    let slash = if windows { '\\' } else { '/' };
    path.split(separator)
        .map(|dir| dir.trim().trim_matches('"'))
        .filter(|dir| !dir.is_empty() && is_absolute(dir, windows))
        .flat_map(|dir| {
            let dir = dir.trim_end_matches(['/', '\\']);
            // alloc: a candidate's path, a few a tool
            extensions.iter().map(move |ext| PathBuf::from(format!("{dir}{slash}{name}{ext}")))
        })
        .find(|it| is_file(it))
}

/// Whether a directory of `PATH` is absolute: a relative one would be searched from wherever
/// the daemon runs, which is no place the caller meant.
fn is_absolute(dir: &str, windows: bool) -> bool {
    match windows {
        true => {
            let bytes = dir.as_bytes();
            dir.starts_with(r"\\")
                || (bytes.len() > 2
                    && bytes[0].is_ascii_alphabetic()
                    && bytes[1] == b':'
                    && matches!(bytes[2], b'\\' | b'/'))
        }
        false => dir.starts_with('/'),
    }
}

/// The program a Scoop shim (`<name>.shim` beside `<name>.exe`) runs: its `path = <file>`
/// line, the file unquoted.
pub(super) fn shim_target(text: &str) -> Option<&str> {
    text.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        let value = value.trim().trim_matches('"');
        (key.trim() == "path" && !value.is_empty()).then_some(value)
    })
}

/// The caches every build script of the run is given, by variable: each `VARIABLE=DIRECTORY`
/// of `BLAZE_SCRIPT_CACHES` in the caller's environment `env` (a list of the system's paths),
/// then each of the workspace's `build-script-caches` (`workspace`) the caller does not name,
/// under `<home>/script-caches/<checkout>/<VARIABLE>`, `<checkout>` a hash of the checkout's
/// root `root`. A script may read and write each, and it is kept across runs; what is in one
/// is in no key ([`blaze_usercode::script::Place::caches`]). Each directory is made if missing
/// and named as the system resolves it; an entry that is not a variable's name and an absolute
/// directory below a volume's root, or a variable named twice, is refused, naming it.
pub(super) fn declared_caches(
    env: &[(String, String)],
    workspace: &[String],
    root: &str,
    home: impl FnOnce() -> Result<PathBuf, String>,
) -> Result<Vec<(String, PathBuf)>, ApiError> {
    const NAME: &str = "BLAZE_SCRIPT_CACHES";
    // alloc: an error path.
    let refused = |what: String| ApiError::new(format!("{NAME}: {what}"), None);
    let mut caches: Vec<(String, PathBuf)> = Vec::new(); // alloc: the caller's few caches, once a run
    let same = |a: &str, b: &str| a.eq_ignore_ascii_case(b);
    if let Some((_, list)) = env.iter().find(|(name, _)| name == NAME) {
        for entry in std::env::split_paths(list) {
            let text = entry.to_string_lossy();
            let Some((name, dir)) = text.split_once('=') else {
                return Err(refused(format!("`{text}` is no VARIABLE=DIRECTORY")));
            };
            if name.is_empty() || !name.bytes().all(|it| it.is_ascii_alphanumeric() || it == b'_') {
                return Err(refused(format!("`{name}` is no variable's name")));
            }
            let dir = PathBuf::from(dir);
            if !dir.is_absolute() || dir.parent().is_none() {
                return Err(refused(format!(
                    "{} is not an absolute directory below a volume's root",
                    dir.display()
                )));
            }
            if caches.iter().any(|(it, _)| same(it, name)) {
                return Err(refused(format!("`{name}` is named twice")));
            }
            caches.push((name.to_owned(), made(&dir).map_err(refused)?));
        }
    }
    let ours: Vec<&String> =
        workspace.iter().filter(|name| !caches.iter().any(|(it, _)| same(it, name))).collect();
    if !ours.is_empty() {
        let refused = |what: String| {
            ApiError::new(
                format!("the workspace's `build-script-caches`: {what}"),
                Some("build-script-caches".to_owned()),
            )
        };
        let home = home().map_err(refused)?;
        let checkout = checkout_dir(root);
        for name in ours {
            let dir = home.join(CACHES).join(&checkout).join(name);
            caches.push((name.clone(), made(&dir).map_err(refused)?)); // clone: the run's own
        }
    }
    caches.sort();
    Ok(caches)
}

/// The directory of one checkout's caches under `<home>/script-caches`: its root's hash, so a
/// checkout's scripts never read what another's wrote, and a checkout keeps its own across
/// runs and restarts.
pub(super) fn checkout_dir(root: &str) -> String {
    let id = Hasher::new("blaze build-script caches of a checkout 1").part(root.as_bytes()).finish();
    format!("{id}") // alloc: a directory's name, once a run
}

/// `dir` made if missing, as the system resolves it.
fn made(dir: &Path) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|error| format!("making {}: {error}", dir.display()))?;
    std::fs::canonicalize(dir).map_err(|error| format!("{}: {error}", dir.display()))
}

/// `env` with each cache's variable naming its directory after it, as the script is started:
/// what a `build-script-link-dirs` entry `${VARIABLE}/rest` is read against.
pub(super) fn with_caches(
    env: &[(std::ffi::OsString, std::ffi::OsString)],
    caches: &[(String, PathBuf)],
) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    // alloc: once a run checked, the environment its link directories are read against
    let mut out = env.to_vec();
    out.extend(caches.iter().map(|(name, dir)| (name.into(), dir.clone().into_os_string())));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The invariant: a tool is the first file of `PATH` the system's own search would run, by
    /// its rules on each system, and never one under a relative directory. The control: a
    /// name the `PATH` lacks is none.
    #[test]
    fn a_tool_is_the_file_the_systems_search_finds_first() {
        let have = |files: &'static [&'static str]| {
            move |it: &Path| files.iter().any(|file| Path::new(file) == it)
        };
        let windows = have(&[r"C:\a\nasm.exe", r"C:\b\nasm.com", r"C:\b\nasm.exe", r"rel\nasm.exe"]);
        let path = r"rel;C:\none;C:\a;C:\b";
        assert_eq!(find_tool("nasm", path, true, &windows), Some(PathBuf::from(r"C:\a\nasm.exe")));
        assert_eq!(
            find_tool("nasm", r#""C:\b";C:\a"#, true, &windows),
            Some(PathBuf::from(r"C:\b\nasm.com")),
            "`.com` before `.exe` in one directory, quotes ignored"
        );
        assert_eq!(find_tool("nasm.exe", r"C:\b", true, &windows), Some(PathBuf::from(r"C:\b\nasm.exe")));
        assert_eq!(find_tool("nasm", "rel", true, &windows), None, "a relative directory");
        assert_eq!(find_tool("yasm", path, true, &windows), None);

        let unix = have(&["/usr/bin/nasm", "/opt/nasm/bin/nasm"]);
        assert_eq!(
            find_tool("nasm", "/opt/nasm/bin:/usr/bin", false, &unix),
            Some(PathBuf::from("/opt/nasm/bin/nasm"))
        );
        assert_eq!(find_tool("nasm", "bin:/nowhere", false, &unix), None);
    }

    #[test]
    fn a_scoop_shim_names_the_program_it_runs() {
        let text = "path = \"C:\\Users\\u\\scoop\\apps\\nasm\\current\\nasm.exe\"\nargs = -v\n";
        assert_eq!(shim_target(text), Some(r"C:\Users\u\scoop\apps\nasm\current\nasm.exe"));
        assert_eq!(shim_target("path = C:\\x\\y.exe\r\n"), Some(r"C:\x\y.exe"));
        assert_eq!(shim_target("args = -v\n"), None);
    }

    /// The invariant: a project's cache is a directory of blaze's home of its checkout alone,
    /// made, and the caller's own directory where the caller names the variable. The control:
    /// another checkout's root is another directory.
    #[test]
    fn a_projects_cache_is_its_checkouts_own_unless_the_caller_names_it() {
        let home = tempfile::tempdir().unwrap();
        let mine = tempfile::tempdir().unwrap();
        let home_of = || Ok(home.path().to_owned());
        let workspace = ["GHOSTTY_VT_CACHE_DIR".to_owned(), "ZIG_CACHE".to_owned()];
        let caches = declared_caches(&[], &workspace, "/w/a", home_of).unwrap();
        let expected = |root: &str, name: &str| {
            std::fs::canonicalize(home.path().join(CACHES).join(checkout_dir(root)).join(name))
                .unwrap()
        };
        assert_eq!(
            caches,
            [
                ("GHOSTTY_VT_CACHE_DIR".to_owned(), expected("/w/a", "GHOSTTY_VT_CACHE_DIR")),
                ("ZIG_CACHE".to_owned(), expected("/w/a", "ZIG_CACHE")),
            ]
        );
        assert_ne!(checkout_dir("/w/a"), checkout_dir("/w/b"), "another checkout");

        let env = [(
            "BLAZE_SCRIPT_CACHES".to_owned(),
            format!("ZIG_CACHE={}", mine.path().display()),
        )];
        let caches = declared_caches(&env, &workspace, "/w/a", home_of).unwrap();
        assert_eq!(caches[1], ("ZIG_CACHE".to_owned(), std::fs::canonicalize(mine.path()).unwrap()));
        assert_eq!(caches[0].1, expected("/w/a", "GHOSTTY_VT_CACHE_DIR"));

        let no_home = declared_caches(&[], &workspace, "/w/a", || Err("no home".to_owned()));
        assert!(no_home.unwrap_err().what.contains("no home"));
        assert!(declared_caches(&[], &[], "/w/a", || -> Result<PathBuf, String> {
            unreachable!("no cache of the project's, no home asked")
        })
        .unwrap()
        .is_empty());
    }
}
