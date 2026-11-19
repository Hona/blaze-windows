//! The Visual Studio C and C++ tools and the Windows SDK on this machine, and the variables a
//! developer prompt (`vcvarsall.bat`) sets for them.
//!
//! A build script's C compiler (`cc`, through `find-msvc-tools`) finds MSVC by those
//! variables, and without them by Visual Studio's setup records under `ProgramData` (its COM
//! server and `vswhere` read them). A sandboxed script runs in an AppContainer, which may read
//! the tools and the SDK under Program Files (every app package may) but not those records,
//! and a user can't grant it them (they are the system's): so the daemon, outside the sandbox,
//! finds the tools once ([`find`]) and a script is started with the variables a developer
//! prompt for its target would give it ([`Developer::variables`]), as one run from that prompt
//! is. Measured: `find_tool("x86_64-pc-windows-msvc", "cl.exe")` in the sandbox finds nothing
//! without them, and `cl.exe /MT` compiles C there with them.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

/// One Visual Studio's MSVC tools and the Windows SDK, as a developer prompt names them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Developer {
    /// Visual Studio's directory (`VSINSTALLDIR`): `...\Microsoft Visual Studio\2022\BuildTools`.
    pub install: PathBuf,
    /// The MSVC tools' version (`VCToolsVersion`), its directory under `VC\Tools\MSVC`.
    pub tools: String,
    /// The Windows 10 and later SDKs' root (`WindowsSdkDir`): `...\Windows Kits\10`.
    pub kits: PathBuf,
    /// The SDK's version (`WindowsSDKVersion`), its directory under `Include` and `Lib`.
    pub sdk: String,
}

/// The architecture a developer prompt names (`VSCMD_ARG_TGT_ARCH`) of an MSVC target triple's
/// first part; `None` for an architecture MSVC has no tools for.
pub fn arch(triple: &str) -> Option<&'static str> {
    match triple.split('-').next()? {
        "x86_64" => Some("x64"),
        "i586" | "i686" => Some("x86"),
        "aarch64" | "arm64ec" => Some("arm64"),
        "thumbv7a" => Some("arm"),
        _ => None,
    }
}

/// Whether `triple` is a target MSVC builds for: a script of one may look for its tools.
pub fn targets(triple: &str) -> bool {
    triple.ends_with("-windows-msvc") && arch(triple).is_some()
}

impl Developer {
    /// MSVC's directory (`VCToolsInstallDir`).
    pub fn vc_tools(&self) -> PathBuf {
        self.install.join("VC").join("Tools").join("MSVC").join(&self.tools)
    }

    /// The variables a developer prompt on a `host` machine for `target` (each as [`arch`]
    /// names it) sets: `PATH` is only what it puts in front of the one it was started with
    /// (`path`), which follows.
    pub fn variables(
        &self,
        host: &str,
        target: &str,
        path: Option<&OsString>,
    ) -> Result<Vec<(OsString, OsString)>, String> {
        let tools = self.vc_tools();
        let include = self.kits.join("Include").join(&self.sdk);
        let lib = self.kits.join("Lib").join(&self.sdk);
        let host_dir = format!("Host{host}");
        let mut bin = vec![tools.join("bin").join(&host_dir).join(target)];
        if host != target {
            // The tools for another target load DLLs of the host's own.
            bin.push(tools.join("bin").join(&host_dir).join(host));
        }
        bin.push(self.kits.join("bin").join(&self.sdk).join(host));
        bin.extend(path.iter().flat_map(std::env::split_paths));
        let joined = |dirs: Vec<PathBuf>| {
            // alloc: once per script run, the value of one variable.
            std::env::join_paths(dirs).map_err(|error| format!("a developer prompt's list: {error}"))
        };
        let dir = |it: &Path| {
            // A developer prompt's directories end with `\`, which scripts that join with
            // `+` rely on.
            let mut it = it.as_os_str().to_owned();
            it.push(r"\");
            it
        };
        Ok(vec![
            ("VSINSTALLDIR".into(), dir(&self.install)),
            ("VCINSTALLDIR".into(), dir(&self.install.join("VC"))),
            ("VCToolsInstallDir".into(), dir(&tools)),
            ("VCToolsVersion".into(), self.tools.clone().into()),
            ("WindowsSdkDir".into(), dir(&self.kits)),
            ("WindowsSDKVersion".into(), format!(r"{}\", self.sdk).into()),
            ("UniversalCRTSdkDir".into(), dir(&self.kits)),
            ("UCRTVersion".into(), self.sdk.clone().into()),
            ("VSCMD_ARG_HOST_ARCH".into(), host.into()),
            ("VSCMD_ARG_TGT_ARCH".into(), target.into()),
            (
                "INCLUDE".into(),
                joined(vec![
                    tools.join("include"),
                    include.join("ucrt"),
                    include.join("um"),
                    include.join("shared"),
                    include.join("winrt"),
                    include.join("cppwinrt"),
                ])?,
            ),
            (
                "LIB".into(),
                joined(vec![
                    tools.join("lib").join(target),
                    lib.join("ucrt").join(target),
                    lib.join("um").join(target),
                ])?,
            ),
            ("PATH".into(), joined(bin)?),
        ])
    }
}

/// The newest SDK version under `kits` with `um\windows.h` and `target`'s `kernel32.lib`.
fn newest_sdk(kits: &Path, target: &str) -> Result<String, String> {
    let include = kits.join("Include");
    let entries =
        std::fs::read_dir(&include).map_err(|error| format!("{}: {error}", include.display()))?;
    let mut newest: Option<(Vec<u32>, String)> = None;
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", include.display()))?;
        let Ok(name) = entry.file_name().into_string() else { continue };
        let Some(version) =
            name.split('.').map(|it| it.parse::<u32>().ok()).collect::<Option<Vec<u32>>>()
        else {
            continue;
        };
        let whole = entry.path().join("um").join("windows.h").is_file()
            && kits.join("Lib").join(&name).join("um").join(target).join("kernel32.lib").is_file();
        if whole && newest.as_ref().is_none_or(|(it, _)| version > *it) {
            newest = Some((version, name));
        }
    }
    newest.map(|it| it.1).ok_or_else(|| {
        format!(
            "{} has no Windows SDK with um\\windows.h and um\\{target}\\kernel32.lib",
            include.display()
        )
    })
}

/// How a file or directory [`find`] read stood: its length and last write, `None` when absent.
pub type Stood = Option<(u64, std::time::SystemTime)>;

/// How `path` stands now, as [`Kept::still`] compares it.
pub fn stood(path: &Path) -> Stood {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.len(), meta.modified().ok()?))
}

/// What [`find`] found, with what it read: the inputs it is valid for. `vswhere` reads Visual
/// Studio's setup records (a directory an instance per install under
/// `ProgramData\Microsoft\VisualStudio\Packages\_Instances`, each one's `state.json`); the
/// rest is the tools' default version file, the SDK directories it listed and the files it
/// checked. A directory's last write moves when an entry is added, removed or renamed in it,
/// so an install, an update or a removal of Visual Studio or an SDK is a changed read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kept {
    pub developer: Developer,
    /// `ProgramFiles(x86)`, where `vswhere` was looked for.
    pub programs: OsString,
    /// The registry's `KitsRoot10`.
    pub kits_root: PathBuf,
    pub reads: Vec<(PathBuf, Stood)>,
}

impl Kept {
    /// Whether what was found still stands: the same `programs` and `kits_root`, and every
    /// read as it stood (`stat` says how a path stands now).
    pub fn still(
        &self,
        programs: &std::ffi::OsStr,
        kits_root: &Path,
        stat: impl Fn(&Path) -> Stood,
    ) -> bool {
        self.programs == programs
            && self.kits_root == kits_root
            && self.reads.iter().all(|(path, was)| stat(path) == *was)
    }
}

/// [`find`], kept for the process's life and found again only when something it read has
/// changed ([`Kept::still`]): a warm edit stats a dozen paths and reads one registry value
/// where `find` starts `vswhere` (about 48 ms a build on a warm daemon, `lanes\backend.md`).
/// An error is never kept: the next ask finds again, so a user who installs the tools needs
/// no restart.
#[cfg(windows)]
pub fn found() -> Result<Developer, String> {
    static KEPT: crate::lock::Lock<Option<Kept>> = crate::lock::Lock::new("platform.msvc.kept", None);
    let programs = std::env::var_os("ProgramFiles(x86)")
        .ok_or("ProgramFiles(x86), where vswhere is, is not set")?;
    let kits = kits_root()?;
    if let Some(kept) = KEPT.lock().as_ref()
        && kept.still(&programs, &kits, stood)
    {
        return Ok(kept.developer.clone()); // clone: a few paths, once per job
    }
    let kept = find_kept()?;
    let developer = kept.developer.clone(); // clone: a few paths, once per find
    *KEPT.lock() = Some(kept);
    Ok(developer)
}

/// The newest Visual Studio with the MSVC x64 tools (as `vswhere -latest` says) and its
/// default tools' version, and the newest whole Windows SDK the registry's `KitsRoot10` names:
/// an error naming what is missing where, as a developer prompt fails to open. Found anew on
/// every call; [`found`] keeps it.
#[cfg(windows)]
pub fn find() -> Result<Developer, String> {
    find_kept().map(|it| it.developer)
}

/// [`find`] with what it read.
#[cfg(windows)]
fn find_kept() -> Result<Kept, String> {
    let programs = std::env::var_os("ProgramFiles(x86)")
        .ok_or("ProgramFiles(x86), where vswhere is, is not set")?;
    // Read before `vswhere` runs, so a change while it runs is a change the next ask sees.
    let mut reads = setup_records();
    let vswhere = Path::new(&programs).join(r"Microsoft Visual Studio\Installer\vswhere.exe");
    reads.push((vswhere.clone(), stood(&vswhere))); // clone: a path, once per find
    let said = super::command::command(&vswhere, Path::new(&programs))
        .args(["-latest", "-products", "*", "-requires"])
        .arg("Microsoft.VisualStudio.Component.VC.Tools.x86.x64")
        .args(["-property", "installationPath", "-utf8"])
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|error| format!("{}: {error}", vswhere.display()))?;
    let install = String::from_utf8(said.stdout)
        .map_err(|_| format!("{} printed what is not UTF-8", vswhere.display()))?;
    let install = PathBuf::from(install.trim());
    if !said.status.success() || install.as_os_str().is_empty() {
        return Err(format!(
            "{} names no Visual Studio with the MSVC x64 tools ({}): install the C++ build tools",
            vswhere.display(),
            said.status
        ));
    }
    let default = install.join(r"VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt");
    reads.push((default.clone(), stood(&default))); // clone: a path, once per find
    let tools = std::fs::read_to_string(&default)
        .map_err(|error| format!("{}: {error}", default.display()))?
        .trim()
        .to_owned();
    let kits = kits_root()?;
    for dir in ["Include", "Lib"] {
        let dir = kits.join(dir);
        reads.push((dir.clone(), stood(&dir))); // clone: a path, once per find
    }
    let sdk = newest_sdk(&kits, "x64")?;
    for file in [
        kits.join("Include").join(&sdk).join(r"um\windows.h"),
        kits.join("Lib").join(&sdk).join(r"um\x64\kernel32.lib"),
    ] {
        let was = stood(&file);
        reads.push((file, was));
    }
    let found = Developer { install, tools, kits: kits.clone(), sdk }; // clone: a path, once per find
    let cl = found.vc_tools().join(r"bin\Hostx64\x64\cl.exe");
    if !cl.is_file() {
        return Err(format!("{} is not a file: the MSVC tools are not whole", cl.display()));
    }
    let was = stood(&cl);
    reads.push((cl, was));
    Ok(Kept { developer: found, programs, kits_root: kits, reads })
}

/// Visual Studio's setup records as `vswhere` reads them: the instances' directory under
/// `ProgramData` and each instance's `state.json`, each as it stands now. With no
/// `ProgramData`, the one read is its absence, which stands until it is set.
#[cfg(windows)]
fn setup_records() -> Vec<(PathBuf, Stood)> {
    let mut reads = Vec::new(); // alloc: a dozen paths, once per find
    let Some(data) = std::env::var_os("ProgramData") else { return reads };
    let instances = Path::new(&data).join(r"Microsoft\VisualStudio\Packages\_Instances");
    reads.push((instances.clone(), stood(&instances))); // clone: a path, once per find
    if let Ok(entries) = std::fs::read_dir(&instances) {
        for entry in entries.flatten() {
            let state = entry.path().join("state.json");
            let was = stood(&state);
            reads.push((state, was));
        }
    }
    reads.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    reads
}

/// `HKLM\SOFTWARE\Microsoft\Windows Kits\Installed Roots`' `KitsRoot10`, which the SDK's
/// installer writes and `vcvarsall.bat` reads.
#[cfg(windows)]
#[allow(unsafe_code, reason = "RegGetValueW into a buffer of this frame, one call")]
fn kits_root() -> Result<PathBuf, String> {
    use std::os::windows::ffi::OsStringExt as _;
    use windows_sys::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6432KEY, RegGetValueW,
    };
    const KEY: &str = r"SOFTWARE\Microsoft\Windows Kits\Installed Roots";
    let wide = |it: &str| it.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let (key, value) = (wide(KEY), wide("KitsRoot10"));
    let mut buffer = [0u16; 1024];
    let mut bytes = size_of_val(&buffer) as u32;
    // SAFETY: the key and value names are NUL-terminated and live for the call; `buffer` is
    // `bytes` bytes, live and exclusive, which the call writes no further than.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6432KEY,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if status != 0 {
        return Err(format!(
            r"HKLM\{KEY}\KitsRoot10, where the Windows SDK is: {}: install the Windows SDK",
            std::io::Error::from_raw_os_error(status as i32)
        ));
    }
    let chars = (bytes as usize / 2).saturating_sub(1);
    let root = PathBuf::from(OsString::from_wide(&buffer[..chars]));
    if !root.is_dir() {
        return Err(format!(r"HKLM\{KEY}\KitsRoot10 is {}, which is not a directory", root.display()));
    }
    Ok(root)
}

#[cfg(test)]
mod tests;
