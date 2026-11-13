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

/// The newest Visual Studio with the MSVC x64 tools (as `vswhere -latest` says) and its
/// default tools' version, and the newest whole Windows SDK the registry's `KitsRoot10` names:
/// an error naming what is missing where, as a developer prompt fails to open.
#[cfg(windows)]
pub fn find() -> Result<Developer, String> {
    let programs = std::env::var_os("ProgramFiles(x86)")
        .ok_or("ProgramFiles(x86), where vswhere is, is not set")?;
    let vswhere = Path::new(&programs).join(r"Microsoft Visual Studio\Installer\vswhere.exe");
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
    let tools = std::fs::read_to_string(&default)
        .map_err(|error| format!("{}: {error}", default.display()))?
        .trim()
        .to_owned();
    let kits = kits_root()?;
    let sdk = newest_sdk(&kits, "x64")?;
    let found = Developer { install, tools, kits, sdk };
    let cl = found.vc_tools().join(r"bin\Hostx64\x64\cl.exe");
    if !cl.is_file() {
        return Err(format!("{} is not a file: the MSVC tools are not whole", cl.display()));
    }
    Ok(found)
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
