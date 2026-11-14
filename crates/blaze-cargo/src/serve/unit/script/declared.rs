//! Inputs of the Windows Cargo-rule cache that are known before a script runs. Never a
//! permission source: the executable search and link directories here grant no access.

use super::*;
use blaze_ids::{ContentId, Hasher};
use blaze_usercode::{inputs::{Disk, granted}, trace::Inputs as _};

/// Capture the actual roots once per inspection. Resolving the saved root name again at
/// each lookup would let a moved junction change the boundary of the lookup itself.
pub(super) fn roots(read: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    read.iter().map(|p| std::fs::canonicalize(p).map_err(|e| format!("resolving script grant {}: {e}", p.display()))).collect()
}

pub(super) fn result(value: &Value) -> ContentId {
    let mut h = Hasher::new("blaze Windows build dependency outputs 1");
    h.part(&value.stdout).part(&value.stderr);
    for file in &value.files {
        h.part(file.path.as_bytes())
            .update(&[u8::from(file.executable)])
            .opt_part(file.link.as_deref().map(str::as_bytes))
            .opt_part(file.bytes.as_deref());
    }
    h.finish()
}

pub(super) fn given(
    job: &Job,
    run: usize,
    unit: &bs::Unit,
    inherited: &[(OsString, OsString)],
    roots: &[PathBuf],
    mut mutable: Vec<PathBuf>,
) -> Result<ContentId, String> {
    let env = script::script_env(unit, inherited).map_err(|it| it.0)?;
    let get = |n: &str| env.iter().rev().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v);
    let mut h = Hasher::new("blaze Windows confined Cargo rules 1");
    h.part(crate::toolchain::library::found()?.digest.as_bytes());
    for dep in &job.unit(run).map_err(|it| it.what)?.dependencies {
        if let Some(output) = job.scripts[dep.index].get() {
            h.part(output.package_id.as_bytes()).id(&output.result);
        }
    }
    // Explicitly configured link search paths, not the whole machine library search path.
    // Repository config permits linking, not reads by the daemon on the script's behalf.
    let mut links = crate::directives::link_dirs(&job.units().link_dirs, inherited)?;
    links.extend(crate::directives::machine_link_dirs(inherited)?);
    for dir in links {
        h.part(dir.as_os_str().as_encoded_bytes());
        if granted(&dir, roots).map_err(|e| e.to_string())? {
            mutable.push(dir);
        }
    }
    mutable.sort();
    mutable.dedup();
    let mut disk = Disk::new(Vec::new()).declared_inputs(roots.to_vec());
    for path in mutable {
        h.part(path.as_os_str().as_encoded_bytes());
        if path.parent().is_none() || !path.is_absolute() {
            return Err(format!(
                "declared script input {} is not below a volume root",
                path.display()
            ));
        }
        let stamp = disk.tree(&path, false).map_err(|e| e.to_string())?;
        match stamp {
            Some(tree) => {
                h.update(b"d").update(&tree);
            }
            None => {
                h.update(b"f").opt_part(
                    disk.file(&path).map_err(|e| e.to_string())?.as_ref().map(|it| &it[..]),
                );
            }
        }
    }
    let mut search = vec![unit.package.manifest_dir.clone()]; // alloc: tool locations in the child's environment
    if let Some(parent) = unit.script.parent() {
        search.push(parent.to_owned());
    }
    if let Some(root) = get("SystemRoot") {
        search.push(Path::new(root).join("System32"));
    }
    if let Some(path) = get("PATH") {
        search.extend(std::env::split_paths(path).map(|dir| unit.package.manifest_dir.join(dir)));
    }
    // Fingerprint all existing candidates, not just the first visible to the daemon:
    // AppContainer may be unable to traverse an earlier PATH entry. Also covers a
    // higher-priority executable appearing between runs. Do not open arbitrary devices.
    let tool = |h: &mut Hasher, path: &Path| -> Result<(), String> {
        use std::os::windows::fs::MetadataExt;
        blaze_vfs::outside::looked(path);
        match std::fs::metadata(path) {
            Ok(m) if m.is_file() => {
                h.part(path.as_os_str().as_encoded_bytes())
                    .update(&m.file_size().to_le_bytes())
                    .update(&m.last_write_time().to_le_bytes())
                    .update(&m.creation_time().to_le_bytes());
            }
            Ok(_) => (),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound
                        | std::io::ErrorKind::NotADirectory
                        | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                ()
            }
            Err(e) => return Err(format!("stamping tool {}: {e}", path.display())),
        }
        Ok(())
    };
    for dir in search {
        for name in [
            "cl.exe", "link.exe", "lib.exe", "ml64.exe", "rc.exe", "nasm.exe", "git.exe", "zig.exe",
        ] {
            tool(&mut h, &dir.join(name))?;
        }
    }
    for path in [&unit.tools.rustc, &unit.tools.rustdoc, &unit.tools.cargo] {
        tool(&mut h, path)?;
    }
    for n in ["CC", "CXX", "AR", "NASM", "ZIG", "RC"] {
        if let Some(path) = get(n).map(Path::new).filter(|p| p.is_absolute()) {
            tool(&mut h, path)?;
        }
    }
    Ok(h.finish())
}
