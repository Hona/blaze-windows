//! The `machine` section of `blaze doctor` on Windows: what this machine costs a build, each
//! with the change that removes the cost. It reads; it never changes a setting.
//!
//! - commit limit: physical memory and the page files at their present size. A cold build of a
//!   large workspace holds tens of gigabytes; past the daemon's ceiling it gives back what it
//!   holds and makes it again, slower ([`crate::serve`]'s relief ladder).
//! - volume: a Dev Drive (ReFS) clones an output where NTFS writes all its bytes, and Defender
//!   scans a trusted Dev Drive in performance mode.
//! - Defender: a directory blaze writes that Defender scans costs a scan at every open.

use std::path::Path;

use super::{Check, Verdict, quoted};

const GIB: u64 = 1 << 30;

/// The commit limit under which a cold build of a large workspace meets the daemon's ceiling:
/// the daemon held 37 GB of commit on rune's `hello` (276 packages) before its memory was cut.
const COMMIT_ENOUGH: u64 = 32 * GIB;

/// The system's commit limit `limit` against its physical memory `physical`.
pub(super) fn commit_check(limit: u64, physical: u64) -> Check {
    let check = |verdict, said: String| Check::new("machine", "commit limit", Path::new(""), verdict, said);
    let said = format!(
        "{:.1} GiB (physical memory {:.1} GiB and the page files as they are now)",
        limit as f64 / GIB as f64,
        physical as f64 / GIB as f64
    );
    match limit >= COMMIT_ENOUGH {
        true => check(Verdict::Ok, said),
        false => check(
            Verdict::Warn,
            format!(
                "{said}: a cold build of a large workspace needs more; at the limit the daemon lets go of what it holds and \
                 makes it again, slower"
            ),
        )
        .fixed_by(
            "let Windows manage the page file (System Properties > Advanced > Performance > Settings > Advanced > \
             Virtual memory > Automatically manage), or set its maximum so it and physical memory make at least 64 GB",
        ),
    }
}

/// What the volume a directory is on is, as [`volume_check`] reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct VolumeFacts {
    /// The file system's name (`NTFS`, `ReFS`).
    system: String,
    /// Its files can share blocks: an output is cloned.
    clones: bool,
    /// Whether it is a Dev Drive, and a trusted one; `None` when the system would not say.
    dev_drive: Option<(bool, bool)>,
}

/// The volume `dir` (blaze's root when `root`, else the workspace) is on.
pub(super) fn volume_check(dir: &Path, root: bool, facts: Result<VolumeFacts, String>) -> Check {
    let what = if root { "blaze's volume" } else { "the workspace's volume" };
    let check = |verdict, said: String| Check::new("machine", what, dir, verdict, said);
    let moved = match root {
        true => "set BLAZE_HOME to a directory on it",
        false => "move the workspace onto it",
    };
    let facts = match facts {
        Ok(facts) => facts,
        Err(why) => return check(Verdict::Warn, format!("its volume cannot be asked: {why}")),
    };
    match (facts.dev_drive, facts.clones) {
        (Some((true, true)), _) => check(
            Verdict::Ok,
            "a trusted Dev Drive: outputs are cloned, and Defender scans it in performance mode".to_owned(),
        ),
        (Some((true, false)), _) => check(
            Verdict::Warn,
            "a Dev Drive the system does not trust: Defender scans it as any volume, before each open".to_owned(),
        )
        .fixed_by(format!("as an administrator: fsutil devdrv trust {}", quoted(volume_root(dir)))),
        (_, true) => check(
            Verdict::Ok,
            format!("{}: outputs are cloned; not a Dev Drive, so Defender scans it as any volume", facts.system),
        ),
        (_, false) => check(
            Verdict::Warn,
            format!(
                "{}: its files share no blocks, so each output is written in full where it goes, and Defender scans \
                 each file before it opens",
                facts.system
            ),
        )
        .fixed_by(format!(
            "make a Dev Drive (Settings > System > Storage > Advanced storage settings > Disks & volumes > Create Dev \
             Drive), then {moved}"
        )),
    }
}

/// The drive `dir` is on (`D:\`), or `dir` when it has none.
fn volume_root(dir: &Path) -> &Path {
    dir.ancestors().last().unwrap_or(dir)
}

/// What the registry says of Defender's exclusions, as [`defender_check`] reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Defender {
    Absent,
    Excludes(Vec<String>),
    Unreadable,
}

/// Whether Defender scans what blaze writes in `dirs` (each with whether it is on a trusted
/// Dev Drive), given its exclusions; `env` names a `%VARIABLE%`'s value.
pub(super) fn defender_check(dirs: &[(&Path, bool)], defender: &Defender, env: impl Fn(&str) -> Option<String>) -> Check {
    let check = |verdict, said: String| Check::new("machine", "Defender", Path::new(""), verdict, said);
    let scanned: Vec<&Path> = match defender {
        Defender::Absent => {
            return check(Verdict::Ok, "Microsoft Defender is not installed: another antivirus may scan".to_owned());
        }
        Defender::Unreadable => dirs.iter().filter(|(_, trusted)| !trusted).map(|(dir, _)| *dir).collect(),
        Defender::Excludes(paths) => dirs
            .iter()
            .filter(|(dir, trusted)| !trusted && !paths.iter().any(|it| covers(&expand(it, &env), dir)))
            .map(|(dir, _)| *dir)
            .collect(),
    };
    if scanned.is_empty() {
        return check(
            Verdict::Ok,
            "every directory blaze writes is excluded or on a trusted Dev Drive".to_owned(),
        );
    }
    let named: Vec<String> = scanned.iter().map(|it| it.display().to_string()).collect();
    let words: Vec<String> = scanned.iter().map(|it| format!("'{}'", it.display().to_string().replace('\'', "''"))).collect();
    let said = match defender {
        Defender::Unreadable => format!(
            "only an administrator can read Defender's exclusions: unless they hold {}, it scans each file blaze opens \
             there; run `blaze doctor` as one to know",
            named.join(", ")
        ),
        _ => format!("Defender scans each file blaze opens in {}", named.join(", ")),
    };
    check(Verdict::Warn, said)
        .fixed_by(format!("in PowerShell, as an administrator: Add-MpPreference -ExclusionPath {}", words.join(",")))
}

/// `path` with each `%NAME%` replaced by `env`'s value of it (left as it is when unset).
fn expand(path: &str, env: &impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(path.len()); // alloc: a doctor's check
    let mut rest = path;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                match env(&after[..end]) {
                    Some(value) => out.push_str(&value),
                    None => out.push_str(&rest[start..start + end + 2]),
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// Whether the excluded path `excluded` holds `dir`: one of its ancestors or itself, compared
/// as Windows compares paths (either slash, any case, a trailing slash or none).
fn covers(excluded: &str, dir: &Path) -> bool {
    let norm = |text: &str| text.replace('/', "\\").trim_end_matches('\\').to_lowercase();
    let (excluded, dir) = (norm(excluded), norm(&dir.display().to_string()));
    !excluded.is_empty()
        && (dir == excluded || dir.strip_prefix(&excluded).is_some_and(|rest| rest.starts_with('\\')))
}

/// Every check of the section, asked of this machine: blaze's root and the workspace.
#[cfg(windows)]
pub(super) fn checks(root: &Path, project: Option<&Path>) -> Vec<Check> {
    let mut checks = Vec::new(); // alloc: once per doctor
    checks.push(match blaze_mem::address_capacity() {
        Ok(it) => commit_check(it.commit_limit, it.physical),
        Err(error) => Check::new("machine", "commit limit", Path::new(""), Verdict::Warn, format!("it cannot be read: {error}")),
    });
    let mut dirs = Vec::new(); // alloc: once per doctor
    for (dir, is_root) in std::iter::once((root, true)).chain(project.map(|it| (it, false))) {
        let facts = facts_of(dir);
        let trusted = matches!(&facts, Ok(VolumeFacts { dev_drive: Some((true, true)), .. }));
        dirs.push((dir, trusted));
        checks.push(volume_check(dir, is_root, facts));
    }
    let defender = match crate::raw::system::defender_exclusions() {
        crate::raw::system::Exclusions::NoDefender => Defender::Absent,
        crate::raw::system::Exclusions::Read(paths) => Defender::Excludes(paths),
        crate::raw::system::Exclusions::Unreadable => Defender::Unreadable,
    };
    checks.push(defender_check(&dirs, &defender, |name| std::env::var(name).ok()));
    checks
}

#[cfg(windows)]
fn facts_of(dir: &Path) -> Result<VolumeFacts, String> {
    let volume = blaze_core::platform::volume(dir).map_err(|error| error.to_string())?;
    let dev_drive = blaze_core::platform::volume::dev_drive(dir).ok().map(|it| (it.dev, it.trusted));
    Ok(VolumeFacts {
        system: volume.system,
        clones: volume.sharing == blaze_core::platform::Sharing::Blocks,
        dev_drive,
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{Defender, VolumeFacts, commit_check, covers, defender_check, expand, volume_check};
    use super::super::Verdict;

    #[test]
    fn a_low_commit_limit_is_a_warning_with_the_page_file_fix() {
        let low = commit_check(24 << 30, 16 << 30);
        assert_eq!(low.verdict, Verdict::Warn);
        assert!(low.fix.as_deref().is_some_and(|it| it.contains("page file")), "{low:?}");
        assert_eq!(commit_check(48 << 30, 32 << 30).verdict, Verdict::Ok);
    }

    #[test]
    fn a_volume_is_judged_by_dev_drive_then_cloning() {
        let facts = |system: &str, clones, dev_drive| Ok(VolumeFacts { system: system.to_owned(), clones, dev_drive });
        let dir = Path::new(r"D:\blaze");
        assert_eq!(volume_check(dir, true, facts("ReFS", true, Some((true, true)))).verdict, Verdict::Ok);
        let untrusted = volume_check(dir, true, facts("ReFS", true, Some((true, false))));
        assert_eq!(untrusted.verdict, Verdict::Warn);
        assert!(untrusted.fix.as_deref().is_some_and(|it| it.contains("fsutil devdrv trust")), "{untrusted:?}");
        assert_eq!(volume_check(dir, true, facts("ReFS", true, None)).verdict, Verdict::Ok);
        let ntfs = volume_check(Path::new(r"C:\w"), false, facts("NTFS", false, Some((false, false))));
        assert_eq!(ntfs.verdict, Verdict::Warn);
        assert!(ntfs.fix.as_deref().is_some_and(|it| it.contains("move the workspace")), "{ntfs:?}");
        assert_eq!(volume_check(dir, true, Err("refused".to_owned())).verdict, Verdict::Warn);
    }

    #[test]
    fn an_exclusion_covers_its_directory_and_below_it_in_any_case_or_slash() {
        assert!(covers(r"C:\Users\me\.blaze\", Path::new(r"c:\users\ME\.blaze\state")));
        assert!(covers("C:/Users/me/.blaze", Path::new(r"C:\Users\me\.blaze")));
        assert!(!covers(r"C:\Users\me\.bl", Path::new(r"C:\Users\me\.blaze")), "a prefix of a name is no ancestor");
        assert!(!covers("", Path::new(r"C:\x")));
    }

    #[test]
    fn variables_in_an_exclusion_are_expanded_and_unknown_ones_kept() {
        let env = |name: &str| (name == "USERPROFILE").then(|| r"C:\Users\me".to_owned());
        assert_eq!(expand(r"%USERPROFILE%\.blaze", &env), r"C:\Users\me\.blaze");
        assert_eq!(expand(r"%NOPE%\x", &env), r"%NOPE%\x");
        assert_eq!(expand("50%", &env), "50%");
    }

    #[test]
    fn defender_warns_of_each_scanned_directory_not_on_a_trusted_dev_drive() {
        let env = |name: &str| (name == "USERPROFILE").then(|| r"C:\Users\me".to_owned());
        let (root, work) = (Path::new(r"C:\Users\me\.blaze"), Path::new(r"D:\work"));
        let excludes = Defender::Excludes(vec![r"%USERPROFILE%\.blaze".to_owned()]);
        let warned = defender_check(&[(root, false), (work, false)], &excludes, env);
        assert_eq!(warned.verdict, Verdict::Warn);
        assert!(warned.said.contains(r"D:\work") && !warned.said.contains(".blaze"), "{warned:?}");
        assert!(warned.fix.as_deref().is_some_and(|it| it.contains(r"-ExclusionPath 'D:\work'")), "{warned:?}");
        assert_eq!(defender_check(&[(root, false), (work, true)], &excludes, env).verdict, Verdict::Ok);
        assert_eq!(defender_check(&[(work, false)], &Defender::Absent, env).verdict, Verdict::Ok);
        let unread = defender_check(&[(work, false)], &Defender::Unreadable, env);
        assert!(unread.said.contains("administrator"), "{unread:?}");
    }
}
