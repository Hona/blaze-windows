//! Windows incremental latency matrix. Run `windows_matrix <config.json>` (or inline JSON, or `-`).
//! Each volume is a scratch directory. A trial owns two disposable clones at the input commit,
//! one per tool. Never edit the caller's checkout. `after` may contain `{tick}` to make each
//! edited body new even if a previous verb built it. Select a noninteractive `run` and a named
//! `test` that exit. `test_args` includes its package, if any. See tools/bench/windows-hello.json.

use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use serde::Deserialize;
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Edit {
    file: PathBuf,
    before: String,
    after: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Matrix {
    project: PathBuf,
    blaze: PathBuf,
    engine: PathBuf,
    blaze_commit: String,
    cargo: PathBuf,
    /// Inputs only. Never seed a daemon image, compiled std or build output.
    toolchains: PathBuf,
    library: Option<PathBuf>,
    sources: Option<PathBuf>,
    volumes: Vec<PathBuf>,
    out: PathBuf,
    runs: u32,
    comment: PathBuf,
    leaf: Edit,
    mid: Option<Edit>,
    test: Edit,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    run_args: Vec<String>,
    test_args: Vec<String>,
    #[serde(default)]
    cases: Vec<String>,
    #[serde(default)]
    environment: BTreeMap<String, String>,
}

const CASES: &[(&str, &str)] = &[
    ("cold", "build"),
    ("restart", "build"),
    ("noop", "check"),
    ("noop", "build"),
    ("comment", "check"),
    ("comment", "build"),
    ("comment", "run"),
    ("leaf", "check"),
    ("leaf", "build"),
    ("leaf", "run"),
    ("mid", "check"),
    ("mid", "build"),
    ("test", "test"),
];

fn summary(mut ms: Vec<f64>) -> Value {
    ms.sort_by(f64::total_cmp);
    let n = ms.len();
    json!({"n":n,"min_ms":ms[0],"median_ms":(ms[(n-1)/2]+ms[n/2])/2.,"p90_ms":ms[(9*n).div_ceil(10)-1]})
}

fn output(cmd: &mut Command) -> Result<String> {
    let o = cmd.output()?;
    if !o.status.success() {
        return Err(format!("{cmd:?}: {}: {}", o.status, String::from_utf8_lossy(&o.stderr)).into());
    }
    Ok(String::from_utf8(o.stdout)?.trim().to_owned())
}
fn git(root: &Path, args: &[&str]) -> Result<String> {
    output(Command::new("git").current_dir(root).args(args))
}

#[cfg(windows)]
mod host {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut std::ffi::c_void;
        fn GetSystemTimes(idle: *mut u64, kernel: *mut u64, user: *mut u64) -> i32;
        fn WaitForSingleObject(handle: *mut std::ffi::c_void, ms: u32) -> u32;
    }
    fn times() -> Result<(u64, u64)> {
        let (mut idle, mut kernel, mut user) = (0, 0, 0);
        // SAFETY: each aligned 8-byte slot holds the returned FILETIME; kernel includes idle.
        if unsafe { GetSystemTimes(&mut idle, &mut kernel, &mut user) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok((idle, kernel + user))
    }
    pub(super) fn load() -> Result<f64> {
        let a = times()?;
        std::thread::sleep(Duration::from_millis(125));
        let b = times()?;
        if b.1 == a.1 {
            return Err("no processor ticks in start-load sample".into());
        }
        Ok(100. * (1. - (b.0 - a.0) as f64 / (b.1 - a.1) as f64))
    }
    pub(super) fn await_stop(pid: u32, stop: impl FnOnce() -> Result<()>) -> Result<()> {
        use std::os::windows::io::{FromRawHandle, OwnedHandle};
        // SAFETY: SYNCHRONIZE only. Open before asking for stop so a reused PID cannot match.
        let handle = unsafe { OpenProcess(0x0010_0000, 0, pid) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
        stop()?;
        // The socket goes away before Windows releases the daemon's file mappings.
        if unsafe { WaitForSingleObject(handle.as_raw_handle(), 60_000) } != 0 {
            return Err(format!("daemon {pid} did not exit after stop").into());
        }
        Ok(())
    }
    pub(super) fn wait(child: &mut std::process::Child) -> Result<()> {
        // SAFETY: the child owns this process handle for the call. No polling tick in wall_ms.
        match unsafe { WaitForSingleObject(child.as_raw_handle(), 3_600_000) } {
            0 => Ok(()),
            258 => {
                child.kill()?;
                child.wait()?;
                Err("command exceeded one hour".into())
            }
            _ => Err(std::io::Error::last_os_error().into()),
        }
    }
}
#[cfg(not(windows))]
mod host {
    use super::*;
    pub(super) fn await_stop(_: u32, _: impl FnOnce() -> Result<()>) -> Result<()> {
        Err("Windows only".into())
    }
    pub fn load() -> Result<f64> {
        Err("windows_matrix needs Windows processor counters".into())
    }
    pub fn wait(_: &mut std::process::Child) -> Result<()> {
        Err("windows_matrix needs Windows".into())
    }
}

struct Side<'a> {
    m: &'a Matrix,
    blaze: bool,
    root: PathBuf,
}
impl Side<'_> {
    fn project(&self) -> PathBuf {
        self.root.join("src")
    }
    fn command(&self) -> Command {
        let mut cmd = Command::new(if self.blaze { &self.m.blaze } else { &self.m.cargo });
        cmd.current_dir(self.project())
            .envs(&self.m.environment)
            .env("BLAZE_HOME", self.root.join("home"))
            .env("CARGO_TARGET_DIR", self.root.join("target"))
            .env("CARGO_NET_OFFLINE", "true");
        // BLAZE_HOME alone still shares std with LOCALAPPDATA/blaze on the same volume.
        // A cold sample owns both; leave cargo's prefetched registry/toolchain unchanged.
        if self.blaze {
            cmd.env("LOCALAPPDATA", self.root.join("local"));
        }
        cmd
    }
    fn stop(&self) -> Result<()> {
        if self.blaze && self.root.join("home").exists() {
            let status: Value =
                serde_json::from_str(&output(self.command().args(["status", "--json"]))?)?;
            if let Some(pid) = status["daemon"]["pid"].as_u64() {
                host::await_stop(pid.try_into()?, || {
                    output(self.command().arg("stop"))?;
                    Ok(())
                })?;
            }
        }
        Ok(())
    }
    fn invoke(&self, args: &[String], log: &Path) -> Result<f64> {
        let mut cmd = self.command();
        let file = fs::File::create_new(log)?;
        cmd.args(args).stdin(Stdio::null()).stdout(file.try_clone()?).stderr(file);
        let t = Instant::now();
        let mut child = cmd.spawn()?;
        host::wait(&mut child)?;
        let status = child.wait()?;
        let ms = t.elapsed().as_secs_f64() * 1000.;
        if !status.success() {
            return Err(format!("{args:?}: {status}; see {}", log.display()).into());
        }
        Ok(ms)
    }
}

fn edit_path(project: &Path, name: &Path) -> Result<PathBuf> {
    let p = project.join(name).canonicalize()?;
    if !p.starts_with(project.canonicalize()?)
        || p.components().any(|c| c.as_os_str() == ".git")
        || !p.is_file()
    {
        return Err(format!("edit outside project sources: {}", name.display()).into());
    }
    Ok(p)
}

/// Copy only from the explicitly named, pre-fetched input tree, never follow links.
fn seed(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dest = to.join(entry.file_name());
        if ty.is_file() {
            fs::copy(entry.path(), dest)?;
        } else if ty.is_dir() {
            seed(&entry.path(), &dest)?;
        } else {
            return Err(format!("unsupported seed file: {}", entry.path().display()).into());
        }
    }
    Ok(())
}

fn changed(text: &str, edit: &Edit, tick: u32) -> Result<String> {
    let after = edit.after.replace("{tick}", &tick.to_string());
    if edit.before.is_empty() || text.matches(&edit.before).count() != 1 || edit.before == after {
        return Err(format!(
            "{}: edit must replace exactly one occurrence with different bytes",
            edit.file.display()
        )
        .into());
    }
    Ok(text.replacen(&edit.before, &after, 1))
}

fn trial(
    m: &Matrix,
    volume: &Path,
    sha: &str,
    i: u32,
    rows: &mut fs::File,
    groups: &mut BTreeMap<String, Vec<f64>>,
) -> Result<()> {
    let dir = volume.join(format!("mx{}-{i}", std::process::id()));
    fs::create_dir(&dir)?; // create, not create_all: this experiment never adopts existing data.
    let sides = [
        Side { m, blaze: true, root: dir.join("b") },
        Side { m, blaze: false, root: dir.join("c") },
    ];
    let result = (|| -> Result<()> {
        for s in &sides {
            fs::create_dir(&s.root)?;
            if s.blaze {
                seed(&m.toolchains, &s.root.join("local/blaze/toolchains"))?;
                if let Some(lib) = &m.library {
                    seed(lib, &s.root.join("home/library"))?;
                }
                if let Some(src) = &m.sources {
                    seed(src, &s.root.join("home/sources"))?;
                }
            }
            output(
                Command::new("git")
                    .args(["clone", "--no-hardlinks", "--no-checkout"])
                    .arg(&m.project)
                    .arg(s.project()),
            )?;
            git(&s.project(), &["checkout", "--detach", sha])?;
        }
        for (k, &(kind, verb)) in CASES.iter().enumerate() {
            let case = format!("{kind}-{verb}");
            if !m.cases.is_empty() && !m.cases.contains(&case) {
                continue;
            }
            if kind == "mid" && m.mid.is_none() {
                continue;
            } // recorded as not applicable in the report
            let tick = i * CASES.len() as u32 + k as u32;
            for j in 0..2 {
                let s = &sides[(i as usize + j + k) % 2];
                let tool = if s.blaze { "blaze" } else { "cargo" };
                let mut args = vec![verb.to_owned()];
                args.extend_from_slice(if kind == "test" { &m.test_args } else { &m.args });
                if verb == "run" && !m.run_args.is_empty() {
                    args.push("--".into());
                    args.extend_from_slice(&m.run_args);
                }
                let log = m.out.join(format!(
                    "v{}-{i}-{case}-{tool}",
                    m.volumes.iter().position(|v| v == volume).unwrap()
                ));
                if kind != "cold" {
                    s.invoke(&args, &log.with_extension("settle"))?;
                }
                // The first walk after work was done establishes the reusable answer. It
                // is not the warm no-op; time the following invocation against cargo's.
                if kind == "noop" {
                    s.invoke(&args, &log.with_extension("warm"))?;
                }
                if kind == "restart" {
                    s.stop()?;
                } // cargo has no daemon; its control is an ordinary warm build.
                let e = match kind {
                    "leaf" => Some(&m.leaf),
                    "mid" => m.mid.as_ref(),
                    "test" => Some(&m.test),
                    _ => None,
                };
                let edited = if let Some(name) =
                    e.map(|e| &e.file).or((kind == "comment").then_some(&m.comment))
                {
                    let p = edit_path(&s.project(), name)?;
                    let old = fs::read_to_string(&p)?;
                    let new = if let Some(e) = e {
                        changed(&old, e, tick)?
                    } else {
                        format!("{old}\n// bench-tick-{tick}\n")
                    };
                    fs::write(&p, new)?;
                    Some((p, old))
                } else {
                    None
                };
                let load = host::load()?;
                let ms = s.invoke(&args, &log.with_extension("log"))?;
                if let Some((p, old)) = edited {
                    fs::write(p, old)?;
                }
                let row = json!({"volume":volume,"trial":i,"warmup":i==0,"case":case,"tool":tool,"args":args,"start_cpu_pct":load,"wall_ms":ms});
                writeln!(rows, "{row}")?;
                rows.flush()?;
                if i != 0 {
                    groups
                        .entry(format!("{}:{case}:{tool}", volume.display()))
                        .or_default()
                        .push(ms);
                }
            }
        }
        Ok(())
    })();
    let stopped = sides[0].stop();
    result?;
    stopped?;
    fs::remove_dir_all(dir)?; // only the new directory this trial successfully created, with daemons stopped
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [arg] = &args[..] else { return Err("windows_matrix: one JSON input".into()) };
    let value = blaze_script::input::read(arg).map_err(|e| e.0)?;
    let m: Matrix = serde_json::from_value(value.clone())?;
    if m.runs == 0
        || m.runs > 1000
        || m.volumes.is_empty()
        || m.volumes.iter().any(|p| !p.is_absolute())
        || !m.blaze.is_absolute()
        || !m.cargo.is_absolute()
    {
        return Err("give absolute tool and scratch paths, 1..1000 trials".into());
    }
    for case in &m.cases {
        if !CASES.iter().any(|(k, v)| *case == format!("{k}-{v}")) {
            return Err(format!("unknown case {case}").into());
        }
    }
    let sha = git(&m.project, &["rev-parse", "HEAD"])?;
    let blob = |p: &Path| output(Command::new("git").arg("hash-object").arg(p));
    let provenance = json!({"input":value,"project_commit":sha,"blaze_commit":m.blaze_commit,"engine_git_blob":blob(&m.engine)?,"client_git_blob":blob(&m.blaze)?,"cargo":output(Command::new(&m.cargo).arg("-Vv"))?,"mid_applicable":m.mid.is_some()});
    fs::create_dir(&m.out)?;
    fs::write(m.out.join("input.json"), serde_json::to_vec_pretty(&provenance)?)?;
    let mut rows = fs::File::create_new(m.out.join("samples.jsonl"))?;
    let mut groups = BTreeMap::new();
    for volume in &m.volumes {
        fs::create_dir_all(volume)?;
        for i in 0..=m.runs {
            trial(&m, volume, &sha, i, &mut rows, &mut groups)?;
        }
    }
    let summary = groups.into_iter().map(|(key, v)| (key, summary(v))).collect::<BTreeMap<_, _>>();
    fs::write(m.out.join("summary.json"), serde_json::to_vec_pretty(&summary)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn percentiles_and_exact_edits() {
        assert_eq!(
            summary(vec![4., 1., 3., 2.]),
            json!({"n":4,"min_ms":1.,"median_ms":2.5,"p90_ms":4.})
        );
        let e = Edit { file: "main.rs".into(), before: "a".into(), after: "{tick}".into() };
        assert_eq!(changed("a\r\n", &e, 5).unwrap(), "5\r\n");
        assert!(changed("aa", &e, 5).is_err());
    }
}
