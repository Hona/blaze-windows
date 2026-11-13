//! Windows build-script cache correctness, not a timing benchmark. One JSON argument:
//! `{"blaze":"target/release/blaze.exe","library":"library","work":"C:/scratch/new"}`.
//! `work` must not exist. The private home, build messages and outputs are left for inspection.

use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
};

use blaze_script::engine::{self, Env};
use serde::Deserialize;
use serde_json::Value;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ask {
    blaze: PathBuf,
    library: PathBuf,
    work: PathBuf,
}

const NATIVE: &str = r#"
use std::{env, fs, path::Path, process::Command};
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let inputs = Path::new("../inputs");
    let cc = Command::new("cl.exe").args(["/nologo", "/EP", "/TC", "unit.c"])
        .current_dir(inputs).output().expect("run the developer prompt's cl.exe");
    assert!(cc.status.success(), "{}", String::from_utf8_lossy(&cc.stderr));
    let mut names = fs::read_dir(inputs.join("members")).unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap()).collect::<Vec<_>>();
    names.sort();
    let result = format!("{};{};{};{}", fs::read_to_string(inputs.join("direct")).unwrap(),
        inputs.join("optional").try_exists().unwrap(), names.join(","),
        String::from_utf8(cc.stdout).unwrap().trim());
    fs::write(Path::new(&env::var_os("OUT_DIR").unwrap()).join("answer"), result).unwrap();
    fs::write(Path::new(&env::var_os("OUT_DIR").unwrap()).join("run-profile"), env::var("LOCALAPPDATA").unwrap()).unwrap();
}
"#;

const ENV_ONLY: &str = r#"
fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_KeySpelling");
    // This write precludes a pure-MIR shortcut; test a real confined script run.
    std::fs::write(std::path::Path::new(&std::env::var_os("OUT_DIR").unwrap()).join("run-profile"), std::env::var("LOCALAPPDATA").unwrap()).unwrap();
    if std::env::var_os("CARGO_KeySpelling").unwrap() == "one" {
        println!("cargo:rustc-cfg=first_value");
    } else {
        println!("cargo:rustc-cfg=second_value");
    }
}
"#;

fn package(root: &Path, name: &str, script: &str) -> Result<()> {
    let dir = root.join(name);
    fs::create_dir_all(dir.join("src"))?;
    fs::write(
        dir.join("Cargo.toml"),
        format!("[package]\nname=\"{name}\"\nversion=\"0.1.0\"\nedition=\"2021\"\n"),
    )?;
    fs::write(dir.join("src/lib.rs"), "pub const N: u32 = 1;\n")?;
    Ok(fs::write(dir.join("build.rs"), script)?)
}

struct Matrix {
    root: PathBuf,
    blaze: String,
    env: Env,
}

impl Matrix {
    fn build(&self, label: &str, name: &str) -> Result<Value> {
        let args = engine::argv(&[&self.blaze[..], "build", "-j2", "--message-format=json"]);
        let ran = engine::run(label, &args, &self.root.join(name), &self.env, 1200., false)
            .map_err(|e| e.said().to_owned())?;
        fs::write(self.root.join(format!("{label}.jsonl")), &ran.stdout)?;
        fs::write(self.root.join(format!("{label}.log")), &ran.stderr)?;
        let ran = ran.checked(label).map_err(|e| e.said().to_owned())?;
        // The project's directory and package have the same name, so cargo's package-id
        // spec elides the redundant name after '#'. The std scripts have different IDs.
        let id = format!("/{name}#0.1.0");
        let mut answer = None;
        for line in ran.stdout.lines() {
            let row: Value = serde_json::from_str(line)?;
            if row["reason"] == "build-script-executed"
                && row["package_id"].as_str().is_some_and(|it| it.ends_with(&id))
            {
                if answer.is_some() {
                    return Err(format!("{label}: two build-script results for {name}").into());
                }
                answer = Some(row);
            }
        }
        answer.ok_or_else(|| format!("{label}: no build-script result for {name}").into())
    }

    fn check(&mut self) -> Result<()> {
        let inputs = self.root.join("inputs");
        let native = "observer-fixture";
        let env_only = "env-fixture";
        package(&self.root, native, NATIVE)?;
        package(&self.root, env_only, ENV_ONLY)?;
        fs::create_dir_all(inputs.join("members"))?;
        fs::write(inputs.join("unit.c"), "#include \"external.h\"\nVALUE\n")?;
        fs::write(inputs.join("external.h"), "#define VALUE header_one\n")?;
        fs::write(inputs.join("direct"), "one")?;
        fs::write(inputs.join("members/a"), "")?;
        let mut profile = String::new();
        for (label, edit, expected) in [
            ("initial", None, "one;false;a;header_one"),
            ("unchanged", None, "one;false;a;header_one"),
            ("changed-read", Some(("direct", "two")), "two;false;a;header_one"),
            ("absent-created", Some(("optional", "")), "two;true;a;header_one"),
            ("listed-added", Some(("members/b", "")), "two;true;a,b;header_one"),
            (
                "child-header",
                Some(("external.h", "#define VALUE header_two\n")),
                "two;true;a,b;header_two",
            ),
        ] {
            if let Some((file, value)) = edit {
                fs::write(inputs.join(file), value)?;
            }
            let row = self.build(label, native)?;
            let out = row["out_dir"].as_str().ok_or("no out_dir in script result")?;
            let actual = fs::read_to_string(Path::new(out).join("answer"))?;
            let now = fs::read_to_string(Path::new(out).join("run-profile"))?;
            if (label == "unchanged") != (now == profile) {
                return Err(format!("{label}: wrong cache decision (compared run-local profile IDs)").into());
            }
            profile = now;
            if actual != expected {
                return Err(format!("{label}: expected {expected}, got {actual}").into());
            }
            println!("{label}: {actual}");
        }
        // A newly resolved PATH tool changes the key even with identical declarations,
        // env and grants. The sentinel is never executed and receives no read grant.
        let bindir = self.root.join("bin");
        fs::create_dir(&bindir)?;
        let path = self.env.iter().find(|(n, _)| n.eq_ignore_ascii_case("PATH")).map(|(_, v)| v.clone()).ok_or("no PATH")?;
        self.env.retain(|n, _| !n.eq_ignore_ascii_case("PATH"));
        self.env.insert("PATH".into(), format!("{};{path}", bindir.display()));
        let stamp = |matrix: &Self, label| -> Result<String> {
            let row = matrix.build(label, native)?;
            Ok(fs::read_to_string(Path::new(row["out_dir"].as_str().ok_or("missing OUT_DIR")?).join("run-profile"))?)
        };
        let before = stamp(self, "tool-absent")?;
        fs::write(bindir.join("zig.exe"), b"stamp only")?;
        let after = stamp(self, "tool-added")?;
        if before == after || after != stamp(self, "tool-warm")? {return Err("tool identity did not invalidate exactly once".into());}
        for (label, value, cfg) in [
            ("env-first", "one", "first_value"),
            ("env-changed", "two", "second_value"),
            ("env-warm", "two", "second_value"),
        ] {
            self.env.insert("CARGO_KEYSPELLING".into(), value.into());
            let row = self.build(label, env_only)?;
            let now = fs::read_to_string(Path::new(row["out_dir"].as_str().ok_or("missing OUT_DIR")?).join("run-profile"))?;
            if (label == "env-warm") != (now == profile) { return Err(format!("{label}: wrong cache decision").into()); }
            profile = now;
            if row["cfgs"] != serde_json::json!([cfg]) {
                return Err(format!("{label}: expected {cfg}, got {}", row["cfgs"]).into());
            }
            println!("{label}: {cfg}");
        }
        // No env changes between the builds of each fixture. Only cl.exe opens the
        // header. Exercise both Cargo rules and deliberately pin the declared-only limit.
        for (name, directive, after) in [
            ("default-header", "", "two"),
            ("declared-header", "println!(\"cargo:rerun-if-changed=include/h.h\");", "two"),
            ("declared-directory", "println!(\"cargo:rerun-if-changed=include\");", "two"),
            ("undeclared-header", "println!(\"cargo:rerun-if-changed=unit.c\");", "one"),
        ] {
            let script = format!(
                r#"fn main() {{
                {directive}
                let cc = std::process::Command::new("cl.exe").args(["/nologo", "/EP", "/TC", "unit.c"]).output().unwrap();
                assert!(cc.status.success());
                println!("cargo:rustc-cfg={{}}", String::from_utf8(cc.stdout).unwrap().trim());
            }}"#
            );
            package(&self.root, name, &script)?;
            let dir = self.root.join(name);
            fs::create_dir(dir.join("include"))?;
            fs::write(dir.join("unit.c"), "#include \"include/h.h\"\nVALUE\n")?;
            for (value, expected) in [("one", "one"), ("two", after)] {
                fs::write(dir.join("include/h.h"), format!("#define VALUE {value}\n"))?;
                let label = format!("{name}-{value}");
                let row = self.build(&label, name)?;
                if row["cfgs"] != serde_json::json!([expected]) {
                    return Err(format!("{label}: expected {expected}, got {}", row["cfgs"]).into());
                }
                println!("{label}: {expected}");
            }
        }
        Ok(())
    }
}

fn main() -> Result<()> {
    if !cfg!(windows) {
        return Err("windows_script_inputs needs a Windows MSVC host".into());
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [arg] = &args[..] else { return Err("windows_script_inputs: one JSON input".into()) };
    let ask: Ask = serde_json::from_value(blaze_script::input::read(arg).map_err(|e| e.0)?)?;
    let root = std::path::absolute(ask.work)?;
    let blaze = std::path::absolute(ask.blaze)?
        .into_os_string()
        .into_string()
        .map_err(|_| "non-text engine path")?;
    let mut env: Env = std::env::vars().collect();
    for (name, path) in [
        ("BLAZE_HOME", root.join("home")),
        ("BLAZE_LIBRARY", std::path::absolute(ask.library)?),
        ("BLAZE_SCRIPT_READ", root.join("inputs")),
    ] {
        env.insert(
            name.into(),
            path.into_os_string().into_string().map_err(|_| format!("non-text {name}"))?,
        );
    }
    env.insert("BLAZE_CORES".into(), "2".into());
    env.insert("CARGO_BUILD_JOBS".into(), "2".into());
    fs::create_dir(&root)?; // Never adopt or empty an existing run's directory.
    let mut matrix = Matrix { root, blaze, env };
    let result = matrix.check();
    engine::run(
        "stop",
        &engine::argv(&[matrix.blaze.as_str(), "stop"]),
        &matrix.root,
        &matrix.env,
        60.,
        true,
    )
    .map_err(|e| e.said().to_owned())?;
    result
}
