"""Check build-script results against real, undeclared inputs on Windows (including cl.exe).

Pass one JSON object with `blaze` (the engine), `library` (its std), and `work` (a new
directory on the test volume). Keep the home, output, and per-build logs there. The test
asserts results, not a particular observer: an incomplete observation must cause a rerun.
"""

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools/typed-input/src"))
from typed_input import parse


@dataclass(frozen=True)
class Ask:
    blaze: str
    library: str
    work: str


SCRIPT = r'''
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
}
'''

ENV_SCRIPT = '''
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var_os("CARGO_KeySpelling").unwrap() == "one" {
        println!("cargo:rustc-cfg=first_value");
    } else {
        println!("cargo:rustc-cfg=second_value");
    }
}
'''


def main(ask: Ask) -> None:
    if os.name != "nt":
        raise SystemExit("windows_script_inputs needs a Windows MSVC host")
    blaze = Path(ask.blaze).resolve(strict=True)
    library = Path(ask.library).resolve(strict=True)
    root = Path(ask.work).resolve()
    root.mkdir()  # Refuse an old result or another run's home.
    project, inputs = root / "project", root / "inputs"
    (project / "src").mkdir(parents=True)
    (inputs / "members").mkdir(parents=True)
    (project / "Cargo.toml").write_text('[package]\nname="observer-fixture"\nversion="0.1.0"\nedition="2021"\n')
    (project / "src/lib.rs").write_text("pub const N: u32 = 1;\n")
    (project / "build.rs").write_text(SCRIPT)
    (inputs / "unit.c").write_text('#include "external.h"\nVALUE\n')
    (inputs / "external.h").write_text("#define VALUE header_one\n")
    (inputs / "direct").write_text("one")
    (inputs / "members/a").touch()
    env = os.environ | dict(BLAZE_HOME=str(root / "home"), BLAZE_LIBRARY=str(library),
                            BLAZE_SCRIPT_READ=str(inputs), BLAZE_CORES="2", CARGO_BUILD_JOBS="2")

    def run(label: str) -> dict:
        p = subprocess.run([blaze, "build", "-j2", "--message-format=json"], cwd=project,
                           env=env, capture_output=True, timeout=1200)
        (root / f"{label}.jsonl").write_bytes(p.stdout)
        (root / f"{label}.log").write_bytes(p.stderr)
        if p.returncode:
            raise RuntimeError(f"{label}: blaze exited {p.returncode}; see {root / (label + '.log')}")
        rows = (json.loads(line) for line in p.stdout.splitlines())
        script, = (row for row in rows if row.get("reason") == "build-script-executed"
                   and "#observer-fixture@" in row["package_id"])
        return script

    def build(label: str, expected: str) -> None:
        actual = (Path(run(label)["out_dir"]) / "answer").read_text()
        if actual != expected:
            raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")
        print(f"{label}: {actual}", flush=True)

    try:
        build("initial", "one;false;a;header_one")
        build("unchanged", "one;false;a;header_one")
        (inputs / "direct").write_text("two")
        build("changed-read", "two;false;a;header_one")
        (inputs / "optional").touch()
        build("absent-created", "two;true;a;header_one")
        (inputs / "members/b").touch()
        build("listed-added", "two;true;a,b;header_one")
        (inputs / "external.h").write_text("#define VALUE header_two\n")
        build("child-header", "two;true;a,b;header_two")
        (project / "build.rs").write_text(ENV_SCRIPT)
        for label, value, cfg in [("env-first", "one", "first_value"),
                                  ("env-changed", "two", "second_value"),
                                  ("env-warm", "two", "second_value")]:
            env["CARGO_KEYSPELLING"] = value
            actual = run(label)["cfgs"]
            if actual != [cfg]:
                raise AssertionError(f"{label}: expected {cfg}, got {actual!r}")
            print(f"{label}: {cfg}", flush=True)
    finally:
        subprocess.run([blaze, "stop"], cwd=project, env=env, timeout=60, check=True)


if __name__ == "__main__":
    main(parse(Ask, sys.argv[1], "windows_script_inputs.py"))
