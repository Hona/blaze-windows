#!/usr/bin/env bash
# Cross-platform batch gate runner for GitHub-hosted Linux (x86-64) and macOS (arm64) runners.
# Runs the unit suites of crates touched by the Windows port (continuing past failures) and a
# hello-world check/build/run/test/noop/edit smoke under the freshly built blaze binary.
# Copied to $RUNNER_TEMP before optional `git checkout --detach <control>` so control and branch
# runs execute the exact same script.
set -uo pipefail

CORE_CRATES=(
  blaze-core
  blaze-mem
  blaze-cas
  blaze-vfs
  blaze-link
  blaze-usercode
  blaze-build-script
  blaze-units
  blaze-client
  blaze-thin
  blaze-profile
  blaze-gc
  blaze-graph
  blaze-query
  blaze-macro-eval
  blaze-manifest
  blaze-remote
  blaze-testsel
  blaze-codegen
  blaze-lower
  blaze-items
  blaze-item-hash
  base-db
  stdx
  parser
  syntax
  syntax-bridge
  hir-expand
  proc-macro-api
  hir-def
  hir-ty
  hir-ty-pure
  hir-ty-borrowck
  hir-ty-mir
  blaze-api
  blaze-report
  blaze-tree
  blaze-registry
  astlog-core:test=rules
)

LLVM_CRATES=(
  hir-ty-codegen:lib:llvm
  blaze-cargo
)

# Run a command with a wall-clock timeout, killing the entire process group on expiry.
# Prints elapsed seconds to stdout and writes combined output to $log_file.
run_bounded() {
  local timeout_s="$1"
  local log_file="$2"
  local cwd="$3"
  shift 3
  python3 - "$timeout_s" "$log_file" "$cwd" "$@" <<'PY'
import os, signal, subprocess, sys, time

timeout_s = int(sys.argv[1])
log_file = sys.argv[2]
cwd = sys.argv[3]
cmd = sys.argv[4:]

start = time.monotonic()
with open(log_file, "wb") as out:
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=out,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    timed_out = False
    try:
        rc = proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except OSError:
            pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            proc.wait()
        rc = 124
elapsed = time.monotonic() - start
print(f"{rc} {elapsed:.1f} {'1' if timed_out else '0'}")
PY
}

# Parse libtest output into counts and failure messages.
parse_unit_log() {
  local label="$1"
  local rc="$2"
  local timed_out="$3"
  local log_file="$4"
  local fail_md="$5"
  local fail_list="$6"
  python3 - "$label" "$rc" "$timed_out" "$log_file" "$fail_md" "$fail_list" <<'PY'
import re, sys

label, rc, timed_out, log_file, fail_md, fail_list = (
    sys.argv[1], int(sys.argv[2]), sys.argv[3] == "1", sys.argv[4], sys.argv[5], sys.argv[6]
)
text = open(log_file, "r", encoding="utf-8", errors="replace").read()
ansi = re.compile(r"\x1b\[[0-9;]*m")
lines = [ansi.sub("", ln) for ln in text.splitlines()]

passed = failed = ignored = 0
failed_names = []
test_re = re.compile(r"^test (\S+)(?: - .*)? \.\.\. (ok|FAILED|ignored)")
for ln in lines:
    m = test_re.match(ln)
    if m:
        name, state = m.group(1), m.group(2)
        if state == "ok":
            passed += 1
        elif state == "FAILED":
            failed += 1
            failed_names.append(name)
        elif state == "ignored":
            ignored += 1

# Extract per-test stdout/panic messages from libtest's `failures:` blocks.
blocks = {}
in_failures = False
current = None
buf = []
hdr_re = re.compile(r"^---- (\S+) stdout ----$")
for ln in lines:
    if ln == "failures:":
        if current and buf:
            blocks[current] = buf[:]
            current, buf = None, []
        in_failures = True
        continue
    if in_failures:
        m = hdr_re.match(ln)
        if m:
            if current and buf:
                blocks[current] = buf[:]
            current = m.group(1)
            buf = []
        elif ln.startswith("test result:"):
            if current and buf:
                blocks[current] = buf[:]
            current, buf = None, []
            in_failures = False
        elif current is not None:
            buf.append(ln)
if current and buf:
    blocks[current] = buf[:]

total = passed + failed + ignored
if timed_out:
    status = "TIMEOUT"
elif failed > 0:
    status = "FAIL"
elif rc != 0:
    status = "CRASH"
elif total == 0:
    status = "EMPTY"
else:
    status = "ok"

with open(fail_list, "a", encoding="utf-8") as fl:
    for name in failed_names:
        fl.write(f"{label}::{name}\n")
    if status in ("TIMEOUT", "CRASH", "EMPTY"):
        fl.write(f"{label}::* ({status}, exit {rc})\n")

if status != "ok":
    with open(fail_md, "a", encoding="utf-8") as fm:
        fm.write(f"#### `{label}` ({status}, exit {rc}, {passed} passed, {failed} failed, {ignored} ignored)\n\n")
        if failed_names:
            for name in failed_names[:40]:
                fm.write(f"- **`{name}`**\n")
                excerpt = [l for l in blocks.get(name, []) if l.strip()]
                if excerpt:
                    shown = excerpt[:12]
                    fm.write("  ```text\n")
                    for l in shown:
                        fm.write(f"  {l[:240]}\n")
                    if len(excerpt) > 12:
                        fm.write(f"  ... ({len(excerpt) - 12} more lines in logs/{label}.log)\n")
                    fm.write("  ```\n")
            if len(failed_names) > 40:
                fm.write(f"- ... and {len(failed_names) - 40} more failures (see `logs/{label}.log`)\n")
        else:
            tail = [l for l in lines if l.strip()][-25:]
            fm.write("```text\n")
            for l in tail:
                fm.write(f"{l[:240]}\n")
            fm.write("```\n")
        fm.write("\n")

print(f"{status}\t{passed}\t{failed}\t{ignored}")
PY
}

cmd_units() {
  local group="$1"
  local out_dir="$2"
  local default_threads="$3"
  local crates_override="${4:-}"
  local profile="${5:-dev}"

  mkdir -p "$out_dir/logs" "$out_dir/meta"
  local results="$out_dir/results.tsv"
  local fail_md="$out_dir/failures.md"
  local fail_list="$out_dir/failed-tests.txt"
  local summary_md="$out_dir/summary.md"

  printf "crate\tstatus\tpassed\tfailed\tignored\tduration_s\n" > "$results"
  : > "$fail_md"
  : > "$fail_list"

  local -a specs=()
  if [[ -n "$crates_override" ]]; then
    read -r -a specs <<< "$crates_override"
  elif [[ "$group" == "core" ]]; then
    specs=("${CORE_CRATES[@]}")
  elif [[ "$group" == "llvm" ]]; then
    specs=("${LLVM_CRATES[@]}")
  else
    echo "unknown unit group: $group" >&2
    exit 2
  fi

  local any_fail=0
  local rev
  rev="$(git rev-parse --short HEAD)"

  for spec in "${specs[@]}"; do
    local crate target features label
    IFS=':' read -r crate target features <<< "$spec"
    target="${target:-lib}"
    features="${features:-}"
    label="$crate"
    if [[ "$target" != "lib" ]]; then
      label="${crate}_${target#test=}"
    fi

    local -a cargo_args=(test --locked -p "$crate")
    if [[ "$profile" == "release" ]]; then
      cargo_args+=(--release)
    fi
    if [[ "$target" == "lib" ]]; then
      cargo_args+=(--lib)
    elif [[ "$target" == test=* ]]; then
      cargo_args+=(--test "${target#test=}")
    else
      cargo_args+=(--"$target")
    fi
    if [[ -n "$features" ]]; then
      cargo_args+=(--features "$features")
    fi

    echo "::group::[$label] build"
    local build_json="$out_dir/meta/${label}.jsonl"
    local build_log="$out_dir/logs/${label}.build.log"
    local build_start build_end build_dur build_rc
    build_start=$(date +%s)
    cargo "${cargo_args[@]}" --no-run --message-format=json-render-diagnostics > "$build_json" 2> "$build_log"
    build_rc=$?
    build_end=$(date +%s)
    build_dur=$((build_end - build_start))
    if [[ "$build_rc" -ne 0 ]]; then
      tail -n 60 "$build_log"
      echo "::endgroup::"
      printf "%s\tBUILD_FAIL\t0\t0\t0\t%s\n" "$label" "$build_dur" >> "$results"
      printf "%s::* (BUILD_FAIL, exit %s)\n" "$label" "$build_rc" >> "$fail_list"
      {
        echo "#### \`$label\` (BUILD_FAIL, exit $build_rc, ${build_dur}s)"
        echo ""
        echo '```text'
        tail -n 45 "$build_log"
        echo '```'
        echo ""
      } >> "$fail_md"
      any_fail=1
      continue
    fi
    echo "built $label in ${build_dur}s"
    echo "::endgroup::"

    local -a built_bins=()
    while IFS= read -r exe; do
      [[ -n "$exe" ]] && built_bins+=("$exe")
    done < <(python3 - "$build_json" <<'PY'
import json, sys
for line in open(sys.argv[1], "r", encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        continue
    if obj.get("reason") == "compiler-artifact" and obj.get("profile", {}).get("test") and obj.get("executable"):
        print(obj["executable"])
PY
)

    local threads="$default_threads"
    local timeout_s=600
    case "$crate" in
      blaze-cargo|hir-ty-codegen)
        threads=1
        timeout_s=900
        ;;
      blaze-cas|blaze-core|blaze-mem)
        threads=1
        timeout_s=600
        ;;
      hir-ty-mir|hir-def)
        timeout_s=900
        ;;
    esac

    echo "::group::[$label] run (--test-threads=$threads, timeout=${timeout_s}s)"
    local run_log="$out_dir/logs/${label}.log"
    local run_info run_rc run_dur timed_out
    run_info="$(run_bounded "$timeout_s" "$run_log" "$PWD" cargo "${cargo_args[@]}" --no-fail-fast -- --test-threads="$threads")"
    read -r run_rc run_dur timed_out <<< "$run_info"

    # Reclaim test executable disk space immediately so hosted runners never fill up.
    for exe in "${built_bins[@]}"; do
      rm -rf "$exe" "${exe}.dSYM" 2>/dev/null || true
    done

    local parsed status passed failed ignored
    parsed="$(parse_unit_log "$label" "$run_rc" "$timed_out" "$run_log" "$fail_md" "$fail_list")"
    IFS=$'\t' read -r status passed failed ignored <<< "$parsed"
    local total_dur
    total_dur="$(python3 -c "print(f'{${build_dur} + ${run_dur}:.1f}')")"
    printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$label" "$status" "$passed" "$failed" "$ignored" "$total_dur" >> "$results"
    echo "$label: $status ($passed passed, $failed failed, $ignored ignored, build ${build_dur}s + run ${run_dur}s)"
    if [[ "$status" != "ok" ]]; then
      grep -E '^test .* \.\.\. FAILED$|^test result:' "$run_log" | head -n 60 || true
      any_fail=1
    fi
    echo "::endgroup::"
  done

  {
    echo "### Cross-platform units: \`${PLATFORM:-unknown}\` / \`$group\` (\`$rev\`, mode \`${XPLAT_MODE:-branch}\`)"
    echo ""
    echo "| Crate | Status | Passed | Failed | Ignored | Time (s) |"
    echo "|---|---|---:|---:|---:|---:|"
    tail -n +2 "$results" | while IFS=$'\t' read -r c st p f i d; do
      echo "| \`$c\` | $st | $p | $f | $i | $d |"
    done
    echo ""
    if [[ -s "$fail_md" ]]; then
      echo "#### Failing tests (\`${PLATFORM:-unknown}\` / \`$group\`)"
      echo ""
      cat "$fail_md"
    fi
  } > "$summary_md"

  cat "$summary_md"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    cat "$summary_md" >> "$GITHUB_STEP_SUMMARY"
  fi
  return "$any_fail"
}

cmd_hello() {
  local blaze_bin="$1"
  local out_dir="$2"

  mkdir -p "$out_dir/logs" "$out_dir/work/hello/src" "$out_dir/work/home"
  local hello_dir="$out_dir/work/hello"
  export BLAZE_HOME="$out_dir/work/home"
  export BLAZE_CORES=all
  export RUST_BACKTRACE=0

  cat > "$hello_dir/Cargo.toml" <<'TOML'
[package]
name = "hello"
version = "0.1.0"
edition = "2024"
TOML

  cat > "$hello_dir/src/main.rs" <<'RS'
fn greeting() -> &'static str {
    "hello from blaze"
}

fn main() {
    println!("{}", greeting());
}

#[test]
fn it_greets() {
    assert!(greeting().starts_with("hello"));
}
RS

  local results="$out_dir/hello-results.tsv"
  local fail_md="$out_dir/hello-failures.md"
  local summary_md="$out_dir/hello-summary.md"
  printf "step\tstatus\texit\tduration_s\tnote\n" > "$results"
  : > "$fail_md"

  local any_fail=0
  local rev
  rev="$(git rev-parse --short HEAD)"

  run_step() {
    local step="$1"
    local timeout_s="$2"
    local expect="$3"
    shift 3
    local log="$out_dir/logs/hello-${step}.log"
    echo "::group::[hello/$step] $*"
    local info rc dur timed_out
    info="$(run_bounded "$timeout_s" "$log" "$hello_dir" "$@")"
    read -r rc dur timed_out <<< "$info"
    local st="ok"
    local note=""
    if [[ "$timed_out" == "1" ]]; then
      st="TIMEOUT"
      note="exceeded ${timeout_s}s"
    elif [[ "$rc" -ne 0 ]]; then
      st="FAIL"
      note="exit $rc"
    elif [[ -n "$expect" ]] && ! grep -Fq "$expect" "$log"; then
      st="FAIL"
      note="missing expected output: $expect"
    fi
    cat "$log" | tail -n 60
    echo "::endgroup::"
    printf "%s\t%s\t%s\t%s\t%s\n" "$step" "$st" "$rc" "$dur" "$note" >> "$results"
    if [[ "$st" != "ok" ]]; then
      any_fail=1
      {
        echo "#### \`hello/$step\` ($st, exit $rc, ${dur}s${note:+, $note})"
        echo ""
        echo '```text'
        tail -n 45 "$log"
        echo '```'
        echo ""
      } >> "$fail_md"
    fi
  }

  run_step "version"    60  "blaze"            "$blaze_bin" --version
  run_step "toolchain"  600 ""                 "$blaze_bin" toolchain
  run_step "lock"       120 ""                 "$blaze_bin" lock
  run_step "check"      600 ""                 "$blaze_bin" check
  run_step "build"      900 ""                 "$blaze_bin" build
  run_step "run"        300 "hello from blaze" "$blaze_bin" run -q
  run_step "test"       600 "test result: ok"  "$blaze_bin" test
  run_step "noop"       300 ""                 "$blaze_bin" build

  python3 - "$hello_dir/src/main.rs" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
p.write_text(p.read_text().replace('"hello from blaze"', '"hello from blaze, edited"'))
PY

  run_step "edit-build" 300 ""                         "$blaze_bin" build
  run_step "edit-run"   300 "hello from blaze, edited" "$blaze_bin" run -q
  run_step "stop"       60  ""                         "$blaze_bin" stop

  # Preserve any daemon logs for diagnosis.
  find "$BLAZE_HOME" -maxdepth 4 \( -name 'serve.log' -o -name 'daemon.log' -o -name 'log' \) -type f 2>/dev/null | while IFS= read -r f; do
    local safe
    safe="$(echo "${f#"$BLAZE_HOME"/}" | tr '/' '_')"
    cp -p "$f" "$out_dir/logs/daemon-${safe}" 2>/dev/null || true
  done

  {
    echo "### Cross-platform hello-world: \`${PLATFORM:-unknown}\` (\`$rev\`, mode \`${XPLAT_MODE:-branch}\`)"
    echo ""
    echo "| Step | Status | Exit | Time (s) | Note |"
    echo "|---|---|---:|---:|---|"
    tail -n +2 "$results" | while IFS=$'\t' read -r s st rc d n; do
      echo "| \`$s\` | $st | $rc | $d | $n |"
    done
    echo ""
    if [[ -s "$fail_md" ]]; then
      echo "#### Hello-world failures (\`${PLATFORM:-unknown}\`)"
      echo ""
      cat "$fail_md"
    fi
  } > "$summary_md"

  cat "$summary_md"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    cat "$summary_md" >> "$GITHUB_STEP_SUMMARY"
  fi
  return "$any_fail"
}

cmd_summary() {
  local root="$1"
  python3 - "$root" <<'PY'
import glob, os, sys

root = sys.argv[1]
platforms = ["linux-x64", "macos-arm64"]

unit_rows = {}  # crate -> {platform: (status, passed, failed, ignored, dur)}
crates_order = []
for plat in platforms:
    for path in sorted(glob.glob(os.path.join(root, f"xplat-units-{plat}-*", "results.tsv"))):
        for ln in open(path, "r", encoding="utf-8").read().splitlines()[1:]:
            parts = ln.split("\t")
            if len(parts) < 6:
                continue
            crate = parts[0]
            if crate not in unit_rows:
                unit_rows[crate] = {}
                crates_order.append(crate)
            unit_rows[crate][plat] = tuple(parts[1:6])

hello_rows = {}  # step -> {platform: (status, rc, dur, note)}
steps_order = []
for plat in platforms:
    for path in sorted(glob.glob(os.path.join(root, f"xplat-engine-{plat}", "hello-results.tsv"))):
        for ln in open(path, "r", encoding="utf-8").read().splitlines()[1:]:
            parts = ln.split("\t")
            if len(parts) < 5:
                continue
            step = parts[0]
            if step not in hello_rows:
                hello_rows[step] = {}
                steps_order.append(step)
            hello_rows[step][plat] = tuple(parts[1:5])

    # Also include blaze-engine unit tests from the engine job if present.
    for path in sorted(glob.glob(os.path.join(root, f"xplat-engine-{plat}", "engine-units", "results.tsv"))):
        for ln in open(path, "r", encoding="utf-8").read().splitlines()[1:]:
            parts = ln.split("\t")
            if len(parts) < 6:
                continue
            crate = parts[0]
            if crate not in unit_rows:
                unit_rows[crate] = {}
                crates_order.append(crate)
            unit_rows[crate][plat] = tuple(parts[1:6])

print(f"## Cross-platform gate summary (`{os.environ.get('XPLAT_MODE', 'branch')}`, target `{os.environ.get('XPLAT_REV', 'HEAD')}`)\n")

def fmt_unit(cell):
    if not cell:
        return "not run"
    st, p, f, i, d = cell
    return f"{st} ({p} ok / {f} fail / {i} ign, {d}s)"

if crates_order:
    print("### Unit suites (crates touched by the Windows port)\n")
    print("| Crate | Linux x86-64 (`ubuntu-latest`) | macOS arm64 (`macos-latest`) |")
    print("|---|---|---|")
    for c in crates_order:
        print(f"| `{c}` | {fmt_unit(unit_rows[c].get('linux-x64'))} | {fmt_unit(unit_rows[c].get('macos-arm64'))} |")
    print()

def fmt_hello(cell):
    if not cell:
        return "not run"
    st, rc, d, note = cell
    extra = f" — {note}" if note else ""
    return f"{st} ({d}s{extra})"

if steps_order:
    print("### Hello-world under built `blaze`\n")
    print("| Step | Linux x86-64 (`ubuntu-latest`) | macOS arm64 (`macos-latest`) |")
    print("|---|---|---|")
    for s in steps_order:
        print(f"| `{s}` | {fmt_hello(hello_rows[s].get('linux-x64'))} | {fmt_hello(hello_rows[s].get('macos-arm64'))} |")
    print()

failure_files = sorted(
    glob.glob(os.path.join(root, "**", "failures.md"), recursive=True)
    + glob.glob(os.path.join(root, "**", "hello-failures.md"), recursive=True)
)
non_empty = [f for f in failure_files if os.path.getsize(f) > 0]
if non_empty:
    print("### Failing tests and error excerpts\n")
    for f in non_empty:
        rel = os.path.relpath(f, root)
        print(f"<details><summary>{rel}</summary>\n")
        print(open(f, "r", encoding="utf-8", errors="replace").read())
        print("</details>\n")
else:
    print("### Failing tests\n\nNone.\n")

print("### Not run on GitHub-hosted runners (do not read silence as a pass)\n")
print("- Full `--workspace` self-build via released `blaze` (`blaze-platform.yaml`: requires 64-vCPU / up to 256 GiB `ix` runners; hosted Linux has 16 GB RAM and hosted macOS has 7 GB RAM).")
print("- `blaze check --workspace --all-targets`, `lint-baselines`, and `scripts` gate (`blaze.yaml` `ix` jobs).")
print("- Lean proof gate (`lean` job; requires `elan` + Mathlib cache).")
print("- Release train harnesses (`harness/ci.py`, `smoke.py` full corpus, `blaze_cli.py`, `realprojects`, `debuginfo.py`, `bench`).")
print("- `blaze-diagnostics` full suite (~4,000 tests; excluded from cheap hosted gate for runner time — only 14 lines of borrowck fixture tests changed).")
print("- Linux AArch64 native (`ubuntu-24.04-arm` / `ix` arm64) and Linux 6.8 `io_uring` buffer-ring check (`linux-6-8`).")
PY
}

case "${1:-}" in
  units)
    shift
    cmd_units "$@"
    ;;
  hello)
    shift
    cmd_hello "$@"
    ;;
  summary)
    shift
    cmd_summary "$@"
    ;;
  *)
    echo "usage: $0 {units|hello|summary} ..." >&2
    exit 2
    ;;
esac
