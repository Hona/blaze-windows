//! Links what a `link.exe` line names with blaze's linker, and times each step: the line rustc
//! wrote for a Windows program (`-C save-temps` keeps it as `linker-arguments`, or
//! `--print link-args` prints it), as a benchmark against link.exe and lld-link on the same
//! inputs.
//!
//! `cargo run --release -p blaze-link --example pe_relink -- <linker-arguments> <out.exe> [runs]`
//!
//! The line's objects, `.rlib`s and `.lib`s are its inputs in order; its options are read as
//! link.exe's ([`blaze_link::args`]); the C runtime and SDK libraries are found as a build finds
//! them ([`blaze_link::target::locate`], `LIB` when set). Each run links from scratch, as a first
//! link does: no image is kept between runs.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use blaze_codegen::{NativeLib, NativeLibKind};
use blaze_link::args::{ArgFrom, GivenArg};
use blaze_link::target::CrateLibs;
use blaze_link::{Change, Debug, Image, Native};

/// The words of a response file: whitespace-separated, `"..."` quoted with `\"` and `\\` inside.
fn words(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let (mut quoted, mut any) = (false, false);
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            '\\' if quoted && matches!(chars.peek(), Some('"' | '\\')) => word.push(chars.next().unwrap()),
            c if c.is_whitespace() && !quoted => {
                if any || !word.is_empty() {
                    out.push(std::mem::take(&mut word));
                }
                any = false;
            }
            c => word.push(c),
        }
    }
    if any || !word.is_empty() {
        out.push(word);
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (Some(line), Some(out)) = (args.get(1), args.get(2)) else {
        eprintln!("usage: pe_relink <linker-arguments> <out.exe> [runs]");
        std::process::exit(2);
    };
    let runs: usize = args.get(3).map_or(1, |it| it.parse().expect("runs"));
    let text = std::fs::read(line).expect("the line");
    // rustc writes the file UTF-16 with a BOM for link.exe.
    let text = if text.starts_with(&[0xff, 0xfe]) {
        let units: Vec<u16> = text[2..].chunks_exact(2).map(|it| u16::from_le_bytes([it[0], it[1]])).collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(&text).into_owned()
    };
    let mut words = words(&text);
    if words.first().is_some_and(|it| it.to_ascii_lowercase().ends_with("link.exe")) {
        words.remove(0);
    }
    let mut given = Vec::new();
    let mut libs = Vec::new();
    for word in words {
        let lower = word.to_ascii_lowercase();
        if lower.starts_with("/out:") {
            continue;
        }
        if lower.ends_with(".rlib") {
            libs.push(NativeLib {
                name: word,
                kind: NativeLibKind::Static { whole: false, bundle: false },
                verbatim: true,
                imports: Vec::new(),
            });
            continue;
        }
        given.push(GivenArg { arg: word, from: ArgFrom::Rustflags });
    }
    for run in 0..runs {
        let started = Instant::now();
        let mut output = blaze_link::target::output("x86_64-pc-windows-msvc", None, Debug::None, false)
            .expect("the output");
        // rustc names the static VC runtime (`/defaultlib:libcmt`) on a `+crt-static` line.
        output.link.pe.crt_static =
            given.iter().any(|it| it.arg.eq_ignore_ascii_case("/defaultlib:libcmt"));
        let applied = blaze_link::args::apply(&mut output, &[], &given).unwrap_or_else(|e| panic!("{e}"));
        let mut all = libs.clone();
        all.extend(applied.libs);
        let crates = [CrateLibs { libs: &all, search: &[] }];
        let located = blaze_link::target::locate(&mut output, &crates, &applied.search, Path::new("unused"))
            .unwrap_or_else(|e| panic!("{e}"));
        let located_at = started.elapsed();
        let read: Vec<(String, Arc<[u8]>, blaze_link::NativeKind, blaze_ids::ContentId)> = located
            .into_iter()
            .map(|it| match it.made {
                Some((id, bytes)) => (it.name, bytes, it.kind, id),
                None => {
                    let bytes: Arc<[u8]> = std::fs::read(&it.path).unwrap_or_else(|e| panic!("{}: {e}", it.name)).into();
                    let id = blaze_ids::ContentId::of("pe_relink", &bytes);
                    (it.name, bytes, it.kind, id)
                }
            })
            .collect();
        let bytes_in: usize = read.iter().map(|it| it.1.len()).sum();
        let read_at = started.elapsed();
        let natives = read
            .iter()
            .enumerate()
            .map(|(at, (name, bytes, kind, id))| Native { id: *id, name, bytes, kind: *kind, order: at as u32 })
            .collect();
        let mut image = Image::new(blaze_core::FileName::new("bench/out.exe").unwrap(), output).expect("the image");
        let staged = image.stage(Change { natives, ..Change::default() }).unwrap_or_else(|e| panic!("{e}"));
        let staged_at = started.elapsed();
        let file = image.bytes(staged).unwrap_or_else(|e| panic!("{e}"));
        let made_at = started.elapsed();
        std::fs::write(PathBuf::from(out), &file).expect("the output file");
        let written_at = started.elapsed();
        println!(
            "run {run}: {} inputs, {:.0} MB read; locate {:.3} s, read {:.3} s, stage {:.3} s, bytes {:.3} s, write {:.3} s; total {:.3} s; {:.1} MB out",
            read.len(),
            bytes_in as f64 / 1e6,
            located_at.as_secs_f64(),
            (read_at - located_at).as_secs_f64(),
            (staged_at - read_at).as_secs_f64(),
            (made_at - staged_at).as_secs_f64(),
            (written_at - made_at).as_secs_f64(),
            written_at.as_secs_f64(),
            file.len() as f64 / 1e6,
        );
    }
}
