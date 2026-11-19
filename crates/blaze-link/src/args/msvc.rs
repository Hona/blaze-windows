//! link.exe's spelling of link arguments: `/NAME[:value]` or `-NAME[:value]`, the name in any
//! case, and bare input files (`delayimp.lib`, `resource.res`, `extra.obj`). Each word is one
//! option: link.exe takes no value from the next word.
//!
//! What build scripts give (winresource's `.res`, tauri-build's `resource.lib`, rune-desktop's
//! `/SUBSYSTEM:WINDOWS`, `/ENTRY:mainCRTStartup`, `/DELAYLOAD:*.dll` with `delayimp.lib`) and
//! what rustc itself passes link.exe are read into [`LinkOption`]s. An option that asks
//! something blaze's PE writer does not do is refused by name.

use std::path::PathBuf;

use blaze_codegen::NativeLibKind;

use super::{Kind, LinkOption, Read, Word, lib, why};
use crate::output::PeFlag;

/// Why each refused link.exe option is, after the option.
mod why_msvc {
    pub(super) const SUBSYSTEM: &str = "blaze links the WINDOWS and CONSOLE subsystems only, each \
                                        with an optional `major[.minor]` version";
    pub(super) const NUMBER: &str = "not a number as link.exe reads one (decimal, or hexadecimal \
                                     after `0x`)";
    pub(super) const VERSION: &str = "not a `major[.minor]` version";
    pub(super) const MACHINE: &str = "blaze links PE for x64 only";
    pub(super) const BASE: &str = "an image base must be a multiple of 64 KiB, as the loader maps \
                                   images on its allocation granularity";
    pub(super) const WHOLE: &str = "a bare `/WHOLEARCHIVE` (every library whole), which blaze's \
                                    linker does not implement; name the library \
                                    (`/WHOLEARCHIVE:foo.lib`)";
    pub(super) const OUTPUT: &str = "blaze names and kinds the image from the crate it builds (its \
                                     path, `bin`, `cdylib`), not from link arguments";
    pub(super) const IMPLIB: &str = "blaze's linker writes no import library yet";
    pub(super) const EXPORT_EXE: &str = "blaze's linker exports nothing from an executable yet";
    pub(super) const EXPORT_FORM: &str = "an export by ordinal, a forwarder or a renamed export, \
                                          which blaze's linker does not write";
    pub(super) const ENTRY_DLL: &str = "a DLL's entry is the CRT's `_DllMainCRTStartup`, which \
                                        blaze's linker does not change yet";
    pub(super) const MANIFEST: &str = "blaze's linker writes no side-by-side or generated manifest \
                                       yet; embed one with a `.res` (winresource, embed-resource)";
    pub(super) const GUARD: &str = "blaze's linker writes no control-flow guard tables";
    pub(super) const CET: &str = "blaze's linker does not mark images CET-compatible yet";
    pub(super) const LTCG: &str = "blaze links no link-time-code-generation objects";
    pub(super) const MERGE: &str = "blaze's linker merges only `.CRT`, `.rtc` and `.00cfg` into \
                                    `.rdata`";
    pub(super) const RELEASE: &str = "blaze's linker writes no header checksum (only drivers and \
                                      boot images need one)";
    pub(super) const RESPONSE: &str = "a response file, which blaze's linker does not read";
    pub(super) const INPUT: &str = "an input file blaze's linker does not read: it takes .obj, .o, \
                                    .lib, .a and .res files";
}

/// Why each link.exe option taken without a field is.
pub(super) mod reason_msvc {
    pub(in crate::args) const NOLOGO: &str = "blaze's linker prints no banner";
    pub(in crate::args) const MACHINE: &str = "blaze links x64 PE images";
    pub(in crate::args) const GC: &str = "blaze's linker drops every section nothing reachable refers to \
                                 (`/OPT:REF`)";
    pub(in crate::args) const NOREF: &str = "a section nothing reachable refers to is never run nor read, \
                                    and exports and `/INCLUDE`s are reachable";
    pub(in crate::args) const ICF: &str = "folding identical functions is link.exe's choice to make, and \
                                  not folding them is always correct";
    pub(in crate::args) const DEBUG: &str = "the build profile's `debug` decides an image's debug info, as \
                                    rustc passes `/DEBUG` from it";
    pub(in crate::args) const PDB: &str = "the debug info's file is named from the image, as the profile \
                                  asks for it";
    pub(in crate::args) const INCREMENTAL: &str = "blaze's linker is incremental its own way, and keeps no \
                                          link.exe `.ilk`";
    pub(in crate::args) const DYNAMICBASE: &str = "blaze's linker makes every PE image relocatable \
                                          (`/DYNAMICBASE`)";
    pub(in crate::args) const HIGHENTROPYVA: &str = "blaze's linker marks every PE image for 64-bit ASLR \
                                            (`/HIGHENTROPYVA`)";
    pub(in crate::args) const NXCOMPAT: &str = "blaze's linker marks every PE image `/NXCOMPAT`";
    pub(in crate::args) const LARGEADDRESSAWARE: &str = "blaze's linker marks every x64 image \
                                                `/LARGEADDRESSAWARE`";
    pub(in crate::args) const TSAWARE: &str = "blaze's linker marks every executable `/TSAWARE`";
    pub(in crate::args) const MANIFEST_NO: &str = "blaze's linker writes no manifest unless one is embedded \
                                          as a resource";
    pub(in crate::args) const MANIFESTUAC: &str = "it shapes only a manifest link.exe generates \
                                          (`/MANIFEST`), which blaze's linker does not";
    pub(in crate::args) const MESSAGES: &str = "it only shapes link.exe's own messages";
    pub(in crate::args) const SAFESEH: &str = "x64 images have no SafeSEH table: their handlers are in the \
                                      unwind info";
    pub(in crate::args) const NATVIS: &str = "a natvis file goes in the PDB, which a debugger reads it \
                                     from; the image holds nothing of it";
    pub(in crate::args) const MERGE: &str = "blaze's linker lays those into `.rdata` already";
    pub(in crate::args) const LARGE_PAGES: &str = "the loader maps images in 4 KiB pages either way";
    pub(in crate::args) const NO_GUARD: &str = "blaze's linker writes no control-flow guard tables";
    pub(in crate::args) const NO_CET: &str = "blaze's linker does not mark images CET-compatible";
}

/// A link.exe number: decimal, or hexadecimal after `0x`.
fn number(text: &str) -> Result<u64, &'static str> {
    let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse(),
    };
    parsed.map_err(|_| why_msvc::NUMBER)
}

/// `major[.minor]`, as `/SUBSYSTEM` and `/VERSION` take it.
fn version(text: &str) -> Result<(u16, u16), &'static str> {
    let (major, minor) = text.split_once('.').unwrap_or((text, "0"));
    let part = |it: &str| it.parse::<u16>().map_err(|_| why_msvc::VERSION);
    Ok((part(major)?, part(minor)?))
}

/// `reserve[,commit]`, as `/STACK` and `/HEAP` take it.
fn sizes(text: &str) -> Result<(u64, Option<u64>), &'static str> {
    match text.split_once(',') {
        Some((reserve, commit)) => Ok((number(reserve)?, Some(number(commit)?))),
        None => Ok((number(text)?, None)),
    }
}

/// Whether `name` ends in `.extension`, ASCII case ignored.
fn has_extension(name: &str, extension: &str) -> bool {
    std::path::Path::new(name)
        .extension()
        .and_then(|it| it.to_str())
        .is_some_and(|it| it.eq_ignore_ascii_case(extension))
}

/// A library a link.exe option or a bare `.lib` names: verbatim when it has an extension
/// (`delayimp.lib`, `C:\x\resource.lib`), else `name.lib`, as link.exe adds the extension.
fn library(name: &str, whole: bool) -> LinkOption {
    let kind = NativeLibKind::Static { whole, bundle: false };
    lib(name, kind, std::path::Path::new(name).extension().is_some())
}

/// A word in link.exe's spelling.
pub(super) fn read(word: Word<'_>, kind: Kind) -> Read {
    let text = word.text;
    if text.is_empty() {
        return Err(why::EMPTY);
    }
    if text.starts_with('@') {
        return Err(why_msvc::RESPONSE);
    }
    let Some(option) = text.strip_prefix(['/', '-']) else {
        return input(text);
    };
    // A path given with forward slashes (`/C/x/foo.lib` is no link.exe option).
    if option.contains(['\\', '/']) && !option.contains(':') {
        return input(text);
    }
    let (name, value) = match option.split_once(':') {
        Some((name, value)) => (name, Some(value)),
        None => (option, None),
    };
    // The option's name uppercased on the stack: no known one is longer.
    let mut buf = [0u8; 24];
    let Some(key) = buf.get_mut(..name.len()) else { return Err(why::UNKNOWN) };
    key.copy_from_slice(name.as_bytes());
    key.make_ascii_uppercase();
    let key: &[u8] = key;
    let shared = kind == Kind::Shared;
    let need = || value.filter(|it| !it.is_empty()).ok_or(why::NO_VALUE);
    let no = value.is_some_and(|it| it.eq_ignore_ascii_case("NO"));
    let flag = |reason: &'static str, flag: PeFlag| match value {
        None => Ok(LinkOption::Already(reason)),
        Some(_) if no => Ok(LinkOption::PeOff(flag)),
        Some(_) => Err(why::UNKNOWN),
    };
    let option = match key {
        b"NOLOGO" => LinkOption::NoEffect(reason_msvc::NOLOGO),
        b"SUBSYSTEM" => {
            let value = need()?;
            let (system, at) = value.split_once(',').map_or((value, None), |(s, v)| (s, Some(v)));
            let windows = if system.eq_ignore_ascii_case("WINDOWS") {
                true
            } else if system.eq_ignore_ascii_case("CONSOLE") {
                false
            } else {
                return Err(why_msvc::SUBSYSTEM);
            };
            let version = at.map(version).transpose().map_err(|_| why_msvc::SUBSYSTEM)?;
            LinkOption::Subsystem { windows, version }
        }
        b"ENTRY" if shared => return Err(why_msvc::ENTRY_DLL),
        // alloc: the entry the output owns
        b"ENTRY" => LinkOption::Entry(need()?.to_owned()),
        // alloc: the DLL the output owns
        b"DELAYLOAD" => LinkOption::DelayLoad(need()?.to_owned()),
        b"DEFAULTLIB" => library(need()?, false),
        // alloc: the library the output owns
        b"NODEFAULTLIB" => LinkOption::NoDefaultLib(value.filter(|it| !it.is_empty()).map(str::to_owned)),
        b"WHOLEARCHIVE" => match value {
            Some(name) if !name.is_empty() => library(name, true),
            _ => return Err(why_msvc::WHOLE),
        },
        b"LIBPATH" => LinkOption::Search(PathBuf::from(need()?)),
        b"STACK" if shared => return Err(why::EXECUTABLE_ONLY),
        b"STACK" => {
            let (reserve, commit) = sizes(need()?)?;
            return Ok((LinkOption::Stack { reserve, commit }, 0));
        }
        b"HEAP" => {
            let (reserve, commit) = sizes(need()?)?;
            LinkOption::Heap { reserve, commit }
        }
        // alloc: the symbol the output owns
        b"INCLUDE" => LinkOption::Include(need()?.to_owned()),
        b"EXPORT" if !shared => return Err(why_msvc::EXPORT_EXE),
        b"EXPORT" => {
            let value = need()?;
            let (name, rest) = value.split_once(',').map_or((value, ""), |(n, r)| (n, r));
            let plain = !name.contains(['=', '.'])
                && rest.split(',').all(|it| {
                    it.is_empty() || it.eq_ignore_ascii_case("DATA") || it.eq_ignore_ascii_case("PRIVATE")
                });
            if !plain {
                return Err(why_msvc::EXPORT_FORM);
            }
            // alloc: the export the output owns
            LinkOption::Export(name.to_owned())
        }
        b"DEF" if !shared => return Err(why_msvc::EXPORT_EXE),
        b"DEF" => LinkOption::Def(PathBuf::from(need()?)),
        b"BASE" => {
            let base = number(need()?)?;
            if base == 0 || base % 0x1_0000 != 0 {
                return Err(why_msvc::BASE);
            }
            LinkOption::Base(base)
        }
        b"VERSION" => {
            let (major, minor) = version(need()?)?;
            LinkOption::ImageVersion { major, minor }
        }
        b"RELEASE" => return Err(why_msvc::RELEASE),
        b"MACHINE" => match need()? {
            it if it.eq_ignore_ascii_case("X64") || it.eq_ignore_ascii_case("AMD64") => {
                LinkOption::Already(reason_msvc::MACHINE)
            }
            _ => return Err(why_msvc::MACHINE),
        },
        b"OPT" => {
            let mut taken = None;
            for part in need()?.split(',') {
                let upper = part.to_ascii_uppercase();
                taken = Some(match upper.as_str() {
                    "REF" => LinkOption::Already(reason_msvc::GC),
                    "NOREF" => LinkOption::NoEffect(reason_msvc::NOREF),
                    "NOICF" | "LBR" | "NOLBR" => LinkOption::NoEffect(reason_msvc::ICF),
                    _ if upper == "ICF" || upper.starts_with("ICF=") => {
                        LinkOption::NoEffect(reason_msvc::ICF)
                    }
                    _ => return Err(why::UNKNOWN),
                });
            }
            taken.ok_or(why::NO_VALUE)?
        }
        b"DEBUG" => match value.map(str::to_ascii_uppercase).as_deref() {
            None | Some("FULL" | "FASTLINK" | "NONE" | "GHASH" | "NOGHASH") => {
                LinkOption::NoEffect(reason_msvc::DEBUG)
            }
            Some(_) => return Err(why::UNKNOWN),
        },
        b"DEBUGTYPE" | b"PDB" | b"PDBALTPATH" | b"PDBSTRIPPED" => {
            need()?;
            LinkOption::NoEffect(reason_msvc::PDB)
        }
        b"NATVIS" => {
            need()?;
            LinkOption::NoEffect(reason_msvc::NATVIS)
        }
        b"INCREMENTAL" => LinkOption::NoEffect(reason_msvc::INCREMENTAL),
        b"DYNAMICBASE" => flag(reason_msvc::DYNAMICBASE, PeFlag::DynamicBase)?,
        b"HIGHENTROPYVA" => flag(reason_msvc::HIGHENTROPYVA, PeFlag::HighEntropyVa)?,
        b"NXCOMPAT" => flag(reason_msvc::NXCOMPAT, PeFlag::NxCompat)?,
        b"LARGEADDRESSAWARE" => flag(reason_msvc::LARGEADDRESSAWARE, PeFlag::LargeAddressAware)?,
        b"TSAWARE" if shared => return Err(why::EXECUTABLE_ONLY),
        b"TSAWARE" => flag(reason_msvc::TSAWARE, PeFlag::TerminalServerAware)?,
        b"FIXED" if value.is_none() => LinkOption::PeOff(PeFlag::DynamicBase),
        b"FIXED" if no => LinkOption::Already(reason_msvc::DYNAMICBASE),
        b"MANIFEST" if no => LinkOption::NoEffect(reason_msvc::MANIFEST_NO),
        b"MANIFEST" | b"MANIFESTINPUT" | b"MANIFESTFILE" | b"MANIFESTDEPENDENCY" | b"ALLOWISOLATION" => {
            return Err(why_msvc::MANIFEST);
        }
        b"MANIFESTUAC" => LinkOption::NoEffect(reason_msvc::MANIFESTUAC),
        b"SAFESEH" => LinkOption::NoEffect(reason_msvc::SAFESEH),
        b"LARGEPAGES" => LinkOption::NoEffect(reason_msvc::LARGE_PAGES),
        b"WX" | b"IGNORE" | b"VERBOSE" | b"TIME" | b"ERRORREPORT" | b"WARN" => {
            LinkOption::NoEffect(reason_msvc::MESSAGES)
        }
        b"GUARD" if no => LinkOption::Already(reason_msvc::NO_GUARD),
        b"GUARD" => return Err(why_msvc::GUARD),
        b"CETCOMPAT" if no => LinkOption::Already(reason_msvc::NO_CET),
        b"CETCOMPAT" => return Err(why_msvc::CET),
        b"LTCG" => return Err(why_msvc::LTCG),
        b"MERGE" => {
            let merged = need()?.split_once('=').is_some_and(|(from, to)| {
                to.eq_ignore_ascii_case(".rdata")
                    && crate::pe::MERGED.iter().any(|it| it.eq_ignore_ascii_case(from))
            });
            if !merged {
                return Err(why_msvc::MERGE);
            }
            LinkOption::NoEffect(reason_msvc::MERGE)
        }
        b"OUT" | b"DLL" => return Err(why_msvc::OUTPUT),
        b"IMPLIB" => return Err(why_msvc::IMPLIB),
        _ => return Err(why::UNKNOWN),
    };
    Ok((option, 0))
}

/// What a module-definition file (`/DEF:file`) says: the DLL's name (`LIBRARY`), when it
/// gives one, and the names it exports, in order. Entries may be `DATA` or `PRIVATE` (an
/// import library's matter); a renamed, ordinal or forwarded export, and every statement but
/// `LIBRARY` and `EXPORTS`, is refused by name, as what blaze's linker does not write.
pub(super) fn def_exports(text: &str) -> Result<(Option<String>, Vec<String>), String> {
    let mut library = None;
    // alloc: once per `/DEF`, the names the output takes
    let mut exports = Vec::new();
    let mut in_exports = false;
    for (at, line) in text.lines().enumerate() {
        let line = line.split(';').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let mut words = line.split_whitespace();
        let first = words.next().unwrap_or_default();
        let upper = first.to_ascii_uppercase();
        match upper.as_str() {
            "LIBRARY" => {
                in_exports = false;
                // alloc: once per `/DEF`
                library = words.next().map(|it| it.trim_matches('"').to_owned());
                continue;
            }
            "EXPORTS" => {
                in_exports = true;
                continue;
            }
            "NAME" | "HEAPSIZE" | "STACKSIZE" | "SECTIONS" | "VERSION" | "DESCRIPTION" | "STUB" => {
                // alloc: error path
                return Err(format!(
                    "line {}: `{first}`, which blaze's linker does not take from a module-definition \
                     file (only LIBRARY and EXPORTS)",
                    at + 1
                ));
            }
            _ if !in_exports => {
                // alloc: error path
                return Err(format!("line {}: `{line}` is outside EXPORTS", at + 1));
            }
            _ => {}
        }
        let name = first.trim_matches('"');
        let plain = !name.contains(['=', '.', '@'])
            && words.all(|it| it.eq_ignore_ascii_case("DATA") || it.eq_ignore_ascii_case("PRIVATE"));
        if !plain || name.is_empty() {
            // alloc: error path
            return Err(format!("line {}: `{line}`: {}", at + 1, why_msvc::EXPORT_FORM));
        }
        // alloc: the export the output owns
        exports.push(name.to_owned());
    }
    Ok((library, exports))
}

/// A bare word: an input file, read by its extension.
fn input(text: &str) -> Read {
    if has_extension(text, "lib") || has_extension(text, "a") {
        return Ok((library(text, false), 0));
    }
    if has_extension(text, "obj") || has_extension(text, "o") || has_extension(text, "res") {
        return Ok((LinkOption::Input(PathBuf::from(text)), 0));
    }
    Err(why_msvc::INPUT)
}
