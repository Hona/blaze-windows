//! PE: Windows x86-64 executables and DLLs (`x86_64-pc-windows-msvc`), laid out as link.exe
//! lays out what rustc's link line asks of it (`/DYNAMICBASE`, `/HIGHENTROPYVA`, `/NXCOMPAT`,
//! `/OPT:REF`, `/DEBUG` without the PDB).
//!
//! Sections in link.exe's order, each starting on a page: `.text` (code, the jump table's
//! stubs, the import thunks), `.rdata` (read-only data, the import address table, the import
//! directory, the export directory, the debug directory, the TLS directory, `.CRT$X*`), `.data`
//! (data, the jump table, `.bss` last), `.pdata`, `.tls`, `.rsrc` and `.reloc`. Outside a dev
//! run, each section's raw data is sized to what is used and packed from `SizeOfHeaders` at
//! `FileAlignment` (4 KiB), while `VirtualSize` carries the growth room (the loader zero-fills
//! past `SizeOfRawData`); in an incremental image, growing tables get their own sections and
//! `.pdata`, `.reloc`, `.bdatap` (patch data) and `.bpatch` (patch code) sit at the tail so
//! edits grow in place or append without shifting the base code and read-only data.
//!
//! A dev run ([`crate::DevRun`]) lays the image out on 64 KiB granules, the unit a view of the
//! code memory maps at: the headers take the first granule, the code sections are one run from
//! the second, every change of protection after them starts a granule, raw offsets equal RVAs,
//! and the reservations (`.barena`, `.bcells`, `.bfixed`: no access, no raw data) come last.
//! Each section's `VirtualSize` reaches the next section, as the NT loader wants them adjacent.
//! The start hook is the first TLS callback (`.CRT$XLAB`, after the CRT's `__xl_a`), the TLS
//! directory is always there, no base relocation lands in code and there is no CFG.

mod coff;
pub(crate) mod delay;
mod image;
pub(crate) mod pdb;
pub(crate) mod rsrc;

pub(crate) use image::pdb_stem;
pub(crate) mod raw_dylib;
#[cfg(test)]
pub(crate) mod tests;

use std::fmt;

use blaze_codegen::Arch;
use blaze_ids::radix;
use blaze_core::lock::Lock;

use crate::model::{
    Class, Counts, File, NativeFile, Placed, Plan, Prot, Region, Reserve, SectionName, Special,
    Writer,
};
use crate::reset::{self, Reset};
use crate::{Format, LinkError, NativeKind, Output, OutputKind};

pub(crate) use coff::{asked_libraries, verbatim_option};

/// Where link.exe loads an executable and a DLL when the loader does not move them.
const EXE_BASE: u64 = 0x1_4000_0000;
const DLL_BASE: u64 = 0x1_8000_0000;
/// `SectionAlignment`, and the room for the headers before the first section.
pub(crate) const PAGE: u64 = 0x1000;
/// Windows' allocation granularity: a dev run's views of the code memory map at it, so its
/// code, the first section after the code and its reservations start on one.
pub(crate) const GRANULE: u64 = 0x1_0000;
/// The function a dev run's first TLS callback points at (`blaze_inproc::runtime`).
pub(crate) const START_HOOK: &str = "blaze_inproc_start";
/// Where the start hook's pointer goes: after the CRT's `__xl_a` (`.CRT$XLA`), before every
/// other TLS callback (std's is `.CRT$XLB`).
const START_HOOK_SECTION: &str = ".CRT$XLAB";

/// The prefix of a name that is the import address table cell of the symbol the rest names
/// (`__imp_X`, [`Special::Got`]).
pub(crate) const IMP: &str = "__imp_";
pub(crate) const IDATA: &str = "pe.idata";
pub(crate) const EDATA: &str = "pe.edata";
pub(crate) const DEBUG: &str = "pe.debug";
pub(crate) const TLS_DIR: &str = "pe.tls";
pub(crate) const TLS_INDEX: &str = "pe.tls_index";
pub(crate) const PDATA: &str = "pe.pdata";
pub(crate) const RELOC: &str = "pe.reloc";

/// The native objects' `.pdata`, which the writer merges with codegen's functions into its
/// own, and the resources the resource directory points at.
pub(crate) const OBJ_PDATA: &str = ".pdata";
pub(crate) const RSRC: &str = ".rsrc";
const CRT: &str = ".CRT";

/// What link.exe defines for an image built without `/guard:cf`, which the CRT's load
/// configuration refers to.
const ABSENT: &[&str] = &[
    "__guard_fids_count",
    "__guard_fids_table",
    "__guard_flags",
    "__guard_iat_count",
    "__guard_iat_table",
    "__guard_longjmp_count",
    "__guard_longjmp_table",
    "__guard_eh_cont_count",
    "__guard_eh_cont_table",
    "__enclave_config",
];

pub(crate) fn writer(output: &Output) -> Result<Pe, LinkError> {
    if output.format != Format::Pe {
        return Err(error(format_args!("the PE writer was asked for a {:?} image", output.format)));
    }
    if output.arch != Arch::X86_64 {
        return Err(error(format_args!(
            "a PE image for {:?}: blaze links PE for x86_64-pc-windows-msvc only",
            output.arch
        )));
    }
    if output.dev_run.is_some() && !matches!(output.kind, OutputKind::Executable { .. }) {
        return Err(error(
            "a dev run of a DLL: only an executable has a start hook and a code memory",
        ));
    }
    let last = output.incremental.then(|| Lock::new("link.pe.last", image::Last::default()));
    let descriptors = Lock::new("link.pe.descriptors", coff::Descriptors::default());
    // alloc: once per link: the writer's own copy of the output it makes
    Ok(Pe { output: output.clone(), descriptors, last })
}

/// An error, formatted only when it is returned.
pub(crate) fn error(what: impl fmt::Display) -> LinkError {
    // alloc: error path
    LinkError { function: None, what: what.to_string(), refusal: None }
}

/// A [`Class::Named`] of a section name.
pub(crate) fn named(name: SectionName, write: bool, exec: bool) -> Class {
    Class::Named { name, write, exec }
}

pub(crate) struct Pe {
    pub(crate) output: Output,
    /// The DLL each long-format import library names by its `__IMPORT_DESCRIPTOR_<lib>`,
    /// from the descriptor members of the archives read so far: a long import member names
    /// only the descriptor. Written once per archive that has descriptors; read once per long
    /// import member the core reads on its own (an import library read whole uses its own).
    pub(crate) descriptors: Lock<coff::Descriptors>,
    /// An incremental output's last tables, which the next synthesis patches when its
    /// [`crate::model::Delta`] is from theirs.
    pub(crate) last: Option<Lock<image::Last>>,
}

impl Pe {
    /// The last tables, when the output is incremental; a synthesis that panicked holding them
    /// leaves them empty, so the next synthesis builds every table.
    pub(crate) fn last(&self) -> Option<Reset<'_, image::Last>> {
        self.last.as_ref().map(reset::lock)
    }

    pub(crate) fn dll(&self) -> bool {
        matches!(self.output.kind, OutputKind::Shared { .. })
    }

    pub(crate) fn base(&self) -> u64 {
        match self.output.link.pe.base {
            Some(base) => base,
            None if self.dll() => DLL_BASE,
            None => EXE_BASE,
        }
    }

    pub(crate) fn dev_run(&self) -> bool {
        self.output.dev_run.is_some()
    }
}

/// Which section of the image a class goes in, in address order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum Segment {
    Text,
    Rdata,
    Data,
    Pdata,
    Tls,
    Rsrc,
    Reloc,
    /// Incremental data and code patch regions, placed at the tail of a non-dev-run
    /// editable image so unused growth room costs no file bytes and edits append at the end.
    PatchData,
    Patch,
    /// A dev run's reservations, one section each, in [`Reserve`]'s order.
    Reserve(Reserve),
}

impl Segment {
    /// The section's place in address order: in an incremental non-dev-run image, `.tls` and
    /// `.rsrc` precede the edit-growing tail (`.pdata`, `.reloc`, `.bdatap`, `.bpatch`);
    /// otherwise link.exe's classic order. Reservations are always last.
    const fn order(self, incremental: bool, dev_run: bool) -> u8 {
        if incremental && !dev_run {
            match self {
                Segment::Text => 0,
                Segment::Rdata => 1,
                Segment::Data => 2,
                Segment::Tls => 3,
                Segment::Rsrc => 4,
                Segment::Pdata => 5,
                Segment::Reloc => 6,
                Segment::PatchData => 7,
                Segment::Patch => 8,
                Segment::Reserve(reserve) => 9 + reserve as u8,
            }
        } else {
            match self {
                Segment::Text => 0,
                Segment::Rdata => 1,
                Segment::Data => 2,
                Segment::Pdata => 3,
                Segment::Tls => 4,
                Segment::Rsrc => 5,
                Segment::Reloc => 6,
                Segment::PatchData => 7,
                Segment::Patch => 8,
                Segment::Reserve(reserve) => 9 + reserve as u8,
            }
        }
    }

    pub(crate) fn name(self) -> &'static [u8] {
        match self {
            Segment::Text => b".text",
            Segment::Rdata => b".rdata",
            Segment::Data => b".data",
            Segment::Pdata => b".pdata",
            Segment::Tls => b".tls",
            Segment::Rsrc => b".rsrc",
            Segment::Reloc => b".reloc",
            Segment::PatchData => b".bdatap",
            Segment::Patch => b".bpatch",
            Segment::Reserve(Reserve::Arena) => b".barena",
            Segment::Reserve(Reserve::Cells) => b".bcells",
            Segment::Reserve(Reserve::Fixed) => b".bfixed",
        }
    }
}

/// Where a class goes: its section, its place in it, and a name ordering the named ones.
/// In an incremental non-dev-run image, fixed regions come first in `.text`/`.rdata`/`.data`
/// and the patch regions sit at the tail (`.bdatap`, `.bpatch`) so slack is never trapped
/// before fixed bytes in a section.
pub(crate) fn place_of(class: &Class, incremental: bool, dev_run: bool) -> (Segment, u8, &str) {
    let compact = incremental && !dev_run;
    match class {
        Class::Text => (Segment::Text, 0, ""),
        Class::Patch if dev_run => (Segment::Text, 1, ""),
        Class::Patch => (Segment::Patch, 0, ""),
        Class::Stubs => (Segment::Text, if dev_run { 2 } else { 1 }, ""),
        Class::Plt => (Segment::Text, if dev_run { 3 } else { 2 }, ""),
        Class::Synthetic(delay::DELAY_CODE) => (Segment::Text, if dev_run { 4 } else { 3 }, ""),
        Class::Named { name, exec: true, .. } => (Segment::Text, if dev_run { 5 } else { 4 }, name),
        // The import address table is read-only (`.rdata`, or `.iat` when incremental): once
        // the loader has bound the cells, it makes the pages the IAT directory spans read-only,
        // so nothing written may share them (seen on Windows 11 26100).
        Class::Got => (Segment::Rdata, if compact { 2 } else { 0 }, ""),
        Class::Rodata => (Segment::Rdata, if compact { 0 } else { 1 }, ""),
        // The loader applies base relocations to read-only pages too: link.exe's `.rdata`
        // holds vtables.
        Class::RelRo => (Segment::Rdata, if compact { 1 } else { 2 }, ""),
        Class::EhFrame => (Segment::Rdata, 3, ""),
        Class::Synthetic(IDATA) => (Segment::Rdata, 4, ""),
        Class::Synthetic(EDATA) => (Segment::Rdata, 5, ""),
        Class::Synthetic(DEBUG) => (Segment::Rdata, 6, ""),
        Class::Synthetic(TLS_DIR) => (Segment::Rdata, 7, ""),
        Class::Synthetic(delay::DELAY) => (Segment::Rdata, 8, ""),
        Class::Named { name, .. } if name == OBJ_PDATA => {
            (Segment::Pdata, if dev_run { 0 } else { 1 }, name)
        }
        Class::Named { name, .. } if name == RSRC => (Segment::Rsrc, 0, name),
        Class::Named { name, write: false, .. } => (Segment::Rdata, 9, name),
        Class::Data => (Segment::Data, 0, ""),
        Class::Table => (Segment::Data, 1, ""),
        Class::Synthetic(delay::DELAY_DATA) => (Segment::Data, if compact { 7 } else { 2 }, ""),
        Class::PatchData if dev_run => (Segment::Data, 3, ""),
        Class::PatchData => (Segment::PatchData, 0, ""),
        Class::InitArray => (Segment::Data, if compact { 2 } else { 4 }, ""),
        // ELF's alone: `image::sections` refuses one.
        Class::PreinitArray => (Segment::Data, if compact { 2 } else { 4 }, ""),
        Class::FiniArray => (Segment::Data, if compact { 3 } else { 5 }, ""),
        Class::Synthetic(TLS_INDEX) => (Segment::Data, if compact { 4 } else { 7 }, ""),
        // Mach-O's alone (`Plan::tls_descriptors` is false): `image::file` refuses one.
        Class::ThreadVars => (Segment::Data, if compact { 5 } else { 8 }, ""),
        Class::Bss => (Segment::Data, if compact { 6 } else { 9 }, ""),
        Class::Named { name, .. } => (Segment::Data, if compact { 8 } else { 6 }, name),
        Class::Synthetic(PDATA) => (Segment::Pdata, if dev_run { 1 } else { 0 }, ""),
        Class::Tdata => (Segment::Tls, 0, ""),
        Class::Tbss => (Segment::Tls, 1, ""),
        Class::Synthetic(RELOC) => (Segment::Reloc, 0, ""),
        Class::Synthetic(name) => (Segment::Rdata, 10, name),
        Class::Reserve(reserve) => (Segment::Reserve(*reserve), 0, ""),
    }
}

/// Non-incremental placement, used where a class's default segment and protection are asked.
pub(crate) fn place(class: &Class) -> (Segment, u8, &str) {
    place_of(class, false, false)
}

/// The named sections link.exe lays into `.rdata` with the rest of the read-only data: the
/// CRT's initializer tables and `/RTC` tables (its objects' `/MERGE:.CRT=.rdata` and
/// `/MERGE:.rtc=.rdata`), and the guard's function pointers (`.00cfg`, which link.exe merges
/// itself).
pub(crate) const MERGED: &[&str] = &[CRT, ".rtc", ".00cfg"];

/// Whether `class` is a section of its own in a non-incremental or dev-run image, as link.exe
/// keeps each section name no `/MERGE` folds into another: every named class but the tables
/// the writer gathers (`.pdata`, `.rsrc`) and [`MERGED`]'s.
pub(crate) fn own_section(class: &Class) -> bool {
    match class {
        Class::Named { name, .. } => {
            let name: &str = name;
            name != OBJ_PDATA && name != RSRC && !MERGED.contains(&name)
        }
        _ => false,
    }
}

/// Whether `class` gets pages (and a PE section) of its own. In an incremental non-dev-run
/// image, every growing table and patch region gets its own section so its unused growth room
/// sits at its section's tail (`VirtualSize > SizeOfRawData`) and costs zero bytes on disk.
pub(crate) fn own_pages_of(class: &Class, incremental: bool, dev_run: bool) -> bool {
    if !incremental || dev_run {
        return own_section(class);
    }
    match class {
        Class::Patch | Class::PatchData | Class::Got | Class::Tdata => true,
        Class::Named { name, .. } => name.as_str() != OBJ_PDATA,
        Class::Synthetic(name) => *name != TLS_INDEX && *name != PDATA,
        _ => false,
    }
}

/// The rank of a grouped section's `$` suffix: link.exe sorts the pieces of a section by the
/// part after the `$`, so `.CRT$XCA` < `.CRT$XCU` < `.CRT$XCZ` and `.tls` < `.tls$` <
/// `.tls$ZZZ`. The first 4 bytes of the suffix, big-endian, order them.
pub(crate) fn rank(suffix: Option<&str>) -> u32 {
    match suffix {
        None => 0,
        Some("") => 1,
        Some(suffix) => {
            let mut key = [0; 4];
            for (to, byte) in key.iter_mut().zip(suffix.bytes()) {
                *to = byte;
            }
            u32::from_be_bytes(key).max(2)
        }
    }
}

impl Writer for Pe {
    fn format(&self) -> Format {
        Format::Pe
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn plan(&self) -> Plan {
        let page = if self.dev_run() { GRANULE } else { PAGE };
        Plan {
            base: self.base(),
            headers: page,
            page,
            indexed_code: false,
            got_by_library: true,
            tls_descriptors: false,
        }
    }

    fn order(&self, classes: &mut Vec<Class>) {
        let (incremental, dev_run) = (self.output.incremental, self.dev_run());
        let rank = |class: &Class| {
            let (segment, rank, _) = place_of(class, incremental, dev_run);
            radix::pack_32(u32::from(segment.order(incremental, dev_run)), u32::from(rank))
        };
        radix::sort_by_key(classes, rank);
        for run in classes.chunk_by_mut(|a, b| rank(a) == rank(b)) {
            run.sort_by(|a, b| {
                place_of(a, incremental, dev_run).2.cmp(place_of(b, incremental, dev_run).2)
            });
        }
        classes.dedup();
    }

    fn own_pages(&self, class: &Class) -> bool {
        own_pages_of(class, self.output.incremental, self.dev_run())
    }

    fn searched_roots(&self) -> &'static [&'static str] {
        &["_load_config_used"]
    }

    fn prot(&self, class: &Class) -> Prot {
        if let Class::Named { write, exec, .. } = class {
            return Prot { read: true, write: *write, exec: *exec };
        }
        match place(class).0 {
            Segment::Text | Segment::Patch => Prot::RX,
            Segment::Data | Segment::Tls | Segment::PatchData => Prot::RW,
            Segment::Rdata | Segment::Pdata | Segment::Rsrc | Segment::Reloc => Prot::R,
            Segment::Reserve(_) => Prot::NONE,
        }
    }

    fn section(
        &self,
        name: &str,
        write: bool,
        exec: bool,
        tls: bool,
    ) -> Result<(Class, u32), String> {
        let (base, suffix) = match name.split_once('$') {
            Some((base, suffix)) => (base, Some(suffix)),
            None => (name, None),
        };
        let class = match base {
            ".text" => Class::Text,
            ".rdata" | ".xdata" => Class::Rodata,
            ".data" => Class::Data,
            ".bss" => Class::Bss,
            ".tls" => Class::Tdata,
            OBJ_PDATA => named(OBJ_PDATA.into(), false, false),
            CRT => named(CRT.into(), false, false),
            RSRC => named(RSRC.into(), false, false),
            ".idata" | ".edata" | ".reloc" | ".didat" => {
                // alloc: error path
                return Err(format!(
                    "section {name} holds tables the linker makes; no input may define it"
                ));
            }
            _ if tls => Class::Tdata,
            _ => named(SectionName::new(base), write, exec),
        };
        Ok((class, rank(suffix)))
    }

    fn special(&self, name: &str) -> Option<Special> {
        match name {
            "__ImageBase" => Some(Special::ImageBase),
            "_tls_used" => Some(Special::Start(Class::Synthetic(TLS_DIR))),
            "_tls_index" => Some(Special::Start(Class::Synthetic(TLS_INDEX))),
            "__blaze_live" => Some(Special::LiveDescriptor),
            _ if ABSENT.contains(&name) => Some(Special::Absolute(0)),
            _ => name
                .strip_prefix(IMP)
                .filter(|it| !it.is_empty())
                .map(|_| Special::Got { from: IMP.len() as u32 }),
        }
    }

    fn got_prefix(&self) -> Option<&'static str> {
        Some(IMP)
    }

    fn read(&self, name: &str, bytes: &[u8], kind: &NativeKind) -> Result<NativeFile, String> {
        coff::read(self, name, bytes, kind)
    }

    fn start_hook(&self) -> Result<(Class, u32), String> {
        self.section(START_HOOK_SECTION, false, false, false)
    }

    fn synthetic(&self, counts: &Counts) -> Vec<(Class, u64)> {
        image::synthetic(counts, self.dev_run(), !self.output.link.pe.delay_load.is_empty())
    }

    fn apply(
        &self,
        r_type: u32,
        bytes: &mut [u8],
        p: u64,
        s: u64,
        addend: i64,
    ) -> Result<(), String> {
        let _ = (bytes, s, addend);
        // alloc: error path
        Err(format!(
            "PE has no relocation of its own (type {r_type} at {p:#x}): every AMD64 relocation \
             is read as one the core applies"
        ))
    }

    fn synthesize(
        &self,
        placed: &Placed<'_>,
    ) -> Result<Vec<(Class, crate::cow::CowBytes)>, LinkError> {
        image::synthesize(self, placed)
    }

    fn offset(&self, placed: &Placed<'_>, region: &Region) -> Option<u64> {
        image::offset(self, placed, region)
    }

    fn file(&self, placed: &Placed<'_>) -> Result<File, LinkError> {
        image::file(self, placed)
    }

    fn encode(&self, placed: &Placed<'_>) -> Result<Vec<(u64, u64)>, LinkError> {
        let mut slots = image::iat_slots(placed)?;
        // A delay-loaded function's GOT cell holds its stub's address ([`delay`]).
        if let Some(delay) = delay::tables(self, placed)? {
            slots.extend(delay.cells);
            radix::sort_by_key(&mut slots, |it: &(u64, u64)| it.0);
        }
        Ok(slots)
    }

    fn shared_entry(&self) -> Option<&'static str> {
        self.dll().then_some("_DllMainCRTStartup")
    }

    fn own(&self, class: &Class) -> (Class, u32) {
        match class {
            Class::Tdata | Class::Tbss => (Class::Tdata, rank(Some(""))),
            // clone: the core asks once per class and keeps the answer (`stage.rs`'s `own`)
            _ => (class.clone(), u32::MAX),
        }
    }
}
