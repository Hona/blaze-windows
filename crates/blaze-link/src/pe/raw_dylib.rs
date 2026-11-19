//! `raw-dylib`: a DLL's imports a crate declares (`#[link(name = "..", kind = "raw-dylib")]`)
//! with no import library on the machine. The link makes the import library itself, as
//! rustc does (`rustc_codegen_ssa::back::archive::create_raw_dylib_import_lib`): an archive of
//! one short import member (`IMPORT_OBJECT_HEADER`) an import, indexed as `lib.exe` indexes
//! one (`X` and `__imp_X` for a function, `__imp_X` alone for data). The archive is then read
//! as any import library is ([`super::coff`]): only the imports the code reaches are taken.
//!
//! Every `raw-dylib` of one DLL on the line (the `windows-link` crate makes an `extern` block
//! a function, all of `kernel32.dll`) is one archive, at the place of the first: its bytes are
//! a function of the imports alone, so a link whose imports did not change hands the image the
//! same input.

use std::sync::Arc;

use blaze_codegen::{NativeLib, NativeLibKind, RawImport};
use blaze_ids::ContentId;

use super::IMP;

/// The domain a made import library's bytes are named in.
const DOMAIN: &str = "blaze v2 link raw-dylib import library 1";

/// The size of an archive member's header.
const MEMBER_HEADER: usize = 60;
/// The size of `IMPORT_OBJECT_HEADER`.
const IMPORT_HEADER: usize = 20;
const IMPORT_OBJECT_CODE: u16 = 0;
const IMPORT_OBJECT_DATA: u16 = 1;
const IMPORT_OBJECT_ORDINAL: u16 = 0;
const IMPORT_OBJECT_NAME: u16 = 1;

/// The file name of the DLL a `raw-dylib` names, as rustc makes it: `name.dll`, or `name` as
/// written with `+verbatim`.
pub(crate) fn dll_name(lib: &NativeLib) -> String {
    match lib.verbatim {
        // alloc: once per `raw-dylib` library on the line, the DLL's name
        true => lib.name.clone(),
        // alloc: as above
        false => format!("{}.dll", lib.name),
    }
}

/// The imports of one DLL, from every `raw-dylib` of it, each symbol once.
#[derive(Debug, Default)]
pub(crate) struct Dll {
    /// As the first library to name it writes it; its file is matched ASCII case ignored, as
    /// the loader matches it.
    pub(crate) name: String,
    imports: Vec<RawImport>,
}

impl Dll {
    pub(crate) fn new(name: String) -> Dll {
        Dll { name, imports: Vec::new() }
    }

    /// Adds `lib`'s imports. One symbol declared twice is one import; declared as two (another
    /// ordinal, or a function and a static) it is an error naming both, where rustc keeps the
    /// last quietly.
    pub(crate) fn add(&mut self, lib: &NativeLib) -> Result<(), String> {
        debug_assert_eq!(lib.kind, NativeLibKind::RawDylib);
        for import in &lib.imports {
            match self.imports.iter().find(|it| it.symbol == import.symbol) {
                Some(it) if it == import => {}
                Some(it) => {
                    // alloc: error path
                    return Err(format!(
                        "`{}` is imported from the `raw-dylib` {} twice, as {} and as {}",
                        import.symbol,
                        self.name,
                        described(it),
                        described(import)
                    ));
                }
                // clone: once per import of the line, which the archive is made of
                None => self.imports.push(import.clone()),
            }
        }
        Ok(())
    }

    /// The import library of the DLL, and its content's id.
    pub(crate) fn library(&self) -> Result<(ContentId, Arc<[u8]>), String> {
        let bytes = import_library(&self.name, &self.imports)?;
        Ok((ContentId::of(DOMAIN, &bytes), Arc::from(bytes)))
    }
}

fn described(import: &RawImport) -> String {
    let what = if import.data { "a static" } else { "a function" };
    match import.ordinal {
        // alloc: error path
        Some(ordinal) => format!("{what} of ordinal {ordinal}"),
        // alloc: error path
        None => format!("{what} by name"),
    }
}

/// An archive of one short import member per import of `dll`, with a first linker member
/// (GNU's symbol table: big-endian offsets, names in member order) and a long-names member
/// holding the DLL's name, which every member is named by.
pub(crate) fn import_library(dll: &str, imports: &[RawImport]) -> Result<Vec<u8>, String> {
    if dll.is_empty() || dll.contains('\0') {
        // alloc: error path
        return Err(format!("the `raw-dylib` DLL name {dll:?} is not a file name"));
    }
    if let Some(it) = imports.iter().find(|it| it.symbol.is_empty() || it.symbol.contains('\0')) {
        // alloc: error path
        return Err(format!("the import {:?} of {dll} has no symbol a DLL can export", it.symbol));
    }
    let names = |import: &RawImport| -> usize {
        let imp = IMP.len() + import.symbol.len() + 1;
        if import.data { imp } else { imp + import.symbol.len() + 1 }
    };
    let symbols: usize = imports.iter().map(|it| if it.data { 1 } else { 2 }).sum();
    let table = 4 + 4 * symbols + imports.iter().map(names).sum::<usize>();
    let long_names = dll.len() + 2;
    let mut at = 8
        + MEMBER_HEADER
        + table.next_multiple_of(2)
        + MEMBER_HEADER
        + long_names.next_multiple_of(2);
    // alloc: per import library made, each member's offset
    let mut offsets = Vec::with_capacity(imports.len());
    for import in imports {
        offsets.push(u32::try_from(at).map_err(|_| too_big(dll))?);
        at += MEMBER_HEADER + member_len(dll, import).next_multiple_of(2);
    }

    // alloc: the import library, which the image keeps as a native input
    let mut out = Vec::with_capacity(at);
    out.extend_from_slice(b"!<arch>\n");
    header(&mut out, "/", table);
    out.extend_from_slice(&u32::try_from(symbols).map_err(|_| too_big(dll))?.to_be_bytes());
    for (import, offset) in imports.iter().zip(&offsets) {
        let count = if import.data { 1 } else { 2 };
        for _ in 0..count {
            out.extend_from_slice(&offset.to_be_bytes());
        }
    }
    for import in imports {
        out.extend_from_slice(IMP.as_bytes());
        out.extend_from_slice(import.symbol.as_bytes());
        out.push(0);
        if !import.data {
            out.extend_from_slice(import.symbol.as_bytes());
            out.push(0);
        }
    }
    pad(&mut out);
    header(&mut out, "//", long_names);
    out.extend_from_slice(dll.as_bytes());
    out.extend_from_slice(b"/\n");
    pad(&mut out);
    for import in imports {
        header(&mut out, "/0", member_len(dll, import));
        import_member(&mut out, dll, import);
        pad(&mut out);
    }
    debug_assert_eq!(out.len(), at);
    Ok(out)
}

fn too_big(dll: &str) -> String {
    // alloc: error path
    format!("the import library of the `raw-dylib` {dll} is past 4 GiB")
}

/// One import as a short import member: `IMPORT_OBJECT_HEADER`, the symbol and the DLL.
fn import_member(out: &mut Vec<u8>, dll: &str, import: &RawImport) {
    let size = member_len(dll, import) - IMPORT_HEADER;
    let kind = if import.data { IMPORT_OBJECT_DATA } else { IMPORT_OBJECT_CODE };
    let (name_type, ordinal_or_hint) = match import.ordinal {
        Some(ordinal) => (IMPORT_OBJECT_ORDINAL, ordinal),
        None => (IMPORT_OBJECT_NAME, 0),
    };
    out.extend_from_slice(&0u16.to_le_bytes()); // Sig1: IMAGE_FILE_MACHINE_UNKNOWN
    out.extend_from_slice(&0xffffu16.to_le_bytes()); // Sig2
    out.extend_from_slice(&0u16.to_le_bytes()); // Version
    out.extend_from_slice(&object::pe::IMAGE_FILE_MACHINE_AMD64.0.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp: none, as `/Brepro`
    out.extend_from_slice(&(size as u32).to_le_bytes());
    out.extend_from_slice(&ordinal_or_hint.to_le_bytes());
    out.extend_from_slice(&(kind | name_type << 2).to_le_bytes());
    out.extend_from_slice(import.symbol.as_bytes());
    out.push(0);
    out.extend_from_slice(dll.as_bytes());
    out.push(0);
}

/// The size of an import's member: its header, its symbol and the DLL, each ended by a NUL.
fn member_len(dll: &str, import: &RawImport) -> usize {
    IMPORT_HEADER + import.symbol.len() + 1 + dll.len() + 1
}

/// An archive member's header: its name, a zero date, owner and mode, and its size.
fn header(out: &mut Vec<u8>, name: &str, size: usize) {
    let field = |out: &mut Vec<u8>, text: &str, width: usize| {
        out.extend_from_slice(text.as_bytes());
        out.resize(out.len() + width - text.len(), b' ');
    };
    field(out, name, 16);
    field(out, "0", 12);
    field(out, "0", 6);
    field(out, "0", 6);
    field(out, "0", 8);
    // alloc: per member, its size as decimal text
    field(out, &size.to_string(), 10);
    out.extend_from_slice(b"`\n");
}

/// Pads a member to an even length, as archive members are 2-aligned.
fn pad(out: &mut Vec<u8>) {
    if out.len() % 2 == 1 {
        out.push(b'\n');
    }
}

#[cfg(test)]
mod tests;
