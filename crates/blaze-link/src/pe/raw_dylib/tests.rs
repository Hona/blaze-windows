use blaze_codegen::{NativeLib, NativeLibKind, RawImport};

use super::{Dll, dll_name, import_library};
use crate::NativeKind;
use crate::model::{NativeFile, SymbolKind, Writer as _};
use crate::pe::tests::{exe, pe};

fn import(symbol: &str, ordinal: Option<u16>, data: bool) -> RawImport {
    RawImport { symbol: symbol.to_owned(), ordinal, data }
}

fn raw(name: &str, verbatim: bool, imports: Vec<RawImport>) -> NativeLib {
    NativeLib { name: name.to_owned(), kind: NativeLibKind::RawDylib, verbatim, imports }
}

/// The library made of a `raw-dylib` reads as `lib.exe`'s import library does: each import a
/// short import member of the DLL, a function indexed by its name and its cell's, data by its
/// cell's alone, an ordinal by `#n` and a name with hint 0.
#[test]
fn a_raw_dylib_library_reads_as_an_import_library() {
    let imports = [
        import("GetLastError", None, false),
        import("by_ordinal", Some(7), false),
        import("Exported", None, true),
    ];
    let bytes = import_library("kernel32.dll", &imports).unwrap();
    let pe = pe(exe());
    let NativeFile::Archive(archive) =
        pe.read("raw-dylib kernel32.dll", &bytes, &NativeKind::Archive { whole: false }).unwrap()
    else {
        panic!("not read as an archive")
    };
    let members: Vec<&str> = archive.members.iter().map(|it| archive.name(it.name)).collect();
    assert_eq!(members, ["kernel32.dll"; 3]);
    let index: Vec<(&str, u32)> =
        archive.index.iter().map(|&(name, member)| (archive.name(name), member)).collect();
    assert_eq!(
        index,
        [
            ("__imp_GetLastError", 0),
            ("GetLastError", 0),
            ("__imp_by_ordinal", 1),
            ("by_ordinal", 1),
            ("__imp_Exported", 2),
        ]
    );
    let read = |member: usize| {
        let member = &bytes[archive.members[member].bytes.clone()];
        match pe.read("raw-dylib kernel32.dll(kernel32.dll)", member, &NativeKind::Object).unwrap()
        {
            NativeFile::Shared(shared) => shared,
            _ => panic!("an import member not read as a DLL's import"),
        }
    };
    for (member, (symbol, version, kind)) in [
        ("GetLastError", "0 GetLastError", SymbolKind::Function),
        ("by_ordinal", "#7", SymbolKind::Function),
        ("Exported", "0 Exported", SymbolKind::Data),
    ]
    .into_iter()
    .enumerate()
    {
        let shared = read(member);
        assert_eq!(shared.name, "kernel32.dll");
        assert_eq!(shared.symbol_name(&shared.symbols[0]), symbol);
        assert_eq!(shared.version(&shared.symbols[0]), Some(version));
        assert_eq!(shared.symbols[0].kind, kind);
    }
}

/// Every `raw-dylib` of a DLL is one library: a symbol declared again is one import, and the
/// bytes are the imports' alone, so a link whose imports are the same makes the same input.
#[test]
fn the_raw_dylibs_of_a_dll_are_one_library() {
    let first = raw("kernel32.dll", true, vec![import("Sleep", None, false)]);
    let again = raw(
        "kernel32.dll",
        true,
        vec![import("Sleep", None, false), import("ExitProcess", None, false)],
    );
    let mut dll = Dll::new(dll_name(&first));
    dll.add(&first).unwrap();
    dll.add(&again).unwrap();
    let (id, bytes) = dll.library().unwrap();
    let alone = import_library(
        "kernel32.dll",
        &[import("Sleep", None, false), import("ExitProcess", None, false)],
    )
    .unwrap();
    assert_eq!(&*bytes, &alone[..]);
    assert_eq!(dll.library().unwrap().0, id, "the same imports, the same input");
    let other = Dll::new("kernel32.dll".to_owned());
    assert_ne!(other.library().unwrap().0, id);

    let conflicting = raw("kernel32.dll", true, vec![import("Sleep", Some(3), false)]);
    let error = dll.add(&conflicting).unwrap_err();
    assert!(
        error.contains("`Sleep`")
            && error.contains("a function by name")
            && error.contains("a function of ordinal 3"),
        "{error}"
    );
}

#[test]
fn a_dll_is_named_as_rustc_names_it() {
    assert_eq!(dll_name(&raw("bcryptprimitives", false, Vec::new())), "bcryptprimitives.dll");
    assert_eq!(dll_name(&raw("kernel32.dll", true, Vec::new())), "kernel32.dll");
    assert_eq!(
        dll_name(&raw("api-ms-win-core-synch-l1-2-0", false, Vec::new())),
        "api-ms-win-core-synch-l1-2-0.dll"
    );
    assert!(import_library("", &[]).is_err());
    assert!(import_library("x.dll", &[import("", None, false)]).is_err());
}
