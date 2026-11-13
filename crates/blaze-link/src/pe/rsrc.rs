//! Compiled resource files (`.res`, what `rc.exe` and `llvm-rc` write and winresource,
//! embed-resource and tauri-build hand the link) merged into one COFF object, as link.exe
//! runs `cvtres` over every `.res` of a link: a `.rsrc$01` section holding the resource
//! directory (types, then names, then languages, each level's named entries before its
//! numbered ones, both sorted) and the data entries, whose `OffsetToData` is an
//! `IMAGE_REL_AMD64_ADDR32NB` relocation into `.rsrc$02`, which holds the data. The writer lays
//! the object's sections into `.rsrc` (`$01` first) and points the resource data directory at
//! it, as it does for any object with resources.
//!
//! One resource (a type, a name and a language) named twice is an error naming both files:
//! link.exe's `CVT1100`. A `.res` that is not one (a truncated header, a size past the end) is
//! an error naming the file and the offset.

use std::cmp::Ordering;

use blaze_format::cursor::Put;

/// The header every `.res` starts with: an empty resource of type 0 and name 0.
const EMPTY: [u8; 32] = [
    0, 0, 0, 0, 0x20, 0, 0, 0, 0xff, 0xff, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0,
];

/// Whether `bytes` is a compiled resource file: its empty first resource.
pub(crate) fn is_res(bytes: &[u8]) -> bool {
    bytes.starts_with(&EMPTY)
}

/// A resource's type or name: a number, or a string (UTF-16, as the file has it).
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum Id {
    Number(u16),
    Name(Vec<u16>),
}

impl Id {
    /// The order of one directory's entries: names first, sorted as the loader's binary
    /// search compares them (`LdrpCompareResourceNames_U`: code units, uppercase); then
    /// numbers, ascending.
    fn order(&self, other: &Id) -> Ordering {
        match (self, other) {
            (Id::Name(a), Id::Name(b)) => {
                let upper = |it: &[u16]| -> Vec<u16> {
                    it.iter()
                        .map(|&c| if (u16::from(b'a')..=u16::from(b'z')).contains(&c) { c - 32 } else { c })
                        .collect()
                };
                upper(a).cmp(&upper(b)).then_with(|| a.cmp(b))
            }
            (Id::Name(_), Id::Number(_)) => Ordering::Less,
            (Id::Number(_), Id::Name(_)) => Ordering::Greater,
            (Id::Number(a), Id::Number(b)) => a.cmp(b),
        }
    }

    /// What an error calls it.
    fn show(&self) -> String {
        match self {
            Id::Number(it) => it.to_string(),
            // alloc: error path
            Id::Name(it) => format!("\"{}\"", String::from_utf16_lossy(it)),
        }
    }
}

/// One resource of a `.res`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Resource {
    pub kind: Id,
    pub name: Id,
    pub language: u16,
    pub data: Vec<u8>,
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

/// A header's type or name at `at`: `0xffff` and a number, or a NUL-terminated UTF-16 string.
/// The id and where the next field is.
fn id_at(bytes: &[u8], at: usize) -> Option<(Id, usize)> {
    if u16_at(bytes, at)? == 0xffff {
        return Some((Id::Number(u16_at(bytes, at + 2)?), at + 4));
    }
    let mut name = Vec::new();
    let mut end = at;
    loop {
        let unit = u16_at(bytes, end)?;
        end += 2;
        if unit == 0 {
            return Some((Id::Name(name), end));
        }
        name.push(unit);
    }
}

/// The resources of the `.res` `bytes` (`file` in errors), in the file's order, the empty
/// first one left out.
pub(crate) fn read(file: &str, bytes: &[u8]) -> Result<Vec<Resource>, String> {
    if !is_res(bytes) {
        // alloc: error path
        return Err(format!("{file} is not a compiled resource file (.res): it does not start with one's empty resource"));
    }
    let mut out = Vec::new();
    let mut at = EMPTY.len();
    while at < bytes.len() {
        // alloc: error path
        let bad = |what: &str| format!("{file}: the resource at offset {at:#x} {what}");
        let data_size = u32_at(bytes, at).ok_or_else(|| bad("has a truncated header"))? as usize;
        let header_size = u32_at(bytes, at + 4).ok_or_else(|| bad("has a truncated header"))? as usize;
        let (kind, next) = id_at(bytes, at + 8).ok_or_else(|| bad("has a truncated type"))?;
        let (name, next) = id_at(bytes, next).ok_or_else(|| bad("has a truncated name"))?;
        let fixed = next.next_multiple_of(4);
        // DataVersion, MemoryFlags, LanguageId, Version, Characteristics.
        let language = u16_at(bytes, fixed + 6).ok_or_else(|| bad("has a truncated header"))?;
        if fixed + 16 > at + header_size || header_size < 24 {
            return Err(bad("has a header shorter than its fields"));
        }
        let data = at + header_size;
        let end = data.checked_add(data_size).filter(|it| *it <= bytes.len());
        let end = end.ok_or_else(|| bad("has data past the end of the file"))?;
        let empty = data_size == 0 && kind == Id::Number(0) && name == Id::Number(0);
        if !empty {
            out.push(Resource { kind, name, language, data: bytes[data..end].to_vec() });
        }
        at = end.next_multiple_of(4);
    }
    Ok(out)
}

/// `files`' resources as one, sorted as the directory lists them; a resource named by two is
/// an error naming both.
pub(crate) fn merge(files: Vec<(String, Vec<Resource>)>) -> Result<Vec<Resource>, String> {
    let mut all: Vec<(usize, Resource)> = Vec::new();
    for (at, (_, resources)) in files.iter().enumerate() {
        all.extend(resources.iter().cloned().map(|it| (at, it)));
    }
    all.sort_by(|(_, a), (_, b)| {
        a.kind.order(&b.kind).then_with(|| a.name.order(&b.name)).then(a.language.cmp(&b.language))
    });
    for pair in all.windows(2) {
        let (a, b) = (&pair[0].1, &pair[1].1);
        if a.kind == b.kind && a.name == b.name && a.language == b.language {
            // alloc: error path
            return Err(format!(
                "the resource of type {}, name {} and language {:#06x} is in both {} and {} (link.exe: CVT1100)",
                a.kind.show(),
                a.name.show(),
                a.language,
                files[pair[0].0].0,
                files[pair[1].0].0
            ));
        }
    }
    Ok(all.into_iter().map(|it| it.1).collect())
}

const DIRECTORY: usize = 16;
const ENTRY: usize = 8;
const DATA_ENTRY: usize = 16;
const SUBDIRECTORY: u32 = 0x8000_0000;
const NAMED: u32 = 0x8000_0000;

/// The resource directory and the data of `resources` (sorted, [`merge`]): `.rsrc$01`'s bytes
/// with the offsets in it of each data entry's `OffsetToData`, to relocate to the data's offset
/// in `.rsrc$02`, whose bytes come last.
fn tables(resources: &[Resource]) -> (Vec<u8>, Vec<(u32, u32)>, Vec<u8>) {
    // The tree: each type's run of resources, and in it each name's run.
    let runs = |items: &[Resource], key: fn(&Resource) -> &Id| -> Vec<std::ops::Range<usize>> {
        let mut out: Vec<std::ops::Range<usize>> = Vec::new();
        for (at, it) in items.iter().enumerate() {
            match out.last_mut() {
                Some(last) if key(&items[last.start]) == key(it) => last.end = at + 1,
                _ => out.push(at..at + 1),
            }
        }
        out
    };
    let types = runs(resources, |it| &it.kind);
    let names: Vec<Vec<std::ops::Range<usize>>> = types
        .iter()
        .map(|range| {
            runs(&resources[range.clone()], |it| &it.name)
                .into_iter()
                .map(|it| it.start + range.start..it.end + range.start)
                .collect()
        })
        .collect();
    let name_count: usize = names.iter().map(Vec::len).sum();
    // Offsets: the root, the type directories, the name directories, then the strings, then
    // the data entries.
    let root = 0;
    let type_dirs = root + DIRECTORY + ENTRY * types.len();
    let mut type_at = Vec::with_capacity(types.len());
    let mut at = type_dirs;
    for named in &names {
        type_at.push(at);
        at += DIRECTORY + ENTRY * named.len();
    }
    let mut name_at = Vec::with_capacity(name_count);
    for named in &names {
        for range in named {
            name_at.push(at);
            at += DIRECTORY + ENTRY * range.len();
        }
    }
    let mut strings: Vec<u8> = Vec::new();
    let string_at = |id: &Id, strings: &mut Vec<u8>| -> Option<u32> {
        let Id::Name(name) = id else { return None };
        let offset = at + strings.len();
        strings.put_u16(name.len() as u16);
        for unit in name {
            strings.put_u16(*unit);
        }
        Some(offset as u32)
    };
    // Each directory's entries' name fields, made in the order they are written.
    let type_names: Vec<Option<u32>> =
        types.iter().map(|range| string_at(&resources[range.start].kind, &mut strings)).collect();
    let name_names: Vec<Option<u32>> = names
        .iter()
        .flatten()
        .map(|range| string_at(&resources[range.start].name, &mut strings))
        .collect();
    let data_entries = (at + strings.len()).next_multiple_of(4);
    let mut out: Vec<u8> = Vec::with_capacity(data_entries + DATA_ENTRY * resources.len());
    let directory = |out: &mut Vec<u8>, ids: &[&Id]| {
        out.put_u32(0);
        out.put_u32(0);
        out.put_u16(0);
        out.put_u16(0);
        let named = ids.iter().filter(|it| matches!(it, Id::Name(_))).count();
        out.put_u16(named as u16);
        out.put_u16((ids.len() - named) as u16);
    };
    let entry = |out: &mut Vec<u8>, id: &Id, name: Option<u32>, to: u32| {
        match (id, name) {
            (Id::Number(n), _) => out.put_u32(u32::from(*n)),
            (Id::Name(_), Some(at)) => out.put_u32(NAMED | at),
            (Id::Name(_), None) => unreachable!("every name's string is made"),
        }
        out.put_u32(to);
    };
    let kinds: Vec<&Id> = types.iter().map(|it| &resources[it.start].kind).collect();
    directory(&mut out, &kinds);
    for (index, range) in types.iter().enumerate() {
        entry(&mut out, &resources[range.start].kind, type_names[index], SUBDIRECTORY | type_at[index] as u32);
    }
    let mut flat = 0;
    for named in &names {
        let ids: Vec<&Id> = named.iter().map(|it| &resources[it.start].name).collect();
        directory(&mut out, &ids);
        for (at, range) in named.iter().enumerate() {
            let index = flat + at;
            entry(&mut out, &resources[range.start].name, name_names[index], SUBDIRECTORY | name_at[index] as u32);
        }
        flat += named.len();
    }
    for range in names.iter().flatten() {
        let languages: Vec<Id> = resources[range.clone()].iter().map(|it| Id::Number(it.language)).collect();
        directory(&mut out, &languages.iter().collect::<Vec<_>>());
        for at in range.clone() {
            out.put_u32(u32::from(resources[at].language));
            out.put_u32((data_entries + DATA_ENTRY * at) as u32);
        }
    }
    out.extend_from_slice(&strings);
    out.resize(data_entries, 0);
    let mut data: Vec<u8> = Vec::new();
    let mut fixups = Vec::with_capacity(resources.len());
    for it in resources {
        fixups.push((out.len() as u32, data.len() as u32));
        out.put_u32(data.len() as u32);
        out.put_u32(it.data.len() as u32);
        out.put_u32(0);
        out.put_u32(0);
        data.extend_from_slice(&it.data);
        data.resize(data.len().next_multiple_of(8), 0);
    }
    (out, fixups, data)
}

/// The COFF object of `resources` (sorted, [`merge`]): `.rsrc$01` and `.rsrc$02`, as `cvtres`
/// writes one, each data entry's `OffsetToData` an `ADDR32NB` against `.rsrc$02`'s section
/// symbol with the data's offset in it as the addend.
pub(crate) fn object(resources: &[Resource]) -> Vec<u8> {
    let (directory, fixups, data) = tables(resources);
    const HEADER: usize = 20;
    const SECTION: usize = 40;
    const RELOCATION: usize = 10;
    const SYMBOL: usize = 18;
    let directory_at = HEADER + 2 * SECTION;
    let relocations_at = directory_at + directory.len();
    let data_at = relocations_at + RELOCATION * fixups.len();
    let symbols_at = data_at + data.len();
    let mut out: Vec<u8> = Vec::with_capacity(symbols_at + 4 * SYMBOL + 4);
    out.put_u16(object::pe::IMAGE_FILE_MACHINE_AMD64.0);
    out.put_u16(2);
    out.put_u32(0);
    out.put_u32(symbols_at as u32);
    out.put_u32(4);
    out.put_u16(0);
    out.put_u16(0);
    let flags = (object::pe::IMAGE_SCN_CNT_INITIALIZED_DATA | object::pe::IMAGE_SCN_MEM_READ).0;
    let section = |out: &mut Vec<u8>, name: &[u8; 8], size: usize, at: usize, relocs: usize, align: u32| {
        out.put_bytes(name);
        out.put_u32(0);
        out.put_u32(0);
        out.put_u32(size as u32);
        out.put_u32(at as u32);
        out.put_u32(if relocs > 0 { relocations_at as u32 } else { 0 });
        out.put_u32(0);
        out.put_u16(relocs as u16);
        out.put_u16(0);
        out.put_u32(flags | align);
    };
    section(&mut out, b".rsrc$01", directory.len(), directory_at, fixups.len(), object::pe::IMAGE_SCN_ALIGN_4BYTES.0);
    section(&mut out, b".rsrc$02", data.len(), data_at, 0, object::pe::IMAGE_SCN_ALIGN_8BYTES.0);
    let mut directory = directory;
    for &(at, addend) in &fixups {
        directory[at as usize..at as usize + 4].copy_from_slice(&addend.to_le_bytes());
    }
    out.extend_from_slice(&directory);
    for &(at, _) in &fixups {
        out.put_u32(at);
        // `.rsrc$02`'s section symbol.
        out.put_u32(2);
        out.put_u16(object::pe::IMAGE_REL_AMD64_ADDR32NB.0);
    }
    out.extend_from_slice(&data);
    let symbol = |out: &mut Vec<u8>, name: &[u8; 8], number: u16, size: usize, relocs: usize| {
        out.put_bytes(name);
        out.put_u32(0);
        out.put_u16(number);
        out.put_u16(0);
        out.put_u8(object::pe::IMAGE_SYM_CLASS_STATIC.0);
        out.put_u8(1);
        // The section definition: its length, relocations, line numbers, checksum, number,
        // selection.
        out.put_u32(size as u32);
        out.put_u16(relocs as u16);
        out.put_u16(0);
        out.put_u32(0);
        out.put_u16(0);
        out.put_u8(0);
        out.put_bytes(&[0; 3]);
    };
    symbol(&mut out, b".rsrc$01", 1, directory.len(), fixups.len());
    symbol(&mut out, b".rsrc$02", 2, data.len(), 0);
    out.put_u32(4);
    out
}

#[cfg(test)]
mod tests;
