use super::{Id, Resource, merge, object, read};

/// `tests/pe_run/app.res` and `more.res`, as `rc.exe` 10.0.26100 compiles them (`build.ps1`).
const APP: &[u8] = include_bytes!("../../tests/pe_run/app.res");
const MORE: &[u8] = include_bytes!("../../tests/pe_run/more.res");

fn name(it: &str) -> Id {
    Id::Name(it.encode_utf16().collect())
}

#[test]
fn a_res_files_resources_are_read_in_order() {
    let app = read("app.res", APP).unwrap();
    let kinds: Vec<(&Id, &Id, u16)> = app.iter().map(|it| (&it.kind, &it.name, it.language)).collect();
    assert_eq!(
        kinds,
        [
            (&Id::Number(3), &Id::Number(1), 0x409),
            (&Id::Number(14), &Id::Number(1), 0x409),
            (&Id::Number(24), &Id::Number(1), 0x409),
            (&Id::Number(10), &name("BLOB"), 0x409),
            (&Id::Number(16), &Id::Number(1), 0x409),
        ]
    );
    assert_eq!(app[3].data, b"blob data\0");
    let more = read("more.res", MORE).unwrap();
    assert!(more.iter().all(|it| it.language == 0x407), "{more:?}");
    assert!(read("x.res", &APP[..APP.len() - 3]).unwrap_err().contains("past the end"));
    assert!(read("x.res", b"MZ").unwrap_err().contains("not a compiled resource file"));
}

#[test]
fn merged_resources_are_sorted_as_the_directory_lists_them_and_a_repeat_is_an_error() {
    let res = |kind, name, language| Resource { kind, name, language, data: vec![1] };
    let merged = merge(vec![
        ("a.res".into(), vec![res(Id::Number(10), Id::Number(7), 1), res(name("b"), Id::Number(1), 1)]),
        ("b.res".into(), vec![res(Id::Number(10), name("Z"), 1), res(Id::Number(3), Id::Number(1), 1), res(Id::Number(10), name("a"), 2)]),
    ])
    .unwrap();
    let order: Vec<(&Id, &Id)> = merged.iter().map(|it| (&it.kind, &it.name)).collect();
    assert_eq!(
        order,
        [
            (&name("b"), &Id::Number(1)),
            (&Id::Number(3), &Id::Number(1)),
            (&Id::Number(10), &name("a")),
            (&Id::Number(10), &name("Z")),
            (&Id::Number(10), &Id::Number(7)),
        ],
        "names before numbers, names without case"
    );
    let error = merge(vec![
        ("a.res".into(), vec![res(Id::Number(24), Id::Number(1), 0x409)]),
        ("b.res".into(), vec![res(Id::Number(24), Id::Number(1), 0x409)]),
    ])
    .unwrap_err();
    for said in ["type 24", "name 1", "0x0409", "a.res", "b.res", "CVT1100"] {
        assert!(error.contains(said), "{said}: {error}");
    }
}

/// The object reads as a COFF object of the two sections, the data entries relocated into the
/// data section.
#[test]
fn the_resource_object_is_cvtres_shaped() {
    use object::{Object as _, ObjectSection as _};
    let merged = merge(vec![("app.res".into(), read("app.res", APP).unwrap())]).unwrap();
    let bytes = object(&merged);
    let file = object::read::coff::CoffFile::<&[u8]>::parse(&bytes[..]).unwrap();
    let names: Vec<&str> = file.sections().map(|it| it.name().unwrap()).collect();
    assert_eq!(names, [".rsrc$01", ".rsrc$02"]);
    let directory = file.sections().next().unwrap();
    assert_eq!(directory.relocations().count(), merged.len());
    let data = file.sections().nth(1).unwrap().data().unwrap();
    let total: usize = merged.iter().map(|it| it.data.len().next_multiple_of(8)).sum();
    assert_eq!(data.len(), total);
}
