use std::path::{Path, PathBuf};

use super::*;

/// The directories the tests ask of: the system's temporary directory, this crate's checkout,
/// and each of `BLAZE_TEST_VOLUMES` (paths split as `PATH` is), for a machine with a volume of
/// the other kind (on Windows, a Dev Drive beside an NTFS `C:`).
fn dirs() -> Vec<PathBuf> {
    let mut dirs = vec![std::env::temp_dir(), PathBuf::from(env!("CARGO_MANIFEST_DIR"))];
    if let Some(more) = std::env::var_os("BLAZE_TEST_VOLUMES") {
        dirs.extend(std::env::split_paths(&more).filter(|it| !it.as_os_str().is_empty()));
    }
    dirs
}

/// A clone of a real file, as the native driver makes one for `Effect::Clone`.
fn clone(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(windows)]
    return crate::iocp::files::clone(from, to);
    #[cfg(unix)]
    return crate::fs::clone(from, to);
}

/// The invariant: what [`volume`] says of a directory's volume is what a clone there does. A
/// volume it says shares blocks takes a clone of a file there and the clone holds the file's
/// bytes; one it says shares none refuses the clone as a file system that cannot share
/// (`ErrorKind::Unsupported`), the refusal the store would meet had it asked.
#[test]
fn a_volume_is_said_to_share_blocks_exactly_where_a_clone_there_works() {
    for dir in dirs() {
        let said = volume(&dir).unwrap();
        eprintln!("{}: {} ({})", dir.display(), said.system, said.sharing.name());
        let scratch = dir.join(format!(".blaze-volume-test.{}", std::process::id()));
        std::fs::create_dir_all(&scratch).unwrap();
        let (from, to) = (scratch.join("from"), scratch.join("to"));
        // Past a whole cluster: the clone is in whole clusters, the file's length is not.
        let bytes: Vec<u8> = (0..(256u32 << 10) + 123).map(|it| (it * 31 % 251) as u8).collect();
        std::fs::write(&from, &bytes).unwrap();
        let cloned = clone(&from, &to);
        let held = std::fs::read(&to).ok();
        std::fs::remove_dir_all(&scratch).unwrap();
        match said.sharing {
            Sharing::Blocks => {
                cloned.unwrap_or_else(|error| panic!("{}: {said:?}, yet {error}", dir.display()));
                assert!(held.as_deref() == Some(&bytes[..]), "{}: the clone's bytes", dir.display());
            }
            Sharing::Unshared => {
                let error = cloned.expect_err(&format!("{}: {said:?}, yet a clone worked", dir.display()));
                assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{}: {error}", dir.display());
            }
        }
    }
}

/// A path not made yet is on its nearest existing ancestor's volume, and asking leaves nothing
/// behind in the directory asked of.
#[test]
fn a_missing_directory_is_on_its_parents_volume_and_the_question_leaves_nothing() {
    for dir in dirs() {
        let scratch = dir.join(format!(".blaze-volume-test-missing.{}", std::process::id()));
        std::fs::create_dir_all(&scratch).unwrap();
        let parent = volume(&scratch).unwrap();
        let missing = volume(&scratch.join("not/made/yet")).unwrap();
        let left: Vec<_> = std::fs::read_dir(&scratch).unwrap().collect();
        std::fs::remove_dir_all(&scratch).unwrap();
        assert_eq!(missing, parent, "{}", dir.display());
        assert!(left.is_empty(), "{}: the question left {left:?}", dir.display());
    }
}

/// A hard link is the file it links (one id), a copy of it is another file, and the volume of
/// each is the directory's.
#[test]
fn a_hard_link_has_its_files_id_and_a_copy_has_its_own() {
    for dir in dirs() {
        let scratch = dir.join(format!(".blaze-volume-test-id.{}", std::process::id()));
        std::fs::create_dir_all(&scratch).unwrap();
        let (file, link, copy) = (scratch.join("file"), scratch.join("link"), scratch.join("copy"));
        std::fs::write(&file, b"blaze").unwrap();
        std::fs::hard_link(&file, &link).unwrap();
        std::fs::copy(&file, &copy).unwrap();
        let ids = [&file, &link, &copy, &scratch].map(|it| file_id(it).unwrap());
        std::fs::remove_dir_all(&scratch).unwrap();
        assert_eq!(ids[0], ids[1], "{}: a link is its file", dir.display());
        assert_ne!(ids[0], ids[2], "{}: a copy is a file of its own", dir.display());
        assert!(ids.iter().all(|it| it.volume == ids[3].volume), "{}: one volume", dir.display());
    }
}