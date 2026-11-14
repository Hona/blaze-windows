use std::{
    fs::{File, OpenOptions},
    io::{Read as _, Write as _},
    path::PathBuf,
};

use super::*;

fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("blaze-platform-lock-{name}-{}", std::process::id()))
}

fn open(path: &PathBuf) -> File {
    OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path).unwrap()
}

/// The invariant: a lock excludes other lockers as `flock` does, and stops no read or write of
/// the file through any handle (on Windows a lock of the file's bytes would, os error 33).
#[test]
fn a_lock_excludes_lockers_and_no_reader() {
    let path = scratch("excl");
    let mut held = open(&path);
    held.write_all(b"partial download").unwrap();
    assert!(lock(&held, Mode::Exclusive, false).unwrap());
    let other = open(&path);
    assert!(!lock(&other, Mode::Exclusive, false).unwrap(), "a second exclusive lock waits");
    assert!(!lock(&other, Mode::Shared, false).unwrap(), "and so does a shared one");
    let mut read = String::new();
    File::open(&path).unwrap().read_to_string(&mut read).unwrap();
    assert_eq!(read, "partial download", "the locked file reads through another handle");
    std::fs::read(&path).unwrap();
    unlock(&held).unwrap();
    assert!(lock(&other, Mode::Exclusive, false).unwrap(), "let go of, it is the next one's");
    unlock(&other).unwrap();
    drop((held, other));
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn shared_locks_share_and_keep_out_an_exclusive_one() {
    let path = scratch("shared");
    let (a, b, c) = (open(&path), open(&path), open(&path));
    assert!(lock(&a, Mode::Shared, false).unwrap());
    assert!(lock(&b, Mode::Shared, false).unwrap());
    assert!(!lock(&c, Mode::Exclusive, false).unwrap());
    unlock(&a).unwrap();
    unlock(&b).unwrap();
    assert!(lock(&c, Mode::Exclusive, true).unwrap());
    unlock(&c).unwrap();
    drop((a, b, c));
    std::fs::remove_file(&path).unwrap();
}
