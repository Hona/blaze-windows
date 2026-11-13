//! A patch is eligible only when its prospective bytes are precisely the maker's result.
//! Compare the two streams without a buffer the size of the file. None means a run of zeros.

use std::io;

type Runs<'a> = &'a [(u64, Vec<u8>)];

fn piece<'a>(runs: &mut Runs<'a>, pos: u64, len: u64) -> (u64, Option<&'a [u8]>) {
    while let Some(((at, bytes), rest)) = runs.split_first() {
        if pos < *at {
            return (*at, None);
        }
        if let Ok(n) = usize::try_from(pos - *at)
            && n < bytes.len()
        {
            return (*at + bytes.len() as u64, Some(&bytes[n..]));
        }
        *runs = rest;
    }
    (len, None)
}

pub(crate) fn matches_patch(
    base: &[u8],
    len: u64,
    mut delta: Runs<'_>,
    mut whole: Runs<'_>,
) -> io::Result<bool> {
    for runs in [delta, whole] {
        let mut end = 0;
        for (at, bytes) in runs {
            if *at < end || at.checked_add(bytes.len() as u64).is_none_or(|stop| stop > len) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "overlapping or out-of-bounds output runs",
                ));
            }
            end = at + bytes.len() as u64;
        }
    }
    let mut pos = 0;
    while pos < len {
        let (end_patch, patch) = piece(&mut delta, pos, len);
        let (end_whole, want) = piece(&mut whole, pos, len);
        let mut end = end_patch.min(end_whole);
        let got = patch.or_else(|| {
            if pos < base.len() as u64 {
                end = end.min(base.len() as u64);
                Some(&base[pos as usize..])
            } else {
                None
            }
        });
        let n = usize::try_from(end - pos)
            .map_err(|_| io::Error::other("patch exceeds address space"))?;
        let equal = match (got, want) {
            (Some(a), Some(b)) => a[..n] == b[..n],
            (Some(a), None) | (None, Some(a)) => a[..n].iter().all(|b| *b == 0),
            (None, None) => true,
        };
        if !equal {
            return Ok(false);
        }
        pos = end;
    }
    Ok(true)
}

#[cfg(all(test, windows))]
mod tests {
    use std::{fs, io::Write as _, os::windows::fs::MetadataExt as _};
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_SPARSE_FILE;

    #[test]
    fn a_fresh_output_is_holes_and_never_truncates_someone_elses_file() {
        let path = std::env::temp_dir().join(format!("blaze-output-holes-{}", std::process::id()));
        super::super::sparse_file(&path, 64 << 20).unwrap();
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.len(), 64 << 20);
        if matches!(crate::platform::volume(&path).unwrap().system.as_str(), "NTFS" | "ReFS") {
            assert_ne!(meta.file_attributes() & FILE_ATTRIBUTE_SPARSE_FILE, 0);
        }
        let mut f = fs::File::options().write(true).open(&path).unwrap();
        f.write_all(b"written").unwrap();
        assert_eq!(
            super::super::sparse_file(&path, 0).unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(f.metadata().unwrap().len(), meta.len());
        drop(f);
        fs::remove_file(path).unwrap();
    }
}
