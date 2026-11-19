//! How edited build outputs are placed on Windows NTFS (`Sharing::Unshared`): choosing
//! between writing a fresh sparse file + atomic POSIX rename (`Route::Rename`) and taking
//! exclusive custody of the existing file to patch changed ranges in place (`Route::Patch`).
//!
//! Why this policy exists: on NTFS with Windows Defender real-time protection active,
//! opening a freshly built or executed PE image (`.exe`, `.dll`) with `dwShareMode = 0` and
//! `GENERIC_WRITE | DELETE` (`Effect::TryPatch`) can stall for ~1.0–1.6 s waiting for an
//! asynchronous `MsMpEng.exe` scan handle to close. Writing a fresh sparse staged file and
//! renaming the old image aside with `DELETE | SHARE_ALL` (`iocp::files::aside`) never takes
//! an exclusive write open on the old image, works while the old image is running, and
//! returns a vouched stamp. Non-PE side files (such as `.pdb`) do not incur PE scan stalls
//! and keep exclusive-custody patching (17–23 ms for a delta write).
//!
//! Configured once per daemon via [`VAR`] (`serve::settings::STARTED_WITH`), never read
//! ambiently inside the loop. Every placement decision records an `"ntfs edit place"` span
//! so paired A/B measurements (`auto` vs `rename` vs `patch` vs custom thresholds) are
//! directly queryable in `blaze explain` and `blaze debug sql`.

/// The daemon-lifetime environment variable selecting how edited outputs are placed on NTFS.
///
/// Accepted values (case-insensitive):
/// - unset / `auto`: Windows PE images up to [`DEFAULT_RENAME_UP_TO`] (16 MiB) use new file +
///   rename; larger images and non-PE files use exclusive-custody patching.
/// - `rename`: every edited Windows PE image uses new file + rename regardless of size
///   (non-PE files still use exclusive-custody patching).
/// - `rename-all`: every edited output on NTFS uses new file + rename.
/// - `patch`: every edited output on NTFS uses exclusive-custody patching (the baseline).
/// - `<N>`, `<N>b`, `<N>kib`, `<N>kb`, `<N>mib`, `<N>mb`: `auto` with a custom size
///   threshold in bytes (`0` selects `patch`).
pub(crate) const VAR: &str = "BLAZE_NTFS_EDIT";

/// Default size threshold for [`NtfsEdit::Auto`]: 16 MiB. Compact dev executables up to this
/// size write faster as a fresh sparse file + POSIX rename than an exclusive-custody patch
/// (which maps the whole file for verification and flushes three times), while avoiding the
/// Defender exclusive-open stall completely.
pub(crate) const DEFAULT_RENAME_UP_TO: u64 = 16 << 20;

/// Policy governing how edited outputs (`Made::Patch`) are placed on an NTFS volume.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum NtfsEdit {
    /// Place Windows PE images up to `rename_up_to` bytes by new sparse file + rename;
    /// larger images and non-PE files use exclusive-custody patching.
    Auto { rename_up_to: u64 },
    /// Always place Windows PE images by new sparse file + rename; non-PE files use
    /// exclusive-custody patching.
    Rename,
    /// Always place every edited output by new sparse file + rename.
    RenameAll,
    /// Always use exclusive-custody in-place patching (pre-B14 baseline).
    Patch,
}

impl Default for NtfsEdit {
    fn default() -> NtfsEdit {
        NtfsEdit::Auto { rename_up_to: DEFAULT_RENAME_UP_TO }
    }
}

/// Which placement mechanism an edited NTFS output takes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Route {
    /// Write a fresh sparse file and replace the target via POSIX rename (`Store::place_edit_rename`).
    Rename,
    /// Take exclusive custody of the existing file and patch changed ranges (`Store::place_edit`).
    Patch,
}

impl Route {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Route::Rename => "rename",
            Route::Patch => "patch",
        }
    }
}

/// The decision made for one edited NTFS output, with fields recorded on its tracing span.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Choice {
    pub(crate) route: Route,
    pub(crate) image: bool,
    pub(crate) reason: &'static str,
    pub(crate) policy: &'static str,
}

/// Whether `path` is a Windows PE image or executable whose exclusive write open triggers
/// Defender PE scanning (matches `blaze_core::iocp::files::image`: `.exe`, `.dll`, `.pyd`,
/// `.node`, plus any output marked `executable`).
pub(crate) fn is_windows_image(path: &str, executable: bool) -> bool {
    if executable {
        return true;
    }
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let Some((_, ext)) = name.rsplit_once('.') else {
        return false;
    };
    ["exe", "dll", "pyd", "node"].iter().any(|it| ext.eq_ignore_ascii_case(it))
}

impl NtfsEdit {
    /// Parses [`VAR`]'s value. `None` (unset) and empty/`auto` select the default policy.
    pub(crate) fn parse(value: Option<&str>) -> Result<NtfsEdit, String> {
        let Some(raw) = value else {
            return Ok(NtfsEdit::default());
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("auto") {
            return Ok(NtfsEdit::default());
        }
        if trimmed.eq_ignore_ascii_case("rename") {
            return Ok(NtfsEdit::Rename);
        }
        if trimmed.eq_ignore_ascii_case("rename-all") {
            return Ok(NtfsEdit::RenameAll);
        }
        if trimmed.eq_ignore_ascii_case("patch") {
            return Ok(NtfsEdit::Patch);
        }
        let lower = trimmed.to_ascii_lowercase();
        let (digits, scale) = if let Some(n) = lower.strip_suffix("mib").or_else(|| lower.strip_suffix("mb")) {
            (n.trim(), 1u64 << 20)
        } else if let Some(n) = lower.strip_suffix("kib").or_else(|| lower.strip_suffix("kb")) {
            (n.trim(), 1u64 << 10)
        } else if let Some(n) = lower.strip_suffix('b') {
            (n.trim(), 1u64)
        } else {
            (lower.as_str(), 1u64)
        };
        if let Ok(count) = digits.parse::<u64>()
            && let Some(bytes) = count.checked_mul(scale)
        {
            return Ok(if bytes == 0 { NtfsEdit::Patch } else { NtfsEdit::Auto { rename_up_to: bytes } });
        }
        // alloc: error text, once at daemon start or drift check
        Err(format!(
            "{VAR}={raw:?}: expected `auto`, `rename`, `rename-all`, `patch`, or a size threshold \
             such as `16mib`, `4096kib`, or `0`"
        ))
    }

    /// Chooses the NTFS edit placement route for `path` (`file_len` logical bytes).
    pub(crate) fn choose(self, path: &str, executable: bool, file_len: u64) -> Choice {
        let image = is_windows_image(path, executable);
        match self {
            NtfsEdit::Patch => Choice { route: Route::Patch, image, reason: "forced_patch", policy: "patch" },
            NtfsEdit::RenameAll => {
                Choice { route: Route::Rename, image, reason: "forced_rename_all", policy: "rename-all" }
            }
            NtfsEdit::Rename if image => {
                Choice { route: Route::Rename, image, reason: "forced_rename", policy: "rename" }
            }
            NtfsEdit::Rename => Choice { route: Route::Patch, image, reason: "non_image", policy: "rename" },
            NtfsEdit::Auto { .. } if !image => {
                Choice { route: Route::Patch, image, reason: "non_image", policy: "auto" }
            }
            NtfsEdit::Auto { rename_up_to } if file_len <= rename_up_to => {
                Choice { route: Route::Rename, image, reason: "small_image", policy: "auto" }
            }
            NtfsEdit::Auto { .. } => {
                Choice { route: Route::Patch, image, reason: "large_image", policy: "auto" }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_modes_and_refuses_unknown_values() {
        assert_eq!(NtfsEdit::parse(None), Ok(NtfsEdit::Auto { rename_up_to: DEFAULT_RENAME_UP_TO }));
        assert_eq!(NtfsEdit::parse(Some("")), Ok(NtfsEdit::Auto { rename_up_to: DEFAULT_RENAME_UP_TO }));
        assert_eq!(NtfsEdit::parse(Some("AUTO")), Ok(NtfsEdit::Auto { rename_up_to: DEFAULT_RENAME_UP_TO }));
        assert_eq!(NtfsEdit::parse(Some("16mib")), Ok(NtfsEdit::Auto { rename_up_to: DEFAULT_RENAME_UP_TO }));
        assert_eq!(NtfsEdit::parse(Some("32MiB")), Ok(NtfsEdit::Auto { rename_up_to: 32 << 20 }));
        assert_eq!(NtfsEdit::parse(Some("512kib")), Ok(NtfsEdit::Auto { rename_up_to: 512 << 10 }));
        assert_eq!(NtfsEdit::parse(Some("4096b")), Ok(NtfsEdit::Auto { rename_up_to: 4096 }));
        assert_eq!(NtfsEdit::parse(Some("8192")), Ok(NtfsEdit::Auto { rename_up_to: 8192 }));
        assert_eq!(NtfsEdit::parse(Some("0")), Ok(NtfsEdit::Patch));
        assert_eq!(NtfsEdit::parse(Some("0mib")), Ok(NtfsEdit::Patch));
        assert_eq!(NtfsEdit::parse(Some("patch")), Ok(NtfsEdit::Patch));
        assert_eq!(NtfsEdit::parse(Some("rename")), Ok(NtfsEdit::Rename));
        assert_eq!(NtfsEdit::parse(Some("rename-all")), Ok(NtfsEdit::RenameAll));

        for bad in ["bogus", "-1", "16gib", "99999999999999999999mib"] {
            let err = NtfsEdit::parse(Some(bad)).unwrap_err();
            assert!(err.contains(VAR) && err.contains(bad), "{bad}: {err}");
        }
    }

    #[test]
    fn detects_windows_pe_images_without_catching_side_files() {
        assert!(is_windows_image("/w/target/debug/hello.exe", true));
        assert!(is_windows_image("/w/target/debug/build_script_build.EXE", false));
        assert!(is_windows_image(r"C:\w\target\debug\rune_www.dll", false));
        assert!(is_windows_image("/w/target/debug/mod.pyd", false));
        assert!(is_windows_image("/w/target/debug/addon.node", false));
        assert!(is_windows_image("/w/target/debug/app", true));

        assert!(!is_windows_image("/w/target/debug/hello.pdb", false));
        assert!(!is_windows_image("/w/target/debug/rune_www.dll.pdb", false));
        assert!(!is_windows_image("/w/target/debug/rune_www.dll.lib", false));
        assert!(!is_windows_image("/w/target/debug/hello.exe.d", false));
        assert!(!is_windows_image("/w/target/debug/libfoo.rlib", false));
    }

    #[test]
    fn auto_renames_small_images_and_patches_large_images_and_side_files() {
        let auto = NtfsEdit::default();
        let small = auto.choose("/w/target/debug/hello.exe", true, 4 << 20);
        assert_eq!((small.route, small.image, small.reason), (Route::Rename, true, "small_image"));

        let exact = auto.choose("/w/target/debug/hello.exe", true, DEFAULT_RENAME_UP_TO);
        assert_eq!((exact.route, exact.reason), (Route::Rename, "small_image"));

        let dll = auto.choose("/w/target/debug/rune_www.dll", false, 8 << 20);
        assert_eq!((dll.route, dll.image, dll.reason), (Route::Rename, true, "small_image"));

        let large = auto.choose("/w/target/debug/opencode-desktop.exe", true, 175 << 20);
        assert_eq!((large.route, large.image, large.reason), (Route::Patch, true, "large_image"));

        let pdb = auto.choose("/w/target/debug/hello.pdb", false, 2 << 20);
        assert_eq!((pdb.route, pdb.image, pdb.reason), (Route::Patch, false, "non_image"));

        let forced_rename = NtfsEdit::Rename.choose("/w/target/debug/opencode-desktop.exe", true, 175 << 20);
        assert_eq!((forced_rename.route, forced_rename.reason), (Route::Rename, "forced_rename"));
        let rename_pdb = NtfsEdit::Rename.choose("/w/target/debug/hello.pdb", false, 2 << 20);
        assert_eq!((rename_pdb.route, rename_pdb.reason), (Route::Patch, "non_image"));

        let rename_all_pdb = NtfsEdit::RenameAll.choose("/w/target/debug/hello.pdb", false, 2 << 20);
        assert_eq!((rename_all_pdb.route, rename_all_pdb.reason), (Route::Rename, "forced_rename_all"));

        let forced_patch = NtfsEdit::Patch.choose("/w/target/debug/hello.exe", true, 2 << 20);
        assert_eq!((forced_patch.route, forced_patch.reason), (Route::Patch, "forced_patch"));
    }
}
