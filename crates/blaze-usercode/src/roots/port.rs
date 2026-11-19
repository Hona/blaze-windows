//! A build's directories as the front end writes paths against them ([`base_db::Port`]): the
//! one port of every value the front end stores, here, inside the front end's code identity
//! (`blaze_codegen_code::FRONT_END`), because what it writes is in the bytes of every record
//! the front end keeps. blaze-cargo's `portable::Places` is this, with what a unit's record key
//! adds (how the roots sit, the key a record tied to them is kept under).

use std::borrow::Cow;

use blaze_core::platform::path::DaemonPath;

use super::{Role, Roots, sort_host_roots};

/// What starts a path in a package id (`path+file:///w/p#0.1.0`): the root after it starts
/// no path as [`Roots::port`] reads one (a `/` is before it), so a string is ported in the
/// pieces these end.
const URL: &[u8] = b"file://";

/// The directories of one build, each by what it is, owned: what its paths are written
/// against.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Dirs {
    roots: Vec<(Role, String)>,
    /// On Windows, the native host-path spelling (`C:\Users\a\w`) of each root that maps to a
    /// host volume, sorted longest first (ties by role), for `\0h<tag>` porting and leak scans.
    /// Empty on Unix.
    host_roots: Vec<(Role, String)>,
}

impl Dirs {
    /// The directories `given` names as daemon paths (`/home/a/w`, `/C:/Users/a/w`); one that
    /// is none, not a valid daemon name, or a volume root (`/`, `/C:`, `/UNC/server/share`) is
    /// no root: what is under it stays as it is.
    pub fn new<'a>(given: impl IntoIterator<Item = (Role, Option<&'a str>)>) -> Dirs {
        Dirs::from_daemon(
            given
                .into_iter()
                .map(|(role, path)| (role, path.and_then(DaemonPath::parse))),
        )
    }

    /// Typed form of [`Dirs::new`] taking validated [`DaemonPath`]s directly.
    pub fn from_daemon<'a>(given: impl IntoIterator<Item = (Role, Option<DaemonPath<'a>>)>) -> Dirs {
        // alloc: once per build's directories, a root each
        let mut roots: Vec<(Role, String)> = Vec::new();
        for (role, path) in given {
            let Some(path) = path.map(DaemonPath::trim_end_slash).filter(|it| !it.is_volume_root())
            else {
                continue;
            };
            match roots.iter_mut().find(|it| it.0 == role) {
                Some(existing) => existing.1 = path.as_str().to_owned(), // alloc: as above
                None => roots.push((role, path.as_str().to_owned())),    // alloc: as above
            }
        }
        let mut host_roots = Vec::new();
        for (role, path) in &roots {
            if let Some(host) = DaemonPath::parse(path).and_then(DaemonPath::host_spelling) {
                host_roots.push((*role, host));
            }
        }
        sort_host_roots(&mut host_roots);
        Dirs { roots, host_roots }
    }

    /// The roots, lent.
    pub fn view(&self) -> Roots<'_> {
        Roots::daemon_with_host(
            self.roots.iter().filter_map(|(role, path)| Some((*role, DaemonPath::parse(path)?))),
            &self.host_roots,
        )
    }

    /// Each root, by what it is, in the order given.
    pub fn roots(&self) -> impl Iterator<Item = (Role, &str)> {
        self.roots.iter().map(|(role, path)| (*role, path.as_str()))
    }

    /// `text` with each root that starts a path in it as its placeholder ([`Roots::port`]), a
    /// root after `file://` among them: lent when it holds none.
    pub fn text<'t>(&self, text: &'t [u8]) -> Cow<'t, [u8]> {
        let roots = self.view();
        if !text.windows(URL.len()).any(|it| it == URL) {
            return roots.ported(text);
        }
        // alloc: a string that names a file by URL (a path package's id), once as it is keyed
        let mut out = Vec::with_capacity(text.len());
        let mut rest = text;
        while let Some(at) = rest.windows(URL.len()).position(|it| it == URL) {
            let (head, tail) = rest.split_at(at + URL.len());
            roots.port(head, |piece| out.extend_from_slice(piece));
            rest = tail;
        }
        roots.port(rest, |piece| out.extend_from_slice(piece));
        Cow::Owned(out)
    }

    /// What `text`, written by [`Dirs::text`] in some build, is in this one: each placeholder
    /// this build's root. An error for a placeholder of a root this build has none of.
    pub fn real<'t>(&self, text: &'t [u8]) -> Result<Cow<'t, [u8]>, String> {
        self.view().unport(text).map_err(|why| why.to_string())
    }
}

impl base_db::Port for Dirs {
    fn ported<'b>(&self, bytes: &'b [u8]) -> Cow<'b, [u8]> {
        self.text(bytes)
    }

    fn placed<'b>(&self, bytes: &'b [u8]) -> Result<Cow<'b, [u8]>, String> {
        self.real(bytes)
    }

    /// The one searcher of a root left in bytes (`Roots::embedded`).
    fn held(&self, bytes: &[u8]) -> Option<&'static str> {
        self.view().embedded(bytes).iter().next().map(Role::name)
    }
}
