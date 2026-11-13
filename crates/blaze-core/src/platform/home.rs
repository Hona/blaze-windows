//! Where blaze keeps what is no checkout's own: the one place each of its directories is found,
//! from the environment a caller reads (`var`, so a test gives a table and a daemon its
//! client's).
//!
//! - **The root**: the daemon's state (`v2/`), the build directories (`build/`) and the fetched
//!   packages (`sources/`). A cache: the user may delete it.
//! - **The home**: what blaze installs and what its user says (`config.toml`, `versions/`,
//!   `toolchains/`, `native/`, `pins/`).
//! - **The socket**: where the daemon listens.
//! - **The machine's**: what every daemon of the user shares whatever its `BLAZE_HOME` (the
//!   standard library's shared store), when it is on the root's volume.
//!
//! `BLAZE_HOME` names one directory that is all of them. Without it:
//!
//! | | Unix | Windows |
//! |---|---|---|
//! | root | `$XDG_CACHE_HOME/blaze`, else `$HOME/.cache/blaze` | `%LOCALAPPDATA%\blaze` |
//! | home | `$HOME/.blaze` | `%LOCALAPPDATA%\blaze` |
//! | socket | `$XDG_RUNTIME_DIR/blaze/v2.sock`, else `<root>/v2.sock` | `<root>\v2.sock` |
//! | machine's | the root, as named without `BLAZE_HOME` | the root, as named without `BLAZE_HOME` |
//!
//! On Windows `%LOCALAPPDATA%` is where a user's caches go (not roamed, not synced by OneDrive),
//! and `HOME` is not read: Git Bash sets one that is not the profile, and a shell of each kind
//! must find one daemon. An empty variable is unset.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

/// What the environment says of blaze's directories ([`homes`]). Each absolute when the
/// variables that name it are.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Homes {
    pub root: PathBuf,
    pub home: PathBuf,
    pub socket: PathBuf,
    /// The directory the user's daemons share, whatever their `BLAZE_HOME`: none where only
    /// `BLAZE_HOME` is set (a daemon then shares nothing outside it).
    pub machine: Option<PathBuf>,
    /// `BLAZE_HOME`, when it named them all.
    pub named: bool,
}

/// [`Homes`] of the environment `var` reads, or why none: the variable it needed.
pub fn homes(var: impl Fn(&str) -> Option<OsString>) -> Result<Homes, String> {
    let set = |name: &str| var(name).filter(|it| !it.is_empty()).map(PathBuf::from);
    if let Some(home) = set("BLAZE_HOME") {
        let socket = home.join("v2.sock");
        let machine = machine(&set).ok();
        return Ok(Homes { root: home.clone(), home, socket, machine, named: true });
    }
    let root = machine(&set)?;
    let (home, socket) = (user_home(&set)?, socket(&set, &root)?);
    Ok(Homes { machine: Some(root.clone()), root, home, socket, named: false })
}

/// The root as it is without `BLAZE_HOME`: the machine's directory.
#[cfg(windows)]
fn machine(set: &impl Fn(&str) -> Option<PathBuf>) -> Result<PathBuf, String> {
    let local = set("LOCALAPPDATA")
        .ok_or("no BLAZE_HOME or LOCALAPPDATA says where blaze keeps its state and builds")?;
    Ok(local.join("blaze"))
}

#[cfg(not(windows))]
fn machine(set: &impl Fn(&str) -> Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(caches) = set("XDG_CACHE_HOME") {
        return Ok(caches.join("blaze"));
    }
    let home = set("HOME").ok_or(
        "no BLAZE_HOME, XDG_CACHE_HOME or HOME says where blaze keeps its state and builds",
    )?;
    Ok(home.join(".cache").join("blaze"))
}

#[cfg(windows)]
fn user_home(set: &impl Fn(&str) -> Option<PathBuf>) -> Result<PathBuf, String> {
    machine(set)
}

#[cfg(not(windows))]
fn user_home(set: &impl Fn(&str) -> Option<PathBuf>) -> Result<PathBuf, String> {
    let home = set("HOME").ok_or("no BLAZE_HOME or HOME says where blaze's home is")?;
    Ok(home.join(".blaze"))
}

#[cfg(windows)]
fn socket(_: &impl Fn(&str) -> Option<PathBuf>, root: &Path) -> Result<PathBuf, String> {
    Ok(root.join("v2.sock"))
}

#[cfg(not(windows))]
fn socket(set: &impl Fn(&str) -> Option<PathBuf>, _: &Path) -> Result<PathBuf, String> {
    if let Some(runtime) = set("XDG_RUNTIME_DIR") {
        return Ok(runtime.join("blaze").join("v2.sock"));
    }
    let home = set("HOME").ok_or("no BLAZE_HOME, XDG_RUNTIME_DIR or HOME says where the daemon's socket is")?;
    Ok(home.join(".cache").join("blaze").join("v2.sock"))
}

/// [`homes`] of this process's environment, each made absolute against the current directory
/// (a relative `BLAZE_HOME` is taken as cargo takes a relative `CARGO_HOME`).
pub fn process() -> Result<Homes, String> {
    let homes = homes(|name| std::env::var_os(name))?;
    let absolute = |dir: PathBuf| {
        std::path::absolute(&dir).map_err(|error| {
            format!("blaze's directory {} against the current directory: {error}", dir.display())
        })
    };
    Ok(Homes {
        root: absolute(homes.root)?,
        home: absolute(homes.home)?,
        socket: absolute(homes.socket)?,
        machine: homes.machine.map(absolute).transpose()?,
        named: homes.named,
    })
}

#[cfg(test)]
mod tests;
