//! The one way blaze makes a `std::process::Command` for a tool it runs itself (`git`, a
//! registry's credential process, `vswhere`): a run that is not an effect's
//! ([`crate::Effect::Spawn`], which every driver makes the same way).
//!
//! On Windows a console program started by a process that has no console (the daemon, started
//! detached) gets a console window of its own, which flashes on the user's desktop, unless it
//! is made with `CREATE_NO_WINDOW`. So every command blaze makes is made so: a tool's output is
//! read through pipes, never shown. On Unix a command is std's as it is.

use std::{ffi::OsStr, path::Path, process::Command};

/// `CREATE_NO_WINDOW` (winbase.h): the process gets no console window; one it starts that has
/// a console program's subsystem gets none either.
#[cfg(windows)]
pub const NO_WINDOW: u32 = 0x0800_0000;

/// A command of `program`, run in `dir`, made to run with no window of its own. The directory
/// is asked for, never the daemon's own, as `std::process::Command::new` is banned for.
pub fn command(program: impl AsRef<OsStr>, dir: &Path) -> Command {
    #[expect(clippy::disallowed_methods, reason = "the one place a tool's command is made")]
    let mut command = Command::new(program);
    command.current_dir(dir);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        command.creation_flags(NO_WINDOW);
    }
    command
}

#[cfg(test)]
mod tests;
