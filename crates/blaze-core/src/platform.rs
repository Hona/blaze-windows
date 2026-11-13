//! What blaze asks of the operating system outside the effects a driver runs: facts of the
//! machine and of the process, one file per concern, each with its systems' arms inside it so
//! that a caller writes no `cfg` (docs/platforms.md, "The platform boundary").
//!
//! The effects ([`crate::Effect`]) stay the interface of everything a state machine does; this
//! is what a driver, the daemon or the command line has to know before it asks for them.

pub mod command;
pub mod env;
pub mod home;
#[cfg(windows)]
#[allow(unsafe_code, reason = "Win32 has the peer PID, token SID and DACL, not std")]
pub mod identity;
pub mod lock;
pub mod msvc;
pub mod path;
pub mod volume;

pub use volume::{Sharing, Volume, volume};
