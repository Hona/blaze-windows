//! What a process in a sandboxed run tells its launcher of what it read, where the launcher
//! can't see it (Windows: no call of a process in the AppContainer is traced), and the check
//! that every process of the run told.
//!
//! The launcher makes a message-mode pipe outside the container and hands its write end to the
//! program, inheritably, named in [`VAR`]: every process the program starts inherits it with
//! the variable. A process that knows what it reads (blaze's own `RUSTC` stand-in, `as_rustc`)
//! writes one message as it ends ([`tell`]): [`HEAD`], its process number and the number of
//! its console's host, then its reads as the record's lines ([`trace::Line`]). One write is one
//! message, so messages of processes ending at once never interleave.
//!
//! The kernel counts every process that ever entered the run's job
//! (`JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::TotalProcesses`), whether it is still there or
//! not, and a count is never lost as a job's notifications may be. The run's trace is whole
//! only when every one of them is accounted for ([`accounted`]): it told, or it is the host of
//! a teller's console. Anything else is an `X` line: the run is not whole and is never kept as
//! if it were (rule 3).
//!
//! The console host: Windows gives each console a `conhost.exe` and puts it in the job of the
//! process the console is made for, started by no process of the run's and running none of its
//! code; it reads nothing on the run's behalf. A program started with `CREATE_NO_WINDOW` and
//! every console program it starts share one console, so one host. It never tells, so a
//! process that tells names its console's host (`ProcessConsoleHostProcess`), and a host so
//! named is accounted for. A host no teller names (that of a console a child made of its own,
//! or that of the program, which tells nothing until blaze observes it) is one more process
//! that told nothing: the run is not whole, never wrongly whole.
//!
//! Trust: a process tells honestly. The pipe stops nothing in the run from writing a message
//! that names reads it never made, or none of those it made; what it bounds is a process that
//! says nothing, or never runs blaze's code at all. A run's own code is trusted this way for
//! the run's key alone, never for a record another machine reads unverified.

#![deny(unsafe_code)]

use blaze_usercode::trace::{self, Seen};

/// The variable naming, to the program and every process it starts, the handle of the pipe it
/// tells its launcher on, in hex (`0x1a4`).
pub const VAR: &str = "__BLAZE_TOLD";

/// What a message starts with: the format and its version.
pub const HEAD: &str = "blaze told 1";

/// The most bytes the processes of one run may tell: a bound on what the launcher holds
/// (rule 18). A run that tells more is not whole.
pub const MOST: usize = 16 << 20;

/// One process's message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Told {
    /// Its process number.
    pub process: u32,
    /// The process number of its console's host, when it has a console.
    pub console: Option<u32>,
    /// What it read, as the record's lines.
    pub lines: Vec<trace::Line>,
}

impl Told {
    /// The message, as one write sends it.
    pub fn encode(&self) -> Vec<u8> {
        let mut text = format!("{HEAD}\t{}\t{}\n", self.process, self.console.unwrap_or(0)); // alloc: the message, once a process
        for line in &self.lines {
            text.push_str(&line.text());
        }
        text.into_bytes()
    }

    /// The message `bytes` are, or why not.
    pub fn decode(bytes: &[u8]) -> Result<Told, String> {
        let text = std::str::from_utf8(bytes).map_err(|_| "a message that is not UTF-8".to_owned())?; // alloc: error path
        let (head, rest) = text.split_once('\n').ok_or_else(|| "a message with no line".to_owned())?; // alloc: error path
        let mut parts = head.split('\t');
        let (Some(HEAD), Some(process), Some(console), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            let shown: String = head.chars().take(200).collect();
            return Err(format!("a message whose first line is not `{HEAD}`, a process and its console's host: {shown:?}")); // alloc: error path
        };
        let number = |it: &str| {
            it.parse::<u32>().map_err(|_| format!("a message naming process {it:?}, not a number")) // alloc: error path
        };
        let process = number(process)?;
        if process == 0 {
            return Err("a message naming process 0".to_owned()); // alloc: error path
        }
        let console = Some(number(console)?).filter(|it| *it != 0);
        let (lines, used) = trace::parse(rest).map_err(|it| it.to_string())?;
        if used != rest.len() {
            return Err(format!("the message of process {process} ends in a line cut short")); // alloc: error path
        }
        Ok(Told { process, console, lines })
    }
}

/// Whether the processes that told, `told`, are all of the `total` the run's job ever held:
/// each told once, or is the host of a teller's console. `Err` names what is missing, for the
/// run's `X` line.
pub fn accounted(total: u32, told: &[Told]) -> Result<(), String> {
    let mut tellers: Vec<u32> = told.iter().map(|it| it.process).collect(); // alloc: once a run that told
    tellers.sort_unstable();
    if let Some(twice) = tellers.windows(2).find(|it| it[0] == it[1]) {
        // A process that tells twice, or a number the job gave a second process once the first
        // ended: either way, which of them told what is not known.
        return Err(format!("process {} told twice", twice[0])); // alloc: error path
    }
    let mut hosts: Vec<u32> = told
        .iter()
        .filter_map(|it| it.console)
        .filter(|it| tellers.binary_search(it).is_err())
        .collect(); // alloc: once a run that told
    hosts.sort_unstable();
    hosts.dedup();
    let known = (tellers.len() + hosts.len()) as u64;
    match known.cmp(&u64::from(total)) {
        std::cmp::Ordering::Equal => Ok(()),
        std::cmp::Ordering::Less => Err(format!(
            "{} of the {total} processes in the run's job told nothing of what they read",
            u64::from(total) - known
        )), // alloc: error path
        std::cmp::Ordering::Greater => Err(format!(
            "{} processes told or were named as a console's host, and the run's job held {total}",
            known
        )), // alloc: error path
    }
}

/// The lines a run's record gets of what its processes told: each one's lines, then an `X`
/// line for each message that is not one (`refused`), and one when not every process of the
/// job is accounted for ([`accounted`]). `failed` is why the launcher could not hear them all
/// (a read that failed, more than [`MOST`]), which makes the run not whole either.
pub fn lines(total: u32, told: &[Told], refused: &[String], failed: Option<&str>) -> Vec<trace::Line> {
    let mut out: Vec<trace::Line> = told.iter().flat_map(|it| it.lines.iter().cloned()).collect(); // alloc: the record's lines, once a run
    for why in refused {
        out.push(trace::Line::new(Seen::Incomplete, "", &format!("a process told its launcher {why}"))); // alloc: as above
    }
    if let Some(why) = failed {
        out.push(trace::Line::new(Seen::Incomplete, "", &format!("what the run's processes told: {why}"))); // alloc: as above
    }
    if let Err(why) = accounted(total, told) {
        out.push(trace::Line::new(Seen::Incomplete, "", &why));
    }
    out
}

/// What a process that tells reads, noted as it reads it, for [`Reads::tell`]. Shared by the
/// threads that read (a probe's front end reads on more than one). Notes nothing in a process
/// no launcher hears ([`VAR`] unset), which then tells nothing.
pub struct Reads(Option<blaze_core::lock::Lock<Vec<trace::Line>>>);

impl std::fmt::Debug for Reads {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Some(noted) => write!(f, "Reads({} noted)", noted.lock().len()),
            None => f.write_str("Reads(unheard)"),
        }
    }
}

impl Default for Reads {
    fn default() -> Reads {
        let heard = std::env::var_os(VAR).is_some();
        Reads(heard.then(|| blaze_core::lock::Lock::new("sandbox.told.reads", Vec::new())))
    }
}

impl Reads {
    /// A file `path` opened to read.
    pub fn read(&self, path: &std::path::Path) {
        self.note(Seen::Read, path);
    }

    /// A path only looked at, there or not.
    pub fn looked(&self, path: &std::path::Path) {
        self.note(Seen::Looked, path);
    }

    /// A directory listed.
    pub fn listed(&self, path: &std::path::Path) {
        self.note(Seen::Listed, path);
    }

    fn note(&self, seen: Seen, path: &std::path::Path) {
        let Some(lines) = &self.0 else { return };
        let line = match std::path::absolute(path).ok().as_deref().and_then(std::path::Path::to_str) {
            Some(text) => trace::Line::new(seen, "", text),
            // A path a line can't hold: the message says the process's reads are not all known.
            None => trace::Line::new(Seen::Incomplete, "", "a path that is not UTF-8, or not made absolute"),
        };
        lines.lock().push(line);
    }

    /// Tells the launcher what was read, after the line that the whole environment was ([`tell`]);
    /// `Ok(false)` in a process no launcher hears.
    pub fn tell(&self) -> Result<bool, String> {
        let Some(noted) = &self.0 else { return Ok(false) };
        let noted = noted.lock();
        let mut lines = Vec::with_capacity(1 + noted.len()); // alloc: the message's lines, once
        lines.push(trace::Line::new(Seen::Env, "", trace::ALL_ENV));
        lines.extend(noted.iter().cloned());
        drop(noted);
        lines.sort();
        lines.dedup();
        tell(lines)
    }
}

/// Tells this process's launcher `lines`, what it read, in one message, when it was started in
/// a sandbox that hears it ([`VAR`] set); `Ok(false)` when it was not. A message that can't be
/// sent is an error: the run is then not whole, as the launcher finds this process untold.
pub fn tell(lines: Vec<trace::Line>) -> Result<bool, String> {
    let Some(named) = std::env::var_os(VAR) else { return Ok(false) };
    let named = named.to_str().and_then(|it| it.strip_prefix("0x")).and_then(|it| u64::from_str_radix(it, 16).ok());
    let Some(handle) = named else {
        return Err(format!("{VAR} is not a handle in hex")); // alloc: error path
    };
    #[cfg(windows)]
    {
        let told = Told { process: std::process::id(), console: super::windows::console_host(), lines };
        super::windows::tell(handle, &told.encode())?;
        Ok(true)
    }
    #[cfg(not(windows))]
    {
        _ = (handle, lines);
        Err(format!("{VAR} is set, and only a Windows launcher hears what a process tells")) // alloc: error path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn told(process: u32, console: Option<u32>) -> Told {
        Told { process, console, lines: vec![trace::Line::new(Seen::Read, "", "C:\\p\\probe.rs")] }
    }

    #[test]
    fn a_message_is_decoded_as_it_was_encoded() {
        let it = Told {
            process: 4242,
            console: Some(17),
            lines: vec![
                trace::Line::new(Seen::Env, "", trace::ALL_ENV),
                trace::Line::new(Seen::Read, "", "C:\\w\\out\\probe.rs"),
                trace::Line::new(Seen::Listed, "", "C:\\lib\\core"),
            ],
        };
        assert_eq!(Told::decode(&it.encode()), Ok(it.clone()));
        let none = Told { console: None, ..it };
        assert_eq!(Told::decode(&none.encode()), Ok(none));
    }

    #[test]
    fn a_message_not_whole_or_not_ours_is_refused() {
        let whole = told(9, None).encode();
        assert!(Told::decode(&whole[..whole.len() - 1]).is_err(), "a last line cut short");
        assert!(Told::decode(b"blaze told 2\t9\t0\n").is_err(), "another version");
        assert!(Told::decode(b"blaze told 1\t0\t0\n").is_err(), "process 0");
        assert!(Told::decode(b"blaze told 1\t9\n").is_err(), "no console field");
        assert!(Told::decode(b"blaze told 1\t9\t0\nQ\t\tx\n").is_err(), "a line that is no line");
        assert_eq!(Told::decode(b"blaze told 1\t9\t0\n").map(|it| it.lines.len()), Ok(0));
    }

    #[test]
    fn a_job_is_accounted_for_only_when_each_process_told_or_hosts_a_tellers_console() {
        // The stand-in run as the program, alone: one process, which told.
        assert_eq!(accounted(1, &[told(10, None)]), Ok(()));
        // It and its console's host, which it names.
        assert_eq!(accounted(2, &[told(10, Some(11))]), Ok(()));
        // Two probes on one console: the host is counted once.
        assert_eq!(accounted(3, &[told(10, Some(11)), told(12, Some(11))]), Ok(()));
        // A build script (which tells nothing yet), its console's host and two probes.
        assert!(accounted(4, &[told(10, Some(11)), told(12, Some(11))]).is_err());
        // A console host no teller names is a process that told nothing.
        assert!(accounted(2, &[told(10, None)]).is_err());
        // Nothing told at all.
        assert!(accounted(1, &[]).is_err());
        // More told than the job held: not taken for whole either.
        assert!(accounted(1, &[told(10, Some(11))]).is_err());
        // A process that told twice.
        assert!(accounted(2, &[told(10, None), told(10, None)]).is_err());
        // A teller named as another's console host is counted once, as a teller.
        assert_eq!(accounted(2, &[told(10, Some(12)), told(12, None)]), Ok(()));
    }

    #[test]
    fn a_runs_lines_end_in_an_x_line_unless_every_process_is_accounted_for() {
        let whole = lines(2, &[told(10, Some(11))], &[], None);
        assert_eq!(whole, vec![trace::Line::new(Seen::Read, "", "C:\\p\\probe.rs")]);
        let partial = lines(3, &[told(10, Some(11))], &[], None);
        assert_eq!(partial.last().map(|it| it.seen), Some(Seen::Incomplete));
        let refused = lines(2, &[told(10, Some(11))], &["x".to_owned()], None);
        assert_eq!(refused.iter().filter(|it| it.seen == Seen::Incomplete).count(), 1);
        let failed = lines(2, &[told(10, Some(11))], &[], Some("more than 16 MiB"));
        assert_eq!(failed.iter().filter(|it| it.seen == Seen::Incomplete).count(), 1);
    }
}
