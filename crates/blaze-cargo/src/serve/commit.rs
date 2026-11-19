//! Windows' private commit is the process charge, not its working set. The guard lasts
//! exactly as long as the engine's state lock, including a host serving in process. No
//! worker or allocator asks the guard for admission.

use std::{sync::mpsc, thread, time::Duration};

use anyhow::Context as _;
use blaze_core::exit::Exit;

pub(super) const VAR: &str = "BLAZE_DAEMON_MEMORY_GB";

pub(super) struct Guard {
    quit: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<()>>,
}

fn limit(value: &str) -> anyhow::Result<u64> {
    let bytes = value.trim().parse::<f64>().unwrap_or(f64::NAN) * (1u64 << 30) as f64;
    anyhow::ensure!((1.0..u64::MAX as f64).contains(&bytes), "{VAR} {value:?}: expected a positive limit in GiB");
    Ok(bytes as u64)
}

impl Guard {
    pub(super) fn arm() -> anyhow::Result<Self> {
        let used = crate::raw::memory::own_footprint_now().context("reading the engine's private commit")?;
        // Keep room for the system as well as this process. The effective page-file
        // availability is already constrained by an enclosing Windows job, if any.
        let available = blaze_mem::address_capacity()?.available_commit;
        let ceiling = used.saturating_add(available - available.div_ceil(8));
        let ceiling = match std::env::var(VAR) {
            Ok(text) => ceiling.min(limit(&text)?),
            Err(std::env::VarError::NotPresent) => ceiling,
            Err(error) => anyhow::bail!("{VAR}: {error}"),
        };
        let (quit, stop) = mpsc::channel();
        let mut watch = super::pulse::CeilingWatch::default();
        let worker = thread::Builder::new().name("blaze-commit-guard".into()).spawn(move || loop {
            let bytes = crate::raw::memory::own_footprint_now();
            use super::pulse::CeilingLook;
            match bytes.map(|n| watch.look(n, ceiling)) {
                Some(CeilingLook::Purge) => { crate::raw::memory::purger().ask(); }
                Some(CeilingLook::Near | CeilingLook::Eased) => super::said::logged!(WARN, "blaze serve: private commit {bytes:?}, limit {ceiling} bytes"),
                Some(CeilingLook::Under) => {}
                None | Some(CeilingLook::Passed) => {
                    super::said::logged!(ERROR, "blaze serve: pid {} stopped at its memory ceiling: private commit {bytes:?}, limit {ceiling} bytes", std::process::id());
                    super::daemon::log_memory(&blaze_mem::tag::snapshot());
                    std::process::exit(Exit::MemoryCeiling.code());
                }
            }
            if stop.recv_timeout(Duration::from_millis(100)) != Err(mpsc::RecvTimeoutError::Timeout) { break; }
        }).context("starting the private commit guard")?;
        Ok(Self { quit, worker: Some(worker) })
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.quit.send(());
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_engine_over_its_commit_limit_stops_even_if_the_loop_is_stuck() {
        const CHILD: &str = "BLAZE_TEST_COMMIT_GUARD";
        if std::env::var_os(CHILD).is_some() {
            let _guard = Guard::arm().unwrap();
            thread::park_timeout(Duration::from_secs(5));
            panic!("a guard armed below this process's existing private commit did not stop it");
        }
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "serve::commit::tests::an_engine_over_its_commit_limit_stops_even_if_the_loop_is_stuck", "--nocapture"])
            .env(CHILD, "1").env(VAR, "0.000001").output().unwrap();
        assert_eq!(result.status.code(), Some(Exit::MemoryCeiling.code()));
        assert!(String::from_utf8_lossy(&result.stderr).contains("private commit"));
    }
}
