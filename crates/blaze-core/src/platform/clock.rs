//! Monotonic nanoseconds shared by the Windows client, engine and daemon. A process-local
//! `Instant` origin cannot date spans that one process writes and another one finishes.

use windows_sys::Win32::{Foundation::FILETIME, System::{Performance::*, SystemInformation::GetSystemTimePreciseAsFileTime, Threading::{GetCurrentProcess, GetProcessTimes}}};

pub fn mono_ns() -> i64 {
    static FREQUENCY: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
    let frequency = FREQUENCY.get_or_init(|| {
        let mut n = 0;
        // SAFETY: a writable counter; the frequency is fixed at boot on Windows x64.
        assert_ne!(unsafe { QueryPerformanceFrequency(&mut n) }, 0);
        n
    });
    let mut ticks = 0;
    // SAFETY: one writable counter.
    assert_ne!(unsafe { QueryPerformanceCounter(&mut ticks) }, 0);
    (i128::from(ticks) * 1_000_000_000 / i128::from(*frequency)) as i64
}

pub fn started_ns() -> Result<i64, String> {
    let (mut made, mut exit, mut kernel, mut user, mut now) = (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
    // SAFETY: the pseudo-handle of this process, and separate writable times.
    if unsafe { GetProcessTimes(GetCurrentProcess(), &mut made, &mut exit, &mut kernel, &mut user) } == 0 {
        return Err(format!("reading this process's creation time: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: one writable FILETIME (100 ns since the system epoch).
    unsafe { GetSystemTimePreciseAsFileTime(&mut now) };
    let ticks = |t: FILETIME| (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime);
    let age = ticks(now).saturating_sub(ticks(made)).saturating_mul(100);
    Ok(mono_ns().saturating_sub(i64::try_from(age).unwrap_or(i64::MAX)))
}
