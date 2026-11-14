//! A minimal reproduction attempt of the Windows bugcheck 0x1A (MEMORY_MANAGEMENT), subtype
//! 0x3453, in `nt!MiDeleteFinalPageTables`, hit four times on 2026-11-14 (Windows 11 26100.9711,
//! Ryzen 9 9950X3D, 93 GB) as blaze's unit-test binary `blaze_cargo-*.exe` exited.
//!
//! It does, outside blaze, the address-space calls blaze's memory layer makes on Windows, then
//! exits without releasing anything, so the kernel tears it all down at process exit, where the
//! bugcheck fired. Each mode is one suspect (see README.md); `all` runs each in child processes.
//!
//! RUN IT ONLY IN A VM. It is meant to crash the kernel.

use std::{ffi::c_void, process::Command, ptr, sync::atomic::{AtomicBool, Ordering}, time::Instant};

use windows_sys::Win32::System::{
    Memory::{
        DiscardVirtualMemory, MEM_COMMIT, MEM_DECOMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE,
        VirtualAlloc, VirtualAllocExNuma, VirtualFree,
    },
    Threading::{ExitProcess, FlushProcessWriteBuffers, GetCurrentProcess},
};

const KIB: usize = 1 << 10;
const MIB: usize = 1 << 20;
const GIB: usize = 1 << 30;
const TIB: usize = 1 << 40;

/// blaze-cas's pool: 4096 windows of 1 GiB, pages of 64 KiB, reserved alone, each page committed
/// as it is loaded (`Region::reserve_sparse_ranges`, `reuse`).
const POOL: usize = 4 * TIB;
const WINDOW: usize = GIB;
const PAGE: usize = 64 * KIB;
/// blaze-mem's chunk space: 256 GiB a NUMA node, 2 MiB chunks (`chunks.rs`).
const SPACE: usize = 256 * GIB;
const CHUNK: usize = 2 * MIB;

struct Args {
    mode: String,
    children: u32,
    reservations: usize,
    windows: usize,
    rounds: usize,
}

fn args() -> Args {
    let mut it = std::env::args().skip(1);
    let mut args = Args { mode: it.next().unwrap_or_else(|| "all".into()), children: 0, reservations: 8, windows: 512, rounds: 4 };
    while let Some(flag) = it.next() {
        let value: usize = it.next().and_then(|it| it.parse().ok()).unwrap_or_else(|| usage());
        match flag.as_str() {
            "--children" => args.children = value as u32,
            "--reservations" => args.reservations = value,
            "--windows" => args.windows = value,
            "--rounds" => args.rounds = value,
            _ => usage(),
        }
    }
    args
}

fn usage() -> ! {
    eprintln!(
        "usage: bsod-repro <pool|decommit|chunks|race|words|all> [--children N] [--reservations R] [--windows W] [--rounds K]"
    );
    std::process::exit(2)
}

fn check(ok: bool, what: &str) {
    if !ok {
        eprintln!("{what}: {}", std::io::Error::last_os_error());
        std::process::exit(3);
    }
}

unsafe fn reserve(bytes: usize) -> *mut u8 {
    let base = unsafe { VirtualAlloc(ptr::null(), bytes, MEM_RESERVE, PAGE_NOACCESS) }.cast::<u8>();
    check(!base.is_null(), &format!("VirtualAlloc(MEM_RESERVE, {bytes})"));
    base
}

unsafe fn commit(at: *mut u8, bytes: usize) {
    let got = unsafe { VirtualAlloc(at.cast(), bytes, MEM_COMMIT, PAGE_READWRITE) };
    check(!got.is_null(), "VirtualAlloc(MEM_COMMIT)");
}

unsafe fn touch(at: *mut u8, bytes: usize, byte: u8) {
    for off in (0..bytes).step_by(4096) {
        unsafe { at.add(off).write_volatile(byte) };
    }
}

unsafe fn decommit(at: *mut u8, bytes: usize) {
    check(unsafe { VirtualFree(at.cast(), bytes, MEM_DECOMMIT) } != 0, "VirtualFree(MEM_DECOMMIT)");
}

unsafe fn discard(at: *mut u8, bytes: usize) {
    check(unsafe { DiscardVirtualMemory(at.cast::<c_void>(), bytes) } == 0, "DiscardVirtualMemory");
}

/// The store's pool before round 6: pages committed scattered across 4 TiB reservations, given
/// back with `DiscardVirtualMemory` (still committed), loaded again; the process exits holding
/// every reservation. Two reservations a daemon (its own store, std's), many daemons a test run.
fn pool(args: &Args, decommit_after_discard: bool, decommit_only: bool) {
    for r in 0..args.reservations {
        let base = unsafe { reserve(POOL) };
        // The state words: 8 bytes a page, a prefix of a 512 MiB reservation committed as
        // windows open (`reserve_sparse_prefix`).
        let words = unsafe { reserve(512 * MIB) };
        unsafe { commit(words, (args.windows * (WINDOW / PAGE) * 8).next_multiple_of(4096).min(512 * MIB)) };
        for round in 0..args.rounds {
            for w in 0..args.windows {
                // Windows are spread over the reservation (first-fit of files), a few pages each.
                let window = (w * 7 + r * 131) % (POOL / WINDOW);
                for p in 0..4 {
                    let at = unsafe { base.add(window * WINDOW + p * 3 * PAGE) };
                    unsafe {
                        commit(at, PAGE);
                        touch(at, PAGE, (round + p) as u8);
                    }
                    match (decommit_only, decommit_after_discard, (w + p + round) % 3) {
                        (true, _, 0 | 1) => unsafe { decommit(at, PAGE) },
                        (false, _, 0) => unsafe { discard(at, PAGE) },
                        (false, true, 1) => unsafe {
                            discard(at, PAGE);
                            decommit(at, PAGE);
                        },
                        _ => {}
                    }
                }
            }
        }
    }
}

/// blaze-mem's chunks: a 256 GiB space reserved on NUMA node 0, 2 MiB chunks committed and
/// written, a trim decommitting the warm ones.
fn chunks(args: &Args) {
    for _ in 0..args.reservations.min(4) {
        let base = unsafe { VirtualAllocExNuma(GetCurrentProcess(), ptr::null(), SPACE, MEM_RESERVE, PAGE_NOACCESS, 0) }
            .cast::<u8>();
        check(!base.is_null(), "VirtualAllocExNuma(MEM_RESERVE, 256 GiB)");
        let count = args.windows.min(SPACE / CHUNK);
        for round in 0..args.rounds {
            for c in 0..count {
                let at = unsafe { base.add(c * CHUNK) };
                unsafe {
                    commit(at, CHUNK);
                    touch(at, CHUNK, round as u8);
                }
            }
            for c in (0..count).step_by(2) {
                unsafe { decommit(base.add(c * CHUNK), CHUNK) };
            }
        }
    }
}

/// Round 6's purger: a thread decommitting and recommitting chunks and flushing every
/// processor's write buffers (the pool's drain) while the main thread ends the process, so the
/// teardown races a `VirtualFree` in flight.
fn race(args: &Args) {
    static GO: AtomicBool = AtomicBool::new(true);
    let base = unsafe { VirtualAllocExNuma(GetCurrentProcess(), ptr::null(), SPACE, MEM_RESERVE, PAGE_NOACCESS, 0) }
        .cast::<u8>() as usize;
    check(base != 0, "VirtualAllocExNuma(MEM_RESERVE, 256 GiB)");
    let pool = unsafe { reserve(POOL) } as usize;
    let count = args.windows.min(SPACE / CHUNK);
    for t in 0..4 {
        std::thread::spawn(move || {
            let mut n = 0usize;
            while GO.load(Ordering::Relaxed) {
                let at = (base + ((n * 4 + t) % count) * CHUNK) as *mut u8;
                let page = (pool + ((n * 4 + t) % 4096) * WINDOW) as *mut u8;
                unsafe {
                    commit(at, CHUNK);
                    touch(at, CHUNK, n as u8);
                    commit(page, PAGE);
                    touch(page, PAGE, n as u8);
                    decommit(page, PAGE);
                    FlushProcessWriteBuffers();
                    decommit(at, CHUNK);
                }
                n += 1;
            }
        });
    }
    std::thread::sleep(std::time::Duration::from_millis(200));
    // Not a clean end: the threads are mid-call as the process goes.
    unsafe { ExitProcess(0) };
}

/// The other Windows regions blaze makes: a sparse table committed whole (`reserve_sparse`),
/// regions grown by commit and cut back by decommit (`decommit_after`), some released.
fn words(args: &Args) {
    for i in 0..args.reservations {
        let table = unsafe { VirtualAlloc(ptr::null(), 64 * MIB, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) }.cast::<u8>();
        check(!table.is_null(), "VirtualAlloc(64 MiB committed)");
        unsafe { touch(table, 64 * MIB, i as u8) };
        let region = unsafe { reserve(64 * GIB) };
        let mut len = 0;
        for step in 0..args.rounds * 8 {
            let grow = 64 * MIB;
            unsafe {
                commit(region.add(len), grow);
                touch(region.add(len), grow, step as u8);
            }
            len += grow;
            if step % 3 == 2 {
                unsafe { decommit(region.add(len / 2), len - len / 2) };
                len /= 2;
            }
        }
        if i % 2 == 0 {
            check(unsafe { VirtualFree(region.cast(), 0, MEM_RELEASE) } != 0, "VirtualFree(MEM_RELEASE)");
        }
    }
}

fn run(args: &Args, mode: &str) {
    match mode {
        "pool" => pool(args, false, false),
        "discard-decommit" => pool(args, true, false),
        "decommit" => pool(args, false, true),
        "chunks" => chunks(args),
        "race" => race(args),
        "words" => words(args),
        _ => usage(),
    }
}

const MODES: [&str; 6] = ["pool", "discard-decommit", "decommit", "chunks", "words", "race"];

fn main() {
    let args = args();
    let modes: Vec<&str> = match args.mode.as_str() {
        "all" => MODES.to_vec(),
        mode => vec![mode],
    };
    if args.children == 0 {
        let started = Instant::now();
        for mode in modes {
            run(&args, mode);
        }
        eprintln!("done in {:?}; exiting with everything still mapped", started.elapsed());
        return;
    }
    let me = std::env::current_exe().expect("this program's path");
    for round in 0..args.children {
        for mode in &modes {
            let started = Instant::now();
            let status = Command::new(&me)
                .args([
                    *mode,
                    "--reservations",
                    &args.reservations.to_string(),
                    "--windows",
                    &args.windows.to_string(),
                    "--rounds",
                    &args.rounds.to_string(),
                ])
                .status()
                .expect("a child");
            println!("child {round} {mode}: {status} in {:?}", started.elapsed());
        }
    }
    println!("all children exited: the machine survived");
}
