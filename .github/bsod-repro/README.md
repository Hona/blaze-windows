# bsod-repro: bugcheck 0x1A / 0x3453 on process exit

**Run this only in a VM.** It is meant to crash the Windows kernel. Never on `adais`.

## What happened

On 2026-11-14 `adais` (Windows 11 26100.9711, Ryzen 9 9950X3D, 93 GB RAM) bugchecked four
times as blaze's unit-test binary `blaze_cargo-*.exe` exited:

| Time | Parameters (`0x1A`) | Dump |
|---|---|---|
| 06:35 | `0x3453, 0xffffad0f0ca2c080, 0x114d362, 3` | `C:\Windows\Minidump\111426-15406-01.dmp` |
| 08:04 | `0x3453, 0xffffc38225329080, 0x446756, 3` | `111426-15171-01.dmp` |
| 08:06 | `0x3453, 0xffff8302e0f430c0, 0x13bb035, 3` | `111426-14718-01.dmp` |
| 09:46 | `0x3453, 0xffffd00d59e6c080, 0xe01741, 3` | `111426-14046-01.dmp` |

Stack top `nt!MiDeleteFinalPageTables`; parameter 2 is the exiting process (`EPROCESS`).
No third-party driver on the stack, about 80 GB free. The dumps need elevation to read.

## What it does

The address-space calls blaze's memory layer (`crates/blaze-mem/src/os.rs`, the store's pool
in `crates/blaze-cas/src/pool.rs`, `chunks.rs`) makes on Windows, without blaze, then exits
with everything still mapped so the kernel tears it down. One mode per suspect:

| Mode | Calls | Suspect |
|---|---|---|
| `pool` | R reservations of 4 TiB (`MEM_RESERVE`), 64 KiB pages committed scattered over 1 GiB windows, `DiscardVirtualMemory` on a third, a 512 MiB words reservation with a committed prefix | the pool as it was before 2026-11-14 |
| `discard-decommit` | as `pool`, a third of the pages discarded then `MEM_DECOMMIT` | round 6's pool give-back after earlier discards |
| `decommit` | as `pool`, two thirds `MEM_DECOMMIT` directly | round 6's `Region::evict_out` |
| `chunks` | 256 GiB `VirtualAllocExNuma` reservations, 2 MiB chunks committed and written, half decommitted | blaze-mem's chunk trim |
| `words` | regions grown by commit and cut back by decommit, half released | regions and frames |
| `race` | four threads commit / touch / decommit chunks and pool pages and call `FlushProcessWriteBuffers` while the main thread calls `ExitProcess` | round 6's purger thread (purge between requests) racing teardown |

## How to run (in a VM)

```pwsh
cargo build --release
# every mode, each in its own child process, 50 rounds:
target\release\bsod-repro.exe all --children 50
# heavier: more reservations and windows (the test binary held dozens of stores at once)
target\release\bsod-repro.exe all --children 50 --reservations 32 --windows 2048
```

A run that prints `all children exited: the machine survived` did not reproduce. A reproduction
is the VM rebooting. Give the VM several cores (8 or more) and 16 GB or more; adais had 32
logical cores and one NUMA node.

## What to collect for Microsoft

- The VM's `C:\Windows\Minidump\*.dmp` and, with a kernel dump configured
  (`SystemPropertiesAdvanced` > Startup and Recovery > Kernel memory dump), `C:\Windows\MEMORY.DMP`.
- `!analyze -v` from WinDbg on it, `winver`, the mode and flags that crashed.
- This folder (source and README).
- Report through Feedback Hub (Developer Platform > Kernel) or the Windows Insider/Microsoft
  support channel, attaching the dump.

## In CI

`.github/workflows/windows-bsod-repro.yaml` in `Hona/blaze-windows` (manual, or a push to
`windows/bsod-repro`) runs the same program from `.github/bsod-repro/` on a GitHub Windows
runner (a VM) and says whether the runner survived.
