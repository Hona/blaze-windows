//! Where a Windows process's commit charge is (`PrivateUsage`, its footprint there, rule
//! `one-memory-measure`), by what holds it: one walk of the address space with `VirtualQuery`,
//! each committed range put to the first holder that owns it. What the memory line says beside
//! the counters, so a daemon past its ceiling or the system's commit limit names the holder of
//! its commit, not only the sum.
//!
//! The holders: the global heap (a range with a page of mimalloc's, `mi_is_in_heap_region`);
//! the store's pools (the regions registered under their name with `blaze_core::spans`); the
//! system's heaps (allocations based at a heap `GetProcessHeaps` names: LLVM's and the C
//! runtime's `malloc`; a heap's later segments and its blocks of a megabyte and more are
//! allocations of their own and read as other); thread stacks (an allocation with a guard
//! page); the images' and mapped views' pages written copy-on-write (charged as private); and
//! the rest of the private memory: blaze-mem's regions, frames and chunks, and whatever else
//! reserves memory itself.

use windows_sys::Win32::System::Memory::{
    GetProcessHeaps, HEAP_SUMMARY, HeapSummary, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
    MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
    PAGE_READWRITE, PAGE_WRITECOPY, VirtualQuery,
};

/// The name the store's pool registers its pages under (`blaze-cas`'s `Pool::new`).
const POOL: &str = "the store's pool";

/// The most heaps read: a daemon has a few (the process's, the C runtime's, a loader's).
const HEAPS_MOST: usize = 64;

/// Where the process's commit charge is, in bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CommitMap {
    /// The process's commit charge (`PrivateUsage`), read after the walk.
    pub total: u64,
    /// Private ranges with a page of mimalloc's.
    pub heap: u64,
    /// Private ranges of the store's pools.
    pub pool: u64,
    /// Private ranges of allocations based at a heap of the system's.
    pub system_heaps: u64,
    /// What the system's heaps say they commit (`HeapSummary`), segments and large blocks alike.
    pub system_heaps_said: u64,
    /// Private ranges of allocations with a guard page: the threads' stacks.
    pub stacks: u64,
    /// Pages of images and mapped views that are writable copy-on-write or written: charged.
    pub images: u64,
    /// Every other private range.
    pub other: u64,
    /// Ranges the walk read.
    pub ranges: u64,
}

impl CommitMap {
    /// What the walk found charged in all.
    pub fn walked(&self) -> u64 {
        self.heap + self.pool + self.system_heaps + self.stacks + self.images + self.other
    }
}

/// Whether a range of an image or a mapped view is charged: writable, so written pages are the
/// process's own copy (a `PAGE_WRITECOPY` page is charged as it is mapped).
fn charged_shared(protect: u32) -> bool {
    protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
        != 0
}

/// Whether any 64 KiB slice of `[at, at + len)` is a page of mimalloc's.
#[cfg(feature = "native")]
fn in_heap(at: usize, len: usize) -> bool {
    const SLICE: usize = 64 << 10;
    let mut slice = at & !(SLICE - 1);
    while slice < at + len {
        // SAFETY: mimalloc's page map lookup reads only its own map; any address is allowed.
        if unsafe {
            libmimalloc_sys::mi_is_in_heap_region(slice.max(at) as *const std::ffi::c_void)
        } {
            return true;
        }
        slice += SLICE;
    }
    false
}

/// Without mimalloc, no range is the global heap's by this walk.
#[cfg(not(feature = "native"))]
fn in_heap(_at: usize, _len: usize) -> bool {
    false
}

/// One walk of this process's address space. Allocates nothing: the pools' and heaps' ranges
/// are read into arrays on the stack. Takes a few milliseconds a daemon (a `VirtualQuery` per
/// range of like pages).
pub fn commit_map() -> CommitMap {
    let mut map = CommitMap::default();
    let mut pools = [(0usize, 0usize); 8];
    let mut pool_count = 0;
    blaze_core::spans::Spans::each(|name, base, len| {
        if name == POOL && pool_count < pools.len() {
            pools[pool_count] = (base, base + len);
            pool_count += 1;
        }
    });
    let pools = &pools[..pool_count];
    let mut heaps = [std::ptr::null_mut(); HEAPS_MOST];
    // SAFETY: `heaps` holds `HEAPS_MOST` handles for the call to write.
    let count = unsafe { GetProcessHeaps(HEAPS_MOST as u32, heaps.as_mut_ptr()) } as usize;
    let heaps = &heaps[..count.min(HEAPS_MOST)];
    for &heap in heaps {
        // SAFETY: all zeros is a valid record of integers, whose size field is set as asked.
        let mut summary: HEAP_SUMMARY = unsafe { std::mem::zeroed() };
        summary.cb = size_of::<HEAP_SUMMARY>() as u32;
        // SAFETY: a heap of this process's, as the system named it, and a live record.
        if unsafe { HeapSummary(heap, 0, &mut summary) } != 0 {
            map.system_heaps_said += summary.cbCommitted as u64;
        }
    }
    let mut at = 0usize;
    // The allocation the walk is in, and what it was found to be.
    let mut allocation = usize::MAX;
    let mut stack = false;
    let mut heap = false;
    loop {
        // SAFETY: all zeros is a valid record of integers and pointers.
        let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: any address may be asked; the record is live for the call to write.
        let got = unsafe {
            VirtualQuery(at as *const _, &mut info, size_of::<MEMORY_BASIC_INFORMATION>())
        };
        if got == 0 {
            break;
        }
        map.ranges += 1;
        let (base, len) = (info.BaseAddress as usize, info.RegionSize);
        if info.AllocationBase as usize != allocation {
            allocation = info.AllocationBase as usize;
            stack = guarded(allocation);
            heap = false;
        }
        if info.State == MEM_COMMIT {
            let bytes = len as u64;
            if info.Type == MEM_IMAGE || info.Type == MEM_MAPPED {
                if charged_shared(info.Protect) {
                    map.images += bytes;
                }
            } else if info.Type == MEM_PRIVATE {
                if pools.iter().any(|&(from, to)| base >= from && base < to) {
                    map.pool += bytes;
                } else if heaps.iter().any(|&it| it as usize == allocation) {
                    map.system_heaps += bytes;
                } else if stack {
                    map.stacks += bytes;
                } else if heap || in_heap(base, len) {
                    heap = true;
                    map.heap += bytes;
                } else {
                    map.other += bytes;
                }
            }
        }
        match base.checked_add(len) {
            Some(next) if next > at => at = next,
            _ => break,
        }
    }
    map.total = super::own_footprint_now().unwrap_or(0);
    map
}

/// Whether the allocation at `base` holds a guard page: a thread's stack, whose guard page the
/// system moves down as the stack grows.
fn guarded(base: usize) -> bool {
    let mut at = base;
    loop {
        // SAFETY: as in `commit_map`.
        let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as in `commit_map`.
        let got = unsafe {
            VirtualQuery(at as *const _, &mut info, size_of::<MEMORY_BASIC_INFORMATION>())
        };
        if got == 0 || info.AllocationBase as usize != base {
            return false;
        }
        if info.State == MEM_COMMIT && info.Protect & PAGE_GUARD != 0 {
            return true;
        }
        match (info.BaseAddress as usize).checked_add(info.RegionSize) {
            Some(next) if next > at => at = next,
            _ => return false,
        }
    }
}

impl std::fmt::Display for CommitMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let gib = |bytes: u64| bytes as f64 / f64::from(1u32 << 30);
        write!(
            f,
            "commit {:.2} GiB: global heap {:.2}, store pool {:.2}, system heaps {:.2} (they say {:.2}), \
             stacks {:.2}, images {:.2}, other private {:.2}",
            gib(self.total),
            gib(self.heap),
            gib(self.pool),
            gib(self.system_heaps),
            gib(self.system_heaps_said),
            gib(self.stacks),
            gib(self.images),
            gib(self.other),
        )
    }
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
    };

    /// The invariant: the walk puts the process's commit charge to its holders, and their sum is
    /// the charge within what moves as it walks; memory committed by a caller of its own counts
    /// as other private memory, and a thread's stack as a stack. The control: the same region
    /// released is gone from the walk.
    #[test]
    fn the_walk_finds_where_the_commit_is() {
        const SIZE: usize = 256 << 20;
        let before = super::commit_map();
        // SAFETY: a fresh region of the system's choosing, released below.
        let region = unsafe {
            VirtualAlloc(std::ptr::null(), SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        };
        assert!(!region.is_null());
        let held = super::commit_map();
        // SAFETY: the region made above, released whole.
        assert_ne!(unsafe { VirtualFree(region, 0, MEM_RELEASE) }, 0);
        let after = super::commit_map();
        let slack = 64 << 20;
        assert!(held.other >= before.other + SIZE as u64 - slack, "{before:?} then {held:?}");
        assert!(after.other + SIZE as u64 - slack <= held.other, "{held:?} then {after:?}");
        assert!(held.stacks > 0, "the test thread's stack: {held:?}");
        // Other test threads allocate as the walk runs: the sum is the charge within a slack.
        assert!(held.walked().abs_diff(held.total) < slack + held.total / 8, "{held:?}");
    }
}
