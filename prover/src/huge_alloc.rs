//! Global allocator that backs large allocations with transparent huge pages.
//!
//! The prover streams a multi-GB working set (LDE matrices, Merkle layers); at
//! 4 KiB pages this overruns the dTLB and pays hundreds of millions of page
//! walks per prove, plus one minor fault per page on first touch. Serving
//! allocations of at least one huge page from their own 2 MiB-aligned,
//! `MADV_HUGEPAGE`-advised mapping removes both costs under the default
//! `transparent_hugepage=madvise` host setting (measured −9% end-to-end on
//! Graviton4, `dtlb_walk` down 31×).
//!
//! Alignment matters: the kernel only backs 2 MiB-aligned ranges with huge
//! pages, so simply advising malloc's mappings loses up to one huge page per
//! buffer edge. Owning the mapping makes coverage exact and deterministic.
//!
//! Whether an allocation uses the huge-page path is a pure function of its
//! `Layout`, so `dealloc` always frees through the same path `alloc` used —
//! there is deliberately no fallback to the system allocator on `mmap`
//! failure, which for these sizes means the machine is out of memory anyway.
//!
//! Allocations below the threshold — and all allocations on non-Linux
//! targets — go to the system allocator unchanged.

use std::alloc::{GlobalAlloc, Layout, System};

/// Allocations of at least this size get their own huge-page mapping.
pub const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;

/// Installs with `#[global_allocator]` in prover binaries.
pub struct HugePageAlloc;

#[cfg(target_os = "linux")]
#[inline]
fn use_huge_path(layout: &Layout) -> bool {
    layout.size() >= HUGE_PAGE_SIZE && layout.align() <= HUGE_PAGE_SIZE
}

#[cfg(target_os = "linux")]
#[inline]
fn rounded(size: usize) -> usize {
    (size + HUGE_PAGE_SIZE - 1) & !(HUGE_PAGE_SIZE - 1)
}

/// Maps `rounded(size)` bytes at a 2 MiB-aligned address, advised for huge
/// pages. Returns null on failure. The mapping is already zeroed.
#[cfg(target_os = "linux")]
fn huge_alloc(size: usize) -> *mut u8 {
    let len = rounded(size);
    // Over-map by one huge page, then trim to alignment: mmap gives no
    // alignment guarantee above the base page size.
    let total = len + HUGE_PAGE_SIZE;
    let raw = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            total,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if raw == libc::MAP_FAILED {
        return core::ptr::null_mut();
    }
    let raw = raw as usize;
    let aligned = (raw + HUGE_PAGE_SIZE - 1) & !(HUGE_PAGE_SIZE - 1);
    let head = aligned - raw;
    let tail = total - head - len;
    unsafe {
        if head > 0 {
            libc::munmap(raw as *mut libc::c_void, head);
        }
        if tail > 0 {
            libc::munmap((aligned + len) as *mut libc::c_void, tail);
        }
        libc::madvise(aligned as *mut libc::c_void, len, libc::MADV_HUGEPAGE);
    }
    aligned as *mut u8
}

#[cfg(target_os = "linux")]
unsafe impl GlobalAlloc for HugePageAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if use_huge_path(&layout) {
            huge_alloc(layout.size())
        } else {
            unsafe { System.alloc(layout) }
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if use_huge_path(&layout) {
            huge_alloc(layout.size())
        } else {
            unsafe { System.alloc_zeroed(layout) }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if use_huge_path(&layout) {
            unsafe {
                libc::munmap(ptr as *mut libc::c_void, rounded(layout.size()));
            }
        } else {
            unsafe { System.dealloc(ptr, layout) }
        }
    }
}

#[cfg(not(target_os = "linux"))]
unsafe impl GlobalAlloc for HugePageAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
