//! A bump allocator for `no_std` handler crates.
//!
//! The value types link the `alloc` crate, so a `no_std` handler crate must name a global
//! allocator. The host instantiates the handler module afresh for every event, so the guest
//! memory starts clean on each call and no allocation outlives one handler run. A bump allocator
//! that never frees is therefore enough, and it keeps the module small.

use core::{
    alloc::{GlobalAlloc, Layout},
    arch::wasm32,
    cell::UnsafeCell,
    ptr,
};

/// The size of one Wasm memory page.
const PAGE_SIZE: usize = 64 * 1024;

/// A bump allocator over the pages it reserves with `memory.grow`.
struct Bump {
    /// The next free address.
    next: UnsafeCell<usize>,
    /// The first address past the reserved region.
    end: UnsafeCell<usize>,
}

// SAFETY: a handler runs alone in its instance, and the guest has no threads.
unsafe impl Sync for Bump {}

// SAFETY: `alloc` returns either null or the start of a region inside the pages this allocator
// reserved, aligned to `layout.align()` and `layout.size()` bytes long. `next` only moves
// forward, so no two live allocations overlap, and `dealloc` never reuses memory.
unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the cells are reachable only through this allocator, and the guest is
        // single-threaded, so no other borrow of them exists.
        let (next, end) = unsafe { (&mut *self.next.get(), &mut *self.end.get()) };

        if let Some((start, stop)) = fit(*next, layout)
            && stop <= *end
        {
            *next = stop;
            return start as *mut u8;
        }

        // Reserve fresh pages. `memory.grow` returns the previous page count, and the memory
        // above it is untouched, so the new region cannot overlap an earlier allocation.
        let Some(bytes) = layout.size().checked_add(layout.align()) else {
            return ptr::null_mut();
        };
        let pages = bytes.div_ceil(PAGE_SIZE);
        let previous = wasm32::memory_grow(0, pages);
        if previous == usize::MAX {
            return ptr::null_mut();
        }
        match fit(previous * PAGE_SIZE, layout) {
            Some((start, stop)) => {
                *next = stop;
                // A successful grow means the host reserved `previous + pages` pages, and the
                // host caps the handler memory far below the 4 GiB of the 32-bit address space,
                // so the byte count of the reserved region fits in a 32-bit `usize`.
                *end = (previous + pages) * PAGE_SIZE;
                start as *mut u8
            },
            None => ptr::null_mut(),
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // The instance goes away after the handler returns; nothing is reused.
    }
}

/// Returns the aligned start and the end of an allocation of `layout` placed at or after `from`,
/// or `None` when the address computation goes past the address space.
#[inline]
fn fit(from: usize, layout: Layout) -> Option<(usize, usize)> {
    let mask = layout.align() - 1;
    let start = from.checked_add(mask)? & !mask;
    Some((start, start.checked_add(layout.size())?))
}

#[global_allocator]
static ALLOCATOR: Bump = Bump {
    next: UnsafeCell::new(0),
    end: UnsafeCell::new(0),
};
