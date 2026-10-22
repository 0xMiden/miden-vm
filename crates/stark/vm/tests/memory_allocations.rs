//! Trace construction queries this model for every execution. Symbolic AIR degree inference
//! allocates, so requiring allocation-free queries keeps that work out of the runtime path.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    hint::black_box,
};

use miden_vm_stark::{memory, setup::config::pcs_params};

thread_local! {
    static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
}

struct CountingAllocator;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn record_allocation() {
    let _ = ALLOCATIONS.try_with(|count| {
        if let Some(current) = count.get() {
            count.set(Some(current + 1));
        }
    });
}

// SAFETY: every allocation and deallocation is forwarded to the system allocator unchanged.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_allocation();
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[test]
fn trace_memory_budget_uses_compiled_geometry_without_allocating() {
    let params = pcs_params();
    ALLOCATIONS.set(Some(0));
    let peak = black_box(memory::prover_peak_bytes(black_box(&[1024, 2048, 4096, 65536]), &params));
    let max_height = black_box(memory::max_any_height_for_budget(black_box(1 << 30), &params));
    let allocations = ALLOCATIONS.replace(None).unwrap();

    assert!(peak.is_some());
    assert!(max_height > 0);
    assert_eq!(allocations, 0, "runtime memory budgeting must use compiled AIR geometry");
}
