//! Trace construction queries this model for every execution. Symbolic AIR degree inference
//! allocates, so requiring allocation-free queries keeps that work out of the runtime path.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    hint::black_box,
};

use miden_air::{
    precompiles::{ChipletMultiAir, NUM_CHIPLETS, policy::precompile_pcs_params},
    vm::config::pcs_params,
};
use miden_core::{Felt, field::QuadFelt};
use miden_stark::memory;

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
    let peak = black_box(miden_vm_stark::memory::prover_peak_bytes(
        black_box(&[1024, 2048, 4096, 65536]),
        &params,
    ));
    let model =
        black_box(miden_vm_stark::memory::memory_model(&params).expect("valid memory model"));
    let max_height = black_box(model.max_any_height_for_budget(black_box(1 << 30)));
    let allocations = ALLOCATIONS.replace(None).unwrap();

    assert!(peak.is_some());
    assert!(max_height > 0);
    assert_eq!(allocations, 0, "runtime memory budgeting must use compiled AIR geometry");
}

#[test]
fn precompile_memory_budget_uses_compiled_geometry_without_allocating() {
    let params = precompile_pcs_params();
    // AIR construction allocates; count only the memory query.
    let multi_air = ChipletMultiAir::new();
    let heights = [1; NUM_CHIPLETS];

    ALLOCATIONS.set(Some(0));
    let peak = black_box(memory::prover_peak_bytes::<Felt, QuadFelt, _>(
        &multi_air,
        black_box(&heights),
        &params,
    ));
    let model = memory::ProverMemoryModel::from_multi_air::<Felt, QuadFelt, _>(&multi_air, &params)
        .expect("production geometry fits");
    assert_eq!(model.prover_peak_bytes(black_box(&heights)), peak);
    assert!(model.max_any_height_for_budget(black_box(1 << 30)) > 0);
    let allocations = ALLOCATIONS.replace(None).unwrap();

    assert!(peak.is_some());
    assert_eq!(allocations, 0, "PVM memory budgeting must use compiled AIR geometry");
}
