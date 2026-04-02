//! Column layout types for the main and auxiliary execution traces.
//!
//! These `#[repr(C)]` structs provide typed, named access to trace columns.
//! They are borrowed zero-copy from raw `[T; WIDTH]` slices and are used
//! exclusively by constraint code. They are independent of trace storage
//! (`MainTrace`, `TraceStorage`, etc.).

use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use super::{
    AceCols, AceEvalCols, AceReadCols, BitwiseCols, HasherCols, KernelRomCols, MemoryCols,
    RangeCols, StackCols, SystemCols,
    chiplets,
    {AUX_TRACE_WIDTH, CHIPLETS_WIDTH, TRACE_WIDTH},
};
use super::decoder::DecoderCols;

// MAIN TRACE COLUMN STRUCT
// ================================================================================================

/// Column layout of the main execution trace (71 columns).
///
/// This `#[repr(C)]` struct provides typed, named access to every column. It can be
/// borrowed zero-copy from a raw `[T; TRACE_WIDTH]` slice via `Borrow<MainCols<T>>`.
///
/// Chiplet columns are not public because the 20 columns are a union — their interpretation
/// depends on which chiplet is active. Access goes through typed accessors like
/// [`MainCols::hasher()`], [`MainCols::bitwise()`], etc.
#[repr(C)]
pub struct MainCols<T> {
    pub system: SystemCols<T>,
    pub decoder: DecoderCols<T>,
    pub stack: StackCols<T>,
    pub range: RangeCols<T>,
    pub(crate) chiplets: [T; CHIPLETS_WIDTH],
}

impl<T> MainCols<T> {
    /// Returns the 5 shared chiplet selector columns `[s0, s1, s2, s3, s4]`.
    pub fn chiplet_selectors(&self) -> &[T; 5] {
        self.chiplets[0..5].try_into().unwrap()
    }

    /// Returns a typed borrow of the hasher chiplet columns (chiplets\[1..17\]).
    pub fn hasher(&self) -> &HasherCols<T> {
        chiplets::borrow_chiplet(&self.chiplets[1..17])
    }

    /// Returns a typed borrow of the bitwise chiplet columns (chiplets\[2..15\]).
    pub fn bitwise(&self) -> &BitwiseCols<T> {
        chiplets::borrow_chiplet(&self.chiplets[2..15])
    }

    /// Returns a typed borrow of the memory chiplet columns (chiplets\[3..18\]).
    pub fn memory(&self) -> &MemoryCols<T> {
        chiplets::borrow_chiplet(&self.chiplets[3..18])
    }

    /// Returns a typed borrow of the ACE chiplet columns (chiplets\[4..20\]).
    pub fn ace(&self) -> &AceCols<T> {
        chiplets::borrow_chiplet(&self.chiplets[4..20])
    }

    /// Returns a typed borrow of the kernel ROM chiplet columns (chiplets\[5..10\]).
    pub fn kernel_rom(&self) -> &KernelRomCols<T> {
        chiplets::borrow_chiplet(&self.chiplets[5..10])
    }
}

impl<T> Borrow<MainCols<T>> for [T] {
    fn borrow(&self) -> &MainCols<T> {
        debug_assert_eq!(self.len(), TRACE_WIDTH);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<MainCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty() && shorts.len() == 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<MainCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut MainCols<T> {
        debug_assert_eq!(self.len(), TRACE_WIDTH);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<MainCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty() && shorts.len() == 1);
        &mut shorts[0]
    }
}

/// Backwards-compatible alias. Constraint code uses this name; new code can use
/// [`MainCols`] directly.
pub type MainTraceRow<T> = MainCols<T>;

// CONST INDEX MAP
// ================================================================================================

/// Generates an array `[0, 1, 2, ..., N-1]` at compile time.
pub const fn indices_arr<const N: usize>() -> [usize; N] {
    let mut arr = [0; N];
    let mut i = 0;
    while i < N {
        arr[i] = i;
        i += 1;
    }
    arr
}

/// Number of columns in the main trace, derived from the struct layout.
pub const NUM_MAIN_COLS: usize = size_of::<MainCols<u8>>();

/// Compile-time index map: each field holds its column index.
///
/// Example: `MAIN_COL_MAP.decoder.addr == 6`, `MAIN_COL_MAP.stack.top[0] == 30`.
pub const MAIN_COL_MAP: MainCols<usize> = {
    assert!(NUM_MAIN_COLS == TRACE_WIDTH);
    unsafe { core::mem::transmute(indices_arr::<NUM_MAIN_COLS>()) }
};

// AUXILIARY TRACE COLUMN STRUCT
// ================================================================================================

/// Column layout of the auxiliary execution trace (8 columns).
#[repr(C)]
pub struct AuxCols<T> {
    /// Decoder: block stack table running product.
    pub p1_block_stack: T,
    /// Decoder: block hash table running product.
    pub p2_block_hash: T,
    /// Decoder: op group table running product.
    pub p3_op_group: T,
    /// Stack overflow running product.
    pub stack_overflow: T,
    /// Range checker LogUp sum.
    pub range_check: T,
    /// Hash-kernel virtual table bus.
    pub hash_kernel_vtable: T,
    /// Chiplets bus running product.
    pub chiplets_bus: T,
    /// ACE wiring LogUp sum.
    pub ace_wiring: T,
}

/// Number of columns in the auxiliary trace, derived from the struct layout.
pub const NUM_AUX_COLS: usize = size_of::<AuxCols<u8>>();

/// Compile-time index map for auxiliary columns.
pub const AUX_COL_MAP: AuxCols<usize> = {
    assert!(NUM_AUX_COLS == AUX_TRACE_WIDTH);
    unsafe { core::mem::transmute(indices_arr::<NUM_AUX_COLS>()) }
};

// COMPILE-TIME SIZE ASSERTIONS
// ================================================================================================

const _: () = assert!(size_of::<MainCols<u8>>() == TRACE_WIDTH);
const _: () = assert!(size_of::<AuxCols<u8>>() == AUX_TRACE_WIDTH);
const _: () = assert!(size_of::<SystemCols<u8>>() == 6);
const _: () = assert!(size_of::<DecoderCols<u8>>() == 24);
const _: () = assert!(size_of::<StackCols<u8>>() == 19);
const _: () = assert!(size_of::<RangeCols<u8>>() == 2);
const _: () = assert!(size_of::<HasherCols<u8>>() == 16);
const _: () = assert!(size_of::<BitwiseCols<u8>>() == 13);
const _: () = assert!(size_of::<MemoryCols<u8>>() == 15);
const _: () = assert!(size_of::<AceCols<u8>>() == 16);
const _: () = assert!(size_of::<AceReadCols<u8>>() == 4);
const _: () = assert!(size_of::<AceEvalCols<u8>>() == 4);
const _: () = assert!(size_of::<KernelRomCols<u8>>() == 5);
