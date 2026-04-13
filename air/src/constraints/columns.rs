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
    chiplets::columns::{
        AceCols, AceEvalCols, AceReadCols, BitwiseCols, ControllerCols, KernelRomCols, MemoryCols,
        PermutationCols, borrow_chiplet,
    },
    decoder::columns::DecoderCols,
    range::columns::RangeCols,
    stack::columns::StackCols,
    system::columns::SystemCols,
};
use crate::trace::{AUX_TRACE_WIDTH, CHIPLETS_WIDTH, TRACE_WIDTH};

// MAIN TRACE COLUMN STRUCT
// ================================================================================================

/// Column layout of the main execution trace (71 columns).
///
/// This `#[repr(C)]` struct provides typed, named access to every column. It can be
/// borrowed zero-copy from a raw `[T; TRACE_WIDTH]` slice via `Borrow<MainCols<T>>`.
///
/// Chiplet columns are not public because the 20 columns are a union — their interpretation
/// depends on which chiplet is active. Access goes through typed accessors like
/// [`MainCols::permutation()`], [`MainCols::controller()`], [`MainCols::bitwise()`], etc.
///
/// The `perm_seg` column is separated from the chiplets array because it is consumed
/// exclusively by the chiplet selector system (`s_perm`), not by any chiplet's constraint
/// code.
#[repr(C)]
pub struct MainCols<T> {
    pub system: SystemCols<T>,
    pub decoder: DecoderCols<T>,
    pub stack: StackCols<T>,
    pub range: RangeCols<T>,
    pub(crate) chiplets: [T; CHIPLETS_WIDTH - 1],
    /// Permutation segment selector (`s_perm`): consumed by `build_chiplet_selectors`.
    pub perm_seg: T,
}

impl<T> MainCols<T> {
    /// Returns the 6 chiplet selector columns `[s_ctrl, s_perm, s1, s2, s3, s4]`.
    ///
    /// `s_ctrl = chiplets[0]` and `s_perm = perm_seg` are the two physical selectors
    /// for the controller and permutation sub-chiplets. `s1..s4` subdivide the
    /// remaining chiplets under the virtual `s0 = 1 - (s_ctrl + s_perm)`.
    pub fn chiplet_selectors(&self) -> [T; 6]
    where
        T: Copy,
    {
        [
            self.chiplets[0],
            self.perm_seg,
            self.chiplets[1],
            self.chiplets[2],
            self.chiplets[3],
            self.chiplets[4],
        ]
    }

    /// Returns a typed borrow of the bitwise chiplet columns (chiplets\[2..15\]).
    pub fn bitwise(&self) -> &BitwiseCols<T> {
        borrow_chiplet(&self.chiplets[2..15])
    }

    /// Returns a typed borrow of the memory chiplet columns (chiplets\[3..18\]).
    pub fn memory(&self) -> &MemoryCols<T> {
        borrow_chiplet(&self.chiplets[3..18])
    }

    /// Returns a typed borrow of the ACE chiplet columns (chiplets\[4..20\]).
    ///
    /// Spans `chiplets[4..20]` (16 cols). Since `chiplets` has 20 elements (indices
    /// 0..19), this is `chiplets[4..20]` = `chiplets[4..]` (all 16 remaining).
    pub fn ace(&self) -> &AceCols<T> {
        borrow_chiplet(&self.chiplets[4..])
    }

    /// Returns a typed borrow of the kernel ROM chiplet columns (chiplets\[5..10\]).
    pub fn kernel_rom(&self) -> &KernelRomCols<T> {
        borrow_chiplet(&self.chiplets[5..10])
    }

    /// Returns a typed borrow of the permutation sub-chiplet columns (chiplets\[1..20\]).
    pub fn permutation(&self) -> &PermutationCols<T> {
        borrow_chiplet(&self.chiplets[1..])
    }

    /// Returns a typed borrow of the controller sub-chiplet columns (chiplets\[1..20\]).
    pub fn controller(&self) -> &ControllerCols<T> {
        borrow_chiplet(&self.chiplets[1..])
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

/// Number of columns in the main trace (71), derived from the struct layout.
pub const NUM_MAIN_COLS: usize = size_of::<MainCols<u8>>();

/// Compile-time index map: each field holds its column index.
///
/// Example: `MAIN_COL_MAP.decoder.addr == 6`, `MAIN_COL_MAP.stack.top[0] == 30`.
#[allow(dead_code)]
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

/// Number of columns in the auxiliary trace (8), derived from the struct layout.
pub const NUM_AUX_COLS: usize = size_of::<AuxCols<u8>>();

/// Compile-time index map for auxiliary columns.
#[allow(dead_code)]
pub const AUX_COL_MAP: AuxCols<usize> = {
    assert!(NUM_AUX_COLS == AUX_TRACE_WIDTH);
    unsafe { core::mem::transmute(indices_arr::<NUM_AUX_COLS>()) }
};

// COLUMN COUNTS
// ================================================================================================

pub const NUM_SYSTEM_COLS: usize = size_of::<SystemCols<u8>>();
pub const NUM_DECODER_COLS: usize = size_of::<DecoderCols<u8>>();
pub const NUM_STACK_COLS: usize = size_of::<StackCols<u8>>();
pub const NUM_RANGE_COLS: usize = size_of::<RangeCols<u8>>();
pub const NUM_BITWISE_COLS: usize = size_of::<BitwiseCols<u8>>();
pub const NUM_MEMORY_COLS: usize = size_of::<MemoryCols<u8>>();
pub const NUM_ACE_COLS: usize = size_of::<AceCols<u8>>();
pub const NUM_ACE_READ_COLS: usize = size_of::<AceReadCols<u8>>();
pub const NUM_ACE_EVAL_COLS: usize = size_of::<AceEvalCols<u8>>();
pub const NUM_KERNEL_ROM_COLS: usize = size_of::<KernelRomCols<u8>>();

const _: () = assert!(NUM_MAIN_COLS == TRACE_WIDTH);
const _: () = assert!(NUM_AUX_COLS == AUX_TRACE_WIDTH);
const _: () = assert!(NUM_SYSTEM_COLS == 6);
const _: () = assert!(NUM_DECODER_COLS == 24);
const _: () = assert!(NUM_STACK_COLS == 19);
const _: () = assert!(NUM_RANGE_COLS == 2);
const _: () = assert!(NUM_BITWISE_COLS == 13);
const _: () = assert!(NUM_MEMORY_COLS == 15);
const _: () = assert!(NUM_ACE_COLS == 16);
const _: () = assert!(NUM_ACE_READ_COLS == 4);
const _: () = assert!(NUM_ACE_EVAL_COLS == 4);
const _: () = assert!(NUM_KERNEL_ROM_COLS == 5);

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::{
        ACE_CHIPLET_WIRING_BUS_OFFSET, CHIPLETS_BUS_AUX_TRACE_OFFSET, CHIPLETS_OFFSET, CLK_COL_IDX,
        CTX_COL_IDX, DECODER_AUX_TRACE_OFFSET, DECODER_TRACE_OFFSET, FN_HASH_OFFSET,
        HASH_KERNEL_VTABLE_AUX_TRACE_OFFSET, RANGE_CHECK_AUX_TRACE_OFFSET, STACK_AUX_TRACE_OFFSET,
        STACK_TRACE_OFFSET, decoder, range, stack,
    };

    // --- Main trace column map vs legacy constants -----------------------------------------------

    #[test]
    fn col_map_system() {
        assert_eq!(MAIN_COL_MAP.system.clk, CLK_COL_IDX);
        assert_eq!(MAIN_COL_MAP.system.ctx, CTX_COL_IDX);
        assert_eq!(MAIN_COL_MAP.system.fn_hash[0], FN_HASH_OFFSET);
        assert_eq!(MAIN_COL_MAP.system.fn_hash[3], FN_HASH_OFFSET + 3);
    }

    #[test]
    fn col_map_decoder() {
        assert_eq!(MAIN_COL_MAP.decoder.addr, DECODER_TRACE_OFFSET + decoder::ADDR_COL_IDX);
        assert_eq!(MAIN_COL_MAP.decoder.op_bits[0], DECODER_TRACE_OFFSET + decoder::OP_BITS_OFFSET);
        assert_eq!(
            MAIN_COL_MAP.decoder.op_bits[6],
            DECODER_TRACE_OFFSET + decoder::OP_BITS_OFFSET + 6
        );
        assert_eq!(
            MAIN_COL_MAP.decoder.hasher_state[0],
            DECODER_TRACE_OFFSET + decoder::HASHER_STATE_OFFSET
        );
        assert_eq!(MAIN_COL_MAP.decoder.in_span, DECODER_TRACE_OFFSET + decoder::IN_SPAN_COL_IDX);
        assert_eq!(
            MAIN_COL_MAP.decoder.group_count,
            DECODER_TRACE_OFFSET + decoder::GROUP_COUNT_COL_IDX
        );
        assert_eq!(MAIN_COL_MAP.decoder.op_index, DECODER_TRACE_OFFSET + decoder::OP_INDEX_COL_IDX);
        assert_eq!(
            MAIN_COL_MAP.decoder.batch_flags[0],
            DECODER_TRACE_OFFSET + decoder::OP_BATCH_FLAGS_OFFSET
        );
        assert_eq!(
            MAIN_COL_MAP.decoder.extra[0],
            DECODER_TRACE_OFFSET + decoder::OP_BITS_EXTRA_COLS_OFFSET
        );
    }

    #[test]
    fn col_map_stack() {
        assert_eq!(MAIN_COL_MAP.stack.top[0], STACK_TRACE_OFFSET + stack::STACK_TOP_OFFSET);
        assert_eq!(MAIN_COL_MAP.stack.top[15], STACK_TRACE_OFFSET + 15);
        assert_eq!(MAIN_COL_MAP.stack.b0, STACK_TRACE_OFFSET + stack::B0_COL_IDX);
        assert_eq!(MAIN_COL_MAP.stack.b1, STACK_TRACE_OFFSET + stack::B1_COL_IDX);
        assert_eq!(MAIN_COL_MAP.stack.h0, STACK_TRACE_OFFSET + stack::H0_COL_IDX);
    }

    #[test]
    fn col_map_range() {
        assert_eq!(MAIN_COL_MAP.range.multiplicity, range::M_COL_IDX);
        assert_eq!(MAIN_COL_MAP.range.value, range::V_COL_IDX);
    }

    #[test]
    fn col_map_chiplets() {
        assert_eq!(MAIN_COL_MAP.chiplets[0], CHIPLETS_OFFSET);
        assert_eq!(MAIN_COL_MAP.chiplets[19], CHIPLETS_OFFSET + 19);
        // perm_seg is a separate field after chiplets[0..20]
        assert_eq!(MAIN_COL_MAP.perm_seg, CHIPLETS_OFFSET + 20);
    }

    // --- Auxiliary trace column map vs legacy constants
    // -------------------------------------------

    #[test]
    fn aux_col_map() {
        assert_eq!(AUX_COL_MAP.p1_block_stack, DECODER_AUX_TRACE_OFFSET);
        assert_eq!(AUX_COL_MAP.p2_block_hash, DECODER_AUX_TRACE_OFFSET + 1);
        assert_eq!(AUX_COL_MAP.p3_op_group, DECODER_AUX_TRACE_OFFSET + 2);
        assert_eq!(AUX_COL_MAP.stack_overflow, STACK_AUX_TRACE_OFFSET);
        assert_eq!(AUX_COL_MAP.range_check, RANGE_CHECK_AUX_TRACE_OFFSET);
        assert_eq!(AUX_COL_MAP.hash_kernel_vtable, HASH_KERNEL_VTABLE_AUX_TRACE_OFFSET);
        assert_eq!(AUX_COL_MAP.chiplets_bus, CHIPLETS_BUS_AUX_TRACE_OFFSET);
        assert_eq!(AUX_COL_MAP.ace_wiring, ACE_CHIPLET_WIRING_BUS_OFFSET);
    }
}
