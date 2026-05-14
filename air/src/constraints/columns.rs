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
use crate::trace::{CHIPLETS_WIDTH, TRACE_WIDTH};

// CORE TRACE COLUMN STRUCT
// ================================================================================================

/// Column layout of the core execution trace.
///
/// `CoreCols` covers the system, decoder, stack, and range-check segments — the columns owned
/// by `CoreAir`. It is also the layout of the leading `NUM_CORE_COLS` columns of the unified
/// `TRACE_WIDTH`-wide main trace, so it can be borrowed from either a per-AIR
/// `[T; NUM_CORE_COLS]` slice or the prefix of a `[T; TRACE_WIDTH]` row via
/// `Borrow<CoreCols<T>>`.
#[repr(C)]
pub struct CoreCols<T> {
    pub system: SystemCols<T>,
    pub decoder: DecoderCols<T>,
    pub stack: StackCols<T>,
    pub range: RangeCols<T>,
}

/// Number of columns in the core trace (51), derived from the struct layout.
pub const NUM_CORE_COLS: usize = size_of::<CoreCols<u8>>();

impl<T> Borrow<CoreCols<T>> for [T] {
    fn borrow(&self) -> &CoreCols<T> {
        debug_assert_eq!(self.len(), NUM_CORE_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<CoreCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty() && shorts.len() == 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<CoreCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut CoreCols<T> {
        debug_assert_eq!(self.len(), NUM_CORE_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<CoreCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty() && shorts.len() == 1);
        &mut shorts[0]
    }
}

// CHIPLETS TRACE COLUMN STRUCT
// ================================================================================================

/// Column layout of the chiplets execution trace.
///
/// `ChipletCols` covers the 20 shared chiplet data columns + `s_perm` + `chip_clk` — the
/// columns owned by `ChipletsAir`. It is also the layout of the trailing `NUM_CHIPLETS_COLS`
/// columns of the unified main trace, so it can be borrowed from either a per-AIR
/// `[T; NUM_CHIPLETS_COLS]` slice or the suffix of a `[T; TRACE_WIDTH]` row via
/// `Borrow<ChipletCols<T>>`.
#[repr(C)]
pub struct ChipletCols<T> {
    pub(crate) chiplets: [T; CHIPLETS_WIDTH - 2],
    /// Permutation segment selector: consumed by `build_chiplet_selectors`.
    pub s_perm: T,
    /// Chiplet-trace row counter: starts at 1 on the first row, increments by 1 each row.
    pub chip_clk: T,
}

/// Number of columns in the chiplets trace (21), derived from the struct layout.
pub const NUM_CHIPLETS_COLS: usize = size_of::<ChipletCols<u8>>();

impl<T> ChipletCols<T> {
    /// Returns the 6 chiplet selector columns `[s_ctrl, s_perm, s1, s2, s3, s4]`.
    ///
    /// `s_ctrl = chiplets[0]` and `s_perm` are the two physical selectors for the controller
    /// and permutation sub-chiplets. `s1..s4` subdivide the remaining chiplets under the
    /// virtual `s0 = 1 - (s_ctrl + s_perm)`.
    pub fn chiplet_selectors(&self) -> [T; 6]
    where
        T: Copy,
    {
        [
            self.chiplets[0],
            self.s_perm,
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

impl<T> Borrow<ChipletCols<T>> for [T] {
    fn borrow(&self) -> &ChipletCols<T> {
        debug_assert_eq!(self.len(), NUM_CHIPLETS_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<ChipletCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty() && shorts.len() == 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<ChipletCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut ChipletCols<T> {
        debug_assert_eq!(self.len(), NUM_CHIPLETS_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<ChipletCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty() && shorts.len() == 1);
        &mut shorts[0]
    }
}

// Compile-time invariant: the two halves cover the full main trace exactly.
const _: () = assert!(NUM_CORE_COLS + NUM_CHIPLETS_COLS == TRACE_WIDTH);

// CONST HELPERS
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

// COLUMN COUNTS
// ================================================================================================
//
// The auxiliary trace is the LogUp lookup-argument segment built by
// [`crate::ProcessorAir`]'s `AuxBuilder` impl (see `air/src/constraints/lookup/`).
// Its 7-column layout is described entirely by `ProcessorAir::column_shape`.

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
        CHIPLETS_OFFSET, CLK_COL_IDX, CTX_COL_IDX, DECODER_TRACE_OFFSET, FN_HASH_OFFSET,
        STACK_TRACE_OFFSET, decoder, range, stack,
    };

    /// Per-AIR index maps used only by the column-layout tests below. Each field holds its
    /// column index inside its own AIR. `CORE_COL_MAP` lines up with unified-trace offsets
    /// since `CoreCols` sits at offset 0; `CHIPLET_COL_MAP` is 0-based within `ChipletCols`.
    const CORE_COL_MAP: CoreCols<usize> = unsafe {
        core::mem::transmute::<[usize; NUM_CORE_COLS], CoreCols<usize>>(
            indices_arr::<NUM_CORE_COLS>(),
        )
    };

    const CHIPLET_COL_MAP: ChipletCols<usize> = unsafe {
        core::mem::transmute::<[usize; NUM_CHIPLETS_COLS], ChipletCols<usize>>(indices_arr::<
            NUM_CHIPLETS_COLS,
        >())
    };

    // --- Core trace column map vs offset constants -------------------------------------------
    //
    // `CoreCols` starts at offset 0 of the unified main trace, so its per-AIR indices match
    // the unified trace offsets one-for-one.

    #[test]
    fn col_map_system() {
        assert_eq!(CORE_COL_MAP.system.clk, CLK_COL_IDX);
        assert_eq!(CORE_COL_MAP.system.ctx, CTX_COL_IDX);
        assert_eq!(CORE_COL_MAP.system.fn_hash[0], FN_HASH_OFFSET);
        assert_eq!(CORE_COL_MAP.system.fn_hash[3], FN_HASH_OFFSET + 3);
    }

    #[test]
    fn col_map_decoder() {
        assert_eq!(CORE_COL_MAP.decoder.addr, DECODER_TRACE_OFFSET + decoder::ADDR_COL_IDX);
        assert_eq!(CORE_COL_MAP.decoder.op_bits[0], DECODER_TRACE_OFFSET + decoder::OP_BITS_OFFSET);
        assert_eq!(
            CORE_COL_MAP.decoder.op_bits[6],
            DECODER_TRACE_OFFSET + decoder::OP_BITS_OFFSET + 6
        );
        assert_eq!(
            CORE_COL_MAP.decoder.hasher_state[0],
            DECODER_TRACE_OFFSET + decoder::HASHER_STATE_OFFSET
        );
        assert_eq!(CORE_COL_MAP.decoder.in_span, DECODER_TRACE_OFFSET + decoder::IN_SPAN_COL_IDX);
        assert_eq!(
            CORE_COL_MAP.decoder.group_count,
            DECODER_TRACE_OFFSET + decoder::GROUP_COUNT_COL_IDX
        );
        assert_eq!(CORE_COL_MAP.decoder.op_index, DECODER_TRACE_OFFSET + decoder::OP_INDEX_COL_IDX);
        assert_eq!(
            CORE_COL_MAP.decoder.batch_flags[0],
            DECODER_TRACE_OFFSET + decoder::OP_BATCH_FLAGS_OFFSET
        );
        assert_eq!(
            CORE_COL_MAP.decoder.extra[0],
            DECODER_TRACE_OFFSET + decoder::OP_BITS_EXTRA_COLS_OFFSET
        );
    }

    #[test]
    fn col_map_stack() {
        assert_eq!(CORE_COL_MAP.stack.top[0], STACK_TRACE_OFFSET + stack::STACK_TOP_OFFSET);
        assert_eq!(CORE_COL_MAP.stack.top[15], STACK_TRACE_OFFSET + 15);
        assert_eq!(CORE_COL_MAP.stack.b0, STACK_TRACE_OFFSET + stack::B0_COL_IDX);
        assert_eq!(CORE_COL_MAP.stack.b1, STACK_TRACE_OFFSET + stack::B1_COL_IDX);
        assert_eq!(CORE_COL_MAP.stack.h0, STACK_TRACE_OFFSET + stack::H0_COL_IDX);
    }

    #[test]
    fn col_map_range() {
        assert_eq!(CORE_COL_MAP.range.multiplicity, range::M_COL_IDX);
        assert_eq!(CORE_COL_MAP.range.value, range::V_COL_IDX);
    }

    // --- Chiplet trace column map -------------------------------------------------------------
    //
    // `CHIPLET_COL_MAP` is 0-based within `ChipletCols`. Adding `NUM_CORE_COLS` (=
    // `CHIPLETS_OFFSET`) recovers the unified-trace offset.

    #[test]
    fn col_map_chiplets() {
        assert_eq!(CHIPLET_COL_MAP.chiplets[0], 0);
        assert_eq!(CHIPLET_COL_MAP.chiplets[19], 19);
        assert_eq!(CHIPLET_COL_MAP.s_perm, 20);
        assert_eq!(CHIPLET_COL_MAP.chip_clk, 21);
        // Sanity: NUM_CORE_COLS lines up with the unified-trace chiplets offset.
        assert_eq!(NUM_CORE_COLS, CHIPLETS_OFFSET);
    }

    // --- Multi-AIR split: CoreCols + ChipletCols widths ---------------------------------------

    /// `NUM_CORE_COLS` matches the sum of the segment widths it covers.
    #[test]
    fn core_cols_width() {
        assert_eq!(
            NUM_CORE_COLS,
            NUM_SYSTEM_COLS + NUM_DECODER_COLS + NUM_STACK_COLS + NUM_RANGE_COLS,
        );
        // The core trace covers everything from the start of the system segment up to the
        // chiplets boundary.
        assert_eq!(NUM_CORE_COLS, CHIPLETS_OFFSET);
    }

    /// `NUM_CHIPLETS_COLS` matches the chiplets segment width.
    #[test]
    fn chiplet_cols_width() {
        assert_eq!(NUM_CHIPLETS_COLS, crate::trace::CHIPLETS_WIDTH);
    }
}
