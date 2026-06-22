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
        PermutationCols,
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
#[derive(Debug, Clone, Default)]
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

impl<T> CoreCols<T> {
    /// Returns the column layout as a flat slice of length NUM_CORE_COLS, in column-index
    /// order. Useful for column-index → field lookups (e.g. a `CoreCols<&str>` name table).
    pub fn as_slice(&self) -> &[T] {
        let ptr = self as *const Self as *const T;
        unsafe { core::slice::from_raw_parts(ptr, NUM_CORE_COLS) }
    }
}

// CHIPLETS TRACE COLUMN STRUCT
// ================================================================================================

/// Column layout of the chiplets execution trace.
///
/// `ChipletCols` covers the `s_00` and `s_01` chiplet selectors, `chip_clk`, and the 19 shared
/// chiplet data columns — the columns owned by `ChipletsAir`. It is also the layout of the
/// trailing `NUM_CHIPLETS_COLS` columns of the unified main trace, so it can be borrowed from
/// either a per-AIR `[T; NUM_CHIPLETS_COLS]` slice or the suffix of a `[T; TRACE_WIDTH]` row via
/// `Borrow<ChipletCols<T>>`.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct ChipletCols<T> {
    /// Permutation segment selector: consumed by `build_chiplet_selectors`.
    pub s_00: T,
    /// Controller segment selector: consumed by `build_chiplet_selectors`.
    pub s_01: T,
    /// Chiplet-trace row counter: starts at 1 on the first row, increments by 1 each row.
    pub chip_clk: T,
    pub(crate) chiplets: [T; CHIPLETS_WIDTH - 3],
}

/// Number of columns in the chiplets trace (22), derived from the struct layout.
pub const NUM_CHIPLETS_COLS: usize = size_of::<ChipletCols<u8>>();

impl<T> ChipletCols<T> {
    /// Returns the 6 chiplet selector columns `[s_00, s_01, s1, s2, s3, s4]`.
    ///
    /// `s_00` and `s_01` are the two physical selectors for the permutation and controller
    /// sub-chiplets. `s1..s4` subdivide the remaining chiplets under the virtual
    /// `s0 = 1 - (s_00 + s_01)`.
    pub fn chiplet_selectors(&self) -> [T; 6]
    where
        T: Copy,
    {
        [
            self.s_00,
            self.s_01,
            self.chiplets[0],
            self.chiplets[1],
            self.chiplets[2],
            self.chiplets[3],
        ]
    }

    /// Returns a typed borrow of the bitwise chiplet columns (chiplets\[1..14\]).
    pub fn bitwise(&self) -> &BitwiseCols<T> {
        self.chiplets[1..14].borrow()
    }

    /// Returns a typed borrow of the memory chiplet columns (chiplets\[2..17\]).
    pub fn memory(&self) -> &MemoryCols<T> {
        self.chiplets[2..17].borrow()
    }

    /// Returns the lower 16-bit limb of the memory word address (chiplets\[17\]).
    ///
    /// Range-check auxiliary column populated by the trace builder for the lookup-bus
    /// emitter; not part of [`MemoryCols`] because the memory AIR's own transition
    /// constraints don't act on it.
    pub fn memory_word_addr_lo(&self) -> T
    where
        T: Copy,
    {
        self.chiplets[17]
    }

    /// Returns the upper 16-bit limb of the memory word address (chiplets\[18\]).
    ///
    /// See [`Self::memory_word_addr_lo`] for the same caveat about the range-check
    /// auxiliary columns living outside [`MemoryCols`].
    pub fn memory_word_addr_hi(&self) -> T
    where
        T: Copy,
    {
        self.chiplets[18]
    }

    /// Returns a typed borrow of the ACE chiplet columns (chiplets\[3..19\]).
    pub fn ace(&self) -> &AceCols<T> {
        self.chiplets[3..].borrow()
    }

    /// Returns a typed borrow of the kernel ROM chiplet columns (chiplets\[4..9\]).
    pub fn kernel_rom(&self) -> &KernelRomCols<T> {
        self.chiplets[4..9].borrow()
    }

    /// Returns a typed borrow of the permutation sub-chiplet columns (chiplets\[0..19\]).
    pub fn permutation(&self) -> &PermutationCols<T> {
        self.chiplets[..].borrow()
    }

    /// Returns a typed borrow of the controller sub-chiplet columns (chiplets\[0..19\]).
    pub fn controller(&self) -> &ControllerCols<T> {
        self.chiplets[..].borrow()
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
// The auxiliary trace is the LogUp lookup-argument segment built per-AIR by `CoreAir`'s
// and `ChipletsAir`'s `build_aux_trace` (see `air/src/constraints/lookup/`): 4 Core
// columns + 3 Chiplets columns.

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
    use crate::trace::{DECODER_TRACE_WIDTH, STACK_TRACE_WIDTH, SYS_TRACE_WIDTH};

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

    /// Column offset of the decoder section within the unified main trace.
    const DECODER_OFFSET: usize = SYS_TRACE_WIDTH;
    /// Column offset of the stack section within the unified main trace.
    const STACK_OFFSET: usize = SYS_TRACE_WIDTH + DECODER_TRACE_WIDTH;
    /// Column offset of the range-check section within the unified main trace.
    const RANGE_OFFSET: usize = STACK_OFFSET + STACK_TRACE_WIDTH;

    // --- Core trace column map vs offset constants -------------------------------------------
    //
    // `CoreCols` starts at offset 0 of the unified main trace, so its per-AIR indices match
    // the unified trace offsets one-for-one.

    #[test]
    fn col_map_system() {
        assert_eq!(CORE_COL_MAP.system.clk, 0);
        assert_eq!(CORE_COL_MAP.system.ctx, 1);
        assert_eq!(CORE_COL_MAP.system.fn_hash[0], 2);
        assert_eq!(CORE_COL_MAP.system.fn_hash[3], 5);
    }

    #[test]
    fn col_map_decoder() {
        assert_eq!(CORE_COL_MAP.decoder.addr, DECODER_OFFSET);
        assert_eq!(CORE_COL_MAP.decoder.op_bits[0], DECODER_OFFSET + 1);
        assert_eq!(CORE_COL_MAP.decoder.op_bits[6], DECODER_OFFSET + 7);
        assert_eq!(CORE_COL_MAP.decoder.hasher_state[0], DECODER_OFFSET + 8);
        assert_eq!(CORE_COL_MAP.decoder.in_span, DECODER_OFFSET + 16);
        assert_eq!(CORE_COL_MAP.decoder.group_count, DECODER_OFFSET + 17);
        assert_eq!(CORE_COL_MAP.decoder.op_index, DECODER_OFFSET + 18);
        assert_eq!(CORE_COL_MAP.decoder.batch_flags[0], DECODER_OFFSET + 19);
        assert_eq!(CORE_COL_MAP.decoder.extra[0], DECODER_OFFSET + 22);
    }

    #[test]
    fn col_map_stack() {
        assert_eq!(CORE_COL_MAP.stack.top[0], STACK_OFFSET);
        assert_eq!(CORE_COL_MAP.stack.top[15], STACK_OFFSET + 15);
        assert_eq!(CORE_COL_MAP.stack.b0, STACK_OFFSET + 16);
        assert_eq!(CORE_COL_MAP.stack.b1, STACK_OFFSET + 17);
        assert_eq!(CORE_COL_MAP.stack.h0, STACK_OFFSET + 18);
    }

    #[test]
    fn col_map_range() {
        assert_eq!(CORE_COL_MAP.range.multiplicity, RANGE_OFFSET);
        assert_eq!(CORE_COL_MAP.range.value, RANGE_OFFSET + 1);
    }

    // --- Chiplet trace column map -------------------------------------------------------------
    //
    // `CHIPLET_COL_MAP` is 0-based within `ChipletCols`.

    #[test]
    fn col_map_chiplets() {
        assert_eq!(CHIPLET_COL_MAP.s_00, 0);
        assert_eq!(CHIPLET_COL_MAP.s_01, 1);
        assert_eq!(CHIPLET_COL_MAP.chip_clk, 2);
        assert_eq!(CHIPLET_COL_MAP.chiplets[0], 3);
        assert_eq!(CHIPLET_COL_MAP.chiplets[18], 21);
    }

    // --- Multi-AIR split: CoreCols + ChipletCols widths ---------------------------------------

    /// `NUM_CORE_COLS` matches the sum of the segment widths it covers.
    #[test]
    fn core_cols_width() {
        assert_eq!(
            NUM_CORE_COLS,
            NUM_SYSTEM_COLS + NUM_DECODER_COLS + NUM_STACK_COLS + NUM_RANGE_COLS,
        );
    }

    /// `NUM_CHIPLETS_COLS` matches the chiplets segment width.
    #[test]
    fn chiplet_cols_width() {
        assert_eq!(NUM_CHIPLETS_COLS, CHIPLETS_WIDTH);
    }

    // --- Layout snapshots ---------------------------------------------------------------------
    //
    // These pin the resolved column-index maps of each `Cols<T>` view to `.snap` files,
    // so any layout change surfaces as a snapshot diff in PR review.
    // Regenerate with `cargo insta review` (or `INSTA_UPDATE=auto cargo test -p miden-air`).

    /// Builds a `$cols<usize>` index map by reinterpreting `[0, 1, …, N-1]` through the
    /// struct's `#[repr(C)]` layout, where `N = size_of::<$cols<u8>>()`.
    macro_rules! col_map {
        ($cols:ident) => {{
            const N: usize = core::mem::size_of::<$cols<u8>>();
            const M: $cols<usize> =
                unsafe { core::mem::transmute::<[usize; N], $cols<usize>>(indices_arr::<N>()) };
            M
        }};
    }

    #[test]
    fn core_col_map_layout() {
        insta::assert_debug_snapshot!(CORE_COL_MAP);
    }

    #[test]
    fn chiplet_col_map_layout() {
        insta::assert_debug_snapshot!(CHIPLET_COL_MAP);
    }

    #[test]
    fn bitwise_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(BitwiseCols));
    }

    #[test]
    fn memory_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(MemoryCols));
    }

    #[test]
    fn ace_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(AceCols));
    }

    #[test]
    fn ace_read_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(AceReadCols));
    }

    #[test]
    fn ace_eval_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(AceEvalCols));
    }

    #[test]
    fn kernel_rom_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(KernelRomCols));
    }

    #[test]
    fn hasher_controller_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(ControllerCols));
    }

    #[test]
    fn hasher_permutation_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(PermutationCols));
    }
}
