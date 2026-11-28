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
        AceCols, AceEvalCols, AceReadCols, AeadStreamCols, AeadStreamHighFirstCols,
        AeadStreamHighSecondCols, AeadStreamLowSecondCols, AeadStreamReadCols, BitwiseOpCols,
        ControllerCols, KernelRomCols, MemoryCols,
    },
    decoder::columns::DecoderCols,
    stack::columns::StackCols,
    system::columns::SystemCols,
};
use crate::vm::trace::{CHIPLETS_WIDTH, TRACE_WIDTH};

// CORE TRACE COLUMN STRUCT
// ================================================================================================

/// Column layout of the core execution trace.
///
/// `CoreCols` covers the system, decoder, and stack segments — the columns owned by `CoreAir`.
/// It is also the layout of the leading `NUM_CORE_COLS` columns of the unified `TRACE_WIDTH`-wide
/// main trace, so it can be borrowed from either a per-AIR
/// `[T; NUM_CORE_COLS]` slice or the prefix of a `[T; TRACE_WIDTH]` row via
/// `Borrow<CoreCols<T>>`.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct CoreCols<T> {
    pub system: SystemCols<T>,
    pub decoder: DecoderCols<T>,
    pub stack: StackCols<T>,
}

/// Number of columns in the core trace (48), derived from the struct layout.
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
/// `ChipletCols` covers the shared chiplet columns.
/// The casting accessors expose each chiplet's typed row overlay over the shared cells.
/// These are the columns owned by `ChipletsAir`. It is also the layout of the trailing
/// `NUM_CHIPLETS_COLS`
/// columns of the unified main trace, so it can be borrowed from either a per-AIR
/// `[T; NUM_CHIPLETS_COLS]` slice or the suffix of a `[T; TRACE_WIDTH]` row via
/// `Borrow<ChipletCols<T>>`.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct ChipletCols<T> {
    pub(crate) chiplets: [T; CHIPLETS_WIDTH],
}

/// Number of columns in the chiplets trace, derived from the struct layout.
pub const NUM_CHIPLETS_COLS: usize = size_of::<ChipletCols<u8>>();

impl<T> ChipletCols<T> {
    /// Returns the controller overlay over shared columns `1..24`.
    ///
    /// Meaningful only on controller rows; other chiplets reuse these cells for their own overlays.
    pub fn controller_cols(&self) -> &ControllerCols<T> {
        self.chiplets[1..24].borrow()
    }

    /// Returns the ordinary bitwise operation overlay over shared columns `3..16`.
    pub fn bitwise_cols(&self) -> &BitwiseOpCols<T> {
        self.chiplets[3..16].borrow()
    }

    /// Returns the AEAD stream overlay over shared columns `3..23`.
    pub fn aead_stream_cols(&self) -> &AeadStreamCols<T> {
        self.chiplets[3..23].borrow()
    }

    /// Returns the memory overlay over shared columns `3..20`.
    pub fn memory_cols(&self) -> &MemoryCols<T> {
        self.chiplets[3..20].borrow()
    }

    /// Returns the ACE overlay over shared columns `4..20`.
    pub fn ace_cols(&self) -> &AceCols<T> {
        self.chiplets[4..20].borrow()
    }

    /// Returns the kernel ROM overlay over shared columns `5..10`.
    pub fn kernel_rom_cols(&self) -> &KernelRomCols<T> {
        self.chiplets[5..10].borrow()
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
// and `ChipletsAir`'s `AuxBuilder` impls (see `crates/air/source/src/vm/constraints/lookup/`): 4
// Core columns + 4 Chiplets columns.

pub const NUM_SYSTEM_COLS: usize = size_of::<SystemCols<u8>>();
pub const NUM_DECODER_COLS: usize = size_of::<DecoderCols<u8>>();
pub const NUM_STACK_COLS: usize = size_of::<StackCols<u8>>();
pub const NUM_BITWISE_OP_COLS: usize = size_of::<BitwiseOpCols<u8>>();
pub const NUM_AEAD_STREAM_COLS: usize = size_of::<AeadStreamCols<u8>>();
pub const NUM_AEAD_STREAM_READ_COLS: usize = size_of::<AeadStreamReadCols<u8>>();
pub const NUM_AEAD_STREAM_HIGH_FIRST_COLS: usize = size_of::<AeadStreamHighFirstCols<u8>>();
pub const NUM_AEAD_STREAM_LOW_SECOND_COLS: usize = size_of::<AeadStreamLowSecondCols<u8>>();
pub const NUM_AEAD_STREAM_HIGH_SECOND_COLS: usize = size_of::<AeadStreamHighSecondCols<u8>>();
pub const NUM_MEMORY_COLS: usize = size_of::<MemoryCols<u8>>();
pub const NUM_ACE_COLS: usize = size_of::<AceCols<u8>>();
pub const NUM_ACE_READ_COLS: usize = size_of::<AceReadCols<u8>>();
pub const NUM_ACE_EVAL_COLS: usize = size_of::<AceEvalCols<u8>>();
pub const NUM_KERNEL_ROM_COLS: usize = size_of::<KernelRomCols<u8>>();

const _: () = assert!(NUM_SYSTEM_COLS == 6);
const _: () = assert!(NUM_DECODER_COLS == 23);
const _: () = assert!(NUM_STACK_COLS == 19);
const _: () = assert!(NUM_BITWISE_OP_COLS == 13);
const _: () = assert!(NUM_AEAD_STREAM_COLS == 20);
const _: () = assert!(NUM_AEAD_STREAM_READ_COLS == 20);
const _: () = assert!(NUM_AEAD_STREAM_HIGH_FIRST_COLS == 20);
const _: () = assert!(NUM_AEAD_STREAM_LOW_SECOND_COLS == 20);
const _: () = assert!(NUM_AEAD_STREAM_HIGH_SECOND_COLS == 20);
const _: () = assert!(NUM_MEMORY_COLS == 17);
const _: () = assert!(NUM_ACE_COLS == 16);
const _: () = assert!(NUM_ACE_READ_COLS == 4);
const _: () = assert!(NUM_ACE_EVAL_COLS == 4);
const _: () = assert!(NUM_KERNEL_ROM_COLS == 5);

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::trace::{CHIPLETS_WIDTH, DECODER_TRACE_WIDTH, SYS_TRACE_WIDTH};

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
        assert_eq!(CORE_COL_MAP.decoder.full_batch, DECODER_OFFSET + 19);
        assert_eq!(CORE_COL_MAP.decoder.batch_size_code, DECODER_OFFSET + 20);
        assert_eq!(CORE_COL_MAP.decoder.extra[0], DECODER_OFFSET + 21);
    }

    #[test]
    fn col_map_stack() {
        assert_eq!(CORE_COL_MAP.stack.top[0], STACK_OFFSET);
        assert_eq!(CORE_COL_MAP.stack.top[15], STACK_OFFSET + 15);
        assert_eq!(CORE_COL_MAP.stack.b0, STACK_OFFSET + 16);
        assert_eq!(CORE_COL_MAP.stack.b1, STACK_OFFSET + 17);
        assert_eq!(CORE_COL_MAP.stack.h0, STACK_OFFSET + 18);
    }

    // --- Chiplet trace column map -------------------------------------------------------------
    //
    // `CHIPLET_COL_MAP` is 0-based within `ChipletCols`.

    #[test]
    fn col_map_chiplets() {
        let controller = CHIPLET_COL_MAP.controller_cols();
        assert_eq!(controller.s0, 1);
        assert_eq!(controller.state[0], 4);
        assert_eq!(controller.row_data[0], 16);
        assert_eq!(controller.op_final, 20);
        assert_eq!(controller.mrupdate_id, 21);
        assert_eq!(controller.merkle_or_padding, 22);
        assert_eq!(controller.addr, 23);
        assert_eq!(NUM_CHIPLETS_COLS, 24);
        let bitwise = CHIPLET_COL_MAP.bitwise_cols();
        assert_eq!((bitwise.op_flag, bitwise.and_bytes[3]), (3, 15));
        let stream = CHIPLET_COL_MAP.aead_stream_cols();
        assert_eq!((stream.payload[0], stream.payload[19]), (3, 22));
        let memory = CHIPLET_COL_MAP.memory_cols();
        assert_eq!((memory.is_read, memory.is_same_ctx_and_addr), (3, 17));
        assert_eq!((memory.word_addr_lo, memory.word_addr_hi), (18, 19));
        let ace = CHIPLET_COL_MAP.ace_cols();
        assert_eq!((ace.s_start, ace.eval().m_0), (4, 19));
        let kernel_rom = CHIPLET_COL_MAP.kernel_rom_cols();
        assert_eq!((kernel_rom.multiplicity, kernel_rom.root[3]), (5, 9));
    }

    // --- Per-AIR width invariants -------------------------------------------------------------

    /// `NUM_CORE_COLS` matches the sum of the segment widths it covers.
    #[test]
    fn core_cols_width() {
        assert_eq!(NUM_CORE_COLS, NUM_SYSTEM_COLS + NUM_DECODER_COLS + NUM_STACK_COLS,);
    }

    /// `NUM_CHIPLETS_COLS` matches the chiplets segment width.
    #[test]
    fn chiplet_cols_width() {
        assert_eq!(NUM_CHIPLETS_COLS, CHIPLETS_WIDTH);
    }

    // --- Layout snapshots ---------------------------------------------------------------------
    //
    // These pin the resolved column-index maps of each `Cols<T>` view to `.snap` files,
    // so layout changes surface as snapshot diffs.
    // Regenerate with `cargo insta review` (or `INSTA_UPDATE=auto cargo test -p
    // miden-air-definitions`).

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
    fn bitwise_op_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(BitwiseOpCols));
    }

    #[test]
    fn aead_stream_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(AeadStreamCols));
    }

    #[test]
    fn aead_stream_read_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(AeadStreamReadCols));
    }

    #[test]
    fn aead_stream_high_first_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(AeadStreamHighFirstCols));
    }

    #[test]
    fn aead_stream_low_second_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(AeadStreamLowSecondCols));
    }

    #[test]
    fn aead_stream_high_second_col_map_layout() {
        insta::assert_debug_snapshot!(col_map!(AeadStreamHighSecondCols));
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
}
