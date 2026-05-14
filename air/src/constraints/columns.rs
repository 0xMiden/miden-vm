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

// MAIN TRACE COLUMN STRUCT
// ================================================================================================

/// Column layout of the main execution trace.
///
/// This `#[repr(C)]` struct provides typed, named access to every column. It can be
/// borrowed zero-copy from a raw `[T; TRACE_WIDTH]` slice via `Borrow<MainCols<T>>`.
///
/// Chiplet columns are not public because the 20 columns are a union — their interpretation
/// depends on which chiplet is active. Access goes through typed accessors like
/// [`MainCols::permutation()`], [`MainCols::controller()`], [`MainCols::bitwise()`], etc.
///
/// The `s_perm` column is separated from the chiplets array because it is consumed
/// exclusively by the chiplet selector system, not by any chiplet's constraint code.
#[repr(C)]
pub struct MainCols<T> {
    pub system: SystemCols<T>,
    pub decoder: DecoderCols<T>,
    pub stack: StackCols<T>,
    pub range: RangeCols<T>,
    pub(crate) chiplets: [T; CHIPLETS_WIDTH - 2],
    /// Permutation segment selector: consumed by `build_chiplet_selectors`.
    pub s_perm: T,
    /// Chiplet-trace row counter: starts at 1 on the first row, increments by 1 each row.
    pub chip_clk: T,
}

impl<T> MainCols<T> {
    /// Returns the 6 chiplet selector columns `[s_ctrl, s_perm, s1, s2, s3, s4]`.
    ///
    /// `s_ctrl = chiplets[0]` and `s_perm` are the two physical selectors
    /// for the controller and permutation sub-chiplets. `s1..s4` subdivide the
    /// remaining chiplets under the virtual `s0 = 1 - (s_ctrl + s_perm)`.
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

    /// Returns the leading system + decoder + stack + range fields as a `&CoreCols<T>`.
    ///
    /// Bridges the legacy `MainCols`-based call sites to the multi-AIR `CoreCols` view
    /// without requiring callers to re-borrow from a slice. `MainCols<T>` and `CoreCols<T>`
    /// are both `#[repr(C)]` and the leading portion of `MainCols<T>` (`system`, `decoder`,
    /// `stack`, `range`) has the same layout as the entirety of `CoreCols<T>` — verified at
    /// runtime by the alignment tests in this module and at compile time by the
    /// `NUM_CORE_COLS + NUM_CHIPLETS_COLS == TRACE_WIDTH` assertion.
    pub fn as_core_cols(&self) -> &CoreCols<T> {
        // SAFETY: `MainCols<T>` is `#[repr(C)]` with the field order
        // `[system, decoder, stack, range, chiplets, s_perm]`. `CoreCols<T>` is also
        // `#[repr(C)]` with the field order `[system, decoder, stack, range]` and the same
        // field types and alignment as the leading fields of `MainCols<T>`. Since the leading
        // field of `MainCols` is `system` at offset 0, the pointer cast is a no-op
        // re-interpretation. The resulting reference's lifetime is tied to `&self`, which
        // prevents aliasing with any later mutation.
        unsafe { &*(self as *const Self).cast::<CoreCols<T>>() }
    }

    /// Returns the trailing chiplets + s_perm fields as a `&ChipletCols<T>`.
    ///
    /// Bridges the legacy `MainCols`-based call sites to the multi-AIR `ChipletCols` view
    /// without requiring callers to re-borrow from a slice. `MainCols<T>` and `ChipletCols<T>`
    /// are both `#[repr(C)]` and the trailing portion of `MainCols<T>` (`chiplets` +
    /// `s_perm`) has the same layout as the entirety of `ChipletCols<T>` — verified at
    /// runtime by the alignment tests in this module and at compile time by the
    /// `NUM_CORE_COLS + NUM_CHIPLETS_COLS == TRACE_WIDTH` assertion.
    pub fn as_chiplet_cols(&self) -> &ChipletCols<T> {
        // SAFETY: `MainCols<T>` is `#[repr(C)]` with the field order
        // `[system, decoder, stack, range, chiplets, s_perm]`. `ChipletCols<T>` is also
        // `#[repr(C)]` with the field order `[chiplets, s_perm]` and the same field types
        // and alignment as the trailing fields of `MainCols<T>`. The pointer arithmetic
        // computes the byte offset of the `chiplets` field via `offset_of!` and reinterprets
        // the pointer there as a `&ChipletCols<T>`. The resulting reference's lifetime is
        // tied to `&self`, which prevents aliasing with any later mutation.
        unsafe {
            let chiplets_ptr =
                (self as *const Self).cast::<u8>().add(core::mem::offset_of!(Self, chiplets));
            &*chiplets_ptr.cast::<ChipletCols<T>>()
        }
    }
}

impl<T> Borrow<MainCols<T>> for [T] {
    fn borrow(&self) -> &MainCols<T> {
        debug_assert!(self.len() >= TRACE_WIDTH);
        let (prefix, shorts, _suffix) = unsafe { self[..TRACE_WIDTH].align_to::<MainCols<T>>() };
        debug_assert!(prefix.is_empty() && shorts.len() == 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<MainCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut MainCols<T> {
        debug_assert!(self.len() >= TRACE_WIDTH);
        let (prefix, shorts, _suffix) =
            unsafe { self[..TRACE_WIDTH].align_to_mut::<MainCols<T>>() };
        debug_assert!(prefix.is_empty() && shorts.len() == 1);
        &mut shorts[0]
    }
}

// CORE TRACE COLUMN STRUCT
// ================================================================================================

/// Column layout of the core execution trace.
///
/// `CoreCols` covers the system, decoder, stack, and range-check segments — the columns owned
/// by `CoreAir`. It is laid out identically to the leading `NUM_CORE_COLS` columns of
/// `MainCols` (`#[repr(C)]` field order matches), so it can be borrowed from the same buffer
/// either as the prefix of a `MainCols` or directly from a 51-element slice.
///
/// Borrow it from a raw `[T; NUM_CORE_COLS]` slice via `Borrow<CoreCols<T>>`.
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
/// columns owned by `ChipletsAir`. It is laid out identically to the trailing
/// `NUM_CHIPLETS_COLS` columns of `MainCols` (`#[repr(C)]` field order matches), so it can be
/// borrowed from the same buffer either as the suffix of a `MainCols` or directly from a
/// 22-element slice.
///
/// The chiplets array is `pub(crate)` for the same reason as on `MainCols`: the 20 columns
/// are a union whose interpretation depends on which chiplet is active. Access goes through
/// typed accessors.
///
/// `chip_clk` is the chiplet-trace row counter — see the field doc on `MainCols::chip_clk`
/// for full semantics.
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
    /// virtual `s0 = 1 - (s_ctrl + s_perm)`. Mirrors [`MainCols::chiplet_selectors`].
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

const _: () = assert!(NUM_MAIN_COLS == TRACE_WIDTH);
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

    // --- Main trace column map vs offset constants -----------------------------------------------

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
        // s_perm is a separate field after chiplets[0..20]
        assert_eq!(MAIN_COL_MAP.s_perm, CHIPLETS_OFFSET + 20);
        // chip_clk follows s_perm at the tail of the chiplet section.
        assert_eq!(MAIN_COL_MAP.chip_clk, CHIPLETS_OFFSET + 21);
    }

    // --- Multi-AIR split: CoreCols + ChipletCols layout ---------------------

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
        // 20 shared chiplet data columns + 1 `s_perm` selector.
        assert_eq!(NUM_CHIPLETS_COLS, crate::trace::CHIPLETS_WIDTH);
    }

    /// Borrowing the leading `NUM_CORE_COLS` of a `MainCols`-shaped buffer as a `CoreCols`
    /// yields the same field values as accessing them through `MainCols` directly.
    #[test]
    fn core_cols_layout_aligned_with_main() {
        // Build a deterministic 72-element buffer where each cell holds its own column index.
        let buf: alloc::vec::Vec<usize> = (0..TRACE_WIDTH).collect();

        let main: &MainCols<usize> = buf.as_slice().borrow();
        let core: &CoreCols<usize> = buf[..NUM_CORE_COLS].borrow();

        assert_eq!(main.system.clk, core.system.clk);
        assert_eq!(main.system.ctx, core.system.ctx);
        assert_eq!(main.system.fn_hash, core.system.fn_hash);
        assert_eq!(main.decoder.addr, core.decoder.addr);
        assert_eq!(main.decoder.op_bits, core.decoder.op_bits);
        assert_eq!(main.stack.top, core.stack.top);
        assert_eq!(main.stack.b0, core.stack.b0);
        assert_eq!(main.range.multiplicity, core.range.multiplicity);
        assert_eq!(main.range.value, core.range.value);
    }

    /// Borrowing the trailing `NUM_CHIPLETS_COLS` of a `MainCols`-shaped buffer as a
    /// `ChipletCols` yields the same field values as accessing them through `MainCols`
    /// directly.
    #[test]
    fn chiplet_cols_layout_aligned_with_main() {
        let buf: alloc::vec::Vec<usize> = (0..TRACE_WIDTH).collect();

        let main: &MainCols<usize> = buf.as_slice().borrow();
        let chiplets: &ChipletCols<usize> = buf[NUM_CORE_COLS..].borrow();

        assert_eq!(main.chiplets, chiplets.chiplets);
        assert_eq!(main.s_perm, chiplets.s_perm);
        assert_eq!(main.chip_clk, chiplets.chip_clk);
        // Spot-check absolute column indices: chiplets[0] sits at CHIPLETS_OFFSET,
        // and the value in our deterministic buffer equals the column index.
        assert_eq!(chiplets.chiplets[0], CHIPLETS_OFFSET);
        assert_eq!(chiplets.s_perm, CHIPLETS_OFFSET + 20);
        assert_eq!(chiplets.chip_clk, CHIPLETS_OFFSET + 21);
    }

    /// `MainCols::as_core_cols()` returns a `&CoreCols<T>` pointing at the leading portion
    /// of the same buffer. Field-by-field comparison verifies the reinterpret cast is sound
    /// (matching what `core_cols_layout_aligned_with_main` proves through the slice-Borrow
    /// path).
    #[test]
    fn as_core_cols_aliases_main_core() {
        let buf: alloc::vec::Vec<usize> = (0..TRACE_WIDTH).collect();

        let main: &MainCols<usize> = buf.as_slice().borrow();
        let bridged: &CoreCols<usize> = main.as_core_cols();

        // The reinterpret cast yields a reference to the same leading fields.
        assert_eq!(bridged.system.clk, main.system.clk);
        assert_eq!(bridged.system.ctx, main.system.ctx);
        assert_eq!(bridged.system.fn_hash, main.system.fn_hash);
        assert_eq!(bridged.decoder.addr, main.decoder.addr);
        assert_eq!(bridged.stack.top, main.stack.top);
        assert_eq!(bridged.range.multiplicity, main.range.multiplicity);

        // Address parity: the bridged CoreCols sits at the same address as re-borrowing the
        // leading slice as CoreCols (and at the same address as the MainCols itself, since
        // CoreCols starts at offset 0).
        let direct: &CoreCols<usize> = buf[..NUM_CORE_COLS].borrow();
        assert_eq!(bridged as *const _ as usize, direct as *const _ as usize);
        assert_eq!(bridged as *const _ as usize, main as *const _ as usize);
    }

    /// `MainCols::as_chiplet_cols()` returns a `&ChipletCols<T>` pointing at the trailing
    /// portion of the same buffer. Field-by-field comparison verifies the reinterpret cast
    /// is sound (matching what `chiplet_cols_layout_aligned_with_main` proves through the
    /// slice-Borrow path).
    #[test]
    fn as_chiplet_cols_aliases_main_chiplets() {
        let buf: alloc::vec::Vec<usize> = (0..TRACE_WIDTH).collect();

        let main: &MainCols<usize> = buf.as_slice().borrow();
        let bridged: &ChipletCols<usize> = main.as_chiplet_cols();

        // The reinterpret cast yields a reference to the same chiplets array.
        assert_eq!(bridged.chiplets, main.chiplets);
        assert_eq!(bridged.s_perm, main.s_perm);
        assert_eq!(bridged.chip_clk, main.chip_clk);

        // And the bridged view starts exactly at the chiplets offset.
        assert_eq!(bridged.chiplets[0], CHIPLETS_OFFSET);
        assert_eq!(bridged.s_perm, CHIPLETS_OFFSET + 20);
        assert_eq!(bridged.chip_clk, CHIPLETS_OFFSET + 21);

        // Address parity: the bridged ChipletCols sits at the same address as
        // re-borrowing the trailing slice as ChipletCols.
        let direct: &ChipletCols<usize> = buf[NUM_CORE_COLS..].borrow();
        assert_eq!(bridged as *const _ as usize, direct as *const _ as usize);
    }

    /// `ChipletCols` chiplet accessors return the same view as the `MainCols` equivalents
    /// when both are borrowed from the same buffer.
    #[test]
    fn chiplet_cols_accessors_match_main() {
        let buf: alloc::vec::Vec<usize> = (0..TRACE_WIDTH).collect();

        let main: &MainCols<usize> = buf.as_slice().borrow();
        let chiplets: &ChipletCols<usize> = buf[NUM_CORE_COLS..].borrow();

        assert_eq!(main.chiplet_selectors(), chiplets.chiplet_selectors());

        // The seven typed sub-chiplet accessors return references into a shared backing
        // slice; compare via address — the two views point to the same physical column.
        assert_eq!(main.bitwise() as *const _ as usize, chiplets.bitwise() as *const _ as usize,);
        assert_eq!(main.memory() as *const _ as usize, chiplets.memory() as *const _ as usize,);
        assert_eq!(main.ace() as *const _ as usize, chiplets.ace() as *const _ as usize,);
        assert_eq!(
            main.kernel_rom() as *const _ as usize,
            chiplets.kernel_rom() as *const _ as usize,
        );
        assert_eq!(
            main.permutation() as *const _ as usize,
            chiplets.permutation() as *const _ as usize,
        );
        assert_eq!(
            main.controller() as *const _ as usize,
            chiplets.controller() as *const _ as usize,
        );
    }
}
