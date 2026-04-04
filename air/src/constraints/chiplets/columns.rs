//! Column structs for all chiplet sub-components and periodic columns.

use alloc::{vec, vec::Vec};
use core::{borrow::Borrow, mem::size_of};

use miden_core::{Felt, WORD_SIZE, chiplets::hasher::Hasher};

use super::super::{columns::indices_arr, ext_field::QuadFeltExpr};
use crate::trace::chiplets::{
    bitwise::NUM_DECOMP_BITS,
    hasher::{CAPACITY_LEN, DIGEST_LEN, HASH_CYCLE_LEN, NUM_SELECTORS, RATE_LEN, STATE_WIDTH},
};

// HELPERS
// ================================================================================================

/// Zero-copy cast from a slice to a `#[repr(C)]` chiplet column struct.
pub fn borrow_chiplet<T, S>(slice: &[T]) -> &S {
    let (prefix, cols, suffix) = unsafe { slice.align_to::<S>() };
    debug_assert!(prefix.is_empty() && suffix.is_empty() && cols.len() == 1);
    &cols[0]
}

// HASHER COLUMNS
// ================================================================================================

/// Hasher chiplet columns (16 columns), viewed from `chiplets[1..17]`.
///
/// ## Layout
///
/// ```text
/// | selectors[3] |     state[12]                                        | node_index |
/// |              | rate0[4] (= digest) | rate1[4]     | capacity[4]     |            |
/// | s0, s1, s2   | h0  h1  h2  h3      | h4  h5  h6  h7 | h8  h9  h10 h11 | i      |
/// ```
///
/// The state holds a Poseidon2 sponge in `[RATE0, RATE1, CAPACITY]` layout.
/// Helper methods `rate0()`, `rate1()`, `capacity()`, and `digest()` provide
/// sub-views into the state array.
#[repr(C)]
pub struct HasherCols<T> {
    /// Hasher-internal selectors hs0, hs1, hs2.
    pub selectors: [T; NUM_SELECTORS],
    /// Poseidon2 state (12 field elements: 8 rate + 4 capacity).
    pub state: [T; STATE_WIDTH],
    /// Merkle tree node index.
    pub node_index: T,
}

impl<T: Copy> HasherCols<T> {
    /// Returns the rate portion of the state (state[0..8]).
    pub fn rate(&self) -> [T; RATE_LEN] {
        [
            self.state[0],
            self.state[1],
            self.state[2],
            self.state[3],
            self.state[4],
            self.state[5],
            self.state[6],
            self.state[7],
        ]
    }

    /// Returns the capacity portion of the state (state[8..12]).
    pub fn capacity(&self) -> [T; CAPACITY_LEN] {
        [self.state[8], self.state[9], self.state[10], self.state[11]]
    }

    /// Returns the digest portion of the state (state[0..4]).
    pub fn digest(&self) -> [T; DIGEST_LEN] {
        [self.state[0], self.state[1], self.state[2], self.state[3]]
    }

    /// Returns rate0 (state[0..4]).
    pub fn rate0(&self) -> [T; DIGEST_LEN] {
        [self.state[0], self.state[1], self.state[2], self.state[3]]
    }

    /// Returns rate1 (state[4..8]).
    pub fn rate1(&self) -> [T; DIGEST_LEN] {
        [self.state[4], self.state[5], self.state[6], self.state[7]]
    }
}

// BITWISE COLUMNS
// ================================================================================================

/// Bitwise chiplet columns (13 columns), viewed from `chiplets[2..15]`.
///
/// Bit decomposition columns (`a_bits`, `b_bits`) are in **little-endian** order:
/// `value = bits[0] + 2*bits[1] + 4*bits[2] + 8*bits[3]`.
#[repr(C)]
pub struct BitwiseCols<T> {
    /// Operation flag: 0 = AND, 1 = XOR.
    pub op_flag: T,
    /// Aggregated input a.
    pub a: T,
    /// Aggregated input b.
    pub b: T,
    /// 4-bit decomposition of a.
    pub a_bits: [T; NUM_DECOMP_BITS],
    /// 4-bit decomposition of b.
    pub b_bits: [T; NUM_DECOMP_BITS],
    /// Previous aggregated output.
    pub prev_output: T,
    /// Current aggregated output.
    pub output: T,
}

// MEMORY COLUMNS
// ================================================================================================

/// Memory chiplet columns (15 columns), viewed from `chiplets[3..18]`.
///
/// When reading from a new word (first access to a context/word pair), the `values`
/// are initialized to zero.
#[repr(C)]
pub struct MemoryCols<T> {
    /// Read/write flag (0 = write, 1 = read).
    pub is_read: T,
    /// Element/word flag (0 = element, 1 = word).
    pub is_word: T,
    /// Memory context ID.
    pub ctx: T,
    /// Word address.
    pub word_addr: T,
    /// First bit of the address index within the word.
    pub idx0: T,
    /// Second bit of the address index within the word.
    pub idx1: T,
    /// Clock cycle of the memory access.
    pub clk: T,
    /// Values stored at this context/word/clock after the operation.
    pub values: [T; WORD_SIZE],
    /// Lower 16 bits of delta.
    pub d0: T,
    /// Upper 16 bits of delta.
    pub d1: T,
    /// Inverse of delta.
    pub d_inv: T,
    /// Flag: same context and same word as previous operation.
    pub is_same_ctx_and_word: T,
}

// ACE COLUMNS
// ================================================================================================

/// ACE chiplet columns (16 columns), viewed from `chiplets[4..20]`.
///
/// Common fields are stored directly. The `mode` array holds 4 columns whose
/// interpretation depends on `s_block`:
///
/// ```text
/// mode idx | READ (s_block=0)       | EVAL (s_block=1)
/// ---------+------------------------+-------------------
///  0       | num_eval               | id_2
///  1       | (unused)               | v_2.0
///  2       | m_1 (wire-1 mult)      | v_2.1
///  3       | m_0 (wire-0 mult)      | m_0 (wire-0 mult)
/// ```
///
/// Use `ace.read()` / `ace.eval()` for typed overlays of the mode columns.
#[repr(C)]
pub struct AceCols<T> {
    /// Start-of-circuit flag.
    pub s_start: T,
    /// Block selector: 0 = READ, 1 = EVAL.
    pub s_block: T,
    /// Memory context.
    pub ctx: T,
    /// Pointer for memory read.
    pub ptr: T,
    /// Clock cycle.
    pub clk: T,
    /// Evaluation operation selector.
    pub eval_op: T,
    /// ID of the first wire (output wire).
    pub id_0: T,
    /// Value of the first wire (QuadFelt).
    pub v_0: QuadFeltExpr<T>,
    /// ID of the second wire (first input / left operand).
    pub id_1: T,
    /// Value of the second wire (QuadFelt).
    pub v_1: QuadFeltExpr<T>,
    /// Mode-dependent columns (interpretation depends on s_block).
    mode: [T; 4],
}

impl<T> AceCols<T> {
    /// Returns a READ-mode overlay of the mode-dependent columns.
    pub fn read(&self) -> &AceReadCols<T> {
        borrow_chiplet(&self.mode)
    }

    /// Returns an EVAL-mode overlay of the mode-dependent columns.
    pub fn eval(&self) -> &AceEvalCols<T> {
        borrow_chiplet(&self.mode)
    }
}

/// READ mode overlay for ACE mode-dependent columns (4 columns).
#[repr(C)]
pub struct AceReadCols<T> {
    /// Number of eval rows.
    pub num_eval: T,
    /// Unused column.
    pub unused: T,
    /// Multiplicity of the second wire.
    pub m_1: T,
    /// Multiplicity of the first wire.
    pub m_0: T,
}

/// EVAL mode overlay for ACE mode-dependent columns (4 columns).
#[repr(C)]
pub struct AceEvalCols<T> {
    /// ID of the third wire (second input / right operand).
    pub id_2: T,
    /// Value of the third wire (QuadFelt).
    pub v_2: QuadFeltExpr<T>,
    /// Multiplicity of the first wire.
    pub m_0: T,
}

// ACE COLUMN INDEX MAPS
// ================================================================================================

/// Compile-time index map for the top-level ACE chiplet columns (16 columns).
#[allow(dead_code)]
pub const ACE_COL_MAP: AceCols<usize> = {
    assert!(size_of::<AceCols<u8>>() == 16);
    unsafe { core::mem::transmute(indices_arr::<{ size_of::<AceCols<u8>>() }>()) }
};

/// Compile-time index map for the READ overlay (relative to `mode`).
pub const ACE_READ_COL_MAP: AceReadCols<usize> = {
    assert!(size_of::<AceReadCols<u8>>() == 4);
    unsafe { core::mem::transmute(indices_arr::<{ size_of::<AceReadCols<u8>>() }>()) }
};

/// Compile-time index map for the EVAL overlay (relative to `mode`).
pub const ACE_EVAL_COL_MAP: AceEvalCols<usize> = {
    assert!(size_of::<AceEvalCols<u8>>() == 4);
    unsafe { core::mem::transmute(indices_arr::<{ size_of::<AceEvalCols<u8>>() }>()) }
};

/// Offset of the `mode` array within the ACE chiplet columns.
#[allow(dead_code)]
pub const MODE_OFFSET: usize = ACE_COL_MAP.mode[0];

const _: () = {
    assert!(size_of::<AceCols<u8>>() == 16);
    assert!(size_of::<AceReadCols<u8>>() == 4);
    assert!(size_of::<AceEvalCols<u8>>() == 4);

    // m_0 is at the same position in both overlays.
    assert!(ACE_READ_COL_MAP.m_0 == ACE_EVAL_COL_MAP.m_0);

    // READ-only and EVAL-only columns overlap at the expected positions.
    assert!(ACE_READ_COL_MAP.num_eval == ACE_EVAL_COL_MAP.id_2);
    assert!(ACE_READ_COL_MAP.m_1 == ACE_EVAL_COL_MAP.v_2.1);
};

// KERNEL ROM COLUMNS
// ================================================================================================

/// Kernel ROM chiplet columns (5 columns), viewed from `chiplets[5..10]`.
#[repr(C)]
pub struct KernelRomCols<T> {
    /// First-row-of-hash flag.
    pub s_first: T,
    /// Kernel procedure root digest.
    pub root: [T; WORD_SIZE],
}

// PERIODIC COLUMNS
// ================================================================================================

/// All chiplet periodic columns (20 columns).
///
/// Aggregates hasher (18 columns) and bitwise (2 columns) periodic values into a single
/// typed view. Use `builder.periodic_values().borrow()` to obtain a `&PeriodicCols<_>`.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct PeriodicCols<T> {
    /// Hasher periodic columns (cycle markers, step selectors, round constants).
    pub hasher: HasherPeriodicCols<T>,
    /// Bitwise periodic columns.
    pub bitwise: BitwisePeriodicCols<T>,
}

/// Hasher chiplet periodic columns (18 columns, period = 32 rows).
///
/// Provides cycle-position markers, step-type selectors, and Poseidon2 round constants
/// for the hasher chiplet.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct HasherPeriodicCols<T> {
    /// 1 on first row of 32-row cycle, 0 elsewhere.
    pub cycle_row_0: T,
    /// 1 on penultimate row (lookahead for output).
    pub cycle_row_30: T,
    /// 1 on final row (boundary/output row).
    pub cycle_row_31: T,
    /// 1 on external round rows (1-4, 27-30).
    pub is_external: T,
    /// 1 on internal round rows (5-26).
    pub is_internal: T,
    /// External round constants per lane (12 lanes), non-zero on external-round rows.
    pub ark_ext: [T; STATE_WIDTH],
    /// Internal round constant (lane 0 only), non-zero on internal-round rows (5-26).
    pub ark_int: T,
}

/// Bitwise chiplet periodic columns (2 columns, period = 8 rows).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BitwisePeriodicCols<T> {
    /// Marks first row of 8-row cycle: `[1, 0, 0, 0, 0, 0, 0, 0]`.
    pub k_first: T,
    /// Marks non-last rows of 8-row cycle: `[1, 1, 1, 1, 1, 1, 1, 0]`.
    pub k_transition: T,
}

// PERIODIC COLUMN GENERATION
// ================================================================================================

#[allow(clippy::new_without_default)]
impl HasherPeriodicCols<Vec<Felt>> {
    /// Generate periodic columns for the Poseidon2 hasher chiplet.
    #[allow(clippy::needless_range_loop)]
    pub fn new() -> Self {
        let mut cycle_row_0 = vec![Felt::ZERO; HASH_CYCLE_LEN];
        let mut cycle_row_30 = vec![Felt::ZERO; HASH_CYCLE_LEN];
        let mut cycle_row_31 = vec![Felt::ZERO; HASH_CYCLE_LEN];
        cycle_row_0[0] = Felt::ONE;
        cycle_row_30[30] = Felt::ONE;
        cycle_row_31[31] = Felt::ONE;

        let mut is_external = vec![Felt::ZERO; HASH_CYCLE_LEN];
        let mut is_internal = vec![Felt::ZERO; HASH_CYCLE_LEN];

        for r in 1..=4 {
            is_external[r] = Felt::ONE;
        }
        for r in 27..=30 {
            is_external[r] = Felt::ONE;
        }
        for r in 5..=26 {
            is_internal[r] = Felt::ONE;
        }

        let ark_ext = core::array::from_fn(|lane| {
            let mut col = vec![Felt::ZERO; HASH_CYCLE_LEN];
            for r in 1..=4 {
                col[r] = Hasher::ARK_EXT_INITIAL[r - 1][lane];
            }
            for r in 27..=30 {
                col[r] = Hasher::ARK_EXT_TERMINAL[r - 27][lane];
            }
            col
        });

        let mut ark_int = vec![Felt::ZERO; HASH_CYCLE_LEN];
        ark_int[5..=26].copy_from_slice(&Hasher::ARK_INT);

        Self {
            cycle_row_0,
            cycle_row_30,
            cycle_row_31,
            is_external,
            is_internal,
            ark_ext,
            ark_int,
        }
    }
}

#[allow(clippy::new_without_default)]
impl BitwisePeriodicCols<Vec<Felt>> {
    /// Generate periodic columns for the bitwise chiplet.
    pub fn new() -> Self {
        let k_first = vec![
            Felt::ONE,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
        ];

        let k_transition = vec![
            Felt::ONE,
            Felt::ONE,
            Felt::ONE,
            Felt::ONE,
            Felt::ONE,
            Felt::ONE,
            Felt::ONE,
            Felt::ZERO,
        ];

        Self { k_first, k_transition }
    }
}

impl PeriodicCols<Vec<Felt>> {
    /// Generate all chiplet periodic columns as a flat `Vec<Vec<Felt>>`.
    pub fn periodic_columns() -> Vec<Vec<Felt>> {
        let HasherPeriodicCols {
            cycle_row_0,
            cycle_row_30,
            cycle_row_31,
            is_external,
            is_internal,
            ark_ext:
                [
                    ark_0,
                    ark_1,
                    ark_2,
                    ark_3,
                    ark_4,
                    ark_5,
                    ark_6,
                    ark_7,
                    ark_8,
                    ark_9,
                    ark_10,
                    ark_11,
                ],
            ark_int,
        } = HasherPeriodicCols::new();

        let BitwisePeriodicCols { k_first, k_transition } = BitwisePeriodicCols::new();

        vec![
            cycle_row_0,
            cycle_row_30,
            cycle_row_31,
            is_external,
            is_internal,
            ark_0,
            ark_1,
            ark_2,
            ark_3,
            ark_4,
            ark_5,
            ark_6,
            ark_7,
            ark_8,
            ark_9,
            ark_10,
            ark_11,
            ark_int,
            k_first,
            k_transition,
        ]
    }
}

/// Total number of periodic columns across all chiplets.
pub const NUM_PERIODIC_COLUMNS: usize = size_of::<PeriodicCols<u8>>();

impl<T> Borrow<PeriodicCols<T>> for [T] {
    fn borrow(&self) -> &PeriodicCols<T> {
        debug_assert_eq!(self.len(), NUM_PERIODIC_COLUMNS);
        let (prefix, cols, suffix) = unsafe { self.align_to::<PeriodicCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty() && cols.len() == 1);
        &cols[0]
    }
}

const _: () = {
    assert!(size_of::<PeriodicCols<u8>>() == 20);
    assert!(size_of::<HasherPeriodicCols<u8>>() == 18);
    assert!(size_of::<BitwisePeriodicCols<u8>>() == 2);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periodic_columns_dimensions() {
        let cols = PeriodicCols::periodic_columns();
        assert_eq!(cols.len(), NUM_PERIODIC_COLUMNS);

        let (hasher_cols, bitwise_cols) = cols.split_at(size_of::<HasherPeriodicCols<u8>>());
        for col in hasher_cols {
            assert_eq!(col.len(), HASH_CYCLE_LEN);
        }
        for col in bitwise_cols {
            assert_eq!(col.len(), 8);
        }
    }

    #[test]
    fn hasher_cycle_markers_are_exclusive() {
        let h = HasherPeriodicCols::new();
        for (row_idx, ((row0, row30), row31)) in
            h.cycle_row_0.iter().zip(&h.cycle_row_30).zip(&h.cycle_row_31).enumerate()
        {
            assert_eq!(*row0 * (*row0 - Felt::ONE), Felt::ZERO);
            assert_eq!(*row30 * (*row30 - Felt::ONE), Felt::ZERO);
            assert_eq!(*row31 * (*row31 - Felt::ONE), Felt::ZERO);

            assert_eq!(*row0 * *row30, Felt::ZERO);
            assert_eq!(*row0 * *row31, Felt::ZERO);
            assert_eq!(*row30 * *row31, Felt::ZERO);

            let expected = match row_idx {
                0 | 30 | 31 => Felt::ONE,
                _ => Felt::ZERO,
            };
            assert_eq!(*row0 + *row30 + *row31, expected);
        }
    }

    #[test]
    fn hasher_step_selectors_are_exclusive() {
        let h = HasherPeriodicCols::new();
        for (row_idx, (is_ext, is_int)) in h.is_external.iter().zip(&h.is_internal).enumerate() {
            assert_eq!(*is_ext * (*is_ext - Felt::ONE), Felt::ZERO);
            assert_eq!(*is_int * (*is_int - Felt::ONE), Felt::ZERO);

            assert_eq!(*is_ext * *is_int, Felt::ZERO);

            let expected = match row_idx {
                1..=4 | 27..=30 => (Felt::ONE, Felt::ZERO),
                5..=26 => (Felt::ZERO, Felt::ONE),
                _ => (Felt::ZERO, Felt::ZERO),
            };
            assert_eq!((*is_ext, *is_int), expected);
        }
    }
}
