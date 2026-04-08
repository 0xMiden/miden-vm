//! Column structs for all chiplet sub-components and periodic columns.

use alloc::{vec, vec::Vec};
use core::{borrow::Borrow, mem::size_of};

use miden_core::{Felt, WORD_SIZE};

use super::super::{columns::indices_arr, ext_field::QuadFeltExpr};
#[cfg(test)]
use crate::trace::chiplets::hasher::HASH_CYCLE_LEN;
use crate::trace::chiplets::{
    bitwise::NUM_DECOMP_BITS,
    hasher::{CAPACITY_LEN, DIGEST_LEN, NUM_SELECTORS, RATE_LEN, STATE_WIDTH},
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

/// Hasher chiplet columns (19 columns), viewed from `chiplets[1..20]`.
///
/// ## Layout
///
/// ```text
/// | selectors[3] |     state[12]                                   | extra cols           |
/// |              | rate0[4] (= digest) | rate1[4]   | capacity[4]  |                      |
/// | s0, s1, s2   | h0..h3             | h4..h7     | h8..h11      | i  mr  bnd  dir  seg |
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
    /// Domain separator for sibling table across MRUPDATE ops.
    pub mrupdate_id: T,
    /// 1 on boundary rows (first input or last output of each permutation).
    pub is_boundary: T,
    /// Direction bit for Merkle path verification.
    pub direction_bit: T,
    /// Permutation segment counter.
    pub perm_seg: T,
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

/// Hasher chiplet periodic columns (16 columns, period = 16 rows).
///
/// Provides step-type selectors and Poseidon2 round constants for the hasher chiplet.
/// The hasher operates on a 16-row cycle (15 transitions + 1 boundary row).
///
/// ## Layout
///
/// | Index | Name           | Description |
/// |-------|----------------|-------------|
/// | 0     | is_init_ext    | 1 on row 0 (init linear + first external round) |
/// | 1     | is_ext         | 1 on rows 1-3, 12-14 (single external round) |
/// | 2     | is_packed_int  | 1 on rows 4-10 (3 packed internal rounds) |
/// | 3     | is_int_ext     | 1 on row 11 (int22 + ext5 merged) |
/// | 4-15  | ark[0..12]     | Shared round constants |
#[derive(Clone, Copy)]
#[repr(C)]
pub struct HasherPeriodicCols<T> {
    /// 1 on row 0 (init linear + first external round).
    pub is_init_ext: T,
    /// 1 on rows 1-3, 12-14 (single external round).
    pub is_ext: T,
    /// 1 on rows 4-10 (3 packed internal rounds).
    pub is_packed_int: T,
    /// 1 on row 11 (int22 + ext5 merged).
    pub is_int_ext: T,
    /// Shared round constants (12 lanes). Carry external round constants on external
    /// rows, and internal round constants in ark[0..2] on packed-internal rows.
    pub ark: [T; STATE_WIDTH],
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

impl HasherPeriodicCols<Vec<Felt>> {
    /// Generate periodic columns from the hasher periodic module.
    pub fn from_periodic_columns() -> Self {
        use super::hasher::periodic;
        let flat = periodic::periodic_columns();
        assert_eq!(flat.len(), periodic::NUM_PERIODIC_COLUMNS);

        Self {
            is_init_ext: flat[periodic::P_IS_INIT_EXT].clone(),
            is_ext: flat[periodic::P_IS_EXT].clone(),
            is_packed_int: flat[periodic::P_IS_PACKED_INT].clone(),
            is_int_ext: flat[periodic::P_IS_INT_EXT].clone(),
            ark: core::array::from_fn(|i| flat[periodic::P_ARK_START + i].clone()),
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
            is_init_ext,
            is_ext,
            is_packed_int,
            is_int_ext,
            ark,
        } = HasherPeriodicCols::from_periodic_columns();

        let BitwisePeriodicCols { k_first, k_transition } = BitwisePeriodicCols::new();

        let mut cols = vec![is_init_ext, is_ext, is_packed_int, is_int_ext];
        cols.extend(ark);
        cols.push(k_first);
        cols.push(k_transition);
        cols
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
    assert!(size_of::<PeriodicCols<u8>>() == 18);
    assert!(size_of::<HasherPeriodicCols<u8>>() == 16);
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
    fn hasher_step_selectors_are_exclusive() {
        let h = HasherPeriodicCols::from_periodic_columns();
        for row in 0..HASH_CYCLE_LEN {
            let init_ext = h.is_init_ext[row];
            let ext = h.is_ext[row];
            let packed_int = h.is_packed_int[row];
            let int_ext = h.is_int_ext[row];

            // Each selector is binary.
            assert_eq!(init_ext * (init_ext - Felt::ONE), Felt::ZERO);
            assert_eq!(ext * (ext - Felt::ONE), Felt::ZERO);
            assert_eq!(packed_int * (packed_int - Felt::ONE), Felt::ZERO);
            assert_eq!(int_ext * (int_ext - Felt::ONE), Felt::ZERO);

            // At most one selector is active per row.
            let sum = init_ext + ext + packed_int + int_ext;
            assert!(sum == Felt::ZERO || sum == Felt::ONE, "row {row}: sum = {sum}");
        }
    }
}
