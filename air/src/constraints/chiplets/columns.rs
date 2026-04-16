//! Column structs for all chiplet sub-components and periodic columns.

use alloc::{vec, vec::Vec};
use core::{borrow::Borrow, mem::size_of};

use miden_core::{Felt, WORD_SIZE, chiplets::hasher::Hasher, field::PrimeCharacteristicRing};

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

// PERMUTATION COLUMNS
// ================================================================================================

/// Permutation chiplet columns (19 columns), viewed from `chiplets[1..20]`.
///
/// Logical overlay for permutation segment rows (`s_perm = 1`). The 3 witness columns
/// `w0..w2` share the same physical columns as the controller's `s0/s1/s2` selectors,
/// and `multiplicity` shares the same physical column as the controller's `node_index`.
///
/// `s_ctrl` (= `chiplets[0]`) and `s_perm` (= `perm_seg`) are consumed by the chiplet
/// selector system and are NOT part of this overlay.
///
/// The state holds a Poseidon2 sponge in `[RATE0, RATE1, CAPACITY]` layout.
/// Helper methods `rate0()`, `rate1()`, `capacity()`, and `digest()` provide
/// sub-views into the state array.
///
/// ## Layout
///
/// ```text
/// | witnesses[3] | state[12]                                    | extra cols      |
/// |              | rate0[4] (= digest) | rate1[4] | capacity[4] |                 |
/// | w0, w1, w2   | h0..h3              | h4..h7   | h8..h11     | m  --  --  --   |
/// ```
#[repr(C)]
pub struct PermutationCols<T> {
    /// S-box witness columns (same physical columns as hasher selectors).
    pub witnesses: [T; NUM_SELECTORS],
    /// Poseidon2 state (12 field elements: 8 rate + 4 capacity).
    pub state: [T; STATE_WIDTH],
    /// Request multiplicity (same physical column as node_index).
    pub multiplicity: T,
    /// Physical slots for controller columns mrupdate_id, is_boundary, and direction_bit.
    /// These must be zero on permutation rows; access via [`Self::unused_padding()`] only.
    _unused: [T; 3],
}

impl<T: Copy> PermutationCols<T> {
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

    /// Returns the 3 padding columns (mrupdate_id, is_boundary, direction_bit) that must
    /// be zero on permutation rows.
    pub fn unused_padding(&self) -> [T; 3] {
        self._unused
    }
}

// CONTROLLER COLUMNS
// ================================================================================================

/// Controller chiplet columns (19 columns), viewed from `chiplets[1..20]`.
///
/// Logical overlay for controller rows (`s_ctrl = 1`). `s0` distinguishes input rows
/// (`s0 = 1`) from output/padding rows (`s0 = 0`). The physical layout mirrors
/// [`PermutationCols`], but column names reflect the controller/permutation split.
///
/// `s_ctrl` (= `chiplets[0]`) and `s_perm` (= `perm_seg`) are consumed by the chiplet
/// selector system and are NOT part of this overlay. Because the chiplet-level
/// non-hasher selector is only ever a virtual expression (`1 - s_ctrl - s_perm`) and is
/// never a named column or struct field, there is no name collision with the
/// controller-internal `s0` defined here.
///
/// The state holds a Poseidon2 sponge in `[RATE0, RATE1, CAPACITY]` layout.
/// Helper methods `rate0()`, `rate1()`, `capacity()`, and `digest()` provide
/// sub-views into the state array.
///
/// ## Layout
///
/// ```text
/// | s0 s1 s2 | state[12]                                    | extra cols      |
/// |          | rate0[4] (= digest) | rate1[4] | capacity[4] |                 |
/// |          | h0..h3              | h4..h7   | h8..h11     | i  mr  bnd  dir |
/// ```
#[repr(C)]
pub struct ControllerCols<T> {
    /// Hasher-internal sub-selector: `s0 = 1` on controller input rows, 0 on output/padding.
    pub s0: T,
    /// Operation sub-selector s1.
    pub s1: T,
    /// Operation sub-selector s2.
    pub s2: T,
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
}

impl<T: Copy> ControllerCols<T> {
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

    /// Merkle-update new-path flag: `s0 * s1 * s2`.
    ///
    /// Active on controller input rows that insert the new Merkle path into the sibling
    /// table (request/remove side of the running product).
    pub fn f_mu<E: PrimeCharacteristicRing>(&self) -> E
    where
        T: Into<E>,
    {
        self.s0.into() * self.s1.into() * self.s2.into()
    }

    /// Merkle-verify / old-path flag: `s0 * s1 * (1 - s2)`.
    ///
    /// Active on controller input rows that extract the old Merkle path from the sibling
    /// table (response/add side of the running product).
    pub fn f_mv<E: PrimeCharacteristicRing>(&self) -> E
    where
        T: Into<E>,
    {
        self.s0.into() * self.s1.into() * (E::ONE - self.s2.into())
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
/// When reading from a new word address (first access to a context/addr pair), the
/// `values` are initialized to zero.
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
    /// Flag: same context and same word address as previous operation (docs: `f_sca`).
    pub is_same_ctx_and_addr: T,
}

// ACE COLUMNS
// ================================================================================================

/// ACE chiplet columns (16 columns), viewed from `chiplets[4..20]`.
///
/// The ACE (Arithmetic Circuit Evaluator) chiplet evaluates arithmetic circuits over
/// quadratic extension field elements. Each circuit evaluation consists of two phases:
///
/// 1. **READ** (`s_block=0`): loads wire values from memory into the chiplet.
/// 2. **EVAL** (`s_block=1`): evaluates arithmetic gates on loaded wire values.
///
/// The first 12 columns are common to both modes. The last 4 (`mode`) are overlaid
/// and reinterpreted depending on `s_block`:
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
    /// Start-of-circuit flag (1 on the first row of a new circuit evaluation).
    pub s_start: T,
    /// Block selector: 0 = READ (memory loads), 1 = EVAL (gate evaluation).
    pub s_block: T,
    /// Memory context for the current circuit evaluation.
    pub ctx: T,
    /// Memory pointer from which to read the next two wire values or instruction.
    pub ptr: T,
    /// Clock cycle at which the memory read is performed.
    pub clk: T,
    /// Arithmetic operation selector (determines which gate to evaluate in EVAL mode).
    pub eval_op: T,
    /// ID of the first wire (output wire / left operand).
    pub id_0: T,
    /// Value of the first wire (quadratic extension field element).
    pub v_0: QuadFeltExpr<T>,
    /// ID of the second wire (first input / left operand).
    pub id_1: T,
    /// Value of the second wire (quadratic extension field element).
    pub v_1: QuadFeltExpr<T>,
    /// Mode-dependent columns (interpretation depends on `s_block`; see table above).
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

impl<T: Copy> AceCols<T> {
    /// ACE read flag: `1 - s_block`.
    ///
    /// Active on ACE rows in READ mode (memory word reads for circuit inputs).
    pub fn f_read<E: PrimeCharacteristicRing>(&self) -> E
    where
        T: Into<E>,
    {
        E::ONE - self.s_block.into()
    }

    /// ACE eval flag: `s_block`.
    ///
    /// Active on ACE rows in EVAL mode (circuit gate evaluation).
    pub fn f_eval<E: PrimeCharacteristicRing>(&self) -> E
    where
        T: Into<E>,
    {
        self.s_block.into()
    }
}

/// READ mode overlay for ACE mode-dependent columns (4 columns).
///
/// In READ mode, the chiplet loads wire values from memory. The multiplicity columns
/// (`m_0`, `m_1`) track how many times each wire participates in circuit gates, used
/// by the wiring bus to verify correct wire connections.
#[repr(C)]
pub struct AceReadCols<T> {
    /// Number of EVAL rows that follow this READ block.
    pub num_eval: T,
    /// Unused column (padding for layout alignment with EVAL overlay).
    pub unused: T,
    /// Multiplicity of the second wire (wire 1).
    pub m_1: T,
    /// Multiplicity of the first wire (wire 0).
    pub m_0: T,
}

/// EVAL mode overlay for ACE mode-dependent columns (4 columns).
///
/// In EVAL mode, the chiplet evaluates an arithmetic gate on three wires: two inputs
/// (`id_1`, `id_2`) and one output (`id_0`). The third wire's ID and value occupy the
/// same physical columns as `num_eval`/`unused`/`m_1` in READ mode.
#[repr(C)]
pub struct AceEvalCols<T> {
    /// ID of the third wire (second input / right operand).
    pub id_2: T,
    /// Value of the third wire.
    pub v_2: QuadFeltExpr<T>,
    /// Multiplicity of the first wire (wire 0).
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

#[allow(clippy::new_without_default)]
impl HasherPeriodicCols<Vec<Felt>> {
    /// Generate periodic columns for the Poseidon2 hasher chiplet.
    ///
    /// All columns repeat every 16 rows, matching one permutation cycle.
    ///
    /// The 4 selector columns identify the row type. The 12 ark columns carry either
    /// external round constants (on external rows) or internal round constants in
    /// `ark[0..2]` (on packed-internal rows).
    ///
    /// ## 16-Row Schedule
    ///
    /// ```text
    /// Row  Transition              Selector
    /// 0    init + ext1             is_init_ext
    /// 1-3  ext2-ext4               is_ext
    /// 4-10 3x packed internal      is_packed_int
    /// 11   int22 + ext5            is_int_ext
    /// 12-14 ext6-ext8              is_ext
    /// 15   boundary                (none)
    /// ```
    #[allow(clippy::needless_range_loop)]
    pub fn new() -> Self {
        // -------------------------------------------------------------------------
        // Selectors
        // -------------------------------------------------------------------------
        let mut is_init_ext = vec![Felt::ZERO; HASH_CYCLE_LEN];
        let mut is_ext = vec![Felt::ZERO; HASH_CYCLE_LEN];
        let mut is_packed_int = vec![Felt::ZERO; HASH_CYCLE_LEN];
        let mut is_int_ext = vec![Felt::ZERO; HASH_CYCLE_LEN];

        is_init_ext[0] = Felt::ONE;

        for r in [1, 2, 3, 12, 13, 14] {
            is_ext[r] = Felt::ONE;
        }

        for r in 4..=10 {
            is_packed_int[r] = Felt::ONE;
        }

        is_int_ext[11] = Felt::ONE;

        // -------------------------------------------------------------------------
        // Shared round constants (12 columns)
        // -------------------------------------------------------------------------
        // On external rows (0-3, 11-14): hold per-lane external round constants.
        // On packed-internal rows (4-10): ark[0..2] hold 3 internal round constants,
        //   ark[3..12] are zero.
        // On boundary (row 15): all zero.
        let ark = core::array::from_fn(|lane| {
            let mut col = vec![Felt::ZERO; HASH_CYCLE_LEN];

            // Row 0 (init+ext1): first initial external round constants
            col[0] = Hasher::ARK_EXT_INITIAL[0][lane];

            // Rows 1-3 (ext2, ext3, ext4): remaining initial external round constants
            for r in 1..=3 {
                col[r] = Hasher::ARK_EXT_INITIAL[r][lane];
            }

            // Rows 4-10 (packed internal): internal constants in lanes 0-2 only
            if lane < 3 {
                for triple in 0..7_usize {
                    let row = 4 + triple;
                    let ark_idx = triple * 3 + lane;
                    col[row] = Hasher::ARK_INT[ark_idx];
                }
            }

            // Row 11 (int22+ext5): terminal external round 0 constants
            // (internal constant ARK_INT[21] is hardcoded in the constraint)
            col[11] = Hasher::ARK_EXT_TERMINAL[0][lane];

            // Rows 12-14 (ext6, ext7, ext8): remaining terminal external round constants
            for r in 12..=14 {
                col[r] = Hasher::ARK_EXT_TERMINAL[r - 11][lane];
            }

            col
        });

        Self {
            is_init_ext,
            is_ext,
            is_packed_int,
            is_int_ext,
            ark,
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
            ark: [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11],
        } = HasherPeriodicCols::new();

        let BitwisePeriodicCols { k_first, k_transition } = BitwisePeriodicCols::new();

        vec![
            is_init_ext,
            is_ext,
            is_packed_int,
            is_int_ext,
            a0,
            a1,
            a2,
            a3,
            a4,
            a5,
            a6,
            a7,
            a8,
            a9,
            a10,
            a11,
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
    assert!(size_of::<PeriodicCols<u8>>() == 18);
    assert!(size_of::<HasherPeriodicCols<u8>>() == 16);
    assert!(size_of::<BitwisePeriodicCols<u8>>() == 2);

    // PermutationCols and ControllerCols overlay chiplets[1..20] (19 columns,
    // excluding perm_seg which is consumed by the chiplet selector system).
    assert!(size_of::<PermutationCols<u8>>() == 19);
    assert!(size_of::<ControllerCols<u8>>() == 19);
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
        let h = HasherPeriodicCols::new();
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

    #[test]
    fn external_round_constants_correct() {
        let h = HasherPeriodicCols::new();

        // Row 0: ARK_EXT_INITIAL[0]
        for lane in 0..STATE_WIDTH {
            assert_eq!(h.ark[lane][0], Hasher::ARK_EXT_INITIAL[0][lane]);
        }

        // Rows 1-3: ARK_EXT_INITIAL[1..3]
        for r in 1..=3 {
            for lane in 0..STATE_WIDTH {
                assert_eq!(h.ark[lane][r], Hasher::ARK_EXT_INITIAL[r][lane]);
            }
        }

        // Row 11: ARK_EXT_TERMINAL[0]
        for lane in 0..STATE_WIDTH {
            assert_eq!(h.ark[lane][11], Hasher::ARK_EXT_TERMINAL[0][lane]);
        }

        // Rows 12-14: ARK_EXT_TERMINAL[1..3]
        for r in 12..=14 {
            for lane in 0..STATE_WIDTH {
                assert_eq!(h.ark[lane][r], Hasher::ARK_EXT_TERMINAL[r - 11][lane]);
            }
        }
    }

    #[test]
    fn internal_round_constants_correct() {
        let h = HasherPeriodicCols::new();

        // Rows 4-10: packed internal round constants in ark[0..2]
        for triple in 0..7_usize {
            let row = 4 + triple;
            for k in 0..3 {
                let ark_idx = triple * 3 + k;
                assert_eq!(
                    h.ark[k][row],
                    Hasher::ARK_INT[ark_idx],
                    "mismatch at row {row}, int constant {k} (ARK_INT[{ark_idx}])"
                );
            }
            // ark[3..12] must be zero on packed-internal rows
            for lane in 3..STATE_WIDTH {
                assert_eq!(
                    h.ark[lane][row],
                    Felt::ZERO,
                    "ark[{lane}] nonzero at packed-int row {row}"
                );
            }
        }
    }

    #[test]
    fn boundary_row_all_zero() {
        let h = HasherPeriodicCols::new();
        for (lane, col) in h.ark.iter().enumerate() {
            assert_eq!(col[15], Felt::ZERO, "ark column {lane} nonzero at row 15");
        }
    }
}
