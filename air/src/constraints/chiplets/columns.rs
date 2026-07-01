//! Column structs for all chiplet sub-components and periodic columns.

use alloc::{vec, vec::Vec};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use miden_core::{Felt, WORD_SIZE, field::PrimeCharacteristicRing};

use super::super::{columns::indices_arr, ext_field::QuadFeltExpr};
use crate::trace::chiplets::{
    bitwise::NUM_DECOMP_BITS,
    hasher::{CAPACITY_LEN, DIGEST_LEN, RATE_LEN, STATE_WIDTH},
};

// HELPERS
// ================================================================================================

/// Generates `Borrow<$cols<T>> for [T]` and the mutable counterpart for a chiplet column
/// struct. The slice length must equal `size_of::<$cols<u8>>()` cells.
macro_rules! impl_borrow_for_chiplet_cols {
    ($cols:ident) => {
        impl<T> Borrow<$cols<T>> for [T] {
            fn borrow(&self) -> &$cols<T> {
                debug_assert_eq!(self.len(), size_of::<$cols<u8>>());
                let (prefix, cols, suffix) = unsafe { self.align_to::<$cols<T>>() };
                debug_assert!(prefix.is_empty() && suffix.is_empty() && cols.len() == 1);
                &cols[0]
            }
        }
        impl<T> BorrowMut<$cols<T>> for [T] {
            fn borrow_mut(&mut self) -> &mut $cols<T> {
                debug_assert_eq!(self.len(), size_of::<$cols<u8>>());
                let (prefix, cols, suffix) = unsafe { self.align_to_mut::<$cols<T>>() };
                debug_assert!(prefix.is_empty() && suffix.is_empty() && cols.len() == 1);
                &mut cols[0]
            }
        }
    };
}

// CONTROLLER COLUMNS
// ================================================================================================

/// Controller chiplet columns (19 columns), viewed from `chiplets[1..20]`.
///
/// Logical overlay for controller rows. The controller-internal `s0` distinguishes input rows
/// (`s0 = 1`) from output/padding rows (`s0 = 0`).
///
/// `chiplets[0]` belongs to the top-level chiplet selector system and is not part of this overlay.
/// The controller-internal `s0` defined here starts at `chiplets[1]`.
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
#[derive(Clone, Debug)]
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
    /// Active on controller input rows that remove siblings for the new Merkle path.
    pub fn f_mu<E: PrimeCharacteristicRing>(&self) -> E
    where
        T: Into<E>,
    {
        self.s0.into() * self.s1.into() * self.s2.into()
    }

    /// Merkle-verify / old-path flag: `s0 * s1 * (1 - s2)`.
    ///
    /// Active on controller input rows that insert siblings for the old Merkle path.
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
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
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
        self.mode.as_slice().borrow()
    }

    /// Returns an EVAL-mode overlay of the mode-dependent columns.
    pub fn eval(&self) -> &AceEvalCols<T> {
        self.mode.as_slice().borrow()
    }

    /// Returns a mutable READ-mode overlay of the mode-dependent columns.
    pub fn read_mut(&mut self) -> &mut AceReadCols<T> {
        self.mode.as_mut_slice().borrow_mut()
    }

    /// Returns a mutable EVAL-mode overlay of the mode-dependent columns.
    pub fn eval_mut(&mut self) -> &mut AceEvalCols<T> {
        self.mode.as_mut_slice().borrow_mut()
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
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
pub struct KernelRomCols<T> {
    /// Number of SYSCALLs to this procedure (CALL-label multiplicity).
    pub multiplicity: T,
    /// Kernel procedure root digest.
    pub root: [T; WORD_SIZE],
}

// PERIODIC COLUMNS
// ================================================================================================

/// All chiplet periodic columns.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct PeriodicCols<T> {
    pub bitwise: BitwisePeriodicCols<T>,
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

impl Default for BitwisePeriodicCols<Vec<Felt>> {
    fn default() -> Self {
        Self::new()
    }
}

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

    /// Generate bitwise periodic columns as a flat vector.
    pub fn periodic_columns() -> Vec<Vec<Felt>> {
        let BitwisePeriodicCols { k_first, k_transition } = Self::new();
        vec![k_first, k_transition]
    }
}

impl PeriodicCols<Vec<Felt>> {
    /// Generate all chiplet periodic columns as a flat `Vec<Vec<Felt>>`.
    pub fn periodic_columns() -> Vec<Vec<Felt>> {
        let BitwisePeriodicCols { k_first, k_transition } = BitwisePeriodicCols::new();
        vec![k_first, k_transition]
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

impl<T> Borrow<BitwisePeriodicCols<T>> for [T] {
    fn borrow(&self) -> &BitwisePeriodicCols<T> {
        debug_assert_eq!(self.len(), size_of::<BitwisePeriodicCols<u8>>());
        let (prefix, cols, suffix) = unsafe { self.align_to::<BitwisePeriodicCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty() && cols.len() == 1);
        &cols[0]
    }
}

const _: () = {
    assert!(size_of::<PeriodicCols<u8>>() == 2);
    assert!(size_of::<BitwisePeriodicCols<u8>>() == 2);

    assert!(size_of::<ControllerCols<u8>>() == 19);
};

// BORROW IMPLS
// ================================================================================================
//
// Each chiplet column struct can be borrowed zero-copy from a `[T]` slice of the matching
// length. Mirrors the `Borrow<CoreCols<T>>` / `Borrow<ChipletCols<T>>` impls on the parent
// `crate::constraints::columns` module.

impl_borrow_for_chiplet_cols!(ControllerCols);
impl_borrow_for_chiplet_cols!(BitwiseCols);
impl_borrow_for_chiplet_cols!(MemoryCols);
impl_borrow_for_chiplet_cols!(AceCols);
impl_borrow_for_chiplet_cols!(AceReadCols);
impl_borrow_for_chiplet_cols!(AceEvalCols);
impl_borrow_for_chiplet_cols!(KernelRomCols);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periodic_columns_dimensions() {
        let cols = PeriodicCols::periodic_columns();
        assert_eq!(cols.len(), NUM_PERIODIC_COLUMNS);

        for col in &cols {
            assert_eq!(col.len(), 8);
        }
    }
}
