use core::mem::size_of;

use crate::{
    constraints::ext_field::QuadFeltExpr,
    trace::{chiplets::Felt, indices_arr},
};

// COLUMN STRUCTS
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
        super::borrow_chiplet(&self.mode)
    }

    /// Returns an EVAL-mode overlay of the mode-dependent columns.
    pub fn eval(&self) -> &AceEvalCols<T> {
        super::borrow_chiplet(&self.mode)
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

// --- CONSTANTS ----------------------------------------------------------------------------------

/// Unique label ACE operation, computed as the chiplet selector with the bits reversed, plus one.
/// `selector = [1, 1, 1, 0]`, `flag = rev(selector) + 1 = [0, 1, 1, 1] + 1 = 8`
pub const ACE_INIT_LABEL: Felt = Felt::new(0b0111 + 1);

/// Total number of columns making up the ACE chiplet.
pub const ACE_CHIPLET_NUM_COLS: usize = size_of::<AceCols<u8>>();

/// Offset of the `ID1` wire used when encoding an ACE instruction.
pub const ACE_INSTRUCTION_ID1_OFFSET: Felt = Felt::new(1 << 30);

/// Offset of the `ID2` wire used when encoding an ACE instruction.
pub const ACE_INSTRUCTION_ID2_OFFSET: Felt = Felt::new(1 << 60);

// COLUMN INDEX MAPS
// ================================================================================================

/// Compile-time index map for the top-level ACE chiplet columns.
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
pub const MODE_OFFSET: usize = ACE_COL_MAP.mode[0];

// COMPILE-TIME ASSERTIONS
// ================================================================================================

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

// LEGACY COLUMN INDEX CONSTANTS
// ================================================================================================
//
// These constants are used by the processor's column-major trace generation code. They will be
// removed once the processor switches to row-major trace generation using the typed col structs.

pub const SELECTOR_START_IDX: usize = ACE_COL_MAP.s_start;
pub const SELECTOR_BLOCK_IDX: usize = ACE_COL_MAP.s_block;
pub const CTX_IDX: usize = ACE_COL_MAP.ctx;
pub const PTR_IDX: usize = ACE_COL_MAP.ptr;
pub const CLK_IDX: usize = ACE_COL_MAP.clk;
pub const EVAL_OP_IDX: usize = ACE_COL_MAP.eval_op;
pub const ID_0_IDX: usize = ACE_COL_MAP.id_0;
pub const V_0_0_IDX: usize = ACE_COL_MAP.v_0.0;
pub const V_0_1_IDX: usize = ACE_COL_MAP.v_0.1;
pub const ID_1_IDX: usize = ACE_COL_MAP.id_1;
pub const V_1_0_IDX: usize = ACE_COL_MAP.v_1.0;
pub const V_1_1_IDX: usize = ACE_COL_MAP.v_1.1;
pub const READ_NUM_EVAL_IDX: usize = MODE_OFFSET + ACE_READ_COL_MAP.num_eval;
pub const ID_2_IDX: usize = MODE_OFFSET + ACE_EVAL_COL_MAP.id_2;
pub const V_2_0_IDX: usize = MODE_OFFSET + ACE_EVAL_COL_MAP.v_2.0;
pub const V_2_1_IDX: usize = MODE_OFFSET + ACE_EVAL_COL_MAP.v_2.1;
pub const M_1_IDX: usize = MODE_OFFSET + ACE_READ_COL_MAP.m_1;
pub const M_0_IDX: usize = MODE_OFFSET + ACE_READ_COL_MAP.m_0;

// Keep the old name alive for external references.
pub const SHARED_OFFSET: usize = MODE_OFFSET;
