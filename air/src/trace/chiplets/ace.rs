use crate::trace::chiplets::Felt;

// COLUMN STRUCTS
// ================================================================================================

/// ACE chiplet columns (16 columns), viewed from `chiplets[4..20]`.
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
    /// Dual-mode columns (interpretation depends on s_block).
    pub shared: [T; 10],
}

impl<T> AceCols<T> {
    /// Returns a READ-mode overlay of the shared columns.
    pub fn read(&self) -> &AceReadCols<T> {
        super::borrow_chiplet(&self.shared)
    }

    /// Returns an EVAL-mode overlay of the shared columns.
    pub fn eval(&self) -> &AceEvalCols<T> {
        super::borrow_chiplet(&self.shared)
    }
}

/// READ mode overlay for ACE shared columns (10 columns).
#[repr(C)]
pub struct AceReadCols<T> {
    /// ID of the first wire.
    pub id_0: T,
    /// Value of the first wire (QuadFelt).
    pub v_0: [T; 2],
    /// ID of the second wire.
    pub id_1: T,
    /// Value of the second wire (QuadFelt).
    pub v_1: [T; 2],
    /// Number of eval rows.
    pub num_eval: T,
    /// Unused column.
    pub unused: T,
    /// Multiplicity of the second wire.
    pub m_1: T,
    /// Multiplicity of the first wire.
    pub m_0: T,
}

/// EVAL mode overlay for ACE shared columns (10 columns).
#[repr(C)]
pub struct AceEvalCols<T> {
    /// ID of the first wire.
    pub id_0: T,
    /// Value of the first wire (QuadFelt).
    pub v_0: [T; 2],
    /// ID of the second wire.
    pub id_1: T,
    /// Value of the second wire (QuadFelt).
    pub v_1: [T; 2],
    /// ID of the third wire.
    pub id_2: T,
    /// Value of the third wire (QuadFelt).
    pub v_2: [T; 2],
    /// Multiplicity of the first wire.
    pub m_0: T,
}

// --- CONSTANTS ----------------------------------------------------------------------------------

/// Unique label ACE operation, computed as the chiplet selector with the bits reversed, plus one.
/// `selector = [1, 1, 1, 0]`, `flag = rev(selector) + 1 = [0, 1, 1, 1] + 1 = 8`
pub const ACE_INIT_LABEL: Felt = Felt::new(0b0111 + 1);

/// Total number of columns making up the ACE chiplet.
pub const ACE_CHIPLET_NUM_COLS: usize = 16;

/// Offset of the `ID1` wire used when encoding an ACE instruction.
pub const ACE_INSTRUCTION_ID1_OFFSET: Felt = Felt::new(1 << 30);

/// Offset of the `ID2` wire used when encoding an ACE instruction.
pub const ACE_INSTRUCTION_ID2_OFFSET: Felt = Felt::new(1 << 60);

// --- OPERATION SELECTORS ------------------------------------------------------------------------

/// The index of the column containing the flag indicating the start of a new circuit evaluation.
pub const SELECTOR_START_IDX: usize = 0;

/// The index of the column containing the flag indicating whether the current row performs
/// a READ or EVAL operation.
pub const SELECTOR_BLOCK_IDX: usize = 1;

// --- OPERATION IDENTIFIERS ----------------------------------------------------------------------

/// The index of the column containing memory context.
pub const CTX_IDX: usize = 2;

/// The index of the column containing the pointer from which to read the next two variables
/// or instruction.
pub const PTR_IDX: usize = 3;

/// The index of the column containing memory clk at which the memory read is performed.
pub const CLK_IDX: usize = 4;

/// The index of the column containing the index of the first wire being evaluated.
pub const READ_NUM_EVAL_IDX: usize = 12;

// --- ARITHMETIC GATES ---------------------------------------------------------------------------

/// The index of the column containing the flag indicating which arithmetic operation to perform.
pub const EVAL_OP_IDX: usize = 5;

/// The index of the column containing ID of the first wire.
pub const ID_0_IDX: usize = 6;

/// The index of the column containing the first base-field element of the value of the first wire.
pub const V_0_0_IDX: usize = 7;

/// The index of the column containing the second base-field element of the value of the first wire.
pub const V_0_1_IDX: usize = 8;

/// The index of the column containing the multiplicity of the first wire.
pub const M_0_IDX: usize = 15;

/// The index of the column containing ID of the second wire.
pub const ID_1_IDX: usize = 9;

/// The index of the column containing the first base-field element of the value of the second wire.
pub const V_1_0_IDX: usize = 10;

/// The index of the column containing the second base-field element of the value of the second
/// wire.
pub const V_1_1_IDX: usize = 11;

/// The index of the column containing the multiplicity of the second wire.
/// This column has the meaning of a multiplicity column only when the rows are `READ` rows, else
/// it should be interpreted as containing the second base-field element of the value of the third
/// wire.
pub const M_1_IDX: usize = 14;

/// The index of the column containing ID of the third wire.
pub const ID_2_IDX: usize = 12;

/// The index of the column containing the first base-field element of the value of the third wire.
pub const V_2_0_IDX: usize = 13;

/// The index of the column containing the second base-field element of the value of the third wire.
pub const V_2_1_IDX: usize = 14;
