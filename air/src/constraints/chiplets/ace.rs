//! ACE (Arithmetic Circuit Evaluation) chiplet constraints.
//!
//! The ACE chiplet reduces the number of cycles required when recursively verifying
//! a STARK proof by evaluating arithmetic circuits and ensuring they evaluate to zero.
//!
//! ## Operation Phases
//!
//! 1. **READ blocks**: Load extension field elements from memory and assign node IDs
//! 2. **EVAL blocks**: Execute arithmetic operations on previously loaded nodes
//!
//! ## Column Layout (16 columns within chiplet)
//!
//! | Column    | Purpose                                        |
//! |-----------|------------------------------------------------|
//! | sstart    | Section start flag (1 = first row of section)  |
//! | sblock    | Block selector (0=READ, 1=EVAL)                |
//! | ctx       | Memory access context                          |
//! | ptr       | Memory pointer (+4 in READ, +1 in EVAL)        |
//! | clk       | Memory access clock cycle                      |
//! | op        | Operation type (-1=SUB, 0=MUL, 1=ADD)          |
//! | id0       | Result node ID                                 |
//! | v0_0/v0_1 | Result node value (extension field)            |
//! | id1       | First operand node ID                          |
//! | v1_0/v1_1 | First operand value                            |
//! | id2/n_eval| Second operand ID (EVAL) / num evals (READ)    |
//! | v2_0      | Second operand value (coefficient 0)           |
//! | v2_1/m1   | Second operand (EVAL) / multiplicity (READ)    |
//! | m0        | Wire bus multiplicity for node 0               |

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use super::selectors::ace_chiplet_flag;
use crate::{
    Felt, MainTraceRow,
    trace::chiplets::ace::{
        CLK_IDX, CTX_IDX, EVAL_OP_IDX, ID_0_IDX, ID_1_IDX, PTR_IDX, READ_NUM_EVAL_IDX,
        SELECTOR_BLOCK_IDX, SELECTOR_START_IDX, V_0_0_IDX, V_0_1_IDX, V_1_0_IDX, V_1_1_IDX,
        V_2_0_IDX, V_2_1_IDX,
    },
};

// CONSTANTS
// ================================================================================================

// ACE chiplet offset from CHIPLETS_OFFSET (after s0, s1, s2, s3).
const ACE_OFFSET: usize = 4;

// ENTRY POINTS
// ================================================================================================

/// Enforce ACE chiplet constraints that apply to all rows.
pub fn enforce_ace_constraints_all_rows<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    // Compute ACE active flag from top-level selectors
    let s0: AB::Expr = local.chiplets[0].clone().into();
    let s1: AB::Expr = local.chiplets[1].clone().into();
    let s2: AB::Expr = local.chiplets[2].clone().into();
    let s3: AB::Expr = local.chiplets[3].clone().into();
    let s3_next: AB::Expr = next.chiplets[3].clone().into();

    let ace_flag = ace_chiplet_flag(s0.clone(), s1.clone(), s2.clone(), s3.clone());

    // Load ACE columns
    let sstart: AB::Expr = load_ace_col::<AB>(local, SELECTOR_START_IDX);
    let sstart_next: AB::Expr = load_ace_col::<AB>(next, SELECTOR_START_IDX);
    let sblock: AB::Expr = load_ace_col::<AB>(local, SELECTOR_BLOCK_IDX);
    let sblock_next: AB::Expr = load_ace_col::<AB>(next, SELECTOR_BLOCK_IDX);
    let ctx: AB::Expr = load_ace_col::<AB>(local, CTX_IDX);
    let ctx_next: AB::Expr = load_ace_col::<AB>(next, CTX_IDX);
    let ptr: AB::Expr = load_ace_col::<AB>(local, PTR_IDX);
    let ptr_next: AB::Expr = load_ace_col::<AB>(next, PTR_IDX);
    let clk: AB::Expr = load_ace_col::<AB>(local, CLK_IDX);
    let clk_next: AB::Expr = load_ace_col::<AB>(next, CLK_IDX);
    let op: AB::Expr = load_ace_col::<AB>(local, EVAL_OP_IDX);
    let id0: AB::Expr = load_ace_col::<AB>(local, ID_0_IDX);
    let id0_next: AB::Expr = load_ace_col::<AB>(next, ID_0_IDX);
    let id1: AB::Expr = load_ace_col::<AB>(local, ID_1_IDX);
    let n_eval: AB::Expr = load_ace_col::<AB>(local, READ_NUM_EVAL_IDX);
    let n_eval_next: AB::Expr = load_ace_col::<AB>(next, READ_NUM_EVAL_IDX);

    let v0_0: AB::Expr = load_ace_col::<AB>(local, V_0_0_IDX);
    let v0_1: AB::Expr = load_ace_col::<AB>(local, V_0_1_IDX);
    let v1_0: AB::Expr = load_ace_col::<AB>(local, V_1_0_IDX);
    let v1_1: AB::Expr = load_ace_col::<AB>(local, V_1_1_IDX);
    let v2_0: AB::Expr = load_ace_col::<AB>(local, V_2_0_IDX);
    let v2_1: AB::Expr = load_ace_col::<AB>(local, V_2_1_IDX);

    let one: AB::Expr = AB::Expr::ONE;
    let four: AB::Expr = AB::Expr::from_u32(4);

    // Gate all transition constraints by is_transition() to avoid last-row issues
    let is_transition: AB::Expr = builder.is_transition();

    // ACE continuing to next row (not transitioning out)
    // Must be combined with is_transition for constraints accessing next-row values
    let flag_ace_next = is_transition.clone() * (one.clone() - s3_next.clone());
    let flag_ace_last = is_transition.clone() * s3_next.clone();

    // ==========================================================================
    // BINARY CONSTRAINTS
    // ==========================================================================

    // sstart must be binary
    builder.assert_zero(ace_flag.clone() * sstart.clone() * (sstart.clone() - one.clone()));

    // sblock must be binary
    builder.assert_zero(ace_flag.clone() * sblock.clone() * (sblock.clone() - one.clone()));

    // ==========================================================================
    // SECTION/BLOCK FLAGS CONSTRAINTS
    // ==========================================================================

    // Last row of ACE chiplet cannot be section start
    builder.assert_zero(ace_flag.clone() * flag_ace_last.clone() * sstart.clone());

    // Prevent consecutive section starts within ACE chiplet
    builder.assert_zero(
        ace_flag.clone() * flag_ace_next.clone() * sstart.clone() * sstart_next.clone(),
    );

    // Sections must start with READ blocks (not EVAL): f_eval = 0 when f_start
    builder.assert_zero(ace_flag.clone() * sstart.clone() * sblock.clone());

    // EVAL blocks cannot be followed by READ blocks within same section
    // (when sstart' = 0 and sblock = 1, then sblock' = 1)
    let f_next = one.clone() - sstart_next.clone();
    builder.assert_zero(
        ace_flag.clone()
            * flag_ace_next.clone()
            * f_next.clone()
            * sblock.clone()
            * (one.clone() - sblock_next.clone()),
    );

    // Sections must end with EVAL blocks (not READ)
    let f_end = binary_or(flag_ace_next.clone() * sstart_next.clone(), flag_ace_last.clone());
    builder.assert_zero(ace_flag.clone() * f_end.clone() * (one.clone() - sblock.clone()));

    // ==========================================================================
    // SECTION CONSTRAINTS (within section)
    // ==========================================================================

    let flag_within_section = one.clone() - sstart_next.clone();
    let f_read = one.clone() - sblock.clone();
    let f_eval = sblock.clone();

    // Context consistency within a section
    // Use a combined gate to share `ace_flag * flag_ace_next * flag_within_section`
    // across all within-section transition constraints.
    let within_section_gate =
        ace_flag.clone() * flag_ace_next.clone() * flag_within_section.clone();

    // Memory pointer increments: +4 in READ, +1 in EVAL
    // ptr' = ptr + 4 * f_read + f_eval
    let expected_ptr = ptr.clone() + four.clone() * f_read.clone() + f_eval.clone();

    // Node ID decrements: -2 in READ, -1 in EVAL
    // id0 = id0' + 2 * f_read + f_eval
    let expected_id0 = id0_next.clone() + f_read.clone().double() + f_eval.clone();
    builder.when(within_section_gate).assert_zeros([
        ctx_next.clone() - ctx.clone(),
        clk_next.clone() - clk.clone(),
        ptr_next.clone() - expected_ptr,
        id0.clone() - expected_id0,
    ]);

    // ==========================================================================
    // READ BLOCK CONSTRAINTS
    // ==========================================================================

    // In READ block, the two node IDs should be consecutive (id1 = id0 - 1)
    builder
        .assert_zero(ace_flag.clone() * f_read.clone() * (id1.clone() - id0.clone() + one.clone()));

    // READ→EVAL transition occurs when n_eval matches the first EVAL id0.
    // Enforce: f_read * (f_read' * n_eval' + f_eval' * id0' - n_eval) = 0
    let f_read_next = one.clone() - sblock_next.clone();
    let f_eval_next = sblock_next.clone();
    let selected = f_read_next * n_eval_next.clone() + f_eval_next * id0_next.clone();
    builder
        .when_transition()
        .assert_zero(ace_flag.clone() * f_read.clone() * (selected - n_eval));

    // ==========================================================================
    // EVAL BLOCK CONSTRAINTS
    // ==========================================================================

    // op must be -1, 0, or 1: op * (op - 1) * (op + 1) = 0
    builder.assert_zero(
        ace_flag.clone()
            * f_eval.clone()
            * op.clone()
            * (op.clone() - one.clone())
            * (op.clone() + one.clone()),
    );

    // Arithmetic operation constraints
    enforce_arithmetic_operation(
        builder,
        ace_flag.clone() * f_eval.clone(),
        op,
        v0_0.clone(),
        v0_1.clone(),
        v1_0,
        v1_1,
        v2_0,
        v2_1,
    );

    // ==========================================================================
    // FINALIZATION CONSTRAINTS
    // ==========================================================================

    // At section end: v0 = 0, id0 = 0
    // Use a combined gate to share `ace_flag * f_end` across all finalization constraints.
    let gate = ace_flag * f_end;
    builder.when(gate).assert_zeros([v0_0, v0_1, id0]);
}

/// Enforce ACE first row constraints.
///
/// On the first row of ACE chiplet, sstart' must be 1.
pub fn enforce_ace_constraints_first_row<AB>(
    builder: &mut AB,
    _local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    flag_next_row_first_ace: AB::Expr,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    let sstart_next: AB::Expr = load_ace_col::<AB>(next, SELECTOR_START_IDX);
    let one: AB::Expr = AB::Expr::ONE;

    // First row of ACE must have sstart' = 1
    builder.assert_zero(flag_next_row_first_ace * (sstart_next - one));
}

// INTERNAL HELPERS
// ================================================================================================

/// Load a column from the ACE section of chiplets.
fn load_ace_col<AB>(row: &MainTraceRow<AB::Var>, ace_col_idx: usize) -> AB::Expr
where
    AB: MidenAirBuilder<F = Felt>,
{
    // ACE columns start after s0, s1, s2, s3 (4 selectors)
    let local_idx = ACE_OFFSET + ace_col_idx;
    row.chiplets[local_idx].clone().into()
}

/// Enforce arithmetic operation constraint for EVAL block.
///
/// Operations in extension field 𝔽ₚ[x]/(x² - 7):
/// - op = -1: Subtraction (v0 = v1 - v2)
/// - op =  0: Multiplication (v0 = v1 × v2)
/// - op =  1: Addition (v0 = v1 + v2)
fn enforce_arithmetic_operation<AB>(
    builder: &mut AB,
    gate: AB::Expr,
    op: AB::Expr,
    v0_0: AB::Expr,
    v0_1: AB::Expr,
    v1_0: AB::Expr,
    v1_1: AB::Expr,
    v2_0: AB::Expr,
    v2_1: AB::Expr,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    // Linear operation: v1 + op * v2 (works for ADD when op=1, SUB when op=-1)
    let linear_0 = v1_0.clone() + op.clone() * v2_0.clone();
    let linear_1 = v1_1.clone() + op.clone() * v2_1.clone();

    // Non-linear operation (multiplication in extension field):
    // (a0 + a1*α) * (b0 + b1*α) where α² = 7
    // = a0*b0 + a0*b1*α + a1*b0*α + a1*b1*α²
    // = a0*b0 + (a0*b1 + a1*b0)*α + a1*b1*7
    // = (a0*b0 + 7*a1*b1) + (a0*b1 + a1*b0)*α
    let a0b0 = v1_0.clone() * v2_0.clone();
    let a1b1 = v1_1.clone() * v2_1.clone();
    let seven: AB::Expr = AB::Expr::from_u32(7);
    let nonlinear_0 = a0b0.clone() + seven * a1b1;
    let nonlinear_1 = v1_0 * v2_1.clone() + v1_1 * v2_0;

    // Select based on op²: if op² = 1, use linear; if op² = 0, use nonlinear
    // op_square * (linear - nonlinear) + nonlinear = v0
    let op_square = op.clone() * op;
    let expected_0 =
        op_square.clone() * (linear_0.clone() - nonlinear_0.clone()) + nonlinear_0.clone();
    let expected_1 = op_square * (linear_1.clone() - nonlinear_1.clone()) + nonlinear_1;

    builder.assert_zero(gate.clone() * (expected_0 - v0_0));
    builder.assert_zero(gate * (expected_1 - v0_1));
}

/// Computes binary OR: `a + b - a * b`
///
/// Assumes both a and b are binary (0 or 1).
/// Returns 1 if either a=1 or b=1.
#[inline]
pub fn binary_or<E>(a: E, b: E) -> E
where
    E: Clone + core::ops::Add<Output = E> + core::ops::Sub<Output = E> + core::ops::Mul<Output = E>,
{
    a.clone() + b.clone() - a * b
}
