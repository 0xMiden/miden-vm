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
//! ## Column Layout (within chiplet, offset by selectors)
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

use super::selectors::{ace_chiplet_flag, memory_chiplet_flag};
use crate::{
    Felt, MainTraceRow,
    constraints::tagging::TaggingAirBuilderExt,
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

/// Enforce ACE chiplet constraints with transition handling.
pub fn enforce_ace_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    // Load selectors
    let s0: AB::Expr = local.chiplets[0].clone().into();
    let s1: AB::Expr = local.chiplets[1].clone().into();
    let s2: AB::Expr = local.chiplets[2].clone().into();
    let s2_next: AB::Expr = next.chiplets[2].clone().into();
    let s3_next: AB::Expr = next.chiplets[3].clone().into();

    // Gate transition constraints by is_transition() to avoid last-row issues
    let is_transition: AB::Expr = builder.is_transition();

    // ACE constraints on all rows (already internally gated)
    enforce_ace_constraints_all_rows(builder, local, next);

    // ACE first row constraints (transitioning from memory to ACE)
    // Flag: current row is memory (s0*s1*!s2), next row is ACE (s2'=1 AND s3'=0)
    // The s3'=0 check is critical because:
    // 1. A trace may skip ACE entirely (going memory -> kernel ROM)
    // 2. When not in ACE, chiplets[4] is s4 (selector), not sstart
    // 3. Without the s3'=0 check, we'd read the wrong column
    // Must be gated by is_transition since it accesses next-row values
    let memory_flag = memory_chiplet_flag(s0, s1, s2);
    // ace_next = s2' * !s3'
    let ace_next = s2_next * (AB::Expr::ONE - s3_next);
    let flag_next_row_first_ace = is_transition * memory_flag * ace_next;
    enforce_ace_constraints_first_row(builder, local, next, flag_next_row_first_ace);
}

/// Enforce ACE chiplet constraints that apply to all rows.
pub fn enforce_ace_constraints_all_rows<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
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
    // n_eval stores (num_eval_rows - 1) so READ→EVAL switches when id0' == n_eval.
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

    // ACE continuing to the next row (not transitioning out).
    // Includes is_transition because it reads next-row values.
    let flag_ace_next = is_transition.clone() * (one.clone() - s3_next.clone());
    // Last ACE row (next row transitions out of ACE).
    // Includes is_transition because it reads next-row values.
    let flag_ace_last = is_transition.clone() * s3_next.clone();

    // ==========================================================================
    // BINARY CONSTRAINTS
    // ==========================================================================

    builder.assert_zero(ace_flag.clone() * sstart.clone() * (sstart.clone() - one.clone()));
    builder.assert_zero(ace_flag.clone() * sblock.clone() * (sblock.clone() - one.clone()));

    // ==========================================================================
    // SECTION/BLOCK FLAGS CONSTRAINTS
    // ==========================================================================

    let f_next = one.clone() - sstart_next.clone();

    // Sections must end with EVAL blocks (not READ).
    // OR(t*a, t*b) = t*OR(a, b) when t is binary.
    let f_end = binary_or((one.clone() - s3_next.clone()) * sstart_next.clone(), s3_next.clone());

    // Last row of ACE chiplet cannot be section start
    builder.assert_zero(ace_flag.clone() * flag_ace_last.clone() * sstart.clone());
    // Prevent consecutive section starts within ACE chiplet
    builder.assert_zero(
        ace_flag.clone() * flag_ace_next.clone() * sstart.clone() * sstart_next.clone(),
    );
    // Sections must start with READ blocks (not EVAL): f_eval = 0 when f_start
    builder.assert_zero(ace_flag.clone() * sstart.clone() * sblock.clone());
    // EVAL blocks cannot be followed by READ blocks within same section
    builder.assert_zero(
        ace_flag.clone()
            * flag_ace_next.clone()
            * f_next.clone()
            * sblock.clone()
            * (one.clone() - sblock_next.clone()),
    );
    // Sections must end with EVAL blocks (not READ)
    builder.assert_zero(
        ace_flag.clone() * is_transition.clone() * f_end.clone() * (one.clone() - sblock.clone()),
    );

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
    let expected_ptr_next = ptr.clone() + four.clone() * f_read.clone() + f_eval.clone();

    // Node ID decrements: -2 in READ, -1 in EVAL
    // id0 = id0' + 2 * f_read + f_eval
    let expected_id0 = id0_next.clone() + f_read.clone().double() + f_eval.clone();
    builder.assert_zero(within_section_gate.clone() * (ctx_next.clone() - ctx.clone()));
    builder.assert_zero(within_section_gate.clone() * (clk_next.clone() - clk.clone()));
    builder.assert_zero(within_section_gate.clone() * (ptr_next.clone() - expected_ptr_next));
    builder.assert_zero(within_section_gate * (id0.clone() - expected_id0));

    // ==========================================================================
    // READ BLOCK CONSTRAINTS
    // ==========================================================================

    // In READ block, the two node IDs should be consecutive (id1 = id0 - 1)
    builder
        .assert_zero(ace_flag.clone() * f_read.clone() * (id1.clone() - id0.clone() + one.clone()));

    // READ→EVAL transition occurs when n_eval matches the first EVAL id0.
    // n_eval is constant across READ rows and encodes (num_eval_rows - 1).
    // Enforce: f_read * (f_read' * n_eval' + f_eval' * id0' - n_eval) = 0
    let f_read_next = one.clone() - sblock_next.clone();
    let f_eval_next = sblock_next.clone();
    let selected = f_read_next * n_eval_next.clone() + f_eval_next * id0_next.clone();
    builder.assert_zero(
        is_transition.clone() * ace_flag.clone() * f_read.clone() * (selected - n_eval),
    );

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
    let eval_gate = ace_flag.clone() * f_eval.clone();
    let (expected_0, expected_1) = compute_arithmetic_expected::<AB>(op, v1_0, v1_1, v2_0, v2_1);
    builder.assert_zero(eval_gate.clone() * (expected_0 - v0_0.clone()));
    builder.assert_zero(eval_gate.clone() * (expected_1 - v0_1.clone()));

    // ==========================================================================
    // FINALIZATION CONSTRAINTS
    // ==========================================================================

    // At section end: v0 = 0, id0 = 0
    // Use a combined gate to share `ace_flag * is_transition * f_end` across all finalization
    // constraints.
    let gate = ace_flag * is_transition * f_end;
    builder.assert_zero(gate.clone() * v0_0);
    builder.assert_zero(gate.clone() * v0_1);
    builder.assert_zero(gate * id0);
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
    AB: TaggingAirBuilderExt<F = Felt>,
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
    AB: TaggingAirBuilderExt<F = Felt>,
{
    // ACE columns start after s0, s1, s2, s3 (4 selectors)
    let local_idx = ACE_OFFSET + ace_col_idx;
    row.chiplets[local_idx].clone().into()
}

/// Compute expected EVAL block outputs (v0) from op and operands.
///
/// Operations in extension field 𝔽ₚ[x]/(x² - 7):
/// - op = -1: Subtraction (v0 = v1 - v2)
/// - op =  0: Multiplication (v0 = v1 × v2)
/// - op =  1: Addition (v0 = v1 + v2)
fn compute_arithmetic_expected<AB>(
    op: AB::Expr,
    v1_0: AB::Expr,
    v1_1: AB::Expr,
    v2_0: AB::Expr,
    v2_1: AB::Expr,
) -> (AB::Expr, AB::Expr)
where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    use crate::constraints::ext_field::QuadFeltExpr;

    let v1 = QuadFeltExpr(v1_0, v1_1);
    let v2 = QuadFeltExpr(v2_0, v2_1);

    // Linear operation: v1 + op * v2 (works for ADD when op=1, SUB when op=-1)
    let linear = v1.clone() + v2.clone() * op.clone();

    // Non-linear operation: multiplication in extension field (α² = 7)
    let nonlinear = v1 * v2;

    // Select based on op²: if op² = 1, use linear; if op² = 0, use nonlinear
    // op_square * (linear - nonlinear) + nonlinear = v0
    let op_square = op.clone() * op;
    let expected = QuadFeltExpr(
        op_square.clone() * (linear.0.clone() - nonlinear.0.clone()) + nonlinear.0,
        op_square * (linear.1.clone() - nonlinear.1.clone()) + nonlinear.1,
    );

    expected.into_parts().into()
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
