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
use miden_crypto::stark::air::AirBuilder;

use super::selectors::ChipletFlags;
use crate::{
    MainTraceRow, MidenAirBuilder,
    constraints::{
        constants::{F_1, F_4},
        utils::{BoolNot, binary_or},
    },
};

// ENTRY POINTS
// ================================================================================================

/// Enforce ACE chiplet constraints that apply to all rows.
pub fn enforce_ace_constraints_all_rows<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    flags: &ChipletFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let s3_next = next.chiplet_selectors()[3];

    let ace_flag = flags.is_active.clone();

    let ace = local.ace();
    let ace_next = next.ace();

    let sstart: AB::Expr = ace.s_start.into();
    let sstart_next: AB::Expr = ace_next.s_start.into();
    let sblock: AB::Expr = ace.s_block.into();
    let sblock_next: AB::Expr = ace_next.s_block.into();
    let ctx: AB::Expr = ace.ctx.into();
    let ctx_next: AB::Expr = ace_next.ctx.into();
    let ptr: AB::Expr = ace.ptr.into();
    let ptr_next: AB::Expr = ace_next.ptr.into();
    let clk: AB::Expr = ace.clk.into();
    let clk_next: AB::Expr = ace_next.clk.into();
    let op: AB::Expr = ace.eval_op.into();
    let id0: AB::Expr = ace.shared[0].into();
    let id0_next: AB::Expr = ace_next.shared[0].into();
    let id1: AB::Expr = ace.shared[3].into();
    // n_eval stores (num_eval_rows - 1) so READ→EVAL switches when id0' == n_eval.
    let n_eval: AB::Expr = ace.read().num_eval.into();
    let n_eval_next: AB::Expr = ace_next.read().num_eval.into();

    let v0_0: AB::Expr = ace.shared[1].into();
    let v0_1: AB::Expr = ace.shared[2].into();
    let v1_0: AB::Expr = ace.shared[4].into();
    let v1_1: AB::Expr = ace.shared[5].into();
    let v2_0: AB::Expr = ace.eval().v_2[0].into();
    let v2_1: AB::Expr = ace.eval().v_2[1].into();

    // Precomputed ACE transition flag (bakes in is_transition)
    let ace_transition = flags.is_transition.clone();
    let ace_last = flags.is_last.clone();

    // ==========================================================================
    // FIRST ROW CONSTRAINTS
    // ==========================================================================

    // First row of ACE must have sstart' = 1
    builder.when(flags.next_is_first.clone()).assert_one(sstart_next.clone());

    // ==========================================================================
    // BINARY CONSTRAINTS
    // ==========================================================================

    // When ACE is active, section flags must be boolean.
    {
        let builder = &mut builder.when(ace_flag.clone());
        builder.assert_bool(sstart.clone());
        builder.assert_bool(sblock.clone());
    }

    // ==========================================================================
    // SECTION/BLOCK FLAGS CONSTRAINTS
    // ==========================================================================

    let f_next = sstart_next.not();

    // Sections must end with EVAL blocks (not READ).
    // OR(t*a, t*b) = t*OR(a, b) when t is binary.
    let f_end = binary_or(s3_next.into().not() * sstart_next.clone(), s3_next.into());

    // Last row of ACE chiplet cannot be section start
    builder.when(ace_last.clone()).assert_zero(sstart.clone());
    // Prevent consecutive section starts within ACE chiplet
    builder
        .when(ace_transition.clone())
        .when(sstart.clone())
        .assert_zero(sstart_next.clone());
    // Sections must start with READ blocks (not EVAL): sblock = 0 when sstart = 1
    builder.when(ace_flag.clone()).when(sstart.clone()).assert_zero(sblock.clone());
    // EVAL blocks cannot be followed by READ blocks within same section
    builder
        .when(ace_transition.clone())
        .when(f_next.clone())
        .when(sblock.clone())
        .assert_one(sblock_next.clone());
    // Sections must end with EVAL blocks (not READ).
    // f_end fires on the last ACE row or on section boundaries. Since ace_flag = 0 on
    // the trace's last row (last-row invariant), no when_transition() guard is needed.
    builder.when(ace_flag.clone()).when(f_end.clone()).assert_one(sblock.clone());

    // ==========================================================================
    // SECTION CONSTRAINTS (within section)
    // ==========================================================================

    let flag_within_section = sstart_next.not();
    let f_read = sblock.not();
    let f_eval = sblock.clone();

    // Within-section transitions: context, clock, pointer, and node ID consistency.
    {
        let builder = &mut builder.when(ace_transition.clone() * flag_within_section.clone());
        builder.assert_eq(ctx_next.clone(), ctx.clone());
        builder.assert_eq(clk_next.clone(), clk.clone());

        // Memory pointer increments: +4 in READ, +1 in EVAL
        // ptr' = ptr + 4 * f_read + f_eval
        let expected_ptr_next = ptr.clone() + f_read.clone() * F_4 + f_eval.clone();
        builder.assert_eq(ptr_next.clone(), expected_ptr_next);

        // Node ID decrements: -2 in READ, -1 in EVAL
        // id0 = id0' + 2 * f_read + f_eval
        let expected_id0 = id0_next.clone() + f_read.clone().double() + f_eval.clone();
        builder.assert_eq(id0.clone(), expected_id0);
    }

    // ==========================================================================
    // READ BLOCK CONSTRAINTS
    // ==========================================================================

    // In READ block, the two node IDs should be consecutive (id1 = id0 - 1)
    builder
        .when(ace_flag.clone())
        .when(f_read.clone())
        .assert_eq(id1.clone(), id0.clone() - F_1);

    // READ→EVAL transition occurs when n_eval matches the first EVAL id0.
    // n_eval is constant across READ rows and encodes (num_eval_rows - 1).
    // Enforce: f_read * (f_read' * n_eval' + f_eval' * id0' - n_eval) = 0
    let f_read_next = sblock_next.not();
    let f_eval_next = sblock_next.clone();
    let selected = f_read_next * n_eval_next.clone() + f_eval_next * id0_next.clone();
    builder
        .when(ace_transition.clone())
        .when(f_read.clone())
        .assert_eq(selected, n_eval);

    // ==========================================================================
    // EVAL BLOCK CONSTRAINTS
    // ==========================================================================

    // EVAL block: op ternary validity and arithmetic operation result.
    {
        let builder = &mut builder.when(ace_flag.clone() * f_eval.clone());
        // op must be -1, 0, or 1: ternary validity (intrinsic, do not decompose)
        builder.assert_zero(op.clone() * (op.clone() - F_1) * (op.clone() + F_1));

        let (expected_0, expected_1) =
            compute_arithmetic_expected::<AB>(op, v1_0, v1_1, v2_0, v2_1);
        builder.assert_eq(expected_0, v0_0.clone());
        builder.assert_eq(expected_1, v0_1.clone());
    }

    // ==========================================================================
    // FINALIZATION CONSTRAINTS
    // ==========================================================================

    // At section end: result value and node ID must be zero.
    // No when_transition() needed: ace_flag = 0 on the last row (last-row invariant).
    {
        let builder = &mut builder.when(ace_flag * f_end);
        builder.assert_zero(v0_0);
        builder.assert_zero(v0_1);
        builder.assert_zero(id0);
    }
}

// INTERNAL HELPERS
// ================================================================================================

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
    AB: MidenAirBuilder,
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
