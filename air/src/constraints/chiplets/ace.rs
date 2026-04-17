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
    MainCols, MidenAirBuilder,
    constraints::{
        constants::{F_1, F_4},
        ext_field::{QuadFeltAirBuilder, QuadFeltExpr},
        utils::BoolNot,
    },
};

// ENTRY POINTS
// ================================================================================================

/// Enforce ACE chiplet constraints that apply to all rows.
pub fn enforce_ace_constraints_all_rows<AB>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    flags: &ChipletFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let local = local.ace();
    let next = next.ace();

    let ace_flag = flags.is_active.clone();
    let ace_transition = flags.is_transition.clone();
    let ace_last = flags.is_last.clone();

    // Derived section flags
    let s_start = local.s_start;
    let s_start_next = next.s_start;
    let s_transition = s_start_next.into().not();

    // ==========================================================================
    // FIRST ROW CONSTRAINTS
    // ==========================================================================

    // First row of ACE must have sstart' = 1
    builder.when(flags.next_is_first.clone()).assert_one(s_start_next);

    // ==========================================================================
    // BINARY CONSTRAINTS
    // ==========================================================================

    // When ACE is active, section flags must be boolean.
    {
        let builder = &mut builder.when(ace_flag.clone());
        builder.assert_bool(local.s_start);
        builder.assert_bool(local.s_block);
    }

    let f_eval = local.s_block;
    let f_eval_next = next.s_block;
    let f_read = f_eval.into().not();
    let f_read_next = f_eval_next.into().not();

    // ==========================================================================
    // SECTION/BLOCK FLAGS CONSTRAINTS
    // ==========================================================================
    {
        // Last row of ACE chiplet cannot be section start
        builder.when(ace_last.clone()).assert_zero(s_start);

        // Prevent consecutive section starts within ACE chiplet
        builder.when(ace_transition.clone()).when(s_start).assert_zero(s_start_next);

        // Sections must start with READ blocks (not EVAL)
        builder.when(ace_flag.clone()).when(s_start).assert_zero(f_eval);

        // EVAL blocks cannot be followed by READ blocks within same section
        builder
            .when(ace_transition.clone())
            .when(s_transition.clone())
            .when(f_eval)
            .assert_zero(f_read_next.clone());
    }

    // ==========================================================================
    // SECTION CONSTRAINTS (within section)
    // ==========================================================================

    // Within-section transitions: context, clock, pointer, and node ID consistency.
    {
        let builder = &mut builder.when(ace_transition.clone() * s_transition);

        // clk and ctx are stable
        builder.assert_eq(next.ctx, local.ctx);
        builder.assert_eq(next.clk, local.clk);

        // Memory pointer increments: +4 in READ, +1 in EVAL
        // ptr' = ptr + 4 * f_read + f_eval
        let expected_ptr: AB::Expr = local.ptr + f_read.clone() * F_4 + f_eval;
        builder.assert_eq(next.ptr, expected_ptr);

        // Node ID decrements: -2 in READ, -1 in EVAL
        // id0 = id0' + 2 * f_read + f_eval
        let expected_id0: AB::Expr = next.id_0 + f_read.double() + f_eval;
        builder.assert_eq(local.id_0, expected_id0);
    }

    // ==========================================================================
    // READ BLOCK CONSTRAINTS
    // ==========================================================================

    // In READ block, the two node IDs should be consecutive (id1 = id0 - 1)
    builder
        .when(ace_flag.clone())
        .when(f_read.clone())
        .assert_eq(local.id_1, local.id_0 - F_1);

    // READ→EVAL transition occurs when n_eval matches the first EVAL id0.
    // n_eval is constant across READ rows and encodes (num_eval_rows - 1).
    // Enforce: f_read * (f_read' * n_eval' + f_eval' * id0' - n_eval) = 0
    let selected: AB::Expr = f_read_next * next.read().num_eval + f_eval_next * next.id_0;
    builder
        .when(ace_transition.clone())
        .when(f_read.clone())
        .assert_eq(selected, local.read().num_eval);

    // ==========================================================================
    // EVAL BLOCK CONSTRAINTS
    // ==========================================================================

    // EVAL block: op ternary validity and arithmetic operation result.
    {
        let builder = &mut builder.when(ace_flag.clone() * f_eval);
        let op: AB::Expr = local.eval_op.into();

        let op_square = op.square();
        // op must be -1, 0, or 1: ternary validity
        // op * (op² - 1) = op ( op - 1) ( op + 1 )
        builder.assert_zero(op.clone() * (op_square.clone() - F_1));

        // Compute expected EVAL block output (v0) from op and operands.
        //
        // Operations in extension field 𝔽ₚ[x]/(x² - 7):
        // - op = -1: Subtraction (v0 = v1 - v2)
        // - op =  0: Multiplication (v0 = v1 × v2)
        // - op =  1: Addition (v0 = v1 + v2)
        let v0: QuadFeltExpr<AB::Expr> = local.v_0.into_expr();
        let v1: QuadFeltExpr<AB::Expr> = local.v_1.into_expr();
        let v2: QuadFeltExpr<AB::Expr> = local.eval().v_2.into_expr();

        let expected = {
            // Linear operation: v1 + op * v2 (works for ADD when op=1, SUB when op=-1)
            let linear = v1.clone() + v2.clone() * op;

            // Non-linear operation: multiplication in extension field (α² = 7)
            let nonlinear = v1 * v2;

            // Select based on op²: if op² = 1, use linear; if op² = 0, use nonlinear
            // result = op² * (linear - nonlinear) + nonlinear
            (linear - nonlinear.clone()) * op_square + nonlinear
        };
        builder.assert_eq_quad(v0, expected);
    }

    // ==========================================================================
    // FINALIZATION CONSTRAINTS
    // ==========================================================================

    // At section end: result value and node ID must be zero.
    {
        // f_end fires on the last ACE row or on section boundaries.
        let f_end = flags.is_last.clone() + flags.is_transition.clone() * s_start_next;
        let builder = &mut builder.when(f_end);

        // Sections must end with EVAL blocks (not READ).
        builder.assert_zero(f_read);

        let v0: QuadFeltExpr<AB::Expr> = local.v_0.into_expr();

        builder.assert_eq_quad(v0, QuadFeltExpr::new(AB::Expr::ZERO, AB::Expr::ZERO));

        builder.assert_zero(local.id_0);
    }
}
