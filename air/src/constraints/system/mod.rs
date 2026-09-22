//! System constraints module.
//!
//! This module contains constraints for the system component of the Miden VM,
//! which manages execution context and function hash system columns transitions.
//!
//! ## System Columns
//!
//! - `clk`: VM execution clock (clk[0] = 0, clk' = clk + 1)
//! - `ctx`: Execution context ID (determines memory context isolation)
//! - `fn_hash` (four elements): Current function digest (identifies executing procedure)
//!
//! ## Context Transitions
//!
//! | Operation             | ctx'              | Description               |
//! |-----------------------|-------------------|---------------------------|
//! | CALL or DYNCALL       | clk + 1           | Create new context        |
//! | SYSCALL               | 0                 | Return to kernel context  |
//! | Caller-frame END      | (from block stack)| Restore caller context    |
//! | Continuation END      | ctx               | Unchanged                 |
//! | Other ops             | ctx               | Unchanged                 |
//!
//! ## Function Hash Transitions
//!
//! | Operation                       | fn_hash'           | Description                 |
//! |---------------------------------|--------------------|-----------------------------|
//! | CALL or DYNCALL                 | decoder h0..h3     | Load new procedure hash     |
//! | Caller-frame END                | (from block stack) | Restore previous hash       |
//! | Continuation END                | fn_hash            | Unchanged                   |
//! | Other ops (incl. DYN, SYSCALL)  | fn_hash            | Unchanged                   |
//!
//! Note: restoration is handled by the block-stack relation only for an END that consumes a
//! caller-frame entry, whose removal carries `ctx` and `fn_hash`. A continuation entry carries
//! neither, so these constraints must preserve both columns across a continuation END -- see
//! `f_restore_caller_frame` below.

pub mod columns;

use miden_crypto::stark::air::AirBuilder;
use p3_field::Dup;

use crate::{
    CoreCols, MidenAirBuilder,
    constraints::{constants::F_1, op_flags::OpFlags, utils::BoolNot},
};

// ENTRY POINTS
// ================================================================================================

/// Enforces system constraints.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &CoreCols<AB::Var>,
    next: &CoreCols<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // Clock: starts at 0, increments by 1
    {
        let builder = &mut builder.when_first_row();
        builder.assert_zero(local.system.clk);
        builder.assert_zero(local.system.ctx);
        for limb in local.system.fn_hash {
            builder.assert_zero(limb);
        }
    }
    {
        builder.when_transition().assert_eq(next.system.clk, local.system.clk + F_1);
    }
    let f_call = op_flags.call();
    let f_syscall = op_flags.syscall();
    let f_dyncall = op_flags.dyncall();

    // Only a caller-frame END may restore `ctx` and `fn_hash`; a continuation END preserves them.
    // The decoder constrains this selector, and the block-stack relation authenticates the entry
    // kind and restored payload.
    let end_flags = local.decoder.end_block_flags();
    let f_restore_caller_frame = op_flags.end() * end_flags.restores_caller_frame;

    // Execution context transition constraints (see module doc for transition table)
    {
        let ctx = local.system.ctx;
        let ctx_next = next.system.ctx;
        let clk = local.system.clk;

        let call_dyncall_flag = f_call.dup() + f_dyncall.dup();
        let change_ctx_flag =
            f_call.dup() + f_syscall.dup() + f_dyncall.dup() + f_restore_caller_frame.dup();
        let default_flag = change_ctx_flag.not();

        builder.when(call_dyncall_flag).assert_eq(ctx_next, clk + F_1);
        builder.when(f_syscall).assert_zero(ctx_next);
        builder.when_transition().when(default_flag).assert_eq(ctx_next, ctx);
    }

    // Function hash transition constraints (see module doc for transition table)
    {
        let f_load = f_call + f_dyncall;
        let f_preserve = (f_load.dup() + f_restore_caller_frame).not();

        {
            let builder = &mut builder.when(f_load);
            for i in 0..4 {
                builder.assert_eq(next.system.fn_hash[i], local.decoder.hasher_state[i]);
            }
        }

        builder
            .when_transition()
            .when(f_preserve)
            .assert_eq_arrays(next.system.fn_hash, local.system.fn_hash);
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_core::{
        Felt,
        field::{PrimeCharacteristicRing, QuadFelt},
        operations::opcodes,
    };
    use miden_crypto::stark::{
        air::{AirBuilder, ExtensionBuilder, PermutationAirBuilder, RowWindow},
        matrix::RowMajorMatrix,
    };

    use super::enforce_main;
    use crate::{
        CoreCols,
        constraints::{
            op_flags::{OpFlags, generate_test_row},
            system::columns::SystemCols,
        },
        trace::{AUX_TRACE_RAND_CHALLENGES, AUX_TRACE_WIDTH, TRACE_WIDTH},
    };

    struct ConstraintEvalBuilder {
        main: RowMajorMatrix<Felt>,
        aux: RowMajorMatrix<QuadFelt>,
        randomness: Vec<QuadFelt>,
        permutation_values: Vec<QuadFelt>,
        periodic_values: Vec<Felt>,
        preprocessed: RowWindow<'static, Felt>,
        evaluations: Vec<QuadFelt>,
    }

    impl ConstraintEvalBuilder {
        fn new() -> Self {
            Self {
                main: RowMajorMatrix::new(vec![Felt::ZERO; TRACE_WIDTH * 2], TRACE_WIDTH),
                aux: RowMajorMatrix::new(
                    vec![QuadFelt::ZERO; AUX_TRACE_WIDTH * 2],
                    AUX_TRACE_WIDTH,
                ),
                randomness: vec![QuadFelt::ZERO; AUX_TRACE_RAND_CHALLENGES],
                permutation_values: vec![QuadFelt::ZERO; AUX_TRACE_WIDTH],
                periodic_values: Vec::new(),
                preprocessed: RowWindow::from_two_rows(&[], &[]),
                evaluations: Vec::new(),
            }
        }
    }

    impl AirBuilder for ConstraintEvalBuilder {
        type F = Felt;
        type Expr = Felt;
        type Var = Felt;
        type PreprocessedWindow = RowWindow<'static, Felt>;
        type MainWindow = RowMajorMatrix<Felt>;
        type PublicVar = Felt;
        type PeriodicVar = Felt;

        fn main(&self) -> Self::MainWindow {
            self.main.clone()
        }

        fn preprocessed(&self) -> &Self::PreprocessedWindow {
            &self.preprocessed
        }

        fn is_first_row(&self) -> Self::Expr {
            Felt::ONE
        }

        fn is_last_row(&self) -> Self::Expr {
            Felt::ZERO
        }

        fn is_transition(&self) -> Self::Expr {
            Felt::ONE
        }

        fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
            self.evaluations.push(QuadFelt::from(x.into()));
        }

        fn public_values(&self) -> &[Self::PublicVar] {
            &[]
        }

        fn periodic_values(&self) -> &[Self::PeriodicVar] {
            &self.periodic_values
        }
    }

    impl ExtensionBuilder for ConstraintEvalBuilder {
        type EF = QuadFelt;
        type ExprEF = QuadFelt;
        type VarEF = QuadFelt;

        fn assert_zero_ext<I>(&mut self, x: I)
        where
            I: Into<Self::ExprEF>,
        {
            self.evaluations.push(x.into());
        }
    }

    impl PermutationAirBuilder for ConstraintEvalBuilder {
        type MP = RowMajorMatrix<QuadFelt>;
        type RandomVar = QuadFelt;
        type PermutationVar = QuadFelt;

        fn permutation(&self) -> Self::MP {
            self.aux.clone()
        }

        fn permutation_randomness(&self) -> &[Self::RandomVar] {
            &self.randomness
        }

        fn permutation_values(&self) -> &[Self::PermutationVar] {
            &self.permutation_values
        }
    }

    fn forged_system_state() -> SystemCols<Felt> {
        SystemCols {
            clk: Felt::ZERO,
            ctx: Felt::new_unchecked(7),
            fn_hash: [
                Felt::new_unchecked(11),
                Felt::new_unchecked(22),
                Felt::new_unchecked(33),
                Felt::new_unchecked(44),
            ],
        }
    }

    #[test]
    fn system_constraints_reject_nonzero_initial_context_and_fn_hash() {
        let mut local = generate_test_row(0);
        local.system = forged_system_state();

        let mut next = generate_test_row(0);
        next.system = forged_system_state();
        next.system.clk = Felt::ONE;

        let op_flags = OpFlags::new(&local.decoder, &local.stack, &next.decoder);
        let mut builder = ConstraintEvalBuilder::new();
        enforce_main(&mut builder, &local, &next, &op_flags);

        assert!(
            builder.evaluations.iter().any(|value| *value != QuadFelt::ZERO),
            "system constraints should reject a forged initial context and function hash"
        );
    }

    /// Evaluates the system constraints on an interior transition, excluding first-row boundary
    /// constraints from these caller-frame restoration tests.
    fn eval_system(local: &CoreCols<Felt>, next: &CoreCols<Felt>) -> Vec<QuadFelt> {
        use crate::constraints::stack::test_utils::ConstraintEvalBuilder as SharedBuilder;
        let op_flags = OpFlags::new(&local.decoder, &local.stack, &next.decoder);
        let mut builder = SharedBuilder::new().with_row_flags(false, false, true);
        enforce_main(&mut builder, local, next, &op_flags);
        builder.evaluations
    }

    /// Builds an END row carrying the given caller-frame restoration flag, with a non-root context
    /// and digest, plus the following row.
    fn end_rows(restores_caller_frame: Felt) -> (CoreCols<Felt>, CoreCols<Felt>) {
        let mut local = generate_test_row(opcodes::END.into());
        local.decoder.hasher_state[6] = restores_caller_frame;
        local.system.ctx = Felt::new_unchecked(7);
        local.system.fn_hash = [Felt::new_unchecked(11); 4];

        let mut next = generate_test_row(0);
        next.system.clk = local.system.clk + Felt::ONE;
        next.system.ctx = local.system.ctx;
        next.system.fn_hash = local.system.fn_hash;
        (local, next)
    }

    #[test]
    fn continuation_end_preserves_context_and_fn_hash() {
        let (local, next) = end_rows(Felt::ZERO);
        assert!(
            eval_system(&local, &next).iter().all(|v| *v == QuadFelt::ZERO),
            "an ordinary END that preserves ctx/fn_hash must be accepted"
        );

        // Changing either column across an ordinary END must be caught.
        let mut changed_ctx = next.clone();
        changed_ctx.system.ctx += Felt::ONE;
        assert!(
            eval_system(&local, &changed_ctx).iter().any(|v| *v != QuadFelt::ZERO),
            "an ordinary END must not be able to change ctx"
        );

        let mut changed_hash = next;
        changed_hash.system.fn_hash[0] += Felt::ONE;
        assert!(
            eval_system(&local, &changed_hash).iter().any(|v| *v != QuadFelt::ZERO),
            "an ordinary END must not be able to change fn_hash"
        );
    }

    #[test]
    fn caller_frame_end_permits_restoration() {
        let (local, next) = end_rows(Felt::ONE);

        let mut restored = next;
        restored.system.ctx = Felt::ZERO;
        restored.system.fn_hash = [Felt::ZERO; 4];

        assert!(
            eval_system(&local, &restored).iter().all(|v| *v == QuadFelt::ZERO),
            "a caller-frame END must permit ctx/fn_hash to be restored to the caller's values"
        );
    }
}
