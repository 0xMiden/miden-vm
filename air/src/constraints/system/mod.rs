//! System constraints module.
//!
//! This module contains constraints for the system component of the Miden VM,
//! which manages execution context and function hash system columns transitions.
//!
//! ## System Columns
//!
//! - `clk`: VM execution clock (clk[0] = 0, clk' = clk + 1)
//! - `ctx`: Execution context ID (determines memory context isolation)
//! - `fn_hash[0..4]`: Current function digest (identifies executing procedure)
//!
//! ## Context Transitions
//!
//! | Operation           | ctx'              | Description               |
//! |---------------------|-------------------|---------------------------|
//! | CALL or DYNCALL     | clk + 1           | Create new context        |
//! | SYSCALL             | 0                 | Return to kernel context  |
//! | END                 | (from block stack)| Restore previous context  |
//! | Other ops           | ctx               | Unchanged                 |
//!
//! ## Function Hash Transitions
//!
//! | Operation                          | fn_hash'           | Description                 |
//! |------------------------------------|--------------------|-----------------------------|
//! | CALL or DYNCALL                    | decoder_h[0..4]    | Load new procedure hash     |
//! | END                                | (from block stack) | Restore previous hash       |
//! | Other ops (incl. DYN, SYSCALL)     | fn_hash            | Unchanged                   |
//!
//! Note: END operation's restoration is handled by the block stack table (bus-based),
//! not by these constraints. These constraints only handle the non-END cases.

pub mod columns;

use miden_crypto::stark::air::AirBuilder;

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
    let f_end = op_flags.end();

    // Execution context transition constraints (see module doc for transition table)
    {
        let ctx = local.system.ctx;
        let ctx_next = next.system.ctx;
        let clk = local.system.clk;

        let call_dyncall_flag = f_call.clone() + f_dyncall.clone();
        let change_ctx_flag =
            f_call.clone() + f_syscall.clone() + f_dyncall.clone() + f_end.clone();
        let default_flag = change_ctx_flag.not();

        let builder = &mut builder.when_transition();
        builder.when(call_dyncall_flag).assert_eq(ctx_next, clk + F_1);
        builder.when(f_syscall).assert_zero(ctx_next);
        builder.when(default_flag).assert_eq(ctx_next, ctx);
    }

    // Function hash transition constraints (see module doc for transition table)
    {
        let f_load = f_call + f_dyncall;
        let f_preserve = (f_load.clone() + f_end).not();

        let builder = &mut builder.when_transition();

        {
            let builder = &mut builder.when(f_load);
            for i in 0..4 {
                builder.assert_eq(next.system.fn_hash[i], local.decoder.hasher_state[i]);
            }
        }

        {
            let builder = &mut builder.when(f_preserve);
            builder.assert_eq_arrays(next.system.fn_hash, local.system.fn_hash);
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_core::{
        Felt,
        field::{PrimeCharacteristicRing, QuadFelt},
    };
    use miden_crypto::stark::{
        air::{AirBuilder, ExtensionBuilder, PermutationAirBuilder, RowWindow},
        matrix::RowMajorMatrix,
    };

    use super::enforce_main;
    use crate::{
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
}
