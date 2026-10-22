//! Constraint diagnostics using the production VM evaluators.
use alloc::vec;

use miden_air::vm::{MidenMultiAir, config};
use miden_air_definitions::vm::VmTrace;
use miden_core::{Felt, field::QuadFelt};
use miden_stark::air::{ProverStatement, Statement};

/// Checks every constraint, panicking on the first violation with AIR and row diagnostics.
pub fn check_constraints(trace: &VmTrace) {
    let (core, chiplets, eidos, and8) = trace.clone_air_matrices();
    let (public_values, aux_inputs) = trace.public_inputs().to_air_inputs();
    let statement: Statement<Felt, QuadFelt, MidenMultiAir> =
        Statement::new(MidenMultiAir::new(), vec![(0, public_values)], aux_inputs)
            .expect("statement construction failed");
    let statement = ProverStatement::new(statement, vec![core, chiplets, eidos, and8])
        .expect("prover statement construction failed");
    use miden_stark::StarkConfig;
    let config = config::eidos_config(config::pcs_params(), config::RELATION_DIGEST);
    miden_stark::debug::check_constraints(&statement, config.challenger());
}
