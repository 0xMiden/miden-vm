//! Per-chiplet test modules.
//!
//! Tests live alongside the code they exercise (one module per chiplet)
//! but are split out of the chiplet source files to keep the production
//! code easy to scan during audit.

mod aux_register;
mod binding;
mod bitwise64;
mod bootstrap;
mod bus_balance;
mod byte_pair_lut;
mod chunk;
mod deferred_state;
mod ec;
mod ec_add;
mod ec_dag;
mod ec_msm;
mod eval;
mod integration;
mod keccak;
mod keccak_node;
mod keccak_sponge;
mod poseidon2;
mod uint;
mod uint_add;
mod uint_dag;
mod uint_mul;
mod utils;
mod vm_uint;

use std::{vec, vec::Vec};

use miden_core::{Felt, field::QuadFelt, utils::RowMajorMatrix};
use miden_lifted_air::{BaseAir, LiftedAir, MultiAir, ProverStatement, ReductionError, Statement};
use miden_lifted_stark::check_constraints;

use crate::stark_config::test_challenger;

/// A local-only [`MultiAir`] wrapper for per-chiplet
/// [`check_constraints`]: its `eval_external` emits no cross-AIR
/// assertion, so a single AIR's *local* constraints are checked without
/// the stack-level Σσ=0 closure (per-AIR σ ≠ 0). Mirrors the pre-0.26
/// per-AIR `check_constraints`.
struct LocalAir<A>(Vec<A>);

impl<A> MultiAir<Felt, QuadFelt> for LocalAir<A>
where
    A: LiftedAir<Felt, QuadFelt>,
{
    type Air = A;

    fn airs(&self) -> &[A] {
        &self.0
    }

    fn eval_external(
        &self,
        _challenges: &[QuadFelt],
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        _aux_values: &[&[QuadFelt]],
        _log_trace_heights: &[u8],
    ) -> Result<Vec<QuadFelt>, ReductionError> {
        Ok(Vec::new())
    }
}

/// Check one AIR's local constraints on `main` with explicit shared public
/// inputs (the eval chip's transcript root; dummy for chiplets that ignore
/// them — see [`check_local`]).
pub(crate) fn check_local_inputs<A>(air: A, main: &RowMajorMatrix<Felt>, air_inputs: Vec<Felt>)
where
    A: LiftedAir<Felt, QuadFelt>,
{
    let statement = Statement::new(LocalAir(vec![air]), air_inputs, Vec::new())
        .expect("local check statement inputs are valid");
    let ps = ProverStatement::new(statement, vec![main.clone()])
        .expect("local check trace shape is valid");
    check_constraints(&ps, test_challenger());
}

/// Check one AIR's local constraints on `main` with dummy public inputs
/// (zeros, sized to the shared `num_public_values`) — fine for every
/// chiplet except the eval chip, which should use [`check_local_inputs`]
/// with its real root.
pub(crate) fn check_local<A>(air: A, main: &RowMajorMatrix<Felt>)
where
    A: LiftedAir<Felt, QuadFelt>,
{
    let n = air.num_public_values();
    check_local_inputs(air, main, vec![Felt::ZERO; n]);
}

/// The per-AIR `log_quotient_degree` — replicated from the public
/// `constraint_degree()` because 0.26 keeps the framework's own
/// `domain::log_quotient_degree` `pub(crate)`. This is the value the lqd
/// design-target smoke tests assert (= `⌈log₂ max(d−1, 1)⌉`, `d` the max
/// base/ext constraint-degree multiple).
pub(crate) fn log_quotient_degree<A>(air: &A) -> u8
where
    A: LiftedAir<Felt, QuadFelt>,
{
    let d = air.constraint_degree().max();
    miden_lifted_air::log2_ceil_u8(d.saturating_sub(1).max(1))
}

/// The `[preprocessed ++ main]` matrix the lookup eval reads for a chiplet
/// with preprocessed columns — mirrors `logup::CombinedWindow` (constraint
/// side) and BytePairLut's prover-side combine. Returns `None` for chiplets
/// without preprocessed columns, so balance-check helpers pass `main`
/// straight to the prover-side fraction builder.
pub(crate) fn combined_lookup_main<A>(
    air: &A,
    main: &RowMajorMatrix<Felt>,
) -> Option<RowMajorMatrix<Felt>>
where
    A: BaseAir<Felt>,
{
    let pre = air.preprocessed_trace()?;
    let (pre_w, main_w) = (pre.width, main.width);
    let height = main.values.len() / main_w;
    let mut values = Vec::with_capacity(height * (pre_w + main_w));
    for r in 0..height {
        values.extend_from_slice(&pre.values[r * pre_w..(r + 1) * pre_w]);
        values.extend_from_slice(&main.values[r * main_w..(r + 1) * main_w]);
    }
    Some(RowMajorMatrix::new(values, pre_w + main_w))
}
