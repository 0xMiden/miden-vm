//! Per-chiplet test modules.
//!
//! Tests live alongside the code they exercise but are split out of the
//! chiplet source files to keep the production code easier to scan.

mod deferred_state;
mod uint;
mod uint_add;
mod uint_dag;
mod uint_mul;

use miden_core::{Felt, field::QuadFelt};
use miden_lifted_air::{BaseAir, LiftedAir, MultiAir, ProverStatement, ReductionError, Statement};
use miden_lifted_stark::check_constraints;
use p3_matrix::dense::RowMajorMatrix;

use crate::stark_config::test_challenger;

/// A local-only [`MultiAir`] wrapper for per-chiplet constraint checks.
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

/// Check one AIR's local constraints on `main` with explicit shared public inputs.
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

/// Check one AIR's local constraints on `main` with dummy public inputs.
pub(crate) fn check_local<A>(air: A, main: &RowMajorMatrix<Felt>)
where
    A: LiftedAir<Felt, QuadFelt>,
{
    let n = air.num_public_values();
    check_local_inputs(air, main, vec![Felt::ZERO; n]);
}

/// The `[preprocessed ++ main]` matrix the lookup eval reads for a chiplet with preprocessed
/// columns.
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
