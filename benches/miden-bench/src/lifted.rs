//! Lifted STARK prove/verify runner for the dummy Miden workload.

use std::fmt;

use miden_stark::{
    ProverInstance, StarkConfig, VerifierInstance,
    air::{MultiAir, ProverStatement, Statement},
    testing::airs::miden::DummyMidenAir,
};
use p3_field::{ExtensionField, PrimeField64, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use tracing::info_span;

use crate::{
    RunResult,
    cli::{Cli, TraceSpec},
};

// ═══════════════════════════════════════════════════════════════════════════════
// MultiAir: empty public inputs; each AIR builds its own all-zero aux trace.
// ═══════════════════════════════════════════════════════════════════════════════

struct BenchMultiAir<F> {
    airs: Vec<DummyMidenAir<F>>,
}

impl<F: PrimeField64, EF: ExtensionField<F>> MultiAir<F, EF> for BenchMultiAir<F> {
    type Air = DummyMidenAir<F>;

    fn airs(&self) -> &[Self::Air] {
        &self.airs
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Runner
// ═══════════════════════════════════════════════════════════════════════════════

pub(crate) fn run_lifted<F: PrimeField64 + TwoAdicField, EF: ExtensionField<F>, SC>(
    config: &SC,
    specs: &[TraceSpec],
    traces: Vec<RowMajorMatrix<F>>,
    cli: &Cli,
) -> RunResult
where
    SC: StarkConfig<F, EF>,
    miden_stark::proof::StarkDigest<F, EF, SC>: PartialEq + fmt::Debug,
{
    let airs = specs
        .iter()
        .map(|spec| DummyMidenAir::<F>::new(spec.width, spec.num_aux_cols))
        .collect();

    let statement =
        Statement::new(BenchMultiAir::<F> { airs }, Vec::new(), Vec::new()).expect("statement");
    let prover_statement = ProverStatement::new(statement, traces).expect("prover statement");
    let prover_instance =
        ProverInstance::new(config, prover_statement, None).expect("no preprocessed columns");

    let (output, statement) = info_span!("prove")
        .in_scope(|| prover_instance.prove(config.challenger()).expect("proving failed"));

    let result = RunResult {
        proof_size_bytes: output.proof.size_in_bytes(),
        field_elems: output.proof.num_field_elements(),
        commitments: output.proof.num_commitments(),
    };

    if !cli.no_verify {
        info_span!("verify").in_scope(|| {
            let digest = VerifierInstance::new(config, &statement, None)
                .expect("no preprocessed columns")
                .verify(&output.proof, config.challenger())
                .expect("verification failed");
            assert_eq!(output.digest, digest);
        });
    }

    result
}
