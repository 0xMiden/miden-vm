//! Lifted STARK AIR enum and prove/verify runner.

use std::fmt;

use miden_lifted_stark::{
    ProverInstance, StarkConfig, VerifierInstance,
    air::{BaseAir, LiftedAir, LiftedAirBuilder, MultiAir, ProverStatement, Statement},
    testing::airs::{blake3::LiftedBlake3Air, keccak::LiftedKeccakAir, miden::DummyMidenAir},
};
use p3_field::{ExtensionField, Field, PrimeField64, TwoAdicField};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use tracing::info_span;

use crate::{
    RunResult,
    cli::{AirType, Cli, TraceSpec},
};

// ═══════════════════════════════════════════════════════════════════════════════
// AIR enum
// ═══════════════════════════════════════════════════════════════════════════════

pub(crate) enum LiftedBenchAir {
    Keccak(LiftedKeccakAir),
    Blake3(LiftedBlake3Air),
    Miden(DummyMidenAir),
}

impl<F> BaseAir<F> for LiftedBenchAir {
    fn width(&self) -> usize {
        match self {
            Self::Keccak(a) => BaseAir::<F>::width(a),
            Self::Blake3(a) => BaseAir::<F>::width(a),
            Self::Miden(a) => BaseAir::<F>::width(a),
        }
    }
}

impl<F: PrimeField64, EF: Field> LiftedAir<F, EF> for LiftedBenchAir {
    fn num_randomness(&self) -> usize {
        match self {
            Self::Miden(a) => LiftedAir::<F, EF>::num_randomness(a),
            _ => 1,
        }
    }

    fn aux_width(&self) -> usize {
        match self {
            Self::Miden(a) => LiftedAir::<F, EF>::aux_width(a),
            _ => 1,
        }
    }

    fn num_aux_values(&self) -> usize {
        match self {
            Self::Miden(a) => LiftedAir::<F, EF>::num_aux_values(a),
            _ => 0,
        }
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<F>,
        _air_inputs: &[F],
        _aux_inputs: &[F],
        _challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        // All-zero aux trace of the AIR's declared width.
        let aux_width = LiftedAir::<F, EF>::aux_width(self);
        let num_aux_values = LiftedAir::<F, EF>::num_aux_values(self);
        let aux = RowMajorMatrix::new(EF::zero_vec(main.height() * aux_width), aux_width);
        (aux, EF::zero_vec(num_aux_values))
    }

    fn eval<AB: LiftedAirBuilder<F = F>>(&self, builder: &mut AB) {
        match self {
            Self::Keccak(a) => LiftedAir::<F, EF>::eval(a, builder),
            Self::Blake3(a) => LiftedAir::<F, EF>::eval(a, builder),
            Self::Miden(a) => LiftedAir::<F, EF>::eval(a, builder),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MultiAir: empty public inputs; each AIR builds its own all-zero aux trace.
// ═══════════════════════════════════════════════════════════════════════════════

struct BenchMultiAir {
    airs: Vec<LiftedBenchAir>,
}

impl<F: PrimeField64, EF: ExtensionField<F>> MultiAir<F, EF> for BenchMultiAir {
    type Air = LiftedBenchAir;

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
    miden_lifted_stark::proof::StarkDigest<F, EF, SC>: PartialEq + fmt::Debug,
{
    let airs: Vec<LiftedBenchAir> = specs
        .iter()
        .map(|spec| match spec.air_type {
            AirType::Keccak => LiftedBenchAir::Keccak(LiftedKeccakAir),
            AirType::Blake3 => LiftedBenchAir::Blake3(LiftedBlake3Air),
            AirType::Miden => {
                LiftedBenchAir::Miden(DummyMidenAir::new(spec.width, spec.num_aux_cols))
            },
        })
        .collect();

    let statement =
        Statement::new(BenchMultiAir { airs }, Vec::new(), Vec::new()).expect("statement");
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
