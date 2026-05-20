//! Lifted STARK AIR enum and prove/verify runner.

use std::fmt;

use miden_lifted_stark::{
    MultiAir, ProverStatement, StarkConfig, Statement,
    air::{BaseAir, LiftedAir, LiftedAirBuilder},
    prove,
    testing::airs::{
        blake3::LiftedBlake3Air, keccak::LiftedKeccakAir, miden::DummyMidenAir,
        poseidon2::LiftedPoseidon2Air,
    },
    verify,
};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use tracing::info_span;

use crate::{
    Felt, GlRoundConstants, QuadFelt, RunResult,
    cli::{AirType, Cli, TraceSpec},
};

// ═══════════════════════════════════════════════════════════════════════════════
// AIR enum
// ═══════════════════════════════════════════════════════════════════════════════

pub(crate) enum LiftedBenchAir {
    Keccak(LiftedKeccakAir),
    Poseidon2(Box<LiftedPoseidon2Air>),
    Blake3(LiftedBlake3Air),
    Miden(DummyMidenAir),
}

impl BaseAir<Felt> for LiftedBenchAir {
    fn width(&self) -> usize {
        match self {
            Self::Keccak(a) => BaseAir::<Felt>::width(a),
            Self::Poseidon2(a) => BaseAir::<Felt>::width(a.as_ref()),
            Self::Blake3(a) => BaseAir::<Felt>::width(a),
            Self::Miden(a) => BaseAir::<Felt>::width(a),
        }
    }
}

impl<EF: Field> LiftedAir<Felt, EF> for LiftedBenchAir {
    fn num_randomness(&self) -> usize {
        match self {
            Self::Miden(a) => LiftedAir::<Felt, EF>::num_randomness(a),
            _ => 1,
        }
    }

    fn aux_width(&self) -> usize {
        match self {
            Self::Miden(a) => LiftedAir::<Felt, EF>::aux_width(a),
            _ => 1,
        }
    }

    fn num_aux_values(&self) -> usize {
        match self {
            Self::Miden(a) => LiftedAir::<Felt, EF>::num_aux_values(a),
            _ => 0,
        }
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        match self {
            Self::Keccak(a) => LiftedAir::<Felt, EF>::eval(a, builder),
            Self::Poseidon2(a) => LiftedAir::<Felt, EF>::eval(a.as_ref(), builder),
            Self::Blake3(a) => LiftedAir::<Felt, EF>::eval(a, builder),
            Self::Miden(a) => LiftedAir::<Felt, EF>::eval(a, builder),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MultiAir: per-AIR all-zero aux trace, empty public inputs.
// ═══════════════════════════════════════════════════════════════════════════════

struct BenchMa {
    /// `(num_aux_cols, num_aux_values)` per AIR.
    aux_shape: Vec<(usize, usize)>,
}

impl MultiAir<Felt, QuadFelt> for BenchMa {
    type Air = LiftedBenchAir;

    fn build_aux_traces(
        &self,
        _airs: &[Self::Air],
        traces: &[&RowMajorMatrix<Felt>],
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        _challenges: &[QuadFelt],
    ) -> (Vec<RowMajorMatrix<QuadFelt>>, Vec<Vec<QuadFelt>>) {
        let mut traces_out = Vec::with_capacity(traces.len());
        let mut values_out = Vec::with_capacity(traces.len());
        for (i, &t) in traces.iter().enumerate() {
            let height = t.height();
            let (num_aux_cols, num_aux_values) = self.aux_shape[i];
            let values = QuadFelt::zero_vec(height * num_aux_cols);
            traces_out.push(RowMajorMatrix::new(values, num_aux_cols));
            values_out.push(vec![QuadFelt::ZERO; num_aux_values]);
        }
        (traces_out, values_out)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Runner
// ═══════════════════════════════════════════════════════════════════════════════

pub(crate) fn run_lifted<SC>(
    config: &SC,
    specs: &[TraceSpec],
    traces: &[RowMajorMatrix<Felt>],
    constants: &Option<GlRoundConstants>,
    cli: &Cli,
) -> RunResult
where
    SC: StarkConfig<Felt, QuadFelt>,
    miden_lifted_stark::StarkDigest<Felt, QuadFelt, SC>: PartialEq + fmt::Debug,
{
    let airs: Vec<LiftedBenchAir> = specs
        .iter()
        .map(|spec| match spec.air_type {
            AirType::Keccak => LiftedBenchAir::Keccak(LiftedKeccakAir),
            AirType::Poseidon2 => {
                let c = constants.as_ref().expect("poseidon2 constants required");
                LiftedBenchAir::Poseidon2(Box::new(LiftedPoseidon2Air::new(c.clone())))
            },
            AirType::Blake3 => LiftedBenchAir::Blake3(LiftedBlake3Air),
            AirType::Miden => {
                LiftedBenchAir::Miden(DummyMidenAir::new(spec.width, spec.num_aux_cols))
            },
        })
        .collect();

    let aux_shape: Vec<(usize, usize)> = specs
        .iter()
        .map(|spec| match spec.air_type {
            AirType::Miden => (spec.num_aux_cols, spec.num_aux_cols),
            _ => (1, 0),
        })
        .collect();

    let traces_owned: Vec<RowMajorMatrix<Felt>> = traces.to_vec();
    let statement =
        Statement::new(BenchMa { aux_shape }, airs, Vec::new(), Vec::new()).expect("statement");
    let prover_statement = ProverStatement::new(statement, traces_owned).expect("prover statement");

    let output = info_span!("prove").in_scope(|| {
        prove(config, &prover_statement, config.challenger()).expect("proving failed")
    });

    let result = RunResult {
        proof_size_bytes: output.proof.size_in_bytes(),
        field_elems: output.proof.num_field_elements(),
        commitments: output.proof.num_commitments(),
    };

    if !cli.no_verify {
        info_span!("verify").in_scope(|| {
            let digest =
                verify(config, prover_statement.statement(), &output.proof, config.challenger())
                    .expect("verification failed");
            assert_eq!(output.digest, digest);
        });
    }

    result
}
