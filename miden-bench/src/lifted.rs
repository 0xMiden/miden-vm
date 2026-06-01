//! Lifted STARK AIR enum and prove/verify runner.

use std::fmt;

use miden_lifted_stark::{
    StarkConfig,
    air::{BaseAir, LiftedAir, LiftedAirBuilder, MultiAir, ProverStatement, Statement},
    prove,
    testing::airs::{
        blake3::LiftedBlake3Air, keccak::LiftedKeccakAir, miden::DummyMidenAir,
        poseidon2::LiftedPoseidon2Air,
    },
    verify,
};
use p3_field::Field;
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

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        _challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        // All-zero aux trace of the AIR's declared width.
        let aux_width = LiftedAir::<Felt, EF>::aux_width(self);
        let num_aux_values = LiftedAir::<Felt, EF>::num_aux_values(self);
        let aux = RowMajorMatrix::new(EF::zero_vec(main.height() * aux_width), aux_width);
        (aux, EF::zero_vec(num_aux_values))
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
// MultiAir: empty public inputs; each AIR builds its own all-zero aux trace.
// ═══════════════════════════════════════════════════════════════════════════════

struct BenchMultiAir {
    airs: Vec<LiftedBenchAir>,
}

impl MultiAir<Felt, QuadFelt> for BenchMultiAir {
    type Air = LiftedBenchAir;

    fn airs(&self) -> &[Self::Air] {
        &self.airs
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Runner
// ═══════════════════════════════════════════════════════════════════════════════

pub(crate) fn run_lifted<SC>(
    config: &SC,
    specs: &[TraceSpec],
    traces: Vec<RowMajorMatrix<Felt>>,
    constants: &Option<GlRoundConstants>,
    cli: &Cli,
) -> RunResult
where
    SC: StarkConfig<Felt, QuadFelt>,
    miden_lifted_stark::proof::StarkDigest<Felt, QuadFelt, SC>: PartialEq + fmt::Debug,
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

    let statement =
        Statement::new(BenchMultiAir { airs }, Vec::new(), Vec::new()).expect("statement");
    let prover_statement = ProverStatement::new(statement, traces).expect("prover statement");

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
