//! Lifted STARK AIR enum and prove/verify runner.

use std::fmt;

use miden_lifted_stark::{
    AirInstance, AirWitness, StarkConfig,
    air::{BaseAir, LiftedAir, LiftedAirBuilder},
    prove_multi,
    testing::airs::{
        ZeroAuxBuilder, blake3::LiftedBlake3Air, keccak::LiftedKeccakAir, miden::DummyMidenAir,
        poseidon2::LiftedPoseidon2Air,
    },
    verify_multi,
};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
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

    fn num_var_len_public_inputs(&self) -> usize {
        0
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

    let aux_builders: Vec<ZeroAuxBuilder> = specs
        .iter()
        .map(|spec| match spec.air_type {
            AirType::Miden => ZeroAuxBuilder {
                num_aux_cols: spec.num_aux_cols,
                num_aux_values: spec.num_aux_cols,
            },
            _ => ZeroAuxBuilder::dummy(),
        })
        .collect();

    let instances: Vec<_> = airs
        .iter()
        .zip(traces)
        .zip(&aux_builders)
        .map(|((air, trace), aux)| (air, AirWitness::new(trace, &[], &[]), aux))
        .collect();

    let output = info_span!("prove")
        .in_scope(|| prove_multi(config, &instances, config.challenger()).expect("proving failed"));

    let result = RunResult {
        proof_size_bytes: output.proof.size_in_bytes(),
        field_elems: output.proof.num_field_elements(),
        commitments: output.proof.num_commitments(),
    };

    if !cli.no_verify {
        info_span!("verify").in_scope(|| {
            let verifier_instances: Vec<_> = airs
                .iter()
                .map(|air| {
                    (
                        air,
                        AirInstance {
                            public_values: &[],
                            var_len_public_inputs: &[],
                        },
                    )
                })
                .collect();
            let digest =
                verify_multi(config, &verifier_instances, &output.proof, config.challenger())
                    .expect("verification failed");
            assert_eq!(output.digest, digest);
        });
    }

    result
}
