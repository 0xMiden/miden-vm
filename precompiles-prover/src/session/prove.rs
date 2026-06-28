//! Multi-AIR proving for the precompile prover chiplet stack.

use miden_core::{Felt, field::QuadFelt};
use miden_lifted_air::{
    BaseAir, LiftedAir, LiftedAirBuilder, MultiAir, ProverStatement, ReductionError, Statement,
};
use miden_lifted_stark::{
    Preprocessed, ProverInstance, VerifierError, VerifierInstance, check_constraints,
};
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    ec::{EcPointStoreAir, add::EcGroupAddAir, groups::EcGroupsAir, msm::EcMsmAir},
    hash::{
        chunk::ChunkAir,
        keccak::{node::KeccakNodeAir, round::KeccakRoundAir, sponge::KeccakSpongeAir},
    },
    logup::sigma_sum,
    primitives::{bitwise64::Bitwise64Air, byte_pair_lut::BytePairLutAir},
    session::{NUM_CHIPLETS, SessionTraces},
    stark_config::{TestDigest, TestProof, test_challenger, test_config},
    transcript::{
        eval::TranscriptEvalAir,
        poseidon2::{P2Digest, Poseidon2Air},
    },
    uint::{UintStoreAir, add::UintAddAir, mul::UintMulAir},
};

#[derive(Clone, Debug)]
pub enum ChipletAir {
    Chunk,
    Poseidon2,
    KeccakRound,
    Bitwise64,
    BytePairLut,
    KeccakSponge,
    KeccakNode,
    TranscriptEval,
    UintStore,
    UintAdd,
    UintMul,
    EcGroups,
    EcPointStore,
    EcGroupAdd,
    EcMsm,
}

macro_rules! delegate {
    ($self:ident, $method:ident $(, $arg:expr)*) => {
        match $self {
            ChipletAir::Chunk => ChunkAir.$method($($arg),*),
            ChipletAir::Poseidon2 => Poseidon2Air.$method($($arg),*),
            ChipletAir::KeccakRound => KeccakRoundAir.$method($($arg),*),
            ChipletAir::Bitwise64 => Bitwise64Air.$method($($arg),*),
            ChipletAir::BytePairLut => BytePairLutAir.$method($($arg),*),
            ChipletAir::KeccakSponge => KeccakSpongeAir.$method($($arg),*),
            ChipletAir::KeccakNode => KeccakNodeAir.$method($($arg),*),
            ChipletAir::TranscriptEval => TranscriptEvalAir.$method($($arg),*),
            ChipletAir::UintStore => UintStoreAir.$method($($arg),*),
            ChipletAir::UintAdd => UintAddAir.$method($($arg),*),
            ChipletAir::UintMul => UintMulAir.$method($($arg),*),
            ChipletAir::EcGroups => EcGroupsAir.$method($($arg),*),
            ChipletAir::EcPointStore => EcPointStoreAir.$method($($arg),*),
            ChipletAir::EcGroupAdd => EcGroupAddAir.$method($($arg),*),
            ChipletAir::EcMsm => EcMsmAir.$method($($arg),*),
        }
    };
}

impl ChipletAir {
    pub fn all() -> [ChipletAir; NUM_CHIPLETS] {
        [
            ChipletAir::Chunk,
            ChipletAir::Poseidon2,
            ChipletAir::KeccakRound,
            ChipletAir::Bitwise64,
            ChipletAir::BytePairLut,
            ChipletAir::KeccakSponge,
            ChipletAir::KeccakNode,
            ChipletAir::TranscriptEval,
            ChipletAir::UintStore,
            ChipletAir::UintAdd,
            ChipletAir::UintMul,
            ChipletAir::EcGroups,
            ChipletAir::EcPointStore,
            ChipletAir::EcGroupAdd,
            ChipletAir::EcMsm,
        ]
    }
}

impl BaseAir<Felt> for ChipletAir {
    fn width(&self) -> usize {
        delegate!(self, width)
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        delegate!(self, preprocessed_trace)
    }

    fn preprocessed_width(&self) -> usize {
        delegate!(self, preprocessed_width)
    }

    fn num_public_values(&self) -> usize {
        delegate!(self, num_public_values)
    }

    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        delegate!(self, periodic_columns)
    }
}

impl LiftedAir<Felt, QuadFelt> for ChipletAir {
    fn num_randomness(&self) -> usize {
        delegate!(self, num_randomness)
    }

    fn aux_width(&self) -> usize {
        delegate!(self, aux_width)
    }

    fn num_aux_values(&self) -> usize {
        delegate!(self, num_aux_values)
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        delegate!(self, build_aux_trace, main, air_inputs, aux_inputs, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        delegate!(self, eval, builder);
    }
}

#[derive(Debug, Clone)]
pub struct ChipletMultiAir {
    airs: Vec<ChipletAir>,
}

impl ChipletMultiAir {
    pub fn new() -> Self {
        Self { airs: ChipletAir::all().to_vec() }
    }
}

impl Default for ChipletMultiAir {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiAir<Felt, QuadFelt> for ChipletMultiAir {
    type Air = ChipletAir;

    fn airs(&self) -> &[ChipletAir] {
        &self.airs
    }

    fn eval_external(
        &self,
        _challenges: &[QuadFelt],
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        aux_values: &[&[QuadFelt]],
        _log_trace_heights: &[u8],
    ) -> Result<Vec<QuadFelt>, ReductionError> {
        Ok(vec![sigma_sum(aux_values)])
    }
}

impl SessionTraces {
    fn prover_statement(&self) -> ProverStatement<Felt, QuadFelt, ChipletMultiAir> {
        let statement = Statement::new(ChipletMultiAir::new(), self.air_inputs(), Vec::new())
            .expect("chiplet statement inputs are valid");
        let mains: Vec<RowMajorMatrix<Felt>> = self.mains().into_iter().cloned().collect();
        ProverStatement::new(statement, mains).expect("chiplet trace shapes are valid")
    }

    pub fn check(&self) {
        check_constraints(&self.prover_statement(), test_challenger());
    }

    pub fn prove(&self) -> SessionProof {
        let prover_statement = self.prover_statement();
        let config = test_config();
        let preprocessed = Preprocessed::build(prover_statement.statement(), &config);
        let output = ProverInstance::new(&config, &prover_statement, preprocessed.as_ref())
            .expect("preprocessed bundle matches the declared columns")
            .prove(test_challenger())
            .expect("prove");
        SessionProof {
            proof: output.proof,
            prover_digest: output.digest,
            public_root: self.public_root(),
        }
    }
}

pub struct SessionProof {
    proof: TestProof,
    prover_digest: TestDigest,
    public_root: P2Digest,
}

impl SessionProof {
    pub fn public_root(&self) -> P2Digest {
        self.public_root
    }

    pub fn verify(&self) -> Result<(), VerifyError> {
        let statement = Statement::new(
            ChipletMultiAir::new(),
            self.public_root.as_array().to_vec(),
            Vec::new(),
        )
        .expect("chiplet statement inputs are valid");
        let config = test_config();
        let preprocessed = Preprocessed::build(&statement, &config);
        let verifier_digest = VerifierInstance::new(
            &config,
            &statement,
            preprocessed.as_ref().map(Preprocessed::commitment),
        )
        .expect("preprocessed commitment matches the declared columns")
        .verify(&self.proof, test_challenger())
        .map_err(VerifyError::Verifier)?;
        if verifier_digest != self.prover_digest {
            return Err(VerifyError::DigestMismatch);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum VerifyError {
    Verifier(VerifierError),
    DigestMismatch,
}
