//! Multi-AIR proving for the chiplet stack.
//!
//! [`ChipletAir`] wraps the fifteen heterogeneous AIRs into one enum (the
//! `MultiAir::Air` type); [`ChipletMultiAir`] owns them and closes the
//! cross-chiplet LogUp identity — `Σ σ = 0` — in
//! [`MultiAir::eval_external`].
//! [`SessionTraces::prove_stark`] produces a core-compatible serialized
//! [`StarkProof`](miden_core::proof::StarkProof), while [`SessionTraces::prove`]
//! returns the core deferred-proof envelope used by VM proof composition.

use alloc::{vec, vec::Vec};

use miden_core::{
    Felt,
    deferred::DeferredRoot,
    field::{Field, PrimeCharacteristicRing, QuadFelt},
    proof::{DeferredProof, HashFunction, StarkProof},
    utils::RowMajorMatrix,
};
use miden_lifted_air::{
    BaseAir, LiftedAir, LiftedAirBuilder, MultiAir, ProverStatement, ReductionError, Statement,
};
use miden_lifted_stark::{
    Preprocessed, PreprocessedValidationError, ProverInstance, StarkConfig, VerifierError,
    VerifierInstance, check_constraints,
    lmcs::Lmcs as LmcsTrait,
    proof::{StarkOutput, StarkProofData},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_wincode::SerdeCompat;

const MAX_STARK_PROOF_BYTES: usize = 64 * 1024 * 1024;

use crate::{
    ProveError,
    ec::{EcPointStoreAir, add::EcGroupAddAir, groups::EcGroupsAir, msm::EcMsmAir},
    hash::{
        chunk::ChunkAir,
        keccak::{node::KeccakNodeAir, round::KeccakRoundAir, sponge::KeccakSpongeAir},
    },
    logup::{Challenges, LookupMessage, lookup_challenges_from_slice, sigma_sum},
    primitives::{bitwise64::Bitwise64Air, byte_pair_lut::BytePairLutAir},
    session::{NUM_CHIPLETS, SessionTraces, fixed_ecgroup_msgs, fixed_uintval_msgs},
    stark_config::{
        DEFAULT_HASH_FUNCTION, PRECOMPILE_RELATION_DIGEST, blake3_256_config, keccak_config,
        observe_protocol_params, pcs_params, poseidon2_config, rpo_config, rpx_config,
        test_challenger,
    },
    transcript::{
        eval::TranscriptEvalAir,
        poseidon2::{P2Digest, Poseidon2Air},
    },
    uint::{UintStoreAir, add::UintAddAir, mul::UintMulAir},
};

/// The fifteen chiplet AIRs wrapped into one enum — the heterogeneous
/// `MultiAir::Air` type. Variant order is the canonical
/// [`SessionTraces::mains`] order.
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

fn eval_lifted<A, AB>(air: &A, builder: &mut AB)
where
    A: LiftedAir<Felt, QuadFelt>,
    AB: LiftedAirBuilder<F = Felt>,
{
    <A as LiftedAir<Felt, QuadFelt>>::eval::<AB>(air, builder);
}

impl ChipletAir {
    /// The fifteen AIRs in canonical [`SessionTraces::mains`] order.
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
        match self {
            ChipletAir::Chunk => eval_lifted(&ChunkAir, builder),
            ChipletAir::Poseidon2 => eval_lifted(&Poseidon2Air, builder),
            ChipletAir::KeccakRound => eval_lifted(&KeccakRoundAir, builder),
            ChipletAir::Bitwise64 => eval_lifted(&Bitwise64Air, builder),
            ChipletAir::BytePairLut => eval_lifted(&BytePairLutAir, builder),
            ChipletAir::KeccakSponge => eval_lifted(&KeccakSpongeAir, builder),
            ChipletAir::KeccakNode => eval_lifted(&KeccakNodeAir, builder),
            ChipletAir::TranscriptEval => eval_lifted(&TranscriptEvalAir, builder),
            ChipletAir::UintStore => eval_lifted(&UintStoreAir, builder),
            ChipletAir::UintAdd => eval_lifted(&UintAddAir, builder),
            ChipletAir::UintMul => eval_lifted(&UintMulAir, builder),
            ChipletAir::EcGroups => eval_lifted(&EcGroupsAir, builder),
            ChipletAir::EcPointStore => eval_lifted(&EcPointStoreAir, builder),
            ChipletAir::EcGroupAdd => eval_lifted(&EcGroupAddAir, builder),
            ChipletAir::EcMsm => eval_lifted(&EcMsmAir, builder),
        }
    }
}

/// The chiplet stack as a [`MultiAir`]: owns the fifteen AIRs (in canonical
/// order) and closes the cross-chiplet LogUp identity — `Σ σ = 0` over
/// every AIR's committed residue — in [`eval_external`](Self::eval_external).
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

fn fixed_boundary_correction(challenges: &[QuadFelt]) -> Result<QuadFelt, ReductionError> {
    let lookup_challenges = lookup_challenges_from_slice(challenges);
    Ok(boundary_correction(
        &lookup_challenges,
        fixed_uintval_msgs(),
        "fixed UintVal boundary denominator was zero",
    )? + boundary_correction(
        &lookup_challenges,
        fixed_ecgroup_msgs(),
        "fixed EcGroup boundary denominator was zero",
    )?)
}

fn boundary_correction<M>(
    challenges: &Challenges<QuadFelt>,
    messages: impl IntoIterator<Item = M>,
    zero_denominator: &'static str,
) -> Result<QuadFelt, ReductionError>
where
    M: LookupMessage<Felt, QuadFelt>,
{
    let mut correction = QuadFelt::ZERO;
    for msg in messages {
        let Some(inv) = msg.encode(challenges).try_inverse() else {
            return Err(zero_denominator.into());
        };
        correction += inv;
    }
    Ok(correction)
}

impl MultiAir<Felt, QuadFelt> for ChipletMultiAir {
    type Air = ChipletAir;

    fn airs(&self) -> &[ChipletAir] {
        &self.airs
    }

    /// The cross-chiplet σ identity: the sum of every AIR's committed
    /// σ residue must vanish (a single assertion). `aux_values[i]` is AIR
    /// `i`'s exposed permutation values — exactly one, its σ.
    fn eval_external(
        &self,
        challenges: &[QuadFelt],
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        aux_values: &[&[QuadFelt]],
        _log_trace_heights: &[u8],
    ) -> Result<Vec<QuadFelt>, ReductionError> {
        Ok(vec![sigma_sum(aux_values) + fixed_boundary_correction(challenges)?])
    }
}

impl SessionTraces {
    /// Build the [`ProverStatement`]: the [`ChipletMultiAir`] + the shared
    /// `air_inputs` (the transcript root) + the fifteen main traces in
    /// canonical [`mains`](Self::mains) order.
    fn prover_statement(&self) -> ProverStatement<Felt, QuadFelt, ChipletMultiAir> {
        let statement = Statement::new(ChipletMultiAir::new(), self.air_inputs(), Vec::new())
            .expect("chiplet statement inputs are valid");
        let mains: Vec<RowMajorMatrix<Felt>> = self.mains().into_iter().cloned().collect();
        ProverStatement::new(statement, mains).expect("chiplet trace shapes are valid")
    }

    /// Per-AIR `check_constraints` under the legacy fast test config — a cheap
    /// local-constraint sanity pass (catches AIR regressions before the more
    /// opaque `prove` failure; no cross-chiplet bus balance, which only the
    /// full prove/verify closes via `eval_external`).
    pub fn check(&self) {
        check_constraints(&self.prover_statement(), test_challenger());
    }

    /// Prove the precompile session with the default production-style hash function,
    /// returning a STARK-backed deferred proof for the session's exact deferred root.
    pub fn prove(&self) -> DeferredProof {
        self.prove_deferred(DEFAULT_HASH_FUNCTION)
            .expect("prove precompile session with default hash function")
    }

    /// Prove the whole stack and return a core-compatible serialized STARK
    /// proof envelope using the requested hash function.
    ///
    /// The proof bytes are the `serde_wincode` serialization of
    /// `StarkProofData<Felt, QuadFelt, SC>` with `wincode`'s default
    /// configuration, matching the VM prover's proof-byte surface.
    #[tracing::instrument("prove_stark", skip_all)]
    pub fn prove_stark(&self, hash_fn: HashFunction) -> Result<StarkProof, ProveError> {
        let params = pcs_params();
        match hash_fn {
            HashFunction::Blake3_256 => {
                let config = blake3_256_config(params, PRECOMPILE_RELATION_DIGEST);
                self.prove_stark_with_config(&config, hash_fn)
            },
            HashFunction::Rpo256 => {
                let config = rpo_config(params, PRECOMPILE_RELATION_DIGEST);
                self.prove_stark_with_config(&config, hash_fn)
            },
            HashFunction::Rpx256 => {
                let config = rpx_config(params, PRECOMPILE_RELATION_DIGEST);
                self.prove_stark_with_config(&config, hash_fn)
            },
            HashFunction::Poseidon2 => {
                let config = poseidon2_config(params, PRECOMPILE_RELATION_DIGEST);
                self.prove_stark_with_config(&config, hash_fn)
            },
            HashFunction::Keccak => {
                let config = keccak_config(params, PRECOMPILE_RELATION_DIGEST);
                self.prove_stark_with_config(&config, hash_fn)
            },
        }
    }

    /// Prove the precompile session and wrap the serialized STARK proof in the core
    /// deferred-proof envelope together with the exact deferred root it proves.
    pub fn prove_deferred(&self, hash_fn: HashFunction) -> Result<DeferredProof, ProveError> {
        let proof = self.prove_stark(hash_fn)?;
        let public_root: DeferredRoot = self.public_root().as_array().into();
        Ok(DeferredProof::stark(proof, public_root))
    }

    fn prove_stark_with_config<SC>(
        &self,
        config: &SC,
        hash_fn: HashFunction,
    ) -> Result<StarkProof, ProveError>
    where
        SC: StarkConfig<Felt, QuadFelt>,
        <SC::Lmcs as LmcsTrait>::Commitment: Serialize,
    {
        let prover_statement = self.prover_statement();

        // BytePairLut declares preprocessed columns (its fixed `(a,b,c)`
        // table), so this must be `Some`; built deterministically from the AIR
        // list and borrowed by the prover instance.
        let preprocessed = {
            let _span = tracing::info_span!("build_preprocessed_trace").entered();
            Preprocessed::build(prover_statement.statement(), config)
                .ok_or(ProveError::MissingPreprocessed)?
        };

        let mut challenger = config.challenger();
        observe_protocol_params(&mut challenger);

        let output: StarkOutput<Felt, QuadFelt, SC> =
            ProverInstance::new(config, &prover_statement, Some(&preprocessed))?
                .prove(challenger)?;

        let proof_encoding_config = wincode::config::Configuration::default();
        let proof_bytes = <SerdeCompat<StarkProofData<Felt, QuadFelt, SC>> as wincode::config::Serialize<
            _,
        >>::serialize(&output.proof, proof_encoding_config)?;
        Ok(StarkProof::new(proof_bytes, hash_fn))
    }
}

/// Verify a STARK-backed deferred proof produced by [`SessionTraces::prove`] or
/// [`SessionTraces::prove_deferred`] and return the verified deferred root.
///
/// The proof must be a [`DeferredProof::Stark`] variant. Its `public_root` is used as the
/// precompile STARK public input; only after that proof verifies is the root returned to callers.
pub fn verify_deferred(proof: &DeferredProof) -> Result<DeferredRoot, VerifyError> {
    match proof {
        DeferredProof::Stark { proof, public_root } => {
            verify_stark(proof, P2Digest::from(*public_root))?;
            Ok(*public_root)
        },
        DeferredProof::Empty | DeferredProof::Wire(_) => Err(VerifyError::InvalidDeferredProof),
    }
}

/// Verify a core serialized STARK proof envelope against a public root.
///
/// `Ok(())` iff the verifier accepts, including the `Σ σ = 0`
/// cross-chiplet identity via `eval_external`.
pub fn verify_stark(proof: &StarkProof, public_root: P2Digest) -> Result<(), VerifyError> {
    let params = pcs_params();
    match proof.hash_fn() {
        HashFunction::Blake3_256 => {
            let config = blake3_256_config(params, PRECOMPILE_RELATION_DIGEST);
            verify_stark_with_config(&config, proof.bytes(), public_root)
        },
        HashFunction::Rpo256 => {
            let config = rpo_config(params, PRECOMPILE_RELATION_DIGEST);
            verify_stark_with_config(&config, proof.bytes(), public_root)
        },
        HashFunction::Rpx256 => {
            let config = rpx_config(params, PRECOMPILE_RELATION_DIGEST);
            verify_stark_with_config(&config, proof.bytes(), public_root)
        },
        HashFunction::Poseidon2 => {
            let config = poseidon2_config(params, PRECOMPILE_RELATION_DIGEST);
            verify_stark_with_config(&config, proof.bytes(), public_root)
        },
        HashFunction::Keccak => {
            let config = keccak_config(params, PRECOMPILE_RELATION_DIGEST);
            verify_stark_with_config(&config, proof.bytes(), public_root)
        },
    }
}

fn verify_stark_with_config<SC>(
    config: &SC,
    proof_bytes: &[u8],
    public_root: P2Digest,
) -> Result<(), VerifyError>
where
    SC: StarkConfig<Felt, QuadFelt>,
    <SC::Lmcs as LmcsTrait>::Commitment: DeserializeOwned,
{
    if proof_bytes.len() > MAX_STARK_PROOF_BYTES {
        return Err(VerifyError::ProofTooLarge {
            size: proof_bytes.len(),
            max: MAX_STARK_PROOF_BYTES,
        });
    }

    let proof_encoding_config = wincode::config::Configuration::default()
        .with_preallocation_size_limit::<MAX_STARK_PROOF_BYTES>();
    let proof: StarkProofData<Felt, QuadFelt, SC> = <SerdeCompat<
        StarkProofData<Felt, QuadFelt, SC>,
    > as wincode::config::Deserialize<_>>::deserialize(
        proof_bytes, proof_encoding_config
    )?;

    let statement =
        Statement::new(ChipletMultiAir::new(), public_root.as_array().to_vec(), Vec::new())
            .expect("chiplet statement inputs are valid");

    // Rebuild the preprocessed bundle (fixed circuit data, deterministic from
    // the AIR list) to recover its commitment — the verifier trusts it like the
    // AIR list itself.
    let preprocessed =
        Preprocessed::build(&statement, config).ok_or(VerifyError::MissingPreprocessed)?;

    let mut challenger = config.challenger();
    observe_protocol_params(&mut challenger);

    VerifierInstance::new(config, &statement, Some(preprocessed.commitment()))?
        .verify(&proof, challenger)?;
    Ok(())
}

/// Why precompile STARK verification rejected a proof.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The chiplet stack declares preprocessed columns, but no preprocessed
    /// bundle was produced. This should not happen for the full session AIR set.
    #[error("chiplet stack declares preprocessed columns, but no preprocessed bundle was built")]
    MissingPreprocessed,
    /// The serialized STARK proof bytes could not be decoded for the selected
    /// hash-function config.
    #[error("failed to deserialize STARK proof: {0}")]
    Deserialization(#[from] wincode::error::ReadError),
    /// The serialized STARK proof exceeds the verifier's byte-size limit.
    #[error("STARK proof is too large: {size} bytes exceeds the {max} byte limit")]
    ProofTooLarge { size: usize, max: usize },
    /// The preprocessed commitment did not match the declared AIR columns/config.
    #[error(transparent)]
    Preprocessed(#[from] PreprocessedValidationError),
    /// The verifier rejected the proof (e.g. the cross-chiplet `Σ σ = 0`
    /// identity didn't close).
    #[error(transparent)]
    Verifier(#[from] VerifierError),
    /// The deferred proof variant is not STARK-backed.
    #[error("deferred proof is not STARK-backed")]
    InvalidDeferredProof,
}
