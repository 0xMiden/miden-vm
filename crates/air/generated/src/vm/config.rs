//! Protocol configuration and the pinned identity of the VM relation.
//!
//! The shared configuration factories live in [`miden_stark::config`]. This module selects the
//! VM parameters and transcript domain and keeps the accepted relation and setup identities.

use miden_core::{Felt, program::domain::STARK_TRANSCRIPT};
pub use miden_stark::config::{
    Blake3Config, EidosConfig, EidosLmcs, KeccakConfig, MidenStarkConfig, RelationDigest,
    blake3_256_config, keccak_config, observe_protocol_params, relation_digest,
};
use miden_stark::pcs::PcsParams;

// PCS PARAMETERS
// ================================================================================================

/// Base-two logarithm of the low-degree extension blowup used by canonical VM proofs.
pub const LOG_BLOWUP: u8 = 3;
/// Log2 of the FRI folding arity (arity = 4).
pub const LOG_FOLDING_ARITY: u8 = 2;
/// Log2 of the final polynomial degree (degree = 128).
const LOG_FINAL_DEGREE: u8 = 7;
/// Proof-of-work bits for FRI folding challenges.
pub const FOLDING_POW_BITS: usize = 4;
/// Proof-of-work bits for DEEP composition polynomial.
pub const DEEP_POW_BITS: usize = 12;
/// Number of FRI query repetitions.
const NUM_QUERIES: usize = 27;
/// Proof-of-work bits for the query phase. Together with 27 queries, this gives the query round
/// exactly 96 conjectured bits; lowering either value drops the preset below that target.
const QUERY_POW_BITS: usize = 17;

/// Default PCS parameters shared by all hash function configurations.
///
/// These are protocol constants. They must not depend on the process environment or benchmark
/// settings because the same factory is used by production provers and verifiers.
pub fn pcs_params() -> PcsParams {
    PcsParams::new(
        LOG_BLOWUP,
        LOG_FOLDING_ARITY,
        LOG_FINAL_DEGREE,
        FOLDING_POW_BITS,
        DEEP_POW_BITS,
        NUM_QUERIES,
        QUERY_POW_BITS,
    )
    .expect("invalid PCS parameters")
}

/// Version of the VM external multi-AIR statement semantics.
pub const PROTOCOL_ID: u64 = 1;

/// Default commitment alignment, in base-field elements.
pub const SPONGE_RATE: usize = miden_crypto::hash::eidos::BLOCK_LEN;
/// Number of base-field elements in a digest.
pub const DIGEST_WIDTH: usize = 4;

/// Creates an Eidos-based STARK configuration bound to the existing VM transcript domain.
pub fn eidos_config(params: PcsParams, relation_digest: RelationDigest) -> EidosConfig {
    miden_stark::config::eidos_config(params, relation_digest, STARK_TRANSCRIPT)
}

/// RELATION_DIGEST = Eidos::hash_elements([PROTOCOL_ID, ACE_CIRCUIT_DIGEST]).
///
/// Compile-time constant binding the Fiat-Shamir transcript to the Miden VM AIR. The generated
/// `sys::vm` wrapper embeds it, and the pinned VM verifier root covers that module.
pub const RELATION_DIGEST: RelationDigest = [
    Felt::new_unchecked(7856671528189646221),
    Felt::new_unchecked(2458781204466877327),
    Felt::new_unchecked(1097061327429211191),
    Felt::new_unchecked(3384814590852465759),
];

/// Eidos digest of the order-invariant recursive-verifier ACE circuit's instruction stream.
///
/// One circuit serves every proof order, so this digest names the accepted circuit outright: it
/// is the advice-map key the stream is served under and the value the MASM loader pins it to.
pub const ACE_CIRCUIT_DIGEST: [Felt; 4] = [
    Felt::new_unchecked(2192960401214109567),
    Felt::new_unchecked(8980372480879030342),
    Felt::new_unchecked(7824773558143124059),
    Felt::new_unchecked(7947412689729091791),
];

// Fixed And8 commitments for the three VM proof configurations, each built from the canonical VM
// setup under its configuration and [`RELATION_DIGEST`].
pub const BLAKE3_PREPROCESSED_COMMITMENT: [u8; 32] = [
    237, 165, 181, 150, 170, 183, 11, 117, 116, 34, 106, 27, 89, 68, 113, 212, 124, 97, 90, 201,
    199, 30, 220, 145, 185, 5, 104, 155, 67, 55, 138, 126,
];
pub const EIDOS_PREPROCESSED_COMMITMENT: [u64; 4] = [
    1070440981155119101,
    2022626773377316756,
    6941685244114430330,
    5172579525468662096,
];
pub const KECCAK_PREPROCESSED_COMMITMENT: [u64; 4] = [
    8953595915908445159,
    18286975921588085812,
    1662605580119539545,
    8308041584975270064,
];

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::{format, vec, vec::Vec};

    use miden_core::{Felt, field::QuadFelt};
    use miden_stark::{Preprocessed, StarkConfig, lmcs::Lmcs};

    use crate::vm::{MidenMultiAir, NUM_PUBLIC_VALUES, Statement, ace};

    const UPDATE_HINT: &str = "an intentional relation change must update the pinned constants \
                               in crates/air/generated/src/vm/config.rs and update \
                               CURRENT_VM_VERIFIER_ROOT in core/src/proof.rs";

    /// Every authored AIR must fit within the degree admitted by the production PCS policy.
    #[test]
    fn handwritten_degrees_fit_the_pcs_policy() {
        for air in miden_air_definitions::vm::AIRS {
            assert!(
                miden_stark::log_quotient_degree::<Felt, QuadFelt, _>(&air) <= super::LOG_BLOWUP
            );
            assert_eq!(
                miden_stark::air::LiftedAir::<Felt, QuadFelt>::aux_width(&air),
                air.column_shape().len()
            );
        }
    }

    /// Snapshot test: catches any AIR change that alters the constraint circuit.
    #[test]
    fn relation_digest_matches_current_air() {
        let circuit =
            ace::build_recursive_verifier_ace_circuit().expect("recursive-verifier ACE circuit");
        let commitment: Vec<u64> = circuit.commitment.iter().map(Felt::as_canonical_u64).collect();

        let digest = super::relation_digest(super::PROTOCOL_ID, &circuit.commitment);
        let expected: Vec<u64> = digest.iter().map(Felt::as_canonical_u64).collect();

        let snapshot = format!(
            "num_inputs: {}\nnum_eval_gates: {}\nstream_len: {}\ncircuit_digest: {:?}\n\
             relation_digest: {:?}",
            circuit.num_inputs, circuit.num_eval_gates, circuit.stream_len, commitment, expected,
        );
        insta::assert_snapshot!(snapshot);

        let actual: Vec<u64> = super::RELATION_DIGEST.iter().map(Felt::as_canonical_u64).collect();
        assert_eq!(actual, expected, "RELATION_DIGEST is stale; {UPDATE_HINT}");
    }

    /// The pinned circuit digest must equal the commitment of the canonical circuit the recursive
    /// verifier evaluates: it binds the transcript to that circuit, so any drift between them
    /// would let a proof be verified against a circuit the protocol constant never committed to.
    #[test]
    fn ace_circuit_digest_matches_canonical_circuit() {
        let expected: Vec<u64> = ace::build_recursive_verifier_ace_circuit()
            .expect("recursive-verifier ACE circuit")
            .commitment
            .iter()
            .map(Felt::as_canonical_u64)
            .collect();
        let actual: Vec<u64> =
            super::ACE_CIRCUIT_DIGEST.iter().map(Felt::as_canonical_u64).collect();
        assert_eq!(actual, expected, "ACE_CIRCUIT_DIGEST is stale; {UPDATE_HINT}");
    }

    /// The And8 setup commitment the given configuration builds from the canonical VM setup.
    fn canonical_setup_commitment<SC: StarkConfig<Felt, QuadFelt>>(
        config: &SC,
    ) -> <SC::Lmcs as Lmcs>::Commitment {
        let statement = Statement::<Felt, QuadFelt, MidenMultiAir>::new(
            MidenMultiAir::new(),
            vec![(0, vec![Felt::ZERO; NUM_PUBLIC_VALUES])],
            vec![],
        )
        .expect("canonical VM statement");
        Preprocessed::build(&statement, config).expect("fixed And8 setup").commitment()
    }

    /// Each pinned And8 setup commitment must be the one its configuration builds from the
    /// canonical VM setup.
    macro_rules! setup_commitment_matches_canonical_setup {
        ($test:ident, $config:ident, $pinned:ident, $repr:ty) => {
            #[test]
            fn $test() {
                let config = super::$config(super::pcs_params(), super::RELATION_DIGEST);
                assert_eq!(
                    <$repr>::from(canonical_setup_commitment(&config)),
                    super::$pinned,
                    "{} is stale; {UPDATE_HINT}",
                    stringify!($pinned)
                );
            }
        };
    }

    setup_commitment_matches_canonical_setup!(
        blake3_setup_commitment_is_current,
        blake3_256_config,
        BLAKE3_PREPROCESSED_COMMITMENT,
        [u8; 32]
    );
    setup_commitment_matches_canonical_setup!(
        eidos_setup_commitment_is_current,
        eidos_config,
        EIDOS_PREPROCESSED_COMMITMENT,
        [u64; 4]
    );
    setup_commitment_matches_canonical_setup!(
        keccak_setup_commitment_is_current,
        keccak_config,
        KECCAK_PREPROCESSED_COMMITMENT,
        [u64; 4]
    );
}
