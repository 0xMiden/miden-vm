//! Protocol configuration and the pinned identity of the VM relation.
//!
//! The digests and commitments below name the relation that proofs are bound to. They are pinned
//! so that any change to the AIRs or the ACE circuit surfaces as a failing test; the tests in this
//! module recompute every value from the AIR definitions.

pub use miden_air_definitions::shared::config::{
    Blake3Config, DEEP_POW_BITS, DIGEST_WIDTH, EidosConfig, EidosLmcs, FOLDING_POW_BITS,
    KeccakConfig, LOG_BLOWUP, LOG_FOLDING_ARITY, MidenStarkConfig, PROTOCOL_ID, RelationDigest,
    SPONGE_RATE, blake3_256_config, eidos_config, keccak_config, observe_protocol_params,
    pcs_params, relation_digest,
};
use miden_core::Felt;

/// RELATION_DIGEST = Eidos::hash_elements([PROTOCOL_ID, ACE_CIRCUIT_DIGEST]).
///
/// Compile-time constant binding the Fiat-Shamir transcript to the Miden VM AIR. The generated
/// `sys::vm` wrapper embeds it, and the pinned VM verifier root covers that module.
pub const RELATION_DIGEST: RelationDigest = [
    Felt::new_unchecked(9098509505774412735),
    Felt::new_unchecked(4737936789760532215),
    Felt::new_unchecked(1438664865551243811),
    Felt::new_unchecked(7897993217034479822),
];

/// Eidos digest of the order-invariant recursive-verifier ACE circuit's instruction stream.
///
/// One circuit serves every proof order, so this digest names the accepted circuit outright: it
/// is the advice-map key the stream is served under and the value the MASM loader pins it to.
pub const ACE_CIRCUIT_DIGEST: [Felt; 4] = [
    Felt::new_unchecked(9122225125595333314),
    Felt::new_unchecked(4575736417990392984),
    Felt::new_unchecked(5414688566126692380),
    Felt::new_unchecked(7406482881221041553),
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

    use miden_air_definitions::ace::build_recursive_verifier_ace_circuit;
    use miden_core::{Felt, field::QuadFelt};
    use miden_lifted_air::Statement;
    use miden_lifted_stark::{Preprocessed, StarkConfig, lmcs::Lmcs, pcs::PcsParams};
    use p3_challenger::CanObserve;

    use crate::{MidenMultiAir, NUM_PUBLIC_VALUES};

    const UPDATE_HINT: &str = "an intentional relation change must update the pinned constants \
                               in air/src/config.rs and update \
                               CURRENT_VM_VERIFIER_ROOT in core/src/proof.rs";

    #[derive(Default)]
    struct RecordingChallenger(Vec<Felt>);

    impl CanObserve<Felt> for RecordingChallenger {
        fn observe(&mut self, value: Felt) {
            self.0.push(value);
        }
    }

    /// Transcript domain separation must bind the parameters actually supplied to the config,
    /// not the Miden VM's compile-time defaults.
    #[test]
    fn protocol_observation_uses_the_supplied_pcs_params() {
        let params = PcsParams::new(4, 3, 6, 5, 11, 19, 13).expect("valid distinct PCS params");
        let mut challenger = RecordingChallenger::default();
        super::observe_protocol_params(&params, &mut challenger);
        assert_eq!(
            challenger.0,
            [19, 13, 11, 5, 4, 6, 8, 0].map(Felt::new_unchecked),
            "the transcript must encode [queries, query PoW, DEEP PoW, folding PoW, blowup log, \
             final-degree log, folding arity, padding]",
        );
    }

    /// Snapshot test: catches any AIR change that alters the constraint circuit.
    #[test]
    fn relation_digest_matches_current_air() {
        let circuit =
            build_recursive_verifier_ace_circuit().expect("recursive-verifier ACE circuit");
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
        let expected: Vec<u64> = build_recursive_verifier_ace_circuit()
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
