//! Production VM accepted pins and source-owned protocol preset reexports.
pub use miden_air_source::vm::config::*;
use miden_core::Felt;
/// RELATION_DIGEST = Eidos::hash_elements([PROTOCOL_ID, ACE_CIRCUIT_DIGEST]).
///
/// Compile-time constant binding the Fiat-Shamir transcript to the Miden VM AIR.
/// Must match the constants in `crates/lib/core/asm/sys/vm/mod.masm`.
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
///
/// Checked by `air-codegen`; changes require deliberate protocol review.
pub const ACE_CIRCUIT_DIGEST: [Felt; 4] = [
    Felt::new_unchecked(9122225125595333314),
    Felt::new_unchecked(4575736417990392984),
    Felt::new_unchecked(5414688566126692380),
    Felt::new_unchecked(7406482881221041553),
];

// Fixed And8 commitments for the six VM proof configurations.
// Accepted from the canonical VM setup; checked independently by `air-codegen --derive-setup`.
pub const BLAKE3_PREPROCESSED_COMMITMENT: [u8; 32] = [
    237, 165, 181, 150, 170, 183, 11, 117, 116, 34, 106, 27, 89, 68, 113, 212, 124, 97, 90, 201,
    199, 30, 220, 145, 185, 5, 104, 155, 67, 55, 138, 126,
];
pub const RPO_PREPROCESSED_COMMITMENT: [Felt; 4] = [
    Felt::new_unchecked(1822154764201048239),
    Felt::new_unchecked(10652700666966391447),
    Felt::new_unchecked(5380745592975976632),
    Felt::new_unchecked(9394895238760322928),
];
pub const RPX_PREPROCESSED_COMMITMENT: [Felt; 4] = [
    Felt::new_unchecked(7794497219439565839),
    Felt::new_unchecked(12108238022531853786),
    Felt::new_unchecked(3575474959316559657),
    Felt::new_unchecked(10734344851506324095),
];
pub const EIDOS_PREPROCESSED_COMMITMENT: [u64; 4] = [
    1070440981155119101,
    2022626773377316756,
    6941685244114430330,
    5172579525468662096,
];
pub const POSEIDON2_PREPROCESSED_COMMITMENT: [Felt; 4] = [
    Felt::new_unchecked(1918020177704289460),
    Felt::new_unchecked(13338901298221777084),
    Felt::new_unchecked(7643362476706389016),
    Felt::new_unchecked(12789699880434201102),
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
    use alloc::{format, vec::Vec};

    use miden_air_source::vm::ace;
    use miden_core::Felt;
    use miden_stark::{challenger::CanObserve, pcs::PcsParams};

    const PROTOCOL_ID: u64 = 1;
    const REGEN_HINT: &str = "make regenerate-constraints";

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
    ///
    /// If this test fails, review the accepted protocol pins before regenerating:
    /// ```text
    /// make regenerate-constraints
    /// ```
    #[test]
    fn relation_digest_matches_current_air() {
        let circuit = ace::build_recursive_verifier_ace_circuit();
        let commitment: Vec<u64> = circuit.commitment.iter().map(Felt::as_canonical_u64).collect();

        let digest = super::relation_digest(PROTOCOL_ID, &circuit.commitment);
        let expected: Vec<u64> = digest.iter().map(Felt::as_canonical_u64).collect();

        let snapshot = format!(
            "num_inputs: {}\nnum_eval_gates: {}\nstream_len: {}\ncircuit_digest: {:?}\n\
             relation_digest: {:?}",
            circuit.num_inputs, circuit.num_eval_gates, circuit.stream_len, commitment, expected,
        );
        insta::assert_snapshot!(snapshot);

        let actual: Vec<u64> = super::RELATION_DIGEST.iter().map(Felt::as_canonical_u64).collect();
        assert_eq!(
            actual, expected,
            "RELATION_DIGEST in config.rs is stale. Review accepted protocol pins before running: {REGEN_HINT}"
        );
    }

    /// The compiled-in circuit digest must equal the commitment of the canonical circuit the
    /// recursive verifier actually evaluates: it is what binds the transcript to that circuit,
    /// so any drift between them would let a proof be verified against a circuit the protocol
    /// constant never committed to.
    #[cfg(feature = "std")]
    #[test]
    fn ace_circuit_digest_matches_canonical_circuit() {
        let expected: Vec<u64> = ace::shared_recursive_circuit()
            .commitment
            .iter()
            .map(Felt::as_canonical_u64)
            .collect();
        let actual: Vec<u64> =
            super::ACE_CIRCUIT_DIGEST.iter().map(Felt::as_canonical_u64).collect();
        assert_eq!(
            actual, expected,
            "ACE_CIRCUIT_DIGEST in config.rs is stale. Review accepted protocol pins before running: {REGEN_HINT}"
        );
    }
}
