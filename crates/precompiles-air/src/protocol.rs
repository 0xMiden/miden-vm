//! Pinned identity and build-compiled artifacts of every declared precompile relation member.
//!
//! The digests and commitments below name the relations that PVM proofs are bound to. They are
//! pinned per member so that any change to the chiplet AIRs or the ACE circuits surfaces as a
//! failing test; the tests in this module and in `miden-precompiles-verifier` recompute them from
//! the AIRs.

use miden_air::security::{AirShape, LookupShape};
use miden_core::{Felt, Word};

use crate::{ace::PvmRecursiveAceCircuit, relation::RelationSelection};

/// Pinned identity of one declared relation member (raw canonical u64 limbs).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelationPins {
    /// Selection mask of the member.
    pub selection_mask: u32,
    /// `Eidos(PROTOCOL_ID || ace_circuit_digest)`, binding the member's circuit into the
    /// Fiat-Shamir transcript.
    pub relation_digest: [u64; 4],
    /// Eidos digest of the member's order-invariant ACE instruction stream.
    pub ace_circuit_digest: [u64; 4],
    /// Commitment to the member's preprocessed (setup) trace tree under the Eidos config. A
    /// trusted verifier input, not proof data: an in-VM verifier cannot rebuild the bundle, so it
    /// observes this pinned value into the transcript.
    pub preprocessed_commitment: [u64; 4],
}

/// Pins of every declared relation member, one entry per [`RelationSelection::all`] member.
#[rustfmt::skip]
pub const RELATION_PINS: &[RelationPins] = &[
    RelationPins {
        selection_mask: 0,
        relation_digest: [
            5618632176883261929,
            5091169848121332946,
            9110857118546866548,
            100418585322354598,
        ],
        ace_circuit_digest: [
            2255028588524991477,
            8088146176287763667,
            1935595524963351362,
            5560235558590875651,
        ],
        preprocessed_commitment: [
            1070440981155119101,
            2022626773377316756,
            6941685244114430330,
            5172579525468662096,
        ],
    },
];

const FULL_PINS: RelationPins = {
    let mut index = 0;
    loop {
        assert!(
            index < RELATION_PINS.len(),
            "RELATION_PINS has no entry for RelationSelection::FULL; add one (placeholder values \
             are fine) and run the miden-precompiles-air tests for the real values"
        );
        if RELATION_PINS[index].selection_mask == RelationSelection::FULL.mask() {
            break RELATION_PINS[index];
        }
        index += 1;
    }
};

/// Relation digest of the full relation.
pub const PVM_RELATION_DIGEST: [u64; 4] = FULL_PINS.relation_digest;

/// ACE circuit digest of the full relation.
pub const PVM_ACE_CIRCUIT_DIGEST: [u64; 4] = FULL_PINS.ace_circuit_digest;

/// Setup commitment of the full relation.
pub const PVM_PREPROCESSED_COMMITMENT: [u64; 4] = FULL_PINS.preprocessed_commitment;

/// Pins of a declared relation member.
pub fn pins(selection: RelationSelection) -> &'static RelationPins {
    RELATION_PINS
        .iter()
        .find(|pins| pins.selection_mask == selection.mask())
        .expect("every declared relation member is pinned")
}

/// Geometry of one relation member, compiled from the chiplet AIRs.
#[derive(Clone, Copy, Debug)]
pub struct ProtocolMetadata {
    /// Selection mask of the member.
    pub selection_mask: u32,
    /// Encoded circuit shape: (READ variables, evaluation gates, stream length in felts).
    pub circuit_shape: (usize, usize, usize),
    /// Security shape of the member at the default commitment alignment.
    pub air_shape: AirShape,
    /// Raw `(preprocessed, main, auxiliary)` widths of each selected AIR, in canonical order.
    pub raw_widths: &'static [(usize, usize, usize)],
    pub num_quotient_chunks: usize,
}

impl ProtocolMetadata {
    pub fn num_deep_terms(&self, alignment: usize) -> u32 {
        miden_air::geometry::num_deep_terms_for_widths(
            self.raw_widths,
            self.num_quotient_chunks,
            alignment,
        )
    }
}

include!(concat!(env!("OUT_DIR"), "/protocol.rs"));

/// Encoded circuit shape of the full relation.
pub const PVM_CIRCUIT_SHAPE: (usize, usize, usize) = FULL_METADATA.circuit_shape;

/// Build-compiled metadata of a declared relation member.
pub fn metadata(selection: RelationSelection) -> &'static ProtocolMetadata {
    PROTOCOLS
        .iter()
        .find(|metadata| metadata.selection_mask == selection.mask())
        .expect("every declared selection is compiled")
}

/// Materialize a member's embedded instruction stream without symbolic AIR capture.
///
/// The commitment is the member's pinned ACE circuit digest; the recursive verifier rejects a
/// stream that does not hash to it.
pub fn recursive_circuit(selection: RelationSelection) -> PvmRecursiveAceCircuit {
    let (num_inputs, num_eval_gates, stream_len) = metadata(selection).circuit_shape;
    PvmRecursiveAceCircuit {
        num_inputs,
        num_eval_gates,
        stream_len,
        commitment: Word::new(pins(selection).ace_circuit_digest.map(Felt::new_unchecked)),
        instructions: generated_instructions(selection.mask())
            .iter()
            .copied()
            .map(Felt::new_unchecked)
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::policy;

    const UPDATE_HINT: &str = "an intentional relation change must update RELATION_PINS in \
                               crates/precompiles-air/src/protocol.rs and update \
                               CURRENT_PVM_VERIFIER_ROOT in \
                               core/src/proof.rs";

    /// Every declared member is pinned exactly once, and nothing else is.
    #[test]
    fn every_declared_member_is_pinned() {
        let mut declared: Vec<_> = RelationSelection::all().iter().map(|s| s.mask()).collect();
        let mut pinned: Vec<_> = RELATION_PINS.iter().map(|pins| pins.selection_mask).collect();
        declared.sort_unstable();
        pinned.sort_unstable();
        assert_eq!(pinned, declared, "RELATION_PINS must list every declared member once");
    }

    /// Each embedded stream and pinned circuit digest must describe the circuit captured
    /// independently from the chiplet AIRs.
    #[test]
    fn embedded_circuits_match_the_declared_relation() {
        for selection in RelationSelection::all() {
            let independently_built: PvmRecursiveAceCircuit =
                crate::ace::build_selected_precompile_ace_circuit(selection)
                    .unwrap()
                    .to_ace()
                    .unwrap()
                    .try_into()
                    .unwrap();
            let embedded = recursive_circuit(selection);
            assert_eq!(
                embedded.commitment,
                independently_built.commitment,
                "member {} ACE circuit digest is stale; {UPDATE_HINT}",
                selection.mask()
            );
            assert!(
                embedded == independently_built,
                "member {} embedded ACE stream differs from the captured circuit",
                selection.mask()
            );
        }
    }

    /// Each pinned relation digest must bind the protocol version to its pinned circuit digest.
    #[test]
    fn relation_digests_bind_the_circuit_digests() {
        for pins in RELATION_PINS {
            let digest = miden_air::config::relation_digest(
                policy::PROTOCOL_ID,
                &Word::new(pins.ace_circuit_digest.map(Felt::new_unchecked)),
            );
            assert_eq!(
                digest.map(|felt| felt.as_canonical_u64()),
                pins.relation_digest,
                "member {} relation digest is stale; {UPDATE_HINT}",
                pins.selection_mask
            );
        }
    }

    /// Each pinned setup commitment must be the one its member builds under the Eidos
    /// configuration, and the full relation's must be the bundle the prover and verifier use.
    #[test]
    fn preprocessed_commitments_match_the_declared_setup() {
        use alloc::vec;

        use miden_core::field::QuadFelt;

        for selection in RelationSelection::all() {
            let pins = pins(selection);
            let statement =
                miden_lifted_air::Statement::<Felt, QuadFelt, crate::ChipletMultiAir>::new(
                    crate::ChipletMultiAir::with_selection(selection),
                    vec![Felt::ZERO; crate::logup::NUM_PUBLIC_VALUES],
                    vec![],
                )
                .expect("declared PVM statement");
            let config = crate::stark_config::eidos_config(
                policy::precompile_pcs_params(),
                pins.relation_digest.map(Felt::new_unchecked),
            );
            let commitment = <[u64; 4]>::from(
                miden_lifted_stark::Preprocessed::build(&statement, &config)
                    .expect("PVM fixed setup")
                    .commitment(),
            );
            assert_eq!(
                commitment,
                pins.preprocessed_commitment,
                "member {} setup commitment is stale; {UPDATE_HINT}",
                selection.mask()
            );
        }
        let full = <[u64; 4]>::from(crate::preprocessed::eidos().commitment());
        assert_eq!(full, PVM_PREPROCESSED_COMMITMENT, "{UPDATE_HINT}");
    }
}
