//! ACE circuit policy for the precompile chiplet multi-AIR proof.
//!
//! The relation uses [`miden_air::precompiles::ChipletAir::all`] as its stable instance order and
//! canonical ACE fold order, and aligns each per-AIR trace region to eight base-field elements. The
//! lifted STARK proof commits traces in ascending height order, which varies per workload, but one
//! order-invariant circuit serves every ordering: the verifier lands each proof-ordered segment at
//! the canonical address the circuit reads it from and stages each chiplet's fold coefficient by
//! proof position.
//!
//! The cross-chiplet LogUp identity enforced by `ChipletMultiAir::eval_external` remains an
//! external multi-AIR assertion.

#[cfg(test)]
use alloc::vec::Vec;

use miden_air::precompiles::NUM_CHIPLETS;
pub use miden_air::precompiles::ace::PvmRecursiveAceCircuit;
#[cfg(test)]
use miden_air::precompiles::ace::build_pvm_recursive_verifier_ace_circuit;
#[cfg(test)]
use miden_air::precompiles::{ChipletAir, ace::build_canonical_precompile_ace_circuit};

/// Returns the process-wide canonical circuit shared by every proof order.
pub fn shared_pvm_recursive_circuit() -> &'static PvmRecursiveAceCircuit {
    static CIRCUIT: std::sync::OnceLock<PvmRecursiveAceCircuit> = std::sync::OnceLock::new();
    CIRCUIT.get_or_init(miden_air::precompiles::protocol::recursive_circuit)
}

/// Returns [`miden_air::precompiles::ChipletAir::all`] instance indices in committed-trace order.
pub fn proof_order_from_log_heights(log_heights: &[u8; NUM_CHIPLETS]) -> [usize; NUM_CHIPLETS] {
    let mut order = core::array::from_fn(|index| index);
    order.sort_by_key(|&index| (log_heights[index], index));
    order
}

/// Orders used by semantic checks: identity, reversal, adjacent swaps, each chiplet
/// moved to either end, and a deterministic random sample. The sample includes non-involutions,
/// where the source and destination permutations differ.
#[cfg(test)]
pub(crate) fn structured_orders() -> Vec<[usize; NUM_CHIPLETS]> {
    let identity: [usize; NUM_CHIPLETS] = core::array::from_fn(|i| i);
    let mut orders = Vec::new();
    orders.push(identity);
    let mut reversed = identity;
    reversed.reverse();
    orders.push(reversed);
    for i in 0..NUM_CHIPLETS - 1 {
        let mut order = identity;
        order.swap(i, i + 1);
        orders.push(order);
    }
    for target in 0..NUM_CHIPLETS {
        let mut front: Vec<usize> = identity.to_vec();
        front.remove(target);
        front.insert(0, target);
        orders.push(front.try_into().expect("permutation"));
        let mut back: Vec<usize> = identity.to_vec();
        back.remove(target);
        back.push(target);
        orders.push(back.try_into().expect("permutation"));
    }
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..64 {
        let mut order = identity;
        // Fisher-Yates with a fixed LCG so the sample is deterministic.
        for i in (1..NUM_CHIPLETS).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            order.swap(i, (state >> 33) as usize % (i + 1));
        }
        orders.push(order);
    }
    assert!(
        orders.iter().any(|order| {
            let mut twice = [0usize; NUM_CHIPLETS];
            for (i, &v) in order.iter().enumerate() {
                twice[i] = order[v];
            }
            twice != core::array::from_fn(|i| i)
        }),
        "sample must contain non-involutions"
    );
    orders
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec::Vec};

    use miden_ace_codegen::InputKey;
    use miden_air::precompiles::ace::LMCS_ALIGNMENT;
    use miden_core::{Felt, Word, crypto::hash::Eidos, field::QuadFelt};
    use miden_crypto::field::PrimeCharacteristicRing;

    use super::*;
    use crate::ace_constants::{
        PVM_ACE_CIRCUIT_DIGEST, PVM_CIRCUIT_SHAPE, PVM_RELATION_DIGEST, relation_digest_for_circuit,
    };

    fn canonical_order() -> Vec<usize> {
        (0..NUM_CHIPLETS).collect()
    }

    /// Deterministic extension-field inputs.
    fn pseudo_random_inputs(len: usize) -> Vec<QuadFelt> {
        let mut state = 0x5eed_1234_abcd_ef01u64;
        (0..len)
            .map(|_| {
                let mut next = || {
                    state =
                        state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    Felt::from((state >> 33) as u32)
                };
                let c0 = next();
                let c1 = next();
                QuadFelt::new([c0, c1])
            })
            .collect()
    }

    /// The encoded recursive-verifier circuit must be the canonical builder's output and nothing
    /// else: its digest is what the compiled-in PVM circuit commitment has to pin.
    #[test]
    fn pvm_recursive_circuit_matches_the_canonical_builder() {
        let encoded = build_canonical_precompile_ace_circuit()
            .expect("canonical circuit")
            .to_ace()
            .expect("canonical circuit must be MASM encodable");
        let produced = build_pvm_recursive_verifier_ace_circuit().expect("recursive circuit");

        assert_eq!(produced.num_inputs, encoded.num_vars());
        assert_eq!(produced.num_eval_gates, encoded.num_eval_rows());
        assert_eq!(produced.stream_len, encoded.size_in_felt());
        assert_eq!(produced.instructions.as_slice(), encoded.instructions());
        assert_eq!(produced.commitment, Eidos::hash_elements(encoded.instructions()));
        assert!(
            produced.stream_len.is_multiple_of(8),
            "the stream must fill whole adv_pipe blocks"
        );

        // The cached circuit is what a repeated caller evaluates, and it is built the same way.
        assert_eq!(*shared_pvm_recursive_circuit(), produced);
    }

    /// Checks the canonical circuit against direct AIR folds for structured PVM proof orders.
    #[test]
    fn canonical_circuit_matches_direct_evaluation_for_structured_orders() {
        let airs = ChipletAir::all();
        let canonical = build_canonical_precompile_ace_circuit().expect("canonical circuit");
        let canonical_layout = canonical.layout();

        // Nonzero quotient openings exercise the shared quotient binding.
        let base = pseudo_random_inputs(canonical_layout.total_inputs);

        let beta = QuadFelt::from_u64(97);
        // Duplicate orders would evaluate identically and defeat the non-vacuity check below.
        let mut orders = structured_orders();
        orders.sort_unstable();
        orders.dedup();

        let mut roots = Vec::with_capacity(orders.len());
        for order in &orders {
            let mut canonical_inputs = base.clone();
            for (position, &air_index) in order.iter().enumerate() {
                let index = canonical_layout
                    .index(InputKey::MultiAirFoldCoeff(air_index))
                    .expect("canonical fold-coefficient slot");
                canonical_inputs[index] = beta.exp_u64((NUM_CHIPLETS - 1 - position) as u64);
            }
            let canonical_root = canonical.eval(&canonical_inputs).expect("canonical evaluation");

            let direct = miden_ace_codegen::testing::eval_multi_air_constraints(
                &airs,
                canonical_layout,
                &canonical_inputs,
                order,
                beta,
                LMCS_ALIGNMENT,
            );
            assert_eq!(canonical_root, direct, "direct symbolic evaluation for {order:?}");
            roots.push(canonical_root);
        }

        // Distinct roots ensure this fixture distinguishes the sampled proof orders.
        for (i, left) in roots.iter().enumerate() {
            for (j, right) in roots.iter().enumerate().skip(i + 1) {
                assert_ne!(left, right, "{:?} and {:?} fold identically", orders[i], orders[j]);
            }
        }
    }

    /// Pin the complete quotient-degree vector, not merely its maximum: otherwise a chiplet could
    /// drift between degrees while another chiplet kept the relation-wide maximum unchanged.
    #[test]
    fn quotient_chunks_match_the_symbolic_derivation() {
        const EXPECTED: [(&str, u8); NUM_CHIPLETS] = [
            ("ChunkNodeSponge", 2),
            ("EidosCompression", 1),
            ("KeccakRound", 2),
            ("BytePairLut", 1),
            ("TranscriptEval", 1),
            ("UintStoreMul", 1),
            ("UintAdd", 1),
            ("EcPointStoreGroups", 1),
            ("EcGroupAdd", 1),
            ("EcMsm", 1),
            ("Sha512", 2),
            ("Sha256", 2),
        ];

        let derived: Vec<(String, u8)> = ChipletAir::all()
            .iter()
            .map(|air| {
                (
                    format!("{air:?}"),
                    miden_stark::log_quotient_degree::<Felt, QuadFelt, ChipletAir>(air),
                )
            })
            .collect();
        let expected: Vec<(String, u8)> =
            EXPECTED.iter().map(|(name, degree)| ((*name).into(), *degree)).collect();
        assert_eq!(
            derived, expected,
            "a chiplet's quotient degree moved; if intended, re-mint the relation digest"
        );

        let max = derived.iter().map(|(_, degree)| *degree).max().expect("non-empty stack");
        assert!(max <= miden_air::precompiles::policy::LOG_BLOWUP);
        let expected_chunks = 1usize << max;
        assert_eq!(
            miden_air::precompiles::protocol::metadata().num_quotient_chunks,
            expected_chunks,
            "the ACE circuit must read exactly the quotient chunks the proof carries"
        );
        let canonical = build_canonical_precompile_ace_circuit().expect("canonical ACE circuit");
        assert_eq!(canonical.layout().counts.num_quotient_chunks, expected_chunks);
    }

    /// Keep protocol and cost changes visible as numbers rather than only as a digest diff.
    #[test]
    fn pvm_canonical_ace_shape_matches_current_air() {
        assert!(
            ChipletAir::all().iter().all(|air| {
                <ChipletAir as miden_stark::air::LiftedAir<Felt, QuadFelt>>::max_periodic_length(
                    air,
                ) <= 128
            }),
            "long periodic tables make every recursive proof pay for dense SHA program polynomials"
        );
        let canonical = build_canonical_precompile_ace_circuit().expect("canonical circuit");
        // BytePairLut is the only chiplet with a preprocessed trace, so the combined
        // preprocessed region must be nonempty.
        assert!(canonical.layout().counts.preprocessed_width > 0);
        let num_aux_values: usize = ChipletAir::all()
            .iter()
            .map(|air| {
                <ChipletAir as miden_stark::air::LiftedAir<Felt, QuadFelt>>::num_aux_values(air)
            })
            .sum();
        assert_eq!(canonical.layout().counts.num_aux_boundary, num_aux_values);

        let circuit = build_pvm_recursive_verifier_ace_circuit().expect("recursive circuit");
        assert!(
            circuit.num_eval_gates < 32_768,
            "the SHA program must not restore the 97,576-gate fixed verifier cost"
        );
        // Encoded READ nodes include constants as well as the layout's variable inputs.
        assert_eq!(
            PVM_CIRCUIT_SHAPE,
            (circuit.num_inputs, circuit.num_eval_gates, circuit.stream_len)
        );
        assert_eq!(circuit.stream_len % 8, 0, "ACE stream supports whole-block ingestion");
        let snapshot = format!(
            "layout_inputs: {}\nnum_vars: {}\nnum_eval_gates: {}\nstream_len: \
             {}\ncircuit_digest: {:?}\nrelation_digest: {:?}",
            canonical.layout().total_inputs,
            circuit.num_inputs,
            circuit.num_eval_gates,
            circuit.stream_len,
            circuit.commitment.iter().map(Felt::as_canonical_u64).collect::<Vec<_>>(),
            PVM_RELATION_DIGEST,
        );

        insta::assert_snapshot!(snapshot);
    }

    /// The compiled-in circuit digest must equal the commitment of the canonical circuit the PVM
    /// recursive verifier actually evaluates: it is what binds the transcript to that circuit, so
    /// any drift between them would let a proof be verified against a circuit the protocol
    /// constant never committed to.
    #[test]
    fn pvm_ace_circuit_digest_matches_canonical_circuit() {
        let circuit = build_pvm_recursive_verifier_ace_circuit().expect("recursive circuit");
        let actual: Vec<u64> = circuit.commitment.iter().map(Felt::as_canonical_u64).collect();
        assert_eq!(
            actual, PVM_ACE_CIRCUIT_DIGEST,
            "PVM_ACE_CIRCUIT_DIGEST is stale relative to the canonical circuit's commitment"
        );
    }

    /// `PVM_RELATION_DIGEST` must be the algebraic binding of the protocol id to the circuit
    /// digest, not merely a value pinned independently: this is what a mutated circuit digest
    /// with a stale relation digest would otherwise leave uncaught.
    #[test]
    fn pvm_relation_digest_binds_the_circuit_digest() {
        let circuit_digest = Word::new(PVM_ACE_CIRCUIT_DIGEST.map(Felt::new_unchecked));
        let expected: Vec<u64> = relation_digest_for_circuit(&circuit_digest)
            .iter()
            .map(Felt::as_canonical_u64)
            .collect();
        assert_eq!(
            PVM_RELATION_DIGEST.to_vec(),
            expected,
            "PVM_RELATION_DIGEST does not bind PVM_ACE_CIRCUIT_DIGEST via relation_digest_for_circuit"
        );
    }

    /// The VM and PVM relations must use distinct protocol ids and land on distinct digests, so
    /// a proof produced for one relation can never be replayed against the other's recursive
    /// verifier.
    #[test]
    fn pvm_domain_is_separated_from_vm() {
        assert_ne!(
            crate::ace_constants::PVM_PROTOCOL_ID,
            1,
            "PVM must not reuse the VM protocol id"
        );
        assert_ne!(
            PVM_RELATION_DIGEST,
            miden_air::config::RELATION_DIGEST.map(|felt| felt.as_canonical_u64()),
            "PVM_RELATION_DIGEST must not collide with the VM's RELATION_DIGEST"
        );
        assert_ne!(
            PVM_ACE_CIRCUIT_DIGEST,
            miden_air::config::ACE_CIRCUIT_DIGEST.map(|felt| felt.as_canonical_u64()),
            "PVM_ACE_CIRCUIT_DIGEST must not collide with the VM's ACE_CIRCUIT_DIGEST"
        );
    }

    /// Proof ordering is stable for equal heights and sorts taller traces last.
    #[test]
    fn proof_order_sorts_by_height_then_instance_index() {
        let mut log_heights = [10u8; NUM_CHIPLETS];
        assert_eq!(proof_order_from_log_heights(&log_heights).to_vec(), canonical_order());

        log_heights[0] = 12;
        let order = proof_order_from_log_heights(&log_heights);
        assert_eq!(*order.last().expect("nonempty"), 0, "tallest AIR sorts last");
        let mut sorted = order;
        sorted.sort_unstable();
        assert_eq!(sorted.to_vec(), canonical_order(), "order is a permutation");
    }

    /// The circuit digest binds the generated circuit but not the external assertion, so each
    /// protocol version pins that assertion's exact value on a fixed, non-zero fixture. The
    /// fixture is spelled out rather than derived from `num_aux_values`, so a change to either
    /// the assertion's semantics or the relation's aux shape lands here instead of silently
    /// producing a different input.
    #[test]
    fn external_assertion_matches_the_protocol_version() {
        use miden_air::precompiles::{ChipletAir, ChipletMultiAir, logup::NUM_PUBLIC_VALUES};
        use miden_stark::air::Statement;

        let challenges = [
            QuadFelt::new([Felt::from(3u32), Felt::from(5u32)]),
            QuadFelt::new([Felt::from(7u32), Felt::from(11u32)]),
        ];
        let aux_values: Vec<Vec<QuadFelt>> = (0..NUM_CHIPLETS)
            .map(|i| {
                alloc::vec![QuadFelt::new([
                    Felt::from((i + 1) as u32),
                    Felt::from((2 * i + 1) as u32)
                ])]
            })
            .collect();
        let aux_refs: Vec<&[QuadFelt]> = aux_values.iter().map(Vec::as_slice).collect();

        let statement = Statement::new(
            ChipletMultiAir::new(),
            alloc::vec![(
                ChipletAir::TRANSCRIPT_EVAL_INDEX,
                alloc::vec![Felt::ZERO; NUM_PUBLIC_VALUES]
            )],
            alloc::vec![],
        )
        .unwrap();
        let actual = statement
            .eval_external(&challenges, &aux_refs, &[0; NUM_CHIPLETS])
            .expect("fixture denominators are non-zero");
        let expected = match crate::ace_constants::PVM_PROTOCOL_ID {
            // Fixed secp256k1, Ed25519 and P-256 boundary denominators plus one value per chiplet.
            4 => QuadFelt::new([
                Felt::new_unchecked(13_307_287_383_580_918_166),
                Felt::new_unchecked(9_765_647_450_999_344_333),
            ]),
            version => panic!("add an external-assertion vector for protocol version {version}"),
        };

        assert_eq!(actual.as_slice(), &[expected]);
    }

    /// The chiplet instance order fixes proof-order tie-breaks and the relation digest.
    /// Intentional changes require a protocol-version bump and a breaking changelog entry.
    #[test]
    fn chiplet_instance_order_is_protocol_pinned() {
        let pinned = [
            ChipletAir::ChunkNodeSponge,
            ChipletAir::EidosCompression,
            ChipletAir::KeccakRound,
            ChipletAir::BytePairLut,
            ChipletAir::TranscriptEval,
            ChipletAir::UintStoreMul,
            ChipletAir::UintAdd,
            ChipletAir::EcPointStoreGroups,
            ChipletAir::EcGroupAdd,
            ChipletAir::EcMsm,
            ChipletAir::Sha512,
            ChipletAir::Sha256,
        ];
        assert_eq!(
            ChipletAir::all(),
            pinned,
            "chiplet instance order moved; an intentional change requires a protocol-version bump"
        );
    }
}
