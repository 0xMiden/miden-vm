//! ACE circuit policy for the precompile chiplet multi-AIR proof.
//!
//! The relation uses [`ChipletAir::all`] as its stable instance order and canonical ACE fold order,
//! and aligns each per-AIR trace region to eight base-field elements. The lifted STARK proof
//! commits traces in ascending height order, which varies per workload, but one order-invariant
//! circuit serves every ordering: the verifier lands each proof-ordered segment at the canonical
//! address the circuit reads it from and stages each chiplet's fold coefficient by proof position.
//!
//! The cross-chiplet LogUp identity enforced by `ChipletMultiAir::eval_external` remains an
//! external multi-AIR assertion.

use alloc::{format, vec::Vec};

#[cfg(test)]
use miden_ace_codegen::build_multi_air_ace_circuit;
use miden_ace_codegen::{
    AceCircuit, AceConfig, AceError, LayoutKind, build_canonical_multi_air_ace_circuit,
};
use miden_core::{Felt, Word, field::QuadFelt};
use miden_precompiles_air::{ChipletAir, NUM_CHIPLETS};

// MULTI-AIR ACE CIRCUIT
// ================================================================================================

/// Per-AIR trace regions are padded to this width before concatenation, matching the LMCS wire
/// alignment used by the commitment scheme.
const LMCS_ALIGNMENT: usize = 8;

/// Number of quotient chunks the precompile relation commits to.
///
/// The lifted STARK verifier derives this quantity symbolically from the AIRs. Deriving it through
/// the same implementation keeps the ACE circuit's READ layout coupled to the proof protocol.
fn num_quotient_chunks() -> usize {
    let max_log_quotient_degree = ChipletAir::all()
        .iter()
        .map(miden_lifted_stark::log_quotient_degree::<Felt, QuadFelt, ChipletAir>)
        .max()
        .expect("the chiplet stack is non-empty");
    1usize << max_log_quotient_degree
}

/// ACE codegen settings for the precompile chiplet relation.
fn precompile_ace_config() -> AceConfig {
    AceConfig {
        num_quotient_chunks: num_quotient_chunks(),
        layout: LayoutKind::Masm,
        num_airs: NUM_CHIPLETS,
    }
}

/// Builds the ACE circuit in the canonical [`ChipletAir::all`] instance order.
///
/// This independent per-order construction is retained as the reference the order-invariant
/// circuit is tested against.
#[cfg(test)]
pub fn build_precompile_multi_air_ace_circuit() -> Result<AceCircuit<QuadFelt>, AceError> {
    let airs = ChipletAir::all();
    let proof_order: Vec<_> = (0..airs.len()).collect();

    build_multi_air_ace_circuit::<ChipletAir>(
        &airs,
        &proof_order,
        precompile_ace_config(),
        LMCS_ALIGNMENT,
    )
}

/// Builds the canonical (order-invariant) precompile chiplet ACE circuit.
///
/// Every chiplet's trace regions sit at its [`ChipletAir::all`] offset and every chiplet reads its
/// fold coefficient from a dedicated slot, so one circuit serves every proof ordering. The caller
/// lands each proof-ordered trace segment on its canonical address and stages the chiplet at proof
/// position `k` with the coefficient `beta^(NUM_CHIPLETS - 1 - k)`.
pub fn build_canonical_precompile_ace_circuit() -> Result<AceCircuit<QuadFelt>, AceError> {
    let airs = ChipletAir::all();
    build_canonical_multi_air_ace_circuit(&airs, precompile_ace_config(), LMCS_ALIGNMENT)
}

// RECURSIVE VERIFIER CIRCUIT
// ================================================================================================

/// Encoded PVM recursive-verifier ACE circuit and the metadata consumed by MASM.
///
/// One circuit serves every proof order, so the stream is a single `adv_pipe`-aligned segment
/// under one digest rather than a per-order shuffle prefix spliced onto a shared common section.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PvmRecursiveAceCircuit {
    /// Number of ACE READ variables.
    pub num_inputs: usize,
    /// Number of ACE EVAL rows.
    pub num_eval_gates: usize,
    /// Encoded instruction stream length in base-field elements.
    pub stream_len: usize,
    /// Eidos digest of the full instruction stream: the advice-map key and the value pinned by
    /// the compiled-in circuit digest.
    pub commitment: Word,
    /// Encoded ACE instruction stream consumed by `eval_circuit`.
    pub instructions: Vec<Felt>,
}

/// Builds and encodes the order-invariant PVM recursive-verifier ACE circuit.
///
/// A caller that needs the circuit per proof should hold [`shared_pvm_recursive_circuit`] rather
/// than rebuild it here.
pub fn build_pvm_recursive_verifier_ace_circuit() -> Result<PvmRecursiveAceCircuit, AceError> {
    let encoded = build_canonical_precompile_ace_circuit()?.to_ace()?;
    let instructions = encoded.instructions();
    let stream_len = encoded.size_in_felt();
    if stream_len != instructions.len() {
        return Err(AceError::InvalidInputLayout {
            message: format!(
                "ACE circuit stream length ({stream_len}) does not match instruction count ({})",
                instructions.len()
            ),
        });
    }
    if !stream_len.is_multiple_of(8) {
        return Err(AceError::InvalidInputLayout {
            message: "ACE circuit stream must be 8-felt aligned for adv_pipe".into(),
        });
    }

    Ok(PvmRecursiveAceCircuit {
        num_inputs: encoded.num_vars(),
        num_eval_gates: encoded.num_eval_rows(),
        stream_len,
        commitment: encoded.circuit_hash(),
        instructions: instructions.to_vec(),
    })
}

/// The process-wide canonical circuit. There is exactly one, for every proof order.
pub fn shared_pvm_recursive_circuit() -> &'static PvmRecursiveAceCircuit {
    static CIRCUIT: std::sync::OnceLock<PvmRecursiveAceCircuit> = std::sync::OnceLock::new();
    CIRCUIT.get_or_init(|| {
        build_pvm_recursive_verifier_ace_circuit()
            .expect("PVM recursive-verifier ACE circuit must build")
    })
}

/// Returns [`ChipletAir::all`] instance indices in committed-trace order.
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
    use miden_core::{Felt, crypto::hash::Eidos, field::QuadFelt};
    use miden_crypto::field::PrimeCharacteristicRing;

    use super::*;
    use crate::ace_constants::{
        PVM_ACE_CIRCUIT_DIGEST, PVM_CIRCUIT_SHAPE, PVM_RELATION_DIGEST, relation_digest_for_circuit,
    };

    const PVM_WRAPPER_PATH: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../lib/core/asm/sys/pvm/mod.masm");
    const SECURITY_ESTIMATOR_PATH: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../lib/core/asm/stark/security.masm");
    const GENERIC_UTILS_PATH: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../lib/core/asm/stark/utils.masm");

    fn canonical_order() -> Vec<usize> {
        (0..NUM_CHIPLETS).collect()
    }

    /// Deterministic extension-field inputs. Values depend only on the slot index, so two layouts
    /// that agree index-for-index on a prefix receive the same values there.
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

    /// Per-chiplet aligned (main, aux, boundary) block widths in the combined READ layout.
    ///
    /// Derived from the chiplet declarations and the documented LMCS alignment rather than from
    /// the codegen, so this cross-checks the production placement instead of mirroring it.
    fn chiplet_block_widths() -> [(usize, usize, usize); NUM_CHIPLETS] {
        use miden_ace_codegen::EXT_DEGREE;
        use miden_lifted_air::{BaseAir, LiftedAir};

        let mut widths = [(0usize, 0usize, 0usize); NUM_CHIPLETS];
        for (index, air) in ChipletAir::all().iter().enumerate() {
            let aux_coords = <ChipletAir as LiftedAir<Felt, QuadFelt>>::aux_width(air) * EXT_DEGREE;
            widths[index] = (
                <ChipletAir as BaseAir<Felt>>::width(air).next_multiple_of(LMCS_ALIGNMENT),
                aux_coords.next_multiple_of(LMCS_ALIGNMENT) / EXT_DEGREE,
                <ChipletAir as LiftedAir<Felt, QuadFelt>>::num_aux_values(air),
            );
        }
        widths
    }

    /// Start of each chiplet's main/aux/boundary block when the blocks are concatenated in
    /// `order`, indexed by instance index.
    fn chiplet_block_offsets(
        widths: &[(usize, usize, usize); NUM_CHIPLETS],
        order: &[usize; NUM_CHIPLETS],
    ) -> [(usize, usize, usize); NUM_CHIPLETS] {
        let mut offsets = [(0usize, 0usize, 0usize); NUM_CHIPLETS];
        let (mut main, mut aux, mut boundary) = (0usize, 0usize, 0usize);
        for &index in order {
            offsets[index] = (main, aux, boundary);
            main += widths[index].0;
            aux += widths[index].1;
            boundary += widths[index].2;
        }
        offsets
    }

    fn masm_const(path: &str, name: &str) -> u64 {
        let source = std::fs::read_to_string(path)
            .unwrap_or_else(|err| panic!("failed to read {path}: {err}"));
        let prefix = alloc::format!("const {name} = ");
        source
            .lines()
            .find_map(|line| {
                line.trim().strip_prefix(&prefix)?.split('#').next()?.trim().parse().ok()
            })
            .unwrap_or_else(|| panic!("constant {name} not found in {path}"))
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

    /// The canonical circuit is order-invariant: a proof order is carried entirely by its READ
    /// inputs, with each chiplet's trace values at their canonical (instance-order) offset and its
    /// fold coefficient staged as `beta^(NUM_CHIPLETS - 1 - proof position)`. Pin that against the
    /// per-order builder over the structured sample: ten chiplets admit `10!` orderings, so an
    /// exhaustive sweep is out of reach and end-to-end proofs only ever exercise a handful.
    #[test]
    fn canonical_circuit_matches_the_per_order_builder_for_structured_orders() {
        use miden_ace_codegen::{EXT_DEGREE, InputLayout};
        use miden_lifted_air::BaseAir;

        let airs = ChipletAir::all();
        let config = precompile_ace_config();
        let canonical = build_canonical_precompile_ace_circuit().expect("canonical circuit");
        let canonical_layout = canonical.layout().clone();

        // Only one chiplet declares preprocessed columns, so its block starts at zero under every
        // order and the routing below needs no preprocessed case. A second one would break that.
        assert_eq!(
            airs.iter()
                .filter(|air| <ChipletAir as BaseAir<Felt>>::preprocessed_width(air) > 0)
                .count(),
            1,
            "a second preprocessed chiplet would make the preprocessed region order-dependent"
        );

        // Zero the quotient openings so the shared `q * v` binding drops out of both circuits and
        // the evaluation is exactly the fold of the per-chiplet accumulators.
        let zero_quotient = |layout: &InputLayout, inputs: &mut [QuadFelt]| {
            for chunk in 0..layout.counts.num_quotient_chunks {
                for offset in 0..2 {
                    for coord in 0..EXT_DEGREE {
                        let key = InputKey::QuotientChunkCoord { offset, chunk, coord };
                        inputs[layout.index(key).expect("quotient slot")] = QuadFelt::ZERO;
                    }
                }
            }
        };

        let widths = chiplet_block_widths();
        let identity: [usize; NUM_CHIPLETS] = core::array::from_fn(|index| index);
        let canonical_offsets = chiplet_block_offsets(&widths, &identity);

        let mut base = pseudo_random_inputs(canonical_layout.total_inputs);
        zero_quotient(&canonical_layout, &mut base);

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

            let per_order = build_multi_air_ace_circuit(&airs, order, config, LMCS_ALIGNMENT)
                .expect("per-order circuit");
            let per_order_layout = per_order.layout().clone();
            let proof_offsets = chiplet_block_offsets(&widths, order);

            // The canonical layout only appends its fold-coefficient slots after the per-AIR
            // selectors, so both layouts agree index-for-index on everything that precedes them;
            // the shared generator therefore gives both the same public, randomness, and
            // preprocessed values, and only the per-chiplet trace blocks need routing.
            let mut inputs = pseudo_random_inputs(per_order_layout.total_inputs);
            zero_quotient(&per_order_layout, &mut inputs);

            for index in 0..NUM_CHIPLETS {
                let (main_width, aux_width, boundary_width) = widths[index];
                let (canonical_main, canonical_aux, canonical_boundary) = canonical_offsets[index];
                let (proof_main, proof_aux, proof_boundary) = proof_offsets[index];
                for offset in 0..2 {
                    for column in 0..main_width {
                        let source = canonical_layout
                            .index(InputKey::Main { offset, index: canonical_main + column })
                            .expect("canonical main slot");
                        let target = per_order_layout
                            .index(InputKey::Main { offset, index: proof_main + column })
                            .expect("proof main slot");
                        inputs[target] = base[source];
                    }
                    for column in 0..aux_width {
                        for coord in 0..EXT_DEGREE {
                            let source = canonical_layout
                                .index(InputKey::AuxCoord {
                                    offset,
                                    index: canonical_aux + column,
                                    coord,
                                })
                                .expect("canonical aux slot");
                            let target = per_order_layout
                                .index(InputKey::AuxCoord {
                                    offset,
                                    index: proof_aux + column,
                                    coord,
                                })
                                .expect("proof aux slot");
                            inputs[target] = base[source];
                        }
                    }
                }
                for value in 0..boundary_width {
                    let source = canonical_layout
                        .index(InputKey::AuxBusBoundary(canonical_boundary + value))
                        .expect("canonical boundary slot");
                    let target = per_order_layout
                        .index(InputKey::AuxBusBoundary(proof_boundary + value))
                        .expect("proof boundary slot");
                    inputs[target] = base[source];
                }
            }

            // The per-order circuit folds through one shared beta slot, Horner over proof order.
            let beta_index = per_order_layout.index(InputKey::MultiAirFoldBeta).expect("beta slot");
            inputs[beta_index] = beta;

            assert_eq!(
                canonical_root,
                per_order.eval(&inputs).expect("per-order evaluation"),
                "the canonical circuit does not reproduce the per-order fold for {order:?}"
            );
            roots.push(canonical_root);
        }

        // A circuit that ignored the staged coefficients, or weighted a chiplet by its instance
        // index instead of its proof position, would fold to the same value under every order and
        // the sweep above would hold vacuously.
        for (i, left) in roots.iter().enumerate() {
            for (j, right) in roots.iter().enumerate().skip(i + 1) {
                assert_ne!(
                    left, right,
                    "{:?} and {:?} fold identically; the sweep is vacuous",
                    orders[i], orders[j]
                );
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
        ];

        let derived: Vec<(String, u8)> = ChipletAir::all()
            .iter()
            .map(|air| {
                (
                    format!("{air:?}"),
                    miden_lifted_stark::log_quotient_degree::<Felt, QuadFelt, ChipletAir>(air),
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
        let expected_chunks = 1usize << max;
        assert_eq!(
            precompile_ace_config().num_quotient_chunks,
            expected_chunks,
            "the ACE circuit must read exactly the quotient chunks the proof carries"
        );
        let per_order =
            build_precompile_multi_air_ace_circuit().expect("per-order multi-AIR ACE circuit");
        let canonical = build_canonical_precompile_ace_circuit().expect("canonical ACE circuit");
        assert_eq!(per_order.layout().counts.num_quotient_chunks, expected_chunks);
        assert_eq!(canonical.layout().counts.num_quotient_chunks, expected_chunks);
    }

    /// Keep protocol and cost changes visible as numbers rather than only as a digest diff.
    #[test]
    fn pvm_canonical_ace_shape_matches_current_air() {
        let canonical = build_canonical_precompile_ace_circuit().expect("canonical circuit");
        // BytePairLut is the only chiplet with a preprocessed trace, so the combined
        // preprocessed region must be nonempty.
        assert!(canonical.layout().counts.preprocessed_width > 0);
        let num_aux_values: usize = ChipletAir::all()
            .iter()
            .map(|air| {
                <ChipletAir as miden_lifted_air::LiftedAir<Felt, QuadFelt>>::num_aux_values(air)
            })
            .sum();
        assert_eq!(canonical.layout().counts.num_aux_boundary, num_aux_values);

        let circuit = build_pvm_recursive_verifier_ace_circuit().expect("recursive circuit");
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

    /// The PVM aux hook reads twelve quadratic-extension component residues as six MASM words.
    /// Pin the complete per-chiplet shape so a redistribution cannot preserve only the total.
    #[test]
    fn pvm_aux_hook_matches_every_chiplets_boundary_shape() {
        const HOOK_PATH: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../lib/core/asm/sys/pvm/aux_trace.masm");

        let derived: Vec<usize> = ChipletAir::all()
            .iter()
            .map(miden_lifted_air::LiftedAir::<Felt, QuadFelt>::num_aux_values)
            .collect();
        assert_eq!(
            derived,
            alloc::vec![1; NUM_CHIPLETS],
            "the PVM aux hook boundary shape drifted"
        );
        assert_eq!(
            derived.iter().sum::<usize>(),
            2 * masm_const(HOOK_PATH, "NUM_AUX_VALUE_WORDS") as usize,
            "the MASM hook must read every normalized LogUp value exactly once"
        );

        // The scatter permutes the region the circuit reads, so it must be exactly one slot per
        // exposed value.
        let canonical = build_canonical_precompile_ace_circuit().expect("PVM canonical circuit");
        let layout = canonical.layout();
        let base = layout.index(InputKey::AuxBusBoundary(0)).expect("boundary base");
        let alpha = layout.index(InputKey::Alpha).expect("auxiliary inputs base");
        assert_eq!(
            alpha - base,
            derived.iter().sum::<usize>(),
            "the circuit's boundary region is not one slot per exposed value"
        );
    }

    #[test]
    fn pvm_aux_hook_matches_the_logup_registry() {
        use miden_precompiles_air::relations::{BusId, MAX_MESSAGE_WIDTH};

        const HOOK_PATH: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../lib/core/asm/sys/pvm/aux_trace.masm");

        assert_eq!(masm_const(HOOK_PATH, "UINT_VAL_BUS_SCALE"), BusId::UintVal as u64 + 1);
        assert_eq!(masm_const(HOOK_PATH, "EC_GROUP_BUS_SCALE"), BusId::EcGroup as u64 + 1);
        assert_eq!(masm_const(HOOK_PATH, "MAX_LOGUP_MESSAGE_WIDTH"), MAX_MESSAGE_WIDTH as u64);
    }

    #[test]
    fn pvm_public_input_hook_matches_the_statement_schema() {
        use miden_lifted_air::MultiAir;
        use miden_precompiles_air::ChipletMultiAir;

        use crate::ace_constants::PVM_PREPROCESSED_COMMITMENT;

        const HOOK_PATH: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../lib/core/asm/sys/pvm/public_inputs.masm");
        const RELATION_PATH: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../lib/core/asm/sys/pvm/mod.masm");

        let multi_air = ChipletMultiAir::new();
        assert_eq!(masm_const(HOOK_PATH, "NUM_PUBLIC_VALUES"), multi_air.num_air_inputs() as u64);
        assert_eq!(masm_const(HOOK_PATH, "MAX_AUX_INPUTS"), multi_air.max_aux_inputs() as u64);
        assert_eq!(masm_const(HOOK_PATH, "NUM_AUX_INPUTS"), 0);
        assert_eq!(masm_const(HOOK_PATH, "NUM_CHIPLETS"), multi_air.airs().len() as u64);
        for (i, expected) in PVM_PREPROCESSED_COMMITMENT.into_iter().enumerate() {
            assert_eq!(
                masm_const(RELATION_PATH, &alloc::format!("PREPROCESSED_COMMITMENT_{i}")),
                expected,
                "PVM trusted setup commitment limb {i} drifted"
            );
        }
    }

    #[test]
    fn pvm_masm_read_layout_matches_every_codegen_boundary() {
        const READ_START: u64 = 3_225_432_064;
        const NEXT_VM_REGION: u64 = 3_238_002_688;
        const LAYOUT_PATH: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../lib/core/asm/sys/pvm/layout.masm");

        let canonical = build_canonical_precompile_ace_circuit().expect("PVM canonical circuit");
        let layout = canonical.layout();
        let boundaries = [
            ("PUBLIC_INPUTS_PTR", InputKey::Public(0)),
            ("AUX_RAND_ELEM_PTR", InputKey::AuxRandBeta),
            ("PREPROCESSED_CURRENT_PTR", InputKey::Preprocessed { offset: 0, index: 0 }),
            ("MAIN_CURRENT_PTR", InputKey::Main { offset: 0, index: 0 }),
            ("AUX_CURRENT_PTR", InputKey::AuxCoord { offset: 0, index: 0, coord: 0 }),
            (
                "QUOTIENT_CURRENT_PTR",
                InputKey::QuotientChunkCoord { offset: 0, chunk: 0, coord: 0 },
            ),
            ("PREPROCESSED_NEXT_PTR", InputKey::Preprocessed { offset: 1, index: 0 }),
            ("MAIN_NEXT_PTR", InputKey::Main { offset: 1, index: 0 }),
            ("AUX_NEXT_PTR", InputKey::AuxCoord { offset: 1, index: 0, coord: 0 }),
            (
                "QUOTIENT_NEXT_PTR",
                InputKey::QuotientChunkCoord { offset: 1, chunk: 0, coord: 0 },
            ),
            ("AUX_BUS_BOUNDARY_PTR", InputKey::AuxBusBoundary(0)),
            ("AUXILIARY_ACE_INPUTS_PTR", InputKey::Alpha),
        ];

        assert_eq!(layout.index(InputKey::Public(0)), Some(0));
        assert_eq!(
            layout.index(InputKey::AuxRandAlpha),
            layout.index(InputKey::AuxRandBeta).map(|index| index + 1),
            "the MASM randomness word is [beta, alpha]"
        );
        for (name, key) in boundaries {
            let index = layout.index(key).unwrap_or_else(|| panic!("missing {key:?}"));
            assert_eq!(
                masm_const(LAYOUT_PATH, name),
                READ_START + 2 * index as u64,
                "{name} does not match InputLayout::{key:?}"
            );
        }

        let stream_ptr = masm_const(LAYOUT_PATH, "ACE_CIRCUIT_STREAM_PTR");
        assert_eq!(stream_ptr, READ_START + 2 * layout.total_inputs as u64);
        let bus_gamma_ptr = masm_const(LAYOUT_PATH, "BUS_GAMMA_PTR");
        assert_eq!(bus_gamma_ptr, stream_ptr + PVM_CIRCUIT_SHAPE.2 as u64);
        let c_total_ptr = masm_const(LAYOUT_PATH, "C_TOTAL_PTR");
        assert_eq!(c_total_ptr, bus_gamma_ptr + 4);
        let current_trace_row_ptr = masm_const(LAYOUT_PATH, "CURRENT_TRACE_ROW_PTR");
        assert_eq!(current_trace_row_ptr, c_total_ptr + 4);
        let current_row_start = layout
            .index(InputKey::Preprocessed { offset: 0, index: 0 })
            .expect("current-row start");
        let next_row_start = layout
            .index(InputKey::Preprocessed { offset: 1, index: 0 })
            .expect("next-row start");
        let current_row_felts = next_row_start - current_row_start;
        let preprocessed_com_ptr = masm_const(LAYOUT_PATH, "PREPROCESSED_COM_PTR");
        assert_eq!(
            preprocessed_com_ptr,
            current_trace_row_ptr + current_row_felts as u64,
            "the query-row scratch extent must come from the codegen layout"
        );
        assert!(
            preprocessed_com_ptr + 4 <= NEXT_VM_REGION,
            "the complete PVM READ + stream + relation scratch allocation overlaps the next VM region"
        );
    }

    #[test]
    fn pvm_deep_query_hook_matches_commitment_group_geometry() {
        use miden_precompiles_air::{
            primitives::byte_pair_lut::TRACE_HEIGHT, stark_config::precompile_pcs_params,
        };

        const HOOK_PATH: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../lib/core/asm/sys/pvm/deep_queries.masm");

        let canonical = build_canonical_precompile_ace_circuit().expect("PVM canonical circuit");
        let layout = canonical.layout();
        let index = |key| layout.index(key).unwrap_or_else(|| panic!("missing {key:?}"));

        let preprocessed = index(InputKey::Main { offset: 0, index: 0 })
            - index(InputKey::Preprocessed { offset: 0, index: 0 });
        let main = index(InputKey::AuxCoord { offset: 0, index: 0, coord: 0 })
            - index(InputKey::Main { offset: 0, index: 0 });
        let aux = index(InputKey::QuotientChunkCoord { offset: 0, chunk: 0, coord: 0 })
            - index(InputKey::AuxCoord { offset: 0, index: 0, coord: 0 });
        let quotient = index(InputKey::Preprocessed { offset: 1, index: 0 })
            - index(InputKey::QuotientChunkCoord { offset: 0, chunk: 0, coord: 0 });

        for (name, width) in [
            ("PREPROCESSED_ROW_DOUBLE_WORDS", preprocessed),
            ("MAIN_ROW_DOUBLE_WORDS", main),
            ("AUX_ROW_DOUBLE_WORDS", aux),
            ("QUOTIENT_ROW_DOUBLE_WORDS", quotient),
        ] {
            assert_eq!(
                masm_const(HOOK_PATH, name) * 8,
                width as u64,
                "{name} does not match the aligned commitment-group width"
            );
        }

        let preprocessed_tree_depth =
            TRACE_HEIGHT.ilog2() + u32::from(precompile_pcs_params().log_blowup());
        assert_eq!(
            masm_const(HOOK_PATH, "PREPROCESSED_TREE_DEPTH"),
            preprocessed_tree_depth as u64
        );
        assert_eq!(
            masm_const(HOOK_PATH, "PREPROCESSED_INDEX_MASK"),
            (1u64 << preprocessed_tree_depth) - 1,
            "the setup-tree projection must retain exactly the low committed-depth bits"
        );
    }

    #[test]
    fn pvm_wrapper_matches_the_relation_contract() {
        use miden_core::utils::Matrix;
        use miden_lifted_air::{BaseAir, LiftedAir};

        assert_eq!(masm_const(PVM_WRAPPER_PATH, "NUM_CHIPLETS"), NUM_CHIPLETS as u64);
        let airs = ChipletAir::all();
        let derived_minima: Vec<u64> = airs
            .iter()
            .map(|air| {
                let periodic_min = air.max_periodic_length().max(2);
                let preprocessed_min =
                    air.preprocessed_trace().map(|trace| trace.height()).unwrap_or(0);
                let min_height = periodic_min.max(preprocessed_min);
                assert!(min_height.is_power_of_two());
                let log_height = min_height.ilog2();
                if let Some(fixed) = air.fixed_log_height() {
                    assert_eq!(fixed, log_height, "fixed AIR height drifted from its trace");
                }
                u64::from(log_height)
            })
            .collect();
        let masm_minima: Vec<u64> = airs
            .iter()
            .enumerate()
            .map(|(i, air)| {
                // Fixed-height instances are pinned as equalities in the wrapper; the shared
                // derivation still supplies the same value.
                let name = match air.fixed_log_height() {
                    Some(_) => alloc::format!("FIXED_LOG_HEIGHT_{i}"),
                    None => alloc::format!("MIN_LOG_HEIGHT_{i}"),
                };
                masm_const(PVM_WRAPPER_PATH, &name)
            })
            .collect();
        assert_eq!(masm_minima, derived_minima, "PVM wrapper per-AIR lower bounds drifted",);
        for (i, expected) in PVM_RELATION_DIGEST.into_iter().enumerate() {
            assert_eq!(
                masm_const(PVM_WRAPPER_PATH, &alloc::format!("RELATION_DIGEST_{i}")),
                expected,
                "PVM wrapper RELATION_DIGEST limb {i} drifted"
            );
        }
    }

    /// Checks the common estimator constants and bounds against the PVM configuration.
    ///
    /// Comparing only the final native and MASM levels would not detect a stale bound for a round
    /// that does not currently determine the result.
    #[test]
    fn pvm_security_masm_matches_air() {
        use miden_precompiles_air::security as pvm_security;

        let fractional_bits = pvm_security::FIXED_POINT_FRACTIONAL_BITS;
        let fixed_point_one = pvm_security::FIXED_POINT_ONE;
        let field_bits = miden_air::security::CHALLENGE_FIELD_BITS;
        let field_ceiling = field_bits.div_ceil(fixed_point_one) * fixed_point_one;
        for (name, expected) in [
            ("FP_SHIFT", u64::from(fractional_bits)),
            ("FP_ONE", fixed_point_one),
            ("MAX_Q16_FRACTION", fixed_point_one - 1),
            ("BITS_PER_QUERY_FP", pvm_security::BITS_PER_QUERY),
            ("CHALLENGE_FIELD_WHOLE_BITS", field_bits >> fractional_bits),
            ("CHALLENGE_FIELD_OFFSET_FP", field_ceiling - field_bits),
            ("SECURITY_CAP_BITS", pvm_security::SECURITY_CAP >> fractional_bits),
            ("FRI_FOLDING_BASE_BITS", pvm_security::FOLDING_BASE >> fractional_bits),
            ("LOG2_E_FP", pvm_security::LOG2_E),
            (
                "MAX_CONSTRAINT_DEGREE",
                (1u64 << miden_precompiles_air::stark_config::precompile_pcs_params().log_blowup())
                    + 1,
            ),
        ] {
            assert_eq!(
                masm_const(SECURITY_ESTIMATOR_PATH, name),
                expected,
                "common estimator {name} drifted from the PVM's native security constant"
            );
        }

        // The estimator omits five native security terms only while the PVM shape satisfies these
        // bounds. `pvm_canonical_ace_shape_matches_current_air` checks the stored shape against the
        // chiplet AIRs; the checks below fail if that shape leaves the estimator envelope.
        let air_shape = pvm_security::AIR_SHAPE;
        let lookup_coefficient = (u64::from(air_shape.lookup.max_message_width) + 2)
            * u64::from(air_shape.lookup.fractions_per_row);
        assert!(
            u64::from(air_shape.num_composed_constraints)
                <= masm_const(SECURITY_ESTIMATOR_PATH, "MAX_COMPOSED_CONSTRAINTS"),
            "the PVM composed-constraint count exceeds the estimator envelope"
        );
        assert!(
            u64::from(air_shape.max_constraint_degree)
                <= masm_const(SECURITY_ESTIMATOR_PATH, "MAX_CONSTRAINT_DEGREE"),
            "the PVM constraint degree exceeds the estimator envelope"
        );
        assert!(
            u64::from(air_shape.num_deep_terms.expect("the PVM uses DEEP composition"))
                <= masm_const(SECURITY_ESTIMATOR_PATH, "MAX_DEEP_TERMS"),
            "the PVM DEEP term count exceeds the estimator envelope"
        );
        assert!(
            lookup_coefficient >= masm_const(SECURITY_ESTIMATOR_PATH, "MIN_LOOKUP_COEFFICIENT"),
            "the PVM lookup coefficient falls below the estimator envelope"
        );
        assert!(
            lookup_coefficient <= masm_const(SECURITY_ESTIMATOR_PATH, "MAX_LOOKUP_COEFFICIENT"),
            "the PVM lookup coefficient exceeds the estimator envelope"
        );
        assert!(
            u64::from(pvm_security::FIXED_BOUNDARY_LOOKUP_TERMS)
                <= masm_const(SECURITY_ESTIMATOR_PATH, "MAX_BOUNDARY_TERMS"),
            "the PVM boundary-term count exceeds the estimator envelope"
        );
        assert_eq!(
            masm_const(PVM_WRAPPER_PATH, "LOG_HEIGHT_MAX"),
            masm_const(SECURITY_ESTIMATOR_PATH, "MAX_LOG_HEIGHT"),
            "the PVM height bound drifted from the estimator envelope"
        );
        // BytePairLut has a fixed log height of 16, so the maximum PVM trace height can never fall
        // below the estimator's minimum of 6.
        assert!(
            masm_const(PVM_WRAPPER_PATH, "FIXED_LOG_HEIGHT_3")
                >= masm_const(SECURITY_ESTIMATOR_PATH, "MIN_LOG_HEIGHT"),
            "the PVM height floor fell below the estimator envelope"
        );
        assert_eq!(
            masm_const(GENERIC_UTILS_PATH, "POW_BITS_MAX"),
            masm_const(SECURITY_ESTIMATOR_PATH, "MAX_POW_BITS"),
            "the grinding bound drifted from the estimator envelope"
        );

        for (name, expected) in [
            ("LOOKUP_POW_BITS", u64::from(pvm_security::LOOKUP_POW_BITS)),
            ("MAX_MESSAGE_WIDTH", u64::from(pvm_security::AIR_SHAPE.lookup.max_message_width)),
            (
                "NUM_COMPOSED_CONSTRAINTS",
                u64::from(pvm_security::AIR_SHAPE.num_composed_constraints),
            ),
            (
                "MAX_CONSTRAINT_DEGREE",
                u64::from(pvm_security::AIR_SHAPE.max_constraint_degree),
            ),
            (
                "NUM_DEEP_TERMS",
                u64::from(
                    pvm_security::AIR_SHAPE.num_deep_terms.expect("the PVM uses DEEP composition"),
                ),
            ),
            (
                "LOOKUP_FRACTIONS_PER_ROW",
                u64::from(pvm_security::AIR_SHAPE.lookup.fractions_per_row),
            ),
            (
                "FIXED_BOUNDARY_LOOKUP_TERMS",
                u64::from(pvm_security::FIXED_BOUNDARY_LOOKUP_TERMS),
            ),
        ] {
            assert_eq!(
                masm_const(PVM_WRAPPER_PATH, name),
                expected,
                "PVM wrapper {name} drifted from its native security constant"
            );
        }
    }

    #[test]
    fn pvm_masm_quotient_inputs_match_the_stark_domain() {
        const EVALUATOR_PATH: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../lib/core/asm/sys/pvm/constraints_eval.masm");

        let canonical = build_canonical_precompile_ace_circuit().expect("PVM canonical circuit");
        let num_chunks = canonical.layout().counts.num_quotient_chunks;
        assert!(num_chunks.is_power_of_two());
        let expected = miden_lifted_stark::quotient_recomposition_inputs::<Felt>(
            num_chunks.ilog2() as u8,
            miden_precompiles_air::stark_config::precompile_pcs_params().log_blowup(),
        )
        .expect("PVM quotient degree fits the PCS blowup");

        assert_eq!(
            Felt::new(masm_const(EVALUATOR_PATH, "QUOTIENT_SHIFT_RATIO")).unwrap(),
            expected.shift_ratio
        );
        assert_eq!(
            Felt::new(masm_const(EVALUATOR_PATH, "QUOTIENT_FIRST_SHIFT")).unwrap(),
            expected.first_shift
        );
        assert_eq!(
            Felt::new(masm_const(EVALUATOR_PATH, "QUOTIENT_FIRST_WEIGHT")).unwrap(),
            expected.first_weight
        );
    }

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

    /// The external assertion is part of the production relation but excluded from the ACE
    /// circuit digest. This test guards its cardinality; raw bus-balance tests cover the
    /// underlying lookup semantics independently.
    #[test]
    fn chiplet_multi_air_exposes_the_sigma_closure() {
        use miden_lifted_air::{LiftedAir, MultiAir};
        use miden_precompiles_air::ChipletMultiAir;

        let challenges = [
            QuadFelt::new([Felt::from(3u32), Felt::from(5u32)]),
            QuadFelt::new([Felt::from(7u32), Felt::from(11u32)]),
        ];
        let multi_air = ChipletMultiAir::new();
        let aux_values: Vec<Vec<QuadFelt>> = multi_air
            .airs()
            .iter()
            .enumerate()
            .map(|(i, air)| {
                (0..air.num_aux_values())
                    .map(|j| {
                        QuadFelt::new([
                            Felt::from((i + j + 1) as u32),
                            Felt::from((2 * i + j + 1) as u32),
                        ])
                    })
                    .collect()
            })
            .collect();
        let aux_refs: Vec<&[QuadFelt]> = aux_values.iter().map(Vec::as_slice).collect();

        let assertions = multi_air
            .eval_external(&challenges, &[Felt::ZERO; 4], &[], &aux_refs, &[0; NUM_CHIPLETS])
            .expect("fixed boundary denominators are non-zero for the fixture");

        assert_eq!(assertions.len(), 1, "the relation exposes exactly one external assertion");
        assert_ne!(assertions[0], QuadFelt::ZERO, "the closure fixture must be non-vacuous");
    }

    /// The circuit digest binds the generated circuit but not the external assertion, so each
    /// protocol version pins that assertion's exact value on a fixed, non-zero fixture. The
    /// fixture is spelled out rather than derived from `num_aux_values`, so a change to either
    /// the assertion's semantics or the relation's aux shape lands here instead of silently
    /// producing a different input.
    #[test]
    fn external_assertion_matches_the_protocol_version() {
        use miden_lifted_air::MultiAir;
        use miden_precompiles_air::ChipletMultiAir;

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

        let actual = ChipletMultiAir::new()
            .eval_external(&challenges, &[Felt::ZERO; 4], &[], &aux_refs, &[0; NUM_CHIPLETS])
            .expect("fixture denominators are non-zero");
        let expected = match crate::ace_constants::PVM_PROTOCOL_ID {
            2 => QuadFelt::new([
                Felt::new_unchecked(17_120_654_257_594_545_925),
                Felt::new_unchecked(12_713_559_468_620_802_518),
            ]),
            version => panic!("add an external-assertion vector for protocol version {version}"),
        };

        assert_eq!(actual.as_slice(), &[expected]);
    }

    /// The chiplet instance order fixes proof-order tie-breaks and the relation digest.
    /// Intentional changes require regenerated protocol constants and a breaking changelog entry.
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
        ];
        assert_eq!(
            ChipletAir::all(),
            pinned,
            "chiplet instance order moved; run `make regenerate-pvm-constants` for an \
             intentional protocol break"
        );
    }
}
