//! Fixture builders shared across signature integration tests and benchmarks.

use alloc::vec::Vec;

use miden_core::{Felt, Word};
use miden_signature::{
    Goldilocks, QuadExt, e2_105_w8 as e2_105,
    internal::{
        air8::Rpo8,
        merkle::{MerkleOpening, hash_row},
        proof::Poseidon2Proof,
        serialize,
        signer::Config,
    },
};
use miden_utils_testing::crypto::{MerklePath, MerkleStore, PartialMerkleTree, Poseidon2};

use super::{
    SigVerifierData,
    conversions::{
        absorb_base_group_full_rate, absorb_deep_poly_full_rate, absorb_ext_group_full_rate,
        append_base_group_full_rate_advice, append_deep_poly_full_rate_advice,
        append_ext_group_full_rate_advice, g4_to_felt4, g4_to_u64,
    },
    instance_seed_goldilocks, message_to_goldilocks, seed_from_label, sign_sig_w8, test_message,
    transcript::SigTranscript,
    verify_sig_w8,
};

pub(crate) struct SigFixture {
    pub(crate) config: Config,
    pub(crate) proof: Poseidon2Proof<QuadExt>,
    pub(crate) data: SigVerifierData,
    pub(crate) pk: e2_105::PublicKey,
    pub(crate) message: [Felt; 4],
}

pub(crate) fn build_fixture(seed: &[u8], msg_tag: u64) -> SigFixture {
    build_fixture_with_message(seed, test_message(msg_tag))
}

pub(crate) fn build_fixture_with_message(seed: &[u8], message: [Felt; 4]) -> SigFixture {
    let (sk, pk) = e2_105::keygen(seed_from_label(seed));
    let signature = sign_sig_w8(&sk, message);
    assert!(verify_sig_w8(&pk, message, &signature).is_ok());

    let config = Config::e2_105bit::<Rpo8>();
    let proof = serialize::deserialize_and_reconstruct::<Rpo8, QuadExt>(
        &signature,
        &config.stark,
        11,
        *pk.elements(),
        message_to_goldilocks(message),
        instance_seed_goldilocks(),
    )
    .expect("deserialization failed");

    let data = pack_proof_for_masm(&pk, message, &proof, &config);
    SigFixture { config, proof, data, pk, message }
}

/// Extract all proof components and pack into SigVerifierData for MASM execution.
pub(crate) fn pack_proof_for_masm(
    pk: &e2_105::PublicKey,
    message: [Felt; 4],
    proof: &Poseidon2Proof<QuadExt>,
    config: &Config,
) -> SigVerifierData {
    let stark = &config.stark;
    let pk_felts = *pk.elements();

    // ── Replay transcript to get query indices ──
    let instance_seed = super::transcript::compute_instance_seed();
    let pk_m = g4_to_felt4(&pk_felts);
    let msg_m = message;
    let mut t = SigTranscript::new(instance_seed, pk_m, msg_m);

    // Salted Fiat-Shamir: absorb the transcript salt immediately after init,
    // before any prover message (matches miden-signature's MasmTranscript::new).
    t.reseed_direct(g4_to_felt4(&proof.salt));

    t.reseed_direct(g4_to_felt4(&proof.witness_commitment));
    assert!(
        t.check_grind(proof.ali_nonce, stark.grinding.ali),
        "ALI grinding check failed during MASM fixture packing"
    );
    let _lambda = t.sample_ext();

    t.reseed_direct(g4_to_felt4(&proof.quotient_commitment));
    assert!(
        t.check_grind(proof.ood_nonce, stark.grinding.ood),
        "OOD grinding check failed during MASM fixture packing"
    );
    let _z = t.sample_ext();

    // Absorb OOD in point-major order: z-row then gz-row.
    absorb_ext_group_full_rate(&mut t, proof.witness_z.as_slice());
    absorb_base_group_full_rate(&mut t, proof.quotient_z.as_slice());
    absorb_ext_group_full_rate(&mut t, proof.witness_gz.as_slice());
    absorb_base_group_full_rate(&mut t, proof.quotient_gz.as_slice());

    assert!(
        t.check_grind(proof.prox_nonce, stark.grinding.prox),
        "PROX grinding check failed during MASM fixture packing"
    );
    let alpha_nd = t.sample_ext();
    let _beta = t.sample_ext();
    absorb_deep_poly_full_rate(&mut t, proof.deep_coeffs.as_slice());
    assert!(
        t.check_grind(proof.query_nonce, stark.grinding.query),
        "QUERY grinding check failed during MASM fixture packing"
    );
    let query_indices = t.sample_indices(11, stark.num_queries);

    // ── Build advice stack ──
    let mut adv = Vec::new();

    // Phase 0 salt: absorbed right after transcript init, before any commitment.
    adv.extend_from_slice(&g4_to_u64(&proof.salt));

    // Phase 1: witness commitment + ali nonce
    adv.extend_from_slice(&g4_to_u64(&proof.witness_commitment));
    adv.push(proof.ali_nonce);

    // Phase 2: quotient commitment + ood nonce
    adv.extend_from_slice(&g4_to_u64(&proof.quotient_commitment));
    adv.push(proof.ood_nonce);

    // Phase 3 prelude: non-deterministic deep alpha (validated later against
    // the transcript sample). alpha1 first so two adv_push ops leave
    // [alpha0, alpha1] on the operand stack.
    adv.push(alpha_nd[1].as_canonical_u64());
    adv.push(alpha_nd[0].as_canonical_u64());

    // Phase 3: OOD evaluations in point-major order: z-row then gz-row
    // [witness_z, quotient_z, witness_gz, quotient_gz].
    append_ext_group_full_rate_advice(&mut adv, proof.witness_z.as_slice());
    append_base_group_full_rate_advice(&mut adv, proof.quotient_z.as_slice());
    append_ext_group_full_rate_advice(&mut adv, proof.witness_gz.as_slice());
    append_base_group_full_rate_advice(&mut adv, proof.quotient_gz.as_slice());
    adv.push(proof.prox_nonce);

    // Phase 4: DEEP coefficients in padded descending order, rate-aligned.
    append_deep_poly_full_rate_advice(&mut adv, proof.deep_coeffs.as_slice());
    adv.push(proof.query_nonce);

    // ── Build Merkle store and advice map ──
    let mut store = MerkleStore::new();
    let mut advice_map: Vec<(Word, Vec<Felt>)> = Vec::new();

    extend_merkle_paths(
        &mut store,
        &mut advice_map,
        &query_indices,
        proof.witness_openings.as_slice(),
        "witness",
    );

    // Quotient tree (already base-field after flattening).
    extend_merkle_paths(
        &mut store,
        &mut advice_map,
        &query_indices,
        proof.quotient_openings.as_slice(),
        "quotient",
    );

    // ── ACE circuit instructions in advice map ──
    {
        let (constants, ops, _num_vars) = super::circuit_gen::build_sig_circuit();
        let stream = super::circuit_gen::encode_for_eval_circuit(
            &constants,
            &ops,
            super::circuit_gen::NUM_INPUTS,
        );
        let hash = super::circuit_gen::circuit_hash(&stream);
        let circuit_key = Word::new(hash);
        advice_map.push((circuit_key, stream));
    }

    // ── Operand stack: [pk, msg] ──
    let mut initial_stack = Vec::with_capacity(8);
    initial_stack.extend_from_slice(&g4_to_u64(&pk_felts));
    initial_stack.extend_from_slice(&message.map(|f| f.as_canonical_u64()));

    SigVerifierData {
        initial_stack,
        advice_stack: adv,
        store,
        advice_map,
    }
}

fn extend_merkle_paths(
    store: &mut MerkleStore,
    advice_map: &mut Vec<(Word, Vec<Felt>)>,
    query_indices: &[usize],
    openings: &[MerkleOpening],
    label: &'static str,
) {
    let mut paths: Vec<(u64, Word, MerklePath)> = Vec::new();
    for (i, &idx) in query_indices.iter().enumerate() {
        let opening = &openings[i];

        // Salted leaf digest: Poseidon2 sponge over the row with the per-leaf
        // salt loaded into the capacity (BCS hiding). Same as the MASM computes.
        let digest_g = hash_row(&opening.row, &opening.salt);
        let leaf_word = Word::new(g4_to_felt4(&digest_g));

        // Advice-map value: salt(4) ++ row. The MASM loads the salt into the
        // sponge capacity, then absorbs the row into the rate.
        let salt_felts = g4_to_felt4(&opening.salt);
        let row_felts = opening.row.iter().map(|&g| Felt::from(g));
        let mut leaf_adv = Vec::with_capacity(4 + opening.row.len());
        leaf_adv.extend_from_slice(&salt_felts);
        leaf_adv.extend(row_felts);
        advice_map.push((leaf_word, leaf_adv));

        let merkle_path =
            MerklePath::new(opening.path.iter().map(|s| Word::new(g4_to_felt4(s))).collect());
        // Query sampling is with replacement; Merkle tree reconstruction
        // needs at most one path per leaf index.
        if paths.iter().any(|(j, ..)| *j == idx as u64) {
            continue;
        }
        paths.push((idx as u64, leaf_word, merkle_path));
    }
    let tree = PartialMerkleTree::with_paths(paths)
        .unwrap_or_else(|_| panic!("{label} partial Merkle reconstruction should succeed"));
    store.extend(tree.inner_nodes());
}

pub(crate) fn sig_proof_key_from_stack(stack: &[u64]) -> Word {
    assert!(stack.len() >= 8, "expected [pk(4), msg(4)] on the operand stack");
    let pk = Word::new([
        Felt::new_unchecked(stack[0]),
        Felt::new_unchecked(stack[1]),
        Felt::new_unchecked(stack[2]),
        Felt::new_unchecked(stack[3]),
    ]);
    let msg = Word::new([
        Felt::new_unchecked(stack[4]),
        Felt::new_unchecked(stack[5]),
        Felt::new_unchecked(stack[6]),
        Felt::new_unchecked(stack[7]),
    ]);
    Poseidon2::merge(&[pk, msg])
}

pub(crate) fn advice_map_with_sig_proof(data: &SigVerifierData) -> Vec<(Word, Vec<Felt>)> {
    let mut map = data.advice_map.clone();
    extend_advice_map_with_sig_proof(&mut map, data);
    map
}

pub(crate) fn advice_map_with_sig_proofs(data: &[&SigVerifierData]) -> Vec<(Word, Vec<Felt>)> {
    let mut map = Vec::new();
    for data in data {
        map.extend(data.advice_map.clone());
        extend_advice_map_with_sig_proof(&mut map, data);
    }
    map
}

pub(crate) fn extend_advice_map_with_sig_proof(
    map: &mut Vec<(Word, Vec<Felt>)>,
    data: &SigVerifierData,
) {
    let key = sig_proof_key_from_stack(&data.initial_stack);
    let proof: Vec<Felt> = data.advice_stack.iter().map(|&v| Felt::new_unchecked(v)).collect();
    map.push((key, proof));
}
