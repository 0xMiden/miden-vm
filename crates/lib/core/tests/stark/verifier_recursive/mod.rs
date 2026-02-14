use alloc::vec::Vec;

use miden_air::ProcessorAir;
use miden_core::{Felt, FieldElement, QuadFelt, ToElements, WORD_SIZE, Word};
use miden_processor::crypto::RpoRandomCoin;
use miden_utils_testing::{
    MIN_STACK_DEPTH, VerifierError,
    crypto::{MerkleStore, Poseidon2, RandomCoin},
};
use winter_air::{
    Air,
    proof::{Proof, merge_ood_evaluations},
};
use winter_fri::VerifierChannel as FriVerifierChannel;

mod channel;
use channel::VerifierChannel;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerifierData {
    pub initial_stack: Vec<u64>,
    pub advice_stack: Vec<u64>,
    pub store: MerkleStore,
    pub advice_map: Vec<(Word, Vec<Felt>)>,
}

pub fn generate_advice_inputs(
    proof: Proof,
    pub_inputs: <ProcessorAir as Air>::PublicInputs,
) -> Result<VerifierData, VerifierError> {
    // we compute the number of procedures in the kernel
    // the public inputs contain, in addition to the kernel procedure roots:
    //
    // 1. The input operand stack (16 field elements),
    // 2. The output operand stack (16 field elements),
    // 3. The program hash (4 field elements).
    let pub_inputs_elements = pub_inputs.to_elements();
    let num_elements_pi = pub_inputs_elements.len();
    // note that since we are padding the fixed length inputs, in our case the program digest, to
    // be double-word aligned, we have to subtract `2 * WORD_SIZE` instead of `WORD_SIZE` for
    // the program digest
    let digests_elements = num_elements_pi - MIN_STACK_DEPTH * 2 - 2 * WORD_SIZE;
    assert_eq!(digests_elements % WORD_SIZE, 0);
    let num_kernel_procedures_digests = digests_elements / (2 * WORD_SIZE);

    // we need to provide the following instance specific data through the operand stack
    let initial_stack = vec![
        proof.context.options().grinding_factor() as u64,
        proof.context.options().num_queries() as u64,
        proof.context.trace_info().length().ilog2() as u64,
    ];

    // build a seed for the public coin; the initial seed is the hash of public inputs and proof
    // context, but as the protocol progresses, the coin will be reseeded with the info received
    // from the prover
    let mut advice_stack = vec![digests_elements as u64];
    let mut public_coin_seed = proof.context.to_elements();
    public_coin_seed.extend_from_slice(&pub_inputs_elements);

    // add the public inputs, which is nothing but the input and output stacks to the VM as well as
    // the digests of the procedures making up the kernel against which the program was compiled,
    // to the advice tape
    let pub_inputs_int: Vec<u64> =
        pub_inputs_elements.iter().map(|a| a.as_canonical_u64()).collect();
    advice_stack.extend_from_slice(&pub_inputs_int);

    // add a placeholder for the auxiliary randomness
    let aux_rand_insertion_index = advice_stack.len();
    advice_stack.extend_from_slice(&[0, 0, 0, 0]);
    advice_stack.push(num_kernel_procedures_digests as u64);

    // create AIR instance for the computation specified in the proof
    let air = ProcessorAir::new(proof.trace_info().to_owned(), pub_inputs, proof.options().clone());
    let seed_digest = Poseidon2::hash_elements(&public_coin_seed);
    let mut public_coin: RpoRandomCoin = RpoRandomCoin::new(seed_digest);
    let mut channel = VerifierChannel::new(&air, proof)?;

    // 1 ----- main segment trace -----------------------------------------------------------------
    let trace_commitments = channel.read_trace_commitments();

    // reseed the coin with the commitment to the main segment trace
    public_coin.reseed(trace_commitments[0]);
    advice_stack.extend_from_slice(&digest_to_int_vec(trace_commitments));

    // 2 ----- auxiliary segment trace ------------------------------------------------------------

    // generate the auxiliary random elements
    let mut aux_trace_rand_elements = vec![];
    for commitment in trace_commitments.iter().skip(1) {
        let rand_elements: Vec<QuadFelt> = air
            .get_aux_rand_elements(&mut public_coin)
            .map_err(|_| VerifierError::RandomCoinError)?
            .rand_elements()
            .to_vec();
        aux_trace_rand_elements.push(rand_elements);
        public_coin.reseed(*commitment);
    }

    let alpha = aux_trace_rand_elements[0][0].to_owned();
    let beta = aux_trace_rand_elements[0][2].to_owned();
    advice_stack[aux_rand_insertion_index] = QuadFelt::base_element(&beta, 0).as_canonical_u64();
    advice_stack[aux_rand_insertion_index + 1] =
        QuadFelt::base_element(&beta, 1).as_canonical_u64();
    advice_stack[aux_rand_insertion_index + 2] =
        QuadFelt::base_element(&alpha, 0).as_canonical_u64();
    advice_stack[aux_rand_insertion_index + 3] =
        QuadFelt::base_element(&alpha, 1).as_canonical_u64();

    // 3 ----- constraint composition trace -------------------------------------------------------

    // build random coefficients for the composition polynomial. we don't need them but we have to
    // generate them in order to update the random coin
    let _constraint_coeffs: winter_air::ConstraintCompositionCoefficients<QuadFelt> = air
        .get_constraint_composition_coefficients(&mut public_coin)
        .map_err(|_| VerifierError::RandomCoinError)?;

    let constraint_commitment = channel.read_constraint_commitment();
    advice_stack.extend_from_slice(&digest_to_int_vec(&[constraint_commitment]));
    public_coin.reseed(constraint_commitment);

    // 4 ----- OOD frames --------------------------------------------------------------

    // generate the the OOD point
    let _z: QuadFelt = public_coin.draw().unwrap();

    // read the main and auxiliary segments' OOD frames and add them to advice tape
    let ood_trace_frame = channel.read_ood_trace_frame();
    let ood_constraint_evaluations = channel.read_ood_constraint_evaluations();
    let ood_evals = merge_ood_evaluations(&ood_trace_frame, &ood_constraint_evaluations);

    // placeholder for the alpha_deep
    let alpha_deep_index = advice_stack.len();
    advice_stack.extend_from_slice(&[0, 0]);

    // add OOD evaluations to advice stack
    advice_stack.extend_from_slice(&to_int_vec(&ood_evals));

    // reseed with the digest of the OOD evaluations
    let ood_digest = Poseidon2::hash_elements(&ood_evals);
    public_coin.reseed(ood_digest);

    // 5 ----- FRI  -------------------------------------------------------------------------------

    // read the FRI layer commitments as well as remainder polynomial
    let fri_commitments_digests = channel.read_fri_layer_commitments();
    let poly = channel.read_remainder().unwrap();

    // add the above to the advice tape
    let fri_commitments: Vec<u64> = digest_to_int_vec(&fri_commitments_digests);
    advice_stack.extend_from_slice(&fri_commitments);
    advice_stack.extend_from_slice(&to_int_vec(&poly));

    // reseed with FRI layer commitments
    let deep_coefficients = air
        .get_deep_composition_coefficients::<QuadFelt, RpoRandomCoin>(&mut public_coin)
        .map_err(|_| VerifierError::RandomCoinError)?;

    // since we are using Horner batching, the randomness will be located in the penultimate
    // position, the last position holds the constant `1`
    assert_eq!(
        deep_coefficients.constraints[deep_coefficients.constraints.len() - 1],
        QuadFelt::ONE
    );
    let alpha_deep = deep_coefficients.constraints[deep_coefficients.constraints.len() - 2];
    advice_stack[alpha_deep_index] = alpha_deep.base_element(0).as_canonical_u64();
    advice_stack[alpha_deep_index + 1] = alpha_deep.base_element(1).as_canonical_u64();

    let layer_commitments = fri_commitments_digests.clone();
    for commitment in layer_commitments.iter() {
        public_coin.reseed(*commitment);
        let _alpha: QuadFelt = public_coin.draw().expect("failed to draw random indices");
    }

    // 6 ----- trace and constraint queries -------------------------------------------------------

    // read proof-of-work nonce sent by the prover and draw pseudo-random query positions for
    // the LDE domain from the public coin
    let pow_nonce = channel.read_pow_nonce();
    let mut query_positions = public_coin
        .draw_integers(air.options().num_queries(), air.lde_domain_size(), pow_nonce)
        .map_err(|_| VerifierError::RandomCoinError)?;
    advice_stack.extend_from_slice(&[pow_nonce]);
    query_positions.sort();
    query_positions.dedup();

    // read advice maps and Merkle paths of the queries to main/aux and constraint composition
    // traces
    let (mut main_aux_adv_map, mut partial_trees_traces) =
        channel.read_queried_trace_states(&query_positions)?;
    let (mut constraint_adv_map, partial_tree_constraint) =
        channel.read_constraint_evaluations(&query_positions)?;

    let (mut partial_trees_fri, mut fri_adv_map) = channel.unbatch_fri_layer_proofs::<4>(
        &query_positions,
        air.lde_domain_size(),
        fri_commitments_digests,
    );

    // consolidate advice maps
    main_aux_adv_map.append(&mut constraint_adv_map);
    main_aux_adv_map.append(&mut fri_adv_map);

    // build the full MerkleStore
    partial_trees_fri.append(&mut partial_trees_traces);
    partial_trees_fri.push(partial_tree_constraint);
    let mut store = MerkleStore::new();
    for partial_tree in &partial_trees_fri {
        store.extend(partial_tree.inner_nodes());
    }

    Ok(VerifierData {
        initial_stack,
        advice_stack,
        store,
        advice_map: main_aux_adv_map,
    })
}

// HELPER FUNCTIONS
// ================================================================================================

pub fn digest_to_int_vec(digest: &[Word]) -> Vec<u64> {
    digest
        .iter()
        .flat_map(|digest| digest.as_elements().iter().map(|e| e.as_canonical_u64()))
        .collect()
}

pub fn to_int_vec(ext_felts: &[QuadFelt]) -> Vec<u64> {
    QuadFelt::slice_as_base_elements(ext_felts)
        .iter()
        .map(|e| e.as_canonical_u64())
        .collect()
}
