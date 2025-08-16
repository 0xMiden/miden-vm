use alloc::vec::Vec;

use miden_air::ProcessorAir;
use miden_core::{Felt, FieldElement, QuadFelt, ToElements, WORD_SIZE, Word};
use miden_processor::crypto::RpoRandomCoin;
use miden_utils_testing::{
    MIN_STACK_DEPTH, VerifierError,
    crypto::{MerkleStore, RandomCoin, Rpo256},
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

/// Generates advice inputs required for recursive STARK proof verification in Miden VM.
///
/// During the course of its execution, the recursive verifier will make use of non-deterministic
/// advice data through the advice provider.
/// In what follows is a description of the expected layout per component of the advice provider.
/// We also include the expected layout of the operand stack for completness.
///
/// # Operand Stack Layout
///
/// ```
/// | Position | Content           | Size (in Felt) | Description                      |
/// | -------- | ----------------- | -------------- | -------------------------------- |
/// | 0        | grinding_factor   | 1              | Proof-of-work difficulty in bits |
/// | 1        | num_queries       | 1              | Number of FRI queries            |
/// | 2        | trace_length_log2 | 1              | Log2 of execution trace length   |
/// ```
///
/// # Advice Stack Layout
///
/// ```
/// | Position | Content                | Size (in Felt) | Description                                           |
/// | -------- | ---------------------- | -------------- | ----------------------------------------------------- |
/// | 0        | variable_len_pi_size   | 1              | Size of variable length PI in Felt                    |
/// | 1-n      | public_inputs_data     | varies         | Input/output stacks + Program digest + kernel digests |
/// | n+1-n+4  | aux_randomness         | 4              | β = (β₀, β₁), ɑ = (ɑ₀, ɑ₁)                            |
/// | n+5      | num_kernel_procedures  | 1              | Count of kernel procedure digests                     |
/// | n+6-m    | trace_commitments      | 4 or 8         | Main/auxiliary trace segment commitments              |
/// | m+1-p    | constraint_commitment  | 4              | Constraint composition commitment                     |
/// | p+1-p+2  | alpha_deep_randomness  | 2              | Deep composition randomness                           |
/// | p+3-q    | ood_evaluations        | varies         | Out-of-domain trace and constraint evals              |
/// | q+1-r    | fri_commitments        | varies         | FRI layer commitment digests                          |
/// | r+1-s    | fri_remainder_poly     | varies         | FRI remainder polynomial coefficients                 |
/// | s+1      | pow_nonce              | 1              | Proof-of-work nonce                                   |
/// ```
///
/// # Advice Merkle Store Content
///
/// ```
/// |         Merkle trees         |
/// | ---------------------------- |
/// | Main trace segment tree      |
/// | Auxiliary trace segment tree |
/// | Constraint composition tree  |
/// | FRI layers commitment trees  |
/// ```
///
/// # Advice Map Layout
///
/// ```
/// | Key (Word)                                               | Value (Vec<Felt>)                   |
/// | -------------------------------------------------------- | ----------------------------------- |
/// | Leaf hash of main trace segment tree at query index      | Main trace evaluations              |
/// | Leaf hash of auxiliary trace segment tree at query index | Auxiliary trace evaluations         |
/// | Leaf hash of constraint composition tree at query index  | Constraint evaluations              |
/// | FRI layer evaluations at folded query index              | FRI codeword evaluations on a coset |
/// ```
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
    let variable_len_pi_size = num_elements_pi - MIN_STACK_DEPTH * 2 - 2 * WORD_SIZE;
    assert_eq!(variable_len_pi_size % WORD_SIZE, 0);
    let num_kernel_procedures_digests = variable_len_pi_size / (2 * WORD_SIZE);

    // we need to provide the following instance specific data through the operand stack
    let initial_stack = vec![
        proof.context.options().grinding_factor() as u64,
        proof.context.options().num_queries() as u64,
        proof.context.trace_info().length().ilog2() as u64,
    ];

    // build a seed for the public coin; the initial seed is the hash of public inputs and proof
    // context, but as the protocol progresses, the coin will be reseeded with the info received
    // from the prover
    let mut advice_stack = vec![variable_len_pi_size as u64];
    let mut public_coin_seed = proof.context.to_elements();
    public_coin_seed.extend_from_slice(&pub_inputs_elements);

    // add the public inputs, which is nothing but the input and output stacks to the VM as well as
    // the digests of the procedures making up the kernel against which the program was compiled,
    // to the advice tape
    let pub_inputs_int: Vec<u64> = pub_inputs_elements.iter().map(|a| a.as_int()).collect();
    advice_stack.extend_from_slice(&pub_inputs_int);

    // add a placeholder for the auxiliary randomness
    let aux_rand_insertion_index = advice_stack.len();
    advice_stack.extend_from_slice(&[0, 0, 0, 0]);
    advice_stack.push(num_kernel_procedures_digests as u64);

    // create AIR instance for the computation specified in the proof
    let air = ProcessorAir::new(proof.trace_info().to_owned(), pub_inputs, proof.options().clone());
    let seed_digest = Rpo256::hash_elements(&public_coin_seed);
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
    advice_stack[aux_rand_insertion_index] = QuadFelt::base_element(&beta, 0).as_int();
    advice_stack[aux_rand_insertion_index + 1] = QuadFelt::base_element(&beta, 1).as_int();
    advice_stack[aux_rand_insertion_index + 2] = QuadFelt::base_element(&alpha, 0).as_int();
    advice_stack[aux_rand_insertion_index + 3] = QuadFelt::base_element(&alpha, 1).as_int();

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
    let ood_digest = Rpo256::hash_elements(&ood_evals);
    public_coin.reseed(ood_digest);

    // 5 ----- FRI  -------------------------------------------------------------------------------

    // read the FRI layer committments as well as remainder polynomial
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
    advice_stack[alpha_deep_index] = alpha_deep.base_element(0).as_int();
    advice_stack[alpha_deep_index + 1] = alpha_deep.base_element(1).as_int();

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
        .flat_map(|digest| digest.as_elements().iter().map(|e| e.as_int()))
        .collect()
}

pub fn to_int_vec(ext_felts: &[QuadFelt]) -> Vec<u64> {
    QuadFelt::slice_as_base_elements(ext_felts).iter().map(|e| e.as_int()).collect()
}
