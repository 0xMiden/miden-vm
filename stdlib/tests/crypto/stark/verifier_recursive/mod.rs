use alloc::vec::Vec;

//use miden_air::ProcessorAir;
use processor::crypto::RpoRandomCoin;
use test_utils::{
    VerifierError,
    crypto::{MerkleStore, RandomCoin, Rpo256, RpoDigest},
    math::{FieldElement, ToElements},
};
use vm_core::{BinomialExtensionField, Felt};
use winter_air::{Air, proof::Proof};
use winter_fri::VerifierChannel as FriVerifierChannel;

mod channel;
use channel::VerifierChannel;

pub type QuadExt = BinomialExtensionField<Felt, 2>;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerifierData {
    pub initial_stack: Vec<u64>,
    pub advice_stack: Vec<u64>,
    pub store: MerkleStore,
    pub advice_map: Vec<(RpoDigest, Vec<Felt>)>,
}

pub fn generate_advice_inputs(
    proof: Proof,
    pub_inputs: <ProcessorAir as Air>::PublicInputs,
) -> Result<VerifierData, VerifierError> {
    // we need to provide the following instance specific data through the operand stack
    let initial_stack = vec![
        proof.context.options().grinding_factor() as u64,
        proof.context.options().blowup_factor().ilog2() as u64,
        proof.context.options().num_queries() as u64,
        proof.context.trace_info().length().ilog2() as u64,
    ];

    // build a seed for the public coin; the initial seed is the hash of public inputs and proof
    // context, but as the protocol progresses, the coin will be reseeded with the info received
    // from the prover
    let mut advice_stack = vec![];
    let mut public_coin_seed = proof.context.to_elements();
    public_coin_seed.append(&mut pub_inputs.to_elements());

    // add the public inputs, which is nothing but the input and output stacks to the VM, to the
    // advice tape
    let pub_inputs_int: Vec<u64> = pub_inputs.to_elements().iter().map(|a| a.as_int()).collect();
    advice_stack.extend_from_slice(&pub_inputs_int[..]);

    // create AIR instance for the computation specified in the proof
    let air = ProcessorAir::new(proof.trace_info().to_owned(), pub_inputs, proof.options().clone());
    let seed_digest = Rpo256::hash_elements(&public_coin_seed);
    let mut public_coin: RpoRandomCoin = RpoRandomCoin::new(seed_digest.into());
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
        let rand_elements: Vec<QuadExt> = air
            .get_aux_rand_elements(&mut public_coin)
            .map_err(|_| VerifierError::RandomCoinError)?
            .rand_elements()
            .to_vec();
        aux_trace_rand_elements.push(rand_elements);
        public_coin.reseed(*commitment);
    }

    // 3 ----- constraint composition trace -------------------------------------------------------

    // build random coefficients for the composition polynomial. we don't need them but we have to
    // generate them in order to update the random coin
    let _constraint_coeffs: winter_air::ConstraintCompositionCoefficients<QuadExt> = air
        .get_constraint_composition_coefficients(&mut public_coin)
        .map_err(|_| VerifierError::RandomCoinError)?;
    let constraint_commitment = channel.read_constraint_commitment();
    advice_stack.extend_from_slice(&digest_to_int_vec(&[constraint_commitment]));
    public_coin.reseed(constraint_commitment);

    // 4 ----- OOD frames --------------------------------------------------------------

    // generate the the OOD point
    let _z: QuadExt = public_coin.draw().unwrap();

    // read the main and auxiliary segments' OOD frames and add them to advice tape
    let ood_trace_frame = channel.read_ood_trace_frame();
    let ood_main_trace_frame = ood_trace_frame.main_frame();
    let ood_aux_trace_frame = ood_trace_frame.aux_frame();

    // the expected layout is:
    // [main_current_elements, aux_current_elements, main_next_elements, aux_next_elements]
    let mut main_and_aux_frame_states = ood_main_trace_frame.current().to_vec();
    main_and_aux_frame_states.extend_from_slice(
        ood_aux_trace_frame
            .as_ref()
            .expect("execution trace should have an auxiliary segment")
            .current(),
    );
    main_and_aux_frame_states.extend_from_slice(ood_main_trace_frame.next());
    main_and_aux_frame_states.extend_from_slice(
        ood_aux_trace_frame
            .as_ref()
            .expect("execution trace should have an auxiliary segment")
            .next(),
    );

    advice_stack.extend_from_slice(&to_int_vec(&main_and_aux_frame_states));
    public_coin.reseed(Rpo256::hash_elements(&main_and_aux_frame_states));

    // read OOD evaluations of composition polynomial columns
    let ood_constraint_evaluations = channel.read_ood_constraint_evaluations();
    advice_stack.extend_from_slice(&to_int_vec(&ood_constraint_evaluations));
    public_coin.reseed(Rpo256::hash_elements(&ood_constraint_evaluations));

    // 5 ----- FRI  -------------------------------------------------------------------------------

    // read the FRI layer committments as well as remainder polynomial
    let fri_commitments_digests = channel.read_fri_layer_commitments();
    let poly = channel.read_remainder().unwrap();

    // add the above to the advice tape
    let fri_commitments: Vec<u64> = digest_to_int_vec(&fri_commitments_digests);
    advice_stack.extend_from_slice(&fri_commitments);
    advice_stack.extend_from_slice(&to_int_vec(&poly));

    // reseed with FRI layer commitments
    let _deep_coefficients = air
        .get_deep_composition_coefficients::<QuadExt, RpoRandomCoin>(&mut public_coin)
        .map_err(|_| VerifierError::RandomCoinError)?;
    let layer_commitments = fri_commitments_digests.clone();
    for commitment in layer_commitments.iter() {
        public_coin.reseed(*commitment);
        let _alpha: QuadExt = public_coin.draw().expect("failed to draw random indices");
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

pub fn digest_to_int_vec(digest: &[RpoDigest]) -> Vec<u64> {
    digest
        .iter()
        .flat_map(|digest| digest.as_elements().iter().map(|e| e.as_int()))
        .collect()
}

pub fn to_int_vec(ext_felts: &[QuadExt]) -> Vec<u64> {
    QuadExt::slice_as_base_elements(ext_felts).iter().map(|e| e.as_int()).collect()
}
