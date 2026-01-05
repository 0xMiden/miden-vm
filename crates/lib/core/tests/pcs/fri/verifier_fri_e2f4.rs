use core::{marker::PhantomData, mem};

use miden_core::{EMPTY_WORD, Felt, FieldElement, QuadFelt, Word};
use miden_processor::crypto::{Hasher, RandomCoin, WinterRandomCoin};
use miden_utils_testing::{
    MerkleTreeVC, PrimeField64,
    crypto::{MerklePath, NodeIndex, PartialMerkleTree, Rpo256 as MidenHasher},
    group_slice_elements,
    math::fft,
};
use winter_fri::{
    DefaultProverChannel, FriOptions, FriProof, FriProver, VerifierError, folding::fold_positions,
};

use super::channel::{MidenFriVerifierChannel, UnBatch};

const MAX_REMAINDER_POLY_DEGREE: usize = 128;
const FRI_FOLDING_FACTOR: usize = 4;
const BLOWUP_FACTOR: usize = 8;
const NUM_FRI_QUERIES: usize = 32;

type AdvMap = Vec<(Word, Vec<Felt>)>;

pub struct FriResult {
    /// A vector containing the Merkle authentication paths used to authenticate the queries.
    pub partial_trees: Vec<PartialMerkleTree>,

    /// A map used to unhash Merkle nodes to a sequence of field elements representing the
    /// query-values.
    pub advice_maps: AdvMap,

    /// A vector of consecutive quadruples of the form (poe, p, e1, e0) where p is index of the
    /// query at the first layer and (e1, e0) is its corresponding evaluation and poe is g^p with g
    /// being the initial domain generator.
    pub positions: Vec<u64>,

    /// A vector of tuples representing the folding challenges.
    pub alphas: Vec<u64>,

    /// A vector of consecutive quadruples (c3, c2, c1, c0) representing the Merkle tree layer
    /// commitments.
    pub commitments: Vec<u64>,

    /// The remainder codeword as consecutive (r0, r1).
    pub remainder: Vec<u64>,

    /// The number of queries contained in the current FRI proof.
    pub num_queries: usize,
}

// This function proves and then verifies a FRI proof with the following fixed parameters:
//  1) Max remainder codeword (1 << 6).
//  2) Blow up factor 8.
//  3) Folding factor 4.
//
//  The main purpose of this function is to build the non-deterministic inputs needed to verify
//  a FRI proof inside the Miden VM.
//  The output is organized as follows:
pub fn fri_prove_verify_fold4_ext2(trace_length_e: usize) -> Result<FriResult, VerifierError> {
    let trace_length = 1 << trace_length_e;
    let lde_blowup = BLOWUP_FACTOR;
    let max_remainder_size = MAX_REMAINDER_POLY_DEGREE;
    let folding_factor = FRI_FOLDING_FACTOR;
    let nonce = 0_u64;

    let options = FriOptions::new(lde_blowup, folding_factor, max_remainder_size);
    let mut channel = build_prover_channel(trace_length, &options);
    let evaluations = build_evaluations(trace_length, lde_blowup);

    // instantiate the prover and generate the proof
    let mut prover = FriProver::<_, _, _, MerkleTreeVC<MidenHasher>>::new(options.clone());
    prover.build_layers(&mut channel, evaluations.clone());
    let positions = channel.draw_query_positions(nonce);
    let proof = prover.build_proof(&positions);

    // make sure the proof can be verified
    let commitments = channel.layer_commitments().to_vec();

    let max_degree = trace_length - 1;
    let result = verify_proof(
        proof.clone(),
        commitments.clone(),
        &evaluations,
        max_degree,
        trace_length * lde_blowup,
        &positions,
        &options,
    );
    let commitments: Vec<u64> = channel
        .layer_commitments()
        .to_vec()
        .iter()
        .flat_map(|digest| digest.as_elements().iter().map(|e| e.as_canonical_u64()))
        .collect();

    let remainder_poly: Vec<QuadFelt> =
        proof.parse_remainder().expect("should return remainder polynomial");
    let remainder: Vec<u64> = QuadFelt::slice_as_base_elements(&remainder_poly[..])
        .to_owned()
        .iter()
        .map(|a| a.as_canonical_u64())
        .collect();

    match result {
        Ok(((partial_trees, advice_maps), all_position_evaluation, alphas)) => Ok(FriResult {
            partial_trees,
            advice_maps,
            positions: all_position_evaluation,
            alphas,
            commitments,
            remainder,
            num_queries: positions.len(),
        }),
        Err(err) => Err(err),
    }
}

// HELPER UTILS
// ================================================================================================

pub fn build_prover_channel(
    trace_length: usize,
    options: &FriOptions,
) -> DefaultProverChannel<QuadFelt, MidenHasher, WinterRandomCoin<MidenHasher>> {
    DefaultProverChannel::new(trace_length * options.blowup_factor(), NUM_FRI_QUERIES)
}

pub fn build_evaluations(trace_length: usize, lde_blowup: usize) -> Vec<QuadFelt> {
    let mut p = (0..trace_length as u32)
        .map(|i| (i, i))
        .map(|(i, j)| QuadFelt::new_complex(i.into(), j.into()))
        .collect::<Vec<_>>();
    let domain_size = trace_length * lde_blowup;
    p.resize(domain_size, QuadFelt::ZERO);

    let twiddles = fft::get_twiddles::<Felt>(domain_size);

    fft::evaluate_poly(&mut p, &twiddles);
    p
}

#[expect(clippy::type_complexity)]
fn verify_proof(
    proof: FriProof,
    commitments: Vec<<MidenHasher as Hasher>::Digest>,
    evaluations: &[QuadFelt],
    max_degree: usize,
    domain_size: usize,
    positions: &[usize],
    options: &FriOptions,
) -> Result<((Vec<PartialMerkleTree>, AdvMap), Vec<u64>, Vec<u64>), VerifierError> {
    let mut channel = MidenFriVerifierChannel::<QuadFelt, MidenHasher>::new(
        proof,
        commitments.clone(),
        domain_size,
        options.folding_factor(),
    )
    .unwrap();
    let mut coin = WinterRandomCoin::new(&[]);

    let miden_verifier =
        FriVerifierFold4Ext2::new(&mut channel, &mut coin, options.clone(), max_degree)?;

    let queried_evaluations = positions.iter().map(|&p| evaluations[p]).collect::<Vec<_>>();

    let result =
        miden_verifier.verify_fold_4_ext_2(&mut channel, &queried_evaluations, positions)?;

    Ok(result)
}

/// Partial implementation for verification in the case of folding factor 4
pub struct FriVerifierFold4Ext2 {
    domain_size: usize,
    domain_generator: Felt,
    layer_commitments: Vec<Word>,
    layer_alphas: Vec<QuadFelt>,
    options: FriOptions,
    _channel: PhantomData<MidenFriVerifierChannel<QuadFelt, MidenHasher>>,
}

impl FriVerifierFold4Ext2 {
    pub fn new(
        channel: &mut MidenFriVerifierChannel<QuadFelt, MidenHasher>,
        public_coin: &mut WinterRandomCoin<MidenHasher>,
        options: FriOptions,
        max_poly_degree: usize,
    ) -> Result<Self, VerifierError> {
        assert_eq!(options.blowup_factor(), BLOWUP_FACTOR);
        assert_eq!(options.folding_factor(), FRI_FOLDING_FACTOR);

        // infer evaluation domain info
        let domain_size = max_poly_degree.next_power_of_two() * options.blowup_factor();
        let domain_generator = Felt::get_root_of_unity(domain_size.ilog2());

        // read layer commitments from the channel and use them to build a list of alphas
        let layer_commitments = channel.read_fri_layer_commitments();
        let mut layer_alphas = Vec::with_capacity(layer_commitments.len());
        let mut max_degree_plus_1 = max_poly_degree + 1;
        for (depth, commitment) in layer_commitments.iter().enumerate() {
            public_coin.reseed(*commitment);
            let alpha = public_coin.draw().map_err(VerifierError::RandomCoinError)?;
            layer_alphas.push(alpha);

            // make sure the degree can be reduced by the folding factor at all layers
            // but the remainder layer
            if depth != layer_commitments.len() - 1
                && !max_degree_plus_1.is_multiple_of(options.folding_factor())
            {
                return Err(VerifierError::DegreeTruncation(
                    max_degree_plus_1 - 1,
                    options.folding_factor(),
                    depth,
                ));
            }
            max_degree_plus_1 /= options.folding_factor();
        }

        Ok(FriVerifierFold4Ext2 {
            domain_size,
            domain_generator,
            layer_commitments,
            layer_alphas,
            options,
            _channel: PhantomData,
        })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns size of the domain over which a polynomial commitment checked by this verifier
    /// has been evaluated.
    ///
    /// The domain size can be computed by rounding `max_poly_degree` to the next power of two
    /// and multiplying the result by the `blowup_factor` from the protocol options.
    pub fn domain_size(&self) -> usize {
        self.domain_size
    }

    /// Verifier in the setting of (folding_factor, blowup_factor, extension_degree) = (4, (1 << 3),
    /// 2)
    #[expect(clippy::type_complexity)]
    fn verify_fold_4_ext_2(
        &self,
        channel: &mut MidenFriVerifierChannel<QuadFelt, MidenHasher>,
        evaluations: &[QuadFelt],
        positions: &[usize],
    ) -> Result<((Vec<PartialMerkleTree>, AdvMap), Vec<u64>, Vec<u64>), VerifierError> {
        // 1 ----- verify the recursive components of the FRI proof -------------------------------
        let positions = positions.to_vec();
        let evaluations = evaluations.to_vec();
        let mut final_pos_eval: Vec<(usize, QuadFelt)> = vec![];
        let advice_provider =
            channel.unbatch::<4, 3>(&positions, self.domain_size(), self.layer_commitments.clone());

        let mut d_generator = self.domain_generator;
        let mut all_alphas = vec![];
        let mut all_position_evaluation = vec![];
        for (index, &position) in positions.iter().enumerate() {
            d_generator = self.domain_generator;
            let (cur_pos, evaluation, position_evaluation, alphas) = iterate_query_fold_4_quad_ext(
                &self.layer_alphas,
                &advice_provider.0,
                &advice_provider.1,
                position,
                self.options.num_fri_layers(self.domain_size()),
                self.domain_size(),
                &evaluations[index],
                &mut d_generator,
            )?;
            all_position_evaluation.extend_from_slice(&position_evaluation[..]);
            all_alphas = alphas;

            final_pos_eval.push((cur_pos, evaluation));
        }

        // 2 ----- verify the remainder of the FRI proof ------------------------------------------

        // read the remainder from the channel and make sure it matches with the columns
        // of the previous layer
        let remainder_commitment = self.layer_commitments.last().unwrap();
        let remainder_poly = channel.read_remainder(remainder_commitment)?;
        let offset = Felt::GENERATOR;
        for &(final_pos, final_eval) in final_pos_eval.iter() {
            let comp_eval = eval_horner_rev(
                &remainder_poly,
                offset * d_generator.exp_vartime(final_pos as u64),
            );
            if comp_eval != final_eval {
                return Err(VerifierError::InvalidRemainderFolding);
            }
        }

        Ok((advice_provider, all_position_evaluation, all_alphas))
    }
}

fn iterate_query_fold_4_quad_ext(
    layer_alphas: &[QuadFelt],
    partial_trees: &[PartialMerkleTree],
    key_val_map: &[(Word, Vec<Felt>)],
    position: usize,
    number_of_layers: usize,
    initial_domain_size: usize,
    evaluation: &QuadFelt,
    domain_generator: &mut Felt,
) -> Result<(usize, QuadFelt, Vec<u64>, Vec<u64>), VerifierError> {
    let mut cur_pos = position;
    let mut evaluation = *evaluation;
    let mut domain_size = initial_domain_size;
    let get_domain_offset = Felt::GENERATOR;

    let initial_domain_generator = *domain_generator;
    let norm_cst = Felt::get_root_of_unity(2).inv();
    let mut init_exp = initial_domain_generator.exp(position as u64);

    let arr = vec![evaluation];
    let a = QuadFelt::slice_as_base_elements(&arr);

    let position_evaluation = vec![
        a[0].as_canonical_u64(),
        a[1].as_canonical_u64(),
        position as u64,
        init_exp.as_canonical_u64(),
    ];

    let mut alphas = vec![];
    for depth in 0..number_of_layers {
        let target_domain_size = domain_size / FRI_FOLDING_FACTOR;

        let folded_pos = cur_pos % target_domain_size;

        // Assumes the num_partitions == 1
        let position_index = folded_pos;

        let tree_depth = target_domain_size.ilog2();

        let query_nodes = partial_trees[depth]
            .get_node(NodeIndex::new(tree_depth as u8, position_index as u64).unwrap())
            .unwrap();
        let query_values = &key_val_map
            .iter()
            .find(|(k, _)| *k == query_nodes)
            .expect("must contain the leaf values")
            .1;

        let query_values = [
            QuadFelt::new_complex(query_values[0], query_values[1]),
            QuadFelt::new_complex(query_values[2], query_values[3]),
            QuadFelt::new_complex(query_values[4], query_values[5]),
            QuadFelt::new_complex(query_values[6], query_values[7]),
        ];

        let query_value = query_values[cur_pos / target_domain_size];

        if evaluation != query_value {
            return Err(VerifierError::InvalidLayerFolding(depth));
        }

        let xs_new = match cur_pos / target_domain_size {
            0 => init_exp,
            1 => init_exp * norm_cst,
            2 => init_exp * (norm_cst * norm_cst),
            _ => init_exp * (norm_cst * norm_cst * norm_cst),
        } * get_domain_offset;

        init_exp = init_exp * init_exp * init_exp * init_exp;

        evaluation = {
            let f_minus_x = query_values[2];
            let f_x = query_values[0];
            let x_star = QuadFelt::from(xs_new);
            let alpha = layer_alphas[depth];

            let tmp0 = fri_2(f_x, f_minus_x, x_star, alpha);

            let f_minus_x = query_values[3];
            let f_x = query_values[1];
            let alpha = layer_alphas[depth];

            let tmp1 = fri_2(f_x, f_minus_x, x_star * QuadFelt::from(norm_cst.inv()), alpha);

            fri_2(tmp0, tmp1, x_star * x_star, alpha * alpha)
        };

        let arr = vec![layer_alphas[depth]];
        let a = QuadFelt::slice_as_base_elements(&arr);
        alphas.push(a[0].as_canonical_u64());
        alphas.push(a[1].as_canonical_u64());
        alphas.push(0);
        alphas.push(0);

        *domain_generator = (*domain_generator).exp((FRI_FOLDING_FACTOR as u32).into());
        cur_pos = folded_pos;
        domain_size /= FRI_FOLDING_FACTOR;
    }

    Ok((cur_pos, evaluation, position_evaluation, alphas))
}

impl UnBatch<QuadFelt, MidenHasher> for MidenFriVerifierChannel<QuadFelt, MidenHasher> {
    fn unbatch<const N: usize, const W: usize>(
        &mut self,
        positions_: &[usize],
        domain_size: usize,
        layer_commitments: Vec<Word>,
    ) -> (Vec<PartialMerkleTree>, Vec<(Word, Vec<Felt>)>) {
        let queries = self.layer_queries().clone();
        let mut current_domain_size = domain_size;
        let mut positions = positions_.to_vec();
        let depth = layer_commitments.len() - 1;

        let mut adv_key_map = vec![];
        let mut partial_trees = vec![];
        let mut layer_proofs = self.layer_proofs();
        for query in queries.iter().take(depth) {
            let mut folded_positions = fold_positions(&positions, current_domain_size, N);

            let layer_proof = layer_proofs.remove(0);

            let x = group_slice_elements::<QuadFelt, N>(query);
            let leaves: Vec<Word> = x.iter().map(|row| MidenHasher::hash_elements(row)).collect();
            let unbatched_proof = layer_proof.into_openings(&leaves, &folded_positions).unwrap();
            assert_eq!(x.len(), unbatched_proof.len());

            let nodes: Vec<[Felt; 4]> =
                leaves.iter().map(|leaf| [leaf[0], leaf[1], leaf[2], leaf[3]]).collect();

            let paths: Vec<MerklePath> =
                unbatched_proof.into_iter().map(|list| list.1.into()).collect();

            let iter_pos = folded_positions.iter_mut().map(|a| *a as u64);
            let nodes_tmp = nodes.clone();
            let iter_nodes = nodes_tmp.iter();
            let iter_paths = paths.into_iter();
            let mut tmp_vec = vec![];
            for (p, (node, path)) in iter_pos.zip(iter_nodes.zip(iter_paths)) {
                tmp_vec.push((p, Word::from(*node), path));
            }

            let new_set =
                PartialMerkleTree::with_paths(tmp_vec).expect("should not fail from paths");
            partial_trees.push(new_set);

            nodes.into_iter().zip(x.iter()).for_each(|(a, b)| {
                let mut value = QuadFelt::slice_as_base_elements(b).to_owned();
                value.extend(EMPTY_WORD);
                adv_key_map.push((a.to_owned().into(), value));
            });

            mem::swap(&mut positions, &mut folded_positions);
            current_domain_size /= N;
        }

        (partial_trees, adv_key_map)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn fri_2<E, B>(f_x: E, f_minus_x: E, x_star: E, alpha: E) -> E
where
    B: PrimeField64,
    E: FieldElement<BaseField = B>,
{
    (f_x + f_minus_x + ((f_x - f_minus_x) * alpha / x_star)) / E::ONE.double()
}

pub fn eval_horner_rev<E>(p: &[E], x: E::BaseField) -> E
where
    E: FieldElement,
{
    p.iter().fold(E::ZERO, |acc, &coeff| acc * E::from(x) + coeff)
}
