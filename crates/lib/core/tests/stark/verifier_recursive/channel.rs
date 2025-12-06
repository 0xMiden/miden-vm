use alloc::vec::Vec;

use miden_air::ProcessorAir;
use miden_core::{Felt, FieldElement, QuadFelt, StarkField, Word};
use miden_utils_testing::{
    MerkleTreeVC, VerifierError,
    crypto::{BatchMerkleProof, PartialMerkleTree, Rpo256},
    group_slice_elements,
};
use winter_air::{
    Air,
    proof::{Proof, Queries, QuotientOodFrame, Table, TraceOodFrame},
};
use winter_fri::{VerifierChannel as FriVerifierChannel, folding::fold_positions};

type AdvMap = Vec<(Word, Vec<Felt>)>;

/// A view into a [Proof] for a computation structured to simulate an "interactive" channel.
///
/// A channel is instantiated for a specific proof, which is parsed into structs over the
/// appropriate field (specified by type parameter `E`). This also validates that the proof is
/// well-formed in the context of the computation for the specified [Air].
pub struct VerifierChannel {
    // trace queries
    trace_roots: Vec<Word>,
    trace_queries: Option<TraceQueries>,
    // constraint queries
    constraint_root: Word,
    constraint_queries: Option<ConstraintQueries>,
    // FRI proof
    fri_roots: Option<Vec<Word>>,
    fri_layer_proofs: Vec<BatchMerkleProof<Rpo256>>,
    fri_layer_queries: Vec<Vec<QuadFelt>>,
    fri_remainder: Option<Vec<QuadFelt>>,
    fri_num_partitions: usize,
    // out-of-domain frame
    ood_trace_frame: Option<TraceOodFrame<QuadFelt>>,
    ood_constraint_evaluations: Option<QuotientOodFrame<QuadFelt>>,
    // query proof-of-work
    pow_nonce: u64,
}

impl VerifierChannel {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates and returns a new [VerifierChannel] initialized from the specified `proof`.
    pub fn new(air: &ProcessorAir, proof: Proof) -> Result<Self, VerifierError> {
        let Proof {
            context,
            commitments,
            trace_queries,
            constraint_queries,
            ood_frame,
            fri_proof,
            pow_nonce,
            num_unique_queries,
        } = proof;

        // make AIR and proof base fields are the same
        if Felt::get_modulus_le_bytes() != context.field_modulus_bytes() {
            return Err(VerifierError::InconsistentBaseField);
        }

        let num_trace_segments = air.trace_info().num_segments();
        let main_trace_width = air.trace_info().main_trace_width();
        let aux_trace_width = air.trace_info().aux_segment_width();
        let lde_domain_size = air.lde_domain_size();
        let fri_options = air.options().to_fri_options();
        let constraint_frame_width = air.context().num_constraint_composition_columns();

        // --- parse commitments ------------------------------------------------------------------
        let (trace_roots, constraint_root, fri_roots) = commitments
            .parse::<Rpo256>(num_trace_segments, fri_options.num_fri_layers(lde_domain_size))
            .map_err(|err| VerifierError::ProofDeserializationError(err.to_string()))?;
        // --- parse trace and constraint queries -------------------------------------------------
        let trace_queries = TraceQueries::new(trace_queries, air, num_unique_queries as usize)?;
        let constraint_queries =
            ConstraintQueries::new(constraint_queries, air, num_unique_queries as usize)?;

        // --- parse FRI proofs -------------------------------------------------------------------
        let fri_num_partitions = fri_proof.num_partitions();
        let fri_remainder = fri_proof
            .parse_remainder()
            .map_err(|err| VerifierError::ProofDeserializationError(err.to_string()))?;
        let (fri_layer_queries, fri_layer_proofs) = fri_proof
            .parse_layers::<QuadFelt, Rpo256, MerkleTreeVC<Rpo256>>(
                lde_domain_size,
                fri_options.folding_factor(),
            )
            .map_err(|err| VerifierError::ProofDeserializationError(err.to_string()))?;

        // --- parse out-of-domain evaluation frame -----------------------------------------------
        let (ood_trace_evaluations, ood_constraint_evaluations) = ood_frame
            .parse(main_trace_width, aux_trace_width, constraint_frame_width)
            .map_err(|err| VerifierError::ProofDeserializationError(err.to_string()))?;

        Ok(VerifierChannel {
            // trace queries
            trace_roots,
            trace_queries: Some(trace_queries),
            // constraint queries
            constraint_root,
            constraint_queries: Some(constraint_queries),
            // FRI proof
            fri_roots: Some(fri_roots),
            fri_layer_proofs,
            fri_layer_queries,
            fri_remainder: Some(fri_remainder),
            fri_num_partitions,
            // out-of-domain evaluation
            ood_trace_frame: Some(ood_trace_evaluations),
            ood_constraint_evaluations: Some(ood_constraint_evaluations),
            // query seed
            pow_nonce,
        })
    }

    // DATA READERS
    // --------------------------------------------------------------------------------------------

    /// Returns execution trace commitments sent by the prover.
    ///
    /// For computations requiring multiple trace segment, the returned slice will contain a
    /// commitment for each trace segment.
    pub fn read_trace_commitments(&self) -> &[Word] {
        &self.trace_roots
    }

    /// Returns constraint evaluation commitment sent by the prover.
    pub fn read_constraint_commitment(&self) -> Word {
        self.constraint_root
    }

    /// Returns trace polynomial evaluations at out-of-domain points z and z * g, where g is the
    /// generator of the LDE domain.
    ///
    /// For computations requiring multiple trace segments, evaluations of auxiliary trace
    /// polynomials are also included as the second value of the returned tuple. Otherwise, the
    /// second value is None.
    pub fn read_ood_trace_frame(&mut self) -> TraceOodFrame<QuadFelt> {
        self.ood_trace_frame.take().expect("already read")
    }

    /// Returns evaluations of composition polynomial columns at z, where z is the out-of-domain
    /// point.
    pub fn read_ood_constraint_evaluations(&mut self) -> QuotientOodFrame<QuadFelt> {
        self.ood_constraint_evaluations.take().expect("already read")
    }

    /// Returns query proof-of-work nonce sent by the prover.
    pub fn read_pow_nonce(&self) -> u64 {
        self.pow_nonce
    }

    /// Returns trace states at the specified positions of the LDE domain. This also checks if
    /// the trace states are valid against the trace commitment sent by the prover.
    ///
    /// For computations requiring multiple trace segments, trace states for auxiliary segments
    /// are also included as the second value of the returned tuple (trace states for all auxiliary
    /// segments are merged into a single table). Otherwise, the second value is None.
    pub fn read_queried_trace_states(
        &mut self,
        positions: &[usize],
    ) -> Result<(AdvMap, Vec<PartialMerkleTree>), VerifierError> {
        let queries = self.trace_queries.take().expect("already read");
        let proofs = queries.query_proofs;
        let main_queries = queries.main_states;
        let aux_queries = queries.aux_states;
        let main_queries_vec: Vec<Vec<Felt>> = main_queries.rows().map(|a| a.to_owned()).collect();

        let aux_queries_vec: Vec<Vec<Felt>> = aux_queries
            .as_ref()
            .unwrap()
            .rows()
            .map(|a| QuadFelt::slice_as_base_elements(a).to_vec())
            .collect();

        let (main_trace_pmt, mut main_trace_adv_map) =
            unbatch_to_partial_mt(positions.to_vec(), main_queries_vec, proofs[0].clone());
        let (aux_trace_pmt, mut aux_trace_adv_map) =
            unbatch_to_partial_mt(positions.to_vec(), aux_queries_vec, proofs[1].clone());

        let mut trees = vec![main_trace_pmt];
        trees.push(aux_trace_pmt);

        main_trace_adv_map.append(&mut aux_trace_adv_map);
        Ok((main_trace_adv_map, trees))
    }

    /// Returns constraint evaluations at the specified positions of the LDE domain. This also
    /// checks if the constraint evaluations are valid against the constraint commitment sent by
    /// the prover.
    pub fn read_constraint_evaluations(
        &mut self,
        positions: &[usize],
    ) -> Result<(AdvMap, PartialMerkleTree), VerifierError> {
        let queries = self.constraint_queries.take().expect("already read");
        let proof = queries.query_proofs;

        let queries = queries
            .evaluations
            .rows()
            .map(|a| QuadFelt::slice_as_base_elements(a).into())
            .collect();
        let (constraint_pmt, constraint_adv_map) =
            unbatch_to_partial_mt(positions.to_vec(), queries, proof);

        Ok((constraint_adv_map, constraint_pmt))
    }

    /// Returns the FRI layers Merkle batch proofs.
    pub fn fri_layer_proofs(&self) -> Vec<BatchMerkleProof<Rpo256>> {
        self.fri_layer_proofs.clone()
    }

    /// Returns the unbatched Merkle proofs as well as a global key-value map for all the FRI layer
    /// proofs.
    pub fn unbatch_fri_layer_proofs<const N: usize>(
        &mut self,
        positions_: &[usize],
        domain_size: usize,
        layer_commitments: Vec<Word>,
    ) -> (Vec<PartialMerkleTree>, Vec<(Word, Vec<Felt>)>) {
        let all_layers_queries = self.fri_layer_queries.clone();
        let mut current_domain_size = domain_size;
        let mut positions = positions_.to_vec();
        let number_of_folds = layer_commitments.len() - 1;

        let mut global_adv_key_map = Vec::new();
        let mut global_partial_merkle_trees = Vec::new();
        let mut layer_proofs = self.fri_layer_proofs();
        for current_layer_queries in all_layers_queries.iter().take(number_of_folds) {
            let mut folded_positions = fold_positions(&positions, current_domain_size, N);

            let layer_proof = layer_proofs.remove(0);
            let queries: Vec<_> = group_slice_elements::<QuadFelt, N>(current_layer_queries)
                .iter()
                .map(|query| QuadFelt::slice_as_base_elements(query).to_vec())
                .collect();

            let (current_partial_merkle_tree, mut cur_adv_key_map) =
                unbatch_to_partial_mt(folded_positions.clone(), queries, layer_proof);

            global_partial_merkle_trees.push(current_partial_merkle_tree);
            global_adv_key_map.append(&mut cur_adv_key_map);

            core::mem::swap(&mut positions, &mut folded_positions);
            current_domain_size /= N;
        }

        (global_partial_merkle_trees, global_adv_key_map)
    }
}

// FRI VERIFIER CHANNEL IMPLEMENTATION
// ================================================================================================

impl FriVerifierChannel<QuadFelt> for VerifierChannel {
    type Hasher = Rpo256;
    type VectorCommitment = MerkleTreeVC<Self::Hasher>;

    fn read_fri_num_partitions(&self) -> usize {
        self.fri_num_partitions
    }

    fn read_fri_layer_commitments(&mut self) -> Vec<Word> {
        self.fri_roots.take().expect("already read")
    }

    fn take_next_fri_layer_proof(&mut self) -> BatchMerkleProof<Rpo256> {
        self.fri_layer_proofs.remove(0)
    }

    fn take_next_fri_layer_queries(&mut self) -> Vec<QuadFelt> {
        self.fri_layer_queries.remove(0)
    }

    fn take_fri_remainder(&mut self) -> Vec<QuadFelt> {
        self.fri_remainder.take().expect("already read")
    }
}

// TRACE QUERIES
// ================================================================================================

/// Container of trace query data, including:
/// * Queried states for all trace segments.
/// * Merkle authentication paths for all queries.
///
/// Trace states for all auxiliary segments are stored in a single table.
struct TraceQueries {
    query_proofs: Vec<BatchMerkleProof<Rpo256>>,
    main_states: Table<Felt>,
    aux_states: Option<Table<QuadFelt>>,
}

impl TraceQueries {
    /// Parses the provided trace queries into trace states in the specified field and
    /// corresponding Merkle authentication paths.
    pub fn new(
        mut queries: Vec<Queries>,
        air: &ProcessorAir,
        num_queries: usize,
    ) -> Result<Self, VerifierError> {
        // parse main trace segment queries; parsing also validates that hashes of each table row
        // form the leaves of Merkle authentication paths in the proofs
        let main_segment_width = air.trace_info().main_trace_width();
        let main_segment_queries = queries.remove(0);
        let (main_segment_query_proofs, main_segment_states) = main_segment_queries
            .parse::<Felt, Rpo256, MerkleTreeVC<Rpo256>>(
                air.lde_domain_size(),
                num_queries,
                main_segment_width,
            )
            .map_err(|err| {
                VerifierError::ProofDeserializationError(format!(
                    "main trace segment query deserialization failed: {err}"
                ))
            })?;

        // all query proofs will be aggregated into a single vector
        let mut query_proofs = vec![main_segment_query_proofs];

        // parse auxiliary trace segment queries (if any); parsing also validates that hashes of
        // each table row form the leaves of Merkle authentication paths in the proofs
        let aux_trace_states = if air.trace_info().is_multi_segment() {
            assert_eq!(queries.len(), 1);
            let segment_width = air.trace_info().aux_segment_width();
            let aux_segment_queries = queries.remove(0);

            let (segment_query_proof, segment_trace_states) = aux_segment_queries
                .parse::<QuadFelt, Rpo256, MerkleTreeVC<Rpo256>>(
                    air.lde_domain_size(),
                    num_queries,
                    segment_width,
                )
                .map_err(|err| {
                    VerifierError::ProofDeserializationError(format!(
                        "auxiliary trace segment query deserialization failed: {err}"
                    ))
                })?;

            query_proofs.push(segment_query_proof);

            Some(segment_trace_states)
        } else {
            None
        };

        Ok(Self {
            query_proofs,
            main_states: main_segment_states,
            aux_states: aux_trace_states,
        })
    }
}

// CONSTRAINT QUERIES
// ================================================================================================

/// Container of constraint evaluation query data, including:
/// * Queried constraint evaluation values.
/// * Merkle authentication paths for all queries.
struct ConstraintQueries {
    query_proofs: BatchMerkleProof<Rpo256>,
    evaluations: Table<QuadFelt>,
}

impl ConstraintQueries {
    /// Parses the provided constraint queries into evaluations in the specified field and
    /// corresponding Merkle authentication paths.
    pub fn new(
        queries: Queries,
        air: &ProcessorAir,
        num_queries: usize,
    ) -> Result<Self, VerifierError> {
        let (query_proofs, evaluations) = queries
            .parse::<QuadFelt, Rpo256, MerkleTreeVC<Rpo256>>(
                air.lde_domain_size(),
                num_queries,
                air.ce_blowup_factor(),
            )
            .map_err(|err| {
                VerifierError::ProofDeserializationError(format!(
                    "constraint evaluation query deserialization failed: {err}"
                ))
            })?;

        Ok(Self { query_proofs, evaluations })
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Takes a set of positions, query values of a trace at these positions and a Merkle batch proof
/// against a commitment to this trace, and outputs a partial Merkle tree with individual Merkle
/// paths for each position as well as a key-value map mapping the digests of the query values
/// (i.e. Merkle tree leaves) to their corresponding query values.
pub fn unbatch_to_partial_mt(
    positions: Vec<usize>,
    queries: Vec<Vec<Felt>>,
    proof: BatchMerkleProof<Rpo256>,
) -> (PartialMerkleTree, Vec<(Word, Vec<Felt>)>) {
    // hash the query values in order to get the leaf
    let leaves: Vec<Word> = queries.iter().map(|row| Rpo256::hash_elements(row)).collect();

    // use the computed leaves with the indices in order to unbatch the Merkle proof batch proof
    let unbatched_proof = proof
        .into_openings(&leaves, &positions)
        .expect("failed to unbatch the batched Merkle proof");

    // construct the partial Merkle tree data
    let mut paths_with_leaves = vec![];
    for (position, merkle_proof) in positions.iter().zip(unbatched_proof.iter()) {
        paths_with_leaves.push((
            *position as u64,
            merkle_proof.0.to_owned(),
            merkle_proof.1.to_owned().into(),
        ))
    }

    // construct the advice key map linking leaves to query values
    let mut adv_key_map = Vec::new();
    leaves.into_iter().zip(queries.iter()).for_each(|(leaf, query_data)| {
        adv_key_map.push((leaf, query_data.to_owned()));
    });

    (
        PartialMerkleTree::with_paths(paths_with_leaves).expect("should not fail from paths"),
        adv_key_map,
    )
}
