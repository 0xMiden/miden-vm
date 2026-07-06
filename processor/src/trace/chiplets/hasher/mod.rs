use alloc::{collections::BTreeMap, vec::Vec};

use miden_air::trace::chiplets::hasher::{
    CONTROLLER_TRACE_ALIGNMENT, DIGEST_RANGE, HASH_CYCLE_LEN, LINEAR_HASH, MP_VERIFY,
    MR_UPDATE_NEW, MR_UPDATE_OLD, RATE_LEN, RETURN_HASH, RETURN_STATE, STATE_WIDTH, Selectors,
};
use miden_core::chiplets::hasher::apply_permutation;

use super::{
    ChipletTraceFragment, Felt, HasherState, MerklePath, MerkleRootUpdate, ONE, OpBatch,
    Word as Digest, ZERO,
};

mod trace;
use trace::{HasherTrace, fill_poseidon2_permutation_trace};

#[cfg(test)]
mod tests;

// HASH PROCESSOR
// ================================================================================================

/// Key type for digest-based lookups.
type DigestKey = [u64; 4];

/// Key type for full-state lookups.
type StateKey = [u64; STATE_WIDTH];

#[derive(Debug, Clone, Copy)]
pub(super) struct PermRequest {
    state: StateKey,
    multiplicity: u64,
}

/// Converts a Digest to a DigestKey for BTreeMap lookup.
fn digest_to_key(digest: Digest) -> DigestKey {
    let elems = digest.as_elements();
    core::array::from_fn(|i| elems[i].as_canonical_u64())
}

/// Converts a HasherState to a StateKey for BTreeMap lookup.
fn state_to_key(state: &HasherState) -> StateKey {
    core::array::from_fn(|i| state[i].as_canonical_u64())
}

/// Hash chiplet for the VM.
///
/// This component records controller rows in the chiplets trace and permutation cycles in the
/// Poseidon2 permutation trace:
///
/// - **Controller region**: pairs of (input, output) rows for each permutation request.
///   Input rows (s0=1) capture the operation type and pre-permutation state. Output rows (s0=0,
///   s1=0) capture the post-permutation state.
///
/// - **Poseidon2 permutation trace**: one 16-row cycle per unique input state, linked to controller
///   rows via the hasher perm-link LogUp bus.
///
/// Equal input states share one permutation cycle with the corresponding multiplicity.
///
/// ## Controller row layout
///
///   s0  s1  s2  h0..h11  idx  mrupdate_id  is_boundary  direction_bit  perm_id
/// ├────┴───┴───┴────────┴────┴────────────┴─────────────┴───────────────┴─────────┤
#[derive(Debug, Default)]
pub struct Hasher {
    trace: HasherTrace,
    /// Maps block digest -> (op_start, op_end) for memoized controller traces.
    memoized_trace_map: BTreeMap<DigestKey, (usize, usize)>,
    /// Maps input state -> Poseidon2 cycle id.
    perm_request_map: BTreeMap<StateKey, usize>,
    /// Deduplicated Poseidon2 requests in cycle-id order.
    perm_requests: Vec<PermRequest>,
    /// Monotonically increasing counter for MRUPDATE domain separation.
    mrupdate_id: Felt,
    /// Whether the controller trace has been finalized.
    finalized: bool,
}

impl Hasher {
    // STATE ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the controller trace length.
    ///
    /// Before finalization, this returns the padded controller-region estimate. The estimate is
    /// checked against the actual length during `fill_trace()`.
    pub(super) fn trace_len(&self) -> usize {
        if self.finalized {
            self.trace.trace_len()
        } else {
            self.estimate_trace_len()
        }
    }

    /// Returns the layout of the hasher region as `(controller_len, poseidon2_len)`.
    ///
    /// `controller_len` includes padding rows that align the following chiplet section.
    /// `poseidon2_len` includes one zero-multiplicity padding cycle.
    pub(super) fn region_lengths(&self) -> (usize, usize) {
        debug_assert!(!self.finalized, "region_lengths must be called before finalization");
        let controller_len = self.trace.trace_len().next_multiple_of(CONTROLLER_TRACE_ALIGNMENT);
        let perm_len = self.poseidon2_permutation_trace_len();
        (controller_len, perm_len)
    }

    /// Returns the unpadded Poseidon2-permutation AIR trace length.
    pub(super) fn poseidon2_permutation_trace_len(&self) -> usize {
        if self.finalized {
            0
        } else {
            (self.perm_requests.len() + 1) * HASH_CYCLE_LEN
        }
    }

    /// Estimates the controller trace length before finalization.
    ///
    /// This must match the actual length produced by `finalize_trace()`. The invariant is
    /// verified by a debug assertion in `fill_trace()`.
    fn estimate_trace_len(&self) -> usize {
        let (controller_len, _) = self.region_lengths();
        controller_len
    }

    // HASHING METHODS
    // --------------------------------------------------------------------------------------------

    /// Applies a single permutation of the hash function to the provided state and records the
    /// execution trace of this computation.
    ///
    /// Returns (addr, permuted_state).
    pub fn permute(&mut self, state: HasherState) -> (Felt, HasherState) {
        let addr = self.trace.next_row_addr();

        let permuted = self.append_controller_permutation(
            LINEAR_HASH,
            RETURN_STATE,
            state,
            ZERO, // input_node_index
            ZERO, // output_node_index
            ONE,  // is_boundary_input = 1 (first input)
            ONE,  // is_boundary_output = 1 (final output)
            ZERO, // input_direction_bit (non-Merkle)
            ZERO, // output_direction_bit (non-Merkle)
        );

        (addr, permuted)
    }

    /// Computes hash(h1, h2) for a control block and returns the result.
    ///
    /// Returns (addr, digest).
    pub fn hash_control_block(
        &mut self,
        h1: Digest,
        h2: Digest,
        domain: Felt,
        expected_hash: Digest,
    ) -> (Felt, Digest) {
        if let Some(memoized) = self.replay_memoized_trace(expected_hash) {
            return memoized;
        }

        let addr = self.trace.next_row_addr();
        let op_start = self.trace.next_op_index();
        let init_state = init_state_from_words_with_domain(&h1, &h2, domain);
        // Single permutation: boundary on both input and output
        let permuted = self.append_controller_permutation(
            LINEAR_HASH,
            RETURN_HASH,
            init_state,
            ZERO,
            ZERO, // node_index: input, output
            ONE,
            ONE, // is_boundary: input=1, output=1
            ZERO,
            ZERO, // direction_bit: non-Merkle
        );

        self.insert_to_memoized_trace_map(op_start, expected_hash);
        let result = get_digest(&permuted);
        (addr, result)
    }

    /// Computes a sequential hash of all operation batches and returns the result.
    ///
    /// Returns (addr, digest).
    pub fn hash_basic_block(
        &mut self,
        op_batches: &[OpBatch],
        expected_hash: Digest,
    ) -> (Felt, Digest) {
        if let Some(memoized) = self.replay_memoized_trace(expected_hash) {
            return memoized;
        }

        let addr = self.trace.next_row_addr();
        let op_start = self.trace.next_op_index();
        let init_state = init_state(op_batches[0].groups(), ZERO);

        let num_batches = op_batches.len();

        if num_batches == 1 {
            // One-batch hashes have both boundary flags set.
            let permuted = self.append_controller_permutation(
                LINEAR_HASH,
                RETURN_HASH,
                init_state,
                ZERO,
                ZERO,
                ONE,
                ONE,
                ZERO,
                ZERO,
            );
            self.insert_to_memoized_trace_map(op_start, expected_hash);
            let result = get_digest(&permuted);
            return (addr, result);
        }

        // First batch: boundary input only.
        let mut state = self.append_controller_permutation(
            LINEAR_HASH,
            RETURN_STATE,
            init_state,
            ZERO,
            ZERO,
            ONE,
            ZERO,
            ZERO,
            ZERO,
        );

        // Middle batches: no boundary flags.
        for batch in op_batches.iter().take(num_batches - 1).skip(1) {
            absorb_into_state(&mut state, batch.groups());
            state = self.append_controller_permutation(
                LINEAR_HASH,
                RETURN_STATE,
                state,
                ZERO,
                ZERO,
                ZERO,
                ZERO,
                ZERO,
                ZERO,
            );
        }

        // Last batch: boundary output only.
        absorb_into_state(&mut state, op_batches[num_batches - 1].groups());
        let permuted = self.append_controller_permutation(
            LINEAR_HASH,
            RETURN_HASH,
            state,
            ZERO,
            ZERO,
            ZERO,
            ONE,
            ZERO,
            ZERO,
        );

        self.insert_to_memoized_trace_map(op_start, expected_hash);
        let result = get_digest(&permuted);
        (addr, result)
    }

    /// Performs Merkle path verification computation and records its execution trace.
    ///
    /// Returns (addr, root).
    pub fn build_merkle_root(
        &mut self,
        value: Digest,
        path: &MerklePath,
        index: Felt,
    ) -> (Felt, Digest) {
        let addr = self.trace.next_row_addr();
        let root = self.verify_merkle_path(
            value,
            path,
            index.as_canonical_u64(),
            MerklePathContext::MpVerify,
        );
        (addr, root)
    }

    /// Performs Merkle root update computation and records its execution trace.
    ///
    /// Increments the mrupdate_id counter. Both MV and MU legs share the same id.
    pub fn update_merkle_root(
        &mut self,
        old_value: Digest,
        new_value: Digest,
        path: &MerklePath,
        index: Felt,
    ) -> MerkleRootUpdate {
        self.mrupdate_id += ONE;

        let address = self.trace.next_row_addr();
        let index = index.as_canonical_u64();

        let old_root =
            self.verify_merkle_path(old_value, path, index, MerklePathContext::MrUpdateOld);
        let new_root =
            self.verify_merkle_path(new_value, path, index, MerklePathContext::MrUpdateNew);

        MerkleRootUpdate { address, old_root, new_root }
    }

    // TRACE GENERATION
    // --------------------------------------------------------------------------------------------

    /// Finalizes and fills the controller and Poseidon2-permutation traces.
    pub(super) fn fill_trace(
        mut self,
        trace: &mut ChipletTraceFragment,
        poseidon2_trace: &mut [Felt],
    ) {
        if !self.finalized {
            let estimated_len = self.estimate_trace_len();
            self.finalize_trace();
            debug_assert_eq!(
                estimated_len,
                self.trace.trace_len(),
                "hasher trace length estimate ({}) diverged from actual ({})",
                estimated_len,
                self.trace.trace_len(),
            );
        }
        let perm_requests = core::mem::take(&mut self.perm_requests);
        self.trace.fill_trace(trace);
        fill_poseidon2_permutation_trace(perm_requests, poseidon2_trace);
    }

    /// Finalizes the controller trace by padding it to the chiplet alignment boundary.
    fn finalize_trace(&mut self) {
        if self.finalized {
            return;
        }

        self.trace.pad_to_controller_boundary(self.mrupdate_id);

        self.finalized = true;
    }

    // CORE HELPER: CONTROLLER PERMUTATION
    // --------------------------------------------------------------------------------------------

    /// Appends a controller (input, output) pair and records the permutation request.
    ///
    /// Writes two rows to the controller region:
    /// - Input row: `init_selectors` (s0=1), pre-permutation `state`, `input_node_index`,
    ///   `is_boundary_input`, `input_direction_bit`.
    /// - Output row: `final_selectors` (s0=0), post-permutation state, `output_node_index`,
    ///   `is_boundary_output`, `output_direction_bit`.
    ///
    /// Both rows carry the current `mrupdate_id` for sibling table domain separation.
    /// The pre-permutation state is also recorded in `perm_request_map` for deduplication.
    ///
    /// For Merkle operations, `input_node_index` is the full tree index and
    /// `output_node_index` is the shifted index (input >> 1). For non-Merkle operations,
    /// both should be ZERO.
    ///
    /// Returns the post-permutation state.
    fn append_controller_permutation(
        &mut self,
        init_selectors: Selectors,
        final_selectors: Selectors,
        state: HasherState,
        input_node_index: Felt,
        output_node_index: Felt,
        is_boundary_input: Felt,
        is_boundary_output: Felt,
        input_direction_bit: Felt,
        output_direction_bit: Felt,
    ) -> HasherState {
        let perm_id = self.record_perm_request(&state);

        self.trace.append_controller_row(
            init_selectors,
            &state,
            input_node_index,
            self.mrupdate_id,
            is_boundary_input,
            input_direction_bit,
            perm_id,
        );

        let mut permuted = state;
        apply_permutation(&mut permuted);

        self.trace.append_controller_row(
            final_selectors,
            &permuted,
            output_node_index,
            self.mrupdate_id,
            is_boundary_output,
            output_direction_bit,
            perm_id,
        );

        permuted
    }

    // MERKLE PATH HELPERS
    // --------------------------------------------------------------------------------------------

    /// Computes a root of the provided Merkle path in the specified context.
    fn verify_merkle_path(
        &mut self,
        value: Digest,
        path: &MerklePath,
        mut index: u64,
        context: MerklePathContext,
    ) -> Digest {
        assert!(!path.is_empty(), "path is empty");
        assert!(
            index.checked_shr(path.len() as u32).unwrap_or(0) == 0,
            "invalid index for the path"
        );

        let main_selectors = context.main_selectors();
        let depth = path.len();

        let mut root = value;

        for (i, &sibling) in path.iter().enumerate() {
            let is_first = i == 0;
            let is_last = i == depth - 1;

            let is_boundary_input = if is_first { ONE } else { ZERO };
            let is_boundary_output = if is_last { ONE } else { ZERO };

            let b_i = index & 1;
            let state = build_merge_state(&root, &sibling, b_i);

            // Input row carries the full index; output row carries the shifted index.
            let input_node_idx = Felt::new_unchecked(index);
            let output_node_idx = Felt::new_unchecked(index >> 1);

            // The output row carries the next level's direction bit for the transition constraint.
            let b_next = if is_last { 0 } else { (index >> 1) & 1 };

            let final_selectors = if is_last { RETURN_HASH } else { RETURN_STATE };

            let permuted = self.append_controller_permutation(
                main_selectors,
                final_selectors,
                state,
                input_node_idx,
                output_node_idx,
                is_boundary_input,
                is_boundary_output,
                Felt::new_unchecked(b_i), // input direction_bit: current step's bit
                Felt::new_unchecked(b_next), // output direction_bit: next step's bit (propagated)
            );

            root = get_digest(&permuted);
            index >>= 1;
        }

        root
    }

    // PERMUTATION DEDUPLICATION
    // --------------------------------------------------------------------------------------------

    /// Records a permutation request for the given input state and returns its cycle id.
    fn record_perm_request(&mut self, state: &HasherState) -> Felt {
        let key = state_to_key(state);
        if let Some(&id) = self.perm_request_map.get(&key) {
            self.perm_requests[id].multiplicity += 1;
            return perm_id_felt(id);
        }

        let id = self.perm_requests.len();
        self.perm_request_map.insert(key, id);
        self.perm_requests.push(PermRequest { state: key, multiplicity: 1 });
        perm_id_felt(id)
    }

    // MEMOIZATION
    // --------------------------------------------------------------------------------------------

    /// Attempts to replay a memoized controller trace for the given expected hash.
    ///
    /// If a memoized trace exists, re-pushes the source ops with the current `mrupdate_id`,
    /// re-registers permutation requests from copied input rows, and returns `Some((addr,
    /// digest))`. Otherwise returns `None`.
    fn replay_memoized_trace(&mut self, expected_hash: Digest) -> Option<(Felt, Digest)> {
        let (op_start, op_end) = match self.get_memoized_trace(expected_hash) {
            Some(&(s, e)) => (s, e),
            None => return None,
        };

        let addr = self.trace.next_row_addr();
        let (last_state, input_states) =
            self.trace.replay_ops_range(op_start..op_end, self.mrupdate_id);

        for input_state in input_states {
            self.record_perm_request(&input_state);
        }

        let result = get_digest(&last_state);
        Some((addr, result))
    }

    /// Returns the start and end op indices of a memoized block trace, if it exists.
    fn get_memoized_trace(&self, hash: Digest) -> Option<&(usize, usize)> {
        self.memoized_trace_map.get(&digest_to_key(hash))
    }

    /// Records the op index range of a block's controller trace for memoization.
    fn insert_to_memoized_trace_map(&mut self, op_start: usize, hash: Digest) {
        let op_end = self.trace.next_op_index();
        self.memoized_trace_map.insert(digest_to_key(hash), (op_start, op_end));
    }
}

// MERKLE PATH CONTEXT
// ================================================================================================

/// Specifies the context of a Merkle path computation.
#[derive(Debug, Clone, Copy)]
enum MerklePathContext {
    /// The computation is for verifying a Merkle path (MPVERIFY).
    MpVerify,
    /// The computation is for verifying a Merkle path to an old node during Merkle root update
    /// procedure (MRUPDATE).
    MrUpdateOld,
    /// The computation is for verifying a Merkle path to a new node during Merkle root update
    /// procedure (MRUPDATE).
    MrUpdateNew,
}

impl MerklePathContext {
    /// Returns selector values for this context.
    pub fn main_selectors(self) -> Selectors {
        match self {
            Self::MpVerify => MP_VERIFY,
            Self::MrUpdateOld => MR_UPDATE_OLD,
            Self::MrUpdateNew => MR_UPDATE_NEW,
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Combines two words into a hasher state for Merkle path computation.
#[inline(always)]
fn build_merge_state(a: &Digest, b: &Digest, index_bit: u64) -> HasherState {
    match index_bit {
        0 => init_state_from_words(a, b),
        1 => init_state_from_words(b, a),
        _ => panic!("index bit is not a binary value"),
    }
}

fn perm_id_felt(id: usize) -> Felt {
    Felt::new_unchecked(id.try_into().expect("Poseidon2 permutation id exceeds u64"))
}

// HASHER STATE MUTATORS
// ================================================================================================

/// Initializes hasher state with the first 8 elements to be absorbed.
///
/// State layout: [RATE0, RATE1, CAP] where:
/// - state[0..8] = init_values (rate)
/// - state[8..12] = [padding_flag, ZERO, ZERO, ZERO] (capacity)
#[inline(always)]
pub fn init_state(init_values: &[Felt; RATE_LEN], padding_flag: Felt) -> [Felt; STATE_WIDTH] {
    debug_assert!(
        padding_flag == ZERO || padding_flag == ONE,
        "first capacity element must be 0 or 1"
    );
    let mut state = [ZERO; STATE_WIDTH];
    state[..RATE_LEN].copy_from_slice(init_values);
    state[RATE_LEN] = padding_flag;
    state
}

/// Initializes hasher state from two words with zero capacity.
#[inline(always)]
pub fn init_state_from_words(w1: &Digest, w2: &Digest) -> [Felt; STATE_WIDTH] {
    init_state_from_words_with_domain(w1, w2, ZERO)
}

/// Initializes hasher state from two words with a domain value in capacity[1].
#[inline(always)]
pub fn init_state_from_words_with_domain(
    w1: &Digest,
    w2: &Digest,
    domain: Felt,
) -> [Felt; STATE_WIDTH] {
    [w1[0], w1[1], w1[2], w1[3], w2[0], w2[1], w2[2], w2[3], ZERO, domain, ZERO, ZERO]
}

/// Absorbs values into the rate portion of the state.
#[inline(always)]
pub fn absorb_into_state(state: &mut [Felt; STATE_WIDTH], values: &[Felt; RATE_LEN]) {
    state[..RATE_LEN].copy_from_slice(values);
}

/// Returns the digest portion of the hasher state.
pub fn get_digest(state: &[Felt; STATE_WIDTH]) -> Digest {
    state[DIGEST_RANGE].try_into().expect("failed to get digest from hasher state")
}
