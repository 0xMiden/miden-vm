use alloc::collections::BTreeMap;

use miden_air::trace::chiplets::hasher::{
    DIGEST_RANGE, HASH_CYCLE_LEN, LINEAR_HASH, MP_VERIFY, MR_UPDATE_NEW, MR_UPDATE_OLD, RATE_LEN,
    RETURN_HASH, RETURN_STATE, STATE_WIDTH, Selectors,
};
use miden_core::chiplets::hasher::apply_permutation;

use super::{
    Felt, HasherState, MerklePath, MerkleRootUpdate, ONE, OpBatch, TraceFragment, Word as Digest,
    ZERO,
};

mod trace;
use trace::HasherTrace;

#[cfg(test)]
#[allow(clippy::needless_range_loop)]
mod tests;

// HASH PROCESSOR
// ================================================================================================

/// Key type for digest-based lookups.
type DigestKey = [u64; 4];

/// Key type for full-state lookups.
type StateKey = [u64; STATE_WIDTH];

/// Converts a Digest to a DigestKey for BTreeMap lookup.
fn digest_to_key(digest: Digest) -> DigestKey {
    let elems = digest.as_elements();
    core::array::from_fn(|i| elems[i].as_canonical_u64())
}

/// Converts a HasherState to a StateKey for BTreeMap lookup.
fn state_to_key(state: &HasherState) -> StateKey {
    core::array::from_fn(|i| state[i].as_canonical_u64())
}

/// Reconstructs a HasherState from a StateKey.
fn key_to_state(key: &StateKey) -> HasherState {
    core::array::from_fn(|i| Felt::new(key[i]))
}

/// Hash chiplet for the VM.
///
/// This component uses a controller/permutation split architecture:
///
/// - **Controller region** (s_perm=0): pairs of (input, output) rows for each permutation request.
///   Input rows (s0=1) capture the operation type and pre-permutation state. Output rows (s0=0,
///   s1=0) capture the post-permutation state.
///
/// - **Permutation segment** (s_perm=1): one 16-row Poseidon2 cycle per unique input state.
///   Multiplicity is stored in the node_index column. Linked to controller rows via the hasher_perm
///   LogUp bus.
///
/// This architecture enables permutation deduplication: N requests with the same input state
/// produce N controller pairs but only one permutation cycle (with multiplicity N).
///
/// ## Trace layout (20 columns)
///
///   s0  s1  s2  h0..h11  idx  mrupdate_id  is_boundary  direction_bit  s_perm
/// ├────┴───┴───┴────────┴────┴────────────┴─────────┴─────────┴────────┤
#[derive(Debug, Default)]
pub struct Hasher {
    trace: HasherTrace,
    /// Maps block digest -> (start_row, end_row) for memoized controller traces.
    memoized_trace_map: BTreeMap<DigestKey, (usize, usize)>,
    /// Maps input state -> multiplicity for permutation deduplication.
    /// During finalize_trace(), one 16-row perm cycle is emitted per entry.
    perm_request_map: BTreeMap<StateKey, u64>,
    /// Monotonically increasing counter for MRUPDATE domain separation.
    mrupdate_id: Felt,
    /// Whether the permutation segment has been finalized.
    finalized: bool,
}

impl Hasher {
    // STATE ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the length of the execution trace.
    ///
    /// Before finalization, this returns an estimate based on the controller region length
    /// plus the expected permutation segment size. The estimate is verified against the
    /// actual length during `fill_trace()` via a debug assertion.
    pub(super) fn trace_len(&self) -> usize {
        if self.finalized {
            self.trace.trace_len()
        } else {
            self.estimate_trace_len()
        }
    }

    /// Returns the layout of the hasher region as `(controller_len, perm_len)`, both exact
    /// multiples of `HASH_CYCLE_LEN`. Must be called before `fill_trace()` consumes the hasher.
    ///
    /// `controller_len` includes the padding rows that `finalize_trace()` will later append to
    /// round the raw controller count up to a cycle boundary; `perm_len` is the total span of
    /// the permutation cycles that `finalize_trace()` will emit, one per unique input state.
    pub(super) fn region_lengths(&self) -> (usize, usize) {
        debug_assert!(!self.finalized, "region_lengths must be called before finalization");
        let controller_len = self.trace.trace_len().next_multiple_of(HASH_CYCLE_LEN);
        let perm_len = self.perm_request_map.len() * HASH_CYCLE_LEN;
        (controller_len, perm_len)
    }

    /// Estimates the total trace length before finalization.
    ///
    /// This must match the actual length produced by `finalize_trace()`. The invariant is
    /// verified by a debug assertion in `fill_trace()`.
    fn estimate_trace_len(&self) -> usize {
        let (controller_len, perm_len) = self.region_lengths();
        controller_len + perm_len
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

        self.insert_to_memoized_trace_map(addr, expected_hash);
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
        // Check memoization
        if let Some(memoized) = self.replay_memoized_trace(expected_hash) {
            return memoized;
        }

        let addr = self.trace.next_row_addr();
        let init_state = init_state(op_batches[0].groups(), ZERO);

        let num_batches = op_batches.len();

        if num_batches == 1 {
            // Single batch: boundary on both input and output
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
            self.insert_to_memoized_trace_map(addr, expected_hash);
            let result = get_digest(&permuted);
            return (addr, result);
        }

        // Multiple batches:
        // First batch: boundary input only
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

        // Middle batches: no boundary flags
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

        // Last batch: boundary output only
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

        self.insert_to_memoized_trace_map(addr, expected_hash);
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
        // Increment the mrupdate_id for this update operation
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

    /// Finalizes and fills the provided trace fragment with data from this hasher trace.
    ///
    /// Finalization pads the controller region and appends one 16-row permutation cycle
    /// per unique input state. This is the only place where the perm segment is materialized.
    pub(super) fn fill_trace(mut self, trace: &mut TraceFragment) {
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
        self.trace.fill_trace(trace);
    }

    /// Finalizes the trace by padding the controller region and appending the permutation segment.
    fn finalize_trace(&mut self) {
        if self.finalized {
            return;
        }

        // Pad controller region to a multiple of HASH_CYCLE_LEN.
        // Padding rows must carry the current mrupdate_id to satisfy the AIR progression
        // constraint (mrupdate_id is constant on non-MV-start transitions).
        self.trace.pad_to_cycle_boundary(self.mrupdate_id);

        // Append one 16-row permutation cycle per unique input state
        for (key, multiplicity) in core::mem::take(&mut self.perm_request_map) {
            let state = key_to_state(&key);
            self.trace.append_permutation_cycle(&state, Felt::new(multiplicity));
        }

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
        // Append input controller row
        self.trace.append_controller_row(
            init_selectors,
            &state,
            input_node_index,
            self.mrupdate_id,
            is_boundary_input,
            input_direction_bit,
        );

        // Apply the permutation
        let mut permuted = state;
        apply_permutation(&mut permuted);

        // Append output controller row
        self.trace.append_controller_row(
            final_selectors,
            &permuted,
            output_node_index,
            self.mrupdate_id,
            is_boundary_output,
            output_direction_bit,
        );

        // Record this permutation request for deduplication
        self.record_perm_request(&state);

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

            // Determine boundary flags
            let is_boundary_input = if is_first { ONE } else { ZERO };
            let is_boundary_output = if is_last { ONE } else { ZERO };

            // Direction bit for this step: LSB of the current index
            let b_i = index & 1;
            let state = build_merge_state(&root, &sibling, b_i);

            // Input row carries the full index; output row carries the shifted index.
            let input_node_idx = Felt::new(index);
            let output_node_idx = Felt::new(index >> 1);

            // Direction bit for the NEXT step (forward propagation for routing constraint).
            // On the last step there is no next step, so direction_bit = 0.
            let b_next = if is_last { 0 } else { (index >> 1) & 1 };

            let final_selectors = if is_last { RETURN_HASH } else { RETURN_STATE };

            // Append controller pair with direction bits
            let permuted = self.append_controller_permutation(
                main_selectors,
                final_selectors,
                state,
                input_node_idx,
                output_node_idx,
                is_boundary_input,
                is_boundary_output,
                Felt::new(b_i),    // input direction_bit: current step's bit
                Felt::new(b_next), // output direction_bit: next step's bit (propagated)
            );

            root = get_digest(&permuted);
            index >>= 1;
        }

        root
    }

    // PERMUTATION DEDUPLICATION
    // --------------------------------------------------------------------------------------------

    /// Records a permutation request for the given input state. If the same state was already
    /// seen, increments the multiplicity counter.
    fn record_perm_request(&mut self, state: &HasherState) {
        let key = state_to_key(state);
        *self.perm_request_map.entry(key).or_insert(0) += 1;
    }

    // MEMOIZATION
    // --------------------------------------------------------------------------------------------

    /// Attempts to replay a memoized controller trace for the given expected hash.
    ///
    /// If a memoized trace exists, copies it, re-registers permutation requests from copied
    /// input rows, and returns `Some((addr, digest))`. Otherwise returns `None`.
    fn replay_memoized_trace(&mut self, expected_hash: Digest) -> Option<(Felt, Digest)> {
        let (start_row, end_row) = match self.get_memoized_trace(expected_hash) {
            Some(&(s, e)) => (s, e),
            None => return None,
        };

        let addr = self.trace.next_row_addr();
        let mut state = [ZERO; STATE_WIDTH];
        let append_start = self.trace.trace_len();
        self.trace.copy_trace(&mut state, start_row..end_row);
        let append_end = self.trace.trace_len();

        // Ensure mrupdate_id is consistent with the current counter for all copied rows.
        self.trace
            .overwrite_mrupdate_id_in_range(append_start..append_end, self.mrupdate_id);

        // Re-register permutation requests from copied input rows
        let input_states = self.trace.input_states_in_range(append_start..append_end);
        for input_state in input_states {
            self.record_perm_request(&input_state);
        }

        let result = get_digest(&state);
        Some((addr, result))
    }

    /// Returns the start and end rows of a memoized block trace, if it exists.
    fn get_memoized_trace(&self, hash: Digest) -> Option<&(usize, usize)> {
        self.memoized_trace_map.get(&digest_to_key(hash))
    }

    /// Records the start and end rows of a block's controller trace for memoization.
    fn insert_to_memoized_trace_map(&mut self, addr: Felt, hash: Digest) {
        let start_row = addr.as_canonical_u64() as usize - 1;
        let end_row = self.trace.next_row_addr().as_canonical_u64() as usize - 1;
        self.memoized_trace_map.insert(digest_to_key(hash), (start_row, end_row));
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
