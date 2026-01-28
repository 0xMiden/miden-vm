use alloc::collections::BTreeMap;

use miden_air::trace::chiplets::hasher::{
    DIGEST_RANGE, LINEAR_HASH, MP_VERIFY, MR_UPDATE_NEW, MR_UPDATE_OLD, RATE_LEN, RETURN_HASH,
    RETURN_STATE, STATE_WIDTH, Selectors, TRACE_WIDTH,
};

use super::{
    Felt, HasherState, MerklePath, MerkleRootUpdate, ONE, OpBatch, TraceFragment, Word as Digest,
    ZERO,
};
use crate::PrimeField64;

mod trace;
use trace::HasherTrace;

#[cfg(test)]
mod tests;

// HASH PROCESSOR
// ================================================================================================

/// Hash chiplet for the VM.
///
/// This component is responsible for performing all hash-related computations for the VM, as well
/// as building an execution trace for these computations. These computations include:
/// * Linear hashes, including simple 2-to-1 hashes, single and multiple permutations.
/// * Merkle path verification.
/// * Merkle root updates.
///
/// ## Execution trace
/// Hasher execution trace consists of 16 columns as illustrated below:
///
///   s0   s1   s2   h0   h1   h2   h3   h4   h5   h6   h7   h8   h9   h10   h11   idx
/// ├────┴────┴────┴────┴────┴────┴────┴────┴────┴────┴────┴────┴────┴─────┴─────┴─────┤
///
/// In the above, the meaning of the columns is as follows:
/// * Selector columns s0, s1, and s2 used to help select transition function for a given row.
/// * Hasher state columns h0 through h11 used to hold the hasher state for each round of hash
///   computation. The state is laid out as `[RATE0, RATE1, CAPACITY]`:
///   - The first eight columns (h0-h7) represent the rate elements of the state. These are used to
///     absorb the values to be hashed. Once a permutation is complete, hash output is located in
///     the first four rate columns (h0, h1, h2, h3).
///   - The last four columns (h8-h11) represent the capacity state of the sponge function.
/// * Node index column idx used to help with Merkle path verification and Merkle root update
///   computations. For all other computations the values in this column are set to 0s.
///
/// Each permutation of the hash function adds 8 rows to the execution trace. Thus, for Merkle
/// path verification, number of rows added to the trace is 8 * path.len(), and for Merkle root
/// update it is 16 * path.len(), since we need to perform two path verifications for each update.
///
/// In addition to the execution trace, the hash chiplet also maintains:
/// - an auxiliary trace builder, which can be used to construct a running product column describing
///   the state of the sibling table (used in Merkle root update operations).
/// - a map of memoized execution trace, which keeps track of start and end rows of the sections of
///   the trace of a control or span block that can be copied to be used later for program blocks
///   encountered with the same digest instead of building it from scratch everytime. The hash of
///   the block is used as the key here after converting it to a bytes array.
#[derive(Debug, Default)]
pub struct Hasher {
    trace: HasherTrace,
    memoized_trace_map: BTreeMap<[u8; 32], (usize, usize)>,
}

impl Hasher {
    // STATE ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns current length of the execution trace stored in this hasher.
    pub(super) fn trace_len(&self) -> usize {
        self.trace.trace_len()
    }

    // HASHING METHODS
    // --------------------------------------------------------------------------------------------

    /// Applies a single permutation of the hash function to the provided state and records the
    /// execution trace of this computation.
    ///
    /// The returned tuple contains the hasher state after the permutation and the row address of
    /// the execution trace at which the permutation started.
    pub fn permute(&mut self, mut state: HasherState) -> (Felt, HasherState) {
        let addr = self.trace.next_row_addr();

        // perform the hash.
        self.trace.append_permutation(&mut state, LINEAR_HASH, RETURN_STATE);

        (addr, state)
    }

    /// Computes the hash of the control block by computing hash(h1, h2) and returns the result.
    /// It also records the execution trace of this computation.
    ///
    /// The returned tuple also contains the row address of the execution trace at which the hash
    /// computation started.
    pub fn hash_control_block(
        &mut self,
        h1: Digest,
        h2: Digest,
        domain: Felt,
        expected_hash: Digest,
    ) -> (Felt, Digest) {
        let addr = self.trace.next_row_addr();
        let mut state = init_state_from_words_with_domain(&h1, &h2, domain);

        if let Some((start_row, end_row)) = self.get_memoized_trace(expected_hash) {
            // copy the trace of a block with same hash instead of building it again.
            self.trace.copy_trace(&mut state, *start_row..*end_row);
        } else {
            // perform the hash.
            self.trace.append_permutation(&mut state, LINEAR_HASH, RETURN_HASH);

            self.insert_to_memoized_trace_map(addr, expected_hash);
        };

        let result = get_digest(&state);

        (addr, result)
    }

    /// Computes a sequential hash of all operation batches in the list and returns the result. It
    /// also records the execution trace of this computation.
    ///
    /// The returned tuple also contains the row address of the execution trace at which the hash
    /// computation started.
    pub fn hash_basic_block(
        &mut self,
        op_batches: &[OpBatch],
        expected_hash: Digest,
    ) -> (Felt, Digest) {
        const START: Selectors = LINEAR_HASH;
        const RETURN: Selectors = RETURN_HASH;
        // absorb selectors are the same as linear hash selectors, but absorb selectors are
        // applied on the last row of a permutation cycle, while linear hash selectors are
        // applied on the first row of a permutation cycle.
        const ABSORB: Selectors = LINEAR_HASH;
        // to continue linear hash we need retain the 2nd and 3rd selector flags and set the
        // 1st flag to ZERO.
        const CONTINUE: Selectors = [ZERO, LINEAR_HASH[1], LINEAR_HASH[2]];

        let addr = self.trace.next_row_addr();

        // initialize the state and absorb the first operation batch into it
        let mut state = init_state(op_batches[0].groups(), ZERO);

        // check if a span block with same hash has been encountered before in which case we can
        // directly copy it's trace.
        let (start_row, end_row, is_memoized) =
            if let Some((start_row, end_row)) = self.get_memoized_trace(expected_hash) {
                (*start_row, *end_row, true)
            } else {
                (0, 0, false)
            };

        let num_batches = op_batches.len();

        // if the span block is encountered for the first time and it's trace is not memoized,
        // we need to build the trace from scratch.
        if !is_memoized {
            if num_batches == 1 {
                // if there is only one batch to hash, we need only one permutation
                self.trace.append_permutation(&mut state, START, RETURN);
            } else {
                // if there is more than one batch, we need to process the first, the last, and the
                // middle permutations a bit differently. Specifically, selector flags for the
                // permutations need to be set as follows:
                // - first permutation: init linear hash on the first row, and absorb the next
                //   operation batch on the last row.
                // - middle permutations: continue hashing on the first row, and absorb the next
                //   operation batch on the last row.
                // - last permutation: continue hashing on the first row, and return the result on
                //   the last row.
                self.trace.append_permutation(&mut state, START, ABSORB);

                for batch in op_batches.iter().take(num_batches - 1).skip(1) {
                    absorb_into_state(&mut state, batch.groups());

                    self.trace.append_permutation(&mut state, CONTINUE, ABSORB);
                }

                absorb_into_state(&mut state, op_batches[num_batches - 1].groups());

                self.trace.append_permutation(&mut state, CONTINUE, RETURN);
            }
            self.insert_to_memoized_trace_map(addr, expected_hash);
        } else {
            self.trace.copy_trace(&mut state, start_row..end_row);
        }

        let result = get_digest(&state);

        (addr, result)
    }

    /// Performs Merkle path verification computation and records its execution trace.
    ///
    /// The computation consists of computing a Merkle root of the specified path for a node with
    /// the specified value, located at the specified index.
    ///
    /// The returned tuple contains the root of the Merkle path and the row address of the
    /// execution trace at which the computation started.
    ///
    /// # Panics
    /// Panics if:
    /// - The provided path does not contain any nodes.
    /// - The provided index is out of range for the specified path.
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
    /// The computation consists of two Merkle path verifications, one for the old value of the
    /// node (value before the update), and another for the new value (value after the update).
    ///
    /// # Panics
    /// Panics if:
    /// - The provided path does not contain any nodes.
    /// - The provided index is out of range for the specified path.
    pub fn update_merkle_root(
        &mut self,
        old_value: Digest,
        new_value: Digest,
        path: &MerklePath,
        index: Felt,
    ) -> MerkleRootUpdate {
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

    /// Fills the provided trace fragment with trace data from this hasher trace instance. This
    /// also returns the trace builder for hasher-related auxiliary trace columns.
    pub(super) fn fill_trace(self, trace: &mut TraceFragment) {
        self.trace.fill_trace(trace)
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Computes a root of the provided Merkle path in the specified context. The path is assumed
    /// to be for a node with the specified value at the specified index.
    ///
    /// This also records the execution trace of the Merkle path computation.
    ///
    /// # Panics
    /// Panics if:
    /// - The provided path does not contain any nodes.
    /// - The provided index is out of range for the specified path.
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
        let mut root = value;

        // determine selectors for the specified context
        let main_selectors = context.main_selectors();
        let part_selectors = context.part_selectors();

        if path.len() == 1 {
            // handle path of length 1 separately because pattern for init and final selectors
            // is different from other cases
            self.verify_mp_leg(root, path[0], &mut index, main_selectors, RETURN_HASH)
        } else {
            // process the first node of the path; for this node, init and final selectors are
            // the same
            let sibling = path[0];
            root = self.verify_mp_leg(root, sibling, &mut index, main_selectors, main_selectors);

            // process all other nodes, except for the last one
            for &sibling in &path[1..path.len() - 1] {
                root =
                    self.verify_mp_leg(root, sibling, &mut index, part_selectors, main_selectors);
            }

            // process the last node
            let sibling = path[path.len() - 1];
            self.verify_mp_leg(root, sibling, &mut index, part_selectors, RETURN_HASH)
        }
    }

    /// Verifies a single leg of a Merkle path.
    ///
    /// This function does the following:
    /// - Builds the initial hasher state based on the least significant bit of the index.
    /// - Applies a permutation to this state and records the resulting trace.
    /// - Returns the result of the permutation and updates the index by removing its least
    ///   significant bit.
    fn verify_mp_leg(
        &mut self,
        root: Digest,
        sibling: Digest,
        index: &mut u64,
        init_selectors: Selectors,
        final_selectors: Selectors,
    ) -> Digest {
        // build the hasher state based on the value of the least significant bit of the index
        let index_bit = *index & 1;
        let mut state = build_merge_state(&root, &sibling, index_bit);

        // determine values for the node index column for this permutation. if the first selector
        // of init_selectors is not ZERO (i.e., we are processing the first leg of the Merkle
        // path), the index for the first row is different from the index for the other rows;
        // otherwise, indexes are the same.
        let (init_index, rest_index) = if init_selectors[0] == ZERO {
            (Felt::new(*index >> 1), Felt::new(*index >> 1))
        } else {
            (Felt::new(*index), Felt::new(*index >> 1))
        };

        // apply the permutation to the state and record its trace
        self.trace.append_permutation_with_index(
            &mut state,
            init_selectors,
            final_selectors,
            init_index,
            rest_index,
        );

        // remove the least significant bit from the index and return hash result
        *index >>= 1;

        get_digest(&state)
    }

    /// Checks if a trace for a program block already exists and returns the start and end rows
    /// of the memoized trace. Returns None otherwise.
    fn get_memoized_trace(&self, hash: Digest) -> Option<&(usize, usize)> {
        let key: [u8; 32] = hash.into();
        self.memoized_trace_map.get(&key)
    }

    /// Inserts start and end rows of trace for a program block to the memoized_trace_map.
    fn insert_to_memoized_trace_map(&mut self, addr: Felt, hash: Digest) {
        let key: [u8; 32] = hash.into();
        let start_row = addr.as_canonical_u64() as usize - 1;
        let end_row = self.trace.next_row_addr().as_canonical_u64() as usize - 1;
        self.memoized_trace_map.insert(key, (start_row, end_row));
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
    pub fn main_selectors(&self) -> Selectors {
        match self {
            Self::MpVerify => MP_VERIFY,
            Self::MrUpdateOld => MR_UPDATE_OLD,
            Self::MrUpdateNew => MR_UPDATE_NEW,
        }
    }

    /// Returns partial selector values for this context. Partial selector values are derived
    /// from selector values by replacing the first selector with ZERO.
    pub fn part_selectors(&self) -> Selectors {
        let selectors = self.main_selectors();
        [ZERO, selectors[1], selectors[2]]
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Combines two words into a hasher state for Merkle path computation.
///
/// If index_bit = 0, the words are combined in the order (a, b), if index_bit = 1, the words are
/// combined in the order (b, a), otherwise, the function panics.
#[inline(always)]
fn build_merge_state(a: &Digest, b: &Digest, index_bit: u64) -> HasherState {
    match index_bit {
        0 => init_state_from_words(a, b),
        1 => init_state_from_words(b, a),
        _ => panic!("index bit is not a binary value"),
    }
}

// TODO: Move these to another file.

// HASHER STATE MUTATORS
// ================================================================================================

/// Initializes hasher state with the first 8 elements to be absorbed. In accordance with the
/// Poseidon2 padding rule, the first capacity element is set with the provided padding flag, which
/// is assumed to be ZERO or ONE, depending on whether the number of elements to be absorbed is a
/// multiple of the rate or not. The remaining elements in the capacity portion of the state are set
/// to ZERO.
///
/// State layout: [R1, R2, CAP] where:
/// - state[0..8] = init_values (rate)
/// - state[8..12] = [padding_flag, ZERO, ZERO, ZERO] (capacity)
#[inline(always)]
pub fn init_state(init_values: &[Felt; RATE_LEN], padding_flag: Felt) -> [Felt; STATE_WIDTH] {
    debug_assert!(
        padding_flag == ZERO || padding_flag == ONE,
        "first capacity element must be 0 or 1"
    );
    [
        init_values[0],
        init_values[1],
        init_values[2],
        init_values[3],
        init_values[4],
        init_values[5],
        init_values[6],
        init_values[7],
        padding_flag,
        ZERO,
        ZERO,
        ZERO,
    ]
}

/// Initializes hasher state with the elements from the provided words. Because the length of the
/// input is a multiple of the rate, all capacity elements are initialized to zero, as specified by
/// the Poseidon2 padding rule.
///
/// State layout: [RATE0, RATE1, CAP] where:
/// - state[0..4] = w1 (first rate word, also digest location)
/// - state[4..8] = w2 (second rate word)
/// - state[8..12] = capacity
#[inline(always)]
pub fn init_state_from_words(w1: &Digest, w2: &Digest) -> [Felt; STATE_WIDTH] {
    init_state_from_words_with_domain(w1, w2, ZERO)
}

/// Initializes hasher state with elements from the provided words. Sets the second element of the
/// capacity register to the provided domain. All other elements of the capacity register are set
/// to 0.
///
/// State layout: [RATE0, RATE1, CAP] where:
/// - state[0..4] = w1 (first rate word, also digest location)
/// - state[4..8] = w2 (second rate word)
/// - state[8..12] = [ZERO, domain, ZERO, ZERO] (capacity)
#[inline(always)]
pub fn init_state_from_words_with_domain(
    w1: &Digest,
    w2: &Digest,
    domain: Felt,
) -> [Felt; STATE_WIDTH] {
    [w1[0], w1[1], w1[2], w1[3], w2[0], w2[1], w2[2], w2[3], ZERO, domain, ZERO, ZERO]
}

/// Absorbs the specified values into the provided state by overwriting the corresponding elements
/// in the rate portion of the state.
///
/// State layout: rate is at state[0..8]
#[inline(always)]
pub fn absorb_into_state(state: &mut [Felt; STATE_WIDTH], values: &[Felt; RATE_LEN]) {
    state[0] = values[0];
    state[1] = values[1];
    state[2] = values[2];
    state[3] = values[3];
    state[4] = values[4];
    state[5] = values[5];
    state[6] = values[6];
    state[7] = values[7];
}

/// Returns elements representing the digest portion of the provided hasher's state.
pub fn get_digest(state: &[Felt; STATE_WIDTH]) -> Digest {
    state[DIGEST_RANGE].try_into().expect("failed to get digest from hasher state")
}
