use alloc::{collections::VecDeque, sync::Arc};

use miden_core::{
    Felt, Word,
    crypto::merkle::MerklePath,
    mast::{MastForest, MastNodeId},
};

pub struct ExternalNodeReplay {
    pub external_node_resolutions: VecDeque<(MastNodeId, Arc<MastForest>)>,
}

impl Default for ExternalNodeReplay {
    fn default() -> Self {
        Self::new()
    }
}

impl ExternalNodeReplay {
    /// Creates a new ExternalNodeReplay with an empty resolution queue
    pub fn new() -> Self {
        Self {
            external_node_resolutions: VecDeque::new(),
        }
    }

    /// Records a resolution of an external node to a MastNodeId with its associated MastForest
    pub fn record_resolution(&mut self, node_id: MastNodeId, forest: Arc<MastForest>) {
        self.external_node_resolutions.push_back((node_id, forest));
    }

    /// Replays the next recorded external node resolution, returning both the node ID and forest
    pub fn replay_resolution(&mut self) -> (MastNodeId, Arc<MastForest>) {
        self.external_node_resolutions
            .pop_front()
            .expect("No external node resolutions recorded")
    }
}

/// Implements a shim for the memory chiplet, in which all elements read from memory during a given
/// fragment are recorded by the fast processor, and replayed by the main trace fragment generators.
///
/// This is used to simulate memory reads in parallel trace generation without needing to actually
/// access the memory chiplet. Writes are not recorded here, as they are not needed for the trace
/// generation process.
///
/// Elements/words read are stored with their addresses and are assumed to be read from the same
/// addresses that they were recorded at. This works naturally since the fast processor has exactly
/// the same access patterns as the main trace generators (which re-executes part of the program).
/// The read methods include debug assertions to verify address consistency.
pub struct MemoryReplay {
    pub elements_read: VecDeque<(Felt, Felt)>,
    pub words_read: VecDeque<(Felt, Word)>,
}

impl Default for MemoryReplay {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryReplay {
    /// Creates a new MemoryReplay with empty read vectors
    pub fn new() -> Self {
        Self {
            elements_read: VecDeque::new(),
            words_read: VecDeque::new(),
        }
    }

    // MUTATIONS (populated by the fast processor)
    // --------------------------------------------------------------------------------

    /// Records a read element from memory
    pub fn record_element(&mut self, element: Felt, addr: Felt) {
        self.elements_read.push_back((addr, element));
    }

    /// Records a read word from memory
    pub fn record_word(&mut self, word: Word, addr: Felt) {
        self.words_read.push_back((addr, word));
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------

    pub fn replay_read_element(&mut self, addr: Felt) -> Felt {
        let (stored_addr, element) =
            self.elements_read.pop_front().expect("No elements read from memory");
        debug_assert_eq!(stored_addr, addr, "Address mismatch: expected {addr}, got {stored_addr}");
        element
    }

    pub fn replay_read_word(&mut self, addr: Felt) -> Word {
        let (stored_addr, word) = self.words_read.pop_front().expect("No words read from memory");
        debug_assert_eq!(stored_addr, addr, "Address mismatch: expected {addr}, got {stored_addr}");
        word
    }
}

/// Implements a shim for the advice provider, in which all advice provider operations during a
/// given fragment are pre-recorded by the fast processor.
///
/// This is used to simulate advice provider interactions in parallel trace generation without
/// needing to actually access the advice provider. All advice provider operations are recorded
/// during fast execution and then replayed during parallel trace generation.
///
/// The shim records all operations with their parameters and results, and provides replay methods
/// that return the pre-recorded results. This works naturally since the fast processor has exactly
/// the same access patterns as the main trace generators (which re-executes part of the program).
/// The read methods include debug assertions to verify parameter consistency.
pub struct AdviceReplay {
    // Stack operations
    pub stack_pops: VecDeque<Felt>,
    pub stack_word_pops: VecDeque<Word>,
    pub stack_dword_pops: VecDeque<[Word; 2]>,

    // Merkle store operations
    pub get_merkle_paths: VecDeque<MerklePath>,
    pub merkle_node_updates: VecDeque<(MerklePath, Word)>,
}

impl Default for AdviceReplay {
    fn default() -> Self {
        Self::new()
    }
}

impl AdviceReplay {
    /// Creates a new AdviceReplay with empty operation vectors
    pub fn new() -> Self {
        Self {
            stack_pops: VecDeque::new(),
            stack_word_pops: VecDeque::new(),
            stack_dword_pops: VecDeque::new(),
            get_merkle_paths: VecDeque::new(),
            merkle_node_updates: VecDeque::new(),
        }
    }

    // MUTATIONS (populated by the fast processor)
    // --------------------------------------------------------------------------------

    /// Records the value returned by a pop_stack operation
    pub fn record_pop_stack(&mut self, value: Felt) {
        self.stack_pops.push_back(value);
    }

    /// Records the word returned by a pop_stack_word operation
    pub fn record_pop_stack_word(&mut self, word: Word) {
        self.stack_word_pops.push_back(word);
    }

    /// Records the double word returned by a pop_stack_dword operation
    pub fn record_pop_stack_dword(&mut self, dword: [Word; 2]) {
        self.stack_dword_pops.push_back(dword);
    }

    /// Records a successful get_merkle_path operation and the returned path
    pub fn record_get_merkle_path(&mut self, path: MerklePath) {
        self.get_merkle_paths.push_back(path);
    }

    /// Records a successful update_merkle_node operation and the returned path and new root
    pub fn record_update_merkle_node(&mut self, path: MerklePath, new_root: Word) {
        self.merkle_node_updates.push_back((path, new_root));
    }

    // ACCESSORS (used during parallel trace generation)
    // --------------------------------------------------------------------------------

    /// Replays a pop_stack operation, returning the previously recorded value
    pub fn replay_pop_stack(&mut self) -> Felt {
        self.stack_pops.pop_front().expect("No stack pop operations recorded")
    }

    /// Replays a pop_stack_word operation, returning the previously recorded word
    pub fn replay_pop_stack_word(&mut self) -> Word {
        self.stack_word_pops.pop_front().expect("No stack word pop operations recorded")
    }

    /// Replays a pop_stack_dword operation, returning the previously recorded double word
    pub fn replay_pop_stack_dword(&mut self) -> [Word; 2] {
        self.stack_dword_pops
            .pop_front()
            .expect("No stack dword pop operations recorded")
    }

    /// Replays a get_merkle_path operation, returning the previously recorded path
    pub fn replay_get_merkle_path(&mut self) -> MerklePath {
        self.get_merkle_paths.pop_front().expect("No merkle path operations recorded")
    }

    /// Replays an update_merkle_node operation
    pub fn replay_update_merkle_node(&mut self) -> (MerklePath, Word) {
        let (recorded_path, recorded_new_root) = self
            .merkle_node_updates
            .pop_front()
            .expect("No node update operations recorded");
        (recorded_path, recorded_new_root)
    }
}

/// Implements a shim for the hasher chiplet, in which all hasher operations during a given
/// fragment are pre-recorded by the fast processor.
///
/// This is used to simulate hasher operations in parallel trace generation without needing
/// to actually perform hash computations. All hasher operations are recorded during fast
/// execution and then replayed during parallel trace generation.
#[derive(Debug)]
pub struct HasherReplay {
    /// Recorded hasher addresses from operations like hash_control_block, hash_basic_block, etc.
    pub block_addresses: VecDeque<Felt>,

    /// Recorded hasher operations from permutation operations (HPerm)
    /// Each entry contains (address, output_state)
    pub permutation_operations: VecDeque<(Felt, [Felt; 12])>,

    /// Recorded hasher operations from Merkle path verification operations
    /// Each entry contains (address, computed_root)
    pub build_merkle_root_operations: VecDeque<(Felt, Word)>,

    /// Recorded hasher operations from Merkle root update operations
    /// Each entry contains (address, old_root, new_root)
    pub mrupdate_operations: VecDeque<(Felt, Word, Word)>,
}

impl Default for HasherReplay {
    fn default() -> Self {
        Self::new()
    }
}

impl HasherReplay {
    pub fn new() -> Self {
        Self {
            block_addresses: VecDeque::new(),
            permutation_operations: VecDeque::new(),
            build_merkle_root_operations: VecDeque::new(),
            mrupdate_operations: VecDeque::new(),
        }
    }

    // MUTATIONS (populated by the fast processor)
    // --------------------------------------------------------------------------------

    /// Records a hasher address from a block hash operation
    pub fn record_block_address(&mut self, addr: Felt) {
        self.block_addresses.push_back(addr);
    }

    /// Records a permutation operation with its address and result
    pub fn record_permutation(&mut self, addr: Felt, output_state: [Felt; 12]) {
        self.permutation_operations.push_back((addr, output_state));
    }

    /// Records a Merkle path verification with its address and computed root
    pub fn record_build_merkle_root(&mut self, addr: Felt, computed_root: Word) {
        self.build_merkle_root_operations.push_back((addr, computed_root));
    }

    /// Records a Merkle root update with its address, old root, and new root
    pub fn record_mrupdate(&mut self, addr: Felt, old_root: Word, new_root: Word) {
        self.mrupdate_operations.push_back((addr, old_root, new_root));
    }

    // ACCESSORS (used by parallel trace generators)
    // --------------------------------------------------------------------------------

    /// Replays a block hash operation, returning the pre-recorded address
    pub fn replay_block_address(&mut self) -> Felt {
        self.block_addresses.pop_front().expect("No block address operations recorded")
    }

    /// Replays a permutation operation, returning the pre-recorded address and result
    pub fn replay_permutation(&mut self) -> (Felt, [Felt; 12]) {
        self.permutation_operations
            .pop_front()
            .expect("No permutation operations recorded")
    }

    /// Replays a Merkle path verification, returning the pre-recorded address and computed root
    pub fn replay_build_merkle_root(&mut self) -> (Felt, Word) {
        self.build_merkle_root_operations
            .pop_front()
            .expect("No build merkle root operations recorded")
    }

    /// Replays a Merkle root update, returning the pre-recorded address, old root, and new root
    pub fn replay_mrupdate(&mut self) -> (Felt, Word, Word) {
        self.mrupdate_operations.pop_front().expect("No mrupdate operations recorded")
    }
}

// pub struct HasherReplay {
//     // Permutation operations
//     pub permutations: VecDeque<(HasherState, Felt, HasherState)>, // (input_state, addr,
// output_state)

//     // Control block hashing operations
//     pub control_block_hashes: VecDeque<(Word, Word, Felt, RpoDigest, Felt, Word)>, // (h1, h2,
// domain, expected_hash, addr, result)

//     // Basic block hashing operations
//     pub basic_block_hashes: VecDeque<(usize, RpoDigest, Felt, Word)>, // (num_batches,
// expected_hash, addr, result)

//     // Merkle path verification operations
//     pub merkle_path_verifications: VecDeque<(Word, usize, Felt, Felt, Word)>, // (value,
// path_len, index, addr, root)

//     // Merkle root update operations
//     pub merkle_root_updates: VecDeque<(Word, Word, usize, Felt, MerkleRootUpdate)>, //
// (old_value, new_value, path_len, index, result) }

// impl HasherReplay {
//     /// Creates a new HasherReplay with empty operation vectors
//     pub fn new() -> Self {
//         Self {
//             permutations: VecDeque::new(),
//             control_block_hashes: VecDeque::new(),
//             basic_block_hashes: VecDeque::new(),
//             merkle_path_verifications: VecDeque::new(),
//             merkle_root_updates: VecDeque::new(),
//         }
//     }

//     // MUTATIONS (populated by the fast processor)
//     // --------------------------------------------------------------------------------

//     /// Records a permutation operation and its result
//     pub fn record_permutation(&mut self, input_state: HasherState, addr: Felt, output_state:
// HasherState) {         self.permutations.push_back((input_state, addr, output_state));
//     }

//     /// Records a control block hash operation and its result
//     pub fn record_control_block_hash(
//         &mut self,
//         h1: Word,
//         h2: Word,
//         domain: Felt,
//         expected_hash: RpoDigest,
//         addr: Felt,
//         result: Word,
//     ) {
//         self.control_block_hashes.push_back((h1, h2, domain, expected_hash, addr, result));
//     }

//     /// Records a basic block hash operation and its result
//     pub fn record_basic_block_hash(
//         &mut self,
//         num_batches: usize,
//         expected_hash: RpoDigest,
//         addr: Felt,
//         result: Word,
//     ) {
//         self.basic_block_hashes.push_back((num_batches, expected_hash, addr, result));
//     }

//     /// Records a Merkle path verification operation and its result
//     pub fn record_merkle_path_verification(
//         &mut self,
//         value: Word,
//         path_len: usize,
//         index: Felt,
//         addr: Felt,
//         root: Word,
//     ) {
//         self.merkle_path_verifications.push_back((value, path_len, index, addr, root));
//     }

//     /// Records a Merkle root update operation and its result
//     pub fn record_merkle_root_update(
//         &mut self,
//         old_value: Word,
//         new_value: Word,
//         path_len: usize,
//         index: Felt,
//         result: MerkleRootUpdate,
//     ) {
//         self.merkle_root_updates.push_back((old_value, new_value, path_len, index, result));
//     }

//     // ACCESSORS (used during parallel trace generation)
//     // --------------------------------------------------------------------------------

//     /// Replays a permutation operation, returning the previously recorded result
//     pub fn replay_permutation(&mut self, input_state: HasherState) -> (Felt, HasherState) {
//         let (recorded_input, addr, output_state) =
//             self.permutations.pop_front().expect("No permutation operations recorded");
//         debug_assert_eq!(
//             recorded_input, input_state,
//             "Permutation input state mismatch: expected {:?}, got {:?}",
//             input_state, recorded_input
//         );
//         (addr, output_state)
//     }

//     /// Replays a control block hash operation, returning the previously recorded result
//     pub fn replay_control_block_hash(
//         &mut self,
//         h1: Word,
//         h2: Word,
//         domain: Felt,
//         expected_hash: RpoDigest,
//     ) -> (Felt, Word) {
//         let (recorded_h1, recorded_h2, recorded_domain, recorded_hash, addr, result) =
//             self.control_block_hashes.pop_front().expect("No control block hash operations
// recorded");         debug_assert_eq!(
//             recorded_h1, h1,
//             "Control block hash h1 mismatch: expected {:?}, got {:?}",
//             h1, recorded_h1
//         );
//         debug_assert_eq!(
//             recorded_h2, h2,
//             "Control block hash h2 mismatch: expected {:?}, got {:?}",
//             h2, recorded_h2
//         );
//         debug_assert_eq!(
//             recorded_domain, domain,
//             "Control block hash domain mismatch: expected {:?}, got {:?}",
//             domain, recorded_domain
//         );
//         debug_assert_eq!(
//             recorded_hash, expected_hash,
//             "Control block hash expected_hash mismatch: expected {:?}, got {:?}",
//             expected_hash, recorded_hash
//         );
//         (addr, result)
//     }

//     /// Replays a basic block hash operation, returning the previously recorded result
//     pub fn replay_basic_block_hash(
//         &mut self,
//         num_batches: usize,
//         expected_hash: RpoDigest,
//     ) -> (Felt, Word) {
//         let (recorded_num_batches, recorded_hash, addr, result) =
//             self.basic_block_hashes.pop_front().expect("No basic block hash operations
// recorded");         debug_assert_eq!(
//             recorded_num_batches, num_batches,
//             "Basic block hash num_batches mismatch: expected {}, got {}",
//             num_batches, recorded_num_batches
//         );
//         debug_assert_eq!(
//             recorded_hash, expected_hash,
//             "Basic block hash expected_hash mismatch: expected {:?}, got {:?}",
//             expected_hash, recorded_hash
//         );
//         (addr, result)
//     }

//     /// Replays a Merkle path verification operation, returning the previously recorded result
//     pub fn replay_merkle_path_verification(
//         &mut self,
//         value: Word,
//         path_len: usize,
//         index: Felt,
//     ) -> (Felt, Word) {
//         let (recorded_value, recorded_path_len, recorded_index, addr, root) =
//             self.merkle_path_verifications.pop_front().expect("No Merkle path verification
// operations recorded");         debug_assert_eq!(
//             recorded_value, value,
//             "Merkle path verification value mismatch: expected {:?}, got {:?}",
//             value, recorded_value
//         );
//         debug_assert_eq!(
//             recorded_path_len, path_len,
//             "Merkle path verification path_len mismatch: expected {}, got {}",
//             path_len, recorded_path_len
//         );
//         debug_assert_eq!(
//             recorded_index, index,
//             "Merkle path verification index mismatch: expected {:?}, got {:?}",
//             index, recorded_index
//         );
//         (addr, root)
//     }

//     /// Replays a Merkle root update operation, returning the previously recorded result
//     pub fn replay_merkle_root_update(
//         &mut self,
//         old_value: Word,
//         new_value: Word,
//         path_len: usize,
//         index: Felt,
//     ) -> MerkleRootUpdate {
//         let (recorded_old_value, recorded_new_value, recorded_path_len, recorded_index, result) =
//             self.merkle_root_updates.pop_front().expect("No Merkle root update operations
// recorded");         debug_assert_eq!(
//             recorded_old_value, old_value,
//             "Merkle root update old_value mismatch: expected {:?}, got {:?}",
//             old_value, recorded_old_value
//         );
//         debug_assert_eq!(
//             recorded_new_value, new_value,
//             "Merkle root update new_value mismatch: expected {:?}, got {:?}",
//             new_value, recorded_new_value
//         );
//         debug_assert_eq!(
//             recorded_path_len, path_len,
//             "Merkle root update path_len mismatch: expected {}, got {}",
//             path_len, recorded_path_len
//         );
//         debug_assert_eq!(
//             recorded_index, index,
//             "Merkle root update index mismatch: expected {:?}, got {:?}",
//             index, recorded_index
//         );
//         result
//     }
// }
