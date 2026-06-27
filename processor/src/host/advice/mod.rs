use alloc::{
    collections::{BTreeSet, VecDeque},
    vec::Vec,
};

use miden_core::{
    Felt, WORD_SIZE, Word,
    advice::{AdviceInputs, AdviceMap},
    crypto::{
        hash::Poseidon2,
        merkle::{InnerNodeInfo, MerkleError, MerklePath, MerkleStore, NodeIndex},
    },
};
#[cfg(test)]
use miden_core::{crypto::hash::Blake3_256, serde::Serializable};

mod errors;
pub use errors::AdviceError;

use crate::{ExecutionOptions, host::AdviceMutation, processor::AdviceProviderInterface};

// CONSTANTS
// ================================================================================================

/// Maximum number of elements allowed on the advice stack. Set to 2^17.
pub const MAX_ADVICE_STACK_SIZE: usize = 1 << 17;

trait MerkleStoreBudget {
    fn contains_internal_node(&self, root: Word) -> bool;

    fn new_internal_node_count<I>(&self, roots: I) -> usize
    where
        I: IntoIterator<Item = Word>;

    fn new_path_node_count(
        &self,
        index: u64,
        node: Word,
        path: &MerklePath,
    ) -> Result<usize, MerkleError>;
}

impl MerkleStoreBudget for MerkleStore {
    fn contains_internal_node(&self, root: Word) -> bool {
        self.get_node(root, NodeIndex::root()).is_ok()
    }

    fn new_internal_node_count<I>(&self, roots: I) -> usize
    where
        I: IntoIterator<Item = Word>,
    {
        let mut seen_roots = BTreeSet::new();
        let mut count = 0;

        for root in roots {
            if seen_roots.insert(root) && !self.contains_internal_node(root) {
                count += 1;
            }
        }

        count
    }

    fn new_path_node_count(
        &self,
        index: u64,
        node: Word,
        path: &MerklePath,
    ) -> Result<usize, MerkleError> {
        path.authenticated_nodes(index, node)
            .map(|nodes| self.new_internal_node_count(nodes.map(|node| node.value)))
    }
}

// ADVICE PROVIDER
// ================================================================================================

/// An advice provider is a component through which the VM can request nondeterministic inputs from
/// the host (i.e., result of a computation performed outside of the VM), as well as insert new data
/// into the advice provider to be recovered by the host after the program has finished executing.
///
/// Advice map size limits are enforced here, rather than by `AdviceMap`, because they are part of
/// execution policy. The provider owns the active `ExecutionOptions` and tracks the live advice map
/// budget across initial advice, host mutations, and system-event inserts.
///
/// An advice provider consists of the following components:
/// 1. Advice stack, which is a LIFO data structure. The processor can move the elements from the
///    advice stack onto the operand stack, as well as push new elements onto the advice stack. The
///    maximum number of elements that can be on the advice stack is 2^17.
/// 2. Advice map, which is a key-value map where keys are words (4 field elements) and values are
///    vectors of field elements. The processor can push the values from the map onto the advice
///    stack, as well as insert new values into the map.
/// 3. Merkle store, which contains structured data reducible to Merkle paths. The VM can request
///    Merkle paths from the store, as well as mutate it by updating or merging nodes contained in
///    the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdviceProvider {
    stack: VecDeque<Felt>,
    map: AdviceMap,
    map_element_count: usize,
    max_map_value_size: usize,
    max_map_elements: usize,
    store: MerkleStore,
    merkle_store_node_count: usize,
    max_merkle_store_nodes: usize,
}

impl Default for AdviceProvider {
    fn default() -> Self {
        Self::empty(&ExecutionOptions::default())
    }
}

impl AdviceProvider {
    /// Creates a new advice provider from the provided inputs and execution options.
    ///
    /// The advice map limits in `options` are enforced while loading the initial advice inputs.
    pub fn new(inputs: AdviceInputs, options: &ExecutionOptions) -> Result<Self, AdviceError> {
        let AdviceInputs { stack, map, store } = inputs;
        let mut provider = Self::empty(options);
        provider.extend_stack(stack)?;
        provider.extend_merkle_store(store.inner_nodes())?;
        provider.extend_map(&map)?;
        Ok(provider)
    }

    fn empty(options: &ExecutionOptions) -> Self {
        let store = MerkleStore::default();
        let merkle_store_node_count = store.num_internal_nodes();
        Self {
            stack: VecDeque::new(),
            map: AdviceMap::default(),
            map_element_count: 0,
            max_map_value_size: options.max_adv_map_value_size(),
            max_map_elements: options.max_adv_map_elements(),
            store,
            merkle_store_node_count,
            max_merkle_store_nodes: options.max_merkle_store_nodes(),
        }
    }

    pub(crate) fn set_options(&mut self, options: &ExecutionOptions) -> Result<(), AdviceError> {
        Self::validate_map_values(&self.map, options.max_adv_map_value_size())?;
        let map_element_count =
            self.map.total_element_count().ok_or(AdviceError::AdvMapElementBudgetExceeded {
                current: self.map_element_count,
                added: usize::MAX,
                max: options.max_adv_map_elements(),
            })?;
        if map_element_count > options.max_adv_map_elements() {
            return Err(AdviceError::AdvMapElementBudgetExceeded {
                current: 0,
                added: map_element_count,
                max: options.max_adv_map_elements(),
            });
        }
        if self.merkle_store_node_count > options.max_merkle_store_nodes() {
            return Err(AdviceError::MerkleStoreNodeBudgetExceeded {
                current: 0,
                added: self.merkle_store_node_count,
                max: options.max_merkle_store_nodes(),
            });
        }

        self.map_element_count = map_element_count;
        self.max_map_value_size = options.max_adv_map_value_size();
        self.max_map_elements = options.max_adv_map_elements();
        self.max_merkle_store_nodes = options.max_merkle_store_nodes();
        Ok(())
    }

    #[cfg(test)]
    #[expect(dead_code)]
    pub(crate) fn merkle_store(&self) -> &MerkleStore {
        &self.store
    }

    /// Applies the mutations given in order to the `AdviceProvider`.
    pub fn apply_mutations(
        &mut self,
        mutations: impl IntoIterator<Item = AdviceMutation>,
    ) -> Result<(), AdviceError> {
        mutations.into_iter().try_for_each(|mutation| self.apply_mutation(mutation))
    }

    fn apply_mutation(&mut self, mutation: AdviceMutation) -> Result<(), AdviceError> {
        match mutation {
            AdviceMutation::ExtendStack { values } => {
                self.extend_stack(values)?;
            },
            AdviceMutation::ExtendMap { other } => {
                self.extend_map(&other)?;
            },
            AdviceMutation::ExtendMerkleStore { infos } => {
                self.extend_merkle_store(infos)?;
            },
        }
        Ok(())
    }

    /// Returns a stable fingerprint of the advice state.
    ///
    /// The fingerprint is insensitive to advice-map insertion order and Merkle-store insertion
    /// order, but it still reflects advice-stack order.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        let stack = self.stack.iter().copied().collect::<Vec<_>>().to_bytes();
        let map = self.map.to_bytes();
        let mut store_nodes = self
            .store
            .inner_nodes()
            .map(|info| (info.value, info.left, info.right))
            .collect::<Vec<_>>();
        store_nodes.sort_unstable_by(|lhs, rhs| {
            lhs.0
                .cmp(&rhs.0)
                .then_with(|| lhs.1.cmp(&rhs.1))
                .then_with(|| lhs.2.cmp(&rhs.2))
        });
        let store = store_nodes
            .into_iter()
            .flat_map(|(value, left, right)| [value, left, right])
            .collect::<Vec<_>>()
            .to_bytes();
        Blake3_256::hash_iter([stack.as_slice(), map.as_slice(), store.as_slice()].into_iter())
            .into()
    }

    // ADVICE STACK
    // --------------------------------------------------------------------------------------------

    /// Pops an element from the advice stack and returns it.
    ///
    /// # Errors
    /// Returns an error if the advice stack is empty.
    fn pop_stack(&mut self) -> Result<Felt, AdviceError> {
        self.stack.pop_front().ok_or(AdviceError::StackReadFailed)
    }

    /// Pops a word (4 elements) from the advice stack and returns it.
    ///
    /// Note: a word is popped off the stack element-by-element. For example, a `[d, c, b, a, ...]`
    /// stack (i.e., `d` is at the top of the stack) will yield `[d, c, b, a]`.
    ///
    /// # Errors
    /// Returns an error if the advice stack does not contain a full word.
    fn pop_stack_word(&mut self) -> Result<Word, AdviceError> {
        if self.stack.len() < 4 {
            return Err(AdviceError::StackReadFailed);
        }

        let w0 = self.stack.pop_front().expect("checked len");
        let w1 = self.stack.pop_front().expect("checked len");
        let w2 = self.stack.pop_front().expect("checked len");
        let w3 = self.stack.pop_front().expect("checked len");

        Ok(Word::new([w0, w1, w2, w3]))
    }

    /// Pops a double word (8 elements) from the advice stack and returns them.
    ///
    /// Note: words are popped off the stack element-by-element. For example, a
    /// `[h, g, f, e, d, c, b, a, ...]` stack (i.e., `h` is at the top of the stack) will yield
    /// two words: `[h, g, f,e ], [d, c, b, a]`.
    ///
    /// # Errors
    /// Returns an error if the advice stack does not contain two words.
    fn pop_stack_dword(&mut self) -> Result<[Word; 2], AdviceError> {
        let word0 = self.pop_stack_word()?;
        let word1 = self.pop_stack_word()?;

        Ok([word0, word1])
    }

    /// Checks that pushing `count` elements would not exceed the advice stack size limit.
    fn check_stack_capacity(&self, count: usize) -> Result<(), AdviceError> {
        let resulting_size =
            self.stack.len().checked_add(count).ok_or(AdviceError::StackSizeExceeded {
                push_count: count,
                max: MAX_ADVICE_STACK_SIZE,
            })?;
        if resulting_size > MAX_ADVICE_STACK_SIZE {
            return Err(AdviceError::StackSizeExceeded {
                push_count: count,
                max: MAX_ADVICE_STACK_SIZE,
            });
        }
        Ok(())
    }

    /// Pushes a single value onto the advice stack.
    pub fn push_stack(&mut self, value: Felt) -> Result<(), AdviceError> {
        self.check_stack_capacity(1)?;
        self.stack.push_front(value);
        Ok(())
    }

    /// Pushes a word (4 elements) onto the stack.
    pub fn push_stack_word(&mut self, word: &Word) -> Result<(), AdviceError> {
        self.check_stack_capacity(4)?;
        for &value in word.iter().rev() {
            self.stack.push_front(value);
        }
        Ok(())
    }

    /// Fetches a list of elements under the specified key from the advice map and pushes them onto
    /// the advice stack.
    ///
    /// If `include_len` is set to true, this also pushes the number of elements onto the advice
    /// stack.
    ///
    /// If `pad_to` is not equal to 0, the elements list obtained from the advice map will be padded
    /// with zeros, increasing its length to the next multiple of `pad_to`.
    ///
    /// Note: this operation doesn't consume the map element so it can be called multiple times
    /// for the same key.
    ///
    /// # Example
    /// Given an advice stack `[a, b, c, ...]`, and a map `x |-> [d, e, f]`:
    ///
    /// A call `push_stack(AdviceSource::Map { key: x, include_len: false, pad_to: 0 })` will result
    /// in advice stack: `[d, e, f, a, b, c, ...]`.
    ///
    /// A call `push_stack(AdviceSource::Map { key: x, include_len: true, pad_to: 0 })` will result
    /// in advice stack: `[3, d, e, f, a, b, c, ...]`.
    ///
    /// A call `push_stack(AdviceSource::Map { key: x, include_len: true, pad_to: 4 })` will result
    /// in advice stack: `[3, d, e, f, 0, a, b, c, ...]`.
    ///
    /// # Errors
    /// Returns an error if the key was not found in the key-value map.
    pub fn push_from_map(
        &mut self,
        key: Word,
        include_len: bool,
        pad_to: u8,
    ) -> Result<(), AdviceError> {
        let values = self.map.get(&key).ok_or(AdviceError::MapKeyNotFound { key })?;

        // Calculate total elements to push including padding and optional length prefix
        let num_pad_elements = if pad_to != 0 {
            values.len().next_multiple_of(pad_to as usize) - values.len()
        } else {
            0
        };
        let total_push = values
            .len()
            .checked_add(num_pad_elements)
            .and_then(|n| n.checked_add(if include_len { 1 } else { 0 }))
            .ok_or(AdviceError::StackSizeExceeded {
                push_count: usize::MAX,
                max: MAX_ADVICE_STACK_SIZE,
            })?;
        self.check_stack_capacity(total_push)?;

        // if pad_to was provided (not equal 0), push some zeros to the advice stack so that the
        // final (padded) elements list length will be the next multiple of pad_to
        for _ in 0..num_pad_elements {
            self.stack.push_front(Felt::default());
        }

        // Treat map values as already canonical sequences of FELTs.
        // The advice stack is LIFO; extend in reverse so that the first element of `values`
        // becomes the first element returned by a subsequent `adv_push`.
        for &value in values.iter().rev() {
            self.stack.push_front(value);
        }
        if include_len {
            self.stack.push_front(Felt::new_unchecked(values.len() as u64));
        }
        Ok(())
    }

    /// Returns the current stack as a vector ordered from top (index 0) to bottom.
    pub fn stack(&self) -> Vec<Felt> {
        self.stack.iter().copied().collect()
    }

    /// Extends the stack with the given elements.
    pub fn extend_stack<I>(&mut self, iter: I) -> Result<(), AdviceError>
    where
        I: IntoIterator<Item = Felt>,
    {
        let values: Vec<Felt> = iter.into_iter().collect();
        self.check_stack_capacity(values.len())?;
        for value in values.into_iter().rev() {
            self.stack.push_front(value);
        }
        Ok(())
    }

    // ADVICE MAP
    // --------------------------------------------------------------------------------------------

    /// Returns true if the key has a corresponding value in the map.
    pub fn contains_map_key(&self, key: &Word) -> bool {
        self.map.contains_key(key)
    }

    /// Returns a reference to the value(s) associated with the specified key in the advice map.
    pub fn get_mapped_values(&self, key: &Word) -> Option<&[Felt]> {
        self.map.get(key).map(AsRef::as_ref)
    }

    /// Returns the current advice map.
    pub fn map(&self) -> &AdviceMap {
        &self.map
    }

    fn validate_map_values(map: &AdviceMap, max_value_size: usize) -> Result<(), AdviceError> {
        for (_, values) in map.iter() {
            if values.len() > max_value_size {
                return Err(AdviceError::AdvMapValueSizeExceeded {
                    size: values.len(),
                    max: max_value_size,
                });
            }
        }
        Ok(())
    }

    fn entry_element_count(value_len: usize) -> Option<usize> {
        WORD_SIZE.checked_add(value_len)
    }

    fn check_map_value_size(&self, size: usize) -> Result<(), AdviceError> {
        if size > self.max_map_value_size {
            return Err(AdviceError::AdvMapValueSizeExceeded {
                size,
                max: self.max_map_value_size,
            });
        }
        Ok(())
    }

    fn check_map_element_budget(&self, added: usize) -> Result<(), AdviceError> {
        let Some(new_total) = self.map_element_count.checked_add(added) else {
            return Err(AdviceError::AdvMapElementBudgetExceeded {
                current: self.map_element_count,
                added,
                max: self.max_map_elements,
            });
        };

        if new_total > self.max_map_elements {
            return Err(AdviceError::AdvMapElementBudgetExceeded {
                current: self.map_element_count,
                added,
                max: self.max_map_elements,
            });
        }
        Ok(())
    }

    fn check_merkle_store_node_budget(&self, node_count: usize) -> Result<(), AdviceError> {
        if node_count > self.max_merkle_store_nodes {
            return Err(AdviceError::MerkleStoreNodeBudgetExceeded {
                current: self.merkle_store_node_count,
                added: node_count.saturating_sub(self.merkle_store_node_count),
                max: self.max_merkle_store_nodes,
            });
        }
        Ok(())
    }

    fn check_merkle_store_node_addition(&self, added: usize) -> Result<(), AdviceError> {
        let Some(node_count) = self.merkle_store_node_count.checked_add(added) else {
            return Err(AdviceError::MerkleStoreNodeBudgetExceeded {
                current: self.merkle_store_node_count,
                added,
                max: self.max_merkle_store_nodes,
            });
        };

        self.check_merkle_store_node_budget(node_count)
    }

    /// Inserts the provided value into the advice map under the specified key.
    ///
    /// The values in the advice map can be moved onto the advice stack by invoking
    /// the [AdviceProvider::push_from_map()] method.
    ///
    /// Returns an error if the specified key is already present in the advice map.
    pub fn insert_into_map(&mut self, key: Word, values: Vec<Felt>) -> Result<(), AdviceError> {
        match self.map.get(&key) {
            Some(existing_values) => {
                let existing_values = existing_values.as_ref();
                if existing_values != values {
                    return Err(AdviceError::MapKeyAlreadyPresent {
                        key,
                        prev_values: existing_values.to_vec(),
                        new_values: values,
                    });
                }
            },
            None => {
                self.check_map_value_size(values.len())?;
                let added = Self::entry_element_count(values.len()).ok_or(
                    AdviceError::AdvMapElementBudgetExceeded {
                        current: self.map_element_count,
                        added: usize::MAX,
                        max: self.max_map_elements,
                    },
                )?;
                self.check_map_element_budget(added)?;
                self.map.insert(key, values);
                self.map_element_count += added;
            },
        }
        Ok(())
    }

    /// Merges all entries from the given [`AdviceMap`] into the current advice map.
    ///
    /// Returns an error if any new entry already exists with the same key but a different value
    /// than the one currently stored. The current map remains unchanged.
    pub fn extend_map(&mut self, other: &AdviceMap) -> Result<(), AdviceError> {
        let mut added = 0usize;
        for (key, values) in other.iter() {
            if let Some(existing_values) = self.map.get(key) {
                if existing_values.as_ref() != values.as_ref() {
                    return Err(AdviceError::MapKeyAlreadyPresent {
                        key: *key,
                        prev_values: existing_values.to_vec(),
                        new_values: values.to_vec(),
                    });
                }
                continue;
            }

            self.check_map_value_size(values.len())?;
            let entry_elements = Self::entry_element_count(values.len()).ok_or(
                AdviceError::AdvMapElementBudgetExceeded {
                    current: self.map_element_count,
                    added: usize::MAX,
                    max: self.max_map_elements,
                },
            )?;
            added = added.checked_add(entry_elements).ok_or(
                AdviceError::AdvMapElementBudgetExceeded {
                    current: self.map_element_count,
                    added: usize::MAX,
                    max: self.max_map_elements,
                },
            )?;
        }
        self.check_map_element_budget(added)?;

        self.map.merge(other).map_err(|((key, prev_values), new_values)| {
            AdviceError::MapKeyAlreadyPresent {
                key,
                prev_values: prev_values.to_vec(),
                new_values: new_values.to_vec(),
            }
        })?;
        self.map_element_count += added;
        Ok(())
    }

    // MERKLE STORE
    // --------------------------------------------------------------------------------------------

    /// Returns a node at the specified depth and index in a Merkle tree with the given root.
    ///
    /// # Errors
    /// Returns an error if:
    /// - A Merkle tree for the specified root cannot be found in this advice provider.
    /// - The specified depth is either zero or greater than the depth of the Merkle tree identified
    ///   by the specified root.
    /// - Value of the node at the specified depth and index is not known to this advice provider.
    pub fn get_tree_node(&self, root: Word, depth: Felt, index: Felt) -> Result<Word, AdviceError> {
        let index = NodeIndex::from_elements(&depth, &index)
            .map_err(|_| AdviceError::InvalidMerkleTreeNodeIndex { depth, index })?;
        self.store.get_node(root, index).map_err(AdviceError::MerkleStoreLookupFailed)
    }

    /// Returns true if a path to a node at the specified depth and index in a Merkle tree with the
    /// specified root exists in this Merkle store.
    ///
    /// # Errors
    /// Returns an error if accessing the Merkle store fails.
    pub fn has_merkle_path(
        &self,
        root: Word,
        depth: Felt,
        index: Felt,
    ) -> Result<bool, AdviceError> {
        let index = NodeIndex::from_elements(&depth, &index)
            .map_err(|_| AdviceError::InvalidMerkleTreeNodeIndex { depth, index })?;

        Ok(self.store.has_path(root, index))
    }

    /// Returns a path to a node at the specified depth and index in a Merkle tree with the
    /// specified root.
    ///
    /// # Errors
    /// Returns an error if:
    /// - A Merkle tree for the specified root cannot be found in this advice provider.
    /// - The specified depth is either zero or greater than the depth of the Merkle tree identified
    ///   by the specified root.
    /// - Path to the node at the specified depth and index is not known to this advice provider.
    pub fn get_merkle_path(
        &self,
        root: Word,
        depth: Felt,
        index: Felt,
    ) -> Result<MerklePath, AdviceError> {
        let index = NodeIndex::from_elements(&depth, &index)
            .map_err(|_| AdviceError::InvalidMerkleTreeNodeIndex { depth, index })?;
        self.store
            .get_path(root, index)
            .map(|value| value.path)
            .map_err(AdviceError::MerkleStoreLookupFailed)
    }

    /// Updates a node at the specified depth and index in a Merkle tree with the specified root;
    /// returns the Merkle path from the updated node to the new root, together with the new root.
    ///
    /// # Errors
    /// Returns an error if:
    /// - A Merkle tree for the specified root cannot be found in this advice provider.
    /// - The specified depth is either zero or greater than the depth of the Merkle tree identified
    ///   by the specified root.
    /// - Path to the leaf at the specified index in the specified Merkle tree is not known to this
    ///   advice provider.
    pub fn update_merkle_node(
        &mut self,
        root: Word,
        depth: Felt,
        index: Felt,
        value: Word,
    ) -> Result<(MerklePath, Word), AdviceError> {
        let node_index = NodeIndex::from_elements(&depth, &index)
            .map_err(|_| AdviceError::InvalidMerkleTreeNodeIndex { depth, index })?;
        let proof = self
            .store
            .get_path(root, node_index)
            .map_err(AdviceError::MerkleStoreUpdateFailed)?;
        let path = proof.path;

        if proof.value == value {
            return Ok((path, root));
        }

        let added = self
            .store
            .new_path_node_count(node_index.position(), value, &path)
            .map_err(AdviceError::MerkleStoreUpdateFailed)?;
        self.check_merkle_store_node_addition(added)?;

        let new_root = self
            .store
            .add_merkle_path(node_index.position(), value, path.clone())
            .map_err(AdviceError::MerkleStoreUpdateFailed)?;
        self.merkle_store_node_count += added;
        Ok((path, new_root))
    }

    /// Creates a new Merkle tree in the advice provider by combining Merkle trees with the
    /// specified roots. The root of the new tree is defined as `hash(left_root, right_root)`.
    ///
    /// After the operation, both the original trees and the new tree remains in the advice
    /// provider (i.e., the input trees are not removed).
    ///
    /// It is not checked whether a Merkle tree for either of the specified roots can be found in
    /// this advice provider.
    pub fn merge_roots(&mut self, lhs: Word, rhs: Word) -> Result<Word, AdviceError> {
        let root = Poseidon2::merge(&[lhs, rhs]);
        let added = self.store.new_internal_node_count([root]);
        self.check_merkle_store_node_addition(added)?;

        let root = self.store.merge_roots(lhs, rhs).map_err(AdviceError::MerkleStoreMergeFailed)?;
        self.merkle_store_node_count += added;
        Ok(root)
    }

    /// Returns true if the Merkle root exists for the advice provider Merkle store.
    pub fn has_merkle_root(&self, root: Word) -> bool {
        self.store.get_node(root, NodeIndex::root()).is_ok()
    }

    /// Extends the [MerkleStore] with the given nodes.
    pub fn extend_merkle_store<I>(&mut self, iter: I) -> Result<(), AdviceError>
    where
        I: IntoIterator<Item = InnerNodeInfo>,
    {
        let nodes = iter.into_iter().collect::<Vec<_>>();
        let added = self.store.new_internal_node_count(nodes.iter().map(|node| node.value));
        self.check_merkle_store_node_addition(added)?;

        self.store.extend(nodes);
        self.merkle_store_node_count += added;
        Ok(())
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Extends the contents of this instance with the contents of an `AdviceInputs`.
    pub fn extend_from_inputs(&mut self, inputs: &AdviceInputs) -> Result<(), AdviceError> {
        self.extend_stack(inputs.stack.iter().cloned())?;
        self.extend_merkle_store(inputs.store.inner_nodes())?;
        self.extend_map(&inputs.map)
    }

    /// Consumes `self` and return its parts (stack, map, store).
    ///
    /// The returned stack vector is ordered from top (index 0) to bottom.
    pub fn into_parts(self) -> (Vec<Felt>, AdviceMap, MerkleStore) {
        (self.stack.into_iter().collect(), self.map, self.store)
    }
}

// ADVICE PROVIDER INTERFACE IMPLEMENTATION
// ================================================================================================

impl AdviceProviderInterface for AdviceProvider {
    #[inline(always)]
    fn pop_stack(&mut self) -> Result<Felt, AdviceError> {
        self.pop_stack()
    }

    #[inline(always)]
    fn pop_stack_word(&mut self) -> Result<Word, AdviceError> {
        self.pop_stack_word()
    }

    #[inline(always)]
    fn pop_stack_dword(&mut self) -> Result<[Word; 2], AdviceError> {
        self.pop_stack_dword()
    }

    #[inline(always)]
    fn get_merkle_path(
        &self,
        root: Word,
        depth: Felt,
        index: Felt,
    ) -> Result<Option<MerklePath>, AdviceError> {
        self.get_merkle_path(root, depth, index).map(Some)
    }

    #[inline(always)]
    fn update_merkle_node(
        &mut self,
        root: Word,
        depth: Felt,
        index: Felt,
        value: Word,
    ) -> Result<Option<MerklePath>, AdviceError> {
        self.update_merkle_node(root, depth, index, value).map(|(path, _)| Some(path))
    }
}

#[cfg(test)]
mod tests {
    use alloc::{collections::BTreeMap, vec, vec::Vec};

    use miden_core::WORD_SIZE;

    use super::AdviceProvider;
    use crate::{
        AdviceInputs, ExecutionOptions, Felt, Word,
        advice::{AdviceError, AdviceMap},
        crypto::merkle::{MerkleStore, MerkleTree},
    };

    fn make_leaf(seed: u64) -> Word {
        [
            Felt::new_unchecked(seed),
            Felt::new_unchecked(seed + 1),
            Felt::new_unchecked(seed + 2),
            Felt::new_unchecked(seed + 3),
        ]
        .into()
    }

    #[test]
    fn fingerprint_is_stable_across_merkle_store_insertion_order() {
        let tree_a =
            MerkleTree::new([make_leaf(1), make_leaf(5), make_leaf(9), make_leaf(13)]).unwrap();
        let tree_b =
            MerkleTree::new([make_leaf(17), make_leaf(21), make_leaf(25), make_leaf(29)]).unwrap();

        let mut store_a = MerkleStore::default();
        store_a.extend(tree_a.inner_nodes());
        store_a.extend(tree_b.inner_nodes());

        let mut store_b = MerkleStore::default();
        store_b.extend(tree_b.inner_nodes());
        store_b.extend(tree_a.inner_nodes());

        assert_eq!(store_a, store_b);

        let provider_a = AdviceProvider::new(
            AdviceInputs::default().with_merkle_store(store_a),
            &Default::default(),
        )
        .unwrap();
        let provider_b = AdviceProvider::new(
            AdviceInputs::default().with_merkle_store(store_b),
            &Default::default(),
        )
        .unwrap();

        assert_eq!(provider_a, provider_b);
        assert_eq!(provider_a.fingerprint(), provider_b.fingerprint());
    }

    #[test]
    fn advice_map_insert_respects_element_budget() {
        let options = ExecutionOptions::default().with_max_adv_map_elements(WORD_SIZE + 1);
        let mut provider = AdviceProvider::new(AdviceInputs::default(), &options).unwrap();

        provider.insert_into_map(make_leaf(0), vec![Felt::ONE]).unwrap();

        let err = provider.insert_into_map(make_leaf(1), vec![Felt::ONE]).unwrap_err();
        assert!(matches!(
            err,
            AdviceError::AdvMapElementBudgetExceeded { current: 5, added: 5, max: 5 }
        ));

        assert_eq!(provider.map.len(), 1);
        assert!(provider.contains_map_key(&make_leaf(0)));
        assert!(!provider.contains_map_key(&make_leaf(1)));
    }

    #[test]
    fn advice_map_insert_respects_value_limit() {
        let options = ExecutionOptions::default().with_max_adv_map_value_size(1);
        let mut provider = AdviceProvider::new(AdviceInputs::default(), &options).unwrap();
        let values = vec![Felt::ONE, Felt::new_unchecked(2)];

        let err = provider.insert_into_map(make_leaf(0), values).unwrap_err();
        assert!(matches!(err, AdviceError::AdvMapValueSizeExceeded { size: 2, max: 1 }));

        assert_eq!(provider.map.len(), 0);
    }

    #[test]
    fn advice_map_extend_respects_element_budget_atomically() {
        let options = ExecutionOptions::default().with_max_adv_map_elements(2 * (WORD_SIZE + 1));
        let mut provider = AdviceProvider::new(AdviceInputs::default(), &options).unwrap();
        provider.insert_into_map(make_leaf(0), vec![Felt::ONE]).unwrap();
        let other = advice_map_from_entries(1..3, 1);

        let err = provider.extend_map(&other).unwrap_err();
        assert!(matches!(
            err,
            AdviceError::AdvMapElementBudgetExceeded { current: 5, added: 10, max: 10 }
        ));

        assert_eq!(provider.map.len(), 1);
        assert!(provider.contains_map_key(&make_leaf(0)));
        assert!(!provider.contains_map_key(&make_leaf(1)));
        assert!(!provider.contains_map_key(&make_leaf(2)));
    }

    #[test]
    fn advice_map_extend_respects_value_limit_atomically() {
        let options = ExecutionOptions::default().with_max_adv_map_value_size(1);
        let mut provider = AdviceProvider::new(AdviceInputs::default(), &options).unwrap();
        let other = advice_map_from_entries(0..2, 2);

        let err = provider.extend_map(&other).unwrap_err();
        assert!(matches!(err, AdviceError::AdvMapValueSizeExceeded { size: 2, max: 1 }));

        assert_eq!(provider.map.len(), 0);
    }

    #[test]
    fn initial_advice_map_respects_element_budget() {
        let options = ExecutionOptions::default().with_max_adv_map_elements(WORD_SIZE);
        let inputs = AdviceInputs::default().with_map([(make_leaf(0), vec![Felt::ONE])]);

        let err = AdviceProvider::new(inputs, &options).unwrap_err();
        assert!(matches!(
            err,
            AdviceError::AdvMapElementBudgetExceeded { current: 0, added: 5, max: 4 }
        ));
    }

    #[test]
    fn initial_merkle_store_respects_node_budget() {
        let tree = merkle_tree_from_leaves(0..4);
        let store = merkle_store_from_tree(&tree);
        let options =
            ExecutionOptions::default().with_max_merkle_store_nodes(store.num_internal_nodes() - 1);
        let inputs = AdviceInputs::default().with_merkle_store(store);

        let err = AdviceProvider::new(inputs, &options).unwrap_err();
        assert!(matches!(
            err,
            AdviceError::MerkleStoreNodeBudgetExceeded {
                current: _,
                added: _,
                max
            } if max == options.max_merkle_store_nodes()
        ));
    }

    #[test]
    fn merkle_store_extend_respects_node_budget_atomically() {
        let base_node_count = MerkleStore::default().num_internal_nodes();
        let options = ExecutionOptions::default().with_max_merkle_store_nodes(base_node_count + 1);
        let mut provider = AdviceProvider::new(AdviceInputs::default(), &options).unwrap();
        let tree = merkle_tree_from_leaves(0..4);

        let err = provider.extend_merkle_store(tree.inner_nodes()).unwrap_err();
        assert!(matches!(
            err,
            AdviceError::MerkleStoreNodeBudgetExceeded {
                current,
                added: _,
                max
            } if current == base_node_count && max == base_node_count + 1
        ));

        assert_eq!(provider.merkle_store_node_count, base_node_count);
        assert!(!provider.has_merkle_root(tree.root()));
    }

    #[test]
    fn merkle_store_extend_allows_exact_node_budget() {
        let base_node_count = MerkleStore::default().num_internal_nodes();
        let tree = merkle_tree_from_leaves(0..2);
        let options = ExecutionOptions::default().with_max_merkle_store_nodes(base_node_count + 1);
        let mut provider = AdviceProvider::new(AdviceInputs::default(), &options).unwrap();

        provider.extend_merkle_store(tree.inner_nodes()).unwrap();

        assert_eq!(provider.merkle_store_node_count, base_node_count + 1);
        assert!(provider.has_merkle_root(tree.root()));
    }

    #[test]
    fn merkle_store_extend_counts_only_new_unique_nodes() {
        let base_node_count = MerkleStore::default().num_internal_nodes();
        let tree = merkle_tree_from_leaves(0..2);
        let options = ExecutionOptions::default().with_max_merkle_store_nodes(base_node_count + 1);
        let mut provider = AdviceProvider::new(AdviceInputs::default(), &options).unwrap();
        let nodes = tree.inner_nodes().collect::<Vec<_>>();

        provider
            .extend_merkle_store(nodes.iter().cloned().chain(nodes.iter().cloned()))
            .unwrap();
        provider.extend_merkle_store(nodes).unwrap();

        assert_eq!(provider.merkle_store_node_count, base_node_count + 1);
        assert!(provider.has_merkle_root(tree.root()));
    }

    #[test]
    fn merkle_store_merge_respects_node_budget_atomically() {
        let base_node_count = MerkleStore::default().num_internal_nodes();
        let options = ExecutionOptions::default().with_max_merkle_store_nodes(base_node_count);
        let mut provider = AdviceProvider::new(AdviceInputs::default(), &options).unwrap();

        let err = provider.merge_roots(make_leaf(0), make_leaf(4)).unwrap_err();
        assert!(matches!(
            err,
            AdviceError::MerkleStoreNodeBudgetExceeded {
                current,
                added: 1,
                max
            } if current == base_node_count && max == base_node_count
        ));

        assert_eq!(provider.merkle_store_node_count, base_node_count);
    }

    #[test]
    fn merkle_store_update_respects_node_budget_atomically() {
        let tree = merkle_tree_from_leaves(0..4);
        let store = merkle_store_from_tree(&tree);
        let node_count = store.num_internal_nodes();
        let options = ExecutionOptions::default().with_max_merkle_store_nodes(node_count);
        let inputs = AdviceInputs::default().with_merkle_store(store);
        let mut provider = AdviceProvider::new(inputs, &options).unwrap();

        let err = provider
            .update_merkle_node(tree.root(), Felt::new_unchecked(2), Felt::ZERO, make_leaf(100))
            .unwrap_err();
        assert!(matches!(
            err,
            AdviceError::MerkleStoreNodeBudgetExceeded {
                current,
                added: _,
                max
            } if current == node_count && max == node_count
        ));

        assert_eq!(provider.merkle_store_node_count, node_count);
        assert_eq!(
            provider.get_tree_node(tree.root(), Felt::new_unchecked(2), Felt::ZERO).unwrap(),
            make_leaf(0)
        );
    }

    #[test]
    fn merkle_store_update_allows_exact_node_budget() {
        let tree = merkle_tree_from_leaves(0..4);
        let store = merkle_store_from_tree(&tree);
        let mut staged = store.clone();
        staged
            .set_node(
                tree.root(),
                miden_core::crypto::merkle::NodeIndex::new(2, 0).unwrap(),
                make_leaf(100),
            )
            .unwrap();
        let options =
            ExecutionOptions::default().with_max_merkle_store_nodes(staged.num_internal_nodes());
        let inputs = AdviceInputs::default().with_merkle_store(store);
        let mut provider = AdviceProvider::new(inputs, &options).unwrap();

        provider
            .update_merkle_node(tree.root(), Felt::new_unchecked(2), Felt::ZERO, make_leaf(100))
            .unwrap();

        assert_eq!(provider.merkle_store_node_count, staged.num_internal_nodes());
    }

    fn advice_map_from_entries(keys: impl Iterator<Item = u64>, value_len: usize) -> AdviceMap {
        keys.map(|key| {
            let values = (0..value_len)
                .map(|offset| Felt::new_unchecked(key + offset as u64))
                .collect::<Vec<_>>();
            (make_leaf(key), values)
        })
        .collect::<BTreeMap<_, _>>()
        .into()
    }

    fn merkle_tree_from_leaves(keys: impl Iterator<Item = u64>) -> MerkleTree {
        MerkleTree::new(keys.map(make_leaf).collect::<Vec<_>>()).unwrap()
    }

    fn merkle_store_from_tree(tree: &MerkleTree) -> MerkleStore {
        let mut store = MerkleStore::default();
        store.extend(tree.inner_nodes());
        store
    }
}
