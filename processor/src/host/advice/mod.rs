use alloc::{
    collections::{BTreeMap, btree_map::Entry},
    vec::Vec,
};

use miden_core::{
    AdviceMap, Felt, Word,
    crypto::merkle::{InnerNodeInfo, MerklePath, MerkleStore, NodeIndex, StoreNode},
};

mod inputs;
pub use inputs::AdviceInputs;

mod errors;
pub use errors::AdviceError;

use crate::host::AdviceMutation;

// TYPE ALIASES
// ================================================================================================

type SimpleMerkleMap = BTreeMap<Word, StoreNode>;

// ADVICE PROVIDER
// ================================================================================================

/// An advice provider is a component through which the VM can request nondeterministic inputs from
/// the host (i.e., result of a computation performed outside of the VM), as well as insert new data
/// into the advice provider to be recovered by the host after the program has finished executing.
///
/// An advice provider consists of the following components:
/// 1. Advice stack, which is a LIFO data structure. The processor can move the elements from the
///    advice stack onto the operand stack, as well as push new elements onto the advice stack.
/// 2. Advice map, which is a key-value map where keys are words (4 field elements) and values are
///    vectors of field elements. The processor can push the values from the map onto the advice
///    stack, as well as insert new values into the map.
/// 3. Merkle store, which contains structured data reducible to Merkle paths. The VM can request
///    Merkle paths from the store, as well as mutate it by updating or merging nodes contained in
///    the store.
///
/// Advice data is store in-memory using [`BTreeMap`](alloc::collections::btree_map::BTreeMap)s as
/// its backing storage.
#[derive(Debug, Clone, Default)]
pub struct AdviceProvider {
    stack: Vec<Felt>,
    map: AdviceMap,
    store: MerkleStore<SimpleMerkleMap>,
}

impl AdviceProvider {
    /// Apply the mutations given in order to the `AdviceProvider`.
    pub fn apply_mutations(
        &mut self,
        mutations: impl IntoIterator<Item = AdviceMutation>,
    ) -> Result<(), AdviceError> {
        mutations.into_iter().try_for_each(|mutation| self.apply_mutation(mutation))
    }

    fn apply_mutation(&mut self, mutation: AdviceMutation) -> Result<(), AdviceError> {
        match mutation {
            AdviceMutation::ExtendStack { values } => {
                self.extend_stack(values);
            },
            AdviceMutation::ExtendMap { other } => {
                self.extend_map(&other)?;
            },
            AdviceMutation::ExtendMerkleStore { infos } => {
                self.extend_merkle_store(infos);
            },
        }
        Ok(())
    }

    // ADVICE STACK
    // --------------------------------------------------------------------------------------------

    /// Pops an element from the advice stack and returns it.
    ///
    /// # Errors
    /// Returns an error if the advice stack is empty.
    pub fn pop_stack(&mut self) -> Result<Felt, AdviceError> {
        self.stack.pop().ok_or(AdviceError::StackReadFailed)
    }

    /// Pops a word (4 elements) from the advice stack and returns it.
    ///
    /// Note: a word is popped off the stack element-by-element. For example, a `[d, c, b, a, ...]`
    /// stack (i.e., `d` is at the top of the stack) will yield `[d, c, b, a]`.
    ///
    /// # Errors
    /// Returns an error if the advice stack does not contain a full word.
    pub fn pop_stack_word(&mut self) -> Result<Word, AdviceError> {
        if self.stack.len() < 4 {
            return Err(AdviceError::StackReadFailed);
        }

        let idx = self.stack.len() - 4;
        let result =
            [self.stack[idx + 3], self.stack[idx + 2], self.stack[idx + 1], self.stack[idx]];

        self.stack.truncate(idx);

        Ok(result.into())
    }

    /// Pops a double word (8 elements) from the advice stack and returns them.
    ///
    /// Note: words are popped off the stack element-by-element. For example, a
    /// `[h, g, f, e, d, c, b, a, ...]` stack (i.e., `h` is at the top of the stack) will yield
    /// two words: `[h, g, f,e ], [d, c, b, a]`.
    ///
    /// # Errors
    /// Returns an error if the advice stack does not contain two words.
    pub fn pop_stack_dword(&mut self) -> Result<[Word; 2], AdviceError> {
        let word0 = self.pop_stack_word()?;
        let word1 = self.pop_stack_word()?;

        Ok([word0, word1])
    }

    /// Pushes a single value onto the advice stack.
    pub fn push_stack(&mut self, value: Felt) {
        self.stack.push(value)
    }

    /// Pushes a word (4 elements) onto the stack.
    pub fn push_stack_word(&mut self, word: &Word) {
        self.stack.extend(word.iter().rev())
    }

    /// Fetches a list of elements under the specified key from the advice map and pushes them onto
    /// the advice stack.
    ///
    /// If `include_len` is set to true, this also pushes the number of elements onto the advice
    /// stack.
    ///
    /// Note: this operation doesn't consume the map element so it can be called multiple times
    /// for the same key.
    ///
    /// # Example
    /// Given an advice stack `[a, b, c, ...]`, and a map `x |-> [d, e, f]`:
    ///
    /// A call `push_stack(AdviceSource::Map { key: x, include_len: false })` will result in
    /// advice stack: `[d, e, f, a, b, c, ...]`.
    ///
    /// A call `push_stack(AdviceSource::Map { key: x, include_len: true })` will result in
    /// advice stack: `[3, d, e, f, a, b, c, ...]`.
    ///
    /// # Errors
    /// Returns an error if the key was not found in the key-value map.
    pub fn push_from_map(&mut self, key: Word, include_len: bool) -> Result<(), AdviceError> {
        let values = self.map.get(&key).ok_or(AdviceError::MapKeyNotFound { key })?;

        self.stack.extend(values.iter().rev());
        if include_len {
            self.stack
                .push(Felt::try_from(values.len() as u64).expect("value length too big"));
        }
        Ok(())
    }

    /// Returns the current stack.
    pub fn stack(&self) -> &[Felt] {
        &self.stack
    }

    /// Extends the stack with the given elements.
    ///
    /// Elements are added to the top of the stack i.e. last element of this iterator is the first
    /// element popped.
    pub fn extend_stack<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = Felt>,
    {
        self.stack.extend(iter);
    }

    // ADVICE MAP
    // --------------------------------------------------------------------------------------------

    /// Returns true if the key has a corresponding value in the map.
    pub fn contains_map_key(&self, key: &Word) -> bool {
        self.map.contains_key(key)
    }

    /// Returns a reference to the value(s) associated with the specified key in the advice map.
    pub fn get_mapped_values(&self, key: &Word) -> Option<&[Felt]> {
        self.map.get(key).map(|value| value.as_ref())
    }

    /// Inserts the provided value into the advice map under the specified key.
    ///
    /// The values in the advice map can be moved onto the advice stack by invoking
    /// the [AdviceProvider::push_from_map()] method.
    ///
    /// Returns an error if the specified key is already present in the advice map.
    pub fn insert_into_map(&mut self, key: Word, values: Vec<Felt>) -> Result<(), AdviceError> {
        match self.map.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(values.into());
            },
            Entry::Occupied(entry) => {
                let existing_values = entry.get().as_ref();
                if existing_values != values {
                    return Err(AdviceError::MapKeyAlreadyPresent {
                        key,
                        prev_values: existing_values.to_vec(),
                        new_values: values,
                    });
                }
            },
        }
        Ok(())
    }

    /// Merges all entries from the given [`AdviceMap`] into the current advice map.
    ///
    /// Returns an error if any new entry already exists with the same key but a different value
    /// than the one currently stored. The current map remains unchanged.
    pub fn extend_map(&mut self, other: &AdviceMap) -> Result<(), AdviceError> {
        self.map.merge(other).map_err(|((key, prev_values), new_values)| {
            AdviceError::MapKeyAlreadyPresent {
                key,
                prev_values: prev_values.to_vec(),
                new_values: new_values.to_vec(),
            }
        })
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
    pub fn get_tree_node(
        &self,
        root: Word,
        depth: &Felt,
        index: &Felt,
    ) -> Result<Word, AdviceError> {
        let index = NodeIndex::from_elements(depth, index).map_err(|_| {
            AdviceError::InvalidMerkleTreeNodeIndex { depth: *depth, index: *index }
        })?;
        self.store.get_node(root, index).map_err(AdviceError::MerkleStoreLookupFailed)
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
        depth: &Felt,
        index: &Felt,
    ) -> Result<MerklePath, AdviceError> {
        let index = NodeIndex::from_elements(depth, index).map_err(|_| {
            AdviceError::InvalidMerkleTreeNodeIndex { depth: *depth, index: *index }
        })?;
        self.store
            .get_path(root, index)
            .map(|value| value.path)
            .map_err(AdviceError::MerkleStoreLookupFailed)
    }

    /// Updates a node at the specified depth and index in a Merkle tree with the specified root;
    /// returns the Merkle path from the updated node to the new root, together with the new root.
    ///
    /// The tree is cloned prior to the update. Thus, the advice provider retains the original and
    /// the updated tree.
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
        depth: &Felt,
        index: &Felt,
        value: Word,
    ) -> Result<(MerklePath, Word), AdviceError> {
        let node_index = NodeIndex::from_elements(depth, index).map_err(|_| {
            AdviceError::InvalidMerkleTreeNodeIndex { depth: *depth, index: *index }
        })?;
        self.store
            .set_node(root, node_index, value)
            .map(|root| (root.path, root.root))
            .map_err(AdviceError::MerkleStoreUpdateFailed)
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
        self.store.merge_roots(lhs, rhs).map_err(AdviceError::MerkleStoreMergeFailed)
    }

    /// Returns true if the Merkle root exists for the advice provider Merkle store.
    pub fn has_merkle_root(&self, root: Word) -> bool {
        self.store.get_node(root, NodeIndex::root()).is_ok()
    }

    /// Extends the [MerkleStore] with the given nodes.
    pub fn extend_merkle_store<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = InnerNodeInfo>,
    {
        self.store.extend(iter);
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Extends the contents of this instance with the contents of an `AdviceInputs`.
    pub fn extend_from_inputs(&mut self, inputs: &AdviceInputs) -> Result<(), AdviceError> {
        self.extend_stack(inputs.stack.iter().cloned().rev());
        self.extend_merkle_store(inputs.store.inner_nodes());
        self.extend_map(&inputs.map)
    }

    /// Consumes `self` and return its parts (stack, map, store).
    ///
    /// Note that the order of the stack is such that the element at the top of the stack is at the
    /// end of the returned vector.
    pub fn into_parts(self) -> (Vec<Felt>, AdviceMap, MerkleStore) {
        (self.stack, self.map, self.store)
    }
}

impl From<AdviceInputs> for AdviceProvider {
    fn from(inputs: AdviceInputs) -> Self {
        let AdviceInputs { mut stack, map, store } = inputs;
        stack.reverse();
        Self { stack, map, store }
    }
}
