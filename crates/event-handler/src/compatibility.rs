//! Deprecated compatibility surface for handlers written against `miden-processor`.
//!
//! Explicit-context methods intentionally read the context supplied by the caller. This differs
//! from the abandoned precursor to this interface, which silently read the active context.

use alloc::{vec, vec::Vec};

use miden_core::{
    ContextId, Felt, MemoryAddress, Word,
    advice::{AdviceMap, AdviceStack},
    crypto::merkle::MerklePath,
    deferred::{Digest, Node, PrecompileError},
};

use crate::{
    AdviceReadError, EventContext, EventContextProvider, MemoryReadError, MerkleReadError,
    context::node_index_from_elements,
};

impl EventContext<'_> {
    /// Legacy alias for [`EventContext::stack_item`].
    #[deprecated(note = "use EventContext::stack_item")]
    pub fn get_stack_item(&self, position: usize) -> Felt {
        self.stack_item(position)
    }

    /// Legacy alias for [`EventContext::stack_word`].
    #[deprecated(note = "use EventContext::stack_word")]
    pub fn get_stack_word(&self, start: usize) -> Word {
        self.stack_word(start)
    }

    /// Legacy allocating operand-stack snapshot.
    #[deprecated(note = "use EventContext::stack_snapshot")]
    pub fn get_stack_state(&self) -> Vec<Felt> {
        self.stack_snapshot()
    }

    /// Legacy alias for [`EventContext::context_id`].
    #[deprecated(note = "use EventContext::context_id")]
    pub const fn ctx(&self) -> ContextId {
        self.context_id()
    }

    /// Reads a value from the explicitly supplied execution context.
    #[deprecated(note = "use EventContext::memory_value_in_context")]
    pub fn get_mem_value(&self, context_id: ContextId, address: u32) -> Option<Felt> {
        self.memory_value_in_context(context_id, address)
    }

    /// Reads a word from the explicitly supplied execution context.
    #[deprecated(note = "use EventContext::memory_word_in_context")]
    pub fn get_mem_word(
        &self,
        context_id: ContextId,
        address: u32,
    ) -> Result<Option<Word>, MemoryReadError> {
        self.memory_word_in_context(context_id, address)
    }

    /// Allocates a memory snapshot for the explicitly supplied execution context.
    #[deprecated(note = "use EventContext::memory_snapshot_in_context")]
    pub fn get_mem_state(&self, context_id: ContextId) -> Vec<(MemoryAddress, Felt)> {
        self.memory_snapshot_in_context(context_id)
    }

    /// Reads and validates a half-open memory range from two operand-stack positions.
    #[deprecated(note = "read stack addresses and use EventContext::memory_range")]
    pub fn get_mem_addr_range(
        &self,
        start_position: usize,
        end_position: usize,
    ) -> Result<core::ops::Range<u32>, MemoryReadError> {
        self.memory_range_from_stack(start_position, end_position)
    }

    /// Returns the legacy read-only advice-provider compatibility view.
    #[allow(deprecated)]
    #[deprecated(note = "use EventContext advice and Merkle accessors directly")]
    pub fn advice_provider(&self) -> AdviceProviderView<'_> {
        AdviceProviderView { provider: self.provider }
    }

    /// Legacy read-only deferred digest lookup.
    #[deprecated(note = "deferred lookups are reserved for built-in handlers")]
    pub fn get_canonical_deferred_digest(&self, digest: Digest) -> Option<Digest> {
        self.builtins().canonical_deferred_digest(digest)
    }

    /// Legacy read-only deferred node lookup.
    #[deprecated(note = "deferred lookups are reserved for built-in handlers")]
    pub fn get_canonical_deferred_node(&self, digest: Digest) -> Option<(Digest, &Node)> {
        self.builtins().canonical_deferred_node(digest)
    }

    /// Legacy required deferred node lookup.
    #[deprecated(note = "deferred lookups are reserved for built-in handlers")]
    pub fn require_canonical_deferred_node(
        &self,
        digest: Digest,
    ) -> Result<(Digest, &Node), PrecompileError> {
        self.builtins().require_canonical_deferred_node(digest)
    }
}

/// Temporary read-only view covering the former advice and Merkle query surface.
#[deprecated(note = "use EventContext advice and Merkle accessors directly")]
pub struct AdviceProviderView<'a> {
    provider: &'a dyn EventContextProvider,
}

#[allow(deprecated)]
impl AdviceProviderView<'_> {
    /// Allocates the advice stack as elements ordered from top to bottom.
    pub fn stack(&self) -> Vec<Felt> {
        self.provider.advice_stack().iter().copied().collect()
    }

    /// Returns the number of elements on the advice stack.
    pub fn stack_len(&self) -> usize {
        self.provider.advice_stack().len()
    }

    /// Iterates over the advice stack from top to bottom.
    pub fn stack_iter(&self) -> impl Iterator<Item = &Felt> {
        self.provider.advice_stack().iter()
    }

    /// Returns the borrowed typed advice stack.
    pub fn typed_stack(&self) -> &AdviceStack {
        self.provider.advice_stack()
    }

    /// Returns the borrowed advice map.
    pub fn map(&self) -> &AdviceMap {
        self.provider.advice_map()
    }

    /// Returns true when the advice map contains `key`.
    pub fn contains_map_key(&self, key: &Word) -> bool {
        self.provider.advice_map().contains_key(key)
    }

    /// Returns the advice-map value associated with `key`.
    pub fn get_mapped_values(&self, key: &Word) -> Option<&[Felt]> {
        self.provider.advice_map().get(key).map(AsRef::as_ref)
    }

    /// Strictly reads an advice-stack range without modifying `output` on failure.
    pub fn read_stack(&self, start: usize, output: &mut [Felt]) -> Result<(), AdviceReadError> {
        let count = output.len();
        let end = start
            .checked_add(count)
            .ok_or(AdviceReadError::RangeOverflow { start, count })?;
        let stack = self.provider.advice_stack();
        if end > stack.len() {
            return Err(AdviceReadError::OutOfBounds { start, count, len: stack.len() });
        }
        for (target, value) in output.iter_mut().zip(stack.iter().skip(start)) {
            *target = *value;
        }
        Ok(())
    }

    /// Allocates a strict advice-stack range.
    pub fn stack_range(&self, start: usize, count: usize) -> Result<Vec<Felt>, AdviceReadError> {
        let mut values = vec![Felt::ZERO; count];
        self.read_stack(start, &mut values)?;
        Ok(values)
    }

    /// Returns a Merkle node addressed by legacy depth/position field elements.
    pub fn get_tree_node(
        &self,
        root: Word,
        depth: Felt,
        position: Felt,
    ) -> Result<Word, MerkleReadError> {
        self.provider.merkle_node(root, node_index_from_elements(depth, position)?)
    }

    /// Returns a Merkle path addressed by legacy depth/position field elements.
    pub fn get_merkle_path(
        &self,
        root: Word,
        depth: Felt,
        position: Felt,
    ) -> Result<MerklePath, MerkleReadError> {
        self.provider.merkle_path(root, node_index_from_elements(depth, position)?)
    }

    /// Checks for a Merkle path addressed by legacy depth/position field elements.
    pub fn has_merkle_path(
        &self,
        root: Word,
        depth: Felt,
        position: Felt,
    ) -> Result<bool, MerkleReadError> {
        Ok(self.provider.has_merkle_path(root, node_index_from_elements(depth, position)?))
    }

    /// Returns true when the Merkle store contains `root`.
    pub fn has_merkle_root(&self, root: Word) -> bool {
        self.provider.has_merkle_root(root)
    }
}
