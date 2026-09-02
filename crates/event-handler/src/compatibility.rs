//! Deprecated compatibility surface for handlers written against `miden-processor`.
//!
//! Explicit-context methods intentionally read the context supplied by the caller. This differs
//! from the abandoned precursor to this interface, which silently read the active context.

use alloc::vec::Vec;

use miden_core::{
    ContextId, Felt, MemoryAddress, Word,
    deferred::{Digest, Node, PrecompileError},
};

use crate::{EventContext, EventContextError};

fn legacy_stack_position(position: usize) -> u64 {
    u64::try_from(position).unwrap_or(u64::MAX)
}

impl EventContext<'_> {
    /// Legacy alias for [`EventContext::stack_item`].
    #[deprecated(note = "use EventContext::stack_item")]
    pub fn get_stack_item(&self, position: usize) -> Felt {
        self.stack_item(legacy_stack_position(position))
    }

    /// Legacy alias for [`EventContext::stack_word`].
    #[deprecated(note = "use EventContext::stack_word")]
    pub fn get_stack_word(&self, start: usize) -> Word {
        self.stack_word(legacy_stack_position(start))
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
        self.memory_value_in_context(context_id, u64::from(address))
            .expect("a u32 memory address is always valid")
    }

    /// Reads a word from the explicitly supplied execution context.
    #[deprecated(note = "use EventContext::memory_word_in_context")]
    pub fn get_mem_word(
        &self,
        context_id: ContextId,
        address: u32,
    ) -> Result<Option<Word>, EventContextError> {
        self.memory_word_in_context(context_id, u64::from(address))
    }

    /// Allocates a memory snapshot for the explicitly supplied execution context.
    #[deprecated(note = "use EventContext::memory_snapshot_in_context")]
    pub fn get_mem_state(&self, context_id: ContextId) -> Vec<(MemoryAddress, Felt)> {
        self.memory_snapshot_in_context(context_id)
    }

    /// Reads and validates a half-open memory range from two operand-stack positions.
    #[deprecated(
        note = "read the pointers with EventContext::stack_item, then use EventContext::memory_range, memory_slice, memory_value, or memory_word as appropriate"
    )]
    pub fn get_mem_addr_range(
        &self,
        start_position: usize,
        end_position: usize,
    ) -> Result<core::ops::Range<u32>, EventContextError> {
        let start = self.stack_item(legacy_stack_position(start_position)).as_canonical_u64();
        let end = self.stack_item(legacy_stack_position(end_position)).as_canonical_u64();
        if start > u32::MAX as u64 {
            return Err(EventContextError::AddressOutOfBounds { address: start });
        }
        if end > u32::MAX as u64 {
            return Err(EventContextError::AddressOutOfBounds { address: end });
        }
        if start > end {
            return Err(EventContextError::InvalidRange { start, end });
        }
        Ok(start as u32..end as u32)
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
