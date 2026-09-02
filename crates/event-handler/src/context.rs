use alloc::{vec, vec::Vec};
use core::fmt;

use miden_core::{
    ContextId, Felt, MemoryAddress, WORD_SIZE, Word, ZERO,
    advice::{AdviceMap, AdviceStack},
    crypto::merkle::{MerkleError, MerklePath, NodeIndex},
    deferred::{Digest, Node, PrecompileError},
    events::EventId,
};

/// Distinguishes the two VM callback kinds that use [`EventContext`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvocationKind {
    /// A custom event which may return advice mutations.
    Event,
    /// An optional, read-only trace event.
    Trace,
}

/// Semantic metadata captured by the processor at callback dispatch.
///
/// The processor decodes the stack layout once: a custom event ID comes from stack position 0,
/// while a trace ID comes from position 1. Handlers receive the semantic ID directly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Invocation {
    kind: InvocationKind,
    id: EventId,
    clock: u32,
    context_id: ContextId,
}

impl Invocation {
    /// Creates custom-event invocation metadata.
    #[doc(hidden)]
    pub const fn event(id: EventId, clock: u32, context_id: ContextId) -> Self {
        Self {
            kind: InvocationKind::Event,
            id,
            clock,
            context_id,
        }
    }

    /// Creates trace-event invocation metadata.
    #[doc(hidden)]
    pub const fn trace(id: EventId, clock: u32, context_id: ContextId) -> Self {
        Self {
            kind: InvocationKind::Trace,
            id,
            clock,
            context_id,
        }
    }

    /// Returns the callback kind.
    pub const fn kind(self) -> InvocationKind {
        self.kind
    }

    /// Returns the semantic custom-event or trace-event ID.
    pub const fn id(self) -> EventId {
        self.id
    }

    /// Returns the processor clock at dispatch.
    pub const fn clock(self) -> u32 {
        self.clock
    }

    /// Returns the active execution context at dispatch.
    pub const fn context_id(self) -> ContextId {
        self.context_id
    }
}

/// Errors returned by memory read capabilities.
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum MemoryReadError {
    /// A field-element address did not fit in the VM's `u32` address space.
    #[error("memory address cannot exceed 2^32 but was {address}")]
    AddressOutOfBounds { address: u64 },
    /// A half-open range extended past the end of the VM's address space.
    #[error("memory range starting at {start} with {count} elements exceeds the address space")]
    RangeOverflow { start: u32, count: usize },
    /// A range derived from two stack values had its end before its start.
    #[error("memory range start cannot exceed end, but was ({start}, {end})")]
    InvalidRange { start: u64, end: u64 },
    /// A strict range read touched a word which has never been initialized.
    #[error("memory at address {address} in context {context_id} is uninitialized")]
    Uninitialized { context_id: ContextId, address: u32 },
    /// A word read used an address which is not divisible by four.
    #[error("word address {address} in context {context_id} is not aligned to four elements")]
    UnalignedWord { context_id: ContextId, address: u32 },
}

/// Errors returned by strict advice-stack range reads.
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum AdviceReadError {
    /// Computing the requested half-open range overflowed `usize`.
    #[error("advice-stack range starting at {start} with {count} elements overflows")]
    RangeOverflow { start: usize, count: usize },
    /// The requested range extended beyond the advice stack.
    #[error(
        "advice-stack range starting at {start} with {count} elements exceeds stack length {len}"
    )]
    OutOfBounds { start: usize, count: usize, len: usize },
}

/// Errors returned by typed Merkle-store reads.
#[derive(Debug, thiserror::Error)]
pub enum MerkleReadError {
    /// Legacy depth/position values did not form a valid [`NodeIndex`].
    #[error("invalid Merkle node index at depth {depth}, position {position}")]
    InvalidNodeIndex { depth: u64, position: u64 },
    /// The requested node or path is not present in the Merkle store.
    #[error("Merkle store lookup failed: {0}")]
    Lookup(#[source] MerkleError),
}

impl From<MerkleError> for MerkleReadError {
    fn from(error: MerkleError) -> Self {
        Self::Lookup(error)
    }
}

/// Read-only capabilities an execution engine provides to [`EventContext`].
///
/// This object-safe interface is public only so execution-engine adapters can implement it.
/// Handler implementations should use [`EventContext`]. Range defaults are deliberately built
/// from the smallest primitive reads and preserve the caller's output buffer on error.
#[doc(hidden)]
pub trait EventContextProvider: Sync {
    fn stack_depth(&self) -> usize;

    fn stack_item(&self, position: usize) -> Felt;

    fn read_stack(&self, start: usize, output: &mut [Felt]) {
        for (offset, value) in output.iter_mut().enumerate() {
            *value = start.checked_add(offset).map_or(ZERO, |position| self.stack_item(position));
        }
    }

    fn stack_word(&self, start: usize) -> Word {
        let mut elements = [ZERO; WORD_SIZE];
        self.read_stack(start, &mut elements);
        elements.into()
    }

    fn stack_snapshot(&self) -> Vec<Felt> {
        let mut snapshot = vec![ZERO; self.stack_depth()];
        self.read_stack(0, &mut snapshot);
        snapshot
    }

    fn memory_value(&self, context_id: ContextId, address: u32) -> Option<Felt>;

    fn read_memory(
        &self,
        context_id: ContextId,
        start: u32,
        output: &mut [Felt],
    ) -> Result<(), MemoryReadError> {
        check_memory_range(start, output.len())?;

        let mut pending = Vec::with_capacity(output.len());
        for offset in 0..output.len() {
            let address = start + offset as u32;
            let value = self
                .memory_value(context_id, address)
                .ok_or(MemoryReadError::Uninitialized { context_id, address })?;
            pending.push(value);
        }
        output.copy_from_slice(&pending);
        Ok(())
    }

    fn memory_word(
        &self,
        context_id: ContextId,
        address: u32,
    ) -> Result<Option<Word>, MemoryReadError> {
        if !address.is_multiple_of(WORD_SIZE as u32) {
            return Err(MemoryReadError::UnalignedWord { context_id, address });
        }

        let mut elements = [ZERO; WORD_SIZE];
        match self.read_memory(context_id, address, &mut elements) {
            Ok(()) => Ok(Some(elements.into())),
            Err(MemoryReadError::Uninitialized { .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn memory_snapshot(&self, context_id: ContextId) -> Vec<(MemoryAddress, Felt)>;

    fn advice_stack(&self) -> &AdviceStack;

    fn advice_map(&self) -> &AdviceMap;

    fn merkle_node(&self, root: Word, index: NodeIndex) -> Result<Word, MerkleReadError>;

    fn merkle_path(&self, root: Word, index: NodeIndex) -> Result<MerklePath, MerkleReadError>;

    fn has_merkle_path(&self, root: Word, index: NodeIndex) -> bool;

    fn has_merkle_root(&self, root: Word) -> bool;
}

/// Internal capabilities needed only by Miden's built-in handlers.
///
/// This is separate from [`EventContextProvider`] so public handlers cannot couple themselves to
/// the full processor execution options or deferred-state implementation.
#[doc(hidden)]
pub trait BuiltinEventContextProvider: Sync {
    fn max_hash_len_bytes(&self) -> usize;

    fn max_advice_size_bytes(&self) -> usize;

    fn canonical_deferred_digest(&self, digest: Digest) -> Option<Digest>;

    fn canonical_deferred_node(&self, digest: Digest) -> Option<(Digest, &Node)>;

    fn require_canonical_deferred_node(
        &self,
        digest: Digest,
    ) -> Result<(Digest, &Node), PrecompileError>;
}

/// A read-only, processor-independent view passed to native event and trace handlers.
pub struct EventContext<'a> {
    pub(crate) provider: &'a dyn EventContextProvider,
    builtins: &'a dyn BuiltinEventContextProvider,
    invocation: Invocation,
}

impl fmt::Debug for EventContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventContext")
            .field("invocation", &self.invocation)
            .finish_non_exhaustive()
    }
}

impl<'a> EventContext<'a> {
    /// Creates a context from execution-engine adapters and semantic invocation metadata.
    #[doc(hidden)]
    pub const fn new(
        provider: &'a dyn EventContextProvider,
        builtins: &'a dyn BuiltinEventContextProvider,
        invocation: Invocation,
    ) -> Self {
        Self { provider, builtins, invocation }
    }

    /// Returns all semantic invocation metadata.
    pub const fn invocation(&self) -> Invocation {
        self.invocation
    }

    /// Returns whether this is an event or trace callback.
    pub const fn kind(&self) -> InvocationKind {
        self.invocation.kind()
    }

    /// Returns the semantic custom-event or trace-event ID.
    pub const fn id(&self) -> EventId {
        self.invocation.id()
    }

    /// Returns the semantic custom-event or trace-event ID.
    ///
    /// This spelling is retained for handlers written against the precursor interface. New code
    /// which handles both callback kinds can use [`Self::id`].
    pub const fn event_id(&self) -> EventId {
        self.id()
    }

    /// Returns the processor clock at callback dispatch.
    pub const fn clock(&self) -> u32 {
        self.invocation.clock()
    }

    /// Returns the active execution context at callback dispatch.
    pub const fn context_id(&self) -> ContextId {
        self.invocation.context_id()
    }

    /// Returns the current operand-stack depth.
    pub fn stack_depth(&self) -> usize {
        self.provider.stack_depth()
    }

    /// Returns an operand-stack element, or zero when `position` is beyond the current depth.
    pub fn stack_item(&self, position: usize) -> Felt {
        self.provider.stack_item(position)
    }

    /// Reads stack positions into `output`, zero-extending beyond the current depth.
    pub fn read_stack(&self, start: usize, output: &mut [Felt]) {
        self.provider.read_stack(start, output);
    }

    /// Returns four stack elements beginning at `start`, zero-extending when necessary.
    pub fn stack_word(&self, start: usize) -> Word {
        self.provider.stack_word(start)
    }

    /// Allocates a stack range, zero-extending when it crosses the current depth.
    pub fn stack_range(&self, start: usize, count: usize) -> Vec<Felt> {
        let mut values = vec![ZERO; count];
        self.read_stack(start, &mut values);
        values
    }

    /// Allocates a snapshot of the complete operand stack, top first.
    pub fn stack_snapshot(&self) -> Vec<Felt> {
        self.provider.stack_snapshot()
    }

    /// Returns a memory value from the active execution context.
    pub fn memory_value(&self, address: u32) -> Option<Felt> {
        self.memory_value_in_context(self.context_id(), address)
    }

    /// Returns a memory value from an explicit execution context.
    pub fn memory_value_in_context(&self, context_id: ContextId, address: u32) -> Option<Felt> {
        self.provider.memory_value(context_id, address)
    }

    /// Returns an aligned memory word from the active execution context.
    pub fn memory_word(&self, address: u32) -> Result<Option<Word>, MemoryReadError> {
        self.memory_word_in_context(self.context_id(), address)
    }

    /// Returns an aligned memory word from an explicit execution context.
    pub fn memory_word_in_context(
        &self,
        context_id: ContextId,
        address: u32,
    ) -> Result<Option<Word>, MemoryReadError> {
        self.provider.memory_word(context_id, address)
    }

    /// Strictly reads a memory range from the active context into `output`.
    ///
    /// On overflow or an uninitialized word, `output` is left unchanged.
    pub fn read_memory(&self, start: u32, output: &mut [Felt]) -> Result<(), MemoryReadError> {
        self.read_memory_in_context(self.context_id(), start, output)
    }

    /// Strictly reads a memory range from an explicit context into `output`.
    ///
    /// On overflow or an uninitialized word, `output` is left unchanged.
    pub fn read_memory_in_context(
        &self,
        context_id: ContextId,
        start: u32,
        output: &mut [Felt],
    ) -> Result<(), MemoryReadError> {
        self.provider.read_memory(context_id, start, output)
    }

    /// Allocates a strict memory range from the active execution context.
    pub fn memory_range(&self, start: u32, count: usize) -> Result<Vec<Felt>, MemoryReadError> {
        self.memory_range_in_context(self.context_id(), start, count)
    }

    /// Allocates a strict memory range from an explicit execution context.
    pub fn memory_range_in_context(
        &self,
        context_id: ContextId,
        start: u32,
        count: usize,
    ) -> Result<Vec<Felt>, MemoryReadError> {
        let mut values = vec![ZERO; count];
        self.read_memory_in_context(context_id, start, &mut values)?;
        Ok(values)
    }

    /// Reads and validates a half-open memory address range from two stack positions.
    pub fn memory_range_from_stack(
        &self,
        start_position: usize,
        end_position: usize,
    ) -> Result<core::ops::Range<u32>, MemoryReadError> {
        let start = self.stack_item(start_position).as_canonical_u64();
        let end = self.stack_item(end_position).as_canonical_u64();
        if start > u32::MAX as u64 {
            return Err(MemoryReadError::AddressOutOfBounds { address: start });
        }
        if end > u32::MAX as u64 {
            return Err(MemoryReadError::AddressOutOfBounds { address: end });
        }
        if start > end {
            return Err(MemoryReadError::InvalidRange { start, end });
        }
        Ok(start as u32..end as u32)
    }

    /// Allocates a snapshot of initialized memory in the active execution context.
    pub fn memory_snapshot(&self) -> Vec<(MemoryAddress, Felt)> {
        self.memory_snapshot_in_context(self.context_id())
    }

    /// Allocates a snapshot of initialized memory in an explicit execution context.
    pub fn memory_snapshot_in_context(&self, context_id: ContextId) -> Vec<(MemoryAddress, Felt)> {
        self.provider.memory_snapshot(context_id)
    }

    /// Returns the borrowed advice stack, ordered from top to bottom.
    pub fn advice_stack(&self) -> &AdviceStack {
        self.provider.advice_stack()
    }

    /// Returns the borrowed advice map.
    pub fn advice_map(&self) -> &AdviceMap {
        self.provider.advice_map()
    }

    /// Returns true when the advice map contains `key`.
    pub fn advice_map_contains(&self, key: &Word) -> bool {
        self.advice_map().contains_key(key)
    }

    /// Returns the advice-map value for `key`.
    pub fn advice_map_entry(&self, key: &Word) -> Option<&[Felt]> {
        self.advice_map().get(key).map(AsRef::as_ref)
    }

    /// Strictly reads an advice-stack range into `output`.
    ///
    /// On overflow or an out-of-bounds range, `output` is left unchanged.
    pub fn read_advice_stack(
        &self,
        start: usize,
        output: &mut [Felt],
    ) -> Result<(), AdviceReadError> {
        let count = output.len();
        let end = start
            .checked_add(count)
            .ok_or(AdviceReadError::RangeOverflow { start, count })?;
        let stack = self.advice_stack();
        if end > stack.len() {
            return Err(AdviceReadError::OutOfBounds { start, count, len: stack.len() });
        }

        for (target, value) in output.iter_mut().zip(stack.iter().skip(start)) {
            *target = *value;
        }
        Ok(())
    }

    /// Allocates a strict advice-stack range.
    pub fn advice_stack_range(
        &self,
        start: usize,
        count: usize,
    ) -> Result<Vec<Felt>, AdviceReadError> {
        let mut values = vec![ZERO; count];
        self.read_advice_stack(start, &mut values)?;
        Ok(values)
    }

    /// Clones the current advice stack.
    pub fn advice_stack_snapshot(&self) -> AdviceStack {
        self.advice_stack().clone()
    }

    /// Clones the current advice map.
    pub fn advice_map_snapshot(&self) -> AdviceMap {
        self.advice_map().clone()
    }

    /// Returns a node from the advice Merkle store.
    pub fn merkle_node(&self, root: Word, index: NodeIndex) -> Result<Word, MerkleReadError> {
        self.provider.merkle_node(root, index)
    }

    /// Returns a path from the advice Merkle store.
    pub fn merkle_path(&self, root: Word, index: NodeIndex) -> Result<MerklePath, MerkleReadError> {
        self.provider.merkle_path(root, index)
    }

    /// Returns true when the advice Merkle store contains the requested path.
    pub fn has_merkle_path(&self, root: Word, index: NodeIndex) -> bool {
        self.provider.has_merkle_path(root, index)
    }

    /// Returns true when the advice Merkle store contains `root`.
    pub fn has_merkle_root(&self, root: Word) -> bool {
        self.provider.has_merkle_root(root)
    }

    /// Returns the narrow capability view reserved for Miden's built-in handlers.
    #[doc(hidden)]
    pub const fn builtins(&self) -> BuiltinEventContext<'a> {
        BuiltinEventContext { provider: self.builtins }
    }
}

/// Narrow read capabilities reserved for Miden's built-in handlers.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct BuiltinEventContext<'a> {
    provider: &'a dyn BuiltinEventContextProvider,
}

impl<'a> BuiltinEventContext<'a> {
    pub fn max_hash_len_bytes(self) -> usize {
        self.provider.max_hash_len_bytes()
    }

    pub fn max_advice_size_bytes(self) -> usize {
        self.provider.max_advice_size_bytes()
    }

    pub fn canonical_deferred_digest(self, digest: Digest) -> Option<Digest> {
        self.provider.canonical_deferred_digest(digest)
    }

    pub fn canonical_deferred_node(self, digest: Digest) -> Option<(Digest, &'a Node)> {
        self.provider.canonical_deferred_node(digest)
    }

    pub fn require_canonical_deferred_node(
        self,
        digest: Digest,
    ) -> Result<(Digest, &'a Node), PrecompileError> {
        self.provider.require_canonical_deferred_node(digest)
    }
}

pub(crate) fn check_memory_range(start: u32, count: usize) -> Result<(), MemoryReadError> {
    let count_u64 = u64::try_from(count).unwrap_or(u64::MAX);
    if u64::from(start).saturating_add(count_u64) > u64::from(u32::MAX) + 1 {
        return Err(MemoryReadError::RangeOverflow { start, count });
    }
    Ok(())
}

pub(crate) fn node_index_from_elements(
    depth: Felt,
    position: Felt,
) -> Result<NodeIndex, MerkleReadError> {
    NodeIndex::from_elements(&depth, &position).map_err(|_| MerkleReadError::InvalidNodeIndex {
        depth: depth.as_canonical_u64(),
        position: position.as_canonical_u64(),
    })
}
