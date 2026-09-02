use alloc::{vec, vec::Vec};
use core::{alloc::Layout, fmt};

use miden_core::{
    ContextId, Felt, MemoryAddress, WORD_SIZE, Word, ZERO,
    advice::{AdviceMap, AdviceStack},
    crypto::merkle::{MerkleError, MerklePath, NodeIndex},
    deferred::{Digest, Node, PrecompileError},
    events::EventId,
};

use crate::EventContextError;

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
    pub const fn event(id: EventId, clock: u32, context_id: ContextId) -> Self {
        Self {
            kind: InvocationKind::Event,
            id,
            clock,
            context_id,
        }
    }

    /// Creates trace-event invocation metadata.
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

/// Errors returned by typed Merkle-store reads.
#[derive(Debug, thiserror::Error)]
pub enum MerkleReadError {
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
/// Handler implementations should use [`EventContext`]. Implementations must zero-extend
/// [`Self::read_stack`] and leave `output` unchanged when [`Self::read_memory`] returns an error.
#[doc(hidden)]
pub trait EventContextProvider: Sync {
    fn stack_depth(&self) -> u32;

    fn read_stack(&self, start: u64, output: &mut [Felt]);

    fn read_memory(
        &self,
        context_id: ContextId,
        start: MemoryAddress,
        output: &mut [Felt],
    ) -> Result<(), EventContextError>;

    fn memory_snapshot(&self, context_id: ContextId) -> Vec<(MemoryAddress, Felt)>;

    fn advice_stack(&self) -> &AdviceStack;

    fn advice_map(&self) -> &AdviceMap;

    fn merkle_node(&self, root: Word, index: NodeIndex) -> Result<Word, MerkleReadError>;

    fn merkle_path(&self, root: Word, index: NodeIndex) -> Result<MerklePath, MerkleReadError>;
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

    /// Returns the processor clock at callback dispatch.
    pub const fn clock(&self) -> u32 {
        self.invocation.clock()
    }

    /// Returns the active execution context at callback dispatch.
    pub const fn context_id(&self) -> ContextId {
        self.invocation.context_id()
    }

    /// Returns the current operand-stack depth.
    pub fn stack_depth(&self) -> u32 {
        self.provider.stack_depth()
    }

    /// Returns an operand-stack element, or zero when `position` is beyond the current depth.
    pub fn stack_item(&self, position: u64) -> Felt {
        let mut value = [ZERO];
        self.read_stack(position, &mut value);
        value[0]
    }

    /// Reads stack positions into `output`, zero-extending beyond the current depth.
    pub fn read_stack(&self, start: u64, output: &mut [Felt]) {
        self.provider.read_stack(start, output);
    }

    /// Returns four stack elements beginning at `start`, zero-extending when necessary.
    pub fn stack_word(&self, start: u64) -> Word {
        let mut elements = [ZERO; WORD_SIZE];
        self.read_stack(start, &mut elements);
        elements.into()
    }

    /// Allocates a stack slice by start and element count, zero-extending when necessary.
    pub fn stack_slice(&self, start: u64, count: u64) -> Result<Vec<Felt>, EventContextError> {
        check_slice_range(start, count)?;
        let count = felt_vec_len(start, count)?;
        let mut values = vec![ZERO; count];
        self.read_stack(start, &mut values);
        Ok(values)
    }

    /// Allocates the half-open stack range `[start, end)`, zero-extending when necessary.
    pub fn stack_range(&self, start: u64, end: u64) -> Result<Vec<Felt>, EventContextError> {
        let count = range_count(start, end)?;
        self.stack_slice(start, count)
    }

    /// Allocates a snapshot of the complete operand stack, top first.
    pub fn stack_snapshot(&self) -> Vec<Felt> {
        let mut values = vec![ZERO; self.stack_depth() as usize];
        self.read_stack(0, &mut values);
        values
    }

    /// Returns a memory value from the active execution context, or `None` when its word is
    /// uninitialized.
    pub fn memory_value(&self, address: u64) -> Result<Option<Felt>, EventContextError> {
        self.memory_value_in_context(self.context_id(), address)
    }

    /// Returns a memory value from an explicit execution context, or `None` when its word is
    /// uninitialized.
    pub fn memory_value_in_context(
        &self,
        context_id: ContextId,
        address: u64,
    ) -> Result<Option<Felt>, EventContextError> {
        let address = check_memory_address(address)?;
        let mut value = [ZERO];
        match self.provider.read_memory(context_id, address, &mut value) {
            Ok(()) => Ok(Some(value[0])),
            Err(EventContextError::UninitializedMemory { .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Returns an aligned memory word from the active execution context, or `None` when it is
    /// uninitialized.
    pub fn memory_word(&self, address: u64) -> Result<Option<Word>, EventContextError> {
        self.memory_word_in_context(self.context_id(), address)
    }

    /// Returns an aligned memory word from an explicit execution context, or `None` when it is
    /// uninitialized.
    pub fn memory_word_in_context(
        &self,
        context_id: ContextId,
        address: u64,
    ) -> Result<Option<Word>, EventContextError> {
        let memory_address = check_memory_address(address)?;
        if !memory_address.as_u32().is_multiple_of(WORD_SIZE as u32) {
            return Err(EventContextError::UnalignedWord {
                context_id,
                address: memory_address.as_u32(),
            });
        }

        let mut elements = [ZERO; WORD_SIZE];
        match self.provider.read_memory(context_id, memory_address, &mut elements) {
            Ok(()) => Ok(Some(elements.into())),
            Err(EventContextError::UninitializedMemory { .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Strictly reads a memory range from the active context into `output`.
    ///
    /// Address validation occurs before the provider is called. On an invalid address, overflow,
    /// or an uninitialized word, `output` is left unchanged.
    pub fn read_memory(&self, start: u64, output: &mut [Felt]) -> Result<(), EventContextError> {
        self.read_memory_in_context(self.context_id(), start, output)
    }

    /// Strictly reads a memory range from an explicit context into `output`.
    ///
    /// Address validation occurs before the provider is called. On an invalid address, overflow,
    /// or an uninitialized word, `output` is left unchanged.
    pub fn read_memory_in_context(
        &self,
        context_id: ContextId,
        start: u64,
        output: &mut [Felt],
    ) -> Result<(), EventContextError> {
        let count = u64::try_from(output.len())
            .map_err(|_| EventContextError::RangeOverflow { start, count: u64::MAX })?;
        let Some(start) = check_memory_range(start, count)? else {
            return Ok(());
        };
        self.provider.read_memory(context_id, start, output)
    }

    /// Allocates a strict memory slice from the active execution context.
    ///
    /// The read fails if the address range is invalid or touches an uninitialized word.
    pub fn memory_slice(&self, start: u64, count: u64) -> Result<Vec<Felt>, EventContextError> {
        self.memory_slice_in_context(self.context_id(), start, count)
    }

    /// Allocates a strict memory slice from an explicit execution context.
    ///
    /// The read fails if the address range is invalid or touches an uninitialized word.
    pub fn memory_slice_in_context(
        &self,
        context_id: ContextId,
        start: u64,
        count: u64,
    ) -> Result<Vec<Felt>, EventContextError> {
        check_memory_range(start, count)?;
        let count = felt_vec_len(start, count)?;
        let mut values = vec![ZERO; count];
        self.read_memory_in_context(context_id, start, &mut values)?;
        Ok(values)
    }

    /// Allocates the strict half-open memory range `[start, end)` from the active context.
    ///
    /// The read fails if the range is reversed, exceeds the address space, or touches an
    /// uninitialized word.
    pub fn memory_range(&self, start: u64, end: u64) -> Result<Vec<Felt>, EventContextError> {
        self.memory_range_in_context(self.context_id(), start, end)
    }

    /// Allocates the strict half-open memory range `[start, end)` from an explicit context.
    ///
    /// The read fails if the range is reversed, exceeds the address space, or touches an
    /// uninitialized word.
    pub fn memory_range_in_context(
        &self,
        context_id: ContextId,
        start: u64,
        end: u64,
    ) -> Result<Vec<Felt>, EventContextError> {
        let count = range_count(start, end)?;
        self.memory_slice_in_context(context_id, start, count)
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

    /// Strictly reads an advice-stack range into `output`.
    ///
    /// On overflow or an out-of-bounds range, `output` is left unchanged.
    pub fn read_advice_stack(
        &self,
        start: u64,
        output: &mut [Felt],
    ) -> Result<(), EventContextError> {
        let count = u64::try_from(output.len())
            .map_err(|_| EventContextError::RangeOverflow { start, count: u64::MAX })?;
        let end = start
            .checked_add(count)
            .ok_or(EventContextError::RangeOverflow { start, count })?;
        let stack = self.advice_stack();
        let len = u64::try_from(stack.len()).unwrap_or(u64::MAX);
        if end > len {
            return Err(EventContextError::AdviceStackOutOfBounds { start, end, len });
        }

        let start = usize::try_from(start).expect("validated advice-stack index must fit in usize");
        for (target, value) in output.iter_mut().zip(stack.iter().skip(start)) {
            *target = *value;
        }
        Ok(())
    }

    /// Allocates a strict advice-stack slice by start and element count.
    pub fn advice_stack_slice(
        &self,
        start: u64,
        count: u64,
    ) -> Result<Vec<Felt>, EventContextError> {
        let end = start
            .checked_add(count)
            .ok_or(EventContextError::RangeOverflow { start, count })?;
        let len = u64::try_from(self.advice_stack().len()).unwrap_or(u64::MAX);
        if end > len {
            return Err(EventContextError::AdviceStackOutOfBounds { start, end, len });
        }

        let count = felt_vec_len(start, count)?;
        let mut values = vec![ZERO; count];
        self.read_advice_stack(start, &mut values)?;
        Ok(values)
    }

    /// Allocates the strict half-open advice-stack range `[start, end)`.
    pub fn advice_stack_range(&self, start: u64, end: u64) -> Result<Vec<Felt>, EventContextError> {
        let count = range_count(start, end)?;
        self.advice_stack_slice(start, count)
    }

    /// Returns a node from the advice Merkle store.
    pub fn merkle_node(&self, root: Word, index: NodeIndex) -> Result<Word, MerkleReadError> {
        self.provider.merkle_node(root, index)
    }

    /// Returns a path from the advice Merkle store.
    pub fn merkle_path(&self, root: Word, index: NodeIndex) -> Result<MerklePath, MerkleReadError> {
        self.provider.merkle_path(root, index)
    }

    /// Returns true when traversal from `root` to the indexed node succeeds.
    pub fn has_merkle_path(&self, root: Word, index: NodeIndex) -> bool {
        self.merkle_node(root, index).is_ok()
    }

    /// Returns true when the advice Merkle store contains `root`.
    pub fn has_merkle_root(&self, root: Word) -> bool {
        self.merkle_node(root, NodeIndex::root()).is_ok()
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

fn range_count(start: u64, end: u64) -> Result<u64, EventContextError> {
    end.checked_sub(start).ok_or(EventContextError::InvalidRange { start, end })
}

fn check_slice_range(start: u64, count: u64) -> Result<(), EventContextError> {
    start
        .checked_add(count)
        .ok_or(EventContextError::RangeOverflow { start, count })?;
    Ok(())
}

fn felt_vec_len(start: u64, count: u64) -> Result<usize, EventContextError> {
    let count_usize =
        usize::try_from(count).map_err(|_| EventContextError::RangeOverflow { start, count })?;
    Layout::array::<Felt>(count_usize)
        .map_err(|_| EventContextError::RangeOverflow { start, count })?;
    Ok(count_usize)
}

fn check_memory_address(address: u64) -> Result<MemoryAddress, EventContextError> {
    MemoryAddress::try_from(address).map_err(|_| EventContextError::AddressOutOfBounds { address })
}

fn check_memory_range(start: u64, count: u64) -> Result<Option<MemoryAddress>, EventContextError> {
    const EXCLUSIVE_END: u64 = u32::MAX as u64 + 1;

    if start > EXCLUSIVE_END {
        return Err(EventContextError::AddressOutOfBounds { address: start });
    }
    if start.checked_add(count).is_none_or(|end| end > EXCLUSIVE_END) {
        return Err(EventContextError::RangeOverflow { start, count });
    }

    if count == 0 {
        Ok(None)
    } else {
        Ok(Some(check_memory_address(start)?))
    }
}
