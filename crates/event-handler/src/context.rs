use alloc::{vec, vec::Vec};
use core::{alloc::Layout, fmt};

use miden_core::{
    Felt, MemoryAddress, WORD_SIZE, Word, ZERO,
    advice::{AdviceMap, AdviceStack},
    crypto::merkle::{MerkleError, MerklePath, NodeIndex},
    events::EventId,
};

use crate::EventContextError;

/// Distinguishes the two VM callback kinds that use [`EventContext`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvocationKind {
    /// A custom event which may record advice.
    Event,
    /// An optional, read-only trace event.
    Trace,
}

/// Semantic metadata captured by the execution-engine adapter at handler dispatch.
///
/// The adapter decodes the raw stack layout: a custom event ID comes from stack position 0,
/// while a trace ID comes from position 1. Handlers receive the semantic ID directly, independently
/// of the registry key used to route the invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Invocation {
    kind: InvocationKind,
    id: EventId,
    clock: u32,
    in_root_context: bool,
}

impl Invocation {
    /// Creates custom-event invocation metadata.
    pub const fn event(id: EventId, clock: u32, in_root_context: bool) -> Self {
        Self {
            kind: InvocationKind::Event,
            id,
            clock,
            in_root_context,
        }
    }

    /// Creates trace-event invocation metadata.
    pub const fn trace(id: EventId, clock: u32, in_root_context: bool) -> Self {
        Self {
            kind: InvocationKind::Trace,
            id,
            clock,
            in_root_context,
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

    /// Returns whether the handler was invoked in the root execution context.
    pub const fn in_root_context(self) -> bool {
        self.in_root_context
    }
}

/// Read-only capabilities an execution engine provides to [`EventContext`].
///
/// This public, object-safe engine interface allows processor implementations to supply reads.
/// Handler implementations should use [`EventContext`]. Providers expose the raw operand stack,
/// including the event or trace dispatch envelope. Implementations must zero-extend
/// [`Self::read_stack`] and leave `output` unchanged when any memory read returns an error.
/// Providers resolve the current and root contexts internally; both reads must address the same
/// memory when execution is in the root context.
/// Strict memory reads report an uninitialized word with
/// [`EventContextError::UninitializedMemory`]. Zero-filled reads expose uninitialized memory as
/// zero and let providers fill bulk output directly without allocating an intermediate buffer.
#[doc(hidden)]
pub trait EventContextProvider: Sync {
    fn stack_depth(&self) -> u32;

    fn read_stack(&self, start: u64, output: &mut [Felt]);

    /// Reads memory in the current execution context according to `mode`.
    fn read_memory(
        &self,
        start: MemoryAddress,
        output: &mut [Felt],
        mode: MemoryReadMode,
    ) -> Result<(), EventContextError>;

    /// Reads memory in the root execution context according to `mode`.
    fn read_memory_root(
        &self,
        start: MemoryAddress,
        output: &mut [Felt],
        mode: MemoryReadMode,
    ) -> Result<(), EventContextError>;

    fn memory_snapshot(&self) -> Vec<(MemoryAddress, Felt)>;

    fn memory_snapshot_root(&self) -> Vec<(MemoryAddress, Felt)>;

    fn advice_stack(&self) -> &AdviceStack;

    fn advice_map(&self) -> &AdviceMap;

    fn merkle_node(&self, root: Word, index: NodeIndex) -> Result<Word, MerkleError>;

    fn merkle_path(&self, root: Word, index: NodeIndex) -> Result<MerklePath, MerkleError>;
}

/// A read-only, processor-independent view passed by value to registered native handlers.
///
/// Copying this view copies a provider reference and invocation metadata, not VM state. Borrowed
/// advice reads retain the provider lifetime, so helpers can accept a context by value and return
/// borrowed data. Neither a copy nor a returned reference may outlive the underlying VM borrow.
#[derive(Clone, Copy)]
pub struct EventContext<'a> {
    pub(crate) provider: &'a dyn EventContextProvider,
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
    /// Creates a context from an execution-engine adapter and semantic invocation metadata.
    #[doc(hidden)]
    pub const fn new(provider: &'a dyn EventContextProvider, invocation: Invocation) -> Self {
        Self { provider, invocation }
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

    /// Returns whether the handler was invoked in the root execution context.
    pub const fn in_root_context(&self) -> bool {
        self.invocation.in_root_context()
    }

    /// Returns the number of operand-stack elements visible to the handler.
    ///
    /// The dispatch envelope is excluded: one element for an event and two for a trace.
    pub fn stack_depth(&self) -> u32 {
        self.provider.stack_depth().saturating_sub(self.stack_prefix_len())
    }

    /// Returns a handler-visible operand-stack element, or zero when `position` is out of bounds.
    pub fn stack_item(&self, position: u64) -> Felt {
        self.read_stack_array::<1>(position)[0]
    }

    /// Reads handler-visible operand-stack elements into `output`, zero-extending when necessary.
    pub fn read_stack(&self, start: u64, output: &mut [Felt]) {
        let Some(start) = start.checked_add(u64::from(self.stack_prefix_len())) else {
            output.fill(ZERO);
            return;
        };
        self.provider.read_stack(start, output);
    }

    /// Returns `N` handler-visible operand-stack elements beginning at `start`, top first,
    /// zero-extending when necessary.
    pub fn read_stack_array<const N: usize>(&self, start: u64) -> [Felt; N] {
        let mut elements = [ZERO; N];
        self.read_stack(start, &mut elements);
        elements
    }

    /// Returns four handler-visible operand-stack elements beginning at `start`, zero-extending
    /// when necessary.
    pub fn stack_word(&self, start: u64) -> Word {
        self.read_stack_array::<WORD_SIZE>(start).into()
    }

    /// Allocates a snapshot of all operand-stack elements visible to the handler, top first.
    pub fn stack_snapshot(&self) -> Vec<Felt> {
        let mut values = vec![ZERO; self.stack_depth() as usize];
        self.read_stack(0, &mut values);
        values
    }

    /// Returns the size of the raw dispatch envelope on the operand stack.
    const fn stack_prefix_len(&self) -> u32 {
        match self.kind() {
            InvocationKind::Event => 1,
            InvocationKind::Trace => 2,
        }
    }

    /// Returns a memory value from the current execution context, or `None` when its word is
    /// uninitialized.
    pub fn memory_value(&self, address: u64) -> Result<Option<Felt>, EventContextError> {
        self.memory_array_from::<1>(MemoryScope::Current, address)
            .map(|value| value.map(|[value]| value))
    }

    /// Returns a memory value from the root execution context, or `None` when its word is
    /// uninitialized.
    pub fn memory_value_root(&self, address: u64) -> Result<Option<Felt>, EventContextError> {
        self.memory_array_from::<1>(MemoryScope::Root, address)
            .map(|value| value.map(|[value]| value))
    }

    /// Returns an aligned memory word from the current execution context, or `None` when it is
    /// uninitialized.
    pub fn memory_word(&self, address: u64) -> Result<Option<Word>, EventContextError> {
        self.memory_array_from::<WORD_SIZE>(MemoryScope::Current, address)
            .map(|word| word.map(Word::new))
    }

    /// Returns an aligned memory word from the root execution context, or `None` when it is
    /// uninitialized.
    pub fn memory_word_root(&self, address: u64) -> Result<Option<Word>, EventContextError> {
        self.memory_array_from::<WORD_SIZE>(MemoryScope::Root, address)
            .map(|word| word.map(Word::new))
    }

    /// Reads a memory range from the current execution context into `output`.
    ///
    /// Uninitialized memory is read as zero. Address validation occurs before the provider is
    /// called, and `output` is left unchanged on an invalid address, overflow, or provider error.
    pub fn read_memory(&self, start: u64, output: &mut [Felt]) -> Result<(), EventContextError> {
        self.read_memory_from(MemoryScope::Current, start, output)
    }

    /// Reads a memory range from the root execution context into `output`.
    ///
    /// Uninitialized memory is read as zero. Address validation occurs before the provider is
    /// called, and `output` is left unchanged on an invalid address, overflow, or provider error.
    pub fn read_memory_root(
        &self,
        start: u64,
        output: &mut [Felt],
    ) -> Result<(), EventContextError> {
        self.read_memory_from(MemoryScope::Root, start, output)
    }

    /// Allocates a memory slice from the current execution context.
    ///
    /// Uninitialized memory is represented by zero. The read fails if the address range is invalid.
    pub fn memory_slice(&self, start: u64, count: u64) -> Result<Vec<Felt>, EventContextError> {
        self.memory_slice_from(MemoryScope::Current, start, count)
    }

    /// Allocates a memory slice from the root execution context.
    ///
    /// Uninitialized memory is represented by zero. The read fails if the address range is invalid.
    pub fn memory_slice_root(
        &self,
        start: u64,
        count: u64,
    ) -> Result<Vec<Felt>, EventContextError> {
        self.memory_slice_from(MemoryScope::Root, start, count)
    }

    /// Allocates the half-open memory range `[start, end)` from the current execution context.
    ///
    /// Uninitialized memory is represented by zero. The read fails if the range is reversed or
    /// exceeds the address space.
    pub fn memory_range(&self, start: u64, end: u64) -> Result<Vec<Felt>, EventContextError> {
        self.memory_slice(start, range_count(start, end)?)
    }

    /// Allocates the half-open memory range `[start, end)` from the root execution context.
    ///
    /// Uninitialized memory is represented by zero. The read fails if the range is reversed or
    /// exceeds the address space.
    pub fn memory_range_root(&self, start: u64, end: u64) -> Result<Vec<Felt>, EventContextError> {
        self.memory_slice_root(start, range_count(start, end)?)
    }

    /// Allocates a snapshot of initialized memory in the current execution context.
    pub fn memory_snapshot(&self) -> Vec<(MemoryAddress, Felt)> {
        self.provider.memory_snapshot()
    }

    /// Allocates a snapshot of initialized memory in the root execution context.
    pub fn memory_snapshot_root(&self) -> Vec<(MemoryAddress, Felt)> {
        self.provider.memory_snapshot_root()
    }

    /// Reads one element (`N = 1`) or an aligned word (`N = WORD_SIZE`).
    fn memory_array_from<const N: usize>(
        &self,
        scope: MemoryScope,
        address: u64,
    ) -> Result<Option<[Felt; N]>, EventContextError> {
        let memory_address = check_memory_address(address)?;
        if N == WORD_SIZE && !memory_address.as_u32().is_multiple_of(WORD_SIZE as u32) {
            return Err(EventContextError::UnalignedWord { address: memory_address.as_u32() });
        }

        let mut elements = [ZERO; N];
        match scope.read(self.provider, memory_address, &mut elements, MemoryReadMode::Strict) {
            Ok(()) => Ok(Some(elements)),
            Err(EventContextError::UninitializedMemory { .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn read_memory_from(
        &self,
        scope: MemoryScope,
        start: u64,
        output: &mut [Felt],
    ) -> Result<(), EventContextError> {
        let count = u64::try_from(output.len())
            .map_err(|_| EventContextError::RangeOverflow { start, count: u64::MAX })?;
        check_memory_range(start, count)?;
        // An empty range may start just past the address space, which MemoryAddress cannot hold.
        if output.is_empty() {
            return Ok(());
        }
        scope.read(self.provider, check_memory_address(start)?, output, MemoryReadMode::ZeroFilled)
    }

    fn memory_slice_from(
        &self,
        scope: MemoryScope,
        start: u64,
        count: u64,
    ) -> Result<Vec<Felt>, EventContextError> {
        check_memory_range(start, count)?;
        let count = felt_vec_len(start, count)?;
        let mut values = vec![ZERO; count];
        self.read_memory_from(scope, start, &mut values)?;
        Ok(values)
    }

    /// Returns the borrowed advice stack, ordered from top to bottom.
    pub fn advice_stack(&self) -> &'a AdviceStack {
        self.provider.advice_stack()
    }

    /// Returns the borrowed advice map.
    pub fn advice_map(&self) -> &'a AdviceMap {
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
    pub fn merkle_node(&self, root: Word, index: NodeIndex) -> Result<Word, MerkleError> {
        self.provider.merkle_node(root, index)
    }

    /// Returns a path from the advice Merkle store.
    pub fn merkle_path(&self, root: Word, index: NodeIndex) -> Result<MerklePath, MerkleError> {
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
}

/// Controls how execution-engine memory reads handle uninitialized words.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryReadMode {
    /// Report [`EventContextError::UninitializedMemory`] without modifying the output.
    Strict,
    /// Read uninitialized words as zero.
    ZeroFilled,
}

#[derive(Clone, Copy)]
enum MemoryScope {
    Current,
    Root,
}

impl MemoryScope {
    fn read(
        self,
        provider: &dyn EventContextProvider,
        start: MemoryAddress,
        output: &mut [Felt],
        mode: MemoryReadMode,
    ) -> Result<(), EventContextError> {
        match self {
            Self::Current => provider.read_memory(start, output, mode),
            Self::Root => provider.read_memory_root(start, output, mode),
        }
    }
}

fn range_count(start: u64, end: u64) -> Result<u64, EventContextError> {
    end.checked_sub(start).ok_or(EventContextError::InvalidRange { start, end })
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

fn check_memory_range(start: u64, count: u64) -> Result<(), EventContextError> {
    const EXCLUSIVE_END: u64 = u32::MAX as u64 + 1;

    if start > EXCLUSIVE_END {
        return Err(EventContextError::AddressOutOfBounds { address: start });
    }
    if start.checked_add(count).is_none_or(|end| end > EXCLUSIVE_END) {
        return Err(EventContextError::RangeOverflow { start, count });
    }

    if count != 0 {
        check_memory_address(start)?;
    }
    Ok(())
}
