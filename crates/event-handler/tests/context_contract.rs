use std::collections::BTreeMap;

use miden_core::{
    Felt, MemoryAddress, Word,
    advice::{AdviceMap, AdviceStack},
    crypto::merkle::{MerkleError, MerklePath, NodeIndex},
    events::{EventId, SystemEvent},
};
use miden_event_handler::{
    EventContext, EventContextError, EventContextProvider, Invocation, InvocationKind,
    MemoryReadMode, MerkleReadError,
};

fn felt(value: u64) -> Felt {
    Felt::new_unchecked(value)
}

struct FakeProvider {
    stack: Vec<Felt>,
    memory: BTreeMap<u32, Felt>,
    root_memory: BTreeMap<u32, Felt>,
    in_root_context: bool,
    error_address: Option<u32>,
    advice_stack: AdviceStack,
    advice_map: AdviceMap,
    merkle_root: Word,
    merkle_index: NodeIndex,
    merkle_node: Word,
    merkle_path: MerklePath,
}

impl EventContextProvider for FakeProvider {
    fn stack_depth(&self) -> u32 {
        self.stack.len() as u32
    }

    fn read_stack(&self, start: u64, output: &mut [Felt]) {
        output.fill(Felt::ZERO);
        let Some(values) = usize::try_from(start).ok().and_then(|start| self.stack.get(start..))
        else {
            return;
        };
        let count = output.len().min(values.len());
        output[..count].copy_from_slice(&values[..count]);
    }

    fn read_memory(
        &self,
        start: MemoryAddress,
        output: &mut [Felt],
        mode: MemoryReadMode,
    ) -> Result<(), EventContextError> {
        self.read(self.current_memory(), start, output, mode)
    }

    fn read_memory_root(
        &self,
        start: MemoryAddress,
        output: &mut [Felt],
        mode: MemoryReadMode,
    ) -> Result<(), EventContextError> {
        self.read(&self.root_memory, start, output, mode)
    }

    fn memory_snapshot(&self) -> Vec<(MemoryAddress, Felt)> {
        memory_snapshot(self.current_memory())
    }

    fn memory_snapshot_root(&self) -> Vec<(MemoryAddress, Felt)> {
        memory_snapshot(&self.root_memory)
    }

    fn advice_stack(&self) -> &AdviceStack {
        &self.advice_stack
    }

    fn advice_map(&self) -> &AdviceMap {
        &self.advice_map
    }

    fn merkle_node(&self, root: Word, index: NodeIndex) -> Result<Word, MerkleReadError> {
        if root != self.merkle_root {
            return Err(MerkleError::RootNotInStore(root).into());
        }
        if index == NodeIndex::root() {
            Ok(root)
        } else if index == self.merkle_index {
            Ok(self.merkle_node)
        } else {
            Err(MerkleError::NodeIndexNotFoundInStore(root, index).into())
        }
    }

    fn merkle_path(&self, root: Word, index: NodeIndex) -> Result<MerklePath, MerkleReadError> {
        assert_eq!((root, index), (self.merkle_root, self.merkle_index));
        Ok(self.merkle_path.clone())
    }
}

impl FakeProvider {
    fn current_memory(&self) -> &BTreeMap<u32, Felt> {
        if self.in_root_context {
            &self.root_memory
        } else {
            &self.memory
        }
    }

    fn read(
        &self,
        memory: &BTreeMap<u32, Felt>,
        start: MemoryAddress,
        output: &mut [Felt],
        mode: MemoryReadMode,
    ) -> Result<(), EventContextError> {
        let start = start.as_u32();
        let count = u64::try_from(output.len()).unwrap_or(u64::MAX);
        if u64::from(start).saturating_add(count) > u64::from(u32::MAX) + 1 {
            return Err(EventContextError::RangeOverflow { start: u64::from(start), count });
        }
        let mut pending = Vec::with_capacity(output.len());
        for offset in 0..output.len() {
            let address = start + offset as u32;
            if self.error_address == Some(address) {
                return Err(EventContextError::UnalignedWord { address });
            }
            let value = match memory.get(&address).copied() {
                Some(value) => value,
                None if mode == MemoryReadMode::ZeroFilled => Felt::ZERO,
                None => return Err(EventContextError::UninitializedMemory { address }),
            };
            pending.push(value);
        }
        output.copy_from_slice(&pending);
        Ok(())
    }
}

fn memory_snapshot(memory: &BTreeMap<u32, Felt>) -> Vec<(MemoryAddress, Felt)> {
    memory
        .iter()
        .map(|(&address, &value)| (MemoryAddress::new(address), value))
        .collect()
}

fn fixture() -> (FakeProvider, Word, Word, NodeIndex) {
    let mut memory = BTreeMap::new();
    let mut root_memory = BTreeMap::new();
    for (offset, value) in [21, 22, 23, 24].into_iter().enumerate() {
        memory.insert(4 + offset as u32, felt(value));
    }
    for (offset, value) in [31, 32, 33, 34].into_iter().enumerate() {
        root_memory.insert(4 + offset as u32, felt(value));
    }
    memory.insert(u32::MAX, felt(25));

    let advice_stack = AdviceStack::from(vec![felt(41), felt(42), felt(43)]);
    let map_key = Word::new([felt(51), felt(52), felt(53), felt(54)]);
    let mut advice_map = AdviceMap::default();
    advice_map.insert(map_key, vec![felt(61), felt(62)]);

    let merkle_root = Word::new([felt(71), felt(72), felt(73), felt(74)]);
    let merkle_node = Word::new([felt(81), felt(82), felt(83), felt(84)]);
    let merkle_index = NodeIndex::new(2, 1).unwrap();
    let merkle_path = MerklePath::new(vec![Word::default(), Word::default()]);

    (
        FakeProvider {
            stack: vec![felt(11), felt(12), felt(13)],
            memory,
            root_memory,
            in_root_context: false,
            error_address: None,
            advice_stack,
            advice_map,
            merkle_root,
            merkle_index,
            merkle_node,
            merkle_path,
        },
        map_key,
        merkle_node,
        merkle_index,
    )
}

#[test]
fn metadata_and_stack_reads_follow_the_context_contract() {
    let (provider, ..) = fixture();
    let event_id = EventId::from_u64(11);
    let context = EventContext::new(&provider, Invocation::event(event_id, 456, false));

    assert_eq!(context.kind(), InvocationKind::Event);
    assert_eq!(context.id(), event_id);
    assert_eq!(context.clock(), 456);
    assert!(!context.in_root_context());
    let depth: u32 = context.stack_depth();
    assert_eq!(depth, 2);
    assert_eq!(context.stack_item(0), felt(12));
    assert_eq!(context.stack_item(1), felt(13));
    assert_eq!(context.stack_item(100), Felt::ZERO);
    assert_eq!(context.stack_item(u64::MAX), Felt::ZERO);
    assert_eq!(context.stack_word(1), Word::new([felt(13), Felt::ZERO, Felt::ZERO, Felt::ZERO]));

    let mut output = [felt(99); 5];
    context.read_stack(1, &mut output);
    assert_eq!(output, [felt(13), Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    context.read_stack(u64::MAX, &mut output[..2]);
    assert_eq!(output[..2], [Felt::ZERO, Felt::ZERO]);
    assert_eq!(context.stack_snapshot(), vec![felt(12), felt(13)]);

    let (mut trace_provider, ..) = fixture();
    let trace_id = EventId::from_u64(999);
    trace_provider.stack = vec![
        SystemEvent::TraceEvent.event_id().as_felt(),
        trace_id.as_felt(),
        felt(21),
        felt(22),
    ];
    let trace = EventContext::new(&trace_provider, Invocation::trace(trace_id, 457, false));
    assert_eq!(trace.kind(), InvocationKind::Trace);
    assert_eq!(trace.id(), trace_id);
    assert!(!trace.in_root_context());
    assert_eq!(trace.stack_depth(), 2);
    assert_eq!(trace.stack_snapshot(), vec![felt(21), felt(22)]);
    assert_eq!(trace.stack_item(u64::MAX), Felt::ZERO);

    // Both invocation kinds expose only the payload, in top-first order, including reads that
    // cross its end. Large offsets must not wrap into the dispatch envelope or payload.
    for (context, first, second) in [(context, felt(12), felt(13)), (trace, felt(21), felt(22))] {
        let [a, b, padding] = context.read_stack_array(0);
        assert_eq!([a, b, padding], [first, second, Felt::ZERO]);
        assert_eq!(context.read_stack_array::<2>(1), [second, Felt::ZERO]);
        for start in [2, u64::MAX - 1, u64::MAX] {
            assert_eq!(context.read_stack_array::<2>(start), [Felt::ZERO; 2]);
        }
        for start in [0, u64::MAX] {
            assert_eq!(context.read_stack_array::<0>(start), [Felt::ZERO; 0]);
        }
    }

    let (mut short_provider, ..) = fixture();
    short_provider.stack.truncate(1);
    let short_trace = EventContext::new(&short_provider, Invocation::trace(trace_id, 458, false));
    assert_eq!(short_trace.stack_depth(), 0);
    assert_eq!(short_trace.stack_snapshot(), Vec::<Felt>::new());
    let mut short_output = [felt(99); 2];
    short_trace.read_stack(0, &mut short_output);
    assert_eq!(short_output, [Felt::ZERO; 2]);

    let (mut empty_provider, ..) = fixture();
    empty_provider.stack.clear();
    let empty_event = EventContext::new(&empty_provider, Invocation::event(event_id, 459, false));
    assert_eq!(empty_event.stack_depth(), 0);
    assert_eq!(empty_event.stack_item(0), Felt::ZERO);
}

#[test]
fn memory_reads_honor_context_zero_fill_bulk_reads_and_preserve_buffers_on_error() {
    let (provider, ..) = fixture();
    let context = EventContext::new(&provider, Invocation::event(EventId::from_u64(1), 2, false));

    // Scalar and word reads derive from the canonical buffer read.
    assert_eq!(context.memory_value(4).unwrap(), Some(felt(21)));
    assert_eq!(context.memory_value_root(4).unwrap(), Some(felt(31)));
    assert_eq!(context.memory_value(u64::from(u32::MAX)).unwrap(), Some(felt(25)));
    assert_eq!(context.memory_value(8).unwrap(), None);
    assert_eq!(
        context.memory_value(u64::from(u32::MAX) + 1),
        Err(EventContextError::AddressOutOfBounds { address: u64::from(u32::MAX) + 1 })
    );
    assert_eq!(
        context.memory_word(4).unwrap(),
        Some(Word::new([felt(21), felt(22), felt(23), felt(24)]))
    );
    assert_eq!(
        context.memory_word_root(4).unwrap(),
        Some(Word::new([felt(31), felt(32), felt(33), felt(34)]))
    );
    assert_eq!(context.memory_word(5), Err(EventContextError::UnalignedWord { address: 5 }));
    assert_eq!(context.memory_word(8).unwrap(), None);
    assert_eq!(
        context.memory_word(u64::from(u32::MAX) + 1),
        Err(EventContextError::AddressOutOfBounds { address: u64::from(u32::MAX) + 1 })
    );

    let mut output = [felt(90), felt(91)];
    context.read_memory_root(5, &mut output).unwrap();
    assert_eq!(output, [felt(32), felt(33)]);
    context.read_memory_root(7, &mut output).unwrap();
    assert_eq!(output, [felt(34), Felt::ZERO]);

    let mut terminal = [Felt::ZERO];
    context.read_memory(u64::from(u32::MAX), &mut terminal).unwrap();
    assert_eq!(terminal, [felt(25)]);

    context.read_memory(7, &mut output).unwrap();
    assert_eq!(output, [felt(24), Felt::ZERO]);
    let before = output;
    assert_eq!(
        context.read_memory(u64::from(u32::MAX), &mut output),
        Err(EventContextError::RangeOverflow { start: u64::from(u32::MAX), count: 2 })
    );
    assert_eq!(output, before);
    assert_eq!(
        context.read_memory(u64::from(u32::MAX) + 1, &mut output),
        Err(EventContextError::RangeOverflow { start: u64::from(u32::MAX) + 1, count: 2 })
    );
    assert_eq!(output, before);

    let mut empty = [];
    context.read_memory(u64::from(u32::MAX) + 1, &mut empty).unwrap();
    assert_eq!(
        context.read_memory(u64::from(u32::MAX) + 2, &mut empty),
        Err(EventContextError::AddressOutOfBounds { address: u64::from(u32::MAX) + 2 })
    );

    assert_eq!(
        context.memory_slice(4, 4).unwrap(),
        vec![felt(21), felt(22), felt(23), felt(24)]
    );
    assert_eq!(context.memory_slice_root(5, 2).unwrap(), vec![felt(32), felt(33)]);
    assert_eq!(
        context.memory_slice(u64::from(u32::MAX), 2),
        Err(EventContextError::RangeOverflow { start: u64::from(u32::MAX), count: 2 })
    );
    assert_eq!(context.memory_slice(7, 2).unwrap(), vec![felt(24), Felt::ZERO]);
    assert_eq!(
        context.memory_range(4, 8).unwrap(),
        vec![felt(21), felt(22), felt(23), felt(24)]
    );
    assert_eq!(context.memory_range_root(5, 7).unwrap(), vec![felt(32), felt(33)]);
    assert_eq!(
        context.memory_range(u64::from(u32::MAX), u64::from(u32::MAX) + 1).unwrap(),
        vec![felt(25)]
    );
    assert_eq!(
        context.memory_range(u64::from(u32::MAX) + 1, u64::from(u32::MAX) + 1).unwrap(),
        Vec::<Felt>::new()
    );
    assert_eq!(
        context.memory_range(8, 7),
        Err(EventContextError::InvalidRange { start: 8, end: 7 })
    );
    assert_eq!(
        context.memory_range(u64::from(u32::MAX), u64::from(u32::MAX) + 2),
        Err(EventContextError::RangeOverflow { start: u64::from(u32::MAX), count: 2 })
    );
    assert_eq!(context.memory_range(7, 9).unwrap(), vec![felt(24), Felt::ZERO]);
    assert_eq!(
        context.memory_snapshot_root(),
        vec![
            (MemoryAddress::new(4), felt(31)),
            (MemoryAddress::new(5), felt(32)),
            (MemoryAddress::new(6), felt(33)),
            (MemoryAddress::new(7), felt(34)),
        ]
    );
}

#[test]
fn current_and_root_memory_agree_for_root_invocations() {
    let (mut provider, ..) = fixture();
    provider.in_root_context = true;
    let id = EventId::from_u64(1);
    for (invocation, kind) in [
        (Invocation::event(id, 2, true), InvocationKind::Event),
        (Invocation::trace(id, 2, true), InvocationKind::Trace),
    ] {
        let context = EventContext::new(&provider, invocation);
        assert_eq!(context.kind(), kind);
        assert!(context.in_root_context());
        assert!(context.invocation().in_root_context());

        let invalid = u64::from(u32::MAX) + 1;
        for address in [4, 8, invalid] {
            assert_eq!(context.memory_value(address), context.memory_value_root(address));
        }
        for address in [4, 5, 8] {
            assert_eq!(context.memory_word(address), context.memory_word_root(address));
        }
        for (start, count) in [(4, 4), (7, 2), (invalid, 1)] {
            assert_eq!(context.memory_slice(start, count), context.memory_slice_root(start, count));
        }
        for (start, end) in [(4, 8), (7, 9), (8, 7)] {
            assert_eq!(context.memory_range(start, end), context.memory_range_root(start, end));
        }
        assert_eq!(context.memory_snapshot(), context.memory_snapshot_root());

        for start in [7, invalid] {
            let before = [felt(99); 2];
            let mut current_output = before;
            let mut root_output = before;
            let result = context.read_memory(start, &mut current_output);
            assert_eq!(result, context.read_memory_root(start, &mut root_output));
            assert_eq!(current_output, root_output);
            if result.is_err() {
                assert_eq!(current_output, before);
            }
        }
    }
}

#[test]
fn provider_errors_after_successful_reads_preserve_current_and_root_buffers() {
    let (mut provider, ..) = fixture();
    // The first element is readable; the second returns a provider error other than uninitialized.
    provider.error_address = Some(6);
    let context = EventContext::new(&provider, Invocation::event(EventId::from_u64(1), 2, false));
    let before = [felt(90), felt(91)];
    let mut output = before;
    assert_eq!(
        context.read_memory(5, &mut output),
        Err(EventContextError::UnalignedWord { address: 6 })
    );
    assert_eq!(output, before);
    assert_eq!(
        context.read_memory_root(5, &mut output),
        Err(EventContextError::UnalignedWord { address: 6 })
    );
    assert_eq!(output, before);
}

#[test]
fn advice_and_merkle_reads_are_borrowed_typed_and_atomic() {
    // The wrapper may be copied into helpers without shortening the provider's read lifetime.
    fn borrowed_advice<'a>(context: EventContext<'a>) -> (&'a AdviceStack, &'a AdviceMap) {
        (context.advice_stack(), context.advice_map())
    }
    fn assert_context_bounds<T: Copy + Clone + Send + Sync>() {}
    assert_context_bounds::<EventContext<'_>>();

    let (provider, map_key, merkle_node, merkle_index) = fixture();
    let context = EventContext::new(&provider, Invocation::event(EventId::from_u64(1), 2, false));

    let (stack, map) = borrowed_advice(context);
    assert!(std::ptr::eq(stack, &provider.advice_stack));
    assert!(std::ptr::eq(map, &provider.advice_map));
    assert_eq!(
        context.advice_map().get(&map_key).map(AsRef::as_ref),
        Some([felt(61), felt(62)].as_slice())
    );

    let mut output = [Felt::ZERO; 2];
    context.read_advice_stack(1, &mut output).unwrap();
    assert_eq!(output, [felt(42), felt(43)]);
    assert_eq!(context.advice_stack_slice(1, 2).unwrap(), output);
    assert_eq!(context.advice_stack_range(1, 3).unwrap(), output);
    assert_eq!(context.advice_stack_range(3, 3).unwrap(), Vec::<Felt>::new());
    assert_eq!(
        context.advice_stack_range(3, 1),
        Err(EventContextError::InvalidRange { start: 3, end: 1 })
    );

    let before = output;
    assert_eq!(
        context.read_advice_stack(2, &mut output),
        Err(EventContextError::AdviceStackOutOfBounds { start: 2, end: 4, len: 3 })
    );
    assert_eq!(output, before);
    assert_eq!(
        context.read_advice_stack(u64::MAX, &mut output[..1]),
        Err(EventContextError::RangeOverflow { start: u64::MAX, count: 1 })
    );
    assert_eq!(output, before);
    assert_eq!(
        context.advice_stack_slice(2, 2),
        Err(EventContextError::AdviceStackOutOfBounds { start: 2, end: 4, len: 3 })
    );
    let mut empty = [];
    assert_eq!(
        context.read_advice_stack(u64::from(u32::MAX) + 1, &mut empty),
        Err(EventContextError::AdviceStackOutOfBounds {
            start: u64::from(u32::MAX) + 1,
            end: u64::from(u32::MAX) + 1,
            len: 3,
        })
    );

    assert_eq!(context.merkle_node(provider.merkle_root, merkle_index).unwrap(), merkle_node);
    assert_eq!(
        context.merkle_path(provider.merkle_root, merkle_index).unwrap(),
        provider.merkle_path
    );
    assert!(context.has_merkle_path(provider.merkle_root, merkle_index));
    assert!(context.has_merkle_root(provider.merkle_root));
    assert!(!context.has_merkle_path(provider.merkle_root, NodeIndex::new(2, 2).unwrap()));
    assert!(!context.has_merkle_root(Word::default()));
}

#[test]
fn unified_handlers_preserve_pending_output_across_borrows_and_child_imports() {
    use std::sync::Arc;

    use miden_event_handler::{AdviceBatch, AdviceRecorder, EventError, EventHandler};

    fn handler(
        context: EventContext<'_>,
        advice: &mut AdviceRecorder<'_>,
    ) -> Result<(), EventError> {
        advice.prepend_stack(context.read_stack_array::<2>(0));
        Ok(())
    }
    let (provider, ..) = fixture();
    let context = EventContext::new(&provider, Invocation::event(EventId::from_u64(1), 2, false));
    let shared: Arc<dyn EventHandler> = Arc::new(handler);
    let closure = |context: EventContext<'_>, advice: &mut AdviceRecorder<'_>| {
        advice.prepend_stack([context.stack_item(2)]);
        Ok(())
    };
    let mut batch = AdviceBatch::new();
    shared.handle(context, &mut batch.recorder()).unwrap();
    closure.handle(context, &mut batch.recorder()).unwrap();
    let mut child = AdviceBatch::new();
    child.recorder().prepend_stack([felt(70), felt(71)]);
    let key = Word::default();
    child.recorder().insert_map_entry(key, vec![felt(1)]);
    batch.recorder().insert_map_entry(key, vec![felt(2)]);
    batch.recorder().import(child);
    let (stack, entries, nodes) = batch.into_parts();
    assert_eq!(
        stack.into_elements(),
        vec![
            felt(70),
            felt(71),
            context.stack_item(2),
            context.stack_item(0),
            context.stack_item(1)
        ]
    );
    assert_eq!(entries, vec![(key, Arc::from([felt(2)])), (key, Arc::from([felt(1)]))]);
    assert!(nodes.is_empty());
}

#[test]
fn trace_output_tracking_distinguishes_empty_iterators_from_empty_map_values() {
    use miden_event_handler::AdviceBatch;
    let mut batch = AdviceBatch::new();
    batch.recorder().prepend_stack([]);
    batch.recorder().extend_merkle_store([]);
    batch.recorder().import(AdviceBatch::new());
    assert!(batch.is_empty());
    batch.recorder().insert_map_entry(Word::default(), vec![]);
    assert!(!batch.is_empty());
}
