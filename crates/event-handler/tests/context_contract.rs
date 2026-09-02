use std::collections::BTreeMap;

use miden_core::{
    ContextId, Felt, MemoryAddress, Word,
    advice::{AdviceMap, AdviceStack},
    crypto::merkle::{MerkleError, MerklePath, NodeIndex},
    deferred::{Digest, Node, PrecompileError},
    events::EventId,
};
use miden_event_handler::{
    BuiltinEventContextProvider, EventContext, EventContextError, EventContextProvider, Invocation,
    InvocationKind, MerkleReadError,
};

fn felt(value: u64) -> Felt {
    Felt::new_unchecked(value)
}

struct FakeProvider {
    stack: Vec<Felt>,
    memory: BTreeMap<(ContextId, u32), Felt>,
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
        context_id: ContextId,
        start: MemoryAddress,
        output: &mut [Felt],
    ) -> Result<(), EventContextError> {
        let start = start.as_u32();
        let mut pending = Vec::with_capacity(output.len());
        for offset in 0..output.len() {
            let address = start + offset as u32;
            let value = self
                .memory
                .get(&(context_id, address))
                .copied()
                .ok_or(EventContextError::UninitializedMemory { context_id, address })?;
            pending.push(value);
        }
        output.copy_from_slice(&pending);
        Ok(())
    }

    fn memory_snapshot(&self, context_id: ContextId) -> Vec<(MemoryAddress, Felt)> {
        self.memory
            .iter()
            .filter_map(|(&(ctx, address), &value)| {
                (ctx == context_id).then_some((MemoryAddress::new(address), value))
            })
            .collect()
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

struct FakeBuiltins {
    max_hash_len_bytes: usize,
    max_advice_size_bytes: usize,
}

impl BuiltinEventContextProvider for FakeBuiltins {
    fn max_hash_len_bytes(&self) -> usize {
        self.max_hash_len_bytes
    }

    fn max_advice_size_bytes(&self) -> usize {
        self.max_advice_size_bytes
    }

    fn canonical_deferred_digest(&self, _digest: Digest) -> Option<Digest> {
        None
    }

    fn canonical_deferred_node(&self, _digest: Digest) -> Option<(Digest, &Node)> {
        None
    }

    fn require_canonical_deferred_node(
        &self,
        _digest: Digest,
    ) -> Result<(Digest, &Node), PrecompileError> {
        Err(PrecompileError::MissingNode)
    }
}

fn fixture() -> (FakeProvider, FakeBuiltins, Word, Word, NodeIndex) {
    let active = ContextId::from(7);
    let other = ContextId::from(9);
    let mut memory = BTreeMap::new();
    for (offset, value) in [21, 22, 23, 24].into_iter().enumerate() {
        memory.insert((active, 4 + offset as u32), felt(value));
    }
    for (offset, value) in [31, 32, 33, 34].into_iter().enumerate() {
        memory.insert((other, 4 + offset as u32), felt(value));
    }
    memory.insert((active, u32::MAX), felt(25));

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
            advice_stack,
            advice_map,
            merkle_root,
            merkle_index,
            merkle_node,
            merkle_path,
        },
        FakeBuiltins {
            max_hash_len_bytes: 1_024,
            max_advice_size_bytes: 2_048,
        },
        map_key,
        merkle_node,
        merkle_index,
    )
}

#[test]
fn metadata_and_stack_reads_follow_the_context_contract() {
    let (provider, builtins, ..) = fixture();
    let event_id = EventId::from_u64(123);
    let context = EventContext::new(
        &provider,
        &builtins,
        Invocation::event(event_id, 456, ContextId::from(7)),
    );

    assert_eq!(context.kind(), InvocationKind::Event);
    assert_eq!(context.id(), event_id);
    assert_eq!(context.clock(), 456);
    assert_eq!(context.context_id(), ContextId::from(7));
    let depth: u32 = context.stack_depth();
    assert_eq!(depth, 3);
    assert_eq!(context.stack_item(1), felt(12));
    assert_eq!(context.stack_item(100), Felt::ZERO);
    assert_eq!(context.stack_item(u64::MAX), Felt::ZERO);
    assert_eq!(context.stack_word(1), Word::new([felt(12), felt(13), Felt::ZERO, Felt::ZERO]));

    let mut output = [felt(99); 5];
    context.read_stack(1, &mut output);
    assert_eq!(output, [felt(12), felt(13), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    context.read_stack(u64::MAX, &mut output[..2]);
    assert_eq!(output[..2], [Felt::ZERO, Felt::ZERO]);
    assert_eq!(context.stack_slice(2, 3).unwrap(), vec![felt(13), Felt::ZERO, Felt::ZERO]);
    assert_eq!(context.stack_range(2, 5).unwrap(), vec![felt(13), Felt::ZERO, Felt::ZERO]);
    assert_eq!(context.stack_range(3, 3).unwrap(), Vec::<Felt>::new());
    assert_eq!(
        context.stack_range(5, 2),
        Err(EventContextError::InvalidRange { start: 5, end: 2 })
    );
    assert_eq!(
        context.stack_slice(1, u64::MAX),
        Err(EventContextError::RangeOverflow { start: 1, count: u64::MAX })
    );
    assert_eq!(
        context.stack_slice(0, u64::MAX),
        Err(EventContextError::RangeOverflow { start: 0, count: u64::MAX })
    );
    assert_eq!(context.stack_range(u64::MAX - 1, u64::MAX).unwrap(), vec![Felt::ZERO]);
    assert_eq!(context.stack_snapshot(), vec![felt(11), felt(12), felt(13)]);

    let trace = EventContext::new(
        &provider,
        &builtins,
        Invocation::trace(EventId::from_u64(999), 457, ContextId::from(9)),
    );
    assert_eq!(trace.kind(), InvocationKind::Trace);
    assert_eq!(trace.id(), EventId::from_u64(999));
    assert_eq!(trace.context_id(), ContextId::from(9));
}

#[test]
fn memory_reads_honor_context_and_leave_caller_buffers_unchanged_on_error() {
    let (provider, builtins, ..) = fixture();
    let active = ContextId::from(7);
    let other = ContextId::from(9);
    let context =
        EventContext::new(&provider, &builtins, Invocation::event(EventId::from_u64(1), 2, active));

    // Scalar and word reads derive from the canonical buffer read.
    assert_eq!(context.memory_value(4).unwrap(), Some(felt(21)));
    assert_eq!(context.memory_value_in_context(other, 4).unwrap(), Some(felt(31)));
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
        context.memory_word_in_context(other, 4).unwrap(),
        Some(Word::new([felt(31), felt(32), felt(33), felt(34)]))
    );
    assert_eq!(
        context.memory_word(5),
        Err(EventContextError::UnalignedWord { context_id: active, address: 5 })
    );
    assert_eq!(context.memory_word(8).unwrap(), None);
    assert_eq!(
        context.memory_word(u64::from(u32::MAX) + 1),
        Err(EventContextError::AddressOutOfBounds { address: u64::from(u32::MAX) + 1 })
    );

    let mut output = [felt(90), felt(91)];
    context.read_memory_in_context(other, 5, &mut output).unwrap();
    assert_eq!(output, [felt(32), felt(33)]);

    let mut terminal = [Felt::ZERO];
    context.read_memory(u64::from(u32::MAX), &mut terminal).unwrap();
    assert_eq!(terminal, [felt(25)]);

    let before = output;
    assert_eq!(
        context.read_memory(7, &mut output),
        Err(EventContextError::UninitializedMemory { context_id: active, address: 8 })
    );
    assert_eq!(output, before);
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
    assert_eq!(context.memory_slice_in_context(other, 5, 2).unwrap(), vec![felt(32), felt(33)]);
    assert_eq!(
        context.memory_slice(u64::from(u32::MAX), 2),
        Err(EventContextError::RangeOverflow { start: u64::from(u32::MAX), count: 2 })
    );
    assert_eq!(
        context.memory_slice(7, 2),
        Err(EventContextError::UninitializedMemory { context_id: active, address: 8 })
    );
    assert_eq!(
        context.memory_range(4, 8).unwrap(),
        vec![felt(21), felt(22), felt(23), felt(24)]
    );
    assert_eq!(context.memory_range_in_context(other, 5, 7).unwrap(), vec![felt(32), felt(33)]);
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
    assert_eq!(
        context.memory_range(7, 9),
        Err(EventContextError::UninitializedMemory { context_id: active, address: 8 })
    );
    assert_eq!(
        context.memory_snapshot_in_context(other),
        vec![
            (MemoryAddress::new(4), felt(31)),
            (MemoryAddress::new(5), felt(32)),
            (MemoryAddress::new(6), felt(33)),
            (MemoryAddress::new(7), felt(34)),
        ]
    );
}

#[test]
fn advice_and_merkle_reads_are_borrowed_typed_and_atomic() {
    let (provider, builtins, map_key, merkle_node, merkle_index) = fixture();
    let context = EventContext::new(
        &provider,
        &builtins,
        Invocation::event(EventId::from_u64(1), 2, ContextId::from(7)),
    );

    assert!(std::ptr::eq(context.advice_stack(), &provider.advice_stack));
    assert!(std::ptr::eq(context.advice_map(), &provider.advice_map));
    assert!(context.advice_map().contains_key(&map_key));
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
fn built_in_capabilities_use_a_separate_adapter() {
    let (provider, builtins, ..) = fixture();
    let context = EventContext::new(
        &provider,
        &builtins,
        Invocation::event(EventId::from_u64(1), 2, ContextId::from(7)),
    );

    assert_eq!(context.builtins().max_hash_len_bytes(), 1_024);
    assert_eq!(context.builtins().max_advice_size_bytes(), 2_048);
    assert!(context.builtins().canonical_deferred_digest(Digest::default()).is_none());
    assert!(matches!(
        context.builtins().require_canonical_deferred_node(Digest::default()),
        Err(PrecompileError::MissingNode)
    ));
}
