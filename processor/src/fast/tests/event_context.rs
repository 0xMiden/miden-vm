use miden_core::{
    ContextId, MemoryAddress,
    crypto::merkle::{MerkleStore, MerkleTree, NodeIndex},
    deferred::TRUE_DIGEST,
    events::{EventId, EventName, SystemEvent},
};
use miden_event_handler::{
    AdviceMutation, EventContext, EventContextError, EventError, Invocation, InvocationKind,
    TraceError,
};

use super::*;

fn felt(value: u64) -> Felt {
    Felt::new_unchecked(value)
}

fn word(start: u64) -> Word {
    Word::new([felt(start), felt(start + 1), felt(start + 2), felt(start + 3)])
}

#[test]
fn fast_processor_adapter_matches_every_public_read_capability() {
    let advice_stack = AdviceStack::from(vec![felt(21), felt(22), felt(23)]);
    let map_key = word(30);
    let map_values = vec![felt(40), felt(41)];
    let tree = MerkleTree::new([word(50), word(60), word(70), word(80)]).unwrap();
    let merkle_store = MerkleStore::from(&tree);
    let advice_inputs = AdviceInputs::default()
        .with_stack(advice_stack)
        .with_map([(map_key, map_values.clone())])
        .with_merkle_store(merkle_store);
    let options = ExecutionOptions::default();
    let mut processor = FastProcessor::new_with_options(
        StackInputs::new(&[felt(11), felt(12), felt(13)]).unwrap(),
        advice_inputs,
        options,
    )
    .unwrap();

    // A context read must stop at the logical stack bottom rather than exposing stale backing
    // buffer contents.
    processor.stack[processor.stack_bot_idx - 1] = felt(999);

    let root_context = ContextId::root();
    let active_context = ContextId::from(9);
    processor
        .memory
        .write_word(root_context, felt(4), 0_u32.into(), word(100))
        .unwrap();
    processor
        .memory
        .write_word(active_context, felt(4), 0_u32.into(), word(200))
        .unwrap();
    processor.ctx = active_context;

    let event_id = EventId::from_u64(1234);
    let context = processor.event_context(Invocation::event(event_id, 77, active_context));

    assert_eq!(context.kind(), InvocationKind::Event);
    assert_eq!(context.id(), event_id);
    assert_eq!(context.clock(), 77);
    assert_eq!(context.context_id(), active_context);
    assert_eq!(context.stack_depth(), processor.stack_depth());
    assert_eq!(context.stack_item(0), processor.stack_get_safe(0));
    assert_eq!(context.stack_item(u64::from(context.stack_depth()) + 10), ZERO);
    assert_eq!(context.stack_word(1), processor.stack_get_word_safe(1));
    let depth = u64::from(context.stack_depth());
    assert_eq!(
        context.stack_word(depth - 2),
        Word::new([context.stack_item(depth - 2), context.stack_item(depth - 1), ZERO, ZERO])
    );
    assert_eq!(
        context.stack_snapshot(),
        processor.stack().iter().rev().copied().collect::<Vec<_>>()
    );

    let mut stack_output = [felt(99); 5];
    context.read_stack(depth - 2, &mut stack_output);
    assert_eq!(stack_output[0], processor.stack_get_safe((depth - 2) as usize));
    assert_eq!(stack_output[1], processor.stack_get_safe((depth - 1) as usize));
    assert_eq!(&stack_output[2..], &[ZERO; 3]);
    assert_eq!(context.stack_range(depth - 2, depth + 3).unwrap(), stack_output);
    assert_eq!(context.stack_slice(depth - 2, 5).unwrap(), stack_output);

    assert_eq!(context.memory_value(4).unwrap(), Some(felt(200)));
    assert_eq!(context.memory_value_in_context(root_context, 4).unwrap(), Some(felt(100)));
    assert_eq!(context.memory_word(4).unwrap(), Some(word(200)));
    assert_eq!(context.memory_word_in_context(root_context, 4).unwrap(), Some(word(100)));
    assert_eq!(context.memory_range(4, 8).unwrap(), word(200).to_vec());
    assert_eq!(context.memory_slice(4, 4).unwrap(), word(200).to_vec());

    let mut memory_output = [ZERO; 2];
    context.read_memory_in_context(root_context, 5, &mut memory_output).unwrap();
    assert_eq!(memory_output, [felt(101), felt(102)]);
    let before = memory_output;
    assert_eq!(
        context.read_memory_in_context(root_context, 7, &mut memory_output),
        Err(EventContextError::UninitializedMemory { context_id: root_context, address: 8 })
    );
    assert_eq!(memory_output, before);
    assert_eq!(
        context.memory_word(5),
        Err(EventContextError::UnalignedWord { context_id: active_context, address: 5 })
    );
    assert_eq!(
        context.memory_snapshot_in_context(root_context),
        vec![
            (MemoryAddress::new(4), felt(100)),
            (MemoryAddress::new(5), felt(101)),
            (MemoryAddress::new(6), felt(102)),
            (MemoryAddress::new(7), felt(103)),
        ]
    );

    assert!(core::ptr::eq(context.advice_stack(), processor.advice.stack_ref()));
    assert!(core::ptr::eq(context.advice_map(), processor.advice.map()));
    assert_eq!(
        context.advice_map().get(&map_key).map(AsRef::as_ref),
        Some(map_values.as_slice())
    );
    assert!(context.advice_map().contains_key(&map_key));

    let mut advice_output = [ZERO; 2];
    context.read_advice_stack(1, &mut advice_output).unwrap();
    assert_eq!(advice_output, [felt(22), felt(23)]);
    assert_eq!(context.advice_stack_range(1, 3).unwrap(), advice_output);
    assert_eq!(context.advice_stack_slice(1, 2).unwrap(), advice_output);
    let before = advice_output;
    assert_eq!(
        context.read_advice_stack(2, &mut advice_output),
        Err(EventContextError::AdviceStackOutOfBounds { start: 2, end: 4, len: 3 })
    );
    assert_eq!(advice_output, before);

    let index = NodeIndex::new(2, 1).unwrap();
    assert_eq!(context.merkle_node(tree.root(), index).unwrap(), tree.get_node(index).unwrap());
    assert_eq!(context.merkle_path(tree.root(), index).unwrap(), tree.get_path(index).unwrap());
    assert!(context.has_merkle_path(tree.root(), index));
    assert!(context.has_merkle_root(tree.root()));

    assert_eq!(context.builtins().max_hash_len_bytes(), options.max_hash_len_bytes());
    assert_eq!(context.builtins().max_advice_size_bytes(), options.max_advice_size_bytes());
    assert_eq!(context.builtins().canonical_deferred_digest(TRUE_DIGEST), Some(TRUE_DIGEST));
    let (canonical_digest, canonical_node) =
        context.builtins().canonical_deferred_node(TRUE_DIGEST).unwrap();
    assert_eq!(canonical_digest, TRUE_DIGEST);
    assert_eq!(canonical_node.digest(), TRUE_DIGEST);
    assert_eq!(
        context.builtins().require_canonical_deferred_node(TRUE_DIGEST).unwrap().0,
        TRUE_DIGEST
    );
}

#[derive(Default)]
struct RecordingHost {
    event: Option<(Invocation, Felt)>,
    trace: Option<(Invocation, Felt, Felt)>,
}

impl BaseHost for RecordingHost {
    fn get_label_and_source_file(
        &self,
        _location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        (SourceSpan::UNKNOWN, None)
    }
}

impl SyncHost for RecordingHost {
    fn get_mast_forest(&self, _node_digest: &Word) -> Option<LoadedMastForest> {
        None
    }

    fn on_event(&mut self, context: &EventContext<'_>) -> Result<Vec<AdviceMutation>, EventError> {
        self.event = Some((context.invocation(), context.stack_item(0)));
        Ok(Vec::new())
    }

    fn on_trace(&mut self, context: &EventContext<'_>) -> Result<(), TraceError> {
        self.trace = Some((context.invocation(), context.stack_item(0), context.stack_item(1)));
        Ok(())
    }
}

#[test]
fn dispatch_supplies_semantic_event_and_trace_ids() {
    let event = EventName::new("test::event_context::event");
    let trace = EventName::new("test::event_context::trace");
    let program = Assembler::default()
        .assemble_program(
            "event_context_dispatch",
            format!("begin emit.event(\"{event}\") drop trace.event(\"{trace}\") end"),
        )
        .unwrap()
        .unwrap_program();
    let mut host = RecordingHost::default();

    FastProcessor::new(StackInputs::default())
        .execute_sync(&program, &mut host)
        .unwrap();

    let (event_invocation, event_stack_top) = host.event.unwrap();
    assert_eq!(event_invocation.kind(), InvocationKind::Event);
    assert_eq!(event_invocation.id(), event.to_event_id());
    assert_eq!(event_invocation.context_id(), ContextId::root());
    assert_eq!(event_stack_top, event.to_event_id().as_felt());

    let (trace_invocation, trace_stack_top, trace_stack_second) = host.trace.unwrap();
    assert_eq!(trace_invocation.kind(), InvocationKind::Trace);
    assert_eq!(trace_invocation.id(), trace.to_event_id());
    assert_eq!(trace_invocation.context_id(), ContextId::root());
    assert_eq!(trace_stack_top, SystemEvent::TraceEvent.event_id().as_felt());
    assert_eq!(trace_stack_second, trace.to_event_id().as_felt());
}

#[allow(clippy::unnecessary_wraps)]
fn conflicting_mutations(_context: &EventContext<'_>) -> Result<Vec<AdviceMutation>, EventError> {
    let mut conflicting_map = AdviceMap::default();
    conflicting_map.insert(Word::default(), vec![ONE]);
    Ok(vec![
        AdviceMutation::extend_advice_stack_with([felt(99)]),
        AdviceMutation::extend_map(conflicting_map),
    ])
}

#[test]
fn dispatch_applies_advice_mutations_all_or_nothing() {
    let event = EventName::new("test::event_context::transaction");
    let initial_stack = AdviceStack::from(vec![felt(7)]);
    let mut initial_map = AdviceMap::default();
    initial_map.insert(Word::default(), vec![ZERO]);
    let advice_inputs = AdviceInputs::default()
        .with_stack(initial_stack.clone())
        .with_map(initial_map.iter().map(|(key, values)| (*key, values.to_vec())));
    let mut processor =
        FastProcessor::new(StackInputs::default()).with_advice(advice_inputs).unwrap();
    let mut host = DefaultHost::default();
    host.register_handler(event.clone(), Arc::new(conflicting_mutations)).unwrap();
    let program = Assembler::default()
        .assemble_program("event_context_transaction", format!("begin emit.event(\"{event}\") end"))
        .unwrap()
        .unwrap_program();

    processor.execute_mut_sync(&program, &mut host).unwrap_err();

    assert_eq!(processor.advice.stack_ref(), &initial_stack);
    assert_eq!(processor.advice.map(), &initial_map);
}
