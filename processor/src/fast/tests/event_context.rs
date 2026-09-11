use miden_core::{
    MemoryAddress,
    crypto::merkle::{MerkleStore, MerkleTree, NodeIndex},
    events::{EventId, EventName},
};
use miden_event_handler::{AdviceRecorder, EventContext, Invocation};

use super::*;

fn felt(value: u64) -> Felt {
    Felt::new_unchecked(value)
}

fn word(start: u64) -> Word {
    Word::new([felt(start), felt(start + 1), felt(start + 2), felt(start + 3)])
}

#[test]
fn fast_processor_adapter_supplies_context_capabilities() {
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

    let context =
        EventContext::new(&processor, Invocation::event(EventId::from_u64(1234), 77, false));

    assert_eq!(context.stack_depth(), processor.stack_depth() - 1);
    let depth = u64::from(context.stack_depth());
    let mut stack_output = [felt(99); 5];
    context.read_stack(depth - 2, &mut stack_output);
    assert_eq!(stack_output[0], processor.stack_get_safe((depth - 1) as usize));
    assert_eq!(stack_output[1], processor.stack_get_safe(depth as usize));
    assert_eq!(&stack_output[2..], &[ZERO; 3]);
    assert_eq!(context.read_stack_array::<5>(depth - 2), stack_output);

    assert!(!context.in_root_context());

    // Exercise both specialized paths in the canonical provider buffer read.
    assert_eq!(context.memory_value(4).unwrap(), Some(felt(200)));
    assert_eq!(context.memory_word_root(4).unwrap(), Some(word(100)));

    let mut memory_output = [ZERO; 2];
    processor
        .read_memory_root(MemoryAddress::new(5), &mut memory_output, MemoryReadMode::Strict)
        .unwrap();
    assert_eq!(memory_output, [felt(101), felt(102)]);
    context.read_memory_root(7, &mut memory_output).unwrap();
    assert_eq!(memory_output, [felt(103), ZERO]);
    assert_eq!(
        context.memory_snapshot_root(),
        vec![
            (MemoryAddress::new(4), felt(100)),
            (MemoryAddress::new(5), felt(101)),
            (MemoryAddress::new(6), felt(102)),
            (MemoryAddress::new(7), felt(103)),
        ]
    );

    assert_eq!(
        context.advice_stack().iter().copied().collect::<Vec<_>>(),
        vec![felt(21), felt(22), felt(23),]
    );
    assert_eq!(
        context.advice_map().get(&map_key).map(AsRef::as_ref),
        Some(map_values.as_slice())
    );

    let index = NodeIndex::new(2, 1).unwrap();
    assert_eq!(context.merkle_node(tree.root(), index).unwrap(), tree.get_node(index).unwrap());
    assert_eq!(context.merkle_path(tree.root(), index).unwrap(), tree.get_path(index).unwrap());

    // In the root execution context, the default and explicit-root views must coincide.
    processor.ctx = root_context;
    let context =
        EventContext::new(&processor, Invocation::event(EventId::from_u64(1234), 77, true));
    assert!(context.in_root_context());
    assert_eq!(context.memory_value(4).unwrap(), context.memory_value_root(4).unwrap());
    assert_eq!(context.memory_word(4).unwrap(), context.memory_word_root(4).unwrap());
    assert_eq!(context.memory_slice(5, 4).unwrap(), context.memory_slice_root(5, 4).unwrap());
    assert_eq!(context.memory_snapshot(), context.memory_snapshot_root());

    // Compare bulk reads with scalar reads across sparse words and the address-space boundary.
    processor.ctx = active_context;
    for address in [12, u32::MAX - 3] {
        processor
            .memory
            .write_word(active_context, felt(u64::from(address)), 0_u32.into(), word(300))
            .unwrap();
    }
    let context = EventContext::new(&processor, Invocation::event(EventId::from_u64(1), 0, false));
    for (start, count) in [
        (0, 4),
        (0, 20),
        (3, 2),
        (4, 4),
        (5, 3),
        (5, 10),
        (16, 8),
        (u64::from(u32::MAX) - 6, 7),
        (u64::from(u32::MAX), 1),
        (u64::from(u32::MAX) + 1, 0),
    ] {
        let expected: Vec<_> = (start..start + count)
            .map(|address| context.memory_value(address).unwrap().unwrap_or(ZERO))
            .collect();
        let expected_root: Vec<_> = (start..start + count)
            .map(|address| context.memory_value_root(address).unwrap().unwrap_or(ZERO))
            .collect();
        let mut output = vec![felt(99); count as usize];
        context.read_memory(start, &mut output).unwrap();
        assert_eq!(output, expected, "current: {start}, {count}");
        context.read_memory_root(start, &mut output).unwrap();
        assert_eq!(output, expected_root, "root: {start}, {count}");
        assert_eq!(context.memory_slice(start, count).unwrap(), expected);
        assert_eq!(context.memory_slice_root(start, count).unwrap(), expected_root);
    }

    // Strict misses and zero-filled range overflow must both leave the provider buffer intact.
    let mut output = [felt(99); 6];
    assert_eq!(
        processor.read_memory(MemoryAddress::new(7), &mut output, MemoryReadMode::Strict),
        Err(EventContextError::UninitializedMemory { address: 8 })
    );
    assert_eq!(output, [felt(99); 6]);
    assert_eq!(
        processor.read_memory_root(
            MemoryAddress::new(u32::MAX),
            &mut output,
            MemoryReadMode::ZeroFilled
        ),
        Err(EventContextError::RangeOverflow { start: u64::from(u32::MAX), count: 6 })
    );
    assert_eq!(output, [felt(99); 6]);
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
    host.register_event_handler(event.clone(), |_: EventContext, advice: &mut AdviceRecorder| {
        advice.prepend_stack([felt(99)]);
        advice.insert_map_entry(Word::default(), vec![ONE]);
        Ok(())
    })
    .unwrap();
    let program = Assembler::default()
        .assemble_program("event_context_transaction", format!("begin emit.event(\"{event}\") end"))
        .unwrap()
        .unwrap_program();

    processor.execute_mut_sync(&program, &mut host).unwrap_err();

    assert_eq!(processor.advice.stack_ref(), &initial_stack);
    assert_eq!(processor.advice.map(), &initial_map);
}

#[test]
#[allow(deprecated)] // Legacy callback coverage or independent raw inspection.
fn legacy_bridge_discards_child_writes_when_the_host_catches_failure() {
    use crate::{
        ProcessorState,
        event::{EventError, legacy_handler},
    };
    let helper = legacy_handler(
        |_: EventContext<'_>, advice: &mut AdviceRecorder<'_>| -> Result<(), EventError> {
            advice.prepend_stack([felt(99)]);
            advice.insert_map_entry(Word::default(), vec![ONE]);
            Err("child failed".into())
        },
    );
    let name = EventName::new("test::caught_child");
    let mut host = DefaultHost::default();
    host.register_handler(
        name.clone(),
        Arc::new(move |state: &ProcessorState<'_>| {
            assert!(helper.on_event(state).is_err());
            Ok(vec![crate::advice::AdviceMutation::extend_advice_stack_with([felt(7)])])
        }),
    )
    .unwrap();
    let program = Assembler::default()
        .assemble_program("program", format!(r#"begin emit.event("{name}") end"#))
        .unwrap()
        .unwrap_program();
    let mut processor = FastProcessor::new(StackInputs::default());
    processor.execute_mut_sync(&program, &mut host).unwrap();
    assert_eq!(processor.advice.stack_ref().iter().copied().collect::<Vec<_>>(), vec![felt(7)]);
    assert!(processor.advice.map().is_empty());
}
