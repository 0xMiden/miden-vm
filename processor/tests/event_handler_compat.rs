#![allow(deprecated)]

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use miden_assembly::Assembler;
use miden_core::{
    ContextId, Felt, Word,
    advice::AdviceStack,
    crypto::merkle::{MerklePath, MerkleStore, MerkleTree, NodeIndex},
    deferred::TRUE_DIGEST,
};
use miden_processor::{
    DefaultHost, FastProcessor, ProcessorState, StackInputs,
    advice::{AdviceInputs, AdviceMutation},
    event::{EventError, EventHandler, EventName},
};

fn felt(value: u64) -> Felt {
    Felt::new_unchecked(value)
}

fn word(start: u64) -> Word {
    Word::new([felt(start), felt(start + 1), felt(start + 2), felt(start + 3)])
}

struct LegacyHandler {
    event: EventName,
    map_key: Word,
    tree_root: Word,
    tree_node: Word,
    tree_path: MerklePath,
    observed: Arc<AtomicBool>,
}

impl EventHandler for LegacyHandler {
    fn on_event(&self, state: &ProcessorState<'_>) -> Result<Vec<AdviceMutation>, EventError> {
        let root = ContextId::root();
        let active = state.ctx();
        assert!(!active.is_root());
        let _: u32 = state.clock();

        assert_eq!(state.get_stack_item(0), self.event.to_event_id().as_felt());
        assert_eq!(state.get_stack_word(0)[0], self.event.to_event_id().as_felt());
        assert_eq!(state.get_stack_state()[0], self.event.to_event_id().as_felt());

        assert_eq!(state.get_mem_value(root, 0), Some(felt(11)));
        assert_eq!(state.get_mem_value(active, 0), Some(felt(22)));
        assert_eq!(
            state.get_mem_word(root, 0).unwrap(),
            Some(Word::new([felt(11), Felt::ZERO, Felt::ZERO, Felt::ZERO]))
        );
        assert_eq!(
            state.get_mem_word(active, 0).unwrap(),
            Some(Word::new([felt(22), Felt::ZERO, Felt::ZERO, Felt::ZERO]))
        );
        assert_eq!(state.get_mem_state(root)[0].1, felt(11));
        assert_eq!(state.get_mem_state(active)[0].1, felt(22));

        let advice = state.advice_provider();
        assert_eq!(advice.stack_len(), 3);
        assert_eq!(advice.stack(), vec![felt(31), felt(32), felt(33)]);
        assert_eq!(advice.stack_iter().copied().collect::<Vec<_>>(), advice.stack());
        assert_eq!(advice.typed_stack(), &AdviceStack::from(vec![felt(31), felt(32), felt(33)]));
        assert!(advice.contains_map_key(&self.map_key));
        assert_eq!(advice.get_mapped_values(&self.map_key), Some([felt(41), felt(42)].as_slice()));

        let mut stack_output = [Felt::ZERO; 2];
        advice.read_stack(1, &mut stack_output).unwrap();
        assert_eq!(stack_output, [felt(32), felt(33)]);
        assert_eq!(advice.stack_range(1, 2).unwrap(), stack_output);

        let depth = felt(2);
        let position = felt(1);
        assert_eq!(advice.get_tree_node(self.tree_root, depth, position).unwrap(), self.tree_node);
        assert_eq!(
            advice.get_merkle_path(self.tree_root, depth, position).unwrap(),
            self.tree_path
        );
        assert!(advice.has_merkle_path(self.tree_root, depth, position).unwrap());
        assert!(advice.has_merkle_root(self.tree_root));

        assert_eq!(state.get_canonical_deferred_digest(TRUE_DIGEST), Some(TRUE_DIGEST));
        assert_eq!(state.get_canonical_deferred_node(TRUE_DIGEST).unwrap().0, TRUE_DIGEST);
        assert_eq!(state.require_canonical_deferred_node(TRUE_DIGEST).unwrap().0, TRUE_DIGEST);

        self.observed.store(true, Ordering::SeqCst);
        Ok(Vec::new())
    }
}

#[test]
fn old_handler_paths_and_explicit_context_reads_remain_behaviorally_compatible() {
    let event = EventName::new("test::event_context::legacy");
    let map_key = word(40);
    let tree = MerkleTree::new([word(50), word(60), word(70), word(80)]).unwrap();
    let tree_index = NodeIndex::new(2, 1).unwrap();
    let tree_node = tree.get_node(tree_index).unwrap();
    let tree_path = tree.get_path(tree_index).unwrap();
    let advice_inputs = AdviceInputs::default()
        .with_stack(AdviceStack::from(vec![felt(31), felt(32), felt(33)]))
        .with_map([(map_key, vec![felt(41), felt(42)])])
        .with_merkle_store(MerkleStore::from(&tree));
    let observed = Arc::new(AtomicBool::new(false));
    let handler = LegacyHandler {
        event: event.clone(),
        map_key,
        tree_root: tree.root(),
        tree_node,
        tree_path,
        observed: observed.clone(),
    };
    let mut host = DefaultHost::default();
    host.register_handler(event.clone(), Arc::new(handler)).unwrap();
    let program = Assembler::default()
        .assemble_program(
            "event_context_legacy",
            format!(
                r#"
                proc child
                    push.22 mem_store.0
                    emit.event("{event}")
                    drop
                end

                begin
                    push.11 mem_store.0
                    call.child
                end
                "#
            ),
        )
        .unwrap()
        .unwrap_program();

    FastProcessor::new(StackInputs::default())
        .with_advice(advice_inputs)
        .unwrap()
        .execute_sync(&program, &mut host)
        .unwrap();

    assert!(observed.load(Ordering::SeqCst));
}
