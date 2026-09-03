#![allow(deprecated)]

use std::sync::Arc;

use miden_assembly::Assembler;
use miden_core::{ContextId, Felt, deferred::TRUE_DIGEST};
use miden_processor::{
    DefaultHost, FastProcessor, ProcessorState, StackInputs,
    advice::AdviceMutation,
    event::{EventError, EventHandler, EventName},
};

fn felt(value: u64) -> Felt {
    Felt::new_unchecked(value)
}

const LEGACY_EVENT: EventName = EventName::new("test::event_context::legacy");

struct LegacyHandler;

// The concrete advice provider, execution options, and `RowIndex` clock are intentional migration
// exceptions rather than compatibility claims.
impl EventHandler for LegacyHandler {
    fn on_event(&self, state: &ProcessorState<'_>) -> Result<Vec<AdviceMutation>, EventError> {
        let root = ContextId::root();
        let active = state.ctx();
        assert!(!active.is_root());
        let _: u32 = state.clock();

        assert_eq!(state.get_stack_item(0), LEGACY_EVENT.to_event_id().as_felt());
        assert_eq!(state.get_stack_word(0)[0], LEGACY_EVENT.to_event_id().as_felt());
        assert_eq!(state.get_stack_state()[0], LEGACY_EVENT.to_event_id().as_felt());
        let _: u32 = state.stack_depth();
        assert_eq!(state.get_mem_addr_range(1, 2).unwrap(), 0..0);

        for (context_id, expected) in [(root, felt(11)), (active, felt(22))] {
            assert_eq!(state.get_mem_value(context_id, 0), Some(expected));
            assert_eq!(state.get_mem_word(context_id, 0).unwrap().unwrap()[0], expected);
            assert_eq!(state.get_mem_state(context_id)[0].1, expected);
        }

        assert_eq!(state.get_canonical_deferred_digest(TRUE_DIGEST), Some(TRUE_DIGEST));
        assert_eq!(state.get_canonical_deferred_node(TRUE_DIGEST).unwrap().0, TRUE_DIGEST);
        assert_eq!(state.require_canonical_deferred_node(TRUE_DIGEST).unwrap().0, TRUE_DIGEST);

        Ok(vec![AdviceMutation::extend_advice_stack_with([felt(99)])])
    }
}

#[test]
fn sdk_base_common_handler_paths_and_explicit_context_reads_remain_compatible() {
    let mut host = DefaultHost::default();
    host.register_handler(LEGACY_EVENT, Arc::new(LegacyHandler)).unwrap();
    let source = format!(
        "proc child push.22 mem_store.0 emit.event(\"{LEGACY_EVENT}\") drop end \
         begin push.11 mem_store.0 call.child end"
    );
    let program = Assembler::default()
        .assemble_program("event_context_legacy", source)
        .unwrap()
        .unwrap_program();

    let output = FastProcessor::new(StackInputs::default())
        .execute_sync(&program, &mut host)
        .unwrap();
    assert_eq!(output.advice.stack_iter().next(), Some(&felt(99)));
}
