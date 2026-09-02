#![allow(deprecated)]

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use miden_assembly::Assembler;
use miden_core::{ContextId, Felt, Word, deferred::TRUE_DIGEST};
use miden_processor::{
    DefaultHost, FastProcessor, ProcessorState, StackInputs,
    advice::AdviceMutation,
    event::{EventError, EventHandler, EventName},
};

fn felt(value: u64) -> Felt {
    Felt::new_unchecked(value)
}

struct LegacyHandler {
    event: EventName,
    observed: Arc<AtomicBool>,
}

// This exercises the SDK-base paths retained by the v0.31 shim. The concrete advice provider and
// execution options are intentional migration exceptions, and the clock assertion below uses the
// new `u32` type rather than pretending the former `RowIndex` return type remains compatible.
impl EventHandler for LegacyHandler {
    fn on_event(&self, state: &ProcessorState<'_>) -> Result<Vec<AdviceMutation>, EventError> {
        let root = ContextId::root();
        let active = state.ctx();
        assert!(!active.is_root());

        let _: u32 = state.clock();

        assert_eq!(state.get_stack_item(0), self.event.to_event_id().as_felt());
        assert_eq!(state.get_stack_word(0)[0], self.event.to_event_id().as_felt());
        assert_eq!(state.get_stack_state()[0], self.event.to_event_id().as_felt());
        let _: u32 = state.stack_depth();
        assert_eq!(state.get_mem_addr_range(1, 2).unwrap(), 0..0);

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

        assert_eq!(state.get_canonical_deferred_digest(TRUE_DIGEST), Some(TRUE_DIGEST));
        assert_eq!(state.get_canonical_deferred_node(TRUE_DIGEST).unwrap().0, TRUE_DIGEST);
        assert_eq!(state.require_canonical_deferred_node(TRUE_DIGEST).unwrap().0, TRUE_DIGEST);

        self.observed.store(true, Ordering::SeqCst);
        Ok(Vec::new())
    }
}

#[test]
fn sdk_base_common_handler_paths_and_explicit_context_reads_remain_compatible() {
    let event = EventName::new("test::event_context::legacy");
    let observed = Arc::new(AtomicBool::new(false));
    let handler = LegacyHandler {
        event: event.clone(),
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
        .execute_sync(&program, &mut host)
        .unwrap();

    assert!(observed.load(Ordering::SeqCst));
}
