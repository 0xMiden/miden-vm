use std::sync::{Arc, Mutex};

use miden_assembly::Assembler;
use miden_event_handler::{
    AdviceBatch, AdviceRecorder, EventContext, EventHandler, Invocation, InvocationKind,
};
use miden_processor::{
    DefaultHost, ExecutionOptions, FastProcessor, Felt, StackInputs,
    advice::AdviceInputs,
    event::{EventName, HandlerRegistry, registration},
};

#[test]
fn one_shared_registration_receives_event_and_trace_payloads() {
    let name = EventName::new("test::unified");
    let calls = Arc::new(Mutex::new(vec![]));
    let seen = calls.clone();
    let shared: Arc<dyn EventHandler> =
        Arc::new(move |context: EventContext<'_>, _: &mut AdviceRecorder<'_>| {
            seen.lock().unwrap().push((context.id(), context.kind(), context.stack_item(0)));
            Ok(())
        });
    let mut host = DefaultHost::default();
    host.register_event_handler(name.clone(), registration::EventHandler::shared(shared.clone()))
        .unwrap();
    assert!(
        host.register_event_handler(name.clone(), registration::EventHandler::shared(shared))
            .is_err()
    );
    let program = Assembler::default()
        .assemble_program(
            "program",
            format!(r#"begin push.9 emit.event("{name}") trace.event("{name}") drop end"#),
        )
        .unwrap()
        .unwrap_program();
    FastProcessor::new(StackInputs::default())
        .execute_sync(&program, &mut host)
        .unwrap();
    assert_eq!(
        *calls.lock().unwrap(),
        vec![
            (name.to_event_id(), InvocationKind::Event, Felt::from_u32(9)),
            (name.to_event_id(), InvocationKind::Trace, Felt::from_u32(9))
        ]
    );
}

#[test]
fn unknown_and_wrong_kind_delivery_policy() {
    for (trace, known, enabled, succeeds) in [
        (true, false, true, true),
        (false, false, true, false),
        (true, true, true, false),
        (true, true, false, true),
        (false, true, false, true),
    ] {
        let name = EventName::new("test::policy");
        let mut host = DefaultHost::default();
        if known {
            host.register_event_handler(
                name.clone(),
                |context: EventContext<'_>, _: &mut AdviceRecorder<'_>| {
                    context.kind().require(InvocationKind::Event)?;
                    Ok(())
                },
            )
            .unwrap();
        }
        let instruction = if trace { "trace" } else { "emit" };
        let program = Assembler::default()
            .assemble_program("program", format!(r#"begin {instruction}.event("{name}") end"#))
            .unwrap()
            .unwrap_program();
        let result = FastProcessor::new_with_options(
            StackInputs::default(),
            AdviceInputs::default(),
            ExecutionOptions::default().with_trace_delivery(enabled),
        )
        .unwrap()
        .execute_sync(&program, &mut host);
        assert_eq!(result.is_ok(), succeeds, "trace={trace}, known={known}, enabled={enabled}");
    }
}

#[test]
fn routing_key_does_not_replace_invocation_identity() {
    let route = EventName::new("test::route");
    let actual = EventName::new("test::actual").to_event_id();
    let mut registry = HandlerRegistry::new();
    registry
        .register(route.clone(), move |context: EventContext<'_>, _: &mut AdviceRecorder<'_>| {
            assert_eq!(context.id(), actual);
            Ok(())
        })
        .unwrap();
    let processor = FastProcessor::new(StackInputs::default());
    let context = EventContext::new(&processor, Invocation::trace(actual, 0, true));
    assert!(
        registry
            .handle_event(route.to_event_id(), context, &mut AdviceBatch::new().recorder())
            .unwrap()
    );
}

#[cfg(feature = "testing")]
#[test]
fn trace_recording_rules_apply_to_idempotent_and_empty_outputs() {
    for output in 0..4 {
        let name = EventName::new("test::trace::output");
        let mut host = DefaultHost::default();
        host.register_event_handler(
            name.clone(),
            move |_: EventContext<'_>, advice: &mut AdviceRecorder<'_>| {
                match output {
                    0 => {
                        advice.prepend_stack([]);
                        advice.extend_merkle_store([]);
                    },
                    1 => advice.insert_map_entry(miden_processor::Word::default(), vec![]),
                    2 => advice.insert_map_entry(miden_processor::Word::default(), vec![Felt::ONE]),
                    _ => {
                        advice.prepend_stack([Felt::ONE]);
                        return Err("callback failure".into());
                    },
                }
                Ok(())
            },
        )
        .unwrap();
        let program = Assembler::default()
            .assemble_program("program", format!(r#"begin trace.event("{name}") end"#))
            .unwrap()
            .unwrap_program();
        let inputs = AdviceInputs::default().with_map([(
            miden_processor::Word::default(),
            if output == 1 { vec![] } else { vec![Felt::ONE] },
        )]);
        let before = FastProcessor::new(StackInputs::default())
            .with_advice(inputs.clone())
            .unwrap()
            .into_parts()
            .0;
        let mut processor = FastProcessor::new(StackInputs::default()).with_advice(inputs).unwrap();
        let result = processor.execute_mut_sync(&program, &mut host);
        assert_eq!(processor.into_parts().0, before);
        if output == 0 {
            assert!(result.is_ok());
        } else {
            let error = format!("{:?}", result.unwrap_err());
            assert!(
                error.contains(if output == 3 { "callback failure" } else { "TraceAdvice" }),
                "{error}"
            );
        }
    }
}
