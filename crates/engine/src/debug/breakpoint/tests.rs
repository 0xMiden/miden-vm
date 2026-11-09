use alloc::string::ToString;

use miden_core::{Felt, operations::Operation};

use super::{Breakpoint, BreakpointType, Event, OperationMatcher};

#[test]
fn unqualified_function_breakpoints_match_path_suffixes() {
    let breakpoint = "in entrypoint".parse::<BreakpointType>().unwrap();

    assert!(breakpoint.should_break_in("::\"root_ns:root@1.0.0\"::fibonacci::entrypoint"));
    assert!(breakpoint.should_break_in("$exec::entrypoint"));
    assert!(!breakpoint.should_break_in("$exec::other_entrypoint"));
    assert!(!breakpoint.should_break_in("$exec::entrypoint_helper"));
}

#[test]
fn function_breakpoints_match_rust_source_names_without_losing_linkage_names() {
    let linkage = "::package::_ZN3foo5inner17h0123456789abcdefE";
    for name in ["in inner", "in foo::inner", "in *_ZN3foo5inner17h0123456789abcdefE"] {
        assert!(name.parse::<BreakpointType>().unwrap().should_break_in(linkage), "{name}");
    }
    assert!(
        "in ::package::foo::inner"
            .parse::<BreakpointType>()
            .unwrap()
            .should_break_in(linkage)
    );
    assert!(
        "in inner"
            .parse::<BreakpointType>()
            .unwrap()
            .should_break_in("_ZN3foo5inner17h0123456789abcdefE")
    );
    assert!(!"in other_inner".parse::<BreakpointType>().unwrap().should_break_in(linkage));
}

#[test]
fn qualified_function_breakpoints_match_exact_suffixes() {
    let breakpoint = "in fibonacci::entrypoint".parse::<BreakpointType>().unwrap();

    assert!(breakpoint.should_break_in("::\"root_ns:root@1.0.0\"::fibonacci::entrypoint"));
    assert!(!breakpoint.should_break_in("::\"root_ns:root@1.0.0\"::wallet::entrypoint"));
}

#[test]
fn log_deferred_breakpoint_accepts_legacy_name_and_displays_canonically() {
    let canonical = "log_deferred".parse::<OperationMatcher>().unwrap();
    let legacy = "log_precompile".parse::<OperationMatcher>().unwrap();

    assert_eq!(canonical, legacy);
    assert_eq!(canonical.to_string(), "log_deferred");
}

#[test]
fn parses_breakpoint_forms_and_rejects_invalid_values() {
    assert!(matches!("next".parse(), Ok(BreakpointType::Next)));
    assert!(matches!("finish".parse(), Ok(BreakpointType::Finish)));
    assert!(matches!("after 4".parse(), Ok(BreakpointType::StepN(4))));
    assert!(matches!("at 12".parse(), Ok(BreakpointType::StepTo(12))));
    assert!(matches!(
        "for push.*".parse(),
        Ok(BreakpointType::Opcode(OperationMatcher::Push))
    ));
    assert!(matches!("src/lib.rs:9".parse(), Ok(BreakpointType::Line { line: 9, .. })));
    assert!(matches!("src/lib.rs".parse(), Ok(BreakpointType::File(_))));
    assert!(matches!("in entrypoint".parse(), Ok(BreakpointType::Called(_))));

    for input in ["after nope", "at nope", "src/lib.rs:nope", "in [broken"] {
        assert!(input.parse::<BreakpointType>().is_err(), "accepted {input:?}");
    }
}

#[test]
fn breakpoint_cycle_and_lifecycle_rules_are_consistent() {
    let mut breakpoint = Breakpoint::new(BreakpointType::Step);
    breakpoint.creation_cycle = 10;
    assert_eq!(breakpoint.cycles_to_skip(10), Some(1));
    assert_eq!(breakpoint.cycles_to_skip(11), Some(0));

    breakpoint.ty = BreakpointType::StepN(4);
    assert_eq!(breakpoint.cycles_to_skip(12), Some(2));
    breakpoint.ty = BreakpointType::StepTo(20);
    assert_eq!(breakpoint.cycles_to_skip(12), Some(8));
    breakpoint.ty = BreakpointType::StepTo(5);
    assert_eq!(breakpoint.cycles_to_skip(12), None);
    breakpoint.ty = BreakpointType::Next;
    assert_eq!(breakpoint.cycles_to_skip(12), None);

    for ty in [
        BreakpointType::Next,
        BreakpointType::NextLine,
        BreakpointType::Finish,
        BreakpointType::Step,
    ] {
        assert!(Breakpoint::new(ty.clone()).is_internal());
        assert!(Breakpoint::new(ty).is_one_shot());
    }
    for ty in [BreakpointType::StepN(1), BreakpointType::StepTo(1)] {
        assert!(!Breakpoint::new(ty.clone()).is_internal());
        assert!(Breakpoint::new(ty).is_one_shot());
    }
    let called = "in entrypoint".parse::<BreakpointType>().unwrap();
    assert!(!Breakpoint::new(called).is_internal());
}

#[test]
fn operation_matchers_cover_specialized_operations() {
    let cases = [
        (OperationMatcher::Assert, Operation::Assert(Felt::ZERO)),
        (OperationMatcher::Push, Operation::Push(Felt::ONE)),
        (OperationMatcher::Dup, Operation::Dup0),
        (OperationMatcher::SwapW, Operation::SwapW),
        (OperationMatcher::Movup, Operation::MovUp2),
        (OperationMatcher::Movdn, Operation::MovDn2),
    ];
    for (matcher, operation) in cases {
        assert!(matcher.should_break_for(&operation));
        assert!(!matcher.should_break_for(&Operation::Noop));
        assert!(!matcher.to_string().is_empty());
    }

    for (text, expected) in [
        ("add", OperationMatcher::Exact(Operation::Add)),
        ("compress", OperationMatcher::Exact(Operation::Compress)),
        ("assert.7", OperationMatcher::Exact(Operation::Assert(Felt::from(7u32)))),
        ("u32assert2.8", OperationMatcher::Exact(Operation::U32assert2(Felt::from(8u32)))),
        ("log_deferred", OperationMatcher::Exact(Operation::LogDeferred)),
        ("unknown", OperationMatcher::Asm("unknown".into())),
    ] {
        assert_eq!(text.parse::<OperationMatcher>().unwrap(), expected);
    }
}

#[test]
fn event_breakpoints_match_emit_operations() {
    let breakpoint = BreakpointType::Event(Event::PrintLn);
    let processor = miden_processor::FastProcessor::new(
        miden_processor::StackInputs::new(&[Event::PrintLn.as_event_id().as_felt()]).unwrap(),
    );
    let state = processor.state();
    assert!(!breakpoint.should_break_for(&Operation::Noop, &state));
    assert!(breakpoint.should_break_for(&Operation::Emit, &state));

    let other_processor = miden_processor::FastProcessor::new(
        miden_processor::StackInputs::new(&[Event::FrameStart.as_event_id().as_felt()]).unwrap(),
    );
    assert!(!breakpoint.should_break_for(&Operation::Emit, &other_processor.state()));
}
