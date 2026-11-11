use alloc::sync::Arc;

use miden_assembly_syntax::ast::types::{StructType, TypeRepr};

use super::*;

#[test]
fn test_tracker_basic() {
    let events: Rc<RefCell<BTreeMap<RowIndex, Vec<DebugVarInfo>>>> = Rc::new(Default::default());

    // Add some events
    {
        let mut events_mut = events.borrow_mut();
        events_mut
            .insert(RowIndex::from(1), vec![DebugVarInfo::new("x", DebugVarLocation::Stack(0))]);
        events_mut
            .insert(RowIndex::from(5), vec![DebugVarInfo::new("y", DebugVarLocation::Stack(1))]);
    }

    let mut tracker = DebugVarTracker::new(events);

    // Initially no variables
    assert_eq!(tracker.variable_count(), 0);

    // Process up to cycle 3
    tracker.update_to_cycle(RowIndex::from(3));
    assert_eq!(tracker.variable_count(), 1);
    assert!(tracker.get_variable("x").is_some());
    assert!(tracker.get_variable("y").is_none());

    // Process up to cycle 10
    tracker.update_to_cycle(RowIndex::from(10));
    assert_eq!(tracker.variable_count(), 2);
    assert!(tracker.get_variable("x").is_some());
    assert!(tracker.get_variable("y").is_some());

    // Verify resolve_variable_value resolves stack values
    let x_snapshot = tracker.get_variable("x").unwrap();
    let value = resolve_variable_value(
        x_snapshot.info.value_location(),
        &[Felt::new(42).expect("value exceeds field modulus")],
        |_| None,
        |_| None,
    );
    assert_eq!(value, Some(Felt::new(42).expect("value exceeds field modulus")));
}

#[test]
fn snapshots_transient_stack_locations_as_constants() {
    let mut infos = vec![
        DebugVarInfo::new("a", DebugVarLocation::Stack(0)),
        DebugVarInfo::new("b", DebugVarLocation::Local(-1)),
        DebugVarInfo::new(
            "c",
            DebugVarLocation::Expression(
                DebugLocationExpression::new(vec![
                    DebugLocationExpressionOp::ReadStack(0),
                    DebugLocationExpressionOp::AddUnsigned(3),
                ])
                .unwrap(),
            ),
        ),
        DebugVarInfo::new(
            "missing",
            DebugVarLocation::Expression(
                DebugLocationExpression::new(vec![DebugLocationExpressionOp::ReadStack(1)])
                    .unwrap(),
            ),
        ),
    ];

    let captured_values = snapshot_transient_debug_values(
        &mut infos,
        &[Felt::new(7).expect("value exceeds field modulus")],
    );

    assert_eq!(
        infos[0].value_location(),
        &DebugVarLocation::Const(Felt::new(7).expect("value exceeds field modulus"))
    );
    assert_eq!(infos[1].value_location(), &DebugVarLocation::Local(-1));
    assert_eq!(
        infos[2].value_location(),
        &DebugVarLocation::Expression(
            DebugLocationExpression::new(vec![
                DebugLocationExpressionOp::ConstU64(7),
                DebugLocationExpressionOp::AddUnsigned(3)
            ])
            .unwrap()
        )
    );
    assert_eq!(infos[3].value_location(), &DebugVarLocation::Unavailable);
    assert_eq!(captured_values.get("a" as &str), Some(&vec![Felt::from_u32(7)]));
}

#[test]
fn snapshots_all_felts_for_typed_stack_locations() {
    let events: Rc<RefCell<BTreeMap<RowIndex, Vec<DebugVarInfo>>>> = Rc::new(Default::default());
    let mut tracker = DebugVarTracker::new(events);
    let mut info = DebugVarInfo::new("wide", DebugVarLocation::Stack(0));
    info.set_ty(Type::U64, None);

    tracker.record_events_with_stack(
        RowIndex::from(1),
        vec![info],
        &[Felt::from_u32(7), Felt::from_u32(1)],
    );
    tracker.update_to_cycle(RowIndex::from(1));

    let snapshot = tracker.get_variable("wide").unwrap();
    assert_eq!(snapshot.info.value_location(), &DebugVarLocation::Const(Felt::from_u32(7)));
    assert_eq!(
        tracker.captured_values("wide"),
        Some([Felt::from_u32(7), Felt::from_u32(1)].as_slice())
    );
}

#[test]
fn resolves_explicit_frame_bases() {
    let expected = Felt::new(4_294_967_303).unwrap();
    for (base, memory_base) in
        [(DebugFrameBase::Local(-7), false), (DebugFrameBase::Memory(9), true)]
    {
        let value = resolve_variable_value(
            &DebugVarLocation::ResolvedFrameBase {
                base,
                byte_offset: 28,
            },
            &[],
            |address| {
                if memory_base && address == 9 {
                    Some(Felt::new(1_048_528).unwrap())
                } else if address == 262_139 {
                    Some(expected)
                } else {
                    None
                }
            },
            |offset| (!memory_base && offset == -7).then_some(Felt::new(1_048_528).unwrap()),
        );
        assert_eq!(value, Some(expected));
    }
}

#[test]
fn resolves_structured_location_expressions() {
    let expression = DebugLocationExpression::new(vec![
        DebugLocationExpressionOp::FrameBaseAddress {
            base: DebugFrameBase::Local(-2),
            byte_offset: 4,
        },
        DebugLocationExpressionOp::AddUnsigned(8),
        DebugLocationExpressionOp::DerefBytes,
    ])
    .unwrap();
    let value = resolve_variable_value(
        &DebugVarLocation::Expression(expression),
        &[],
        |address| (address == 27).then_some(Felt::new(13).unwrap()),
        |offset| (offset == -2).then_some(Felt::new(96).unwrap()),
    );

    assert_eq!(value, Some(Felt::new(13).unwrap()));
}

#[test]
fn resolves_untyped_byte_dereferences_as_memory_elements() {
    let expression = DebugLocationExpression::new(vec![
        DebugLocationExpressionOp::ConstU64(1),
        DebugLocationExpressionOp::DerefBytes,
    ])
    .unwrap();
    let expected = Felt::new(4_294_967_303).unwrap();
    let value = resolve_variable_value(
        &DebugVarLocation::Expression(expression),
        &[],
        |address| (address == 0).then_some(expected),
        |_| None,
    );

    assert_eq!(value, Some(expected));
}

#[test]
fn preserves_whole_felts_after_nonterminal_byte_dereferences() {
    let expression = DebugLocationExpression::new(vec![
        DebugLocationExpressionOp::ConstU64(1),
        DebugLocationExpressionOp::DerefBytes,
        DebugLocationExpressionOp::AddUnsigned(1),
    ])
    .unwrap();
    let value = resolve_variable_value(
        &DebugVarLocation::Expression(expression),
        &[],
        |address| (address == 0).then(|| Felt::new(4_294_967_303).unwrap()),
        |_| None,
    );

    assert_eq!(value, Some(Felt::new(4_294_967_304).unwrap()));
}

#[test]
fn resolves_wide_typed_values_from_unaligned_byte_addresses() {
    let expression = DebugLocationExpression::new(vec![
        DebugLocationExpressionOp::ConstU64(3),
        DebugLocationExpressionOp::DerefBytes,
    ])
    .unwrap();
    let values = resolve_typed_variable_values(
        &DebugVarLocation::Expression(expression),
        &Type::U64,
        2,
        &[],
        |address| match address {
            0 => Some(Felt::from_u32(0x3322_11aa)),
            1 => Some(Felt::from_u32(0x7766_5544)),
            2 => Some(Felt::from_u32(0xbbaa_9988)),
            _ => None,
        },
        |_| None,
    );

    assert_eq!(values, Some(vec![Felt::from_u32(0x6655_4433), Felt::from_u32(0xaa99_8877)]));
}

#[test]
fn lifts_packed_struct_fields_into_canonical_abi_felts() {
    let packed = Type::from(StructType::new_with_repr(
        TypeRepr::packed(1),
        [(Arc::from("tiny"), Type::U8), (Arc::from("half"), Type::U16)],
    ));
    let values = resolve_typed_variable_values(
        &DebugVarLocation::ResolvedFrameBase {
            base: DebugFrameBase::Local(-1),
            byte_offset: 0,
        },
        &packed,
        2,
        &[],
        |address| (address == 0).then_some(Felt::from_u32(0x3322_11aa)),
        |offset| (offset == -1).then_some(Felt::from_u32(1)),
    );

    assert_eq!(values, Some(vec![Felt::from_u32(0x11), Felt::from_u32(0x3322)]));
    assert_eq!(
        crate::debug::format_value(&packed, |count| {
            resolve_typed_variable_values(
                &DebugVarLocation::ResolvedFrameBase {
                    base: DebugFrameBase::Local(-1),
                    byte_offset: 0,
                },
                &packed,
                count,
                &[],
                |address| (address == 0).then_some(Felt::from_u32(0x3322_11aa)),
                |offset| (offset == -1).then_some(Felt::from_u32(1)),
            )
        })
        .as_deref(),
        Some("{ tiny: 17, half: 13090 }")
    );
}

#[test]
fn sign_extends_typed_integers_to_their_canonical_slots() {
    let values = resolve_typed_variable_values(
        &DebugVarLocation::ResolvedFrameBase {
            base: DebugFrameBase::Local(-1),
            byte_offset: 0,
        },
        &Type::I8,
        1,
        &[],
        |address| (address == 0).then_some(Felt::from_u32(0x0000_ff00)),
        |offset| (offset == -1).then_some(Felt::from_u32(1)),
    );

    assert_eq!(values, Some(vec![Felt::from_u32(u32::MAX)]));
}

#[test]
fn rejects_invalid_location_expression_results() {
    for expression in [
        DebugLocationExpression::new(vec![DebugLocationExpressionOp::ConstI64(-1)]).unwrap(),
        DebugLocationExpression::new(vec![
            DebugLocationExpressionOp::ConstU64(u64::MAX),
            DebugLocationExpressionOp::ConstU64(1),
            DebugLocationExpressionOp::Add,
        ])
        .unwrap(),
    ] {
        assert_eq!(
            resolve_variable_value(
                &DebugVarLocation::Expression(expression),
                &[],
                |_| None,
                |_| None,
            ),
            None
        );
    }
}

#[test]
fn resolves_consecutive_memory_values() {
    let values = resolve_variable_values(
        &DebugVarLocation::Memory(10),
        2,
        &[],
        |address| match address {
            10 => Some(Felt::new(1).unwrap()),
            11 => Some(Felt::new(2).unwrap()),
            _ => None,
        },
        |_| None,
    );

    assert_eq!(values, Some(vec![Felt::new(1).unwrap(), Felt::new(2).unwrap()]));
}

#[test]
fn debug_kill_removes_current_variable() {
    let events: Rc<RefCell<BTreeMap<RowIndex, Vec<DebugVarInfo>>>> = Rc::new(Default::default());
    {
        let mut events = events.borrow_mut();
        events.insert(
            RowIndex::from(1),
            vec![DebugVarInfo::new(
                "x",
                DebugVarLocation::Const(Felt::new(1).expect("value exceeds field modulus")),
            )],
        );
        events
            .insert(RowIndex::from(2), vec![DebugVarInfo::new("x", DebugVarLocation::Unavailable)]);
    }

    let mut tracker = DebugVarTracker::new(events);
    tracker.update_to_cycle(RowIndex::from(1));
    assert!(tracker.get_variable("x").is_some());

    tracker.update_to_cycle(RowIndex::from(2));
    assert!(tracker.get_variable("x").is_none());
}
