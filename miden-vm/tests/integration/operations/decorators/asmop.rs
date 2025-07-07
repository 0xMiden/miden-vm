use miden_core::{AssemblyOp, Felt, Operation};
use miden_debuginfo::Location;
use miden_processor::{AsmOpInfo, RowIndex, VmStateIterator};
use miden_test_utils::{assert_eq, build_debug_test};

#[test]
fn asmop_one_span_block_test() {
    let source = "begin push.1 push.2 add swap drop swap drop end";
    let test = build_debug_test!(source);
    let path = test.source.uri();
    let push1_loc = Some(Location {
        uri: path.clone(),
        start: 6.into(),
        end: (6 + 6).into(),
    });
    let push2_loc = Some(Location {
        uri: path.clone(),
        start: 13.into(),
        end: (13 + 6).into(),
    });
    let add_loc = Some(Location {
        uri: path.clone(),
        start: 20.into(),
        end: (20 + 3).into(),
    });
    let swap1_loc = Some(Location {
        uri: path.clone(),
        start: 24.into(),
        end: (24 + 4).into(),
    });
    let drop1_loc = Some(Location {
        uri: path.clone(),
        start: 29.into(),
        end: (29 + 4).into(),
    });
    let swap2_loc = Some(Location {
        uri: path.clone(),
        start: 34.into(),
        end: (34 + 4).into(),
    });
    let drop2_loc = Some(Location {
        uri: path.clone(),
        start: 39.into(),
        end: (39 + 4).into(),
    });
    let vm_state_iterator = test.execute_iter();
    let expected_vm_state = vec![
        VmStatePartial {
            clk: RowIndex::from(0),
            asmop: None,
            op: None,
        },
        VmStatePartial {
            clk: RowIndex::from(1),
            asmop: None,
            op: Some(Operation::Span),
        },
        VmStatePartial {
            clk: RowIndex::from(2),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    push1_loc.clone(),
                    "$exec::$main".to_string(),
                    2,
                    "push.1".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Pad),
        },
        VmStatePartial {
            clk: RowIndex::from(3),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    push1_loc,
                    "$exec::$main".to_string(),
                    2,
                    "push.1".to_string(),
                    false,
                ),
                2,
            )),
            op: Some(Operation::Incr),
        },
        VmStatePartial {
            clk: RowIndex::from(4),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    push2_loc,
                    "$exec::$main".to_string(),
                    1,
                    "push.2".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Push(Felt::new(2))),
        },
        VmStatePartial {
            clk: RowIndex::from(5),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(add_loc, "$exec::$main".to_string(), 1, "add".to_string(), false),
                1,
            )),
            op: Some(Operation::Add),
        },
        VmStatePartial {
            clk: RowIndex::from(6),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    swap1_loc,
                    "$exec::$main".to_string(),
                    1,
                    "swap.1".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Swap),
        },
        VmStatePartial {
            clk: RowIndex::from(7),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    drop1_loc,
                    "$exec::$main".to_string(),
                    1,
                    "drop".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Drop),
        },
        VmStatePartial {
            clk: RowIndex::from(8),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    swap2_loc,
                    "$exec::$main".to_string(),
                    1,
                    "swap.1".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Swap),
        },
        VmStatePartial {
            clk: RowIndex::from(9),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    drop2_loc,
                    "$exec::$main".to_string(),
                    1,
                    "drop".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Drop),
        },
        VmStatePartial {
            clk: RowIndex::from(10),
            asmop: None,
            op: Some(Operation::End),
        },
    ];
    let vm_state = build_vm_state(vm_state_iterator);
    assert_eq!(expected_vm_state, vm_state);
}

#[test]
fn asmop_with_one_procedure() {
    let source = "proc.foo push.1 push.2 add end begin exec.foo swap drop swap drop end";
    let test = build_debug_test!(source);
    let path = test.source.uri();
    let push1_loc = Some(Location {
        uri: path.clone(),
        start: 9.into(),
        end: (9 + 6).into(),
    });
    let push2_loc = Some(Location {
        uri: path.clone(),
        start: 16.into(),
        end: (16 + 6).into(),
    });
    let add_loc = Some(Location {
        uri: path.clone(),
        start: 23.into(),
        end: (23 + 3).into(),
    });
    let swap1_loc = Some(Location {
        uri: path.clone(),
        start: 46.into(),
        end: (46 + 4).into(),
    });
    let drop1_loc = Some(Location {
        uri: path.clone(),
        start: 51.into(),
        end: (51 + 4).into(),
    });
    let swap2_loc = Some(Location {
        uri: path.clone(),
        start: 56.into(),
        end: (56 + 4).into(),
    });
    let drop2_loc = Some(Location {
        uri: path.clone(),
        start: 61.into(),
        end: (61 + 4).into(),
    });
    let vm_state_iterator = test.execute_iter();
    let expected_vm_state = vec![
        VmStatePartial {
            clk: RowIndex::from(0),
            asmop: None,
            op: None,
        },
        VmStatePartial {
            clk: RowIndex::from(1),
            asmop: None,
            op: Some(Operation::Span),
        },
        VmStatePartial {
            clk: RowIndex::from(2),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    push1_loc.clone(),
                    "$exec::foo".to_string(),
                    2,
                    "push.1".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Pad),
        },
        VmStatePartial {
            clk: RowIndex::from(3),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    push1_loc,
                    "$exec::foo".to_string(),
                    2,
                    "push.1".to_string(),
                    false,
                ),
                2,
            )),
            op: Some(Operation::Incr),
        },
        VmStatePartial {
            clk: RowIndex::from(4),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    push2_loc,
                    "$exec::foo".to_string(),
                    1,
                    "push.2".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Push(Felt::new(2))),
        },
        VmStatePartial {
            clk: RowIndex::from(5),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(add_loc, "$exec::foo".to_string(), 1, "add".to_string(), false),
                1,
            )),
            op: Some(Operation::Add),
        },
        VmStatePartial {
            clk: RowIndex::from(6),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    swap1_loc,
                    "$exec::$main".to_string(),
                    1,
                    "swap.1".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Swap),
        },
        VmStatePartial {
            clk: RowIndex::from(7),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    drop1_loc,
                    "$exec::$main".to_string(),
                    1,
                    "drop".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Drop),
        },
        VmStatePartial {
            clk: RowIndex::from(8),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    swap2_loc,
                    "$exec::$main".to_string(),
                    1,
                    "swap.1".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Swap),
        },
        VmStatePartial {
            clk: RowIndex::from(9),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    drop2_loc,
                    "$exec::$main".to_string(),
                    1,
                    "drop".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Drop),
        },
        VmStatePartial {
            clk: RowIndex::from(10),
            asmop: None,
            op: Some(Operation::End),
        },
    ];
    let vm_state = build_vm_state(vm_state_iterator);
    assert_eq!(expected_vm_state, vm_state);
}

#[test]
fn asmop_repeat_test() {
    let source = "
        begin
            repeat.3
                push.1 push.2 add
            end
            swapdw dropw dropw
        end";
    let test = build_debug_test!(source);
    let path = test.source.uri();
    let push1_loc = Some(Location {
        uri: path.clone(),
        start: 52.into(),
        end: (52 + 6).into(),
    });
    let push2_loc = Some(Location {
        uri: path.clone(),
        start: 59.into(),
        end: (59 + 6).into(),
    });
    let add_loc = Some(Location {
        uri: path.clone(),
        start: 66.into(),
        end: (66 + 3).into(),
    });
    let swapdw_loc = Some(Location {
        uri: path.clone(),
        start: 98.into(),
        end: (98 + 6).into(),
    });
    let dropw1_loc = Some(Location {
        uri: path.clone(),
        start: 105.into(),
        end: (105 + 5).into(),
    });
    let dropw2_loc = Some(Location {
        uri: path.clone(),
        start: 111.into(),
        end: (111 + 5).into(),
    });
    let vm_state_iterator = test.execute_iter();
    let expected_vm_state = vec![
        VmStatePartial {
            clk: RowIndex::from(0),
            asmop: None,
            op: None,
        },
        VmStatePartial {
            clk: RowIndex::from(1),
            asmop: None,
            op: Some(Operation::Span),
        },
        VmStatePartial {
            clk: RowIndex::from(2),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    push1_loc.clone(),
                    "$exec::$main".to_string(),
                    2,
                    "push.1".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Pad),
        },
        VmStatePartial {
            clk: RowIndex::from(3),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    push1_loc.clone(),
                    "$exec::$main".to_string(),
                    2,
                    "push.1".to_string(),
                    false,
                ),
                2,
            )),
            op: Some(Operation::Incr),
        },
        VmStatePartial {
            clk: RowIndex::from(4),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    push2_loc.clone(),
                    "$exec::$main".to_string(),
                    1,
                    "push.2".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Push(Felt::new(2))),
        },
        VmStatePartial {
            clk: RowIndex::from(5),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    add_loc.clone(),
                    "$exec::$main".to_string(),
                    1,
                    "add".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Add),
        },
        // End first Span
        VmStatePartial {
            clk: RowIndex::from(6),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    push1_loc.clone(),
                    "$exec::$main".to_string(),
                    2,
                    "push.1".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Pad),
        },
        VmStatePartial {
            clk: RowIndex::from(7),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    push1_loc.clone(),
                    "$exec::$main".to_string(),
                    2,
                    "push.1".to_string(),
                    false,
                ),
                2,
            )),
            op: Some(Operation::Incr),
        },
        VmStatePartial {
            clk: RowIndex::from(8),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    push2_loc.clone(),
                    "$exec::$main".to_string(),
                    1,
                    "push.2".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Push(Felt::new(2))),
        },
        VmStatePartial {
            clk: RowIndex::from(9),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    add_loc.clone(),
                    "$exec::$main".to_string(),
                    1,
                    "add".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Add),
        },
        // End second Span
        VmStatePartial {
            clk: RowIndex::from(10),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    push1_loc.clone(),
                    "$exec::$main".to_string(),
                    2,
                    "push.1".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Pad),
        },
        VmStatePartial {
            clk: RowIndex::from(11),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    push1_loc,
                    "$exec::$main".to_string(),
                    2,
                    "push.1".to_string(),
                    false,
                ),
                2,
            )),
            op: Some(Operation::Incr),
        },
        VmStatePartial {
            clk: RowIndex::from(12),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    push2_loc,
                    "$exec::$main".to_string(),
                    1,
                    "push.2".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Push(Felt::new(2))),
        },
        VmStatePartial {
            clk: RowIndex::from(13),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(add_loc, "$exec::$main".to_string(), 1, "add".to_string(), false),
                1,
            )),
            op: Some(Operation::Add),
        },
        VmStatePartial {
            clk: RowIndex::from(14),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    swapdw_loc,
                    "$exec::$main".to_string(),
                    1,
                    "swapdw".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::SwapDW),
        },
        VmStatePartial {
            clk: RowIndex::from(15),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    dropw1_loc.clone(),
                    "$exec::$main".to_string(),
                    4,
                    "dropw".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Drop),
        },
        VmStatePartial {
            clk: RowIndex::from(16),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    dropw1_loc.clone(),
                    "$exec::$main".to_string(),
                    4,
                    "dropw".to_string(),
                    false,
                ),
                2,
            )),
            op: Some(Operation::Drop),
        },
        VmStatePartial {
            clk: RowIndex::from(17),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    dropw1_loc.clone(),
                    "$exec::$main".to_string(),
                    4,
                    "dropw".to_string(),
                    false,
                ),
                3,
            )),
            op: Some(Operation::Drop),
        },
        VmStatePartial {
            clk: RowIndex::from(18),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    dropw1_loc,
                    "$exec::$main".to_string(),
                    4,
                    "dropw".to_string(),
                    false,
                ),
                4,
            )),
            op: Some(Operation::Drop),
        },
        VmStatePartial {
            clk: RowIndex::from(19),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    dropw2_loc.clone(),
                    "$exec::$main".to_string(),
                    4,
                    "dropw".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Drop),
        },
        VmStatePartial {
            clk: RowIndex::from(20),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    dropw2_loc.clone(),
                    "$exec::$main".to_string(),
                    4,
                    "dropw".to_string(),
                    false,
                ),
                2,
            )),
            op: Some(Operation::Drop),
        },
        VmStatePartial {
            clk: RowIndex::from(21),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    dropw2_loc.clone(),
                    "$exec::$main".to_string(),
                    4,
                    "dropw".to_string(),
                    false,
                ),
                3,
            )),
            op: Some(Operation::Drop),
        },
        VmStatePartial {
            clk: RowIndex::from(22),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    dropw2_loc,
                    "$exec::$main".to_string(),
                    4,
                    "dropw".to_string(),
                    false,
                ),
                4,
            )),
            op: Some(Operation::Drop),
        },
        VmStatePartial {
            clk: RowIndex::from(23),
            asmop: None,
            op: Some(Operation::Noop),
        },
        VmStatePartial {
            clk: RowIndex::from(24),
            asmop: None,
            op: Some(Operation::Noop),
        },
        VmStatePartial {
            clk: RowIndex::from(25),
            asmop: None,
            op: Some(Operation::End),
        },
    ];
    let vm_state = build_vm_state(vm_state_iterator);
    assert_eq!(expected_vm_state, vm_state);
}

#[test]
fn asmop_conditional_execution_test() {
    let source = "
        begin
            eq
            if.true
                push.1 push.2 add
            else
                push.3 push.4 add
            end

            swap drop swap drop
        end";

    //if branch
    let test = build_debug_test!(source, &[1, 1]);
    let path = test.source.uri();
    let if_branch_loc = Some(Location {
        uri: path.clone(),
        start: 42.into(),
        end: 150.into(),
    });
    let eq_loc = Some(Location {
        uri: path.clone(),
        start: 27.into(),
        end: (27 + 2).into(),
    });
    let push1_loc = Some(Location {
        uri: path.clone(),
        start: 66.into(),
        end: (66 + 6).into(),
    });
    let push2_loc = Some(Location {
        uri: path.clone(),
        start: 73.into(),
        end: (73 + 6).into(),
    });
    let add_loc = Some(Location {
        uri: path.clone(),
        start: 80.into(),
        end: (80 + 3).into(),
    });
    let swap1_loc = Some(Location {
        uri: path.clone(),
        start: 164.into(),
        end: (164 + 4).into(),
    });
    let drop1_loc = Some(Location {
        uri: path.clone(),
        start: 169.into(),
        end: (169 + 4).into(),
    });
    let swap2_loc = Some(Location {
        uri: path.clone(),
        start: 174.into(),
        end: (174 + 4).into(),
    });
    let drop2_loc = Some(Location {
        uri: path.clone(),
        start: 179.into(),
        end: (179 + 4).into(),
    });
    let vm_state_iterator = test.execute_iter();
    let expected_vm_state = vec![
        VmStatePartial {
            clk: RowIndex::from(0),
            asmop: None,
            op: None,
        },
        VmStatePartial {
            clk: RowIndex::from(1),
            asmop: None,
            op: Some(Operation::Join),
        },
        VmStatePartial {
            clk: RowIndex::from(2),
            asmop: None,
            op: Some(Operation::Join),
        },
        VmStatePartial {
            clk: RowIndex::from(3),
            asmop: None,
            op: Some(Operation::Span),
        },
        VmStatePartial {
            clk: RowIndex::from(4),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(eq_loc, "$exec::$main".to_string(), 1, "eq".to_string(), false),
                1,
            )),
            op: Some(Operation::Eq),
        },
        VmStatePartial {
            clk: RowIndex::from(5),
            asmop: None,
            op: Some(Operation::End),
        },
        VmStatePartial {
            clk: RowIndex::from(6),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    if_branch_loc,
                    "$exec::$main".to_string(),
                    0,
                    "if.true".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Split),
        },
        VmStatePartial {
            clk: RowIndex::from(7),
            asmop: None,
            op: Some(Operation::Span),
        },
        VmStatePartial {
            clk: RowIndex::from(8),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    push1_loc.clone(),
                    "$exec::$main".to_string(),
                    2,
                    "push.1".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Pad),
        },
        VmStatePartial {
            clk: RowIndex::from(9),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    push1_loc,
                    "$exec::$main".to_string(),
                    2,
                    "push.1".to_string(),
                    false,
                ),
                2,
            )),
            op: Some(Operation::Incr),
        },
        VmStatePartial {
            clk: RowIndex::from(10),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    push2_loc,
                    "$exec::$main".to_string(),
                    1,
                    "push.2".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Push(Felt::new(2))),
        },
        VmStatePartial {
            clk: RowIndex::from(11),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(add_loc, "$exec::$main".to_string(), 1, "add".to_string(), false),
                1,
            )),
            op: Some(Operation::Add),
        },
        VmStatePartial {
            clk: RowIndex::from(12),
            asmop: None,
            op: Some(Operation::End),
        },
        VmStatePartial {
            clk: RowIndex::from(13),
            asmop: None,
            op: Some(Operation::End),
        },
        VmStatePartial {
            clk: RowIndex::from(14),
            asmop: None,
            op: Some(Operation::End),
        },
        VmStatePartial {
            clk: RowIndex::from(15),
            asmop: None,
            op: Some(Operation::Span),
        },
        VmStatePartial {
            clk: RowIndex::from(16),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    swap1_loc,
                    "$exec::$main".to_string(),
                    1,
                    "swap.1".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Swap),
        },
        VmStatePartial {
            clk: RowIndex::from(17),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    drop1_loc,
                    "$exec::$main".to_string(),
                    1,
                    "drop".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Drop),
        },
        VmStatePartial {
            clk: RowIndex::from(18),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    swap2_loc,
                    "$exec::$main".to_string(),
                    1,
                    "swap.1".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Swap),
        },
        VmStatePartial {
            clk: RowIndex::from(19),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    drop2_loc,
                    "$exec::$main".to_string(),
                    1,
                    "drop".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Drop),
        },
        VmStatePartial {
            clk: RowIndex::from(20),
            asmop: None,
            op: Some(Operation::End),
        },
        VmStatePartial {
            clk: RowIndex::from(21),
            asmop: None,
            op: Some(Operation::End),
        },
    ];
    let vm_state = build_vm_state(vm_state_iterator);
    assert_eq!(expected_vm_state, vm_state);

    //else branch
    let test = build_debug_test!(source, &[1, 0]);
    let path = test.source.uri();
    let else_branch_loc = Some(Location {
        uri: path.clone(),
        start: 42.into(),
        end: 150.into(),
    });
    let eq_loc = Some(Location {
        uri: path.clone(),
        start: 27.into(),
        end: (27 + 2).into(),
    });
    let push3_loc = Some(Location {
        uri: path.clone(),
        start: 117.into(),
        end: (117 + 6).into(),
    });
    let push4_loc = Some(Location {
        uri: path.clone(),
        start: 124.into(),
        end: (124 + 6).into(),
    });
    let add_loc = Some(Location {
        uri: path.clone(),
        start: 131.into(),
        end: (131 + 3).into(),
    });
    let swap1_loc = Some(Location {
        uri: path.clone(),
        start: 164.into(),
        end: (164 + 4).into(),
    });
    let drop1_loc = Some(Location {
        uri: path.clone(),
        start: 169.into(),
        end: (169 + 4).into(),
    });
    let swap2_loc = Some(Location {
        uri: path.clone(),
        start: 174.into(),
        end: (174 + 4).into(),
    });
    let drop2_loc = Some(Location {
        uri: path.clone(),
        start: 179.into(),
        end: (179 + 4).into(),
    });
    let vm_state_iterator = test.execute_iter();
    let expected_vm_state = vec![
        VmStatePartial {
            clk: RowIndex::from(0),
            asmop: None,
            op: None,
        },
        VmStatePartial {
            clk: RowIndex::from(1),
            asmop: None,
            op: Some(Operation::Join),
        },
        VmStatePartial {
            clk: RowIndex::from(2),
            asmop: None,
            op: Some(Operation::Join),
        },
        VmStatePartial {
            clk: RowIndex::from(3),
            asmop: None,
            op: Some(Operation::Span),
        },
        VmStatePartial {
            clk: RowIndex::from(4),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(eq_loc, "$exec::$main".to_string(), 1, "eq".to_string(), false),
                1,
            )),
            op: Some(Operation::Eq),
        },
        VmStatePartial {
            clk: RowIndex::from(5),
            asmop: None,
            op: Some(Operation::End),
        },
        VmStatePartial {
            clk: RowIndex::from(6),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    else_branch_loc,
                    "$exec::$main".to_string(),
                    0,
                    "if.true".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Split),
        },
        VmStatePartial {
            clk: RowIndex::from(7),
            asmop: None,
            op: Some(Operation::Span),
        },
        VmStatePartial {
            clk: RowIndex::from(8),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    push3_loc,
                    "$exec::$main".to_string(),
                    1,
                    "push.3".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Push(Felt::new(3))),
        },
        VmStatePartial {
            clk: RowIndex::from(9),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    push4_loc,
                    "$exec::$main".to_string(),
                    1,
                    "push.4".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Push(Felt::new(4))),
        },
        VmStatePartial {
            clk: RowIndex::from(10),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(add_loc, "$exec::$main".to_string(), 1, "add".to_string(), false),
                1,
            )),
            op: Some(Operation::Add),
        },
        VmStatePartial {
            clk: RowIndex::from(11),
            asmop: None,
            op: Some(Operation::Noop),
        },
        VmStatePartial {
            clk: RowIndex::from(12),
            asmop: None,
            op: Some(Operation::End),
        },
        VmStatePartial {
            clk: RowIndex::from(13),
            asmop: None,
            op: Some(Operation::End),
        },
        VmStatePartial {
            clk: RowIndex::from(14),
            asmop: None,
            op: Some(Operation::End),
        },
        VmStatePartial {
            clk: RowIndex::from(15),
            asmop: None,
            op: Some(Operation::Span),
        },
        VmStatePartial {
            clk: RowIndex::from(16),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    swap1_loc,
                    "$exec::$main".to_string(),
                    1,
                    "swap.1".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Swap),
        },
        VmStatePartial {
            clk: RowIndex::from(17),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    drop1_loc,
                    "$exec::$main".to_string(),
                    1,
                    "drop".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Drop),
        },
        VmStatePartial {
            clk: RowIndex::from(18),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    swap2_loc,
                    "$exec::$main".to_string(),
                    1,
                    "swap.1".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Swap),
        },
        VmStatePartial {
            clk: RowIndex::from(19),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    drop2_loc,
                    "$exec::$main".to_string(),
                    1,
                    "drop".to_string(),
                    false,
                ),
                1,
            )),
            op: Some(Operation::Drop),
        },
        VmStatePartial {
            clk: RowIndex::from(20),
            asmop: None,
            op: Some(Operation::End),
        },
        VmStatePartial {
            clk: RowIndex::from(21),
            asmop: None,
            op: Some(Operation::End),
        },
    ];
    let vm_state = build_vm_state(vm_state_iterator);
    assert_eq!(expected_vm_state, vm_state);
}

/// This is a helper function to build a vector of [VmStatePartial] from a specified
/// [VmStateIterator].
fn build_vm_state(vm_state_iterator: VmStateIterator) -> Vec<VmStatePartial> {
    let mut vm_state = Vec::new();
    for state in vm_state_iterator {
        vm_state.push(VmStatePartial {
            clk: state.as_ref().unwrap().clk,
            asmop: state.as_ref().unwrap().asmop.clone(),
            op: state.as_ref().unwrap().op,
        });
    }
    vm_state
}

/// [VmStatePartial] holds the following current process state information at a specific clock cycle
/// * clk: Current clock cycle
/// * asmop: AsmOp decorator at the specific clock cycle
/// * op: Operation executed at the specific clock cycle
#[derive(Clone, Debug, Eq, PartialEq)]
struct VmStatePartial {
    clk: RowIndex,
    asmop: Option<AsmOpInfo>,
    op: Option<Operation>,
}
