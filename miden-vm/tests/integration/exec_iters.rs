use miden_core::{AssemblyOp, Operation};
use miden_debug_types::Location;
use miden_processor::{AsmOpInfo, ContextId, RowIndex, VmState};
use miden_utils_testing::{Felt, ONE, ToElements, assert_eq, build_debug_test};

// EXEC ITER TESTS
// =================================================================
/// TODO: Reenable (and fix) after we stabilized the assembler
/// Note: expect the memory values to be very wrong.
#[test]
#[ignore]
fn test_exec_iter() {
    let source = "proc.foo.1 loc_store.0 end begin mem_storew_be.1 dropw push.17 exec.foo end";
    let mut init_stack: Vec<u64> = Vec::new();
    (1..=16).for_each(|i| {
        init_stack.push(i);
    });
    let test = build_debug_test!(source, &init_stack);
    let path = test.source.uri();
    let traces = test.execute_iter();
    let fmp = Felt::new(2u64.pow(30));
    let next_fmp = fmp + ONE;
    // TODO: double check this value
    let mem = vec![(1u32.into(), Felt::from(13_u32))];
    let mem_storew1_loc = Some(Location {
        uri: path.clone(),
        start: 33.into(),
        end: (33 + 12).into(),
    });
    let dropw_loc = Some(Location {
        uri: path.clone(),
        start: 46.into(),
        end: (46 + 5).into(),
    });
    let push17_loc = Some(Location {
        uri: path.clone(),
        start: 52.into(),
        end: (52 + 7).into(),
    });
    let locstore0_loc = Some(Location {
        uri: path.clone(),
        start: 11.into(),
        end: (11 + 11).into(),
    });
    let expected_states = vec![
        VmState {
            clk: RowIndex::from(0),
            ctx: ContextId::root(),
            op: None,
            asmop: None,
            stack: [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1].to_elements(),
            fmp,
            memory: Vec::new(),
        },
        VmState {
            clk: RowIndex::from(1),
            ctx: ContextId::root(),
            op: Some(Operation::Join),
            asmop: None,
            stack: [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1].to_elements(),
            fmp,
            memory: Vec::new(),
        },
        VmState {
            clk: RowIndex::from(2),
            ctx: ContextId::root(),
            op: Some(Operation::Span),
            asmop: None,
            stack: [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1].to_elements(),
            fmp,
            memory: Vec::new(),
        },
        VmState {
            clk: RowIndex::from(3),
            ctx: ContextId::root(),
            op: Some(Operation::Pad),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    mem_storew1_loc.clone(),
                    "$exec::$main".to_string(),
                    3,
                    "mem_storew_be.1".to_string(),
                    false,
                ),
                1,
            )),
            stack: [0, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1].to_elements(),
            fmp,
            memory: Vec::new(),
        },
        VmState {
            clk: RowIndex::from(4),
            ctx: ContextId::root(),
            op: Some(Operation::Incr),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    mem_storew1_loc.clone(),
                    "$exec::$main".to_string(),
                    3,
                    "mem_storew_be.1".to_string(),
                    false,
                ),
                2,
            )),
            stack: [1, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2].to_elements(),
            fmp,
            memory: Vec::new(),
        },
        VmState {
            clk: RowIndex::from(5),
            ctx: ContextId::root(),
            op: Some(Operation::MStoreW),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    mem_storew1_loc,
                    "$exec::$main".to_string(),
                    3,
                    "mem_storew_be.1".to_string(),
                    false,
                ),
                3,
            )),
            stack: [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1].to_elements(),
            fmp,
            memory: mem.clone(),
        },
        VmState {
            clk: RowIndex::from(6),
            ctx: ContextId::root(),
            op: Some(Operation::Drop),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    dropw_loc.clone(),
                    "$exec::$main".to_string(),
                    4,
                    "dropw".to_string(),
                    false,
                ),
                1,
            )),
            stack: [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0].to_elements(),
            fmp,
            memory: mem.clone(),
        },
        VmState {
            clk: RowIndex::from(7),
            ctx: ContextId::root(),
            op: Some(Operation::Drop),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    dropw_loc.clone(),
                    "$exec::$main".to_string(),
                    4,
                    "dropw".to_string(),
                    false,
                ),
                2,
            )),
            stack: [14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0].to_elements(),
            fmp,
            memory: mem.clone(),
        },
        VmState {
            clk: RowIndex::from(8),
            ctx: ContextId::root(),
            op: Some(Operation::Drop),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    dropw_loc.clone(),
                    "$exec::$main".to_string(),
                    4,
                    "dropw".to_string(),
                    false,
                ),
                3,
            )),
            stack: [13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0].to_elements(),
            fmp,
            memory: mem.clone(),
        },
        VmState {
            clk: RowIndex::from(9),
            ctx: ContextId::root(),
            op: Some(Operation::Drop),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    dropw_loc,
                    "$exec::$main".to_string(),
                    4,
                    "dropw".to_string(),
                    false,
                ),
                4,
            )),
            stack: [12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0].to_elements(),
            fmp,
            memory: mem.clone(),
        },
        VmState {
            clk: RowIndex::from(10),
            ctx: ContextId::root(),
            op: Some(Operation::Push(Felt::new(17))),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    push17_loc,
                    "$exec::$main".to_string(),
                    1,
                    "push.17".to_string(),
                    false,
                ),
                1,
            )),
            stack: [17, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0].to_elements(),
            fmp,
            memory: mem.clone(),
        },
        VmState {
            clk: RowIndex::from(11),
            ctx: ContextId::root(),
            op: Some(Operation::Noop),
            asmop: None,
            stack: [17, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0].to_elements(),
            fmp,
            memory: mem.clone(),
        },
        VmState {
            clk: RowIndex::from(12),
            ctx: ContextId::root(),
            op: Some(Operation::End),
            asmop: None,
            stack: [17, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0].to_elements(),
            fmp,
            memory: mem.clone(),
        },
        VmState {
            clk: RowIndex::from(13),
            ctx: ContextId::root(),
            op: Some(Operation::Span),
            asmop: None,
            stack: [17, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0].to_elements(),
            fmp,
            memory: mem.clone(),
        },
        VmState {
            clk: RowIndex::from(14),
            ctx: ContextId::root(),
            op: Some(Operation::Push(ONE)),
            asmop: None,
            stack: [1, 17, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0].to_elements(),
            fmp,
            memory: mem.clone(),
        },
        VmState {
            clk: RowIndex::from(15),
            ctx: ContextId::root(),
            op: Some(Operation::FmpUpdate),
            asmop: None,
            stack: [17, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0].to_elements(),
            fmp: next_fmp,
            memory: mem.clone(),
        },
        VmState {
            clk: RowIndex::from(16),
            ctx: ContextId::root(),
            op: Some(Operation::Pad),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    locstore0_loc.clone(),
                    "$exec::foo".to_string(),
                    4,
                    "loc_store.0".to_string(),
                    false,
                ),
                1,
            )),
            stack: [0, 17, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0].to_elements(),
            fmp: next_fmp,
            memory: mem.clone(),
        },
        VmState {
            clk: RowIndex::from(17),
            ctx: ContextId::root(),
            op: Some(Operation::FmpAdd),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    locstore0_loc.clone(),
                    "$exec::foo".to_string(),
                    4,
                    "loc_store.0".to_string(),
                    false,
                ),
                2,
            )),
            stack: [2u64.pow(30) + 1, 17, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0]
                .to_elements(),
            fmp: next_fmp,
            memory: mem,
        },
        VmState {
            clk: RowIndex::from(18),
            ctx: ContextId::root(),
            op: Some(Operation::MStore),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    locstore0_loc.clone(),
                    "$exec::foo".to_string(),
                    4,
                    "loc_store.0".to_string(),
                    false,
                ),
                3,
            )),
            stack: [17, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0].to_elements(),
            fmp: next_fmp,
            memory: vec![(1u32.into(), 13_u32.into()), ((2u32.pow(30) + 1).into(), 17_u32.into())],
        },
        VmState {
            clk: RowIndex::from(19),
            ctx: ContextId::root(),
            op: Some(Operation::Drop),
            asmop: Some(AsmOpInfo::new(
                AssemblyOp::new(
                    locstore0_loc.clone(),
                    "$exec::foo".to_string(),
                    4,
                    "loc_store.0".to_string(),
                    false,
                ),
                4,
            )),
            stack: [12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0].to_elements(),
            fmp: next_fmp,
            memory: vec![(1u32.into(), 13_u32.into()), ((2u32.pow(30) + 1).into(), 17_u32.into())],
        },
        VmState {
            clk: RowIndex::from(20),
            ctx: ContextId::root(),
            op: Some(Operation::Push(Felt::new(18446744069414584320))),
            asmop: None,
            stack: [18446744069414584320, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0]
                .to_elements(),
            fmp: next_fmp,
            memory: vec![(1u32.into(), 13_u32.into()), ((2u32.pow(30) + 1).into(), 17_u32.into())],
        },
        VmState {
            clk: RowIndex::from(21),
            ctx: ContextId::root(),
            op: Some(Operation::FmpUpdate),
            asmop: None,
            stack: [12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0].to_elements(),
            fmp,
            memory: vec![(1u32.into(), 13_u32.into()), ((2u32.pow(30) + 1).into(), 17_u32.into())],
        },
        VmState {
            clk: RowIndex::from(22),
            ctx: ContextId::root(),
            op: Some(Operation::Noop),
            asmop: None,
            stack: [12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0].to_elements(),
            fmp,
            memory: vec![(1u32.into(), 13_u32.into()), ((2u32.pow(30) + 1).into(), 17_u32.into())],
        },
        VmState {
            clk: RowIndex::from(23),
            ctx: ContextId::root(),
            op: Some(Operation::End),
            asmop: None,
            stack: [12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0].to_elements(),
            fmp,
            memory: vec![(1u32.into(), 13_u32.into()), ((2u32.pow(30) + 1).into(), 17_u32.into())],
        },
        VmState {
            clk: RowIndex::from(24),
            ctx: ContextId::root(),
            op: Some(Operation::End),
            asmop: None,
            stack: [12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0].to_elements(),
            fmp,
            memory: vec![(1u32.into(), 13_u32.into()), ((2u32.pow(30) + 1).into(), 17_u32.into())],
        },
    ];
    for (expected, t) in expected_states.iter().zip(traces) {
        let state = t.as_ref().unwrap();
        assert_eq!(*expected, *state);
    }
}
