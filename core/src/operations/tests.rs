use alloc::vec::Vec;

use proptest::prelude::*;

use crate::{
    mast::arbitrary::op_non_control_strategy,
    operations::{Operation, opcodes},
    serde::{Deserializable, DeserializationError, Serializable, SliceReader},
};

/// Operation kind used for joint opcode strategies (test-only).
#[derive(Clone, Debug)]
enum OpKind {
    Basic(Operation),
    ControlFlow(u8),
}

/// Strategy for control-flow opcodes (not representable as `Operation`).
fn op_control_flow_opcode_strategy() -> impl Strategy<Value = u8> {
    prop_oneof![
        Just(opcodes::JOIN),
        Just(opcodes::SPLIT),
        Just(opcodes::LOOP),
        Just(opcodes::CALL),
        Just(opcodes::DYN),
        Just(opcodes::DYNCALL),
        Just(opcodes::SYSCALL),
        Just(opcodes::SPAN),
        Just(opcodes::END),
        Just(opcodes::REPEAT),
        Just(opcodes::RESPAN),
        Just(opcodes::HALT),
    ]
}

/// Strategy selecting either a basic-block operation or a control-flow opcode.
fn op_any_opcode_strategy() -> impl Strategy<Value = OpKind> {
    prop_oneof![
        op_non_control_strategy().prop_map(OpKind::Basic),
        op_control_flow_opcode_strategy().prop_map(OpKind::ControlFlow),
    ]
}

proptest! {
    #[test]
    fn control_flow_opcodes_are_rejected(kind in op_any_opcode_strategy()) {
        match kind {
            OpKind::Basic(op) => {
                let mut bytes = Vec::new();
                op.write_into(&mut bytes);
                let mut reader = SliceReader::new(&bytes);
                let decoded = Operation::read_from(&mut reader).expect("basic op must deserialize");
                prop_assert_eq!(decoded, op);
            },
            OpKind::ControlFlow(opcode) => {
                let bytes = [opcode];
                let mut reader = SliceReader::new(&bytes);
                let result = Operation::read_from(&mut reader);
                prop_assert!(matches!(result, Err(DeserializationError::InvalidValue(_))));
            },
        }
    }
}
