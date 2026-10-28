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

#[test]
fn compress_wire_opcode_is_pinned() {
    assert_eq!(opcodes::COMPRESS, 0x50);
    assert_eq!(Operation::Compress.op_code(), 0x50);
    assert_eq!(Operation::Compress.to_bytes(), [0x50]);
    assert_eq!(Operation::read_from_bytes(&[0x50]).unwrap(), Operation::Compress);
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

// EXHAUSTIVE WIRE SWEEP
// ================================================================================================

/// Drives the `Operation` decoder across the full byte space so every
/// variant's wire form is exercised deterministically. The macro-generated
/// roundtrip test runs 100 hardcoded cases, which by coupon collection
/// exercises only ~57 of the 81 variants in a typical run — this sweep
/// makes per-variant coverage total without depending on sampling luck
/// (no `arbitrary` feature needed; runs in the default suite).
///
/// - Every unit variant decodes from exactly one byte and roundtrips byte-stably (`to_bytes() ==
///   [opcode]`).
/// - Every data-carrying variant errors on a bare opcode (missing payload) and roundtrips
///   byte-stably with a nonzero payload — nonzero per the width-coverage lesson (a truncating
///   reader must not pass).
/// - Every remaining byte is rejected as `InvalidValue` — pinning that no unassigned opcode
///   silently maps to a variant.
///
/// Adding a variant must extend the pinned counts below.
#[test]
fn operation_wire_roundtrip_covers_every_opcode() {
    let mut units: Vec<(u8, Operation)> = Vec::new();
    let mut data_opcodes: Vec<u8> = Vec::new();
    let mut unassigned: u32 = 0;

    for byte in 0u8..=u8::MAX {
        match Operation::read_from_bytes(&[byte]) {
            Ok(op) => {
                assert_eq!(op.to_bytes(), alloc::vec![byte], "unit variant wire form");
                assert_eq!(Operation::read_from_bytes(&op.to_bytes()).unwrap(), op);
                units.push((byte, op));
            },
            // A data-carrying variant: the opcode is valid but the payload
            // is missing.
            Err(DeserializationError::UnexpectedEOF) => data_opcodes.push(byte),
            // An unassigned opcode.
            Err(DeserializationError::InvalidValue(_)) => unassigned += 1,
            Err(other) => panic!("unexpected decode error for byte {byte}: {other}"),
        }
    }

    assert_eq!(units.len(), 77, "unit-variant count changed — extend this sweep");
    assert_eq!(data_opcodes.len(), 4, "data-variant count changed — extend this sweep");
    assert_eq!(unassigned, 175, "unassigned-opcode count changed");

    // Data-carrying variants with a nonzero payload (all four write one
    // Felt): byte-exact roundtrip both ways.
    // The sweep collects them in byte order; pin the SET (each constant
    // present exactly once).
    let mut expected =
        alloc::vec![opcodes::ASSERT, opcodes::MPVERIFY, opcodes::U32ASSERT2, opcodes::PUSH,];
    expected.sort_unstable();
    assert_eq!(data_opcodes, expected);
    for byte in data_opcodes {
        // Full-width payload: nonzero in EVERY byte, so a reader that
        // truncates the payload decodes a different Felt and fails the
        // byte-exact comparison (a payload like [1, 0, ..., 0] would pass
        // under a one-byte-truncating reader: trailing bytes are ignored
        // and re-serialization restores the zeros).
        let payload: Vec<u8> = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08].to_vec();
        let mut bytes: Vec<u8> = alloc::vec![byte];
        bytes.extend_from_slice(&payload);
        let op = Operation::read_from_bytes(&bytes).expect("padded data opcode decodes");
        assert_eq!(op.to_bytes(), bytes, "data variant wire form");
        assert_eq!(Operation::read_from_bytes(&op.to_bytes()).unwrap(), op);

        // Every proper prefix of the wire form must be rejected as
        // UnexpectedEOF — the payload length is load-bearing, not optional.
        for prefix_len in 1..bytes.len() {
            let result = Operation::read_from_bytes(&bytes[..prefix_len]);
            assert!(
                matches!(result, Err(DeserializationError::UnexpectedEOF)),
                "prefix of length {prefix_len} must be rejected as truncated"
            );
        }
    }
}
