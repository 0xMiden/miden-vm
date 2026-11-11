use alloc::{string::String, vec::Vec};
use std::collections::BTreeSet;

use miden_core::{Felt, operations::Operation, serde::Deserializable};

use super::{ALL_OPERATIONS, OpHistogram};

/// `ALL_OPERATIONS` must contain exactly the set of opcodes that map to a valid `Operation`.
///
/// We use `Operation`'s `Deserializable` impl as the source of truth.
#[test]
fn all_operations_covers_every_valid_opcode() {
    // The payload-carrying variants (Push, Assert, MpVerify, U32assert2) read an extra `Felt`
    // after the opcode byte, so pad with enough zero bytes for them to deserialize. Trailing
    // bytes are ignored by the reader, so this is harmless for the 1-byte variants.
    let valid: BTreeSet<u8> = (0u8..=u8::MAX)
        .filter(|&op| Operation::read_from_bytes(&[op, 0, 0, 0, 0, 0, 0, 0, 0]).is_ok())
        .collect();

    let ours: BTreeSet<u8> = ALL_OPERATIONS.iter().map(|op| op.op_code()).collect();

    // `ALL_OPERATIONS` holds real `Operation` values, so  `ours ⊆ valid`. The list can
    // therefore only fall out of sync by *missing* a variant.
    let missing_in_ours: Vec<String> = valid
        .difference(&ours)
        .map(|&op| {
            format!(
                "{}",
                Operation::read_from_bytes(&[op, 0, 0, 0, 0, 0, 0, 0, 0])
                    .expect("valid opcode deserializes to an Operation")
            )
        })
        .collect();

    if !missing_in_ours.is_empty() {
        panic!(
            "ALL_OPERATIONS is out of sync with miden-core's Operation enum.\n  missing from \
             ALL_OPERATIONS (add these): {missing_in_ours:?}"
        );
    }
}

#[test]
fn sorted_counts_orders_by_count_desc_then_opcode() {
    let mut hist = OpHistogram::default();

    hist.record(Operation::Add);
    hist.record(Operation::Add);
    hist.record(Operation::Noop);
    hist.record(Operation::Eq);

    let (ops, counts): (Vec<Operation>, Vec<u64>) = hist.sorted_counts().into_iter().unzip();

    // Most frequent op comes first.
    assert_eq!(ops[0], Operation::Add);
    assert_eq!(counts[0], 2);

    // The two single-cycle ops are ordered by opcode, since their counts tie.
    assert_eq!(counts[1], 1);
    assert_eq!(counts[2], 1);
    assert!(ops[1].op_code() < ops[2].op_code());

    // `total_cycles` accounts for every recorded cycle.
    assert_eq!(hist.total_cycles(), 4);
}

#[test]
fn sorted_counts_excludes_unrecorded_operations() {
    let hist = OpHistogram::default();
    assert!(hist.sorted_counts().is_empty());
    assert_eq!(hist.total_cycles(), 0);
}

/// Payload-carrying operations must render with just their mnemonic, e.g. `push` rather than
/// `push(0)`.
#[test]
fn op_histogram_omits_payload_from_mnemonic() {
    let mut hist = OpHistogram::default();

    // All payload carrying variants
    hist.record(Operation::Push(Felt::ZERO));
    hist.record(Operation::Assert(Felt::ZERO));
    hist.record(Operation::MpVerify(Felt::ZERO));
    hist.record(Operation::U32assert2(Felt::ZERO));

    let report = hist.report();

    assert!(
        !report.contains("(0)"),
        "report must not contain placeholder payloads: {report}"
    );
    for mnemonic in ["push", "assert", "mpverify", "u32assert2"] {
        assert!(report.contains(mnemonic), "report missing `{mnemonic}`: {report}");
    }
}
