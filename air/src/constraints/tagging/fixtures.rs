//! Test fixtures for constraint tagging.

use alloc::vec::Vec;

use miden_core::{Felt, field::QuadFelt};

use super::ood_eval::EvalRecord;

/// Seed used for OOD evaluation fixtures.
pub const OOD_SEED: u64 = 0xc0ffee;

/// Expected OOD evaluations for the System+Range group.
///
/// These values are captured from the Rust constraints with seed 0xC0FFEE.
pub fn system_range_expected() -> Vec<EvalRecord> {
    vec![
        EvalRecord {
            id: 0,
            namespace: "system.clk.first_row",
            value: QuadFelt::new([Felt::new(1065013626484053923), Felt::new(0)]),
        },
        EvalRecord {
            id: 1,
            namespace: "system.clk.transition",
            value: QuadFelt::new([Felt::new(5561241394822338942), Felt::new(0)]),
        },
        EvalRecord {
            id: 2,
            namespace: "system.ctx.call_dyncall",
            value: QuadFelt::new([Felt::new(8631524473419082362), Felt::new(0)]),
        },
        EvalRecord {
            id: 3,
            namespace: "system.ctx.syscall",
            value: QuadFelt::new([Felt::new(3242942367983627164), Felt::new(0)]),
        },
        EvalRecord {
            id: 4,
            namespace: "system.ctx.default",
            value: QuadFelt::new([Felt::new(2699910395066589652), Felt::new(0)]),
        },
        EvalRecord {
            id: 5,
            namespace: "system.fn_hash.load",
            value: QuadFelt::new([Felt::new(5171717963692258605), Felt::new(0)]),
        },
        EvalRecord {
            id: 6,
            namespace: "system.fn_hash.load",
            value: QuadFelt::new([Felt::new(8961147296413400172), Felt::new(0)]),
        },
        EvalRecord {
            id: 7,
            namespace: "system.fn_hash.load",
            value: QuadFelt::new([Felt::new(11894020196642675053), Felt::new(0)]),
        },
        EvalRecord {
            id: 8,
            namespace: "system.fn_hash.load",
            value: QuadFelt::new([Felt::new(16889079421217525114), Felt::new(0)]),
        },
        EvalRecord {
            id: 9,
            namespace: "system.fn_hash.preserve",
            value: QuadFelt::new([Felt::new(11909329801663906014), Felt::new(0)]),
        },
        EvalRecord {
            id: 10,
            namespace: "system.fn_hash.preserve",
            value: QuadFelt::new([Felt::new(6717961555159342431), Felt::new(0)]),
        },
        EvalRecord {
            id: 11,
            namespace: "system.fn_hash.preserve",
            value: QuadFelt::new([Felt::new(3950851291570048124), Felt::new(0)]),
        },
        EvalRecord {
            id: 12,
            namespace: "system.fn_hash.preserve",
            value: QuadFelt::new([Felt::new(11146653144264413142), Felt::new(0)]),
        },
        EvalRecord {
            id: 13,
            namespace: "range.main.v.first_row",
            value: QuadFelt::new([Felt::new(1112338059331632069), Felt::new(0)]),
        },
        EvalRecord {
            id: 14,
            namespace: "range.main.v.last_row",
            value: QuadFelt::new([Felt::new(13352757668188868927), Felt::new(0)]),
        },
        EvalRecord {
            id: 15,
            namespace: "range.main.v.transition",
            value: QuadFelt::new([Felt::new(12797082443503681195), Felt::new(0)]),
        },
        EvalRecord {
            id: 16,
            namespace: "range.bus.transition",
            value: QuadFelt::new([
                Felt::new(10365289165200035540),
                Felt::new(16469718665506609592),
            ]),
        },
    ]
}

/// Entry point for the active tagged group in parity tests.
pub fn active_expected_ood_evals() -> Vec<EvalRecord> {
    system_range_expected()
}
