//! Test fixtures for constraint tagging.

use alloc::vec::Vec;

use miden_core::{Felt, field::QuadFelt};

use super::ood_eval::EvalRecord;

/// Seed used for OOD evaluation fixtures.
pub const OOD_SEED: u64 = 0xc0ffee;

/// Expected OOD evaluations for the current group.
///
/// These values are captured from the Rust constraints with seed 0xC0FFEE.
pub fn current_group_expected() -> Vec<EvalRecord> {
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
            namespace: "stack.general.transition.0",
            value: QuadFelt::new([Felt::new(2617308096902219240), Felt::new(0)]),
        },
        EvalRecord {
            id: 17,
            namespace: "stack.general.transition.1",
            value: QuadFelt::new([Felt::new(4439102810547612775), Felt::new(0)]),
        },
        EvalRecord {
            id: 18,
            namespace: "stack.general.transition.2",
            value: QuadFelt::new([Felt::new(15221140463513662734), Felt::new(0)]),
        },
        EvalRecord {
            id: 19,
            namespace: "stack.general.transition.3",
            value: QuadFelt::new([Felt::new(4910128267170087966), Felt::new(0)]),
        },
        EvalRecord {
            id: 20,
            namespace: "stack.general.transition.4",
            value: QuadFelt::new([Felt::new(8221884229886405628), Felt::new(0)]),
        },
        EvalRecord {
            id: 21,
            namespace: "stack.general.transition.5",
            value: QuadFelt::new([Felt::new(87491100192562680), Felt::new(0)]),
        },
        EvalRecord {
            id: 22,
            namespace: "stack.general.transition.6",
            value: QuadFelt::new([Felt::new(11411892308848385202), Felt::new(0)]),
        },
        EvalRecord {
            id: 23,
            namespace: "stack.general.transition.7",
            value: QuadFelt::new([Felt::new(2425094460891103256), Felt::new(0)]),
        },
        EvalRecord {
            id: 24,
            namespace: "stack.general.transition.8",
            value: QuadFelt::new([Felt::new(2767534397043537043), Felt::new(0)]),
        },
        EvalRecord {
            id: 25,
            namespace: "stack.general.transition.9",
            value: QuadFelt::new([Felt::new(11686523590994044007), Felt::new(0)]),
        },
        EvalRecord {
            id: 26,
            namespace: "stack.general.transition.10",
            value: QuadFelt::new([Felt::new(15000969044032170777), Felt::new(0)]),
        },
        EvalRecord {
            id: 27,
            namespace: "stack.general.transition.11",
            value: QuadFelt::new([Felt::new(17422355615541008592), Felt::new(0)]),
        },
        EvalRecord {
            id: 28,
            namespace: "stack.general.transition.12",
            value: QuadFelt::new([Felt::new(2555448945580115158), Felt::new(0)]),
        },
        EvalRecord {
            id: 29,
            namespace: "stack.general.transition.13",
            value: QuadFelt::new([Felt::new(8864896307613509), Felt::new(0)]),
        },
        EvalRecord {
            id: 30,
            namespace: "stack.general.transition.14",
            value: QuadFelt::new([Felt::new(3997062422665481459), Felt::new(0)]),
        },
        EvalRecord {
            id: 31,
            namespace: "stack.general.transition.15",
            value: QuadFelt::new([Felt::new(6149720027324442163), Felt::new(0)]),
        },
        EvalRecord {
            id: 32,
            namespace: "stack.overflow.depth.first_row",
            value: QuadFelt::new([Felt::new(1820735510664294085), Felt::new(0)]),
        },
        EvalRecord {
            id: 33,
            namespace: "stack.overflow.depth.last_row",
            value: QuadFelt::new([Felt::new(12520055704510454391), Felt::new(0)]),
        },
        EvalRecord {
            id: 34,
            namespace: "stack.overflow.addr.first_row",
            value: QuadFelt::new([Felt::new(9235172344178625178), Felt::new(0)]),
        },
        EvalRecord {
            id: 35,
            namespace: "stack.overflow.addr.last_row",
            value: QuadFelt::new([Felt::new(6001883085148683205), Felt::new(0)]),
        },
        EvalRecord {
            id: 36,
            namespace: "stack.overflow.depth.transition",
            value: QuadFelt::new([Felt::new(6706883717633639596), Felt::new(0)]),
        },
        EvalRecord {
            id: 37,
            namespace: "stack.overflow.flag.transition",
            value: QuadFelt::new([Felt::new(5309566436521762910), Felt::new(0)]),
        },
        EvalRecord {
            id: 38,
            namespace: "stack.overflow.addr.transition",
            value: QuadFelt::new([Felt::new(13739720401332236216), Felt::new(0)]),
        },
        EvalRecord {
            id: 39,
            namespace: "stack.overflow.zero_insert.transition",
            value: QuadFelt::new([Felt::new(15830245309845547857), Felt::new(0)]),
        },
        EvalRecord {
            id: 40,
            namespace: "range.bus.transition",
            value: QuadFelt::new([
                Felt::new(10365289165200035540),
                Felt::new(16469718665506609592),
            ]),
        },
        EvalRecord {
            id: 41,
            namespace: "stack.overflow.bus.transition",
            value: QuadFelt::new([Felt::new(7384164985445418427), Felt::new(3858806565449404456)]),
        },
    ]
}

/// Entry point for the active tagged group in parity tests.
pub fn active_expected_ood_evals() -> Vec<EvalRecord> {
    current_group_expected()
}
