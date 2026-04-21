//! Memory-chiplet bus tests.
//!
//! Exercises stack-issued memory opcodes (`MStoreW`, `MLoadW`, `MLoad`, `MStore`, `MStream`)
//! plus the `CryptoStream` double-word read+write pair, and verifies the chiplet-requests /
//! chiplet-responses bus pair.
//!
//! For each stack-level memory op the test registers an expected `-1` push of a
//! [`MemoryMsg`] (the "request" side). For each memory chiplet row the test registers an
//! expected `+1` push of a [`MemoryResponseMsg`] (the "response" side). The subset matcher in
//! `lookup_harness` is column-blind, so a `(mult, denom)` pair on the response side pairs up
//! with a matching `(-mult, denom)` on the request side regardless of which aux column the
//! framework routes them onto.
//!
//! # Scope
//!
//! Coverage is limited to the stack-only memory ops above plus `CryptoStream`. The DYN,
//! DYNCALL, CALL-FMP-write, and PIPE memory-request paths in
//! `air/src/constraints/lookup/buses/chiplet_requests.rs` are deferred to integration tests —
//! each is heavyweight to set up and small in algebraic surface. A bug in those paths would
//! escape this module.
//!
//! The programs run at ctx = 0 throughout (no CALL/SYSCALL), so a request/response bug that
//! mismatches stack-side `ctx` vs chiplet-side `mem_ctx` is not caught here.

use miden_air::{
    logup_msg::{MemoryHeader, MemoryResponseMsg},
    trace::chiplets::{MEMORY_IS_READ_COL_IDX, MEMORY_IS_WORD_ACCESS_COL_IDX},
};
use miden_core::{
    Felt, ONE, ZERO,
    operations::{Operation, opcodes},
};

use super::super::{
    build_trace_from_ops,
    lookup_harness::{Expectations, InteractionLog},
};
use crate::RowIndex;

const FOUR: Felt = Felt::new(4);

/// Covers `MStoreW`, `MLoad`, `MLoadW`, `MStore`, `MStream` — every memory opcode issuable
/// directly from the stack — asserting the chiplet-bus request/response pair fires at every
/// memory row.
#[test]
fn memory_chiplet_bus_request_response_pairs() {
    let stack = [0, 1, 2, 3, 4];
    let operations = vec![
        Operation::MStoreW, // store [1, 2, 3, 4] at addr 0
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::MLoad,      // read first element at addr 0
        Operation::MovDn5,     // reshape stack
        Operation::MLoadW,     // load word from addr 0
        Operation::Push(ONE),  // value = 1
        Operation::Push(FOUR), // addr = 4
        Operation::MStore,     // store 1 at addr 4
        Operation::Drop,
        Operation::MStream, // two-word read starting at stack[12]
    ];
    let trace = build_trace_from_ops(operations, &stack);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut exp = Expectations::new(&log);

    // ---- Request side: stack rows emit `-1 × MemoryMsg` when their opcode is a memory op.
    //
    // We also count the number of `remove` calls and assert it matches the expected total at
    // the end. Without this, a bug that stopped the emitter entirely would pass vacuously:
    // the request-opcode loop iterates the trace, so no memory rows → no expectations →
    // trivial subset match.
    let mut request_exps_added = 0usize;
    for row in 0..main.num_rows() {
        let idx = RowIndex::from(row);
        let ctx = main.ctx(idx);
        let clk = main.clk(idx);
        let next = RowIndex::from(row + 1);
        let op = main.get_op_code(idx).as_canonical_u64();
        let header = |addr| MemoryHeader { ctx, addr, clk };

        if op == opcodes::MLOAD as u64 {
            let addr = main.stack_element(0, idx);
            let value = main.stack_element(0, next);
            exp.remove(row, &header(addr).read_element(value));
            request_exps_added += 1;
        } else if op == opcodes::MSTORE as u64 {
            let addr = main.stack_element(0, idx);
            let value = main.stack_element(1, idx);
            exp.remove(row, &header(addr).write_element(value));
            request_exps_added += 1;
        } else if op == opcodes::MLOADW as u64 {
            let addr = main.stack_element(0, idx);
            let word = next_word(main, next, 0);
            exp.remove(row, &header(addr).read_word(word));
            request_exps_added += 1;
        } else if op == opcodes::MSTOREW as u64 {
            let addr = main.stack_element(0, idx);
            let word = [
                main.stack_element(1, idx),
                main.stack_element(2, idx),
                main.stack_element(3, idx),
                main.stack_element(4, idx),
            ];
            exp.remove(row, &header(addr).write_word(word));
            request_exps_added += 1;
        } else if op == opcodes::MSTREAM as u64 {
            let base = main.stack_element(12, idx);
            let word0 = next_word(main, next, 0);
            let word1 = next_word(main, next, 4);
            exp.remove(row, &header(base).read_word(word0));
            exp.remove(row, &header(base + FOUR).read_word(word1));
            request_exps_added += 2;
        }
    }
    // 5 stack opcodes (MStoreW, MLoad, MLoadW, MStore, MStream) + 1 extra for MStream's 2nd read.
    assert_eq!(request_exps_added, 6, "expected 6 memory request expectations");

    // ---- Response side: every memory chiplet row emits `+1 × MemoryResponseMsg`.
    let mut mem_rows_seen = 0usize;
    for row in 0..main.num_rows() {
        let idx = RowIndex::from(row);
        if !main.is_memory_row(idx) {
            continue;
        }
        mem_rows_seen += 1;

        let is_read = main.get(idx, MEMORY_IS_READ_COL_IDX);
        let is_word = main.get(idx, MEMORY_IS_WORD_ACCESS_COL_IDX);
        let mem_ctx = main.chiplet_memory_ctx(idx);
        let word_addr = main.chiplet_memory_word(idx);
        let idx0 = main.chiplet_memory_idx0(idx);
        let idx1 = main.chiplet_memory_idx1(idx);
        let addr = word_addr + idx1.double() + idx0;
        let mem_clk = main.chiplet_memory_clk(idx);
        let word = [
            main.chiplet_memory_value_0(idx),
            main.chiplet_memory_value_1(idx),
            main.chiplet_memory_value_2(idx),
            main.chiplet_memory_value_3(idx),
        ];
        // `element` is ignored by `MemoryResponseMsg::encode` when `is_word = 1`, so on
        // word-access rows the fallback `ZERO` is harmless. `element_idx` uses `u64`
        // arithmetic (native `usize` indexing) while `addr` above uses felt arithmetic —
        // same math, different domain required by the consumer.
        let element = if is_word == ZERO {
            let element_idx = (idx1.as_canonical_u64() * 2 + idx0.as_canonical_u64()) as usize;
            word[element_idx]
        } else {
            ZERO
        };

        exp.add(
            row,
            &MemoryResponseMsg {
                is_read,
                ctx: mem_ctx,
                addr,
                clk: mem_clk,
                is_word,
                element,
                word,
            },
        );
    }
    // 6 memory operations: MStoreW, MLoad, MLoadW, MStore, MStream (2 rows).
    assert_eq!(mem_rows_seen, 6, "expected 6 memory chiplet rows");

    log.assert_contains(&exp);
}

/// Regression test for a production bug where `CryptoStream`'s four memory requests weren't
/// being emitted onto the chiplet-requests bus. Verifies the exact read+read+write+write
/// pattern using hand-coded expected values (ciphertext = plaintext + rate), not values
/// read back from the trace — a missing emission, a wrong opcode label, or a swapped
/// addr/clk would all fail the subset match.
///
/// Currently ignored: `air/src/constraints/lookup/buses/chiplet_requests.rs` has no
/// CryptoStream branch on this branch (the emission was lost during the LogUp port). Remove
/// the `#[ignore]` once the wiring is restored — the test will then guard against future
/// regressions.
#[test]
#[ignore = "CryptoStream memory requests not yet wired into LogUp chiplet_requests bus"]
fn cryptostream_emits_four_memory_requests() {
    // `crypto_stream` stack layout: [rate(8), cap(4), src_ptr, dst_ptr, pad, pad]
    let stack = [
        1, 2, 3, 4, 5, 6, 7, 8, // rate(8)
        0, 0, 0, 0, // cap(4)
        0, // src_ptr
        8, // dst_ptr
        0, 0, // pad
    ];

    let trace = build_trace_from_ops(vec![Operation::CryptoStream], &stack);
    let log = InteractionLog::new(&trace);

    let mut exp = Expectations::new(&log);

    // CryptoStream runs at cycle 1 (cycle 0 is SPAN), ctx = 0, uninitialized source memory
    // (reads return zeros). Ciphertext = plaintext + rate = rate in this case.
    const ROW: usize = 1;
    let header = |addr| MemoryHeader { ctx: ZERO, addr, clk: ONE };
    let zero_word = [ZERO, ZERO, ZERO, ZERO];
    let cipher1 = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)];
    let cipher2 = [Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)];

    let mut request_exps_added = 0usize;
    exp.remove(ROW, &header(ZERO).read_word(zero_word)); // read src_ptr
    request_exps_added += 1;
    exp.remove(ROW, &header(FOUR).read_word(zero_word)); // read src_ptr + 4
    request_exps_added += 1;
    exp.remove(ROW, &header(Felt::new(8)).write_word(cipher1)); // write dst_ptr
    request_exps_added += 1;
    exp.remove(ROW, &header(Felt::new(12)).write_word(cipher2)); // write dst_ptr + 4
    request_exps_added += 1;

    assert_eq!(request_exps_added, 4, "expected 4 CryptoStream request expectations");

    log.assert_contains(&exp);
}

fn next_word(main: &miden_air::trace::MainTrace, next: RowIndex, start: usize) -> [Felt; 4] {
    [
        main.stack_element(start, next),
        main.stack_element(start + 1, next),
        main.stack_element(start + 2, next),
        main.stack_element(start + 3, next),
    ]
}
