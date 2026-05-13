//! End-to-end test: drive the unified `deferred_register` keyword through a real `FastProcessor`
//! run, then inspect the `DeferredState` accumulated on the advice provider and the extracted
//! witness. Includes a legacy-smoke check that an unrelated `EventHandler` registered on the
//! host still fires alongside the deferred infrastructure.

use alloc::vec::Vec;
use std::sync::Arc;

use miden_assembly::Assembler;
use miden_core::{Word, ZERO};
use miden_processor::{
    DefaultHost, ExecutionOptions, FastProcessor, Felt, ProcessorState, StackInputs,
    advice::{AdviceInputs, AdviceMutation},
    deferred::{Field0Handler, Node, Payload},
    event::{EventError, EventHandler, EventName},
};

extern crate alloc;

// PROCESSOR FACTORY
// ================================================================================================

/// Builds a `FastProcessor` configured for the deferred-DAG tests with the [`Field0Handler`]
/// installed as the schema. The processor consumes itself when running the program.
fn build_processor() -> FastProcessor {
    FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    )
    .expect("processor construction")
    .with_schema(Box::new(Field0Handler))
}

// MASM BUILDERS
// ================================================================================================

/// Build a MASM block that pushes the 8-felt payload then the 4-felt tag, invokes the unified
/// `deferred_register` keyword, and cleans up the 12 felts left on the operand stack.
fn emit_register(src: &mut String, node: Node) {
    push_node(src, node);
    src.push_str("    deferred_register\n");
    for _ in 0..12 {
        src.push_str("    drop\n");
    }
}

/// Build a MASM block that pushes the node, invokes `deferred_evaluate`, drops the 12 input
/// felts, and pulls the canonical 12 felts off the advice stack into memory starting at
/// `out_base` so the test can inspect them via `output.memory`.
fn emit_evaluate_into_mem(src: &mut String, node: Node, out_base: u32) {
    use core::fmt::Write;
    push_node(src, node);
    src.push_str("    deferred_evaluate\n");
    for _ in 0..12 {
        src.push_str("    drop\n");
    }
    // Advice stack: tag word (top) || payload first half || payload second half. Pull each
    // word and write to memory in order.
    for word_idx in 0..3u32 {
        src.push_str("    adv_pushw\n");
        writeln!(src, "    mem_storew_le.{}", out_base + word_idx * 4).unwrap();
        src.push_str("    dropw\n");
    }
}

fn push_node(src: &mut String, node: Node) {
    use core::fmt::Write;
    for f in node.payload.0.iter().rev() {
        writeln!(src, "    push.{}", f.as_int()).unwrap();
    }
    for f in node.tag.iter().rev() {
        writeln!(src, "    push.{}", f.as_int()).unwrap();
    }
}

trait FeltExt {
    fn as_int(&self) -> u64;
}
impl FeltExt for Felt {
    fn as_int(&self) -> u64 {
        self.as_canonical_u64()
    }
}

// FIELD0 LEAF HELPER
// ================================================================================================

fn field0_leaf(low: u64) -> Node {
    let mut limbs = [Felt::from_u32(0); 8];
    limbs[0] = Felt::from_u32(low as u32);
    limbs[1] = Felt::from_u32((low >> 32) as u32);
    Node::new(Field0Handler::LEAF, Payload::new(limbs))
}

// END-TO-END: (a + b) * c == 35  (with a=3, b=4, c=5)
// ================================================================================================

#[test]
fn deferred_end_to_end_register_eval_assert() {
    // Precompute every node and digest the program will use.
    let a = field0_leaf(3);
    let b = field0_leaf(4);
    let c = field0_leaf(5);
    let d = field0_leaf(35); // (3 + 4) * 5

    let a_digest = a.digest();
    let b_digest = b.digest();
    let c_digest = c.digest();
    let d_digest = d.digest();
    let add = Node::new(Field0Handler::ADD, Payload::binary_op(a_digest, b_digest));
    let add_digest = add.digest();
    let mul = Node::new(Field0Handler::MUL, Payload::binary_op(add_digest, c_digest));
    let mul_digest = mul.digest();
    let assertion =
        Node::new(Field0Handler::ASSERT_EQ, Payload::binary_op(mul_digest, d_digest));

    // Build the program.
    let mut src = String::from("begin\n");
    for n in [a, b, c, d] {
        emit_register(&mut src, n);
    }
    emit_register(&mut src, add);
    emit_register(&mut src, mul);
    emit_register(&mut src, assertion);
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");

    let mut host = DefaultHost::default();
    let output = build_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    let state = output.advice.deferred_state();
    // Six reachable expression nodes, one assertion node.
    let expected_digests = [a_digest, b_digest, c_digest, d_digest, add_digest, mul_digest];
    for digest in expected_digests {
        assert!(state.contains(&digest), "missing node for digest {:?}", digest);
    }
    assert_eq!(state.assertions().len(), 1);
    let a0 = &state.assertions()[0];
    let lhs = Word::new([a0.payload.0[0], a0.payload.0[1], a0.payload.0[2], a0.payload.0[3]]);
    let rhs = Word::new([a0.payload.0[4], a0.payload.0[5], a0.payload.0[6], a0.payload.0[7]]);
    assert_eq!(lhs, mul_digest);
    assert_eq!(rhs, d_digest);

    // Transcript must be non-zero and equal to the manual fold over the assertion's digest.
    let expected_transcript =
        miden_core::crypto::hash::Poseidon2::merge(&[Word::new([ZERO; 4]), a0.digest()]);
    assert_eq!(state.transcript(), expected_transcript);
    assert_ne!(state.transcript(), Word::new([ZERO; 4]));

    // Witness includes every registered expression node + the assertion + the transcript.
    let witness = state.extract_witness();
    assert_eq!(witness.nodes.len(), 6);
    let witness_digests: Vec<_> = witness.nodes.iter().map(|(d, _)| *d).collect();
    assert!(witness_digests.windows(2).all(|p| p[0] < p[1]));
    for d in expected_digests {
        assert!(witness_digests.contains(&d));
    }
    assert_eq!(witness.assertions.len(), 1);
    assert_eq!(witness.transcript, expected_transcript);
}

// E2E: deferred_evaluate pushes the canonical (tag, payload) onto the advice stack.
// ================================================================================================

#[test]
fn deferred_evaluate_pushes_canonical_form_to_advice() {
    // Register two leaves a=3 and b=4, then ask `deferred_evaluate` for the canonical form of
    // (a + b). Confirm the advice-pop yields a leaf node with payload limb0 = 7.
    let a = field0_leaf(3);
    let b = field0_leaf(4);
    let add = Node::new(Field0Handler::ADD, Payload::binary_op(a.digest(), b.digest()));

    let mut src = String::from("begin\n");
    emit_register(&mut src, a);
    emit_register(&mut src, b);
    emit_evaluate_into_mem(&mut src, add, 0);
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");

    let mut host = DefaultHost::default();
    let output = build_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    // Memory layout: addresses 0..4 hold the canonical tag (Field0Handler::LEAF), 4..12 hold the
    // canonical payload (a 256-bit u32-limbed integer of value 7).
    let ctx = 0u32.into();
    let mut mem = [Felt::from_u32(0); 12];
    for i in 0..12u32 {
        mem[i as usize] = output
            .memory
            .read_element(ctx, Felt::from_u32(i))
            .expect("memory read");
    }
    let canonical_tag = [mem[0], mem[1], mem[2], mem[3]];
    assert_eq!(canonical_tag, Field0Handler::LEAF, "evaluate returns canonical leaf tag");
    assert_eq!(mem[4].as_canonical_u64(), 7, "limb 0 of (3+4)");
    for (limb_idx, felt) in mem.iter().enumerate().skip(5) {
        assert_eq!(felt.as_canonical_u64(), 0, "limb {} of (3+4) must be zero", limb_idx - 4);
    }
}

// E2E: assert_eq with mismatched values surfaces as an execution error.
// ================================================================================================

#[test]
fn deferred_assert_eq_mismatch_fails_execution() {
    let a = field0_leaf(7);
    let b = field0_leaf(8);
    let mismatch =
        Node::new(Field0Handler::ASSERT_EQ, Payload::binary_op(a.digest(), b.digest()));

    let mut src = String::from("begin\n");
    emit_register(&mut src, a);
    emit_register(&mut src, b);
    emit_register(&mut src, mismatch);
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");

    let mut host = DefaultHost::default();
    let result = build_processor().execute_sync(&program, &mut host);
    assert!(result.is_err(), "mismatched assert_eq must fail execution");
}

// LEGACY SMOKE: registered EventHandler still works alongside the deferred infrastructure.
// ================================================================================================

struct CountingHandler {
    counter: Arc<std::sync::atomic::AtomicUsize>,
}

impl EventHandler for CountingHandler {
    fn on_event(&self, _process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        self.counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Vec::new())
    }
}

#[test]
fn legacy_event_handler_still_works_with_deferred_infrastructure() {
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut host = DefaultHost::default();
    let event = EventName::new("test::legacy_counter");
    let event_id = event.to_event_id().as_u64();
    host.register_handler(event, Arc::new(CountingHandler { counter: counter.clone() }))
        .expect("registration");

    let leaf = field0_leaf(42);

    let mut src = String::from("begin\n");
    // Legacy event: push event_id, emit, drop.
    use core::fmt::Write;
    writeln!(&mut src, "    push.{event_id}").unwrap();
    src.push_str("    emit\n");
    src.push_str("    drop\n");
    // Deferred event right after.
    emit_register(&mut src, leaf);
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");

    let output =
        build_processor().execute_sync(&program, &mut host).expect("execution must succeed");

    assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(output.advice.deferred_state().nodes().len(), 1);
}
