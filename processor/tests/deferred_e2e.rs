//! End-to-end test: drive the three deferred system events through a real `FastProcessor` run
//! via `emit` instructions, then inspect the `DeferredState` accumulated on the advice provider
//! and the extracted witness. Includes a legacy-smoke check that an unrelated `EventHandler`
//! registered on the host still fires alongside the deferred infrastructure.

use alloc::vec::Vec;
use std::sync::Arc;

use miden_assembly::Assembler;
use miden_processor::{
    DefaultHost, ExecutionOptions, FastProcessor, Felt, ProcessorState, StackInputs, Word, ZERO,
    advice::{AdviceInputs, AdviceMutation},
    deferred::{
        DeferredTag, Field0Handler, Payload, TypeHandlerRegistry, binary_op_payload,
        extract_witness, hash_node,
    },
    event::{EventError, EventHandler, EventName},
};

extern crate alloc;

// PROCESSOR FACTORY
// ================================================================================================

/// Builds a `FastProcessor` configured for the deferred-DAG tests with the [`Field0Handler`]
/// registered. The processor consumes itself when running the program.
fn build_processor() -> FastProcessor {
    let mut registry = TypeHandlerRegistry::new();
    registry
        .register(Arc::new(Field0Handler))
        .expect("Field0Handler registration on empty registry");
    FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    )
    .expect("processor construction")
    .with_deferred_registry(Arc::new(registry))
}

// EVENT-DRIVING MASM BUILDER
// ================================================================================================

/// Build a MASM block that pushes the data segment + tag, invokes the sugared deferred keyword,
/// and cleans up the 12 felts left on the operand stack (the keyword itself drops the event ID).
///
/// `data_below_tag` is the 8-felt segment that sits at stack positions 5..13 once the tag is
/// pushed — for a register event it is the payload, for an assert-eq event it is
/// `lhs_digest || rhs_digest`.
fn emit_event(src: &mut String, keyword: &str, tag: [Felt; 4], data_below_tag: [Felt; 8]) {
    use core::fmt::Write;
    // Push payload-equivalent felts in reverse so data_below_tag[0] ends up at position 5 once
    // the tag sits above it.
    for f in data_below_tag.iter().rev() {
        writeln!(src, "    push.{}", f.as_int()).unwrap();
    }
    for f in tag.iter().rev() {
        writeln!(src, "    push.{}", f.as_int()).unwrap();
    }
    writeln!(src, "    {keyword}").unwrap();
    // The sugared keyword lowers to push.<id>; emit; drop, so the event_id is already gone;
    // 12 felts (4 tag + 8 data) remain to be cleaned.
    for _ in 0..12 {
        src.push_str("    drop\n");
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

fn field0_leaf_payload(low: u64) -> Payload {
    let mut limbs = [Felt::from_u32(0); 8];
    limbs[0] = Felt::from_u32(low as u32);
    limbs[1] = Felt::from_u32((low >> 32) as u32);
    Payload::new(limbs)
}

// END-TO-END: (a + b) * c == 35  (with a=3, b=4, c=5)
// ================================================================================================

#[test]
fn deferred_end_to_end_register_eval_assert() {
    // Precompute every digest the program will use. The processor will recompute these via
    // Poseidon2; if anything diverges between Rust and the in-host hash_node helper, the
    // witness check below will catch it.
    let a_payload = field0_leaf_payload(3);
    let b_payload = field0_leaf_payload(4);
    let c_payload = field0_leaf_payload(5);
    let d_payload = field0_leaf_payload(35); // (3 + 4) * 5

    let leaf_tag = DeferredTag::Field0Leaf;
    let add_tag = DeferredTag::Field0Add;
    let mul_tag = DeferredTag::Field0Mul;
    let assert_tag = DeferredTag::Field0AssertEq;

    let a_digest = hash_node(leaf_tag, &a_payload);
    let b_digest = hash_node(leaf_tag, &b_payload);
    let c_digest = hash_node(leaf_tag, &c_payload);
    let d_digest = hash_node(leaf_tag, &d_payload);
    let add_payload = binary_op_payload(a_digest, b_digest);
    let add_digest = hash_node(add_tag, &add_payload);
    let mul_payload = binary_op_payload(add_digest, c_digest);
    let mul_digest = hash_node(mul_tag, &mul_payload);

    // Build the program.
    let mut src = String::from("begin\n");
    for payload in [&a_payload, &b_payload, &c_payload, &d_payload] {
        emit_event(&mut src, "deferred.register_leaf", leaf_tag.to_felts(), payload.0);
    }
    emit_event(&mut src, "deferred.register_op", add_tag.to_felts(), add_payload.0);
    emit_event(&mut src, "deferred.register_op", mul_tag.to_felts(), mul_payload.0);
    let assert_data = digests_concat(mul_digest, d_digest);
    emit_event(&mut src, "deferred.assert_eq", assert_tag.to_felts(), assert_data);
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");

    let mut host = DefaultHost::default();
    let output = build_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    let state = output.advice.deferred_state();
    // Six reachable nodes, one assertion.
    let expected_digests = [a_digest, b_digest, c_digest, d_digest, add_digest, mul_digest];
    for d in expected_digests {
        assert!(state.contains(&d), "missing node for digest {:?}", d);
    }
    assert_eq!(state.assertions().len(), 1);
    let a0 = &state.assertions()[0];
    assert_eq!(a0.lhs, mul_digest);
    assert_eq!(a0.rhs, d_digest);

    // Witness should contain exactly the reachable subgraph, sorted by digest, and the single
    // assertion in insertion order.
    let witness = extract_witness(state);
    assert_eq!(witness.nodes.len(), 6);
    let witness_digests: Vec<_> = witness.nodes.iter().map(|(d, _)| *d).collect();
    assert!(witness_digests.windows(2).all(|p| p[0] < p[1]));
    for d in expected_digests {
        assert!(witness_digests.contains(&d));
    }
    assert_eq!(witness.assertions.len(), 1);
}

fn digests_concat(lhs: Word, rhs: Word) -> [Felt; 8] {
    let mut out = [ZERO; 8];
    out[0..4].copy_from_slice(lhs.as_elements());
    out[4..8].copy_from_slice(rhs.as_elements());
    out
}

// E2E: AssertEq with mismatched values surfaces as an execution error.
// ================================================================================================

#[test]
fn deferred_assert_eq_mismatch_fails_execution() {
    let a_payload = field0_leaf_payload(7);
    let b_payload = field0_leaf_payload(8);
    let leaf_tag = DeferredTag::Field0Leaf;
    let assert_tag = DeferredTag::Field0AssertEq;
    let a_digest = hash_node(leaf_tag, &a_payload);
    let b_digest = hash_node(leaf_tag, &b_payload);

    let mut src = String::from("begin\n");
    emit_event(&mut src, "deferred.register_leaf", leaf_tag.to_felts(), a_payload.0);
    emit_event(&mut src, "deferred.register_leaf", leaf_tag.to_felts(), b_payload.0);
    emit_event(
        &mut src,
        "deferred.assert_eq",
        assert_tag.to_felts(),
        digests_concat(a_digest, b_digest),
    );
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

    // Mix a deferred RegisterLeaf with the legacy event in one program.
    let leaf_tag = DeferredTag::Field0Leaf;
    let payload = field0_leaf_payload(42);

    let mut src = String::from("begin\n");
    // Legacy event: push event_id, emit, drop.
    use core::fmt::Write;
    writeln!(&mut src, "    push.{event_id}").unwrap();
    src.push_str("    emit\n");
    src.push_str("    drop\n");
    // Deferred event right after.
    emit_event(&mut src, "deferred.register_leaf", leaf_tag.to_felts(), payload.0);
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");

    let output =
        build_processor().execute_sync(&program, &mut host).expect("execution must succeed");

    assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(output.advice.deferred_state().nodes().len(), 1);
}
