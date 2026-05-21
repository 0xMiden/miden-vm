//! End-to-end test: drive the `adv.register_deferred` keyword through a real `FastProcessor`
//! run, then inspect the `DeferredState` accumulated on the advice provider and the extracted
//! witness. Includes a legacy-smoke check that an unrelated `EventHandler` registered on the
//! host still fires alongside the deferred infrastructure.

use alloc::vec::Vec;
use std::sync::Arc;

use miden_assembly::Assembler;
use miden_core::{
    deferred::{Node, Payload, TRUE_DIGEST, Tag},
    testing::precompile::{Hash, Uint},
};
use miden_processor::{
    DefaultHost, ExecutionOptions, FastProcessor, Felt, ProcessorState, StackInputs,
    advice::{AdviceInputs, AdviceMutation},
    event::{EventError, EventHandler, EventName},
};

extern crate alloc;

// PROCESSOR FACTORY
// ================================================================================================

/// Builds a `FastProcessor` configured for the deferred-DAG tests with [`Uint`] installed. The
/// processor consumes itself when running the program.
fn build_processor() -> FastProcessor {
    FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    )
    .expect("processor construction")
    .with_precompile(Uint)
}

// MASM BUILDERS
// ================================================================================================

/// Build a MASM block that pushes the 4-felt tag then the 8-felt payload, invokes the
/// `adv.register_deferred` keyword, and cleans up the 12 felts left on the operand stack.
/// Also discards the NODE_DIGEST that `adv.register_deferred` pushes onto the advice stack —
/// tests that want to consume the digest should build their MASM inline rather than going
/// through this helper.
fn emit_register(src: &mut String, node: Node) {
    push_node(src, node);
    src.push_str("    adv.register_deferred\n");
    for _ in 0..12 {
        src.push_str("    drop\n");
    }
    // Pop the advice-pushed NODE_DIGEST so subsequent advice consumers see a clean stack.
    src.push_str("    adv_pushw\n");
    src.push_str("    dropw\n");
}

/// Build a MASM block that pushes the node's digest and invokes `adv.evaluate_deferred`, then
/// drops the input digest. `evaluate_deferred` pushes the canonical digest to advice and records
/// the canonical in the advice map keyed by that canonical digest; this helper just drives the
/// evaluation for its side effects (verifying a predicate / surfacing an error). Tests inspect the
/// recorded entry via `output.advice`.
///
/// The node MUST already be interned in `DeferredState`.
fn emit_evaluate_for_side_effect(src: &mut String, node: Node) {
    push_digest(src, node.digest());
    src.push_str("    adv.evaluate_deferred\n");
    for _ in 0..4 {
        src.push_str("    drop\n");
    }
}

/// Push a 4-felt digest onto the operand stack, deepest felt first so the top is `digest[0]`.
fn push_digest(src: &mut String, digest: miden_core::Word) {
    use core::fmt::Write;
    for f in digest.as_elements().iter().rev() {
        writeln!(src, "    push.{}", f.as_int()).unwrap();
    }
}

fn push_node(src: &mut String, node: Node) {
    use core::fmt::Write;
    // Push tag first (its 4 felts end up deepest), then payload (8 felts on top), so the stack
    // layout under `event_id` becomes [PAYLOAD_LO, PAYLOAD_HI, TAG] — the Poseidon2 sponge layout
    // used by `Node::digest`.
    for f in node.tag.as_word().iter().rev() {
        writeln!(src, "    push.{}", f.as_int()).unwrap();
    }
    let payload = node.payload.as_felts().expect("push_node only handles expression-bodied nodes");
    for f in payload.iter().rev() {
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

fn arith_leaf(low: u64) -> Node {
    let mut limbs = [0u32; 8];
    limbs[0] = low as u32;
    limbs[1] = (low >> 32) as u32;
    Uint::leaf_node(limbs)
}

// END-TO-END: (a + b) * c == 35  (with a=3, b=4, c=5)
// ================================================================================================

#[test]
fn deferred_end_to_end_register_eval_assert() {
    // Precompute every node and digest the program will use.
    let a = arith_leaf(3);
    let b = arith_leaf(4);
    let c = arith_leaf(5);
    let d = arith_leaf(35); // (3 + 4) * 5

    let a_digest = a.digest();
    let b_digest = b.digest();
    let c_digest = c.digest();
    let d_digest = d.digest();
    let add = Node::join(Uint::add_tag(), a_digest, b_digest);
    let add_digest = add.digest();
    let mul = Node::join(Uint::mul_tag(), add_digest, c_digest);
    let mul_digest = mul.digest();
    // Predicate node: same shape as a binary op (expression body, two child digests), just with
    // ASSERT_EQ as the tag.
    let assertion = Node::join(Uint::eq_tag(), mul_digest, d_digest);

    // Build the program: register every node, then evaluate the predicate to verify it.
    let mut src = String::from("begin\n");
    for n in [a, b, c, d] {
        emit_register(&mut src, n);
    }
    emit_register(&mut src, add);
    emit_register(&mut src, mul);
    emit_register(&mut src, assertion.clone());
    emit_evaluate_for_side_effect(&mut src, assertion.clone());
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");

    let mut host = DefaultHost::default();
    let output = build_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    let state = &output.deferred_state;
    // Six reachable expression nodes, plus the predicate node, all interned by register.
    let expected_digests = [a_digest, b_digest, c_digest, d_digest, add_digest, mul_digest];
    for digest in expected_digests {
        assert!(state.contains(&digest), "missing node for digest {digest:?}");
    }
    assert!(state.contains(&assertion.digest()), "predicate node must be interned");

    // The transcript root stays at the TRUE sentinel until `log` advances it.
    assert_eq!(state.root(), TRUE_DIGEST);

    // `state.nodes` stores registered nodes and canonicals computed during evaluation.
    // This run evaluates one predicate over (a+b)*c and interns canonical(add)=leaf(7)
    // plus canonical(predicate)=TRUE in addition to the 7 registered nodes.
    assert_eq!(state.nodes().len(), 9);
    for d in expected_digests {
        assert!(state.contains(&d));
    }
    assert!(state.contains(&assertion.digest()));
    assert_eq!(state.root(), TRUE_DIGEST);
}

// E2E: adv.evaluate_deferred records the canonical (tag || payload) in the advice map.
// ================================================================================================

#[test]
fn deferred_evaluate_records_canonical_in_advice_map() {
    // Register two leaves a=3 and b=4, then ask `adv.evaluate_deferred` for the canonical form of
    // (a + b). The canonical (leaf 7) must be recorded in the advice map under the canonical
    // digest, serialized as `tag || payload`.
    let a = arith_leaf(3);
    let b = arith_leaf(4);
    let add = Node::join(Uint::add_tag(), a.digest(), b.digest());

    let mut src = String::from("begin\n");
    emit_register(&mut src, a);
    emit_register(&mut src, b);
    emit_register(&mut src, add.clone());
    emit_evaluate_for_side_effect(&mut src, add);
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");

    let mut host = DefaultHost::default();
    let output = build_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    // The canonical of (3 + 4) is leaf 7. Its advice-map value is `tag || payload`.
    let canonical = arith_leaf(7);
    let canonical_digest = canonical.digest();
    let mut expected: Vec<Felt> = canonical.tag.as_word().to_vec();
    expected.extend_from_slice(canonical.payload.as_felts().unwrap());

    let recorded = output
        .advice
        .get_mapped_values(&canonical_digest)
        .expect("evaluate must record the canonical under canonical digest");
    assert_eq!(recorded, expected.as_slice(), "advice map must hold canonical `tag || payload`");
}

// E2E: evaluating a predicate records the TRUE node — no special-casing of predicates.
// ================================================================================================

#[test]
fn deferred_evaluate_records_true_node_for_predicate() {
    // Register one leaf, build a self-equal predicate (a == a), evaluate it. The predicate must
    // verify successfully, and its canonical (the TRUE node) is recorded in the advice map under
    // the TRUE node's digest — uniform with every other node shape.
    let a = arith_leaf(7);
    let a_eq_a = Node::join(Uint::eq_tag(), a.digest(), a.digest());

    let mut src = String::from("begin\n");
    emit_register(&mut src, a);
    emit_register(&mut src, a_eq_a.clone());
    emit_evaluate_for_side_effect(&mut src, a_eq_a);
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");

    let mut host = DefaultHost::default();
    let output = build_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    // The TRUE node serializes to its 12 felts (zero tag || zero payload) like any expression.
    let mut expected: Vec<Felt> = Node::TRUE.tag.as_word().to_vec();
    expected.extend_from_slice(Node::TRUE.payload.as_felts().unwrap());

    let recorded = output
        .advice
        .get_mapped_values(&Node::TRUE.digest())
        .expect("evaluate must record the TRUE node under the TRUE digest");
    assert_eq!(recorded, expected.as_slice(), "predicate canonical must be the TRUE node felts");
}

// E2E: a predicate is just a host hint — `adv.register_deferred` does NOT verify it. The
// mismatch only surfaces when the program explicitly evaluates the predicate.
// ================================================================================================

#[test]
fn deferred_register_predicate_does_not_verify() {
    let a = arith_leaf(7);
    let b = arith_leaf(8);
    let mismatch = Node::join(Uint::eq_tag(), a.digest(), b.digest());

    // Just register — execution must succeed because register is a pure host hint.
    let mut src = String::from("begin\n");
    emit_register(&mut src, a);
    emit_register(&mut src, b);
    emit_register(&mut src, mismatch.clone());
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");
    let mut host = DefaultHost::default();
    let output = build_processor()
        .execute_sync(&program, &mut host)
        .expect("register-only execution must succeed even with a bad predicate");
    assert!(output.deferred_state.contains(&mismatch.digest()));
}

#[test]
fn deferred_evaluate_predicate_mismatch_fails_execution() {
    let a = arith_leaf(7);
    let b = arith_leaf(8);
    let mismatch = Node::join(Uint::eq_tag(), a.digest(), b.digest());

    let mut src = String::from("begin\n");
    emit_register(&mut src, a);
    emit_register(&mut src, b);
    emit_register(&mut src, mismatch.clone());
    emit_evaluate_for_side_effect(&mut src, mismatch);
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");

    let mut host = DefaultHost::default();
    let result = build_processor().execute_sync(&program, &mut host);
    assert!(result.is_err(), "evaluating a mismatched predicate must fail execution");
}

// E2E: adv.register_deferred pushes the registered node's digest onto the advice stack.
// ================================================================================================

#[test]
fn deferred_register_pushes_node_digest_to_advice() {
    // Register a leaf, then pull the advice-pushed digest into memory and assert it matches the
    // node's content-addressed digest.
    let leaf = arith_leaf(42);
    let expected = leaf.digest();

    let mut src = String::from("begin\n");
    push_node(&mut src, leaf);
    src.push_str("    adv.register_deferred\n");
    for _ in 0..12 {
        src.push_str("    drop\n");
    }
    // Pull the NODE_DIGEST off advice and stash to memory[0..4].
    src.push_str("    adv_pushw\n");
    src.push_str("    mem_storew_le.0\n");
    src.push_str("    dropw\n");
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");
    let mut host = DefaultHost::default();
    let output = build_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    let ctx = 0u32.into();
    let observed: [Felt; 4] = core::array::from_fn(|i| {
        output.memory.read_element(ctx, Felt::from_u32(i as u32)).expect("memory read")
    });
    assert_eq!(observed, *expected.as_elements(), "register must push the node's digest");
}

#[test]
fn deferred_evaluate_pushes_canonical_digest_to_operand() {
    // Register a=3, b=4 and add=(a+b). Evaluate add, then move the advice-pushed
    // CANONICAL_DIGEST to the operand stack (`adv.evaluate_deferred; dropw; adv_pushw`) and
    // store it in memory to assert it equals digest(leaf 7).
    let a = arith_leaf(3);
    let b = arith_leaf(4);
    let add = Node::join(Uint::add_tag(), a.digest(), b.digest());
    let expected = arith_leaf(7).digest();

    let mut src = String::from("begin\n");
    emit_register(&mut src, a);
    emit_register(&mut src, b);
    emit_register(&mut src, add.clone());
    push_digest(&mut src, add.digest());
    src.push_str("    adv.evaluate_deferred\n");
    src.push_str("    dropw\n");
    src.push_str("    adv_pushw\n");
    src.push_str("    mem_storew_le.0\n");
    src.push_str("    dropw\n");
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");
    let mut host = DefaultHost::default();
    let output = build_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    let ctx = 0u32.into();
    let observed: [Felt; 4] = core::array::from_fn(|i| {
        output.memory.read_element(ctx, Felt::from_u32(i as u32)).expect("memory read")
    });
    assert_eq!(observed, *expected.as_elements(), "evaluate must push canonical digest");
}

#[test]
fn deferred_register_chunk_pushes_node_digest_to_advice() {
    use core::fmt::Write;
    // Lay out one 8-felt chunk in memory at addresses 0..8, register the chunk node, then pull
    // the advice-pushed digest into memory[8..12] and assert it equals the chunk node's digest.
    let chunk: [Felt; 8] = core::array::from_fn(|i| Felt::from_u32(101 + i as u32));
    let tag = preimage_tag(1);
    let expected = Node::chunk(tag, vec![chunk]).digest();

    let mut src = String::from("begin\n");
    for (i, felt) in chunk.iter().enumerate() {
        writeln!(&mut src, "    push.{}", felt.as_canonical_u64()).unwrap();
        writeln!(&mut src, "    mem_store.{}", i as u32).unwrap();
    }
    writeln!(&mut src, "    push.{}", 0u32).unwrap(); // ptr
    for f in tag.as_word().iter().rev() {
        writeln!(&mut src, "    push.{}", f.as_canonical_u64()).unwrap();
    }
    src.push_str("    adv.register_deferred_chunk\n");
    for _ in 0..5 {
        src.push_str("    drop\n");
    }
    src.push_str("    adv_pushw\n");
    src.push_str("    mem_storew_le.8\n");
    src.push_str("    dropw\n");
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");
    let mut host = DefaultHost::default();
    let output = build_chunk_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    let ctx = 0u32.into();
    let observed: [Felt; 4] = core::array::from_fn(|i| {
        output
            .memory
            .read_element(ctx, Felt::from_u32(8 + i as u32))
            .expect("memory read")
    });
    assert_eq!(observed, *expected.as_elements(), "register_chunk must push the node's digest");
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

    let leaf = arith_leaf(42);

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

    let output = build_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(output.deferred_state.nodes().len(), 1);
}

// CHUNK REGISTER E2E
// ================================================================================================
//
// Drives `adv.register_deferred_chunk` against the [`Hash`] chunk precompile.

/// Tag for an `n`-chunk `Hash` preimage. `Hash` derives the chunk count from a byte length, so a
/// chunk count of `n` is requested as `n * BYTES_PER_CHUNK` bytes.
fn preimage_tag(n: u32) -> Tag {
    Hash::preimage_tag(n * Hash::BYTES_PER_CHUNK)
}

fn build_chunk_processor() -> FastProcessor {
    FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    )
    .expect("processor construction")
    .with_precompile(Hash)
}

#[test]
fn chunk_register_reads_bulk_data_from_memory_and_interns_node() {
    use core::fmt::Write;

    // Lay out two 8-felt chunks in MASM memory starting at address 0:
    //   chunk 0: limbs (1, 2, 3, 4, 5, 6, 7, 8)
    //   chunk 1: limbs (9, 10, 11, 12, 13, 14, 15, 16)
    let chunks: Vec<[Felt; 8]> = (0..2u32)
        .map(|i| core::array::from_fn(|j| Felt::from_u32(1 + i * 8 + j as u32)))
        .collect();
    let tag = preimage_tag(2);
    let ptr: u32 = 0;
    let expected_digest = Node::chunk(tag, chunks.clone()).digest();

    // MASM: write the 16 felts to memory at addresses 0..16, then push (ptr, TAG, deepest-first)
    // and invoke `adv.register_deferred_chunk`. After the event, drop the 5 felts left on the
    // operand stack.
    let mut src = String::from("begin\n");
    for (i, felt) in chunks.iter().flatten().enumerate() {
        writeln!(&mut src, "    push.{}", felt.as_canonical_u64()).unwrap();
        writeln!(&mut src, "    mem_store.{}", ptr + i as u32).unwrap();
    }
    // Push ptr, then tag (deepest first so tag[0] ends up on top under event_id).
    writeln!(&mut src, "    push.{ptr}").unwrap();
    for f in tag.as_word().iter().rev() {
        writeln!(&mut src, "    push.{}", f.as_canonical_u64()).unwrap();
    }
    src.push_str("    adv.register_deferred_chunk\n");
    for _ in 0..5 {
        src.push_str("    drop\n");
    }
    // Discard the advice-pushed NODE_DIGEST so any later advice consumer sees a clean stack.
    src.push_str("    adv_pushw\n");
    src.push_str("    dropw\n");
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");

    let mut host = DefaultHost::default();
    let output = build_chunk_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    let state = &output.deferred_state;
    assert!(
        state.contains(&expected_digest),
        "chunk node must be stored under its linear-hash digest"
    );
    let stored = state.get(&expected_digest).expect("chunk node lookup");
    match &stored.payload {
        Payload::Chunk(c) => {
            assert_eq!(c.as_ref(), chunks.as_slice(), "bulk data must match memory contents")
        },
        Payload::Expression(_) => panic!("expected chunk variant in deferred state"),
    }
    assert_eq!(stored.tag, tag);
}

#[test]
fn chunk_register_rejects_unaligned_pointer() {
    use core::fmt::Write;
    let tag = preimage_tag(1);
    let ptr: u32 = 1; // not word-aligned

    let mut src = String::from("begin\n");
    writeln!(&mut src, "    push.{ptr}").unwrap();
    for f in tag.as_word().iter().rev() {
        writeln!(&mut src, "    push.{}", f.as_canonical_u64()).unwrap();
    }
    src.push_str("    adv.register_deferred_chunk\n");
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");
    let mut host = DefaultHost::default();
    let result = build_chunk_processor().execute_sync(&program, &mut host);
    assert!(result.is_err(), "unaligned ptr must surface as an execution error");
}

#[test]
fn chunk_register_with_zero_chunks_still_interns_a_node() {
    // n=0 — no memory reads. The digest still depends on the tag (one permutation runs even
    // for empty chunks), so the resulting node lives in the state map.
    use core::fmt::Write;
    let tag = preimage_tag(0);
    let ptr: u32 = 0;
    let expected_digest = Node::chunk(tag, vec![]).digest();

    let mut src = String::from("begin\n");
    writeln!(&mut src, "    push.{ptr}").unwrap();
    for f in tag.as_word().iter().rev() {
        writeln!(&mut src, "    push.{}", f.as_canonical_u64()).unwrap();
    }
    src.push_str("    adv.register_deferred_chunk\n");
    for _ in 0..5 {
        src.push_str("    drop\n");
    }
    // Discard the advice-pushed NODE_DIGEST.
    src.push_str("    adv_pushw\n");
    src.push_str("    dropw\n");
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");
    let mut host = DefaultHost::default();
    let output = build_chunk_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");
    assert!(output.deferred_state.contains(&expected_digest));
}
