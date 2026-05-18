//! End-to-end test: drive the `adv.register_deferred` keyword through a real `FastProcessor`
//! run, then inspect the `DeferredState` accumulated on the advice provider and the extracted
//! witness. Includes a legacy-smoke check that an unrelated `EventHandler` registered on the
//! host still fires alongside the deferred infrastructure.

use alloc::vec::Vec;
use std::sync::Arc;

use miden_assembly::Assembler;
use miden_core::{
    ZERO,
    deferred::{
        Node, NodePayload, NodeType, Payload, ReduceCtx, Schema, SchemaError, TRUE_DIGEST, Tag,
        TagInfo, Uint256,
    },
};
use miden_processor::{
    DefaultHost, ExecutionOptions, FastProcessor, Felt, ProcessorState, StackInputs,
    advice::{AdviceInputs, AdviceMutation},
    event::{EventError, EventHandler, EventName},
};

extern crate alloc;

// PROCESSOR FACTORY
// ================================================================================================

/// Builds a `FastProcessor` configured for the deferred-DAG tests with [`Uint256`] installed as
/// the schema. The processor consumes itself when running the program.
fn build_processor() -> FastProcessor {
    FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    )
    .expect("processor construction")
    .with_schema(Arc::new(Uint256))
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

/// Build a MASM block that pushes the node's digest (4 felts), invokes `adv.evaluate_deferred`,
/// drops the 4 input felts, and pulls the canonical 12 felts off the advice stack into memory
/// starting at `out_base` so the test can inspect them via `output.memory`.
///
/// The node MUST already be interned in `DeferredState` — call `emit_register` first.
fn emit_evaluate_into_mem(src: &mut String, node: Node, out_base: u32) {
    use core::fmt::Write;
    push_digest(src, node.digest());
    src.push_str("    adv.evaluate_deferred\n");
    for _ in 0..4 {
        src.push_str("    drop\n");
    }
    // Advice stack top-to-bottom: PAYLOAD_LO || PAYLOAD_HI || TAG (matching the operand-stack
    // input layout). Pull each word and write to memory in order.
    for word_idx in 0..3u32 {
        src.push_str("    adv_pushw\n");
        writeln!(src, "    mem_storew_le.{}", out_base + word_idx * 4).unwrap();
        src.push_str("    dropw\n");
    }
}

/// Build a MASM block that pushes the node's digest and invokes `adv.evaluate_deferred` without
/// consuming any advice output — used for predicates whose canonical form is the TRUE node (no
/// advice push) or for cases where we just want to surface the verification error.
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
    for f in node.tag.iter().rev() {
        writeln!(src, "    push.{}", f.as_int()).unwrap();
    }
    let payload = node
        .payload_felts()
        .expect("push_node only handles expression-bodied nodes");
    for f in payload.0.iter().rev() {
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

// UINT256 LEAF HELPER
// ================================================================================================

fn uint256_leaf(low: u64) -> Node {
    let mut limbs = [0u32; 8];
    limbs[0] = low as u32;
    limbs[1] = (low >> 32) as u32;
    Uint256::leaf_node(limbs)
}

// END-TO-END: (a + b) * c == 35  (with a=3, b=4, c=5)
// ================================================================================================

#[test]
fn deferred_end_to_end_register_eval_assert() {
    // Precompute every node and digest the program will use.
    let a = uint256_leaf(3);
    let b = uint256_leaf(4);
    let c = uint256_leaf(5);
    let d = uint256_leaf(35); // (3 + 4) * 5

    let a_digest = a.digest();
    let b_digest = b.digest();
    let c_digest = c.digest();
    let d_digest = d.digest();
    let add = Node::expression(Uint256::add_tag(), Payload::binary_op(a_digest, b_digest));
    let add_digest = add.digest();
    let mul = Node::expression(Uint256::mul_tag(), Payload::binary_op(add_digest, c_digest));
    let mul_digest = mul.digest();
    // Predicate node: same shape as a binary op (expression body, two child digests), just with
    // ASSERT_EQ as the tag.
    let assertion =
        Node::expression(Uint256::eq_tag(), Payload::binary_op(mul_digest, d_digest));

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
        assert!(state.contains(&digest), "missing node for digest {:?}", digest);
    }
    assert!(state.contains(&assertion.digest()), "predicate node must be interned");

    // No `log_precompile` calls, so the transcript root is still the TRUE sentinel.
    assert_eq!(state.root(), TRUE_DIGEST);

    // State includes every registered node plus the predicate's reduce intermediates. The
    // evaluate of the predicate reduces (a+b) → leaf(7) and (a+b)*c → leaf(35). leaf(35)
    // collides with the pre-registered `d`, so the DAG gains one new node beyond the seven
    // originally registered: canonical(add) = leaf(7). The TRUE node from the predicate
    // reduction is not interned (it's a structural sentinel, not a load-bearing DAG node).
    assert_eq!(state.nodes().len(), 8);
    for d in expected_digests {
        assert!(state.contains(&d));
    }
    assert!(state.contains(&assertion.digest()));
    assert_eq!(state.root(), TRUE_DIGEST);
}

// E2E: adv.evaluate_deferred pushes the canonical (tag, payload) onto the advice stack.
// ================================================================================================

#[test]
fn deferred_evaluate_pushes_canonical_form_to_advice() {
    // Register two leaves a=3 and b=4, then ask `adv.evaluate_deferred` for the canonical form of
    // (a + b). Confirm the advice-pop yields a leaf node with payload limb0 = 7.
    let a = uint256_leaf(3);
    let b = uint256_leaf(4);
    let add = Node::expression(Uint256::add_tag(), Payload::binary_op(a.digest(), b.digest()));

    let mut src = String::from("begin\n");
    emit_register(&mut src, a);
    emit_register(&mut src, b);
    emit_register(&mut src, add.clone());
    emit_evaluate_into_mem(&mut src, add, 0);
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");

    let mut host = DefaultHost::default();
    let output = build_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    // Memory layout: addresses 0..8 hold the canonical payload (a 256-bit u32-limbed integer of
    // value 7), 8..12 hold the canonical tag (Uint256::leaf_tag()).
    let ctx = 0u32.into();
    let mut mem = [Felt::from_u32(0); 12];
    for i in 0..12u32 {
        mem[i as usize] = output.memory.read_element(ctx, Felt::from_u32(i)).expect("memory read");
    }
    let canonical_tag = [mem[8], mem[9], mem[10], mem[11]];
    assert_eq!(canonical_tag, Uint256::leaf_tag(), "evaluate returns canonical leaf tag");
    assert_eq!(mem[0].as_canonical_u64(), 7, "limb 0 of (3+4)");
    for (limb_idx, felt) in mem[..8].iter().enumerate().skip(1) {
        assert_eq!(felt.as_canonical_u64(), 0, "limb {} of (3+4) must be zero", limb_idx);
    }
}

// E2E: evaluating a predicate is a pure verify — nothing is pushed onto the advice stack.
// ================================================================================================

#[test]
fn deferred_evaluate_on_predicate_pushes_nothing_to_advice() {
    // Register one leaf, build a self-equal predicate (a == a), evaluate it. The predicate must
    // verify successfully but nothing is pushed onto the advice stack — a trailing `adv_push`
    // therefore underflows and fails execution.
    let a = uint256_leaf(7);
    let a_eq_a =
        Node::expression(Uint256::eq_tag(), Payload::binary_op(a.digest(), a.digest()));

    let mut src = String::from("begin\n");
    emit_register(&mut src, a);
    emit_register(&mut src, a_eq_a.clone());
    push_digest(&mut src, a_eq_a.digest());
    src.push_str("    adv.evaluate_deferred\n");
    for _ in 0..4 {
        src.push_str("    drop\n");
    }
    // Try to pop a single felt off the advice stack — must underflow because evaluate(predicate)
    // pushed nothing.
    src.push_str("    adv_push\n");
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");

    let mut host = DefaultHost::default();
    let result = build_processor().execute_sync(&program, &mut host);
    assert!(
        result.is_err(),
        "adv_push.1 after evaluate(predicate) must underflow because nothing was pushed"
    );
}

// E2E: a predicate is just a host hint — `adv.register_deferred` does NOT verify it. The
// mismatch only surfaces when the program explicitly evaluates the predicate.
// ================================================================================================

#[test]
fn deferred_register_predicate_does_not_verify() {
    let a = uint256_leaf(7);
    let b = uint256_leaf(8);
    let mismatch =
        Node::expression(Uint256::eq_tag(), Payload::binary_op(a.digest(), b.digest()));

    // Just register — execution must succeed because register is a pure host hint.
    let mut src = String::from("begin\n");
    emit_register(&mut src, a.clone());
    emit_register(&mut src, b.clone());
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
    let a = uint256_leaf(7);
    let b = uint256_leaf(8);
    let mismatch =
        Node::expression(Uint256::eq_tag(), Payload::binary_op(a.digest(), b.digest()));

    let mut src = String::from("begin\n");
    emit_register(&mut src, a);
    emit_register(&mut src, b);
    emit_register(&mut src, mismatch.clone());
    emit_evaluate_for_side_effect(&mut src, mismatch);
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");

    let mut host = DefaultHost::default();
    let result = build_processor().execute_sync(&program, &mut host);
    assert!(
        result.is_err(),
        "evaluating a mismatched predicate must fail execution"
    );
}

// E2E: adv.register_deferred pushes the registered node's digest onto the advice stack.
// ================================================================================================

#[test]
fn deferred_register_pushes_node_digest_to_advice() {
    // Register a leaf, then pull the advice-pushed digest into memory and assert it matches the
    // node's content-addressed digest.
    let leaf = uint256_leaf(42);
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
        output
            .memory
            .read_element(ctx, Felt::from_u32(i as u32))
            .expect("memory read")
    });
    assert_eq!(observed, *expected.as_elements(), "register must push the node's digest");
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
    for f in tag.iter().rev() {
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

    let leaf = uint256_leaf(42);

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
// A minimal chunk-aware test schema, mirroring `core/tests/deferred_chunk.rs::TestSchema`:
// `decode` reads role from tag[2] and (for chunks) `n` from tag[3]; `reduce` for a chunk
// returns an expression digest-leaf via a fake limb-sum hash.

const TEST_PREFIX: [Felt; 2] = [Felt::new_unchecked(0x73), Felt::new_unchecked(0x68)];
const PREIMAGE_ROLE: Felt = Felt::new_unchecked(0);
const DIGEST_ROLE: Felt = Felt::new_unchecked(1);

fn preimage_tag(n: u32) -> Tag {
    [TEST_PREFIX[0], TEST_PREFIX[1], PREIMAGE_ROLE, Felt::from_u32(n)]
}

fn digest_tag() -> Tag {
    [TEST_PREFIX[0], TEST_PREFIX[1], DIGEST_ROLE, ZERO]
}

#[derive(Debug, Default, Clone, Copy)]
struct ChunkTestSchema;

impl Schema for ChunkTestSchema {
    fn decode(&self, tag: Tag) -> Result<TagInfo, SchemaError> {
        if tag[0] != TEST_PREFIX[0] || tag[1] != TEST_PREFIX[1] {
            return Err(SchemaError::InvalidNode);
        }
        match tag[2] {
            r if r == PREIMAGE_ROLE => Ok(TagInfo {
                node_type: NodeType::Chunks(tag[3].as_canonical_u64() as u32),
                evaluates_to: digest_tag(),
            }),
            r if r == DIGEST_ROLE => Ok(TagInfo {
                node_type: NodeType::Value,
                evaluates_to: digest_tag(),
            }),
            _ => Err(SchemaError::InvalidNode),
        }
    }

    fn reduce(&self, node: &Node, _ctx: &mut dyn ReduceCtx) -> Result<Node, SchemaError> {
        match &node.payload {
            NodePayload::Chunk(chunks) => {
                let mut acc = [ZERO; 8];
                for c in chunks.iter() {
                    for (a, x) in acc.iter_mut().zip(c.iter()) {
                        *a += *x;
                    }
                }
                Ok(Node::expression(digest_tag(), Payload::new(acc)))
            },
            NodePayload::Expression(_) => Ok(node.clone()),
        }
    }
}

fn build_chunk_processor() -> FastProcessor {
    FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    )
    .expect("processor construction")
    .with_schema(Arc::new(ChunkTestSchema))
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
    writeln!(&mut src, "    push.{}", ptr).unwrap();
    for f in tag.iter().rev() {
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
        NodePayload::Chunk(c) => {
            assert_eq!(c.as_ref(), chunks.as_slice(), "bulk data must match memory contents")
        },
        _ => panic!("expected chunk variant in deferred state"),
    }
    assert_eq!(stored.tag, tag);
}

#[test]
fn chunk_register_rejects_unaligned_pointer() {
    use core::fmt::Write;
    let tag = preimage_tag(1);
    let ptr: u32 = 1; // not word-aligned

    let mut src = String::from("begin\n");
    writeln!(&mut src, "    push.{}", ptr).unwrap();
    for f in tag.iter().rev() {
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
    writeln!(&mut src, "    push.{}", ptr).unwrap();
    for f in tag.iter().rev() {
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
