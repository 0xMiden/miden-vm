//! End-to-end coverage for deferred advice events on a real `FastProcessor`.
//!
//! The tests prove that registration, evaluation, in-circuit digest binding, and chunk
//! registration work without bypassing deferred-state verification.

use alloc::{sync::Arc, vec::Vec};

use miden_assembly::Assembler;
use miden_core::{
    deferred::{Node, Payload, PrecompileRegistry, Tag},
    testing::precompile::{Hash, Uint},
};
use miden_processor::{
    DefaultHost, ExecutionError, ExecutionOptions, FastProcessor, Felt, StackInputs,
    advice::AdviceInputs,
};

extern crate alloc;

// PROCESSOR FACTORY
// ================================================================================================

/// Builds a processor with the uint precompile installed for deferred tests.
fn build_processor() -> FastProcessor {
    build_processor_with_options(ExecutionOptions::default())
}

fn build_processor_with_options(options: ExecutionOptions) -> FastProcessor {
    FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
        .expect("processor construction")
}

fn uint_host() -> DefaultHost {
    DefaultHost::default()
        .with_precompiles(Arc::new(PrecompileRegistry::default().with_precompile(Uint)))
}

// MASM BUILDERS
// ================================================================================================

/// Emits MASM that registers an expression node and restores the operand stack.
fn emit_register(src: &mut String, node: Node) {
    push_node(src, node);
    src.push_str("    adv.register_deferred\n");
    for _ in 0..12 {
        src.push_str("    drop\n");
    }
}

/// Emits MASM that evaluates an already-registered node for its side effects.
fn emit_evaluate_for_side_effect(src: &mut String, node: Node) {
    push_digest(src, node.digest());
    src.push_str("    adv.evaluate_deferred\n");
    for _ in 0..4 {
        src.push_str("    drop\n");
    }
}

/// Pushes a digest in VM stack order.
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

// E2E: adv.evaluate_deferred returns the canonical (tag || payload) on the advice stack.
// ================================================================================================

/// Captures the canonical expression returned by `adv.evaluate_deferred` into memory.
fn emit_capture_canonical_value(src: &mut String) {
    src.push_str("    dropw\n"); // drop the input NODE_DIGEST
    src.push_str("    adv_pushw mem_storew_le.0 dropw\n"); // TAG       -> mem[0..4]
    src.push_str("    adv_pushw mem_storew_le.4 dropw\n"); // PAYLOAD_LO -> mem[4..8]
    src.push_str("    adv_pushw mem_storew_le.8 dropw\n"); // PAYLOAD_HI -> mem[8..12]
}

/// Reads the captured canonical `tag || payload` from memory.
fn read_canonical_value(output: &miden_processor::ExecutionOutput) -> Vec<Felt> {
    let ctx = 0u32.into();
    (0..12)
        .map(|i| output.memory.read_element(ctx, Felt::from_u32(i)).expect("memory read"))
        .collect()
}

#[test]
fn deferred_evaluate_returns_canonical_value_on_advice() {
    // Register two leaves a=3 and b=4, then ask `adv.evaluate_deferred` for the canonical form of
    // (a + b). The canonical (leaf 7) is returned on the advice stack as `tag || payload`.
    let a = arith_leaf(3);
    let b = arith_leaf(4);
    let add = Node::join(Uint::add_tag(), a.digest(), b.digest());

    let mut src = String::from("begin\n");
    emit_register(&mut src, a);
    emit_register(&mut src, b);
    emit_register(&mut src, add.clone());
    push_digest(&mut src, add.digest());
    src.push_str("    adv.evaluate_deferred\n");
    emit_capture_canonical_value(&mut src);
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");

    let mut host = uint_host();
    let output = build_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    let canonical = arith_leaf(7);
    let mut expected: Vec<Felt> = canonical.tag.as_word().to_vec();
    expected.extend_from_slice(canonical.payload.as_felts().unwrap());

    assert_eq!(
        read_canonical_value(&output),
        expected,
        "evaluate must return the canonical `tag || payload` on the advice stack"
    );
}

// E2E: evaluating a predicate returns the TRUE node — no special-casing of predicates.
// ================================================================================================

#[test]
fn deferred_evaluate_returns_true_node_for_predicate() {
    // Register one leaf, build a self-equal predicate (a == a), evaluate it. The predicate must
    // verify successfully, and its canonical (the TRUE node) is returned on the advice stack as 12
    // zero felts — uniform with every other node shape.
    let a = arith_leaf(7);
    let a_eq_a = Node::join(Uint::eq_tag(), a.digest(), a.digest());

    let mut src = String::from("begin\n");
    emit_register(&mut src, a);
    emit_register(&mut src, a_eq_a.clone());
    push_digest(&mut src, a_eq_a.digest());
    src.push_str("    adv.evaluate_deferred\n");
    emit_capture_canonical_value(&mut src);
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");

    let mut host = uint_host();
    let output = build_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    let mut expected: Vec<Felt> = Node::TRUE.tag.as_word().to_vec();
    expected.extend_from_slice(Node::TRUE.payload.as_felts().unwrap());

    assert_eq!(
        read_canonical_value(&output),
        expected,
        "predicate canonical must be returned as the TRUE node felts"
    );
}

// E2E: a predicate is just a host hint — `adv.register_deferred` does NOT verify it. The
// mismatch only surfaces when the program explicitly evaluates the predicate.
// ================================================================================================

#[test]
fn deferred_register_over_deferred_budget_is_rejected() {
    let leaf = arith_leaf(42);

    let mut src = String::from("begin\n");
    emit_register(&mut src, leaf);
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");
    let mut host = uint_host();
    let result =
        build_processor_with_options(ExecutionOptions::default().with_max_deferred_elements(11))
            .execute_sync(&program, &mut host);

    match result {
        Err(ExecutionError::DeferredStateTooLarge { num_elements, max, .. }) => {
            assert_eq!(num_elements, 12);
            assert_eq!(max, 11);
        },
        other => panic!("expected DeferredStateTooLarge, got {other:?}"),
    }
}

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
    let mut host = uint_host();
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

    let mut host = uint_host();
    let result = build_processor().execute_sync(&program, &mut host);
    assert!(result.is_err(), "evaluating a mismatched predicate must fail execution");
}

// EQUIVALENCE: the in-circuit digest derivation reproduces `Node::digest` bit-for-bit.
// ================================================================================================
//
// The register events no longer hand back the digest via advice; the `sys` wrappers compute it
// in-circuit (`hperm` for expressions, a `mem_stream` linear hash for chunks). These tests inline
// the exact wrapper bodies and assert the result equals `Node::digest`, which is the verifier's
// reference. They are the source of truth for the rate/capacity layout and the chunk loop now that
// the digest is recomputed in MASM.

#[test]
fn deferred_register_expr_digest_matches_node_digest() {
    // `sys::register_expr` body: intern, then `hperm` over `[PAYLOAD_LO, PAYLOAD_HI, TAG]` and
    // squeeze rate0. Assert the operand-stack result equals `Node::digest`.
    let leaf = arith_leaf(42);
    let expected = leaf.digest();

    let mut src = String::from("begin\n");
    push_node(&mut src, leaf);
    src.push_str("    adv.register_deferred\n");
    src.push_str("    hperm swapw.2 dropw dropw\n"); // digest = rate0 of permuted state
    src.push_str("    mem_storew_le.0 dropw\n");
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");
    let mut host = uint_host();
    let output = build_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    let ctx = 0u32.into();
    let observed: [Felt; 4] = core::array::from_fn(|i| {
        output.memory.read_element(ctx, Felt::from_u32(i as u32)).expect("memory read")
    });
    assert_eq!(observed, *expected.as_elements(), "in-circuit hperm must match Node::digest");
}

#[test]
fn deferred_evaluate_value_rehashes_to_canonical_digest() {
    // Register a=3, b=4 and add=(a+b). Evaluate add to pull the canonical `tag || payload` off the
    // advice stack, re-hash it in-circuit (the binding step), and assert the digest equals
    // digest(leaf 7) — i.e. a caller can recover a *bound* canonical digest from the evaluate hint.
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
    src.push_str("    dropw\n"); // drop the input NODE_DIGEST
    // Pull TAG, PAYLOAD_LO, PAYLOAD_HI (TAG-first) onto the operand stack: [PHI, PLO, TAG].
    src.push_str("    adv_pushw adv_pushw adv_pushw\n");
    // Reorder to the sponge layout [PAYLOAD_LO, PAYLOAD_HI, TAG] = [R0, R1, C], then hash.
    src.push_str("    swapw hperm swapw.2 dropw dropw\n");
    src.push_str("    mem_storew_le.0 dropw\n");
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");
    let mut host = uint_host();
    let output = build_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    let ctx = 0u32.into();
    let observed: [Felt; 4] = core::array::from_fn(|i| {
        output.memory.read_element(ctx, Felt::from_u32(i as u32)).expect("memory read")
    });
    assert_eq!(observed, *expected.as_elements(), "re-hashed canonical must match its digest");
}

#[test]
fn deferred_register_chunk_digest_matches_node_digest() {
    use core::fmt::Write;
    // `sys::register_chunk` body over two 8-felt chunks in memory at 0..16: intern, derive
    // end_addr = ptr + 8*n_chunks, then `mem_stream`/`hperm` once per block. Assert the result
    // equals the chunk node's `Node::digest`.
    let chunks: Vec<[Felt; 8]> = (0..2u32)
        .map(|i| core::array::from_fn(|j| Felt::from_u32(101 + i * 8 + j as u32)))
        .collect();
    let tag = preimage_tag(2);
    let expected = Node::chunk(tag, chunks.clone()).digest();

    let mut src = String::from("begin\n");
    for (i, felt) in chunks.iter().flatten().enumerate() {
        writeln!(&mut src, "    push.{}", felt.as_canonical_u64()).unwrap();
        writeln!(&mut src, "    mem_store.{}", i as u32).unwrap();
    }
    // Stack: [TAG, ptr=0, n_chunks=2].
    writeln!(&mut src, "    push.{}", 2u32).unwrap(); // n_chunks
    writeln!(&mut src, "    push.{}", 0u32).unwrap(); // ptr
    for f in tag.as_word().iter().rev() {
        writeln!(&mut src, "    push.{}", f.as_canonical_u64()).unwrap();
    }
    src.push_str("    adv.register_deferred_chunk\n");
    // Inline the register_chunk hashing body.
    src.push_str("    movup.5 mul.8 dup.5 add movdn.5\n"); // -> [TAG, ptr, end_addr]
    src.push_str("    padw padw\n"); // -> [R0=0w, R1=0w, C=TAG, start, end]
    src.push_str("    dup.13 dup.13 neq\n");
    src.push_str("    while.true\n");
    src.push_str("        mem_stream hperm\n");
    src.push_str("        dup.13 dup.13 neq\n");
    src.push_str("    end\n");
    src.push_str("    swapw.2 dropw dropw\n"); // digest = rate0
    src.push_str("    movup.4 drop movup.4 drop\n"); // drop the two end_addr felts
    src.push_str("    mem_storew_le.16 dropw\n");
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");
    let mut host = hash_host();
    let output = build_chunk_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    let ctx = 0u32.into();
    let observed: [Felt; 4] = core::array::from_fn(|i| {
        output
            .memory
            .read_element(ctx, Felt::from_u32(16 + i as u32))
            .expect("memory read")
    });
    assert_eq!(
        observed,
        *expected.as_elements(),
        "in-circuit mem_stream must match Node::digest"
    );
}

// CHUNK REGISTER E2E
// ================================================================================================
//
// Drives `adv.register_deferred_chunk` against the [`Hash`] chunk precompile.

/// Builds a hash preimage tag whose byte length implies `n` chunks.
fn preimage_tag(n: u32) -> Tag {
    Hash::preimage_tag(n * Hash::BYTES_PER_CHUNK)
}

fn build_chunk_processor() -> FastProcessor {
    build_chunk_processor_with_options(ExecutionOptions::default())
}

fn build_chunk_processor_with_options(options: ExecutionOptions) -> FastProcessor {
    FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
        .expect("processor construction")
}

fn hash_host() -> DefaultHost {
    DefaultHost::default()
        .with_precompiles(Arc::new(PrecompileRegistry::default().with_precompile(Hash)))
}

/// Emits MASM that registers a chunk node from memory.
fn emit_register_chunk(src: &mut String, tag: Tag, ptr: u32) {
    use core::fmt::Write;
    writeln!(src, "    push.{ptr}").unwrap();
    for f in tag.as_word().iter().rev() {
        writeln!(src, "    push.{}", f.as_canonical_u64()).unwrap();
    }
    src.push_str("    adv.register_deferred_chunk\n");
}

#[test]
fn chunk_register_over_deferred_budget_is_rejected_before_reading_memory() {
    let huge_n_chunks = 1 << 20;
    let tag = preimage_tag(huge_n_chunks);

    let mut src = String::from("begin\n");
    emit_register_chunk(&mut src, tag, 0);
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");
    let mut host = hash_host();
    let result = build_chunk_processor_with_options(
        ExecutionOptions::default().with_max_deferred_elements(16),
    )
    .execute_sync(&program, &mut host);

    match result {
        Err(ExecutionError::DeferredStateTooLarge { num_elements, max, .. }) => {
            assert_eq!(num_elements, 4 + 8 * huge_n_chunks as usize);
            assert_eq!(max, 16);
        },
        other => panic!("expected DeferredStateTooLarge, got {other:?}"),
    }
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

    // Write the 16 felts to memory at addresses 0..16, register the chunk, then drop the 5 felts
    // left on the operand stack.
    let mut src = String::from("begin\n");
    for (i, felt) in chunks.iter().flatten().enumerate() {
        writeln!(&mut src, "    push.{}", felt.as_canonical_u64()).unwrap();
        writeln!(&mut src, "    mem_store.{}", ptr + i as u32).unwrap();
    }
    emit_register_chunk(&mut src, tag, ptr);
    for _ in 0..5 {
        src.push_str("    drop\n");
    }
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");

    let mut host = hash_host();
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
    let tag = preimage_tag(1);
    let ptr: u32 = 1; // not word-aligned

    let mut src = String::from("begin\n");
    emit_register_chunk(&mut src, tag, ptr);
    src.push_str("end\n");

    let program = Assembler::default().assemble_program(&src).expect("program must assemble");
    let mut host = hash_host();
    let result = build_chunk_processor().execute_sync(&program, &mut host);
    assert!(result.is_err(), "unaligned ptr must surface as an execution error");
}
