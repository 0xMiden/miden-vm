//! End-to-end coverage for deferred advice events on a real `FastProcessor`.
//!
//! The tests prove that registration, evaluation, in-circuit digest binding, and bulk-data
//! registration work without bypassing deferred-state verification.

use alloc::vec::Vec;

use miden_assembly::Assembler;
use miden_core::{
    deferred::{Node, PrecompileError, PrecompileRegistry, TRUE_DIGEST, Tag},
    program::Program,
    testing::precompile::{Hash, Uint},
};
use miden_processor::{
    DefaultHost, ExecutionError, ExecutionOptions, FastProcessor, Felt, StackInputs,
    advice::AdviceInputs,
};

extern crate alloc;

// PROCESSOR FACTORY
// ================================================================================================

/// Builds a processor with an empty deferred precompile registry.
fn build_processor() -> FastProcessor {
    build_processor_with_options(ExecutionOptions::default())
}

fn build_processor_with_options(options: ExecutionOptions) -> FastProcessor {
    FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
        .expect("processor construction")
}

fn uint_precompiles() -> PrecompileRegistry {
    PrecompileRegistry::default().with_precompile(Uint)
}

fn build_uint_processor() -> FastProcessor {
    build_uint_processor_with_options(ExecutionOptions::default())
}

fn build_uint_processor_with_options(options: ExecutionOptions) -> FastProcessor {
    build_processor_with_options(options)
        .with_deferred_precompiles(uint_precompiles())
        .expect("uint precompile registration")
}

fn assemble_test_program(src: &str) -> Program {
    Assembler::default()
        .assemble_program("test", src)
        .expect("program must assemble")
        .unwrap_program()
}

// MASM BUILDERS
// ================================================================================================

/// Emits MASM that registers a value or join node and restores the operand stack.
fn emit_register(src: &mut String, node: Node) {
    push_node(src, node);
    src.push_str("    adv.register_deferred\n");
    for _ in 0..12 {
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
    // Push tag first (its 4 felts end up deepest), then the 8 payload felts on top, so the stack
    // layout under `event_id` becomes [PAYLOAD_LO, PAYLOAD_HI, TAG] — the Poseidon2 sponge layout
    // used by `Node::digest`. The eight payload felts are one data chunk for a value or lhs||rhs
    // for a join, taken from `Node::to_felts` after the four-felt tag.
    for f in node.tag().as_word().iter().rev() {
        writeln!(src, "    push.{}", f.as_int()).unwrap();
    }
    let felts = node.to_felts();
    let payload = &felts[4..12];
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

fn arith_value(low: u64) -> Node {
    let mut limbs = [0u32; 8];
    limbs[0] = low as u32;
    limbs[1] = (low >> 32) as u32;
    Uint::value_node(limbs)
}

#[test]
fn empty_processor_rejects_uint_deferred_tag() {
    let value = arith_value(42);

    let mut src = String::from("begin\n");
    emit_register(&mut src, value);
    src.push_str("end\n");

    let program = assemble_test_program(&src);
    let mut host = DefaultHost::default();
    match build_processor().execute_sync(&program, &mut host) {
        Err(ExecutionError::DeferredError { err, .. }) => {
            assert!(matches!(err.root(), PrecompileError::InvalidNode));
        },
        Err(err) => panic!("expected invalid deferred node, got {err:?}"),
        Ok(_) => panic!("empty processor should reject Uint deferred nodes"),
    }
}

// E2E: adv.evaluate_deferred returns the canonical (tag || payload) on the advice stack.
// ================================================================================================

/// Captures the canonical value returned by `adv.evaluate_deferred` into memory.
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
    // (a + b). The canonical (value 7) is returned on the advice stack as `tag || payload`.
    let a = arith_value(3);
    let b = arith_value(4);
    let add = Node::join(Uint::add_tag(), a.digest(), b.digest()).unwrap();

    let mut src = String::from("begin\n");
    emit_register(&mut src, a);
    emit_register(&mut src, b);
    emit_register(&mut src, add.clone());
    push_digest(&mut src, add.digest());
    src.push_str("    adv.evaluate_deferred\n");
    emit_capture_canonical_value(&mut src);
    src.push_str("end\n");

    let program = assemble_test_program(&src);

    let mut host = DefaultHost::default();
    let output = build_uint_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    let canonical = arith_value(7);
    let expected = canonical.to_felts();

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
    // Register one value, then a self-equal predicate (a == a). Registration verifies it eagerly;
    // `adv.evaluate_deferred` then returns the memoized canonical TRUE node as only its 4-felt tag
    // — TRUE has no payload.
    let a = arith_value(7);
    let a_eq_a = Node::join(Uint::eq_tag(), a.digest(), a.digest()).unwrap();

    let mut src = String::from("begin\n");
    emit_register(&mut src, a);
    emit_register(&mut src, a_eq_a.clone());
    push_digest(&mut src, a_eq_a.digest());
    src.push_str("    adv.evaluate_deferred\n");
    src.push_str("    dropw\n"); // drop the input NODE_DIGEST
    src.push_str("    adv_pushw mem_storew_le.0 dropw\n"); // TRUE tag (4 felts) -> mem[0..4]
    src.push_str("end\n");

    let program = assemble_test_program(&src);

    let mut host = DefaultHost::default();
    let output = build_uint_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    let expected = Node::TRUE.to_felts();
    let ctx = 0u32.into();
    let observed: Vec<Felt> = (0..expected.len())
        .map(|i| output.memory.read_element(ctx, Felt::from_u32(i as u32)).expect("memory read"))
        .collect();

    assert_eq!(
        observed, expected,
        "predicate canonical must be returned as the 4-felt TRUE tag"
    );
}

#[test]
fn deferred_evaluate_true_digest_returns_exactly_true_tag() {
    let mut src = String::from("begin\n");
    push_digest(&mut src, TRUE_DIGEST);
    src.push_str("    adv.evaluate_deferred\n");
    src.push_str("    dropw\n"); // drop the input TRUE_DIGEST
    src.push_str("    adv_pushw mem_storew_le.0 dropw\n");
    src.push_str("end\n");

    let program = assemble_test_program(&src);
    let mut host = DefaultHost::default();
    let output = build_uint_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    let ctx = 0u32.into();
    let observed: Vec<Felt> = (0..4)
        .map(|i| output.memory.read_element(ctx, Felt::from_u32(i)).expect("memory read"))
        .collect();

    assert_eq!(observed, Node::TRUE.to_felts());
    assert_eq!(output.advice.stack(), Vec::<Felt>::new(), "TRUE evaluation must push one word");
}

// E2E: eager registration rejects over-budget nodes and false predicates.
// ================================================================================================

#[test]
fn deferred_register_over_deferred_budget_is_rejected() {
    let value = Hash::digest_node([Felt::from_u32(42); 8]);

    let mut src = String::from("begin\n");
    emit_register(&mut src, value);
    src.push_str("end\n");

    let program = assemble_test_program(&src);
    let mut host = DefaultHost::default();
    let result = build_hash_processor_with_options(
        ExecutionOptions::default().with_max_deferred_elements(11),
    )
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
fn deferred_register_predicate_mismatch_fails_execution() {
    let a = arith_value(7);
    let b = arith_value(8);
    let mismatch = Node::join(Uint::eq_tag(), a.digest(), b.digest()).unwrap();

    let mut src = String::from("begin\n");
    emit_register(&mut src, a);
    emit_register(&mut src, b);
    emit_register(&mut src, mismatch);
    src.push_str("end\n");

    let program = assemble_test_program(&src);
    let mut host = DefaultHost::default();
    let result = build_uint_processor().execute_sync(&program, &mut host);

    match result {
        Err(ExecutionError::DeferredError { err, .. }) => {
            assert!(matches!(err.root(), PrecompileError::AssertionFailed));
        },
        Err(err) => panic!("expected deferred assertion failure, got {err:?}"),
        Ok(_) => panic!("registering a mismatched predicate must fail execution"),
    }
}

// EQUIVALENCE: the in-circuit digest derivation reproduces `Node::digest` bit-for-bit.
// ================================================================================================
//
// The register events no longer hand back the digest via advice; the `sys` wrappers compute it
// in-circuit (`hperm` for value/join nodes, a `mem_stream` linear hash for data chunks). These
// tests inline the exact wrapper bodies and assert the result equals `Node::digest`, which is the
// verifier's reference. They are the source of truth for the rate/capacity layout and the chunk
// loop now that the digest is recomputed in MASM.

#[test]
fn deferred_register_value_digest_matches_node_digest() {
    // Register a value node, then `hperm` over `[PAYLOAD_LO, PAYLOAD_HI, TAG]` and squeeze rate0.
    // Assert the operand-stack result equals `Node::digest`.
    let value = arith_value(42);
    let expected = value.digest();

    let mut src = String::from("begin\n");
    push_node(&mut src, value);
    src.push_str("    adv.register_deferred\n");
    src.push_str("    hperm swapw.2 dropw dropw\n"); // digest = rate0 of permuted state
    src.push_str("    mem_storew_le.0 dropw\n");
    src.push_str("end\n");

    let program = assemble_test_program(&src);
    let mut host = DefaultHost::default();
    let output = build_uint_processor()
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
    // digest(value 7) — i.e. a caller can recover a *bound* canonical digest from the evaluate
    // hint.
    let a = arith_value(3);
    let b = arith_value(4);
    let add = Node::join(Uint::add_tag(), a.digest(), b.digest()).unwrap();
    let expected = arith_value(7).digest();

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

    let program = assemble_test_program(&src);
    let mut host = DefaultHost::default();
    let output = build_uint_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    let ctx = 0u32.into();
    let observed: [Felt; 4] = core::array::from_fn(|i| {
        output.memory.read_element(ctx, Felt::from_u32(i as u32)).expect("memory read")
    });
    assert_eq!(observed, *expected.as_elements(), "re-hashed canonical must match its digest");
}

#[test]
fn deferred_register_data_digest_matches_node_digest() {
    use core::fmt::Write;
    // Register-data body over two 8-felt data chunks in memory at 0..16: register, then derive
    // end_addr = ptr + 8*n_chunks for this test's in-circuit hashing loop. The raw event itself
    // does not read n_chunks from the stack; it decodes the data chunk count from the tag.
    let chunks: Vec<[Felt; 8]> = (0..2u32)
        .map(|i| core::array::from_fn(|j| Felt::from_u32(101 + i * 8 + j as u32)))
        .collect();
    let tag = preimage_tag(2);
    let expected = Node::try_data(tag, chunks.clone()).unwrap().digest();

    let mut src = String::from("begin\n");
    for (i, felt) in chunks.iter().flatten().enumerate() {
        writeln!(&mut src, "    push.{}", felt.as_canonical_u64()).unwrap();
        writeln!(&mut src, "    mem_store.{}", i as u32).unwrap();
    }
    // Stack: [TAG, ptr=0, n_chunks=2]. `n_chunks` is wrapper-local loop control below the raw
    // event operands; `adv.register_deferred_data` reads only TAG and ptr.
    writeln!(&mut src, "    push.{}", 2u32).unwrap(); // wrapper-local n_chunks
    writeln!(&mut src, "    push.{}", 0u32).unwrap(); // ptr
    for f in tag.as_word().iter().rev() {
        writeln!(&mut src, "    push.{}", f.as_canonical_u64()).unwrap();
    }
    src.push_str("    adv.register_deferred_data\n");
    // Inline the register-data hashing body.
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

    let program = assemble_test_program(&src);
    let mut host = DefaultHost::default();
    let output = build_hash_processor()
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

// DATA REGISTER E2E
// ================================================================================================
//
// Drives `adv.register_deferred_data` against the [`Hash`] data precompile.

/// Builds a hash preimage tag whose byte length implies `n` data chunks.
fn preimage_tag(n: u32) -> Tag {
    Hash::preimage_tag(n * Hash::BYTES_PER_CHUNK)
}

fn hash_precompiles() -> PrecompileRegistry {
    PrecompileRegistry::default().with_precompile(Hash)
}

fn build_hash_processor() -> FastProcessor {
    build_hash_processor_with_options(ExecutionOptions::default())
}

fn build_hash_processor_with_options(options: ExecutionOptions) -> FastProcessor {
    build_processor_with_options(options)
        .with_deferred_precompiles(hash_precompiles())
        .expect("hash precompile registration")
}

/// Emits MASM that registers a data node from memory.
fn emit_register_data(src: &mut String, tag: Tag, ptr: u32) {
    use core::fmt::Write;
    writeln!(src, "    push.{ptr}").unwrap();
    for f in tag.as_word().iter().rev() {
        writeln!(src, "    push.{}", f.as_canonical_u64()).unwrap();
    }
    src.push_str("    adv.register_deferred_data\n");
}

#[test]
fn data_register_over_deferred_budget_is_rejected() {
    let data_chunk_count = 2;
    let tag = preimage_tag(data_chunk_count);

    let mut src = String::from("begin\n");
    emit_register_data(&mut src, tag, 0);
    src.push_str("end\n");

    let program = assemble_test_program(&src);
    let mut host = DefaultHost::default();
    let result = build_hash_processor_with_options(
        ExecutionOptions::default().with_max_deferred_elements(16),
    )
    .execute_sync(&program, &mut host);

    match result {
        Err(ExecutionError::DeferredStateTooLarge { num_elements, max, .. }) => {
            assert_eq!(num_elements, 4 + 8 * data_chunk_count as usize);
            assert_eq!(max, 16);
        },
        other => panic!("expected DeferredStateTooLarge, got {other:?}"),
    }
}

#[test]
fn data_register_canonical_over_deferred_budget_is_rejected() {
    let data_chunk_count = 2;
    let tag = preimage_tag(data_chunk_count);

    let mut src = String::from("begin\n");
    emit_register_data(&mut src, tag, 0);
    src.push_str("end\n");

    let program = assemble_test_program(&src);
    let mut host = DefaultHost::default();
    let result = build_hash_processor_with_options(
        ExecutionOptions::default().with_max_deferred_elements(4 + 8 * data_chunk_count as usize),
    )
    .execute_sync(&program, &mut host);

    match result {
        Err(ExecutionError::DeferredStateTooLarge { num_elements, max, .. }) => {
            assert_eq!(num_elements, 12);
            assert_eq!(max, 0);
        },
        other => panic!("expected DeferredStateTooLarge, got {other:?}"),
    }
}

#[test]
fn deferred_data_one_stack_and_memory_registration_are_equivalent() {
    use core::fmt::Write;

    let chunk = core::array::from_fn(|i| Felt::from_u32(11 + i as u32));
    let tag = Hash::digest_tag();
    let node = Hash::digest_node(chunk);
    let digest = node.digest();
    let ptr: u32 = 0;

    let mut src = String::from("begin\n");
    for (i, felt) in chunk.iter().enumerate() {
        writeln!(&mut src, "    push.{}", felt.as_canonical_u64()).unwrap();
        writeln!(&mut src, "    mem_store.{}", ptr + i as u32).unwrap();
    }

    emit_register_data(&mut src, tag, ptr);
    for _ in 0..5 {
        src.push_str("    drop\n");
    }

    emit_register(&mut src, node.clone());
    src.push_str("end\n");

    let program = assemble_test_program(&src);
    let mut host = DefaultHost::default();
    let mut output = build_hash_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    assert_eq!(output.deferred_state.evaluate(digest).unwrap(), node);
}

#[test]
fn data_register_reads_bulk_data_from_memory_and_materializes_node() {
    use core::fmt::Write;

    // Lay out two 8-felt chunks in MASM memory starting at address 0:
    //   chunk 0: limbs (1, 2, 3, 4, 5, 6, 7, 8)
    //   chunk 1: limbs (9, 10, 11, 12, 13, 14, 15, 16)
    let chunks: Vec<[Felt; 8]> = (0..2u32)
        .map(|i| core::array::from_fn(|j| Felt::from_u32(1 + i * 8 + j as u32)))
        .collect();
    let tag = preimage_tag(2);
    let ptr: u32 = 0;
    let data_node = Node::try_data(tag, chunks.clone()).unwrap();
    let data_digest = data_node.digest();
    let expected_canonical = Hash::digest_node(Hash::hash(&chunks));

    // Write the 16 felts to memory at addresses 0..16, register the data node, then drop the 5
    // felts left on the operand stack.
    let mut src = String::from("begin\n");
    for (i, felt) in chunks.iter().flatten().enumerate() {
        writeln!(&mut src, "    push.{}", felt.as_canonical_u64()).unwrap();
        writeln!(&mut src, "    mem_store.{}", ptr + i as u32).unwrap();
    }
    emit_register_data(&mut src, tag, ptr);
    for _ in 0..5 {
        src.push_str("    drop\n");
    }
    src.push_str("end\n");

    let program = assemble_test_program(&src);

    let mut host = DefaultHost::default();
    let mut output = build_hash_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    assert_eq!(output.deferred_state.node(&data_digest), Some(&data_node));
    let canonical = output.deferred_state.evaluate(data_digest).unwrap();
    assert_eq!(
        canonical, expected_canonical,
        "registered bulk data must evaluate to the hash digest of memory contents",
    );
}

#[test]
fn data_register_rejects_unaligned_pointer() {
    let tag = preimage_tag(1);
    let ptr: u32 = 1; // not word-aligned

    let mut src = String::from("begin\n");
    emit_register_data(&mut src, tag, ptr);
    src.push_str("end\n");

    let program = assemble_test_program(&src);
    let mut host = DefaultHost::default();
    let result = build_hash_processor().execute_sync(&program, &mut host);
    assert!(result.is_err(), "unaligned ptr must surface as an execution error");
}
