//! End-to-end coverage for deferred advice events on a real `FastProcessor`.
//!
//! Each test embeds the MASM program it runs as an inline template: the deferred events, stack
//! cleanup, advice captures, and memory addresses are written out literally, and only the numeric
//! push-lists (tags, digests, payloads) are interpolated. This keeps the executed program visible
//! at the test site. Low-level error and budget behavior lives in the handler and core tests;
//! transcript logging (`log_deferred`) is a separate concern owned by its dedicated tests.

use alloc::vec::Vec;

use miden_assembly::Assembler;
use miden_core::{
    deferred::{DataChunk, Node, PrecompileError, TRUE_DIGEST},
    program::Program,
    testing::precompile::{Group, Hash, Sig, Uint, mock_precompile_registry},
};
use miden_processor::{
    DefaultHost, ExecutionError, ExecutionOptions, ExecutionOutput, FastProcessor, Felt,
    StackInputs, advice::AdviceInputs,
};

extern crate alloc;

// FIXTURES
// ================================================================================================

/// A processor with every reference precompile installed.
fn build_mock_processor() -> FastProcessor {
    FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    )
    .expect("processor construction")
    .with_deferred_precompiles(mock_precompile_registry())
    .expect("mock precompile registration")
}

fn assemble_test_program(src: &str) -> Program {
    Assembler::default()
        .assemble_program("test", src)
        .expect("program must assemble")
        .unwrap_program()
}

/// Builds a uint value carrying `low` in its least-significant limbs.
fn uint_value(low: u64) -> Node {
    let mut limbs = [0u32; 8];
    limbs[0] = low as u32;
    limbs[1] = (low >> 32) as u32;
    Uint::value_node(limbs)
}

/// Builds `n` distinct 8-felt data chunks (first felt non-zero, so `Sig::verify` succeeds).
fn data_chunks(n: u32) -> Vec<DataChunk> {
    (0..n)
        .map(|i| core::array::from_fn(|j| Felt::from_u32(1 + i * 8 + j as u32)))
        .collect()
}

// MASM FORMATTERS
// ================================================================================================
//
// These format the numeric operands the templates interpolate; the deferred instructions themselves
// stay literal in each test.

/// Formats felts as a dotted `push` operand list in VM stack order, so `felts[0]` ends on top.
fn felt_list(felts: &[Felt]) -> String {
    felts
        .iter()
        .rev()
        .map(|f| f.as_canonical_u64().to_string())
        .collect::<Vec<_>>()
        .join(".")
}

/// Formats the three `push` instructions that lay out `[PAYLOAD_LO, PAYLOAD_HI, TAG]` for
/// `adv.register_deferred` (payload low half ends on top, tag deepest).
fn push_node(node: &Node) -> String {
    let felts = node.to_felts(); // tag(4) || payload(8)
    format!(
        "push.{} push.{} push.{}",
        felt_list(&node.tag().as_word()), // TAG (deepest)
        felt_list(&felts[8..12]),         // PAYLOAD_HI
        felt_list(&felts[4..8]),          // PAYLOAD_LO (top)
    )
}

/// Formats the `push`/`mem_store` pairs that write `chunks` to memory at `ptr`.
fn store_chunks(ptr: u32, chunks: &[DataChunk]) -> String {
    chunks
        .iter()
        .flatten()
        .enumerate()
        .map(|(i, felt)| format!("push.{} mem_store.{}", felt.as_canonical_u64(), ptr + i as u32))
        .collect::<Vec<_>>()
        .join("\n    ")
}

/// Reads `len` field elements from memory starting at `ptr`.
fn read_memory_felts(output: &ExecutionOutput, ptr: u32, len: usize) -> Vec<Felt> {
    let ctx = 0u32.into();
    (0..len as u32)
        .map(|i| output.memory.read_element(ctx, Felt::from_u32(ptr + i)).expect("memory read"))
        .collect()
}

fn payload_felts(node: &Node) -> Vec<Felt> {
    if node.is_true() {
        return Vec::new();
    }
    if let Ok(chunks) = node.payload().as_data() {
        return chunks.iter().flatten().copied().collect();
    }
    let (lhs, rhs) = node.payload().as_join().expect("non-TRUE/non-data nodes are joins");
    lhs.as_elements().iter().chain(rhs.as_elements()).copied().collect()
}

fn tag_felts(node: &Node) -> Vec<Felt> {
    node.tag().as_word().to_vec()
}

// HAPPY-PATH WORKFLOWS
// ================================================================================================

#[test]
fn uint_and_group_happy_path_returns_child_digests_that_can_be_evaluated() {
    // Build two group elements over uint coordinates, add them, and evaluate the sum. The canonical
    // sum is a `Group::new` over the two minted coordinate values; each returned child digest then
    // evaluates back to its uint value, and a group-equality assertion canonicalizes to TRUE.
    let dx1 = uint_value(3);
    let dy1 = uint_value(4);
    let dx2 = uint_value(10);
    let dy2 = uint_value(20);
    let g1 = Group::new_node(dx1.digest(), dy1.digest());
    let g2 = Group::new_node(dx2.digest(), dy2.digest());
    let add = Group::add_node(g1.digest(), g2.digest());
    let minted_x = uint_value(13);
    let minted_y = uint_value(24);
    let canonical_add = Group::new_node(minted_x.digest(), minted_y.digest());
    let eq = Group::eq_node(add.digest(), canonical_add.digest());

    let src = format!(
        "begin
    {reg_dx1} adv.register_deferred dropw dropw dropw
    {reg_dy1} adv.register_deferred dropw dropw dropw
    {reg_dx2} adv.register_deferred dropw dropw dropw
    {reg_dy2} adv.register_deferred dropw dropw dropw
    {reg_g1} adv.register_deferred dropw dropw dropw
    {reg_g2} adv.register_deferred dropw dropw dropw
    {reg_add} adv.register_deferred dropw dropw dropw
    push.{add_digest} adv.evaluate_deferred_payload dropw
    adv_pushw adv_pushw
    mem_storew_le.0 dropw
    mem_storew_le.4 dropw
    push.{minted_x_digest} adv.evaluate_deferred_payload dropw
    adv_pushw adv_pushw
    mem_storew_le.8 dropw
    mem_storew_le.12 dropw
    push.{minted_y_digest} adv.evaluate_deferred_payload dropw
    adv_pushw adv_pushw
    mem_storew_le.16 dropw
    mem_storew_le.20 dropw
    {reg_expected} adv.register_deferred dropw dropw dropw
    {reg_eq} adv.register_deferred dropw dropw dropw
    push.{eq_digest} adv.evaluate_deferred_payload dropw
end",
        reg_dx1 = push_node(&dx1),
        reg_dy1 = push_node(&dy1),
        reg_dx2 = push_node(&dx2),
        reg_dy2 = push_node(&dy2),
        reg_g1 = push_node(&g1),
        reg_g2 = push_node(&g2),
        reg_add = push_node(&add),
        add_digest = felt_list(add.digest().as_elements()),
        minted_x_digest = felt_list(minted_x.digest().as_elements()),
        minted_y_digest = felt_list(minted_y.digest().as_elements()),
        reg_expected = push_node(&canonical_add), // the expected group element == canonical sum
        reg_eq = push_node(&eq),
        eq_digest = felt_list(eq.digest().as_elements()),
    );

    let program = assemble_test_program(&src);
    let mut host = DefaultHost::default();
    let output = build_mock_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    // Payload-only canonical sum is `new(minted_x, minted_y)`: both minted coordinate child
    // digests.
    assert_eq!(read_memory_felts(&output, 0, 8), payload_felts(&canonical_add));
    // Each payload-only returned child digest evaluates back to its uint payload.
    assert_eq!(read_memory_felts(&output, 8, 8), payload_felts(&minted_x));
    assert_eq!(read_memory_felts(&output, 16, 8), payload_felts(&minted_y));
    // The equality assertion canonicalizes to TRUE, whose payload is empty, so no advice remains.
    assert_eq!(output.advice.stack(), Vec::<Felt>::new());

    // The framework state retains the original op, its canonical, and the minted coordinates.
    let ds = &output.deferred_state;
    assert_eq!(ds.get_node(&add.digest()), Some(&add));
    assert_eq!(ds.get_node(&canonical_add.digest()), Some(&canonical_add));
    assert_eq!(ds.get_node(&minted_x.digest()), Some(&minted_x));
    assert_eq!(ds.get_node(&minted_y.digest()), Some(&minted_y));
}

#[test]
fn hash_preimage_data_happy_path_checks_equality() {
    // Register a multi-chunk preimage from memory, evaluate it to its canonical digest value, then
    // prove a digest-equality assertion against an independently registered digest evaluates to
    // TRUE.
    let chunks = data_chunks(2);
    let preimage = Hash::preimage_node(2 * Hash::BYTES_PER_CHUNK, chunks.clone());
    let canonical = Hash::digest_node(Hash::hash(&chunks));
    let eq = Hash::eq_node(preimage.digest(), canonical.digest());

    let src = format!(
        "begin
    {store}
    push.{preimage_chunks} push.0 push.{preimage_tag} adv.register_deferred_data dropw drop drop
    push.{preimage_digest} adv.evaluate_deferred_payload dropw
    adv_pushw adv_pushw
    mem_storew_le.16 dropw
    mem_storew_le.20 dropw
    {reg_canonical} adv.register_deferred dropw dropw dropw
    {reg_eq} adv.register_deferred dropw dropw dropw
    push.{eq_digest} adv.evaluate_deferred_payload dropw
end",
        store = store_chunks(0, &chunks),
        preimage_chunks = chunks.len(),
        preimage_tag = felt_list(&preimage.tag().as_word()),
        preimage_digest = felt_list(preimage.digest().as_elements()),
        reg_canonical = push_node(&canonical),
        reg_eq = push_node(&eq),
        eq_digest = felt_list(eq.digest().as_elements()),
    );

    let program = assemble_test_program(&src);
    let mut host = DefaultHost::default();
    let output = build_mock_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    // The preimage payload-only evaluation returns the hash digest payload of its memory contents.
    assert_eq!(read_memory_felts(&output, 16, 8), payload_felts(&canonical));
    // The digest-equality assertion canonicalizes to TRUE, whose payload is empty.
    assert_eq!(output.advice.stack(), Vec::<Felt>::new());

    let mut ds = output.deferred_state;
    assert_eq!(ds.get_node(&preimage.digest()), Some(&preimage));
    assert_eq!(ds.get_node(&canonical.digest()), Some(&canonical));
    assert_eq!(ds.evaluate_digest(preimage.digest()).unwrap(), canonical.digest());
    assert_eq!(ds.evaluate_digest(eq.digest()).unwrap(), TRUE_DIGEST);
}

#[test]
fn evaluate_deferred_full_returns_canonical_tag_and_payload() {
    // A preimage node canonicalizes to a digest leaf. Full evaluation returns that canonical digest
    // leaf's tag first in advice-pop order, then its payload in the existing payload word order.
    let chunks = data_chunks(2);
    let preimage = Hash::preimage_node(2 * Hash::BYTES_PER_CHUNK, chunks.clone());
    let canonical = Hash::digest_node(Hash::hash(&chunks));

    let src = format!(
        "begin
    {store}
    push.{preimage_chunks} push.0 push.{preimage_tag} adv.register_deferred_data dropw drop drop
    push.{preimage_digest} adv.evaluate_deferred dropw
    adv_pushw adv_pushw adv_pushw
    mem_storew_le.16 dropw
    mem_storew_le.20 dropw
    mem_storew_le.24 dropw
end",
        store = store_chunks(0, &chunks),
        preimage_chunks = chunks.len(),
        preimage_tag = felt_list(&preimage.tag().as_word()),
        preimage_digest = felt_list(preimage.digest().as_elements()),
    );

    let program = assemble_test_program(&src);
    let mut host = DefaultHost::default();
    let output = build_mock_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    assert_eq!(read_memory_felts(&output, 16, 8), payload_felts(&canonical));
    assert_eq!(read_memory_felts(&output, 24, 4), tag_felts(&canonical));
    assert_eq!(output.advice.stack(), Vec::<Felt>::new());
}

#[test]
fn evaluate_deferred_tag_returns_canonical_tag_only() {
    // Tag-only evaluation returns the canonical digest leaf's tag and omits the payload entirely.
    let chunks = data_chunks(2);
    let preimage = Hash::preimage_node(2 * Hash::BYTES_PER_CHUNK, chunks.clone());
    let canonical = Hash::digest_node(Hash::hash(&chunks));

    let src = format!(
        "begin
    {store}
    push.{preimage_chunks} push.0 push.{preimage_tag} adv.register_deferred_data dropw drop drop
    push.{preimage_digest} adv.evaluate_deferred_tag dropw
    adv_pushw
    mem_storew_le.16 dropw
end",
        store = store_chunks(0, &chunks),
        preimage_chunks = chunks.len(),
        preimage_tag = felt_list(&preimage.tag().as_word()),
        preimage_digest = felt_list(preimage.digest().as_elements()),
    );

    let program = assemble_test_program(&src);
    let mut host = DefaultHost::default();
    let output = build_mock_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    assert_eq!(read_memory_felts(&output, 16, 4), tag_felts(&canonical));
    assert_eq!(output.advice.stack(), Vec::<Felt>::new());
}

#[test]
fn sig_verify_data_predicate_happy_path_returns_true() {
    // A memory-backed signature predicate registered via `adv.register_deferred_data` verifies
    // eagerly and evaluates to TRUE.
    let chunks = data_chunks(Sig::SIG_CHUNKS);
    let sig = Sig::verify_node(chunks.clone());

    let src = format!(
        "begin
    {store}
    push.{sig_chunks} push.0 push.{sig_tag} adv.register_deferred_data dropw drop drop
    push.{sig_digest} adv.evaluate_deferred_payload dropw
end",
        store = store_chunks(0, &chunks),
        sig_chunks = chunks.len(),
        sig_tag = felt_list(&sig.tag().as_word()),
        sig_digest = felt_list(sig.digest().as_elements()),
    );

    let program = assemble_test_program(&src);
    let mut host = DefaultHost::default();
    let output = build_mock_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    assert_eq!(output.advice.stack(), Vec::<Felt>::new());

    let mut ds = output.deferred_state;
    assert_eq!(ds.get_node(&sig.digest()), Some(&sig));
    assert_eq!(ds.evaluate_digest(sig.digest()).unwrap(), TRUE_DIGEST);
}

#[test]
fn deferred_evaluate_payload_true_digest_emits_no_advice() {
    // Payload-only evaluation of the implicit seeded TRUE node emits no advice because TRUE has no
    // payload.
    let src = format!(
        "begin
    push.{true_digest} adv.evaluate_deferred_payload dropw
end",
        true_digest = felt_list(TRUE_DIGEST.as_elements()),
    );

    let program = assemble_test_program(&src);
    let mut host = DefaultHost::default();
    let output = build_mock_processor()
        .execute_sync(&program, &mut host)
        .expect("execution must succeed");

    assert_eq!(output.advice.stack(), Vec::<Felt>::new());
}

// FAILURE SMOKE
// ================================================================================================

#[test]
fn mismatched_predicate_fails_during_register_deferred() {
    // With eager registration, a false predicate fails at the VM boundary during the register
    // event, not later at evaluation.
    let a = uint_value(7);
    let b = uint_value(8);
    let mismatch = Node::join(Uint::eq_tag(), a.digest(), b.digest()).unwrap();

    let src = format!(
        "begin
    {reg_a} adv.register_deferred dropw dropw dropw
    {reg_b} adv.register_deferred dropw dropw dropw
    {reg_mismatch} adv.register_deferred dropw dropw dropw
end",
        reg_a = push_node(&a),
        reg_b = push_node(&b),
        reg_mismatch = push_node(&mismatch),
    );

    let program = assemble_test_program(&src);
    let mut host = DefaultHost::default();
    match build_mock_processor().execute_sync(&program, &mut host) {
        Err(ExecutionError::DeferredError { err, .. }) => {
            assert!(matches!(err.root(), PrecompileError::AssertionFailed));
        },
        other => panic!("expected deferred assertion failure, got {other:?}"),
    }
}
