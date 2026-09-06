use miden_core::{Felt, deferred::Node, utils::bytes_to_packed_u32_elements};
use miden_crypto::hash::keccak::Keccak256;
use miden_precompiles::{
    CurveId, CurvePrecompile, Keccak256Precompile, UintDomain, UintPrecompile,
};
use miden_processor::{ExecutionError, operation::OperationError};

use super::helpers::{
    TRUNCATE_STACK_TO_OUTPUT_PROC, assert_deferred_state_round_trips, masm_store_felts,
    read_memory_felts, read_stack_felts, run_precompile_program,
};

const IN_PTR: u32 = 128;
const OUT_PTR: u32 = 256;
const DIGEST_FELTS: usize = 8;
const BYTES_PER_FELT: usize = 4;

#[test]
fn deferred_chunks_digest_matches_host() {
    assert_deferred_chunks_digest_matches_host(1);
}

#[test]
fn deferred_two_chunks_digest_matches_host() {
    assert_deferred_chunks_digest_matches_host(2);
}

#[test]
fn deferred_three_chunks_digest_matches_host() {
    assert_deferred_chunks_digest_matches_host(3);
}

#[test]
fn deferred_dynamic_chunks_digest_matches_host() {
    assert_deferred_chunks_digest_matches_host(4);
}

#[test]
fn deferred_dynamic_chunks_rejects_encoded_length_overflow() {
    let num_chunks = u32::MAX / 8 + 1;
    let source = format!(
        "begin push.{num_chunks} push.{IN_PTR} exec.::miden::core::precompiles::register_chunks_mem end"
    );

    let error = run_precompile_program(&source).expect_err("encoded length overflow must trap");
    let expected_error_code =
        miden_core::mast::error_code_from_msg("Deferred CHUNKS length must fit in u32");
    assert!(
        matches!(
            error,
            ExecutionError::OperationError {
                err: OperationError::U32AssertionFailed { err_code, .. },
                ..
            } if err_code == expected_error_code
        ),
        "encoded length overflow reached the wrong guard: {error:?}",
    );
}

fn assert_deferred_chunks_digest_matches_host(num_chunks: usize) {
    let chunks = (0..num_chunks)
        .map(|chunk| core::array::from_fn(|i| Felt::from_u32((chunk * 8 + i + 1) as u32)))
        .collect::<Vec<_>>();
    let stores = masm_store_felts(&chunks.concat(), IN_PTR);
    let register = if num_chunks <= 3 {
        format!("push.{IN_PTR}\nexec.::miden::core::precompiles::register_chunks_mem_{num_chunks}")
    } else {
        format!(
            "push.{num_chunks} push.{IN_PTR}\nexec.::miden::core::precompiles::register_chunks_mem"
        )
    };
    let source = format!(
        r#"
        begin
            {stores}
            {register}
            swapw dropw
        end
        "#,
    );

    let output = run_precompile_program(&source).expect("CHUNKS registration must execute");
    let expected = Node::chunks(chunks).expect("non-empty CHUNKS node").digest();
    assert_eq!(read_stack_felts(&output, 4), expected.as_elements());
}

#[test]
fn deferred_expression_digest_matches_host() {
    let input: Vec<u8> = (0u8..32).collect();
    let input_chunk: [Felt; 8] = bytes_to_packed_u32_elements(&input).try_into().unwrap();
    let output_chunk: [Felt; 8] = bytes_to_packed_u32_elements(Keccak256::hash(&input).as_ref())
        .try_into()
        .unwrap();
    let stores = format!(
        "{}\n{}",
        masm_store_felts(&input_chunk, IN_PTR),
        masm_store_felts(&output_chunk, OUT_PTR),
    );
    let frame = Keccak256Precompile::assert_frame(input.len() as u32).as_word();
    let frame = frame
        .iter()
        .rev()
        .map(Felt::as_canonical_u64)
        .map(|felt| felt.to_string())
        .collect::<Vec<_>>()
        .join(".");
    let source = format!(
        r#"
        begin
            {stores}
            push.{IN_PTR}
            exec.::miden::core::precompiles::register_chunks_mem_1
            push.{OUT_PTR}
            exec.::miden::core::precompiles::register_chunks_mem_1
            swapw
            push.{frame}
            exec.::miden::core::precompiles::register_expr
            swapw dropw
        end
        "#,
    );

    let output = run_precompile_program(&source).expect("expression registration must execute");
    let input_digest = Node::chunks(vec![input_chunk]).unwrap().digest();
    let output_digest = Node::chunks(vec![output_chunk]).unwrap().digest();
    let expected =
        Keccak256Precompile::assert_node(input.len() as u32, input_digest, output_digest).digest();
    assert_eq!(read_stack_felts(&output, 4), expected.as_elements());
}

#[test]
fn deferred_memory_value_digest_matches_host() {
    let limbs = core::array::from_fn(|i| (i + 1) as u32);
    let chunk = limbs.map(Felt::from_u32);
    let stores = masm_store_felts(&chunk, IN_PTR);
    let cv = UintPrecompile::value_frame(UintDomain::U256).initial_chaining_word();
    let cv = cv
        .iter()
        .rev()
        .map(Felt::as_canonical_u64)
        .map(|felt| felt.to_string())
        .collect::<Vec<_>>()
        .join(".");
    let source = format!(
        r#"
        begin
            {stores}
            push.1 push.{IN_PTR} push.{cv}
            exec.::miden::core::precompiles::register_mem
            swapw dropw
        end
        "#,
    );

    let output = run_precompile_program(&source).expect("memory registration must execute");
    let expected = UintPrecompile::value_node(UintDomain::U256, limbs).digest();
    assert_eq!(read_stack_felts(&output, 4), expected.as_elements());
}

#[test]
fn deferred_memory_pair_list_digest_matches_host_for_multiple_blocks() {
    let curve = CurveId::Secp256k1;
    let generator = CurvePrecompile::generator_node(curve).digest();
    let scalar_one =
        UintPrecompile::value_node(UintDomain::K1Scalar, [1, 0, 0, 0, 0, 0, 0, 0]).digest();
    let scalar_two =
        UintPrecompile::value_node(UintDomain::K1Scalar, [2, 0, 0, 0, 0, 0, 0, 0]).digest();
    let two_generator =
        Node::try_pair_list(CurvePrecompile::msm_frame(1), vec![(generator, scalar_two)])
            .expect("curve MSM frame must accept a pair list")
            .digest();
    let pairs = vec![(generator, scalar_one), (two_generator, scalar_two)];
    let payload = pairs
        .iter()
        .flat_map(|(point, scalar)| point.as_elements().iter().chain(scalar.as_elements()).copied())
        .collect::<Vec<_>>();
    let stores = masm_store_felts(&payload, IN_PTR);
    let cv = CurvePrecompile::msm_frame(2)
        .initial_chaining_word()
        .iter()
        .rev()
        .map(Felt::as_canonical_u64)
        .map(|felt| felt.to_string())
        .collect::<Vec<_>>()
        .join(".");
    let source = format!(
        r#"
        begin
            {stores}

            exec.::miden::core::precompiles::fields::k1_scalar::push_two_digest
            exec.::miden::core::precompiles::curves::secp256k1::mul_scalar_generator
            dropw

            push.2 push.{IN_PTR} push.{cv}
            exec.::miden::core::precompiles::register_mem
            swapw dropw
        end
        "#,
    );

    let output = run_precompile_program(&source).expect("pair-list registration must execute");
    let expected = Node::try_pair_list(CurvePrecompile::msm_frame(2), pairs)
        .expect("curve MSM frame must accept a pair list")
        .digest();
    assert_eq!(read_stack_felts(&output, 4), expected.as_elements());
}

#[test]
fn keccak_hash_1_chunk_mem_writes_expected_digest() {
    let input: Vec<u8> = (0u8..32).collect();

    let keccak = run_hash_mem("keccak256", "hash_1_chunk_mem", &input, 0)
        .expect("keccak256::hash_1_chunk_mem must execute");
    assert_eq!(keccak, pack_digest(&Keccak256::hash(&input)));
}

#[test]
fn keccak_hash_bytes_mem_handles_short_preimages() {
    let input = b"hash wrapper coverage";

    let keccak = run_hash_mem("keccak256", "hash_bytes_mem", input, 0)
        .expect("keccak256::hash_bytes_mem must execute");
    assert_eq!(keccak, pack_digest(&Keccak256::hash(input)));
}

#[test]
fn keccak_hash_2_chunks_mem_hashes_concatenated_inputs() {
    let left: Vec<u8> = (0u8..32).collect();
    let right: Vec<u8> = (32u8..64).collect();
    let mut preimage = left;
    preimage.extend_from_slice(&right);

    let output = run_hash_mem("keccak256", "hash_2_chunks_mem", &preimage, 0)
        .expect("keccak256::hash_2_chunks_mem must execute");
    assert_eq!(output, pack_digest(&Keccak256::hash(&preimage)));
}

/// The wrapper must accept preimage memory that was never written to, matching the in-VM rule
/// that unwritten memory reads as zero.
#[test]
fn keccak_hash_bytes_mem_hashes_never_written_region() {
    const UNWRITTEN_FELTS: usize = 8;
    let preimage = vec![0u8; UNWRITTEN_FELTS * BYTES_PER_FELT];

    let output = run_hash_mem("keccak256", "hash_bytes_mem", &[], UNWRITTEN_FELTS)
        .expect("keccak256::hash_bytes_mem must execute");
    assert_eq!(output, pack_digest(&Keccak256::hash(&preimage)));
}

/// Same as above, but the preimage starts with non-zero elements that are written to memory, so
/// only its tail relies on unwritten memory.
#[test]
fn keccak_hash_2_chunks_mem_hashes_never_written_tail() {
    const UNWRITTEN_FELTS: usize = 8;
    let written: Vec<u8> = (1u8..=32).collect();
    let mut preimage = written.clone();
    preimage.resize(written.len() + UNWRITTEN_FELTS * BYTES_PER_FELT, 0);

    let output = run_hash_mem("keccak256", "hash_2_chunks_mem", &written, UNWRITTEN_FELTS)
        .expect("keccak256::hash_2_chunks_mem must execute");
    assert_eq!(output, pack_digest(&Keccak256::hash(&preimage)));
}

/// Hashes `input` followed by `trailing_zero_felts` zero elements which the test program does not
/// write to memory, so that they rely on zero-initialized VM memory.
fn run_hash_mem(
    module: &str,
    proc: &str,
    input: &[u8],
    trailing_zero_felts: usize,
) -> Result<Vec<Felt>, ExecutionError> {
    let input_felts = bytes_to_packed_u32_elements(input);
    let stores = masm_store_felts(&input_felts, IN_PTR);
    let source = format!(
        r#"
        begin
            {stores}
            push.{OUT_PTR}
            push.{len_bytes}
            push.{IN_PTR}
            exec.::miden::core::precompiles::hashes::{module}::{proc}
        end
        "#,
        len_bytes = input.len() + trailing_zero_felts * BYTES_PER_FELT,
    );

    let output = run_precompile_program(&source)?;
    assert_deferred_state_round_trips(&output);
    Ok(read_memory_felts(&output, OUT_PTR, DIGEST_FELTS))
}

fn pack_digest(bytes: &[u8]) -> Vec<Felt> {
    bytes_to_packed_u32_elements(bytes)
}

#[test]
fn hash_precompile_cycle_baselines() {
    let input: Vec<u8> = (0u8..32).collect();
    let left: Vec<u8> = (0u8..32).collect();
    let right: Vec<u8> = (32u8..64).collect();
    let mut bytes64 = left;
    bytes64.extend_from_slice(&right);
    let short = b"hash wrapper coverage";

    let mut mismatches = Vec::new();
    for (name, source, expected) in [
        (
            "keccak_hash_1_chunk_mem",
            cycle_hash_mem_source("keccak256", "hash_1_chunk_mem", &input),
            136,
        ),
        (
            "keccak_hash_2_chunks_mem",
            cycle_hash_mem_source("keccak256", "hash_2_chunks_mem", &bytes64),
            136,
        ),
        (
            "keccak_hash_bytes_mem_short",
            cycle_hash_mem_source("keccak256", "hash_bytes_mem", short),
            195,
        ),
    ] {
        let output =
            run_precompile_program(&source).unwrap_or_else(|err| panic!("{name} failed: {err:?}"));
        let cycles = read_stack_felts(&output, 1)[0].as_canonical_u64();
        if cycles != expected {
            mismatches.push(format!("{name}: expected {expected}, got {cycles}"));
        }
    }

    assert!(mismatches.is_empty(), "cycle count changed:\n{}", mismatches.join("\n"));
}

fn cycle_hash_mem_source(module: &str, proc: &str, input: &[u8]) -> String {
    let input_felts = bytes_to_packed_u32_elements(input);
    let stores = masm_store_felts(&input_felts, IN_PTR);
    format!(
        r#"
        {TRUNCATE_STACK_TO_OUTPUT_PROC}
        begin
            {stores}
            push.{OUT_PTR}
            push.{len_bytes}
            push.{IN_PTR}
            clk push.512 mem_store
            exec.::miden::core::precompiles::hashes::{module}::{proc}
            clk push.512 mem_load sub
            exec.truncate_stack_to_output
        end
        "#,
        len_bytes = input.len(),
        module = module,
        proc = proc,
    )
}
