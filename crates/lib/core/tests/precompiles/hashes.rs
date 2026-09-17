use miden_core::{Felt, utils::bytes_to_packed_u32_elements};
use miden_core_lib::handlers::precompiles::keccak256::KECCAK256_DIGEST_EVENT_NAME;
use miden_crypto::hash::keccak::Keccak256;
use miden_event_handler::MAX_KECCAK_INPUT_BYTES;
use miden_processor::ExecutionError;

use super::helpers::{
    TRUNCATE_STACK_TO_OUTPUT_PROC, assert_deferred_state_round_trips, masm_store_felts,
    read_memory_felts, read_stack_felts, run_precompile_program,
};

const IN_PTR: u32 = 128;
const OUT_PTR: u32 = 256;
const DIGEST_FELTS: usize = 8;
const BYTES_PER_FELT: usize = 4;

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
fn keccak_input_limit_is_inclusive_and_checked_before_memory() {
    // An unaligned pointer makes the exact-limit case stop before allocating the preimage.
    for (len_bytes, expected) in [
        (
            MAX_KECCAK_INPUT_BYTES,
            "address 1 is not word-aligned (must be divisible by 4)".to_owned(),
        ),
        (
            MAX_KECCAK_INPUT_BYTES + 1,
            format!(
                "keccak256 input length {} bytes exceeds maximum of {MAX_KECCAK_INPUT_BYTES} bytes",
                MAX_KECCAK_INPUT_BYTES + 1
            ),
        ),
    ] {
        let source =
            format!("begin push.{len_bytes}.1 emit.event(\"{KECCAK256_DIGEST_EVENT_NAME}\") end");
        let Err(ExecutionError::EventError { error, .. }) = run_precompile_program(&source) else {
            panic!("Keccak input should fail before reading memory");
        };
        assert_eq!(error.to_string(), expected);
    }
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
            153,
        ),
        (
            "keccak_hash_2_chunks_mem",
            cycle_hash_mem_source("keccak256", "hash_2_chunks_mem", &bytes64),
            153,
        ),
        (
            "keccak_hash_bytes_mem_short",
            cycle_hash_mem_source("keccak256", "hash_bytes_mem", short),
            200,
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
