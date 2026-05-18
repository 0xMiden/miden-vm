//! Differential tests for the MASM Keccak-256 implementation against the Rust
//! reference in [`miden_core_lib::keccak256_native::reference`] and against
//! standard published NIST / Ethereum KATs.
//!
//! Coverage:
//! - **Boundary lengths**: every length that exercises a distinct padding or
//!   block-loop path (empty, 1, 2, 31, 32, 60, 135, 136, 137, 270, 271, 272).
//! - **Published KATs**: a handful of NIST short-message vectors plus the
//!   canonical "abc" / "quick brown fox" Ethereum sanity values, hashed via
//!   the MASM proc and checked against externally-published digests. Catches
//!   any bug that the MASM-vs-reference diff would miss because both share it.
//! - **Random inputs**: a low-case-count proptest of MASM vs reference for
//!   random byte slices in `0..=300`, hitting interior lengths the fixtures
//!   don't cover.

use miden_core::Felt;
use miden_core::advice::AdviceInputs;
use miden_core_lib::keccak256_native::reference::keccak256;
use miden_utils_testing::proptest::prelude::*;

/// Absolute memory address where the harness stages the input bytes (u32-packed).
/// Chosen well outside any range used by the Keccak proc's proc-local memory.
const INPUT_ADDR: u32 = 6000;

// HARNESS
// ================================================================================================

/// Pack a byte slice into u32-packed felts (4 little-endian bytes per felt;
/// trailing bytes of the final partial u32 are zero, per the proc's contract).
fn bytes_to_u32_felts(input: &[u8]) -> Vec<Felt> {
    let n_u32 = input.len().div_ceil(4);
    let mut out = Vec::with_capacity(n_u32);
    for chunk in input.chunks(4) {
        let mut bytes = [0u8; 4];
        bytes[..chunk.len()].copy_from_slice(chunk);
        out.push(Felt::from_u32(u32::from_le_bytes(bytes)));
    }
    out
}

/// Run `keccak256_bytes` in MASM on `input` and compare against the Rust ref.
/// Panics on mismatch with both digests printed in hex for diagnostic ease.
fn assert_masm_keccak_matches_reference(input: &[u8]) {
    let input_u32s = bytes_to_u32_felts(input);
    let len_bytes = input.len();

    // Build the wrapper: stage input u32s at INPUT_ADDR..INPUT_ADDR+n_u32, then
    // call keccak256_bytes with (src_ptr=INPUT_ADDR, len_bytes).
    let mut src = String::new();
    src.push_str("use miden::core::crypto::hashes::keccak256_native\n");
    src.push_str("use miden::core::sys\n\n");
    src.push_str("begin\n");
    let n_words = input_u32s.len() / 4;
    let n_tail = input_u32s.len() % 4;
    for w in 0..n_words {
        src.push_str(&format!(
            "    adv_pushw  push.{addr}  mem_storew_le  dropw\n",
            addr = INPUT_ADDR + 4 * w as u32
        ));
    }
    for t in 0..n_tail {
        src.push_str(&format!(
            "    adv_push   push.{addr}  mem_store\n",
            addr = INPUT_ADDR + (4 * n_words as u32) + t as u32
        ));
    }
    src.push_str(&format!(
        "    push.{len_bytes}  push.{INPUT_ADDR}  exec.keccak256_native::keccak256_bytes\n"
    ));
    src.push_str("    exec.sys::truncate_stack\n");
    src.push_str("end\n");

    let mut test = build_debug_test!(&src, &[]);
    test.advice_inputs = AdviceInputs::default().with_stack(input_u32s);

    let (output, _) = test
        .execute_for_output()
        .unwrap_or_else(|err| panic!("MASM execution failed for len={len_bytes}: {err}"));
    let stack = &output.stack;

    let mut actual_bytes = [0u8; 32];
    for k in 0..8 {
        let u32val = stack
            .get_element(k)
            .unwrap_or_else(|| panic!("missing stack output {k} for len={len_bytes}"))
            .as_canonical_u64() as u32;
        actual_bytes[4 * k..4 * (k + 1)].copy_from_slice(&u32val.to_le_bytes());
    }
    let expected = keccak256(input);

    if actual_bytes != expected {
        panic!(
            "MASM keccak256_bytes diverged from reference for len={len_bytes}\n\
             input    : {}\n\
             expected : {}\n\
             actual   : {}",
            hex_str(input),
            hex_str(&expected),
            hex_str(&actual_bytes),
        );
    }
}

fn hex_str(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 * bytes.len());
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex byte"))
        .collect()
}

// BOUNDARY-LENGTH FIXTURES
// ================================================================================================

#[test]
fn masm_keccak256_bytes_empty() {
    assert_masm_keccak_matches_reference(&[]);
}

#[test]
fn masm_keccak256_bytes_one_byte() {
    assert_masm_keccak_matches_reference(&[0x5a]);
}

#[test]
fn masm_keccak256_bytes_two_bytes() {
    assert_masm_keccak_matches_reference(&[0x41, 0xfb]);
}

#[test]
fn masm_keccak256_bytes_aligned_32_bytes() {
    let input: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(31).wrapping_add(7));
    assert_masm_keccak_matches_reference(&input);
}

#[test]
fn masm_keccak256_bytes_unaligned_31_bytes() {
    let input: [u8; 31] = core::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(3));
    assert_masm_keccak_matches_reference(&input);
}

#[test]
fn masm_keccak256_bytes_60_bytes() {
    let input: Vec<u8> = (0..60u8).map(|i| i.wrapping_mul(31).wrapping_add(7)).collect();
    assert_masm_keccak_matches_reference(&input);
}

#[test]
fn masm_keccak256_bytes_one_full_block_minus_one_byte() {
    // 135 bytes: padding spans a single block (the padding byte fits in the
    // same block as the message).
    let input: Vec<u8> = (0..135u8).map(|i| i.wrapping_mul(13).wrapping_add(5)).collect();
    assert_masm_keccak_matches_reference(&input);
}

#[test]
fn masm_keccak256_bytes_exactly_one_full_block() {
    // 136 bytes: message fills the block exactly; padding occupies a fresh block.
    let input: Vec<u8> = (0..136u8).map(|i| i.wrapping_mul(19).wrapping_add(11)).collect();
    assert_masm_keccak_matches_reference(&input);
}

#[test]
fn masm_keccak256_bytes_one_full_block_plus_one_byte() {
    // 137 bytes: one full block absorbed, then a single-byte tail with padding.
    let input: Vec<u8> = (0..137u8).map(|i| i.wrapping_mul(23).wrapping_add(13)).collect();
    assert_masm_keccak_matches_reference(&input);
}

#[test]
fn masm_keccak256_bytes_two_full_blocks_minus_two_bytes() {
    // 270 bytes: one full block absorbed, second block holds 134-byte tail +
    // padding spread across the last two u32s.
    let input: Vec<u8> =
        (0..270).map(|i| ((i as u32).wrapping_mul(31).wrapping_add(7)) as u8).collect();
    assert_masm_keccak_matches_reference(&input);
}

#[test]
fn masm_keccak256_bytes_two_full_blocks_minus_one_byte() {
    // 271 bytes: padding byte and final-bit marker collapse into the same u32.
    let input: Vec<u8> =
        (0..271).map(|i| ((i as u32).wrapping_mul(37).wrapping_add(11)) as u8).collect();
    assert_masm_keccak_matches_reference(&input);
}

#[test]
fn masm_keccak256_bytes_two_full_blocks() {
    // 272 bytes: two full blocks absorbed; padding occupies a fresh third block.
    let input: Vec<u8> =
        (0..272).map(|i| ((i as u32).wrapping_mul(41).wrapping_add(17)) as u8).collect();
    assert_masm_keccak_matches_reference(&input);
}

// PUBLISHED KNOWN-ANSWER TESTS
// ================================================================================================

/// `(input_hex, expected_digest_hex)`. Vectors are widely-published Keccak-256
/// outputs from NIST short-message KATs and the canonical Ethereum sanity inputs.
const KECCAK256_KATS: &[(&str, &str)] = &[
    // Empty input.
    ("", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
    // NIST short-message: one byte 0xCC.
    ("cc", "eead6dbfc7340a56caedc044696a168870549a6a7f6f56961e84a54bd9970b8a"),
    // NIST short-message: two bytes 0x41FB.
    ("41fb", "a8eaceda4d47b3281a795ad9e1ea2122b407baf9aabcb9e18b5717b7873537d2"),
    // "abc".
    ("616263", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
    // "The quick brown fox jumps over the lazy dog".
    (
        "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
        "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15",
    ),
];

#[test]
fn masm_keccak256_bytes_matches_published_kats() {
    for (idx, (input_hex, expected_hex)) in KECCAK256_KATS.iter().enumerate() {
        let input = hex_decode(input_hex);
        let expected = hex_decode(expected_hex);

        // Sanity-check the reference against the published digest first, so a
        // reference regression doesn't get mistaken for a MASM bug.
        let ref_digest = keccak256(&input);
        assert_eq!(
            ref_digest.as_slice(),
            expected.as_slice(),
            "KAT {idx}: Rust reference disagrees with published digest for input={input_hex}\n  \
             expected: {expected_hex}\n  actual  : {actual}",
            actual = hex_str(&ref_digest),
        );
        // Pin MASM to the same published digest via the differential helper.
        assert_masm_keccak_matches_reference(&input);
    }
}

// CYCLE BENCHMARKS
// ================================================================================================

/// Builds the standard "clk; staging; clk; truncate" wrapper used to time a
/// single MASM invocation.
fn cycle_benchmark_source(input_staging: &str, invocation: &str) -> String {
    format!(
        "
            use miden::core::crypto::hashes::keccak256_native
            use miden::core::sys

            begin
                {input_staging}

                clk
                {invocation}
                clk
                exec.sys::truncate_stack
            end
        "
    )
}

fn extract_cycle_delta(output: &miden_processor::ExecutionOutput) -> u64 {
    let stack = &output.stack;
    let t1 = stack.get_element(0).expect("t1 missing").as_canonical_u64();
    let t0 = stack.get_element(1).expect("t0 missing").as_canonical_u64();
    t1 - t0
}

#[test]
#[ignore = "benchmark; run with --ignored to print cycle count"]
fn bench_keccak256_bytes_32_bytes() {
    let msg: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
    let msg_u32s = bytes_to_u32_felts(&msg);

    let input_staging = format!(
        "adv_pushw  push.{addr}  mem_storew_le  dropw\n\
         adv_pushw  push.{addr2} mem_storew_le  dropw\n",
        addr = INPUT_ADDR,
        addr2 = INPUT_ADDR + 4,
    );
    let invocation = format!(
        "push.32  push.{INPUT_ADDR}  exec.keccak256_native::keccak256_bytes\n\
         drop drop drop drop drop drop drop drop"
    );
    let source = cycle_benchmark_source(&input_staging, &invocation);

    let mut test = build_debug_test!(&source, &[]);
    test.advice_inputs = AdviceInputs::default().with_stack(msg_u32s);
    let (output, _) = test.execute_for_output().unwrap();
    eprintln!("keccak256_bytes (32 bytes) cycles: {}", extract_cycle_delta(&output));
}

#[test]
#[ignore = "benchmark; run with --ignored to print cycle count"]
fn bench_keccak256_bytes_60_bytes() {
    // 60 bytes = 15 u32s = 3 full words + 3 tail felts.
    let input: Vec<u8> = (0..60u8).collect();
    let input_u32s = bytes_to_u32_felts(&input);

    let mut input_staging = String::new();
    for w in 0..3 {
        input_staging.push_str(&format!(
            "adv_pushw  push.{addr}  mem_storew_le  dropw\n",
            addr = INPUT_ADDR + 4 * w as u32
        ));
    }
    for t in 0..3 {
        input_staging.push_str(&format!(
            "adv_push   push.{addr}  mem_store\n",
            addr = INPUT_ADDR + 12 + t as u32
        ));
    }
    let invocation = format!(
        "push.60  push.{INPUT_ADDR}  exec.keccak256_native::keccak256_bytes\n\
         drop drop drop drop drop drop drop drop"
    );
    let source = cycle_benchmark_source(&input_staging, &invocation);

    let mut test = build_debug_test!(&source, &[]);
    test.advice_inputs = AdviceInputs::default().with_stack(input_u32s);
    let (output, _) = test.execute_for_output().unwrap();
    eprintln!("keccak256_bytes (60 bytes) cycles: {}", extract_cycle_delta(&output));
}

// MASM-VS-REFERENCE PROPTEST (random inputs)
// ================================================================================================

proptest! {
    // MASM execution is slow relative to native, so the case count is capped low.
    // The fixed-fixture tests above cover boundary lengths exhaustively; this
    // proptest exists to catch interior-length bugs that the fixtures might miss.
    #![proptest_config(ProptestConfig::with_cases(8))]

    /// MASM `keccak256_bytes` output must match the Rust reference on random byte slices.
    /// Length range covers single-block (< 136 bytes), exact-block, and multi-block paths.
    #[test]
    fn masm_keccak256_bytes_matches_reference_proptest(
        input in prop::collection::vec(any::<u8>(), 0..=300usize),
    ) {
        assert_masm_keccak_matches_reference(&input);
    }
}
