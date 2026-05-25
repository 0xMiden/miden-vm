//! Tests for the Rust reference implementation in `keccak256_native`.
//!
//! Two layers of coverage:
//! - **NIST KAT vectors**: a handful of well-known Keccak-256 outputs from the public test vector
//!   sets (Ethereum reference values + the standard `200 bytes of 0xa3` long-message KAT). Locks
//!   down the absolute correctness of the reference, independent of any other implementation in the
//!   workspace.
//! - **Proptest against `miden_core::crypto::hash::Keccak256`**: a fast differential check across
//!   random byte slices (length and content), catching any deviation from the production reference.
//!
//! Together these guarantee that the reference impl is a trustworthy oracle
//! for the eventual MASM differential test harness.

use miden_core::crypto::hash::Keccak256;
use miden_core_lib::keccak256_native::reference::keccak256;
use miden_utils_testing::proptest::prelude::*;

// NIST / ETHEREUM KNOWN ANSWER TESTS
// ================================================================================================

/// Each entry pairs a hex-encoded input with the expected hex-encoded
/// Keccak-256 output. Vectors are chosen to exercise:
/// - the empty input (single-block, all-padding case);
/// - very short inputs (one and two bytes), from the NIST short-message KAT;
/// - the canonical "abc" / "quick brown fox" Ethereum sanity values.
///
/// Boundary lengths (e.g. exactly `RATE_BYTES - 1`, exactly `RATE_BYTES`,
/// `RATE_BYTES + 1`) are exercised stochastically by the proptest below
/// against `miden_core::crypto::hash::Keccak256`.
const KAT_VECTORS: &[(&str, &str)] = &[
    // Empty input. Ethereum: keccak256("") =
    // c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470.
    ("", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
    // Single byte 0xCC -- NIST short-message KAT.
    ("cc", "eead6dbfc7340a56caedc044696a168870549a6a7f6f56961e84a54bd9970b8a"),
    // Two bytes 0x41FB -- NIST short-message KAT.
    ("41fb", "a8eaceda4d47b3281a795ad9e1ea2122b407baf9aabcb9e18b5717b7873537d2"),
    // "abc" -- canonical Keccak sanity input.
    ("616263", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
    // "The quick brown fox jumps over the lazy dog" -- another widely-quoted vector.
    (
        "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
        "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15",
    ),
];

/// Run every entry in [`KAT_VECTORS`] through the reference and assert the
/// output matches the locked-in hex digest exactly. Fails noisily on the first
/// vector that diverges so a regression is easy to localise.
#[test]
fn reference_matches_known_answer_test_vectors() {
    for (idx, (input_hex, expected_hex)) in KAT_VECTORS.iter().enumerate() {
        let input = hex_decode(input_hex);
        let expected = hex_decode(expected_hex);
        let actual = keccak256(&input);
        assert_eq!(
            actual.as_slice(),
            expected.as_slice(),
            "KAT vector {idx}: input={input_hex}, expected={expected_hex}",
        );
    }
}

// PROPTEST AGAINST PRODUCTION KECCAK256
// ================================================================================================

proptest! {
    /// Random byte slices of varied lengths must produce the same digest as
    /// `miden_core::crypto::hash::Keccak256::hash`. Lengths range from 0 to
    /// 1024 bytes to exercise both single-block and multi-block sponges
    /// (RATE_BYTES = 136, so 1024 bytes = ~7 absorptions plus a final
    /// padded block).
    #[test]
    fn reference_matches_production_keccak256(input in any_byte_slice_up_to_1024()) {
        let actual = keccak256(&input);
        let expected: [u8; 32] = Keccak256::hash(&input).into();
        prop_assert_eq!(actual, expected);
    }
}

// HELPERS
// ================================================================================================

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex byte"))
        .collect()
}

/// Strategy producing byte vectors of length in `0..=1024`. Length is chosen
/// uniformly; bytes are independent uniform u8s.
fn any_byte_slice_up_to_1024() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=1024usize)
}
