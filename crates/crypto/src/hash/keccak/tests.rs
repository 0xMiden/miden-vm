#![cfg(feature = "std")]
use alloc::vec::Vec;

use proptest::prelude::*;

use super::*;
use crate::rand::test_utils::rand_vector;

#[test]
fn keccak256_hash_elements() {
    // test multiple of 8
    let elements = rand_vector::<Felt>(16);
    let expected = compute_expected_element_hash(&elements);
    let actual: [u8; 32] = hash_elements(&elements);
    assert_eq!(&expected, &actual);

    // test not multiple of 8
    let elements = rand_vector::<Felt>(17);
    let expected = compute_expected_element_hash(&elements);
    let actual: [u8; 32] = hash_elements(&elements);
    assert_eq!(&expected, &actual);
}

proptest! {
    #[test]
    fn keccak256_wont_panic_with_arbitrary_input(ref vec in any::<Vec<u8>>()) {
        Keccak256::hash(vec);
    }

    #[test]
    fn keccak256_hash_iter_matches_hash(ref slices in any::<Vec<Vec<u8>>>()) {
        // Test that hash_iter produces the same result as concatenating all slices

        // Concatenate all slices to create the expected result using the original hash method
        let mut concatenated = Vec::new();
        for slice in slices.iter() {
            concatenated.extend_from_slice(slice);
        }
        let expected = Keccak256::hash(&concatenated);

        // Test with the original iterator of slices
        let actual = Keccak256::hash_iter(slices.iter().map(Vec::as_slice));
        assert_eq!(expected, actual);

        // Test with empty slices list (should produce hash of empty string)
        let empty_actual = Keccak256::hash_iter(core::iter::empty());
        let empty_expected = Keccak256::hash(b"");
        assert_eq!(empty_expected, empty_actual);

        // Test with single slice (should be identical to hash)
        if let Some(single_slice) = slices.first() {
            let single_actual = Keccak256::hash_iter(core::iter::once(single_slice.as_slice()));
            let single_expected = Keccak256::hash(single_slice);
            assert_eq!(single_expected, single_actual);
        }
    }
}

#[test]
fn test_nist_test_vectors() {
    for (i, vector) in NIST_TEST_VECTORS.iter().enumerate() {
        let result = Keccak256::hash(vector.input);
        let expected = hex::decode(vector.expected).unwrap();
        assert_eq!(
            result.to_vec(),
            expected,
            "NIST test vector {} failed: {}",
            i,
            vector.description
        );
    }
}

#[test]
fn test_ethereum_test_vectors() {
    for (i, vector) in ETHEREUM_TEST_VECTORS.iter().enumerate() {
        let result = Keccak256::hash(vector.input);
        let expected = hex::decode(vector.expected).unwrap();
        assert_eq!(
            result.to_vec(),
            expected,
            "Ethereum test vector {} failed: {}",
            i,
            vector.description
        );
    }
}

// HELPER FUNCTION AND STRUCT
// ================================================================================================

fn compute_expected_element_hash(elements: &[Felt]) -> [u8; DIGEST256_BYTES] {
    let mut bytes = Vec::new();
    for element in elements.iter() {
        bytes.extend_from_slice(&element.as_canonical_u64().to_le_bytes());
    }
    let mut hasher = sha3::Keccak256::new();
    hasher.update(&bytes);

    hasher.finalize().into()
}

struct TestVector {
    input: &'static [u8],
    expected: &'static str,
    description: &'static str,
}

// TEST VECTORS
// ================================================================================================

// Derived from the wrapped implementation
const NIST_TEST_VECTORS: &[TestVector] = &[
    TestVector {
        input: b"",
        expected: "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        description: "Empty input",
    },
    TestVector {
        input: b"a",
        expected: "3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb",
        description: "Single byte 'a'",
    },
    TestVector {
        input: b"abc",
        expected: "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        description: "String 'abc'",
    },
];

// Fetched from https://docs.ethers.org/v5/api/utils/hashing/
const ETHEREUM_TEST_VECTORS: &[TestVector] = &[
    TestVector {
        input: b"\x19Ethereum Signed Message:\n11Hello World",
        expected: "a1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2",
        description: "Ethereum signed message prefix: Hello World",
    },
    TestVector {
        input: b"\x19Ethereum Signed Message:\n40x42",
        expected: "f0d544d6e4a96e1c08adc3efabe2fcb9ec5e28db1ad6c33ace880ba354ab0fce",
        description: "Ethereum signed message prefix: `[0, x, 4, 2]` sequence of characters ",
    },
    TestVector {
        input: b"\x19Ethereum Signed Message:\n1B",
        expected: "d18c12b87124f9ceb7e1d3a5d06a5ac92ecab15931417e8d1558d9a263f99d63",
        description: "Ethereum signed message prefix: `0x42` byte in UTF-8",
    },
];
