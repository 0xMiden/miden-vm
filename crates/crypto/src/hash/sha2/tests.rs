#![cfg(feature = "std")]
use alloc::vec::Vec;

use proptest::prelude::*;

use super::*;
use crate::rand::test_utils::rand_vector;

// SHA-256 TESTS
// ================================================================================================

#[test]
fn sha256_hash_elements() {
    // test multiple of 8
    let elements = rand_vector::<Felt>(16);
    let expected = compute_expected_sha256_element_hash(&elements);
    let actual: [u8; DIGEST256_BYTES] = hash_elements_256(&elements);
    assert_eq!(&expected, &actual);

    // test not multiple of 8
    let elements = rand_vector::<Felt>(17);
    let expected = compute_expected_sha256_element_hash(&elements);
    let actual: [u8; DIGEST256_BYTES] = hash_elements_256(&elements);
    assert_eq!(&expected, &actual);
}

proptest! {
    #[test]
    fn sha256_wont_panic_with_arbitrary_input(ref vec in any::<Vec<u8>>()) {
        Sha256::hash(vec);
    }

    #[test]
    fn sha256_hash_iter_matches_hash(ref slices in any::<Vec<Vec<u8>>>()) {
        // Concatenate all slices to create the expected result
        let mut concatenated = Vec::new();
        for slice in slices.iter() {
            concatenated.extend_from_slice(slice);
        }
        let expected = Sha256::hash(&concatenated);

        // Test with iterator
        let actual = Sha256::hash_iter(slices.iter().map(Vec::as_slice));
        assert_eq!(expected, actual);

        // Test with empty slices list
        let empty_actual = Sha256::hash_iter(core::iter::empty());
        let empty_expected = Sha256::hash(b"");
        assert_eq!(empty_expected, empty_actual);

        // Test with single slice
        if let Some(single_slice) = slices.first() {
            let single_actual = Sha256::hash_iter(core::iter::once(single_slice.as_slice()));
            let single_expected = Sha256::hash(single_slice);
            assert_eq!(single_expected, single_actual);
        }
    }
}

#[test]
fn test_sha256_nist_test_vectors() {
    for (i, vector) in SHA256_TEST_VECTORS.iter().enumerate() {
        let result = Sha256::hash(vector.input);
        let expected = hex::decode(vector.expected).unwrap();
        assert_eq!(
            result.to_vec(),
            expected,
            "SHA-256 test vector {} failed: {}",
            i,
            vector.description
        );
    }
}

// SHA-512 TESTS
// ================================================================================================

#[test]
fn sha512_hash_elements() {
    // test multiple of 16
    let elements = rand_vector::<Felt>(32);
    let expected = compute_expected_sha512_element_hash(&elements);
    let actual: [u8; DIGEST512_BYTES] = hash_elements_512(&elements);
    assert_eq!(&expected, &actual);

    // test not multiple of 16
    let elements = rand_vector::<Felt>(17);
    let expected = compute_expected_sha512_element_hash(&elements);
    let actual: [u8; DIGEST512_BYTES] = hash_elements_512(&elements);
    assert_eq!(&expected, &actual);
}

proptest! {
    #[test]
    fn sha512_wont_panic_with_arbitrary_input(ref vec in any::<Vec<u8>>()) {
        Sha512::hash(vec);
    }

    #[test]
    fn sha512_hash_iter_matches_hash(ref slices in any::<Vec<Vec<u8>>>()) {
        // Concatenate all slices to create the expected result
        let mut concatenated = Vec::new();
        for slice in slices.iter() {
            concatenated.extend_from_slice(slice);
        }
        let expected = Sha512::hash(&concatenated);

        // Test with iterator
        let actual = Sha512::hash_iter(slices.iter().map(Vec::as_slice));
        assert_eq!(expected, actual);

        // Test with empty slices list
        let empty_actual = Sha512::hash_iter(core::iter::empty());
        let empty_expected = Sha512::hash(b"");
        assert_eq!(empty_expected, empty_actual);

        // Test with single slice
        if let Some(single_slice) = slices.first() {
            let single_actual = Sha512::hash_iter(core::iter::once(single_slice.as_slice()));
            let single_expected = Sha512::hash(single_slice);
            assert_eq!(single_expected, single_actual);
        }
    }
}

#[test]
fn test_sha512_nist_test_vectors() {
    for (i, vector) in SHA512_TEST_VECTORS.iter().enumerate() {
        let result = Sha512::hash(vector.input);
        let expected = hex::decode(vector.expected).unwrap();
        assert_eq!(
            result.to_vec(),
            expected,
            "SHA-512 test vector {} failed: {}",
            i,
            vector.description
        );
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn compute_expected_sha256_element_hash(elements: &[Felt]) -> [u8; DIGEST256_BYTES] {
    let mut bytes = Vec::new();
    for element in elements.iter() {
        bytes.extend_from_slice(&element.as_canonical_u64().to_le_bytes());
    }
    let mut hasher = sha2::Sha256::new();
    hasher.update(&bytes);

    hasher.finalize().into()
}

fn compute_expected_sha512_element_hash(elements: &[Felt]) -> [u8; DIGEST512_BYTES] {
    let mut bytes = Vec::new();
    for element in elements.iter() {
        bytes.extend_from_slice(&element.as_canonical_u64().to_le_bytes());
    }
    let mut hasher = sha2::Sha512::new();
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

// NIST test vectors for SHA-256
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
const SHA256_TEST_VECTORS: &[TestVector] = &[
    TestVector {
        input: b"",
        expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        description: "Empty input",
    },
    TestVector {
        input: b"abc",
        expected: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        description: "String 'abc'",
    },
    TestVector {
        input: b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        expected: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        description: "448 bits message",
    },
];

// NIST test vectors for SHA-512
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf
const SHA512_TEST_VECTORS: &[TestVector] = &[
    TestVector {
        input: b"",
        expected: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        description: "Empty input",
    },
    TestVector {
        input: b"abc",
        expected: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        description: "String 'abc'",
    },
    TestVector {
        input: b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        expected: "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        description: "896 bits message",
    },
];

// MEMORY LAYOUT TESTS
// ================================================================================================

#[test]
fn test_memory_layout_assumptions() {
    // Verify struct size equals inner array size (required for safe pointer casting)
    assert_eq!(size_of::<Sha256Digest>(), size_of::<[u8; 32]>());

    // Verify alignment
    assert_eq!(align_of::<Sha256Digest>(), align_of::<[u8; 32]>());

    // Same for Sha512Digest
    assert_eq!(size_of::<Sha512Digest>(), size_of::<[u8; 64]>());
    assert_eq!(align_of::<Sha512Digest>(), align_of::<[u8; 64]>());
}

#[test]
fn test_sha256_digests_as_bytes_correctness() {
    let digests = vec![
        Sha256Digest::from([1u8; 32]),
        Sha256Digest::from([2u8; 32]),
        Sha256Digest::from([3u8; 32]),
    ];

    let bytes = Sha256Digest::digests_as_bytes(&digests);

    // Verify length
    assert_eq!(bytes.len(), 96);

    // Verify contiguous layout
    assert_eq!(&bytes[0..32], &[1u8; 32]);
    assert_eq!(&bytes[32..64], &[2u8; 32]);
    assert_eq!(&bytes[64..96], &[3u8; 32]);
}

#[test]
fn test_sha512_digests_as_bytes_correctness() {
    let digests = vec![
        Sha512Digest::from([1u8; 64]),
        Sha512Digest::from([2u8; 64]),
        Sha512Digest::from([3u8; 64]),
    ];

    let bytes = Sha512Digest::digests_as_bytes(&digests);

    // Verify length
    assert_eq!(bytes.len(), 192);

    // Verify contiguous layout
    assert_eq!(&bytes[0..64], &[1u8; 64]);
    assert_eq!(&bytes[64..128], &[2u8; 64]);
    assert_eq!(&bytes[128..192], &[3u8; 64]);
}

// MERGE_MANY CORRECTNESS TESTS
// ================================================================================================

proptest! {
    #[test]
    fn sha256_merge_many_matches_concatenated_hash(
        digests in prop::collection::vec(any::<[u8; 32]>(), 1..10)
    ) {
        let sha_digests: Vec<Sha256Digest> =
            digests.iter().map(|&d| Sha256Digest::from(d)).collect();

        // Method 1: Using merge_many (uses unsafe digests_as_bytes)
        let result1 = Sha256::merge_many(&sha_digests);

        // Method 2: Safe concatenation for comparison
        let mut concat = Vec::new();
        for d in &sha_digests {
            concat.extend_from_slice(d.as_bytes());
        }
        let result2 = Sha256::hash(&concat);

        // Should produce identical results
        assert_eq!(result1, result2);
    }

    #[test]
    fn sha512_merge_many_matches_concatenated_hash(
        digests in prop::collection::vec(any::<[u8; 64]>(), 1..10)
    ) {
        let sha_digests: Vec<Sha512Digest> =
            digests.iter().map(|&d| Sha512Digest::from(d)).collect();

        let result1 = Sha512::merge_many(&sha_digests);

        let mut concat = Vec::new();
        for d in &sha_digests {
            concat.extend_from_slice(d.as_bytes());
        }
        let result2 = Sha512::hash(&concat);

        assert_eq!(result1, result2);
    }
}
