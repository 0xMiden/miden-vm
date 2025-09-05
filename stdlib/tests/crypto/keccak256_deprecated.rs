use miden_utils_testing::{
    Felt, IntoBytes, MIN_STACK_DEPTH,
    rand::{rand_array, rand_value},
};
use sha3::{Digest, Keccak256};

/// Equivalent to https://github.com/itzmeanjan/merklize-sha/blob/1d35aae/include/test_bit_interleaving.hpp#L12-L34
#[test]
fn keccak256_bit_interleaving() {
    let source = "
    use.std::crypto::hashes::keccak256_deprecated

    begin
        exec.keccak256_deprecated::to_bit_interleaved
        exec.keccak256_deprecated::from_bit_interleaved
    end
    ";

    let word = rand_value::<u64>();

    let high = (word >> 32) as u32 as u64;
    let low = word as u32 as u64;

    let test = build_test!(source, &[low, high]);
    let stack = test.get_last_stack_state();

    assert_eq!(stack[0], Felt::new(high));
    assert_eq!(stack[1], Felt::new(low));
}

#[test]
fn keccak256_2_to_1_hash() {
    let source = "
    use.std::crypto::hashes::keccak256_deprecated

    begin
        exec.keccak256_deprecated::hash
        swapdw dropw dropw
    end
    ";

    // prepare random input byte array
    let i_digest_0: [u8; 32] = rand_array::<Felt, 4>().into_bytes();
    let i_digest_1: [u8; 32] = rand_array::<Felt, 4>().into_bytes();

    // 64 -bytes wide concatenated input digest
    let mut i_digest = [0u8; 64];
    i_digest[..32].copy_from_slice(&i_digest_0);
    i_digest[32..].copy_from_slice(&i_digest_1);

    // computing keccak256 of 64 -bytes input, on host CPU
    let mut hasher = Keccak256::new();
    hasher.update(i_digest);
    // producing 32 -bytes keccak256 digest
    let digest = hasher.finalize();

    // 32 -bytes digest represented in terms eight ( little endian )
    // 32 -bit integers such that it's easy to compare against final stack trace
    let mut expected_stack = [0u64; MIN_STACK_DEPTH >> 1];
    to_stack(&digest, &mut expected_stack);

    // 64 -bytes input represented in terms of sixteen ( little endian ) 32 -bit
    // integers so that miden assembly implementation of keccak256 2-to-1 hash can
    // consume it and produce 32 -bytes digest
    let mut in_stack = [0u64; MIN_STACK_DEPTH];
    to_stack(&i_digest, &mut in_stack);
    in_stack.reverse();

    let test = build_test!(source, &in_stack);
    test.expect_stack(&expected_stack);
}

/// Given N -many bytes ( such that N % 8 == 0 ), this function considers
/// each block of contiguous 8 -bytes as little endian 64 -bit unsigned
/// integer word and converts each u64 into two u32s such that first one holds
/// higher 32 -bits of u64 word and second one holds remaining lower 32 -bits
/// of u64 word.
///
/// Ensure that stack.len() == (i_digest.len() / 4) !
fn to_stack(i_digest: &[u8], stack: &mut [u64]) {
    for i in 0..(i_digest.len() >> 3) {
        // byte array ( = 8 -bytes ) to little endian 64 -bit unsigned integer
        let word = ((i_digest[(i << 3) + 7] as u64) << 56)
            | ((i_digest[(i << 3) + 6] as u64) << 48)
            | ((i_digest[(i << 3) + 5] as u64) << 40)
            | ((i_digest[(i << 3) + 4] as u64) << 32)
            | ((i_digest[(i << 3) + 3] as u64) << 24)
            | ((i_digest[(i << 3) + 2] as u64) << 16)
            | ((i_digest[(i << 3) + 1] as u64) << 8)
            | (i_digest[i << 3] as u64);

        // split into higher/ lower bits of u64
        let high = (word >> 32) as u32;
        let low = word as u32;

        // 64 -bit standard representation number kept as two 32 -bit numbers
        // where first one holds higher 32 -bits and second one holds remaining lower
        // 32 -bits of u64 word
        stack[i << 1] = high as u64;
        stack[(i << 1) + 1] = low as u64;
    }
}
