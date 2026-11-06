use miden_crypto::hash::blake::Blake3_256;
use miden_utils_testing::{IntoBytes, group_slice_elements, rand::seeded_word};
#[test]
fn blake3_hash_64_bytes() {
    let source = "
    use miden::core::crypto::hashes::blake3

    begin
        exec.blake3::merge
        swapdw dropw dropw
    end
    ";

    let mut seed = 1u64;
    let (input0, input1) = (seeded_word(&mut seed), seeded_word(&mut seed));
    let (input0, input1) = (input0.into_bytes(), input1.into_bytes());

    let mut ibytes = [0u8; 64];
    ibytes[..32].copy_from_slice(&input0);
    ibytes[32..].copy_from_slice(&input1);

    let ifelts = group_slice_elements::<u8, 4>(&ibytes)
        .iter()
        .map(|&bytes| u32::from_le_bytes(bytes) as u64)
        .collect::<Vec<u64>>();

    let ohash = Blake3_256::hash(&ibytes);
    let ofelts = group_slice_elements::<u8, 4>(ohash.as_bytes())
        .iter()
        .map(|&bytes| u32::from_le_bytes(bytes) as u64)
        .collect::<Vec<u64>>();

    let test = build_test!(source, &ifelts);
    test.expect_stack(&ofelts);
}

#[test]
fn blake3_hash_32_bytes() {
    let source = "
    use miden::core::crypto::hashes::blake3

    begin
        exec.blake3::hash
        swapdw dropw dropw
    end
    ";

    let mut seed = 2u64;
    let ibytes = seeded_word(&mut seed).into_bytes();
    let ifelts = group_slice_elements::<u8, 4>(&ibytes)
        .iter()
        .map(|&bytes| u32::from_le_bytes(bytes) as u64)
        .collect::<Vec<u64>>();

    let ohash = Blake3_256::hash(&ibytes);
    let ofelts = group_slice_elements::<u8, 4>(ohash.as_bytes())
        .iter()
        .map(|&bytes| u32::from_le_bytes(bytes) as u64)
        .collect::<Vec<u64>>();

    let test = build_test!(source, &ifelts);
    test.expect_stack(&ofelts);
}
