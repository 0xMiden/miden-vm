use miden_utils_testing::{Felt, IntoBytes, group_slice_elements, rand::rand_array};

#[test]
fn blake3_hash_64_bytes() {
    let source = "
    use miden::core::crypto::hashes::blake3

    begin
        exec.blake3::merge
        swapdw dropw dropw
    end
    ";

    let input0 = rand_array::<Felt, 4>().into_bytes();
    let input1 = rand_array::<Felt, 4>().into_bytes();

    let mut ibytes = [0u8; 64];
    ibytes[..32].copy_from_slice(&input0);
    ibytes[32..].copy_from_slice(&input1);

    let ifelts = group_slice_elements::<u8, 4>(&ibytes)
        .iter()
        .map(|&bytes| u32::from_le_bytes(bytes) as u64)
        .rev()
        .collect::<Vec<u64>>();

    let hasher = blake3::hash(&ibytes);
    let obytes = hasher.as_bytes();
    let ofelts = group_slice_elements::<u8, 4>(obytes)
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

    let ibytes = rand_array::<Felt, 4>().into_bytes();
    let ifelts = group_slice_elements::<u8, 4>(&ibytes)
        .iter()
        .map(|&bytes| u32::from_le_bytes(bytes) as u64)
        .rev()
        .collect::<Vec<u64>>();

    let hasher = blake3::hash(&ibytes);
    let obytes = hasher.as_bytes();
    let ofelts = group_slice_elements::<u8, 4>(obytes)
        .iter()
        .map(|&bytes| u32::from_le_bytes(bytes) as u64)
        .collect::<Vec<u64>>();

    let test = build_test!(source, &ifelts);
    test.expect_stack(&ofelts);
}
