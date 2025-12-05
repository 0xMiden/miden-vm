use miden_utils_testing::{
    Felt, IntoBytes, group_slice_elements, push_inputs,
    rand::{rand_array, rand_value, rand_vector},
};
use sha2::{Digest, Sha256};

#[test]
fn sha256_hash_bytes() {
    let length_in_bytes = rand_value::<u64>() & 1023; // length: 0-1023
    let ibytes: Vec<u8> = rand_vector(length_in_bytes as usize);
    let ipadding: Vec<u8> = vec![0; (4 - (length_in_bytes as usize % 4)) % 4];

    let ifelts = [
        group_slice_elements::<u8, 4>(&[ibytes.clone(), ipadding].concat())
            .iter()
            .map(|&bytes| u32::from_be_bytes(bytes) as u64)
            .rev()
            .collect::<Vec<u64>>(),
        vec![length_in_bytes as u64; 1],
    ]
    .concat();

    let source = format!(
        "
    use miden::core::crypto::hashes::sha256

    begin
        # push inputs on the stack
        {inputs}

        # mem.0 - input data address
        push.10000 mem_store.0

        # mem.1 - length in bytes
        mem_store.1

        # mem.2 - length in words
        mem_load.1 u32assert u32overflowing_add.15 assertz u32assert u32div.16 mem_store.2

        # Load input data into memory address 10000, 10004, ...
        mem_load.2 u32assert neq.0
        while.true
            mem_load.0 mem_storew_be dropw
            mem_load.0 u32assert u32overflowing_add.4 assertz mem_store.0
            mem_load.2 u32assert u32overflowing_sub.1 assertz dup mem_store.2 u32assert neq.0
        end

        # Compute hash of memory address 10000, 10004, ...
        mem_load.1
        push.10000
        exec.sha256::hash_bytes

        # truncate the stack
        swapdw dropw dropw
    end",
        inputs = push_inputs(&ifelts)
    );

    let mut hasher = Sha256::new();
    hasher.update(ibytes);

    let obytes = hasher.finalize();
    let ofelts = group_slice_elements::<u8, 4>(&obytes)
        .iter()
        .map(|&bytes| u32::from_be_bytes(bytes) as u64)
        .collect::<Vec<u64>>();

    let test = build_test!(source, &[]);
    test.expect_stack(&ofelts);
}

#[test]
fn sha256_2_to_1_hash() {
    let source = "
    use miden::core::crypto::hashes::sha256

    begin
        exec.sha256::merge
    end";

    let input0 = rand_array::<Felt, 4>().into_bytes();
    let input1 = rand_array::<Felt, 4>().into_bytes();

    let mut ibytes = [0u8; 64];
    ibytes[..32].copy_from_slice(&input0);
    ibytes[32..].copy_from_slice(&input1);

    let ifelts = group_slice_elements::<u8, 4>(&ibytes)
        .iter()
        .map(|&bytes| u32::from_be_bytes(bytes) as u64)
        .rev()
        .collect::<Vec<u64>>();

    let mut hasher = Sha256::new();
    hasher.update(ibytes);

    let obytes = hasher.finalize();
    let ofelts = group_slice_elements::<u8, 4>(&obytes)
        .iter()
        .map(|&bytes| u32::from_be_bytes(bytes) as u64)
        .collect::<Vec<u64>>();

    let test = build_test!(source, &ifelts);
    test.expect_stack(&ofelts);
}

#[test]
fn sha256_1_to_1_hash() {
    let source = "
    use miden::core::crypto::hashes::sha256

    begin
        exec.sha256::hash
    end";

    let ibytes = rand_array::<Felt, 4>().into_bytes();
    let ifelts = group_slice_elements::<u8, 4>(&ibytes)
        .iter()
        .map(|&bytes| u32::from_be_bytes(bytes) as u64)
        .rev()
        .collect::<Vec<u64>>();

    let mut hasher = Sha256::new();
    hasher.update(ibytes);

    let obytes = hasher.finalize();
    let ofelts = group_slice_elements::<u8, 4>(&obytes)
        .iter()
        .map(|&bytes| u32::from_be_bytes(bytes) as u64)
        .collect::<Vec<u64>>();

    let test = build_test!(source, &ifelts);
    test.expect_stack(&ofelts);
}
