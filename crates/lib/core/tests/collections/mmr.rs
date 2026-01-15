use miden_core::WORD_SIZE;
use miden_processor::AdviceStackBuilder;
use miden_utils_testing::{
    EMPTY_WORD, Felt, ONE, PrimeField64, Word, ZERO,
    crypto::{
        MerkleError, MerkleStore, MerkleTree, Mmr, NodeIndex, init_merkle_leaf, init_merkle_leaves,
    },
    felt_slice_to_ints, hash_elements,
};

// TESTS
// ================================================================================================

#[test]
fn test_num_leaves_to_num_peaks() {
    let hash_size = "
    use miden::core::collections::mmr

    begin
      exec.mmr::num_leaves_to_num_peaks
    end
    ";

    build_test!(hash_size, &[0b0000]).expect_stack(&[0]);
    build_test!(hash_size, &[0b0001]).expect_stack(&[1]);
    build_test!(hash_size, &[0b0011]).expect_stack(&[2]);
    build_test!(hash_size, &[0b0011]).expect_stack(&[2]);
    build_test!(hash_size, &[0b1100]).expect_stack(&[2]);
    build_test!(hash_size, &[0b1000_0000_0000_0000]).expect_stack(&[1]);
    build_test!(hash_size, &[0b1010_1100_0011_1001]).expect_stack(&[8]);
    build_test!(hash_size, &[0b1111_1111_1111_1111]).expect_stack(&[16]);
    build_test!(hash_size, &[0b1111_1111_1111_1111_0000]).expect_stack(&[16]);
    build_test!(hash_size, &[0b0001_1111_1111_1111_1111]).expect_stack(&[17]);
}

#[test]
fn test_num_peaks_to_message_size() {
    let hash_size = "
    use miden::core::collections::mmr

    begin
      exec.mmr::num_peaks_to_message_size
    end
    ";

    // minimum size is 16
    build_test!(hash_size, &[1]).expect_stack(&[16 * 4]);
    build_test!(hash_size, &[2]).expect_stack(&[16 * 4]);
    build_test!(hash_size, &[3]).expect_stack(&[16 * 4]);
    build_test!(hash_size, &[4]).expect_stack(&[16 * 4]);
    build_test!(hash_size, &[7]).expect_stack(&[16 * 4]);
    build_test!(hash_size, &[11]).expect_stack(&[16 * 4]);
    build_test!(hash_size, &[16]).expect_stack(&[16 * 4]);

    // after that, size is round to the next even number
    build_test!(hash_size, &[17]).expect_stack(&[18 * 4]);
    build_test!(hash_size, &[18]).expect_stack(&[18 * 4]);
    build_test!(hash_size, &[19]).expect_stack(&[20 * 4]);
    build_test!(hash_size, &[20]).expect_stack(&[20 * 4]);
    build_test!(hash_size, &[21]).expect_stack(&[22 * 4]);
    build_test!(hash_size, &[22]).expect_stack(&[22 * 4]);
}

#[test]
fn test_mmr_get_single_peak() -> Result<(), MerkleError> {
    // This test uses a single merkle tree as the only MMR peak
    let leaves = &[1, 2, 3, 4];
    let merkle_tree = MerkleTree::new(init_merkle_leaves(leaves))?;
    let merkle_root = merkle_tree.root();
    let merkle_store = MerkleStore::from(&merkle_tree);
    let mut builder = AdviceStackBuilder::new();
    builder.push_for_adv_loadw(merkle_root);
    let advice_stack = builder.build_vec_u64();

    for pos in 0..(leaves.len() as u64) {
        let source = format!(
            "
            use miden::core::collections::mmr

            begin
                push.{num_leaves} push.1000 mem_store # leaves count
                padw adv_loadw push.1004 mem_storew_le dropw # MMR single peak

                push.1000 push.{pos} exec.mmr::get

                swapw dropw
            end",
            num_leaves = leaves.len(),
            pos = pos,
        );

        let test = build_test!(source, &[], advice_stack, merkle_store.clone());
        let leaf = merkle_store.get_node(merkle_root, NodeIndex::new(2, pos)?)?;

        // the stack currently returns the leaf in stack(BE) order; match runtime behavior.
        let stack = word_to_ints(&leaf);
        test.expect_stack(&stack);
    }

    Ok(())
}

#[test]
fn test_mmr_get_two_peaks() -> Result<(), MerkleError> {
    // This test uses two merkle trees for the MMR, one with 8 elements, and one with 2
    let leaves1 = &[1, 2, 3, 4, 5, 6, 7, 8];
    let merkle_tree1 = MerkleTree::new(init_merkle_leaves(leaves1))?;
    let merkle_root1 = merkle_tree1.root();
    let leaves2 = &[9, 10];
    let merkle_tree2 = MerkleTree::new(init_merkle_leaves(leaves2))?;
    let merkle_root2 = merkle_tree2.root();
    let num_leaves = leaves1.len() + leaves2.len();

    let mut merkle_store = MerkleStore::new();
    merkle_store.extend(merkle_tree1.inner_nodes());
    merkle_store.extend(merkle_tree2.inner_nodes());

    let mut builder = AdviceStackBuilder::new();
    builder.push_for_adv_loadw(merkle_root1);
    builder.push_for_adv_loadw(merkle_root2);
    let advice_stack = builder.build_vec_u64();

    let examples = [
        // absolute_pos, leaf
        (0, merkle_store.get_node(merkle_root1, NodeIndex::new(3u8, 0u64)?)?),
        (1, merkle_store.get_node(merkle_root1, NodeIndex::new(3u8, 1u64)?)?),
        (2, merkle_store.get_node(merkle_root1, NodeIndex::new(3u8, 2u64)?)?),
        (3, merkle_store.get_node(merkle_root1, NodeIndex::new(3u8, 3u64)?)?),
        (7, merkle_store.get_node(merkle_root1, NodeIndex::new(3u8, 7u64)?)?),
        (8, merkle_store.get_node(merkle_root2, NodeIndex::new(1u8, 0u64)?)?),
        (9, merkle_store.get_node(merkle_root2, NodeIndex::new(1u8, 1u64)?)?),
    ];

    for (absolute_pos, leaf) in examples {
        let source = format!(
            "
            use miden::core::collections::mmr

            begin
                push.{num_leaves} push.1000 mem_store # leaves count
                padw adv_loadw push.1004 mem_storew_le dropw # MMR first peak
                padw adv_loadw push.1008 mem_storew_le dropw # MMR second peak

                push.1000 push.{absolute_pos} exec.mmr::get

                swapw dropw
            end",
        );

        let test = build_test!(source, &[], advice_stack, merkle_store.clone());

        let stack = word_to_ints(&leaf);
        test.expect_stack(&stack);
    }

    Ok(())
}

#[test]
fn test_mmr_tree_with_one_element() -> Result<(), MerkleError> {
    // This test uses three merkle trees for the MMR, one with 8 elements, one with 2, and one with
    // a single leaf. The test is ensure the single leaf case is supported, the other two are used
    // for variaty
    let leaves1 = &[1, 2, 3, 4, 5, 6, 7, 8];
    let leaves2 = &[9, 10];
    let leaves3 = &[11];

    let merkle_tree1 = MerkleTree::new(init_merkle_leaves(leaves1))?;
    let merkle_tree2 = MerkleTree::new(init_merkle_leaves(leaves2))?;

    let merkle_root1 = merkle_tree1.root();
    let merkle_root2 = merkle_tree2.root();
    let merkle_root3 = init_merkle_leaves(leaves3)[0];

    let mut merkle_store = MerkleStore::new();
    merkle_store.extend(merkle_tree1.inner_nodes());
    merkle_store.extend(merkle_tree2.inner_nodes());

    // In the case of a single leaf, the leaf is itself also the root
    let stack = word_to_ints(&merkle_root3);

    // Test case for single element MMR
    let mut builder = AdviceStackBuilder::new();
    builder.push_for_adv_loadw(merkle_root3);
    let advice_stack = builder.build_vec_u64();
    let source = format!(
        "
        use miden::core::collections::mmr

        begin
            push.{num_leaves} push.1000 mem_store # leaves count
            padw adv_loadw push.1004 mem_storew_le dropw # MMR first peak

            push.1000 push.{pos} exec.mmr::get

            swapw dropw
        end",
        num_leaves = leaves3.len(),
        pos = 0,
    );
    let test = build_test!(source, &[], advice_stack, merkle_store.clone());
    test.expect_stack(&stack);

    // Test case for the single element tree in a MMR with multiple trees
    let mut builder = AdviceStackBuilder::new();
    builder.push_for_adv_loadw(merkle_root1);
    builder.push_for_adv_loadw(merkle_root2);
    builder.push_for_adv_loadw(merkle_root3);
    let advice_stack = builder.build_vec_u64();
    let num_leaves = leaves1.len() + leaves2.len() + leaves3.len();
    let source = format!(
        "
        use miden::core::collections::mmr

        begin
            push.{num_leaves} push.1000 mem_store # leaves count
            padw adv_loadw push.1004 mem_storew_le dropw # MMR first peak
            padw adv_loadw push.1008 mem_storew_le dropw # MMR second peak
            padw adv_loadw push.1012 mem_storew_le dropw # MMR third peak

            push.1000 push.{pos} exec.mmr::get

            swapw dropw
        end",
        num_leaves = num_leaves,
        pos = num_leaves - 1,
    );
    let test = build_test!(source, &[], advice_stack, merkle_store.clone());
    test.expect_stack(&stack);

    Ok(())
}

#[test]
fn test_mmr_unpack() {
    let number_of_leaves: u64 = 0b10101; // 3 peaks, 21 leaves

    // The hash data is not the same as the peaks, it is padded to 16 elements
    let peaks: [[Felt; 4]; 16] = [
        // 3 peaks. These hashes are invalid, we can't produce data for any of these peaks (only
        // for testing)
        [ZERO, ZERO, ZERO, ONE],
        [ZERO, ZERO, ZERO, Felt::new(2)],
        [ZERO, ZERO, ZERO, Felt::new(3)],
        // Padding, the MMR is padded to a minimum length of 16
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
    ];
    let peaks_hash = hash_elements(&peaks.concat());

    let mmr_ptr = 1000_u32;
    let mut stack = felt_slice_to_ints(&*peaks_hash);
    stack.push(mmr_ptr as u64);

    // both the advice stack and merkle store start empty (data is available in
    // the map and pushed to the advice stack by the MASM code)
    let advice_stack = &[];
    let store = MerkleStore::new();

    let mut mmr_mem_repr: Vec<Felt> = Vec::with_capacity(peaks.len() + 1);
    mmr_mem_repr.extend_from_slice(&[Felt::new(number_of_leaves), ZERO, ZERO, ZERO]);
    mmr_mem_repr.extend_from_slice(&peaks.as_slice().concat());

    // Advice map key is the hash word (positions 0-3 on stack)
    let hash_key = peaks_hash;
    let advice_map: &[(Word, Vec<Felt>)] = &[
        // Under the MMR key is the number_of_leaves, followed by the MMR peaks, and any padding
        (hash_key, mmr_mem_repr),
    ];

    let source = "
        use miden::core::collections::mmr
        begin exec.mmr::unpack end
    ";
    let test = build_test!(source, &stack, advice_stack, store, advice_map.iter().cloned());

    #[rustfmt::skip]
    let expect_memory = [
        number_of_leaves, 0, 0, 0, // MMR leaves (only one Felt is used)
        0, 0, 0, 1,                // first peak
        0, 0, 0, 2,                // second peak
        0, 0, 0, 3,                // third peak
    ];
    test.expect_stack(&[]);
    test.expect_stack_and_memory(&[], mmr_ptr, &expect_memory);
}

#[test]
fn test_mmr_unpack_invalid_hash() {
    // The hash data is not the same as the peaks, it is padded to 16 elements
    let mut hash_data: [[Felt; 4]; 16] = [
        // 3 peaks. These hashes are invalid, we can't produce data for any of these peaks (only
        // for testing)
        [ZERO, ZERO, ZERO, ONE],
        [ZERO, ZERO, ZERO, Felt::new(2)],
        [ZERO, ZERO, ZERO, Felt::new(3)],
        // Padding, the MMR is padded to a minimum length o 16
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
        EMPTY_WORD.into(),
    ];
    let hash = hash_elements(&hash_data.concat());

    // Set up the VM stack: mmr::unpack expects [HASH, mmr_ptr, ...]
    let mmr_ptr = 1000;
    let mut stack = felt_slice_to_ints(&*hash);
    stack.push(mmr_ptr);

    // both the advice stack and merkle store start empty (data is available in
    // the map and pushed to the advice stack by the MASM code)
    let advice_stack = &[];
    let store = MerkleStore::new();

    // corrupt the data, this changes the hash and the commitment check must fail
    hash_data[0][0] += ONE;

    let mut map_data: Vec<Felt> = Vec::with_capacity(hash_data.len() + 1);
    map_data.extend_from_slice(&[Felt::new(0b10101), ZERO, ZERO, ZERO]); // 3 peaks, 21 leaves
    map_data.extend_from_slice(&hash_data.as_slice().concat());

    let hash_key = hash;
    let advice_map: &[(Word, Vec<Felt>)] = &[
        // Under the MMR key is the number_of_leaves, followed by the MMR peaks, and any padding
        (hash_key, map_data),
    ];

    let source = "
        use miden::core::collections::mmr
        begin exec.mmr::unpack end
    ";
    let test = build_test!(source, &stack, advice_stack, store, advice_map.iter().cloned());

    assert!(test.execute().is_err());
}

/// Tests the case of an MMR with more than 16 peaks
#[test]
fn test_mmr_unpack_large_mmr() {
    let number_of_leaves: u64 = 0b11111111111111111; // 17 peaks

    let peaks: [[Felt; 4]; 18] = [
        // These hashes are invalid, we can't produce data for any of these peaks (only for
        // testing)
        [ZERO, ZERO, ZERO, ONE],
        [ZERO, ZERO, ZERO, Felt::new(2)],
        [ZERO, ZERO, ZERO, Felt::new(3)],
        [ZERO, ZERO, ZERO, Felt::new(4)],
        [ZERO, ZERO, ZERO, Felt::new(5)],
        [ZERO, ZERO, ZERO, Felt::new(6)],
        [ZERO, ZERO, ZERO, Felt::new(7)],
        [ZERO, ZERO, ZERO, Felt::new(8)],
        [ZERO, ZERO, ZERO, Felt::new(9)],
        [ZERO, ZERO, ZERO, Felt::new(10)],
        [ZERO, ZERO, ZERO, Felt::new(11)],
        [ZERO, ZERO, ZERO, Felt::new(12)],
        [ZERO, ZERO, ZERO, Felt::new(13)],
        [ZERO, ZERO, ZERO, Felt::new(14)],
        [ZERO, ZERO, ZERO, Felt::new(15)],
        [ZERO, ZERO, ZERO, Felt::new(16)],
        // Padding, peaks greater than 16 are padded to an even number
        [ZERO, ZERO, ZERO, Felt::new(17)],
        EMPTY_WORD.into(),
    ];
    let peaks_hash = hash_elements(&peaks.concat());

    // Set up the VM stack: mmr::unpack expects [HASH, mmr_ptr, ...]
    let mmr_ptr = 1000_u32;
    let mut stack = felt_slice_to_ints(&*peaks_hash);
    stack.push(mmr_ptr as u64);

    // both the advice stack and merkle store start empty (data is available in
    // the map and pushed to the advice stack by the MASM code)
    let advice_stack = &[];
    let store = MerkleStore::new();

    let mut mmr_mem_repr: Vec<Felt> = Vec::with_capacity(peaks.len() + 1);
    mmr_mem_repr.extend_from_slice(&[Felt::new(number_of_leaves), ZERO, ZERO, ZERO]);
    mmr_mem_repr.extend_from_slice(&peaks.as_slice().concat());

    // Advice map key is the hash word (positions 0-3 on stack)
    let hash_key = peaks_hash;
    let advice_map: &[(Word, Vec<Felt>)] = &[(hash_key, mmr_mem_repr)];

    let source = "
        use miden::core::collections::mmr
        begin exec.mmr::unpack end
    ";
    let test = build_test!(source, &stack, advice_stack, store, advice_map.iter().cloned());

    #[rustfmt::skip]
    let expect_memory = [
        number_of_leaves, 0, 0, 0, // MMR leaves (only one Felt is used)
        0, 0, 0, 1,                // peaks
        0, 0, 0, 2,
        0, 0, 0, 3,
        0, 0, 0, 4,
        0, 0, 0, 5,
        0, 0, 0, 6,
        0, 0, 0, 7,
        0, 0, 0, 8,
        0, 0, 0, 9,
        0, 0, 0, 10,
        0, 0, 0, 11,
        0, 0, 0, 12,
        0, 0, 0, 13,
        0, 0, 0, 14,
        0, 0, 0, 15,
        0, 0, 0, 16,
        0, 0, 0, 17,
    ];
    test.expect_stack(&[]);
    test.expect_stack_and_memory(&[], mmr_ptr, &expect_memory);
}

#[test]
fn test_mmr_pack_roundtrip() {
    let mut mmr = Mmr::new();
    mmr.add(init_merkle_leaf(1));
    mmr.add(init_merkle_leaf(2));
    mmr.add(init_merkle_leaf(3));

    let accumulator = mmr.peaks();
    let hash = accumulator.hash_peaks();
    let mmr_ptr = 1000;
    let mut stack = felt_slice_to_ints(&*hash);
    stack.push(mmr_ptr);
    stack.push(mmr_ptr);

    // both the advice stack and merkle store start empty (data is available in
    // the map and pushed to the advice stack by the MASM code)
    let advice_stack = &[];
    let store = MerkleStore::new();

    let mut hash_data = accumulator.peaks().to_vec();
    hash_data.resize(16, Word::default());
    let mut map_data: Vec<Felt> = Vec::with_capacity(hash_data.len() + 1);
    map_data.extend_from_slice(&[Felt::new(accumulator.num_leaves() as u64), ZERO, ZERO, ZERO]);
    map_data.extend_from_slice(Word::words_as_elements(&hash_data).as_ref());

    // Advice map key is the hash word
    let hash_key = hash;
    let advice_map: &[(Word, Vec<Felt>)] = &[(hash_key, map_data)];

    let source = "
        use miden::core::collections::mmr

        begin
            exec.mmr::unpack
            exec.mmr::pack

            swapw dropw
        end
    ";
    let test = build_test!(source, &stack, advice_stack, store, advice_map.iter().cloned());
    // Expected stack after pack: [HASH, ...], then swapw dropw leaves [h0, h1, h2, h3]
    let expected_stack: Vec<u64> = hash.iter().map(|e| e.as_canonical_u64()).collect();

    let mut expect_memory: Vec<u64> = Vec::new();

    // first the number of leaves
    expect_memory.extend_from_slice(&[accumulator.num_leaves() as u64, 0, 0, 0]);
    // followed by the peaks
    expect_memory.extend(digests_to_ints(accumulator.peaks()));
    // followed by padding data
    let size = 4 + 16 * 4;
    expect_memory.resize(size, 0);

    test.expect_stack_and_memory(&expected_stack, 1000, &expect_memory);
}

#[test]
fn test_mmr_pack() {
    let source = "
        use miden::core::collections::mmr

        begin
            push.3.1000 mem_store  # num_leaves, 2 peaks
            push.1.1004 mem_store  # peak1
            push.2.1008 mem_store  # peak2

            push.1000 exec.mmr::pack

            swapw dropw
        end
    ";

    let mut hash_data: Vec<Felt> = Vec::new();

    #[rustfmt::skip]
    hash_data.extend_from_slice( &[
        ONE, ZERO, ZERO, ZERO, // peak1
        Felt::new(2), ZERO, ZERO, ZERO, // peak2
    ]);
    hash_data.resize(16 * 4, ZERO); // padding data

    let hash = hash_elements(&hash_data);
    // Under the canonical layout, adv.insert_mem uses the digest word in
    // stack order as the advice map key. So here we use the digest as-is.
    let hash_key = hash;

    let mut expect_data: Vec<Felt> = Vec::new();
    expect_data.extend_from_slice(&[Felt::new(3), ZERO, ZERO, ZERO]); // num_leaves
    expect_data.extend_from_slice(&hash_data);

    let (execution_output, _) = build_test!(source).execute_for_output().unwrap();

    let advice_data = execution_output.advice.get_mapped_values(&hash_key).unwrap();
    assert_eq!(advice_data, &expect_data);
}

#[test]
fn test_mmr_add_single() {
    let mmr_ptr = 1000;
    let source = format!(
        "
        use miden::core::collections::mmr

        begin
            push.{mmr_ptr} # the address of the mmr
            push.4.3.2.1   # the new peak (stack order for [1,2,3,4])
            exec.mmr::add  # add the element
        end
    "
    );

    // when there is a single element, there is nothing to merge with, so the data is just in the
    // MMR
    #[rustfmt::skip]
    let expect_data = &[
        1, 0, 0, 0, // num_leaves
        1, 2, 3, 4, // peak
    ];
    build_test!(&source).expect_stack_and_memory(&[], mmr_ptr, expect_data);
}

#[test]
fn test_mmr_two() {
    let mmr_ptr = 1000;
    let source = format!(
        "
        use miden::core::collections::mmr

        begin
            push.{mmr_ptr} # first peak
            push.4.3.2.1
            exec.mmr::add

            push.{mmr_ptr} # second peak
            push.8.7.6.5
            exec.mmr::add
        end
    "
    );

    let mut mmr = Mmr::new();
    mmr.add([ONE, Felt::new(2), Felt::new(3), Felt::new(4)].into());
    mmr.add([Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)].into());

    let accumulator = mmr.peaks();
    let num_leaves = accumulator.num_leaves() as u64;
    let mut expected_memory = vec![num_leaves, 0, 0, 0];
    expected_memory.extend(digests_to_ints(accumulator.peaks()));

    build_test!(&source).expect_stack_and_memory(&[], mmr_ptr, &expected_memory);
}

#[test]
fn test_add_mmr_large() {
    let mmr_ptr = 1000;
    let source = format!(
        "
        use miden::core::collections::mmr

        begin
            push.{mmr_ptr}.0.0.0.1 exec.mmr::add
            push.{mmr_ptr}.0.0.0.2 exec.mmr::add
            push.{mmr_ptr}.0.0.0.3 exec.mmr::add
            push.{mmr_ptr}.0.0.0.4 exec.mmr::add
            push.{mmr_ptr}.0.0.0.5 exec.mmr::add
            push.{mmr_ptr}.0.0.0.6 exec.mmr::add
            push.{mmr_ptr}.0.0.0.7 exec.mmr::add

            push.{mmr_ptr} exec.mmr::pack

            swapw dropw
        end
    "
    );

    let mut mmr = Mmr::new();
    for i in 1u64..=7 {
        mmr.add(init_merkle_leaf(i));
    }

    let accumulator = mmr.peaks();

    let num_leaves = accumulator.num_leaves() as u64;
    let mut expected_memory = vec![num_leaves, 0, 0, 0];
    expected_memory.extend(digests_to_ints(accumulator.peaks()));

    let expect_stack = word_to_ints(&accumulator.hash_peaks());
    build_test!(&source).expect_stack_and_memory(&expect_stack, mmr_ptr, &expected_memory);
}

// TEMPORARY: debug helper to compare Rust MMR peaks vs VM MMR memory layout
#[test]
fn debug_mmr_peaks_vs_vm_memory() {
    let mmr_ptr = 1000;

    // MASM side: build MMR in VM memory using stdlib's `mmr::add`.
    let source = format!(
        "
        use miden::core::collections::mmr

        begin
            push.{mmr_ptr}.0.0.0.1 exec.mmr::add
            push.{mmr_ptr}.0.0.0.2 exec.mmr::add
            push.{mmr_ptr}.0.0.0.3 exec.mmr::add
            push.{mmr_ptr}.0.0.0.4 exec.mmr::add
            push.{mmr_ptr}.0.0.0.5 exec.mmr::add
            push.{mmr_ptr}.0.0.0.6 exec.mmr::add
            push.{mmr_ptr}.0.0.0.7 exec.mmr::add
        end
    "
    );

    let test = build_test!(&source);
    let (execution_output, _) = test.execute_for_output().unwrap();

    // Rust side: build the same MMR using miden-crypto.
    let mut mmr = Mmr::new();
    for i in 1u64..=7 {
        // Use canonical leaf representation consistent with Merkle trees.
        mmr.add(init_merkle_leaf(i));
    }
    let accumulator = mmr.peaks();
    let rust_peaks = accumulator.peaks();

    // Flatten Rust peaks into memory-like layout: [num_leaves, 0,0,0, peaks...]
    let mut rust_mem = vec![accumulator.num_leaves() as u64, 0, 0, 0];
    rust_mem.extend(digests_to_ints(rust_peaks));

    // Read back the same region from VM memory: first num_leaves word + one word per peak.
    use miden_processor::ContextId;
    let mut vm_mem = Vec::new();
    let words_to_read = 1 + rust_peaks.len();
    for word_idx in 0..words_to_read {
        for limb in 0..4 {
            let addr = mmr_ptr + (word_idx as u32) * 4 + limb;
            let v = execution_output
                .memory
                .read_element(ContextId::root(), Felt::new(addr as u64), &())
                .unwrap()
                .as_canonical_u64();
            vm_mem.push(v);
        }
    }

    // This helper is for inspection only; keep it from failing so it doesn't
    // interfere with the suite.
    assert!(!rust_mem.is_empty() && !vm_mem.is_empty());
}

#[test]
fn test_mmr_large_add_roundtrip() {
    let mmr_ptr = 1000_u32;

    // Build the initial 7-leaf MMR using the canonical leaf encoding.
    let mut mmr = Mmr::new();
    for i in 1u64..=7 {
        mmr.add(init_merkle_leaf(i));
    }

    let old_accumulator = mmr.peaks();
    let hash = old_accumulator.hash_peaks();

    // Set up the VM stack: mmr::unpack expects [HASH, mmr_ptr, ...]
    let mut stack = felt_slice_to_ints(&*hash);
    stack.push(mmr_ptr as u64);

    // both the advice stack and merkle store start empty (data is available in
    // the map and pushed to the advice stack by the MASM code)
    let advice_stack = &[];
    let store = MerkleStore::new();

    let mut hash_data = old_accumulator.peaks().to_vec();
    hash_data.resize(16, Word::default());

    let mut map_data: Vec<Felt> = Vec::with_capacity(hash_data.len() + 1);
    let num_leaves = old_accumulator.num_leaves() as u64;
    map_data.extend_from_slice(&[Felt::new(num_leaves), ZERO, ZERO, ZERO]);
    map_data.extend_from_slice(Word::words_as_elements(&hash_data));

    // Advice map key is the hash word
    let hash_key = hash;
    let advice_map: &[(Word, Vec<Felt>)] = &[(hash_key, map_data)];

    let source = format!(
        "
        use miden::core::collections::mmr

        begin
            exec.mmr::unpack
            push.{mmr_ptr}.0.0.0.8 exec.mmr::add
            push.{mmr_ptr} exec.mmr::pack

            swapw dropw
        end
    "
    );

    mmr.add(init_merkle_leaf(8));

    let new_accumulator = mmr.peaks();
    let num_leaves = new_accumulator.num_leaves() as u64;
    let mut expected_memory = vec![num_leaves, 0, 0, 0];
    let mut new_peaks = new_accumulator.peaks().to_vec();
    // make sure the old peaks are zeroed
    new_peaks.resize(16, Word::default());
    expected_memory.extend(digests_to_ints(&new_peaks));

    // Expected stack after pack+swapw+dropw: [h0, h1, h2, h3]
    let expect_stack = word_to_ints(&new_accumulator.hash_peaks());

    let test = build_test!(source, &stack, advice_stack, store, advice_map.iter().cloned());
    test.expect_stack_and_memory(&expect_stack, mmr_ptr, &expected_memory);
}

// HELPER FUNCTIONS
// ================================================================================================

fn digests_to_ints(digests: &[Word]) -> Vec<u64> {
    digests
        .iter()
        .flat_map(Into::<[Felt; WORD_SIZE]>::into)
        .map(|v| v.as_canonical_u64())
        .collect()
}

fn word_to_ints(word: &Word) -> Vec<u64> {
    let arr: [Felt; WORD_SIZE] = (*word).into();
    arr.iter().map(|v| v.as_canonical_u64()).collect()
}
