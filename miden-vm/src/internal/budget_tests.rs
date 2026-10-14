use miden_processor::{ExecutionOptions, FastProcessor};

use super::*;

fn word_hex(value: u64) -> String {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    format!("0x{}", hex::encode(bytes))
}

fn base_bytes() -> usize {
    MerkleStore::default().num_internal_nodes() * 3 * Word::SERIALIZED_SIZE
}

fn inputs_with(data: MerkleData) -> InputFile {
    InputFile {
        merkle_store: Some(vec![data]),
        ..InputFile::default()
    }
}

#[test]
fn construction_stops_at_the_first_unaffordable_final_node() {
    let cases = [
        MerkleData::MerkleTree((1..=8).map(word_hex).collect()),
        MerkleData::SparseMerkleTree((0..16u64).map(|i| (i << 60, word_hex(i + 1))).collect()),
        MerkleData::PartialMerkleTree((0..8u64).rev().map(|i| ((3, i), word_hex(i + 1))).collect()),
    ];
    for data in cases {
        let options = ExecutionOptions::default().with_max_advice_size_bytes(base_bytes() + 96);
        let mut provider =
            miden_processor::advice::AdviceProvider::new(AdviceInputs::default(), &options)
                .unwrap();
        let mut parents_computed = 0;
        let err = merkle_builder::add_tree(&data, &mut |left, right| {
            parents_computed += 1;
            provider.merge_roots(left, right).map_err(|err| err.to_string())
        })
        .unwrap_err();
        assert!(err.contains("advice provider size budget exceeded"), "{err}");
        assert_eq!(parents_computed, 2, "must stop at the first node that cannot fit");
        let (_, _, store) = provider.into_parts();
        assert_eq!(
            store.num_internal_nodes() * 96,
            options.max_advice_size_bytes(),
            "the unaffordable node must not have been inserted"
        );

        let complete = inputs_with(data).parse_advice_inputs().unwrap();
        assert!(complete.store().num_internal_nodes() > store.num_internal_nodes());
    }
}

#[test]
fn sparse_budget_stops_before_later_leaves_are_decoded() {
    // The budget permits one new node: unlike a budget below the default store's cost,
    // this requires construction to start and stop while visiting the first deep path.
    let mut leaves: Vec<_> = (0..16u64).map(|i| (i << 60, word_hex(i + 1))).collect();
    leaves.last_mut().unwrap().1 = "not-a-word".into();
    let inputs = inputs_with(MerkleData::SparseMerkleTree(leaves));
    let options = ExecutionOptions::default()
        .with_max_advice_size_bytes(base_bytes() + 3 * Word::SERIALIZED_SIZE);
    let err = inputs.parse_advice_inputs_with_options(&options).unwrap_err();
    assert!(err.contains("advice provider size budget exceeded"), "{err}");
}

#[test]
fn sparse_budget_above_base_rejects_distributed_leaves() {
    let inputs = inputs_with(MerkleData::SparseMerkleTree(
        (0..16u64).map(|i| (i << 60, word_hex(i + 1))).collect(),
    ));
    let options = ExecutionOptions::default().with_max_advice_size_bytes(base_bytes() + 31 * 96);
    let err = inputs.parse_advice_inputs_with_options(&options).unwrap_err();
    assert!(err.contains("advice provider size budget exceeded"), "{err}");
}

#[test]
fn exact_budget_preserves_dense_sparse_and_partial_inputs() {
    let cases = [
        MerkleData::MerkleTree(vec![word_hex(1), word_hex(2)]),
        MerkleData::SparseMerkleTree(vec![(u64::MAX, word_hex(2)), (0, word_hex(1))]),
        MerkleData::PartialMerkleTree(vec![
            ((2, 0), word_hex(1)),
            ((1, 1), word_hex(3)),
            ((2, 1), word_hex(2)),
        ]),
    ];
    for data in cases {
        let mut inputs = inputs_with(data);
        inputs.advice_stack = Some(vec!["1".into(), "2".into(), "3".into()]);
        inputs.advice_map = Some(HashMap::from([(word_hex(7), vec![4, 5])]));
        let expected = inputs.parse_advice_inputs().unwrap();
        let required = expected.store().num_internal_nodes() * 96 + 3 * 8 + 32 + 2 * 8;
        let options = ExecutionOptions::default().with_max_advice_size_bytes(required);
        let actual = inputs.parse_advice_inputs_with_options(&options).unwrap();
        assert_eq!(actual, expected);
        FastProcessor::new_with_options(StackInputs::default(), actual, options).unwrap();
        let options = options.with_max_advice_size_bytes(required - 1);
        assert!(inputs.parse_advice_inputs_with_options(&options).is_err());
    }
}

#[test]
fn zero_sparse_entries_fit_the_empty_store_budget() {
    let inputs = inputs_with(MerkleData::SparseMerkleTree(
        (0..256).map(|index| (index, word_hex(0))).collect(),
    ));
    let options = ExecutionOptions::default().with_max_advice_size_bytes(base_bytes());
    assert_eq!(
        inputs.parse_advice_inputs_with_options(&options).unwrap(),
        inputs.parse_advice_inputs().unwrap(),
    );
}

#[test]
fn shared_and_repeated_trees_are_charged_once() {
    let inputs = InputFile {
        merkle_store: Some(vec![
            MerkleData::MerkleTree(vec![word_hex(1), word_hex(2), word_hex(1), word_hex(2)]),
            MerkleData::MerkleTree(vec![word_hex(1), word_hex(2)]),
            MerkleData::MerkleTree(vec![word_hex(1), word_hex(2)]),
            MerkleData::SparseMerkleTree(vec![(0, word_hex(1)), (1, word_hex(2))]),
            MerkleData::SparseMerkleTree(vec![(1, word_hex(2)), (0, word_hex(1))]),
            MerkleData::PartialMerkleTree(vec![((1, 0), word_hex(1)), ((1, 1), word_hex(2))]),
        ]),
        ..InputFile::default()
    };
    let expected = inputs.parse_advice_inputs().unwrap();
    let options = ExecutionOptions::default()
        .with_max_advice_size_bytes(expected.store().num_internal_nodes() * 96);
    assert_eq!(inputs.parse_advice_inputs_with_options(&options).unwrap(), expected);
}

#[test]
fn sparse_variants_match_the_legacy_store_at_exact_budget() {
    let positions = [0, 1, 2, 3, 1 << 63, u64::MAX - 1, u64::MAX];
    for seed in 0..24u64 {
        let mut leaves: Vec<_> = positions
            .iter()
            .enumerate()
            .filter(|(i, _)| !(seed + *i as u64).is_multiple_of(3))
            .map(|(i, &index)| (index, word_hex((seed + i as u64) % 4)))
            .collect();
        leaves.reverse();
        let inputs = inputs_with(MerkleData::SparseMerkleTree(leaves));
        let expected = inputs.parse_advice_inputs().unwrap();
        let options = ExecutionOptions::default()
            .with_max_advice_size_bytes(expected.store().num_internal_nodes() * 96);
        assert_eq!(
            inputs.parse_advice_inputs_with_options(&options).unwrap(),
            expected,
            "seed={seed}"
        );
    }
}

#[test]
fn partial_depth_64_and_dense_empty_subtrees_match_legacy() {
    let mut deep: Vec<_> = (1..=64).map(|depth| ((depth, 1), word_hex(depth as u64))).collect();
    deep.push(((64, 0), word_hex(65)));
    let cases = [
        MerkleData::PartialMerkleTree(deep),
        MerkleData::MerkleTree(vec![word_hex(0); 64]),
        MerkleData::MerkleTree((0..32).map(|i| word_hex(i % 3)).collect()),
    ];
    for data in cases {
        let inputs = inputs_with(data);
        let expected = inputs.parse_advice_inputs().unwrap();
        let options = ExecutionOptions::default()
            .with_max_advice_size_bytes(expected.store().num_internal_nodes() * 96);
        assert_eq!(inputs.parse_advice_inputs_with_options(&options).unwrap(), expected);
    }
}

#[test]
fn partial_duplicate_indices_keep_the_last_value() {
    let inputs = inputs_with(MerkleData::PartialMerkleTree(vec![
        ((1, 0), word_hex(1)),
        ((1, 1), word_hex(2)),
        ((1, 0), word_hex(3)),
    ]));
    let expected = inputs.parse_advice_inputs().unwrap();
    let options = ExecutionOptions::default()
        .with_max_advice_size_bytes(expected.store().num_internal_nodes() * 96);
    assert_eq!(inputs.parse_advice_inputs_with_options(&options).unwrap(), expected);
}

#[test]
fn invalid_merkle_shapes_remain_rejected() {
    let cases = [
        MerkleData::MerkleTree(vec![]),
        MerkleData::MerkleTree(vec![word_hex(1)]),
        MerkleData::MerkleTree(vec![word_hex(1); 3]),
        MerkleData::SparseMerkleTree(vec![(0, word_hex(0)), (0, word_hex(0))]),
        MerkleData::SparseMerkleTree(vec![(1, word_hex(1)), (1, word_hex(2))]),
        MerkleData::PartialMerkleTree(vec![((0, 0), word_hex(1))]),
        MerkleData::PartialMerkleTree(vec![((65, 0), word_hex(1))]),
        MerkleData::PartialMerkleTree(vec![((1, 2), word_hex(1))]),
        MerkleData::PartialMerkleTree(vec![((1, 0), word_hex(1))]),
        MerkleData::PartialMerkleTree(vec![
            ((1, 0), word_hex(1)),
            ((1, 1), word_hex(2)),
            ((2, 0), word_hex(3)),
        ]),
        MerkleData::PartialMerkleTree(vec![
            ((1, 0), "invalid".into()),
            ((1, 0), word_hex(1)),
            ((1, 1), word_hex(2)),
        ]),
    ];
    for data in cases {
        let inputs = inputs_with(data);
        assert!(inputs.parse_advice_inputs().is_err());
        assert!(inputs.parse_advice_inputs_with_options(&ExecutionOptions::default()).is_err());
    }
}

#[test]
fn empty_inputs_and_trees_fit_exact_base_budget() {
    for merkle_store in [
        None,
        Some(vec![]),
        Some(vec![
            MerkleData::SparseMerkleTree(vec![]),
            MerkleData::PartialMerkleTree(vec![]),
        ]),
    ] {
        let inputs = InputFile { merkle_store, ..InputFile::default() };
        let options = ExecutionOptions::default().with_max_advice_size_bytes(base_bytes());
        assert_eq!(
            inputs.parse_advice_inputs_with_options(&options).unwrap(),
            inputs.parse_advice_inputs().unwrap()
        );
        assert!(
            inputs
                .parse_advice_inputs_with_options(
                    &options.with_max_advice_size_bytes(base_bytes() - 1)
                )
                .is_err()
        );
    }
}

#[test]
fn normalized_advice_map_keys_are_not_double_charged() {
    let lower = word_hex(10);
    let upper = format!("0x{}", lower[2..].to_uppercase());
    assert_ne!(lower, upper);
    let inputs = InputFile {
        advice_map: Some(HashMap::from([(lower, vec![1]), (upper, vec![2, 3])])),
        ..InputFile::default()
    };
    let expected = inputs.parse_advice_inputs().unwrap();
    assert_eq!(expected.map().len(), 1);
    let value_len = expected.map().iter().next().unwrap().1.len();
    let options =
        ExecutionOptions::default().with_max_advice_size_bytes(base_bytes() + 32 + value_len * 8);
    assert_eq!(inputs.parse_advice_inputs_with_options(&options).unwrap(), expected);
}
