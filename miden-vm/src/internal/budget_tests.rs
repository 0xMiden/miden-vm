use std::collections::{BTreeMap, BTreeSet};

use miden_processor::{ExecutionOptions, FastProcessor};

use super::*;
use crate::crypto::merkle::{MerkleStore, MerkleTree, PartialMerkleTree, SimpleSmt};

// Keep an independent full-tree oracle for the streamed construction path.
fn legacy_advice_inputs(inputs: &InputFile) -> Result<AdviceInputs, String> {
    let mut store = MerkleStore::default();
    for data in inputs.merkle_store.as_deref().unwrap_or_default() {
        match data {
            MerkleData::MerkleTree(data) => {
                let tree = MerkleTree::new(InputFile::parse_merkle_tree(data)?)
                    .map_err(|err| err.to_string())?;
                store.extend(tree.inner_nodes());
            },
            MerkleData::SparseMerkleTree(data) => {
                let tree = SimpleSmt::<SIMPLE_SMT_DEPTH>::with_leaves(
                    InputFile::parse_sparse_merkle_tree(data)?,
                )
                .map_err(|err| err.to_string())?;
                store.extend(tree.inner_nodes());
            },
            MerkleData::PartialMerkleTree(data) => {
                let tree =
                    PartialMerkleTree::with_leaves(InputFile::parse_partial_merkle_tree(data)?)
                        .map_err(|err| err.to_string())?;
                store.extend(tree.inner_nodes());
            },
            MerkleData::SmtWitness(_) => unreachable!("the legacy oracle has no witness inputs"),
        }
    }
    Ok(inputs.parse_advice_inputs_base()?.with_merkle_store(store))
}

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

// SplitMix64 keeps generated fixtures deterministic without adding a test dependency.
fn next_generated_u64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
    value ^ (value >> 31)
}

fn assert_matches_legacy_at_exact_and_short_budget(data: MerkleData, context: &str) {
    let inputs = inputs_with(data);
    let expected = legacy_advice_inputs(&inputs).unwrap();
    let required = expected.store().num_internal_nodes() * 3 * Word::SERIALIZED_SIZE;
    let exact = ExecutionOptions::default().with_max_advice_size_bytes(required);
    assert_eq!(
        inputs.parse_advice_inputs_with_options(&exact).unwrap(),
        expected,
        "exact budget: {context}"
    );

    let short = exact.with_max_advice_size_bytes(required - 1);
    let err = inputs.parse_advice_inputs_with_options(&short).unwrap_err();
    assert!(
        err.contains("advice provider size budget exceeded"),
        "one-byte-short budget: {context}: {err}"
    );
}

fn generated_sparse_leaves(seed: u64) -> Vec<(u64, String)> {
    let mut state = seed;
    let prefix_bits = 1 + (next_generated_u64(&mut state) % 63) as u32;
    let suffix_bits = 64 - prefix_bits;
    let suffix_mask = (1u64 << suffix_bits) - 1;
    let prefix = next_generated_u64(&mut state) & !suffix_mask;
    let mut leaves = BTreeMap::new();

    // Most entries share an arbitrary generated prefix; the rest exercise unrelated branches.
    for index in 0..20 {
        let position = if index < 16 {
            prefix | (next_generated_u64(&mut state) & suffix_mask)
        } else {
            next_generated_u64(&mut state)
        };
        let value = next_generated_u64(&mut state) % Felt::ORDER_U64;
        leaves.insert(position, word_hex(value));
    }

    leaves.into_iter().rev().collect()
}

fn generated_partial_partition(seed: u64, splits: usize) -> Vec<((u8, u64), String)> {
    let mut state = seed;
    let mut leaves = vec![(1u8, 0u64), (1, 1)];
    for _ in 0..splits {
        let candidates: Vec<_> = leaves
            .iter()
            .enumerate()
            .filter(|(_, (depth, _))| *depth < SIMPLE_SMT_DEPTH)
            .map(|(index, _)| index)
            .collect();
        let selected = candidates[next_generated_u64(&mut state) as usize % candidates.len()];
        let (depth, position) = leaves.swap_remove(selected);
        leaves.push((depth + 1, position * 2));
        leaves.push((depth + 1, position * 2 + 1));
    }

    leaves
        .into_iter()
        .map(|index| {
            let value = next_generated_u64(&mut state) % Felt::ORDER_U64;
            (index, word_hex(value))
        })
        .collect()
}

fn right_edge_depth_64_partition() -> Vec<((u8, u64), String)> {
    let mut leaves = vec![(1u8, 0u64), (1, 1)];
    for depth in 1..SIMPLE_SMT_DEPTH {
        let position = (1u64 << depth) - 1;
        let selected = leaves.iter().position(|index| *index == (depth, position)).unwrap();
        leaves.swap_remove(selected);
        leaves.push((depth + 1, position * 2));
        leaves.push((depth + 1, position * 2 + 1));
    }

    leaves
        .into_iter()
        .enumerate()
        .map(|(value, index)| (index, word_hex(value as u64 + 1)))
        .collect()
}

#[test]
fn witness_and_legacy_trees_share_the_same_budget() {
    use crate::{
        crypto::merkle::{PartialSmt, Smt},
        serde::Serializable,
    };

    let key = Word::from([1, 2, 3, 7u32]);
    let tree = Smt::with_entries([(key, Word::from([4u32; 4]))]).unwrap();
    let partial = PartialSmt::from_proofs([tree.open(&key)]).unwrap();
    let encoded = format!("0x{}", hex::encode(SmtWitness::from(&partial).to_bytes()));
    let expected = inputs_with(MerkleData::SmtWitness(encoded.clone()))
        .parse_advice_inputs()
        .unwrap();
    let required = expected.store().num_internal_nodes() * 96
        + expected.map().total_element_count().unwrap() * 8;
    let exact = ExecutionOptions::default().with_max_advice_size_bytes(required);

    for witness_first in [false, true] {
        let witness = MerkleData::SmtWitness(encoded.clone());
        let legacy = MerkleData::SparseMerkleTree(vec![(7, tree.get_leaf(&key).hash().to_hex())]);
        let inputs = InputFile {
            merkle_store: Some(if witness_first {
                vec![witness, legacy]
            } else {
                vec![legacy, witness]
            }),
            ..InputFile::default()
        };
        assert_eq!(inputs.parse_advice_inputs_with_options(&exact).unwrap(), expected);
        let short = exact.clone().with_max_advice_size_bytes(required - 1);
        let err = inputs.parse_advice_inputs_with_options(&short).unwrap_err();
        assert!(err.contains("advice provider size budget exceeded"), "{err}");
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
        let mut provider = AdviceProvider::new(AdviceInputs::default(), &options).unwrap();
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

        let complete = legacy_advice_inputs(&inputs_with(data)).unwrap();
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
        let expected = legacy_advice_inputs(&inputs).unwrap();
        let required = expected.store().num_internal_nodes() * 96 + 3 * 8 + 32 + 2 * 8;
        let options = ExecutionOptions::default().with_max_advice_size_bytes(required);
        let actual = inputs.parse_advice_inputs_with_options(&options).unwrap();
        assert_eq!(actual, expected);
        FastProcessor::new_with_options(StackInputs::default(), actual, options.clone()).unwrap();
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
        legacy_advice_inputs(&inputs).unwrap(),
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
    let expected = legacy_advice_inputs(&inputs).unwrap();
    let options = ExecutionOptions::default()
        .with_max_advice_size_bytes(expected.store().num_internal_nodes() * 96);
    assert_eq!(inputs.parse_advice_inputs_with_options(&options).unwrap(), expected);
}

#[test]
fn generated_sparse_prefixes_match_legacy_at_budget_boundary() {
    for seed in 0..16u64 {
        let leaves = generated_sparse_leaves(seed);
        assert_matches_legacy_at_exact_and_short_budget(
            MerkleData::SparseMerkleTree(leaves),
            &format!("sparse seed={seed}"),
        );
    }
}

#[test]
fn generated_mixed_depth_partitions_match_legacy_at_budget_boundary() {
    for seed in 0..12u64 {
        let leaves = generated_partial_partition(seed, 12 + seed as usize);
        let depths: BTreeSet<_> = leaves.iter().map(|((depth, _), _)| *depth).collect();
        assert!(depths.len() >= 3, "seed={seed}: expected mixed depths");
        assert_matches_legacy_at_exact_and_short_budget(
            MerkleData::PartialMerkleTree(leaves),
            &format!("partial seed={seed}"),
        );
    }

    let leaves = right_edge_depth_64_partition();
    assert!(leaves.iter().any(|(index, _)| *index == (64, u64::MAX)));
    assert_matches_legacy_at_exact_and_short_budget(
        MerkleData::PartialMerkleTree(leaves),
        "right-edge depth-64 partition",
    );
}

#[test]
fn dense_empty_subtrees_match_legacy() {
    let cases = [
        MerkleData::MerkleTree(vec![word_hex(0); 64]),
        MerkleData::MerkleTree((0..32).map(|i| word_hex(i % 3)).collect()),
    ];
    for data in cases {
        let inputs = inputs_with(data);
        let expected = legacy_advice_inputs(&inputs).unwrap();
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
    let expected = legacy_advice_inputs(&inputs).unwrap();
    let options = ExecutionOptions::default()
        .with_max_advice_size_bytes(expected.store().num_internal_nodes() * 96);
    assert_eq!(inputs.parse_advice_inputs_with_options(&options).unwrap(), expected);
}

#[test]
fn partial_missing_node_error_reports_depth_and_position() {
    let cases = [
        (
            vec![((2, 0), word_hex(1)), ((2, 2), word_hex(2)), ((2, 3), word_hex(3))],
            "failed to parse a Partial Merkle Tree: incomplete leaves: missing node at depth 2 \
             and position 1",
        ),
        (
            vec![((1, 1), word_hex(1))],
            "failed to parse a Partial Merkle Tree: incomplete leaves: missing node at depth 1 \
             and position 0",
        ),
        (
            vec![((1, 0), word_hex(1))],
            "failed to parse a Partial Merkle Tree: incomplete leaves: missing node at depth 1 \
             and position 1",
        ),
    ];
    for (leaves, expected) in cases {
        let inputs = inputs_with(MerkleData::PartialMerkleTree(leaves));
        let err = inputs
            .parse_advice_inputs_with_options(&ExecutionOptions::default())
            .unwrap_err();
        assert_eq!(err, expected);
    }
}

#[test]
fn partial_overlap_error_reports_ancestor_depth_and_position() {
    let inputs = inputs_with(MerkleData::PartialMerkleTree(vec![
        ((1, 0), word_hex(1)),
        ((2, 0), word_hex(2)),
        ((2, 1), word_hex(3)),
        ((1, 1), word_hex(4)),
    ]));

    let err = inputs
        .parse_advice_inputs_with_options(&ExecutionOptions::default())
        .unwrap_err();

    assert_eq!(
        err,
        "failed to parse a Partial Merkle Tree: overlapping leaves: node at depth 1 and position \
         0 is an ancestor of node at depth 2 and position 0"
    );
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
        assert!(legacy_advice_inputs(&inputs).is_err());
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
            legacy_advice_inputs(&inputs).unwrap()
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
    let expected = legacy_advice_inputs(&inputs).unwrap();
    assert_eq!(expected.map().len(), 1);
    let value_len = expected.map().iter().next().unwrap().1.len();
    let options =
        ExecutionOptions::default().with_max_advice_size_bytes(base_bytes() + 32 + value_len * 8);
    assert_eq!(inputs.parse_advice_inputs_with_options(&options).unwrap(), expected);
}
