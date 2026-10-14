//! Postorder construction of input-file Merkle trees.
//!
//! Only final parents are emitted to the budgeted advice provider. In particular, sparse-tree
//! updates must not retain historical roots or build the entire SMT before checking the budget.
//! Sorting sparse/partial inputs requires borrowed metadata proportional to the input, but the
//! recursive hash frontier is bounded by the tree depth (at most 64).

use std::collections::BTreeMap;

use super::{InputFile, MerkleData, SIMPLE_SMT_DEPTH, Word};
use crate::crypto::merkle::{EmptySubtreeRoots, MerkleError, NodeIndex};

/// Emits each final parent immediately; an error from `merge` stops construction.
pub(super) fn add_tree(
    data: &MerkleData,
    merge: &mut impl FnMut(Word, Word) -> Result<Word, String>,
) -> Result<Word, String> {
    match data {
        MerkleData::MerkleTree(leaves) => {
            let n = leaves.len();
            if n <= 1 {
                return Err(format!(
                    "failed to parse a Merkle tree: {}",
                    MerkleError::DepthTooSmall(n as u8)
                ));
            }
            if !n.is_power_of_two() {
                return Err(format!(
                    "failed to parse a Merkle tree: {}",
                    MerkleError::NumLeavesNotPowerOfTwo(n)
                ));
            }
            dense_subtree(leaves, merge)
        },
        MerkleData::SparseMerkleTree(leaves) => {
            let mut entries: Vec<_> = leaves.iter().collect();
            entries.sort_unstable_by_key(|(index, _)| *index);
            for pair in entries.windows(2) {
                if pair[0].0 == pair[1].0 {
                    return Err(format!(
                        "failed to parse a Sparse Merkle Tree: {}",
                        MerkleError::DuplicateValuesForIndex(pair[0].0)
                    ));
                }
            }
            sparse_subtree(&entries, 0, merge)
        },
        MerkleData::PartialMerkleTree(leaves) => {
            // Match PartialMerkleTree's last-value-wins semantics for repeated indices. Validate
            // every supplied word, including overwritten values, as the legacy parser does.
            let mut by_index = BTreeMap::new();
            for ((depth, position), value) in leaves {
                let index = NodeIndex::new(*depth, *position).map_err(|err| err.to_string())?;
                InputFile::parse_word(value)?;
                if *depth == 0 {
                    return Err(MerkleError::DepthTooSmall(0).to_string());
                }
                by_index.insert(index, value.as_str());
            }
            let mut entries: Vec<_> = by_index.into_iter().collect();
            entries.sort_unstable_by_key(|(index, _)| interval_start(*index));
            if entries.is_empty() {
                return Ok(Word::default());
            }

            // A partial tree is a complete partition of the root's leaf interval. Missing
            // siblings and ancestor/descendant pairs must not be interpreted as empty subtrees.
            let mut end = 0u128;
            for (index, _) in &entries {
                if interval_start(*index) != end {
                    return Err(
                        "failed to parse a Partial Merkle Tree: incomplete or overlapping leaves"
                            .into(),
                    );
                }
                end = (u128::from(index.position()) + 1) << (SIMPLE_SMT_DEPTH - index.depth());
            }
            if end != 1u128 << SIMPLE_SMT_DEPTH {
                return Err("failed to parse a Partial Merkle Tree: incomplete leaves".into());
            }
            partial_subtree(&entries, NodeIndex::root(), merge)
        },
    }
}

fn dense_subtree(
    leaves: &[String],
    merge: &mut impl FnMut(Word, Word) -> Result<Word, String>,
) -> Result<Word, String> {
    if leaves.len() == 1 {
        return InputFile::parse_word(&leaves[0]);
    }
    let (left, right) = leaves.split_at(leaves.len() / 2);
    let left = dense_subtree(left, merge)?;
    let right = dense_subtree(right, merge)?;
    merge(left, right)
}

fn sparse_subtree(
    entries: &[&(u64, String)],
    depth: u8,
    merge: &mut impl FnMut(Word, Word) -> Result<Word, String>,
) -> Result<Word, String> {
    let empty = *EmptySubtreeRoots::entry(SIMPLE_SMT_DEPTH, depth);
    if entries.is_empty() {
        return Ok(empty);
    }
    if depth == SIMPLE_SMT_DEPTH {
        return InputFile::parse_word(&entries[0].1);
    }
    let bit = 1u64 << (SIMPLE_SMT_DEPTH - depth - 1);
    let split = entries.partition_point(|(index, _)| index & bit == 0);
    let left = sparse_subtree(&entries[..split], depth + 1, merge)?;
    let right = sparse_subtree(&entries[split..], depth + 1, merge)?;
    let empty_child = *EmptySubtreeRoots::entry(SIMPLE_SMT_DEPTH, depth + 1);
    if left == empty_child && right == empty_child {
        return Ok(empty);
    }
    merge(left, right)
}

fn interval_start(index: NodeIndex) -> u128 {
    u128::from(index.position()) << (SIMPLE_SMT_DEPTH - index.depth())
}

fn partial_subtree(
    entries: &[(NodeIndex, &str)],
    index: NodeIndex,
    merge: &mut impl FnMut(Word, Word) -> Result<Word, String>,
) -> Result<Word, String> {
    if entries.len() == 1 && entries[0].0 == index {
        return InputFile::parse_word(entries[0].1);
    }
    // Interval validation above guarantees two nonempty children and a maximum depth of 64.
    let depth = index.depth() + 1;
    let left_index = NodeIndex::new(depth, index.position() * 2).map_err(|err| err.to_string())?;
    let right_index =
        NodeIndex::new(depth, index.position() * 2 + 1).map_err(|err| err.to_string())?;
    let split =
        entries.partition_point(|(leaf, _)| interval_start(*leaf) < interval_start(right_index));
    let left = partial_subtree(&entries[..split], left_index, merge)?;
    let right = partial_subtree(&entries[split..], right_index, merge)?;
    merge(left, right)
}
