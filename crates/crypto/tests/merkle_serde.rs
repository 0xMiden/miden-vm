use std::collections::{BTreeMap, BTreeSet};

use miden_crypto::{
    Felt, Map, Word, ZERO,
    merkle::{
        MerklePath, MerkleTree, NodeIndex, PartialMerkleTree, SparseMerklePath,
        mmr::{Forest, Mmr, MmrPath, MmrPeaks},
        smt::{InnerNode, SimpleSmt},
    },
    utils::{Deserializable, Serializable},
};
use serde_json::json;

#[test]
fn node_index_serde_validates_depth_and_position() {
    for index in [
        NodeIndex::new(0, 0).unwrap(),
        NodeIndex::new(63, (1u64 << 63) - 1).unwrap(),
        NodeIndex::new(64, u64::MAX).unwrap(),
    ] {
        let value = serde_json::to_value(index).unwrap();
        assert_eq!(serde_json::from_value::<NodeIndex>(value).unwrap(), index);
    }

    assert!(serde_json::from_value::<NodeIndex>(json!({ "depth": 0, "position": 1 })).is_err());
    assert!(serde_json::from_value::<NodeIndex>(json!({ "depth": 65, "position": 0 })).is_err());
}

#[test]
fn merkle_path_serde_validates_length() {
    for len in [0usize, 1, u8::MAX as usize] {
        let path = MerklePath::new(vec![Word::default(); len]);
        let encoded = serde_json::to_vec(&path).unwrap();
        assert_eq!(serde_json::from_slice::<MerklePath>(&encoded).unwrap(), path);
    }

    let encoded = serde_json::to_vec(&json!({
        "nodes": vec![Word::default(); u8::MAX as usize + 1],
    }))
    .unwrap();
    let error = serde_json::from_slice::<MerklePath>(&encoded).unwrap_err();
    assert!(error.to_string().contains("sequence contains more than 255 elements"));
}

#[test]
fn sparse_merkle_path_serde_validates_parts() {
    for (mask, node_count) in [
        (0, 0),
        (0, 64),
        (1, 0),
        (1u64 << 63, 63),
        (0xaaaa_aaaa_aaaa_aaaa, 32),
        (u64::MAX, 0),
    ] {
        let path = SparseMerklePath::from_parts(mask, vec![Word::default(); node_count]).unwrap();
        let encoded = serde_json::to_vec(&path).unwrap();
        assert_eq!(serde_json::from_slice::<SparseMerklePath>(&encoded).unwrap(), path);
    }

    let encoded = serde_json::to_vec(&json!({
        "empty_nodes_mask": 1u64 << 63,
        "nodes": [Word::default()],
    }))
    .unwrap();
    assert!(serde_json::from_slice::<SparseMerklePath>(&encoded).is_err());

    let encoded = serde_json::to_vec(&json!({
        "empty_nodes_mask": 0,
        "nodes": vec![Word::default(); 65],
    }))
    .unwrap();
    let error = serde_json::from_slice::<SparseMerklePath>(&encoded).unwrap_err();
    assert!(error.to_string().contains("sequence contains more than 64 elements"));
}

// STRUCTURED-TYPE VALIDATION
// ================================================================================================

/// Decodes through a JSON string rather than `from_value`: `Word` deserializes from a borrowed
/// hex string, which an owned `serde_json::Value` cannot lend.
fn decode<T: serde::de::DeserializeOwned>(
    value: &serde_json::Value,
) -> Result<T, serde_json::Error> {
    serde_json::from_str(&serde_json::to_string(value).unwrap())
}

fn leaf(value: u64) -> Word {
    Word::new([Felt::new_unchecked(value), ZERO, ZERO, ZERO])
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename = "PartialMerkleTree")]
struct RawPartialMerkleTree {
    max_depth: u8,
    nodes: BTreeMap<NodeIndex, Word>,
    leaves: BTreeSet<NodeIndex>,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename = "SimpleSmt")]
struct RawSimpleSmt {
    root: Word,
    inner_nodes: Map<NodeIndex, InnerNode>,
    leaves: Map<u64, Word>,
}

#[test]
fn mmr_serde_and_binary_validate_state() {
    let mut mmr = Mmr::new();
    for value in 1..=3u64 {
        mmr.add(leaf(value)).unwrap();
    }
    let value = serde_json::to_value(&mmr).unwrap();
    // Mmr has no PartialEq; compare canonical binary encodings instead.
    let round_tripped = decode::<Mmr>(&value).unwrap();
    assert_eq!(round_tripped.to_bytes(), mmr.to_bytes());

    // Dropping a node breaks the forest-implied count.
    let mut tampered = value.clone();
    tampered["nodes"].as_array_mut().unwrap().pop();
    assert!(decode::<Mmr>(&tampered).is_err());

    // The third node is the parent of the first two leaves. Its hash must match those children.
    let mut tampered = value;
    tampered["nodes"][2] = serde_json::to_value(leaf(999)).unwrap();
    assert!(decode::<Mmr>(&tampered).is_err());

    // Binary deserialization enforces the same node-count and parent-hash checks.
    let mut bytes = Forest::new(7).unwrap().to_bytes();
    bytes.extend(vec![leaf(1); 2].to_bytes());
    assert!(Mmr::read_from_bytes(&bytes).is_err());

    let mut bytes = Forest::new(3).unwrap().to_bytes();
    bytes.extend(vec![leaf(1), leaf(2), leaf(999), leaf(3)].to_bytes());
    assert!(Mmr::read_from_bytes(&bytes).is_err());
}

#[test]
fn mmr_peaks_serde_validates_peak_count() {
    let forest = Forest::new(Forest::MAX_LEAVES).unwrap();
    let peaks = MmrPeaks::new(forest, vec![leaf(1); forest.num_trees()]).unwrap();
    let value = serde_json::to_value(&peaks).unwrap();
    assert_eq!(decode::<MmrPeaks>(&value).unwrap(), peaks);

    let mut tampered = value;
    tampered["peaks"].as_array_mut().unwrap().pop();
    assert!(decode::<MmrPeaks>(&tampered).is_err());
}

#[test]
fn mmr_peaks_serde_rejects_the_first_excess_peak() {
    let max_peaks = Forest::MAX_LEAVES.count_ones() as usize;
    let value = json!({ "forest": 0, "peaks": vec![Word::default(); max_peaks + 1] });

    let error = decode::<MmrPeaks>(&value).unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains(&format!("sequence contains more than {max_peaks} elements")),
        "unexpected error: {message}",
    );
}

#[test]
fn mmr_path_serde_validates_position_and_depth() {
    let path = MmrPath::new(Forest::new(2).unwrap(), 0, MerklePath::new(vec![leaf(9)]));
    let value = serde_json::to_value(&path).unwrap();
    assert_eq!(decode::<MmrPath>(&value).unwrap(), path);

    // Both relative-position and peak-index calculations require a position inside the forest.
    let mut tampered = value.clone();
    tampered["position"] = serde_json::json!(2);
    assert!(decode::<MmrPath>(&tampered).is_err());

    for path_len in [0, 2] {
        let mut tampered = value.clone();
        tampered["merkle_path"]["nodes"] = json!(vec![Word::default(); path_len]);
        assert!(decode::<MmrPath>(&tampered).is_err(), "accepted path length {path_len}");
    }
}

#[test]
fn merkle_tree_serde_validates_internal_nodes() {
    let tree = MerkleTree::new(vec![leaf(1), leaf(2), leaf(3), leaf(4)]).unwrap();
    let value = serde_json::to_value(&tree).unwrap();
    assert_eq!(decode::<MerkleTree>(&value).unwrap(), tree);

    // Tampering with an internal node must be caught by the rebuild comparison.
    let mut tampered = value.clone();
    tampered["nodes"][1] = serde_json::to_value(leaf(999)).unwrap();
    assert!(decode::<MerkleTree>(&tampered).is_err());

    // A node buffer that is not twice a power-of-two leaf count is rejected up front.
    let mut truncated = value;
    truncated["nodes"].as_array_mut().unwrap().pop();
    assert!(decode::<MerkleTree>(&truncated).is_err());
}

#[test]
fn partial_merkle_tree_serde_validates_state() {
    // JSON cannot represent the NodeIndex map keys, so use it only for the dangling-leaf check.
    let tree = PartialMerkleTree::new();
    let value = serde_json::to_value(&tree).unwrap();
    assert_eq!(decode::<PartialMerkleTree>(&value).unwrap(), tree);

    // A leaf listed without a value in the node map must be rejected.
    let mut tampered = value;
    tampered["leaves"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::to_value(NodeIndex::new(1, 0).unwrap()).unwrap());
    assert!(decode::<PartialMerkleTree>(&tampered).is_err());

    // Postcard supports structured map keys and exercises a non-empty tree.
    let tree = PartialMerkleTree::with_leaves(BTreeMap::from([
        (NodeIndex::new(1, 0).unwrap(), leaf(1)),
        (NodeIndex::new(1, 1).unwrap(), leaf(2)),
    ]))
    .unwrap();
    let valid_encoded = postcard::to_allocvec(&tree).unwrap();
    assert_eq!(postcard::from_bytes::<PartialMerkleTree>(&valid_encoded).unwrap(), tree);

    // Changing a claimed internal node must fail even when all leaves are present.
    let mut tampered = postcard::from_bytes::<RawPartialMerkleTree>(&valid_encoded).unwrap();
    *tampered.nodes.get_mut(&NodeIndex::root()).unwrap() = leaf(999);
    let encoded = postcard::to_allocvec(&tampered).unwrap();
    assert!(postcard::from_bytes::<PartialMerkleTree>(&encoded).is_err());

    // The maximum depth is derived from the materialized leaves.
    let mut tampered = postcard::from_bytes::<RawPartialMerkleTree>(&valid_encoded).unwrap();
    tampered.max_depth += 1;
    let encoded = postcard::to_allocvec(&tampered).unwrap();
    assert!(postcard::from_bytes::<PartialMerkleTree>(&encoded).is_err());

    // A non-empty depth-zero tree violates the PartialMerkleTree leaf-depth invariant.
    let root = NodeIndex::root();
    let tampered = RawPartialMerkleTree {
        max_depth: 0,
        nodes: BTreeMap::from([(root, leaf(1))]),
        leaves: BTreeSet::from([root]),
    };
    let encoded = postcard::to_allocvec(&tampered).unwrap();
    assert!(postcard::from_bytes::<PartialMerkleTree>(&encoded).is_err());
}

#[test]
fn simple_smt_serde_validates_state() {
    // JSON cannot represent the non-empty inner-node map's NodeIndex keys, so use it for the
    // empty-tree root check only.
    let tree = SimpleSmt::<8>::new().unwrap();
    let value = serde_json::to_value(&tree).unwrap();
    assert_eq!(decode::<SimpleSmt<8>>(&value).unwrap(), tree);

    let mut tampered = value;
    tampered["root"] = serde_json::to_value(leaf(999)).unwrap();
    assert!(decode::<SimpleSmt<8>>(&tampered).is_err());

    // Postcard supports structured map keys and exercises a non-empty tree.
    let tree = SimpleSmt::<8>::with_leaves([(3, leaf(1)), (200, leaf(2))]).unwrap();
    let encoded = postcard::to_allocvec(&tree).unwrap();
    assert_eq!(postcard::from_bytes::<SimpleSmt<8>>(&encoded).unwrap(), tree);

    // Changing a claimed inner node must fail even when the root and leaves are unchanged.
    let mut tampered = postcard::from_bytes::<RawSimpleSmt>(&encoded).unwrap();
    tampered.inner_nodes.get_mut(&NodeIndex::root()).unwrap().left = leaf(999);
    let tampered = postcard::to_allocvec(&tampered).unwrap();
    assert!(postcard::from_bytes::<SimpleSmt<8>>(&tampered).is_err());

    // Empty values are canonicalized away and may not be claimed as materialized leaves.
    let mut tampered = postcard::from_bytes::<RawSimpleSmt>(&encoded).unwrap();
    tampered.leaves.insert(7, Word::default());
    let tampered = postcard::to_allocvec(&tampered).unwrap();
    assert!(postcard::from_bytes::<SimpleSmt<8>>(&tampered).is_err());
}
