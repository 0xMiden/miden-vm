use miden_crypto::{
    Word,
    merkle::{MerklePath, NodeIndex, SparseMerklePath},
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
