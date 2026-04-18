use alloc::{collections::BTreeMap, vec::Vec};

use super::{
    super::{
        MerkleError, MerkleTree, NodeIndex, PartialMerkleTree, int_to_node, store::MerkleStore,
    },
    Deserializable, DeserializationError, InnerNodeInfo, MerkleProof, Serializable, Word,
};

// TEST DATA
// ================================================================================================

const NODE10: NodeIndex = NodeIndex::new_unchecked(1, 0);
const NODE11: NodeIndex = NodeIndex::new_unchecked(1, 1);

const NODE20: NodeIndex = NodeIndex::new_unchecked(2, 0);
const NODE21: NodeIndex = NodeIndex::new_unchecked(2, 1);
const NODE22: NodeIndex = NodeIndex::new_unchecked(2, 2);
const NODE23: NodeIndex = NodeIndex::new_unchecked(2, 3);

const NODE30: NodeIndex = NodeIndex::new_unchecked(3, 0);
const NODE31: NodeIndex = NodeIndex::new_unchecked(3, 1);
const NODE32: NodeIndex = NodeIndex::new_unchecked(3, 2);
const NODE33: NodeIndex = NodeIndex::new_unchecked(3, 3);

const VALUES8: [Word; 8] = [
    int_to_node(30),
    int_to_node(31),
    int_to_node(32),
    int_to_node(33),
    int_to_node(34),
    int_to_node(35),
    int_to_node(36),
    int_to_node(37),
];

// TESTS
// ================================================================================================

// For the Partial Merkle Tree tests we will use parts of the Merkle Tree which full form is
// illustrated below:
//
//              __________ root __________
//             /                          \
//       ____ 10 ____                ____ 11 ____
//      /            \              /            \
//     20            21            22            23
//   /    \        /    \        /    \        /    \
// (30)  (31)    (32)  (33)    (34)  (35)    (36)  (37)
//
// Where node number is a concatenation of its depth and index. For example, node with
// NodeIndex(3, 5) will be labeled as `35`. Leaves of the tree are shown as nodes with parenthesis
// (33).

/// Checks that creation of the PMT with `with_leaves()` constructor is working correctly.
#[test]
fn with_leaves() {
    let mt = MerkleTree::new(VALUES8).unwrap();
    let expected_root = mt.root();

    let leaf_nodes_vec = vec![
        (NODE20, mt.get_node(NODE20).unwrap()),
        (NODE32, mt.get_node(NODE32).unwrap()),
        (NODE33, mt.get_node(NODE33).unwrap()),
        (NODE22, mt.get_node(NODE22).unwrap()),
        (NODE23, mt.get_node(NODE23).unwrap()),
    ];

    let leaf_nodes: BTreeMap<NodeIndex, Word> = leaf_nodes_vec.into_iter().collect();

    let pmt = PartialMerkleTree::with_leaves(leaf_nodes).unwrap();

    assert_eq!(expected_root, pmt.root())
}

/// Checks that `with_leaves()` function returns an error when using incomplete set of nodes.
#[test]
fn err_with_leaves() {
    // NODE22 is missing
    let leaf_nodes_vec = vec![
        (NODE20, int_to_node(20)),
        (NODE32, int_to_node(32)),
        (NODE33, int_to_node(33)),
        (NODE23, int_to_node(23)),
    ];

    let leaf_nodes: BTreeMap<NodeIndex, Word> = leaf_nodes_vec.into_iter().collect();

    assert!(PartialMerkleTree::with_leaves(leaf_nodes).is_err());
}

/// Checks that `with_leaves()` accepts an empty input and returns an empty tree.
#[test]
fn with_leaves_empty() {
    let leaf_nodes: BTreeMap<NodeIndex, Word> = BTreeMap::new();

    let pmt = PartialMerkleTree::with_leaves(leaf_nodes).unwrap();

    assert_eq!(PartialMerkleTree::new().root(), pmt.root());
    assert_eq!(0, pmt.max_depth());
}

/// Checks that `read_from_bytes_with_budget()` accepts an empty input.
#[test]
fn deserialize_empty_with_budget() {
    let pmt = PartialMerkleTree::new();
    let bytes = pmt.to_bytes();

    let parsed = PartialMerkleTree::read_from_bytes_with_budget(&bytes, bytes.len()).unwrap();
    assert_eq!(pmt, parsed);
}

/// Checks that oversized leaf counts are rejected during deserialization.
#[test]
fn deserialize_rejects_oversized_length() {
    let mut bytes = Vec::new();
    u64::MAX.write_into(&mut bytes);

    let result = PartialMerkleTree::read_from_bytes_with_budget(&bytes, bytes.len());
    assert!(matches!(result, Err(DeserializationError::InvalidValue(_))));
}

/// Tests that `with_leaves()` returns `EntryIsNotLeaf` error when an entry
/// is an ancestor of another entry.
#[test]
fn err_with_leaves_entry_is_not_leaf() {
    // Provide all 8 leaves at depth 3
    let mut entries: BTreeMap<NodeIndex, Word> = (0u64..8)
        .map(|i| (NodeIndex::new(3, i).unwrap(), VALUES8[i as usize]))
        .collect();

    // Add an entry at depth 1 - this is an ancestor of some depth-3 entries
    entries.insert(NodeIndex::new(1, 0).unwrap(), int_to_node(999));

    // Verify we get EntryIsNotLeaf error
    match PartialMerkleTree::with_leaves(entries) {
        Err(MerkleError::EntryIsNotLeaf { node }) => {
            assert_eq!(node.depth(), 1);
            assert_eq!(node.position(), 0);
        },
        other => panic!("Expected EntryIsNotLeaf error, got {:?}", other),
    }
}

/// Checks that root returned by `root()` function is equal to the expected one.
#[test]
fn get_root() {
    let mt = MerkleTree::new(VALUES8).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);
    let path33 = ms.get_path(expected_root, NODE33).unwrap();

    let pmt = PartialMerkleTree::with_paths([(3, path33.value, path33.path)]).unwrap();

    assert_eq!(expected_root, pmt.root());
}

/// This test checks correctness of the `add_path()` and `get_path()` functions. First it creates a
/// PMT using `add_path()` by adding Merkle Paths from node 33 and node 22 to the empty PMT. Then
/// it checks that paths returned by `get_path()` function are equal to the expected ones.
#[test]
fn add_and_get_paths() {
    let mt = MerkleTree::new(VALUES8).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let expected_path33 = ms.get_path(expected_root, NODE33).unwrap();
    let expected_path22 = ms.get_path(expected_root, NODE22).unwrap();

    let mut pmt = PartialMerkleTree::new();
    pmt.add_path(3, expected_path33.value, expected_path33.path.clone()).unwrap();
    pmt.add_path(2, expected_path22.value, expected_path22.path.clone()).unwrap();

    let path33 = pmt.get_path(NODE33).unwrap();
    let path22 = pmt.get_path(NODE22).unwrap();
    let actual_root = pmt.root();

    assert_eq!(expected_path33.path, path33);
    assert_eq!(expected_path22.path, path22);
    assert_eq!(expected_root, actual_root);
}

/// Checks that function `get_node` used on nodes 10 and 32 returns expected values.
#[test]
fn get_node() {
    let mt = MerkleTree::new(VALUES8).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, NODE33).unwrap();

    let pmt = PartialMerkleTree::with_paths([(3, path33.value, path33.path)]).unwrap();

    assert_eq!(ms.get_node(expected_root, NODE32).unwrap(), pmt.get_node(NODE32).unwrap());
    assert_eq!(ms.get_node(expected_root, NODE10).unwrap(), pmt.get_node(NODE10).unwrap());
}

/// Updates leaves of the PMT using `update_leaf()` function and checks that new root of the tree
/// is equal to the expected one.
#[test]
fn update_leaf() {
    let mt = MerkleTree::new(VALUES8).unwrap();
    let root = mt.root();

    let mut ms = MerkleStore::from(&mt);
    let path33 = ms.get_path(root, NODE33).unwrap();

    let mut pmt = PartialMerkleTree::with_paths([(3, path33.value, path33.path)]).unwrap();

    let new_value32 = int_to_node(132);
    let expected_root = ms.set_node(root, NODE32, new_value32).unwrap().root;

    pmt.update_leaf(2, new_value32).unwrap();
    let actual_root = pmt.root();

    assert_eq!(expected_root, actual_root);

    let new_value20 = int_to_node(120);
    let expected_root = ms.set_node(expected_root, NODE20, new_value20).unwrap().root;

    pmt.update_leaf(0, new_value20).unwrap();
    let actual_root = pmt.root();

    assert_eq!(expected_root, actual_root);

    let new_value11 = int_to_node(111);
    let expected_root = ms.set_node(expected_root, NODE11, new_value11).unwrap().root;

    pmt.update_leaf(6, new_value11).unwrap();
    let actual_root = pmt.root();

    assert_eq!(expected_root, actual_root);
}

/// Checks that paths of the PMT returned by `paths()` function are equal to the expected ones.
#[test]
fn get_paths() {
    let mt = MerkleTree::new(VALUES8).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, NODE33).unwrap();
    let path22 = ms.get_path(expected_root, NODE22).unwrap();

    let mut pmt = PartialMerkleTree::new();
    pmt.add_path(3, path33.value, path33.path).unwrap();
    pmt.add_path(2, path22.value, path22.path).unwrap();
    // After PMT creation with path33 (33; 32, 20, 11) and path22 (22; 23, 10) we will have this
    // tree:
    //
    //           ______root______
    //          /                \
    //      ___10___           ___11___
    //     /        \         /        \
    //   (20)       21      (22)      (23)
    //            /    \
    //          (32)  (33)
    //
    // Which have leaf nodes 20, 22, 23, 32 and 33. Hence overall we will have 5 paths -- one path
    // for each leaf.

    let leaves = [NODE20, NODE22, NODE23, NODE32, NODE33];
    let expected_paths: Vec<(NodeIndex, MerkleProof)> = leaves
        .iter()
        .map(|&leaf| {
            (
                leaf,
                MerkleProof {
                    value: mt.get_node(leaf).unwrap(),
                    path: mt.get_path(leaf).unwrap(),
                },
            )
        })
        .collect();

    let actual_paths = pmt.to_paths();

    assert_eq!(expected_paths, actual_paths);
}

// Checks correctness of leaves determination when using the `leaves()` function.
#[test]
fn leaves() {
    let mt = MerkleTree::new(VALUES8).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, NODE33).unwrap();
    let path22 = ms.get_path(expected_root, NODE22).unwrap();

    let mut pmt = PartialMerkleTree::with_paths([(3, path33.value, path33.path)]).unwrap();
    // After PMT creation with path33 (33; 32, 20, 11) we will have this tree:
    //
    //           ______root______
    //          /                \
    //      ___10___            (11)
    //     /         \
    //   (20)        21
    //             /    \
    //           (32)  (33)
    //
    // Which have leaf nodes 11, 20, 32 and 33.

    let value11 = mt.get_node(NODE11).unwrap();
    let value20 = mt.get_node(NODE20).unwrap();
    let value32 = mt.get_node(NODE32).unwrap();
    let value33 = mt.get_node(NODE33).unwrap();

    let leaves = [(NODE11, value11), (NODE20, value20), (NODE32, value32), (NODE33, value33)];

    let expected_leaves = leaves.iter().copied();
    assert!(expected_leaves.eq(pmt.leaves()));

    pmt.add_path(2, path22.value, path22.path).unwrap();
    // After adding the path22 (22; 23, 10) to the existing PMT we will have this tree:
    //
    //           ______root______
    //          /                \
    //      ___10___           ___11___
    //     /        \         /        \
    //   (20)       21      (22)      (23)
    //            /    \
    //          (32)  (33)
    //
    // Which have leaf nodes 20, 22, 23, 32 and 33.

    let value20 = mt.get_node(NODE20).unwrap();
    let value22 = mt.get_node(NODE22).unwrap();
    let value23 = mt.get_node(NODE23).unwrap();
    let value32 = mt.get_node(NODE32).unwrap();
    let value33 = mt.get_node(NODE33).unwrap();

    let leaves = [
        (NODE20, value20),
        (NODE22, value22),
        (NODE23, value23),
        (NODE32, value32),
        (NODE33, value33),
    ];

    let expected_leaves = leaves.iter().copied();
    assert!(expected_leaves.eq(pmt.leaves()));
}

/// Checks that nodes of the PMT returned by `inner_nodes()` function are equal to the expected
/// ones.
#[test]
fn test_inner_node_iterator() {
    let mt = MerkleTree::new(VALUES8).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, NODE33).unwrap();
    let path22 = ms.get_path(expected_root, NODE22).unwrap();

    let mut pmt = PartialMerkleTree::with_paths([(3, path33.value, path33.path)]).unwrap();

    // get actual inner nodes
    let actual: Vec<InnerNodeInfo> = pmt.inner_nodes().collect();

    let expected_n00 = mt.root();
    let expected_n10 = mt.get_node(NODE10).unwrap();
    let expected_n11 = mt.get_node(NODE11).unwrap();
    let expected_n20 = mt.get_node(NODE20).unwrap();
    let expected_n21 = mt.get_node(NODE21).unwrap();
    let expected_n32 = mt.get_node(NODE32).unwrap();
    let expected_n33 = mt.get_node(NODE33).unwrap();

    // create vector of the expected inner nodes
    let mut expected = vec![
        InnerNodeInfo {
            value: expected_n00,
            left: expected_n10,
            right: expected_n11,
        },
        InnerNodeInfo {
            value: expected_n10,
            left: expected_n20,
            right: expected_n21,
        },
        InnerNodeInfo {
            value: expected_n21,
            left: expected_n32,
            right: expected_n33,
        },
    ];

    assert_eq!(actual, expected);

    // add another path to the Partial Merkle Tree
    pmt.add_path(2, path22.value, path22.path).unwrap();

    // get new actual inner nodes
    let actual: Vec<InnerNodeInfo> = pmt.inner_nodes().collect();

    let expected_n22 = mt.get_node(NODE22).unwrap();
    let expected_n23 = mt.get_node(NODE23).unwrap();

    let info_11 = InnerNodeInfo {
        value: expected_n11,
        left: expected_n22,
        right: expected_n23,
    };

    // add new inner node to the existing vertor
    expected.insert(2, info_11);

    assert_eq!(actual, expected);
}

/// Checks that serialization and deserialization implementations for the PMT are working
/// correctly.
#[test]
fn serialization() {
    let mt = MerkleTree::new(VALUES8).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, NODE33).unwrap();
    let path22 = ms.get_path(expected_root, NODE22).unwrap();

    let pmt = PartialMerkleTree::with_paths([
        (3, path33.value, path33.path),
        (2, path22.value, path22.path),
    ])
    .unwrap();

    let serialized_pmt = pmt.to_bytes();
    let deserialized_pmt = PartialMerkleTree::read_from_bytes(&serialized_pmt).unwrap();

    assert_eq!(deserialized_pmt, pmt);
}

/// Checks that deserialization fails with incorrect data.
#[test]
fn err_deserialization() {
    let mut tree_bytes: Vec<u8> = vec![5];
    tree_bytes.append(&mut NODE20.to_bytes());
    tree_bytes.append(&mut int_to_node(20).to_bytes());

    tree_bytes.append(&mut NODE21.to_bytes());
    tree_bytes.append(&mut int_to_node(21).to_bytes());

    // node with depth 1 could have index 0 or 1, but it has 2
    tree_bytes.append(&mut vec![1, 2]);
    tree_bytes.append(&mut int_to_node(11).to_bytes());

    assert!(PartialMerkleTree::read_from_bytes(&tree_bytes).is_err());
}

/// Checks that addition of the path with different root will cause an error.
#[test]
fn err_add_path() {
    let path33 = vec![int_to_node(1), int_to_node(2), int_to_node(3)].into();
    let path22 = vec![int_to_node(4), int_to_node(5)].into();

    let mut pmt = PartialMerkleTree::new();
    pmt.add_path(3, int_to_node(6), path33).unwrap();

    assert!(pmt.add_path(2, int_to_node(7), path22).is_err());
}

/// Checks that the request of the node which is not in the PMT will cause an error.
#[test]
fn err_get_node() {
    let mt = MerkleTree::new(VALUES8).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, NODE33).unwrap();

    let pmt = PartialMerkleTree::with_paths([(3, path33.value, path33.path)]).unwrap();

    assert!(pmt.get_node(NODE22).is_err());
    assert!(pmt.get_node(NODE23).is_err());
    assert!(pmt.get_node(NODE30).is_err());
    assert!(pmt.get_node(NODE31).is_err());
}

/// Checks that the request of the path from the leaf which is not in the PMT will cause an error.
#[test]
fn err_get_path() {
    let mt = MerkleTree::new(VALUES8).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, NODE33).unwrap();

    let pmt = PartialMerkleTree::with_paths([(3, path33.value, path33.path)]).unwrap();

    assert!(pmt.get_path(NODE22).is_err());
    assert!(pmt.get_path(NODE23).is_err());
    assert!(pmt.get_path(NODE30).is_err());
    assert!(pmt.get_path(NODE31).is_err());
}

#[test]
fn err_update_leaf() {
    let mt = MerkleTree::new(VALUES8).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, NODE33).unwrap();

    let mut pmt = PartialMerkleTree::with_paths([(3, path33.value, path33.path)]).unwrap();

    assert!(pmt.update_leaf(8, int_to_node(38)).is_err());
}
