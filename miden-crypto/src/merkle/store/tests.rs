#![cfg(feature = "std")]
use assert_matches::assert_matches;
use seq_macro::seq;
#[cfg(feature = "std")]
use {
    super::{Deserializable, DeserializationError, Serializable},
    alloc::boxed::Box,
    alloc::vec::Vec,
    std::error::Error,
};

use super::{
    EmptySubtreeRoots, MerkleError, MerklePath, MerkleStore, NodeIndex, PartialMerkleTree,
    Poseidon2, Word,
};
use crate::{
    Felt, ONE, ZERO,
    merkle::{
        MerkleTree, int_to_leaf, int_to_node,
        smt::{LeafIndex, SMT_MAX_DEPTH, SimpleSmt},
    },
};

// TEST DATA
// ================================================================================================

const KEYS4: [u64; 4] = [0, 1, 2, 3];
const VALUES4: [Word; 4] = [int_to_node(1), int_to_node(2), int_to_node(3), int_to_node(4)];

const VALUES8: [Word; 8] = [
    int_to_node(1),
    int_to_node(2),
    int_to_node(3),
    int_to_node(4),
    int_to_node(5),
    int_to_node(6),
    int_to_node(7),
    int_to_node(8),
];

// TESTS
// ================================================================================================

#[test]
fn test_root_not_in_store() -> Result<(), MerkleError> {
    let mtree = MerkleTree::new(VALUES4)?;
    let store = MerkleStore::from(&mtree);
    assert_matches!(
        store.get_node(VALUES4[0], NodeIndex::make(mtree.depth(), 0)),
        Err(MerkleError::RootNotInStore(root)) if root == VALUES4[0],
        "Leaf 0 is not a root"
    );
    assert_matches!(
        store.get_path(VALUES4[0], NodeIndex::make(mtree.depth(), 0)),
        Err(MerkleError::RootNotInStore(root)) if root == VALUES4[0],
        "Leaf 0 is not a root"
    );
    assert!(
        !store.has_path(VALUES4[0], NodeIndex::make(mtree.depth(), 0)),
        "Leaf 0 is not a root"
    );

    Ok(())
}

#[test]
fn test_merkle_tree() -> Result<(), MerkleError> {
    let mtree = MerkleTree::new(VALUES4)?;
    let store = MerkleStore::from(&mtree);

    // STORE LEAVES ARE CORRECT -------------------------------------------------------------------
    // checks the leaves in the store corresponds to the expected values
    assert_eq!(
        store.get_node(mtree.root(), NodeIndex::make(mtree.depth(), 0)).unwrap(),
        VALUES4[0],
        "node 0 must be in the tree"
    );
    assert_eq!(
        store.get_node(mtree.root(), NodeIndex::make(mtree.depth(), 1)).unwrap(),
        VALUES4[1],
        "node 1 must be in the tree"
    );
    assert_eq!(
        store.get_node(mtree.root(), NodeIndex::make(mtree.depth(), 2)).unwrap(),
        VALUES4[2],
        "node 2 must be in the tree"
    );
    assert_eq!(
        store.get_node(mtree.root(), NodeIndex::make(mtree.depth(), 3)).unwrap(),
        VALUES4[3],
        "node 3 must be in the tree"
    );

    // STORE LEAVES MATCH TREE --------------------------------------------------------------------
    // sanity check the values returned by the store and the tree
    assert_eq!(
        mtree.get_node(NodeIndex::make(mtree.depth(), 0)).unwrap(),
        store.get_node(mtree.root(), NodeIndex::make(mtree.depth(), 0)).unwrap(),
        "node 0 must be the same for both MerkleTree and MerkleStore"
    );
    assert_eq!(
        mtree.get_node(NodeIndex::make(mtree.depth(), 1)).unwrap(),
        store.get_node(mtree.root(), NodeIndex::make(mtree.depth(), 1)).unwrap(),
        "node 1 must be the same for both MerkleTree and MerkleStore"
    );
    assert_eq!(
        mtree.get_node(NodeIndex::make(mtree.depth(), 2)).unwrap(),
        store.get_node(mtree.root(), NodeIndex::make(mtree.depth(), 2)).unwrap(),
        "node 2 must be the same for both MerkleTree and MerkleStore"
    );
    assert_eq!(
        mtree.get_node(NodeIndex::make(mtree.depth(), 3)).unwrap(),
        store.get_node(mtree.root(), NodeIndex::make(mtree.depth(), 3)).unwrap(),
        "node 3 must be the same for both MerkleTree and MerkleStore"
    );

    // STORE MERKLE PATH MATCHES ==============================================================
    // assert the merkle path returned by the store is the same as the one in the tree
    let result = store.get_path(mtree.root(), NodeIndex::make(mtree.depth(), 0)).unwrap();
    assert_eq!(
        VALUES4[0], result.value,
        "Value for merkle path at index 0 must match leaf value"
    );
    assert_eq!(
        mtree.get_path(NodeIndex::make(mtree.depth(), 0)).unwrap(),
        result.path,
        "merkle path for index 0 must be the same for the MerkleTree and MerkleStore"
    );
    assert!(
        store.has_path(mtree.root(), NodeIndex::make(mtree.depth(), 0)),
        "path for index 0 must exist"
    );

    let result = store.get_path(mtree.root(), NodeIndex::make(mtree.depth(), 1)).unwrap();
    assert_eq!(
        VALUES4[1], result.value,
        "Value for merkle path at index 0 must match leaf value"
    );
    assert_eq!(
        mtree.get_path(NodeIndex::make(mtree.depth(), 1)).unwrap(),
        result.path,
        "merkle path for index 1 must be the same for the MerkleTree and MerkleStore"
    );
    assert!(
        store.has_path(mtree.root(), NodeIndex::make(mtree.depth(), 1)),
        "path for index 1 must exist"
    );

    let result = store.get_path(mtree.root(), NodeIndex::make(mtree.depth(), 2)).unwrap();
    assert_eq!(
        VALUES4[2], result.value,
        "Value for merkle path at index 0 must match leaf value"
    );
    assert_eq!(
        mtree.get_path(NodeIndex::make(mtree.depth(), 2)).unwrap(),
        result.path,
        "merkle path for index 0 must be the same for the MerkleTree and MerkleStore"
    );
    assert!(
        store.has_path(mtree.root(), NodeIndex::make(mtree.depth(), 2)),
        "path for index 2 must exist"
    );

    let result = store.get_path(mtree.root(), NodeIndex::make(mtree.depth(), 3)).unwrap();
    assert_eq!(
        VALUES4[3], result.value,
        "Value for merkle path at index 0 must match leaf value"
    );
    assert_eq!(
        mtree.get_path(NodeIndex::make(mtree.depth(), 3)).unwrap(),
        result.path,
        "merkle path for index 0 must be the same for the MerkleTree and MerkleStore"
    );
    assert!(
        store.has_path(mtree.root(), NodeIndex::make(mtree.depth(), 3)),
        "path for index 3 must exist"
    );

    Ok(())
}

#[test]
fn test_empty_roots() {
    let store = MerkleStore::default();
    let mut root = Word::default();

    for depth in 0..255 {
        root = Poseidon2::merge(&[root; 2]);
        assert!(
            store.get_node(root, NodeIndex::make(0, 0)).is_ok(),
            "The root of the empty tree of depth {depth} must be registered"
        );
    }
}

#[test]
fn test_leaf_paths_for_empty_trees() -> Result<(), MerkleError> {
    let store = MerkleStore::default();

    // Starts at 1 because leaves are not included in the store.
    // Ends at 64 because it is not possible to represent an index of a depth greater than 64,
    // because a u64 is used to index the leaf.
    seq!(DEPTH in 1_u8..64_u8 {
        let smt = SimpleSmt::<DEPTH>::new()?;

        let index = NodeIndex::make(DEPTH, 0);
        let store_path = store.get_path(smt.root(), index)?;
        let smt_path = smt.open(&LeafIndex::<DEPTH>::new(0)?).path;
        assert_eq!(
            store_path.value,
            Word::default(),
            "the leaf of an empty tree is always ZERO"
        );
        assert_eq!(
            store_path.path, smt_path,
            "the returned merkle path does not match the computed values"
        );
        assert_eq!(
            store_path.path.compute_root(DEPTH.into(), Word::default()).unwrap(),
            smt.root(),
            "computed root from the path must match the empty tree root"
        );
        assert!(store.has_path(smt.root(), index), "path for index 0 at depth {} must exist", DEPTH);

    });

    Ok(())
}

#[test]
fn test_get_invalid_node() {
    let mtree = MerkleTree::new(VALUES4).expect("creating a merkle tree must work");
    let store = MerkleStore::from(&mtree);
    let _ = store.get_node(mtree.root(), NodeIndex::make(mtree.depth(), 3));
}

#[test]
fn test_add_sparse_merkle_tree_one_level() -> Result<(), MerkleError> {
    let keys2: [u64; 2] = [0, 1];
    let leaves2: [Word; 2] = [int_to_leaf(1), int_to_leaf(2)];
    let smt = SimpleSmt::<1>::with_leaves(keys2.into_iter().zip(leaves2)).unwrap();
    let store = MerkleStore::from(&smt);

    let idx = NodeIndex::make(1, 0);
    assert_eq!(smt.get_node(idx).unwrap(), leaves2[0]);
    assert_eq!(store.get_node(smt.root(), idx).unwrap(), smt.get_node(idx).unwrap());

    let idx = NodeIndex::make(1, 1);
    assert_eq!(smt.get_node(idx).unwrap(), leaves2[1]);
    assert_eq!(store.get_node(smt.root(), idx).unwrap(), smt.get_node(idx).unwrap());

    Ok(())
}

#[test]
fn test_sparse_merkle_tree() -> Result<(), MerkleError> {
    let smt =
        SimpleSmt::<SMT_MAX_DEPTH>::with_leaves(KEYS4.into_iter().zip(VALUES4.to_vec())).unwrap();

    let store = MerkleStore::from(&smt);

    // STORE LEAVES ARE CORRECT ==============================================================
    // checks the leaves in the store corresponds to the expected values
    assert_eq!(
        store.get_node(smt.root(), NodeIndex::make(SMT_MAX_DEPTH, 0)).unwrap(),
        VALUES4[0],
        "node 0 must be in the tree"
    );
    assert_eq!(
        store.get_node(smt.root(), NodeIndex::make(SMT_MAX_DEPTH, 1)).unwrap(),
        VALUES4[1],
        "node 1 must be in the tree"
    );
    assert_eq!(
        store.get_node(smt.root(), NodeIndex::make(SMT_MAX_DEPTH, 2)).unwrap(),
        VALUES4[2],
        "node 2 must be in the tree"
    );
    assert_eq!(
        store.get_node(smt.root(), NodeIndex::make(SMT_MAX_DEPTH, 3)).unwrap(),
        VALUES4[3],
        "node 3 must be in the tree"
    );
    assert_eq!(
        store.get_node(smt.root(), NodeIndex::make(SMT_MAX_DEPTH, 4)).unwrap(),
        Word::default(),
        "unmodified node 4 must be ZERO"
    );

    // STORE LEAVES MATCH TREE ===============================================================
    // sanity check the values returned by the store and the tree
    assert_eq!(
        smt.get_node(NodeIndex::make(SMT_MAX_DEPTH, 0)).unwrap(),
        store.get_node(smt.root(), NodeIndex::make(SMT_MAX_DEPTH, 0)).unwrap(),
        "node 0 must be the same for both SparseMerkleTree and MerkleStore"
    );
    assert_eq!(
        smt.get_node(NodeIndex::make(SMT_MAX_DEPTH, 1)).unwrap(),
        store.get_node(smt.root(), NodeIndex::make(SMT_MAX_DEPTH, 1)).unwrap(),
        "node 1 must be the same for both SparseMerkleTree and MerkleStore"
    );
    assert_eq!(
        smt.get_node(NodeIndex::make(SMT_MAX_DEPTH, 2)).unwrap(),
        store.get_node(smt.root(), NodeIndex::make(SMT_MAX_DEPTH, 2)).unwrap(),
        "node 2 must be the same for both SparseMerkleTree and MerkleStore"
    );
    assert_eq!(
        smt.get_node(NodeIndex::make(SMT_MAX_DEPTH, 3)).unwrap(),
        store.get_node(smt.root(), NodeIndex::make(SMT_MAX_DEPTH, 3)).unwrap(),
        "node 3 must be the same for both SparseMerkleTree and MerkleStore"
    );
    assert_eq!(
        smt.get_node(NodeIndex::make(SMT_MAX_DEPTH, 4)).unwrap(),
        store.get_node(smt.root(), NodeIndex::make(SMT_MAX_DEPTH, 4)).unwrap(),
        "node 4 must be the same for both SparseMerkleTree and MerkleStore"
    );

    // STORE MERKLE PATH MATCHES ==============================================================
    // assert the merkle path returned by the store is the same as the one in the tree
    let result = store.get_path(smt.root(), NodeIndex::make(SMT_MAX_DEPTH, 0)).unwrap();
    assert_eq!(
        VALUES4[0], result.value,
        "Value for merkle path at index 0 must match leaf value"
    );
    assert_eq!(
        smt.open(&LeafIndex::<SMT_MAX_DEPTH>::new(0).unwrap()).path,
        result.path,
        "merkle path for index 0 must be the same for the MerkleTree and MerkleStore"
    );
    assert!(
        store.has_path(smt.root(), NodeIndex::make(SMT_MAX_DEPTH, 0)),
        "path for index 0 must exist"
    );

    let result = store.get_path(smt.root(), NodeIndex::make(SMT_MAX_DEPTH, 1)).unwrap();
    assert_eq!(
        VALUES4[1], result.value,
        "Value for merkle path at index 1 must match leaf value"
    );
    assert_eq!(
        smt.open(&LeafIndex::<SMT_MAX_DEPTH>::new(1).unwrap()).path,
        result.path,
        "merkle path for index 1 must be the same for the MerkleTree and MerkleStore"
    );
    assert!(
        store.has_path(smt.root(), NodeIndex::make(SMT_MAX_DEPTH, 1)),
        "path for index 1 must exist"
    );

    let result = store.get_path(smt.root(), NodeIndex::make(SMT_MAX_DEPTH, 2)).unwrap();
    assert_eq!(
        VALUES4[2], result.value,
        "Value for merkle path at index 2 must match leaf value"
    );
    assert_eq!(
        smt.open(&LeafIndex::<SMT_MAX_DEPTH>::new(2).unwrap()).path,
        result.path,
        "merkle path for index 2 must be the same for the MerkleTree and MerkleStore"
    );
    assert!(
        store.has_path(smt.root(), NodeIndex::make(SMT_MAX_DEPTH, 2)),
        "path for index 2 must exist"
    );

    let result = store.get_path(smt.root(), NodeIndex::make(SMT_MAX_DEPTH, 3)).unwrap();
    assert_eq!(
        VALUES4[3], result.value,
        "Value for merkle path at index 3 must match leaf value"
    );
    assert_eq!(
        smt.open(&LeafIndex::<SMT_MAX_DEPTH>::new(3).unwrap()).path,
        result.path,
        "merkle path for index 3 must be the same for the MerkleTree and MerkleStore"
    );
    assert!(
        store.has_path(smt.root(), NodeIndex::make(SMT_MAX_DEPTH, 3)),
        "path for index 3 must exist"
    );

    let result = store.get_path(smt.root(), NodeIndex::make(SMT_MAX_DEPTH, 4)).unwrap();
    assert_eq!(
        Word::default(),
        result.value,
        "Value for merkle path at index 4 must match leaf value"
    );
    assert_eq!(
        smt.open(&LeafIndex::<SMT_MAX_DEPTH>::new(4).unwrap()).path,
        result.path,
        "merkle path for index 4 must be the same for the MerkleTree and MerkleStore"
    );
    assert!(
        store.has_path(smt.root(), NodeIndex::make(SMT_MAX_DEPTH, 4)),
        "path for index 4 must exist"
    );

    Ok(())
}

#[test]
fn test_add_merkle_paths() -> Result<(), MerkleError> {
    let mtree = MerkleTree::new(VALUES4)?;

    let i0 = 0;
    let p0 = mtree.get_path(NodeIndex::make(2, i0)).unwrap();

    let i1 = 1;
    let p1 = mtree.get_path(NodeIndex::make(2, i1)).unwrap();

    let i2 = 2;
    let p2 = mtree.get_path(NodeIndex::make(2, i2)).unwrap();

    let i3 = 3;
    let p3 = mtree.get_path(NodeIndex::make(2, i3)).unwrap();

    let paths = [
        (i0, VALUES4[i0 as usize], p0),
        (i1, VALUES4[i1 as usize], p1),
        (i2, VALUES4[i2 as usize], p2),
        (i3, VALUES4[i3 as usize], p3),
    ];

    let mut store = MerkleStore::default();
    store.add_merkle_paths(paths.clone()).expect("the valid paths must work");

    let pmt = PartialMerkleTree::with_paths(paths).unwrap();

    // STORE LEAVES ARE CORRECT ==============================================================
    // checks the leaves in the store corresponds to the expected values
    assert_eq!(
        store.get_node(pmt.root(), NodeIndex::make(pmt.max_depth(), 0)).unwrap(),
        VALUES4[0],
        "node 0 must be in the pmt"
    );
    assert_eq!(
        store.get_node(pmt.root(), NodeIndex::make(pmt.max_depth(), 1)).unwrap(),
        VALUES4[1],
        "node 1 must be in the pmt"
    );
    assert_eq!(
        store.get_node(pmt.root(), NodeIndex::make(pmt.max_depth(), 2)).unwrap(),
        VALUES4[2],
        "node 2 must be in the pmt"
    );
    assert_eq!(
        store.get_node(pmt.root(), NodeIndex::make(pmt.max_depth(), 3)).unwrap(),
        VALUES4[3],
        "node 3 must be in the pmt"
    );

    // STORE LEAVES MATCH PMT ================================================================
    // sanity check the values returned by the store and the pmt
    assert_eq!(
        pmt.get_node(NodeIndex::make(pmt.max_depth(), 0)).unwrap(),
        store.get_node(pmt.root(), NodeIndex::make(pmt.max_depth(), 0)).unwrap(),
        "node 0 must be the same for both PartialMerkleTree and MerkleStore"
    );
    assert_eq!(
        pmt.get_node(NodeIndex::make(pmt.max_depth(), 1)).unwrap(),
        store.get_node(pmt.root(), NodeIndex::make(pmt.max_depth(), 1)).unwrap(),
        "node 1 must be the same for both PartialMerkleTree and MerkleStore"
    );
    assert_eq!(
        pmt.get_node(NodeIndex::make(pmt.max_depth(), 2)).unwrap(),
        store.get_node(pmt.root(), NodeIndex::make(pmt.max_depth(), 2)).unwrap(),
        "node 2 must be the same for both PartialMerkleTree and MerkleStore"
    );
    assert_eq!(
        pmt.get_node(NodeIndex::make(pmt.max_depth(), 3)).unwrap(),
        store.get_node(pmt.root(), NodeIndex::make(pmt.max_depth(), 3)).unwrap(),
        "node 3 must be the same for both PartialMerkleTree and MerkleStore"
    );

    // STORE MERKLE PATH MATCHES ==============================================================
    // assert the merkle path returned by the store is the same as the one in the pmt
    let result = store.get_path(pmt.root(), NodeIndex::make(pmt.max_depth(), 0)).unwrap();
    assert_eq!(
        VALUES4[0], result.value,
        "Value for merkle path at index 0 must match leaf value"
    );
    assert_eq!(
        pmt.get_path(NodeIndex::make(pmt.max_depth(), 0)).unwrap(),
        result.path,
        "merkle path for index 0 must be the same for the MerkleTree and MerkleStore"
    );
    assert!(
        store.has_path(pmt.root(), NodeIndex::make(pmt.max_depth(), 0)),
        "path for index 0 must exist"
    );

    let result = store.get_path(pmt.root(), NodeIndex::make(pmt.max_depth(), 1)).unwrap();
    assert_eq!(
        VALUES4[1], result.value,
        "Value for merkle path at index 0 must match leaf value"
    );
    assert_eq!(
        pmt.get_path(NodeIndex::make(pmt.max_depth(), 1)).unwrap(),
        result.path,
        "merkle path for index 1 must be the same for the MerkleTree and MerkleStore"
    );
    assert!(
        store.has_path(pmt.root(), NodeIndex::make(pmt.max_depth(), 1)),
        "path for index 1 must exist"
    );

    let result = store.get_path(pmt.root(), NodeIndex::make(pmt.max_depth(), 2)).unwrap();
    assert_eq!(
        VALUES4[2], result.value,
        "Value for merkle path at index 0 must match leaf value"
    );
    assert_eq!(
        pmt.get_path(NodeIndex::make(pmt.max_depth(), 2)).unwrap(),
        result.path,
        "merkle path for index 0 must be the same for the MerkleTree and MerkleStore"
    );
    assert!(
        store.has_path(pmt.root(), NodeIndex::make(pmt.max_depth(), 2)),
        "path for index 2 must exist"
    );

    let result = store.get_path(pmt.root(), NodeIndex::make(pmt.max_depth(), 3)).unwrap();
    assert_eq!(
        VALUES4[3], result.value,
        "Value for merkle path at index 0 must match leaf value"
    );
    assert_eq!(
        pmt.get_path(NodeIndex::make(pmt.max_depth(), 3)).unwrap(),
        result.path,
        "merkle path for index 0 must be the same for the MerkleTree and MerkleStore"
    );
    assert!(
        store.has_path(pmt.root(), NodeIndex::make(pmt.max_depth(), 3)),
        "path for index 3 must exist"
    );

    Ok(())
}

#[test]
fn wont_open_to_different_depth_root() {
    let empty = EmptySubtreeRoots::empty_hashes(64);
    let a = Word::new([ONE; 4]);
    let b = Word::new([Felt::new_unchecked(2); 4]);

    // Compute the root for a different depth. We cherry-pick this specific depth to prevent a
    // regression to a bug in the past that allowed the user to fetch a node at a depth lower than
    // the inserted path of a Merkle tree.
    let mut root = Poseidon2::merge(&[a, b]);
    for depth in (1..=63).rev() {
        root = Poseidon2::merge(&[root, empty[depth]]);
    }

    // For this example, the depth of the Merkle tree is 1, as we have only two leaves. Here we
    // attempt to fetch a node on the maximum depth, and it should fail because the root shouldn't
    // exist for the set.
    let mtree = MerkleTree::new(vec![a, b]).unwrap();
    let store = MerkleStore::from(&mtree);
    let index = NodeIndex::root();
    let err = store.get_node(root, index).err().unwrap();
    assert_matches!(err, MerkleError::RootNotInStore(err_root) if err_root == root);
}

#[test]
fn store_path_opens_from_leaf() {
    let a = Word::new([ONE; 4]);
    let b = Word::new([Felt::new_unchecked(2); 4]);
    let c = Word::new([Felt::new_unchecked(3); 4]);
    let d = Word::new([Felt::new_unchecked(4); 4]);
    let e = Word::new([Felt::new_unchecked(5); 4]);
    let f = Word::new([Felt::new_unchecked(6); 4]);
    let g = Word::new([Felt::new_unchecked(7); 4]);
    let h = Word::new([Felt::new_unchecked(8); 4]);

    let i = Poseidon2::merge(&[a, b]);
    let j = Poseidon2::merge(&[c, d]);
    let k = Poseidon2::merge(&[e, f]);
    let l = Poseidon2::merge(&[g, h]);

    let m = Poseidon2::merge(&[i, j]);
    let n = Poseidon2::merge(&[k, l]);

    let root = Poseidon2::merge(&[m, n]);

    let mtree = MerkleTree::new(vec![a, b, c, d, e, f, g, h]).unwrap();
    let store = MerkleStore::from(&mtree);
    let path = store.get_path(root, NodeIndex::make(3, 1)).unwrap().path;

    let expected = MerklePath::new([a, j, n].to_vec());
    assert_eq!(path, expected);
}

#[test]
fn test_set_node() -> Result<(), MerkleError> {
    let mtree = MerkleTree::new(VALUES4)?;
    let mut store = MerkleStore::from(&mtree);
    let value = int_to_node(42);
    let index = NodeIndex::make(mtree.depth(), 0);
    let new_root = store.set_node(mtree.root(), index, value)?.root;
    assert_eq!(store.get_node(new_root, index).unwrap(), value, "value must have changed");

    Ok(())
}

#[test]
fn test_constructors() -> Result<(), MerkleError> {
    let mtree = MerkleTree::new(VALUES4)?;
    let store = MerkleStore::from(&mtree);

    let depth = mtree.depth();
    let leaves = 2u64.pow(depth.into());
    for index in 0..leaves {
        let index = NodeIndex::make(depth, index);
        let value_path = store.get_path(mtree.root(), index)?;
        assert_eq!(mtree.get_path(index)?, value_path.path);
        assert!(
            store.has_path(mtree.root(), index),
            "path for index {} at depth {} must exist",
            index.position(),
            depth
        );
    }

    const DEPTH: u8 = 32;
    let smt = SimpleSmt::<DEPTH>::with_leaves(KEYS4.into_iter().zip(VALUES4)).unwrap();
    let store = MerkleStore::from(&smt);

    for key in KEYS4 {
        let index = NodeIndex::make(DEPTH, key);
        let value_path = store.get_path(smt.root(), index)?;
        assert_eq!(smt.open(&LeafIndex::<DEPTH>::new(key).unwrap()).path, value_path.path);
        assert!(
            store.has_path(smt.root(), index),
            "path for key {} at depth {} must exist",
            key,
            DEPTH
        );
    }

    let d = 2;
    let paths = [
        (0, VALUES4[0], mtree.get_path(NodeIndex::make(d, 0)).unwrap()),
        (1, VALUES4[1], mtree.get_path(NodeIndex::make(d, 1)).unwrap()),
        (2, VALUES4[2], mtree.get_path(NodeIndex::make(d, 2)).unwrap()),
        (3, VALUES4[3], mtree.get_path(NodeIndex::make(d, 3)).unwrap()),
    ];

    let mut store1 = MerkleStore::default();
    store1.add_merkle_paths(paths.clone())?;

    let mut store2 = MerkleStore::default();
    store2.add_merkle_path(0, VALUES4[0], mtree.get_path(NodeIndex::make(d, 0))?)?;
    store2.add_merkle_path(1, VALUES4[1], mtree.get_path(NodeIndex::make(d, 1))?)?;
    store2.add_merkle_path(2, VALUES4[2], mtree.get_path(NodeIndex::make(d, 2))?)?;
    store2.add_merkle_path(3, VALUES4[3], mtree.get_path(NodeIndex::make(d, 3))?)?;
    let pmt = PartialMerkleTree::with_paths(paths).unwrap();

    for key in [0, 1, 2, 3] {
        let index = NodeIndex::make(d, key);
        let value_path1 = store1.get_path(pmt.root(), index)?;
        let value_path2 = store2.get_path(pmt.root(), index)?;
        assert_eq!(value_path1, value_path2);

        let index = NodeIndex::make(d, key);
        assert_eq!(pmt.get_path(index)?, value_path1.path);
        assert!(
            store1.has_path(pmt.root(), index),
            "path for key {} at depth {} must exist in store1",
            key,
            d
        );
        assert!(
            store2.has_path(pmt.root(), index),
            "path for key {} at depth {} must exist in store2",
            key,
            d
        );
    }

    Ok(())
}

#[test]
fn node_path_should_be_truncated_by_midtier_insert() {
    let key = 0b11010010_11001100_11001100_11001100_11001100_11001100_11001100_11001100_u64;

    let mut store = MerkleStore::new();
    let root: Word = EmptySubtreeRoots::empty_hashes(64)[0];

    // insert first node - works as expected
    let depth = 64;
    let node = Word::from([Felt::new_unchecked(key); Word::NUM_ELEMENTS]);
    let index = NodeIndex::new(depth, key).unwrap();
    let root = store.set_node(root, index, node).unwrap().root;
    let result = store.get_node(root, index).unwrap();
    let path = store.get_path(root, index).unwrap().path;
    assert_eq!(node, result);
    assert_eq!(path.depth(), depth);
    assert!(path.verify(index.position(), result, &root).is_ok());
    assert!(store.has_path(root, index), "path for first inserted node must exist");

    // flip the first bit of the key and insert the second node on a different depth
    let key = key ^ (1 << 63);
    let key = key >> 8;
    let depth = 56;
    let node = Word::from([Felt::new_unchecked(key); Word::NUM_ELEMENTS]);
    let index = NodeIndex::new(depth, key).unwrap();
    let root = store.set_node(root, index, node).unwrap().root;
    let result = store.get_node(root, index).unwrap();
    let path = store.get_path(root, index).unwrap().path;
    assert_eq!(node, result);
    assert_eq!(path.depth(), depth);
    assert!(path.verify(index.position(), result, &root).is_ok());
    assert!(store.has_path(root, index), "path for second inserted node must exist");

    // attempt to fetch a path of the second node to depth 64
    // should fail because the previously inserted node will remove its sub-tree from the set
    let key = key << 8;
    let index = NodeIndex::new(64, key).unwrap();
    assert!(store.get_node(root, index).is_err());
}

// LEAF TRAVERSAL
// ================================================================================================

#[test]
fn get_leaf_depth_works_depth_64() {
    let mut store = MerkleStore::new();
    let mut root: Word = EmptySubtreeRoots::empty_hashes(64)[0];
    let key = u64::MAX;

    // this will create a rainbow tree and test all opening to depth 64
    for d in 0..64 {
        let k = key & (u64::MAX >> d);
        let node = Word::from([Felt::new_unchecked(k); Word::NUM_ELEMENTS]);
        let index = NodeIndex::new(64, k).unwrap();

        // assert the leaf doesn't exist before the insert. the returned depth should always
        // increment with the paths count of the set, as they are intersecting one another up to
        // the first bits of the used key.
        assert_eq!(d, store.get_leaf_depth(root, 64, k).unwrap());

        // insert and assert the correct depth
        root = store.set_node(root, index, node).unwrap().root;
        assert_eq!(64, store.get_leaf_depth(root, 64, k).unwrap());
    }
}

#[test]
fn get_leaf_depth_works_with_incremental_depth() {
    let mut store = MerkleStore::new();
    let mut root: Word = EmptySubtreeRoots::empty_hashes(64)[0];

    // insert some path to the left of the root and assert it
    let key = 0b01001011_10110110_00001101_01110100_00111011_10101101_00000100_01000001_u64;
    assert_eq!(0, store.get_leaf_depth(root, 64, key).unwrap());
    let depth = 64;
    let index = NodeIndex::new(depth, key).unwrap();
    let node = Word::from([Felt::new_unchecked(key); Word::NUM_ELEMENTS]);
    root = store.set_node(root, index, node).unwrap().root;
    assert_eq!(depth, store.get_leaf_depth(root, 64, key).unwrap());

    // flip the key to the right of the root and insert some content on depth 16
    let key = 0b11001011_10110110_00000000_00000000_00000000_00000000_00000000_00000000_u64;
    assert_eq!(1, store.get_leaf_depth(root, 64, key).unwrap());
    let depth = 16;
    let index = NodeIndex::new(depth, key >> (64 - depth)).unwrap();
    let node = Word::from([Felt::new_unchecked(key); Word::NUM_ELEMENTS]);
    root = store.set_node(root, index, node).unwrap().root;
    assert_eq!(depth, store.get_leaf_depth(root, 64, key).unwrap());

    // attempt the sibling of the previous leaf
    let key = 0b11001011_10110111_00000000_00000000_00000000_00000000_00000000_00000000_u64;
    assert_eq!(16, store.get_leaf_depth(root, 64, key).unwrap());
    let index = NodeIndex::new(depth, key >> (64 - depth)).unwrap();
    let node = Word::from([Felt::new_unchecked(key); Word::NUM_ELEMENTS]);
    root = store.set_node(root, index, node).unwrap().root;
    assert_eq!(depth, store.get_leaf_depth(root, 64, key).unwrap());

    // move down to the next depth and assert correct behavior
    let key = 0b11001011_10110100_00000000_00000000_00000000_00000000_00000000_00000000_u64;
    assert_eq!(15, store.get_leaf_depth(root, 64, key).unwrap());
    let depth = 17;
    let index = NodeIndex::new(depth, key >> (64 - depth)).unwrap();
    let node = Word::from([Felt::new_unchecked(key); Word::NUM_ELEMENTS]);
    root = store.set_node(root, index, node).unwrap().root;
    assert_eq!(depth, store.get_leaf_depth(root, 64, key).unwrap());
}

#[test]
fn get_leaf_depth_works_with_depth_8() {
    let mut store = MerkleStore::new();
    let mut root: Word = EmptySubtreeRoots::empty_hashes(8)[0];

    // insert some random, 8 depth keys. `a` diverges from the first bit
    let a = 0b01101001_u64;
    let b = 0b10011001_u64;
    let c = 0b10010110_u64;
    let d = 0b11110110_u64;

    for k in [a, b, c, d] {
        let index = NodeIndex::new(8, k).unwrap();
        let node = Word::from([Felt::new_unchecked(k); Word::NUM_ELEMENTS]);
        root = store.set_node(root, index, node).unwrap().root;
    }

    // assert all leaves returns the inserted depth
    for k in [a, b, c, d] {
        assert_eq!(8, store.get_leaf_depth(root, 8, k).unwrap());
    }

    // flip last bit of a and expect it to return the same depth, but for an empty node
    assert_eq!(8, store.get_leaf_depth(root, 8, 0b01101000_u64).unwrap());

    // flip fourth bit of a and expect an empty node on depth 4
    assert_eq!(4, store.get_leaf_depth(root, 8, 0b01111001_u64).unwrap());

    // flip third bit of a and expect an empty node on depth 3
    assert_eq!(3, store.get_leaf_depth(root, 8, 0b01001001_u64).unwrap());

    // flip second bit of a and expect an empty node on depth 2
    assert_eq!(2, store.get_leaf_depth(root, 8, 0b00101001_u64).unwrap());

    // flip fourth bit of c and expect an empty node on depth 4
    assert_eq!(4, store.get_leaf_depth(root, 8, 0b10000110_u64).unwrap());

    // flip second bit of d and expect an empty node on depth 3 as depth 2 conflicts with b and c
    assert_eq!(3, store.get_leaf_depth(root, 8, 0b10110110_u64).unwrap());

    // duplicate the tree on `a` and assert the depth is short-circuited by such sub-tree
    let index = NodeIndex::new(8, a).unwrap();
    root = store.set_node(root, index, root).unwrap().root;
    assert_matches!(store.get_leaf_depth(root, 8, a).unwrap_err(), MerkleError::DepthTooBig(9));
}

#[test]
fn find_lone_leaf() {
    let mut store = MerkleStore::new();
    let empty = EmptySubtreeRoots::empty_hashes(64);
    let mut root: Word = empty[0];

    // insert a single leaf into the store at depth 64
    let key_a = 0b01010101_10101010_00001111_01110100_00111011_10101101_00000100_01000001_u64;
    let idx_a = NodeIndex::make(64, key_a);
    let val_a = Word::from([ONE, ONE, ONE, ONE]);
    root = store.set_node(root, idx_a, val_a).unwrap().root;

    // for every ancestor of A, A should be a long leaf
    for depth in 1..64 {
        let parent_index = NodeIndex::make(depth, key_a >> (64 - depth));
        let parent = store.get_node(root, parent_index).unwrap();

        let res = store.find_lone_leaf(parent, parent_index, 64).unwrap();
        assert_eq!(res, Some((idx_a, val_a)));
    }

    // insert another leaf into the store such that it has the same 8 bit prefix as A
    let key_b = 0b01010101_01111010_00001111_01110100_00111011_10101101_00000100_01000001_u64;
    let idx_b = NodeIndex::make(64, key_b);
    let val_b = Word::from([ONE, ONE, ONE, ZERO]);
    root = store.set_node(root, idx_b, val_b).unwrap().root;

    // for any node which is common between A and B, find_lone_leaf() should return None as the
    // node has two descendants
    for depth in 1..9 {
        let parent_index = NodeIndex::make(depth, key_a >> (64 - depth));
        let parent = store.get_node(root, parent_index).unwrap();

        let res = store.find_lone_leaf(parent, parent_index, 64).unwrap();
        assert_eq!(res, None);
    }

    // for other ancestors of A and B, A and B should be lone leaves respectively
    for depth in 9..64 {
        let parent_index = NodeIndex::make(depth, key_a >> (64 - depth));
        let parent = store.get_node(root, parent_index).unwrap();

        let res = store.find_lone_leaf(parent, parent_index, 64).unwrap();
        assert_eq!(res, Some((idx_a, val_a)));
    }

    for depth in 9..64 {
        let parent_index = NodeIndex::make(depth, key_b >> (64 - depth));
        let parent = store.get_node(root, parent_index).unwrap();

        let res = store.find_lone_leaf(parent, parent_index, 64).unwrap();
        assert_eq!(res, Some((idx_b, val_b)));
    }

    // for any other node, find_lone_leaf() should return None as they have no leaf nodes
    let parent_index = NodeIndex::make(16, 0b01010101_11111111);
    let parent = store.get_node(root, parent_index).unwrap();
    let res = store.find_lone_leaf(parent, parent_index, 64).unwrap();
    assert_eq!(res, None);
}

// SUBSET EXTRACTION
// ================================================================================================

#[test]
fn mstore_subset() {
    // add a Merkle tree of depth 3 to the store
    let mtree = MerkleTree::new(VALUES8).unwrap();
    let mut store = MerkleStore::default();
    let empty_store_num_nodes = store.nodes.len();
    store.extend(mtree.inner_nodes());

    // build 3 subtrees contained within the above Merkle tree; note that subtree2 is a subset
    // of subtree1
    let subtree1 = MerkleTree::new(&VALUES8[..4]).unwrap();
    let subtree2 = MerkleTree::new(&VALUES8[2..4]).unwrap();
    let subtree3 = MerkleTree::new(&VALUES8[6..]).unwrap();

    // --- extract all 3 subtrees ---------------------------------------------

    let substore = store.subset([subtree1.root(), subtree2.root(), subtree3.root()].iter());

    // number of nodes should increase by 4: 3 nodes form subtree1 and 1 node from subtree3
    assert_eq!(substore.nodes.len(), empty_store_num_nodes + 4);

    // make sure paths that all subtrees are in the store
    check_mstore_subtree(&substore, &subtree1);
    check_mstore_subtree(&substore, &subtree2);
    check_mstore_subtree(&substore, &subtree3);

    // --- extract subtrees 1 and 3 -------------------------------------------
    // this should give the same result as above as subtree2 is nested within subtree1

    let substore = store.subset([subtree1.root(), subtree3.root()].iter());

    // number of nodes should increase by 4: 3 nodes form subtree1 and 1 node from subtree3
    assert_eq!(substore.nodes.len(), empty_store_num_nodes + 4);

    // make sure paths that all subtrees are in the store
    check_mstore_subtree(&substore, &subtree1);
    check_mstore_subtree(&substore, &subtree2);
    check_mstore_subtree(&substore, &subtree3);
}

fn check_mstore_subtree(store: &MerkleStore, subtree: &MerkleTree) {
    for (i, value) in subtree.leaves() {
        let index = NodeIndex::new(subtree.depth(), i).unwrap();
        let path1 = store.get_path(subtree.root(), index).unwrap();
        assert_eq!(path1.value, *value);

        let path2 = subtree.get_path(index).unwrap();
        assert_eq!(path1.path, path2);
        assert!(store.has_path(subtree.root(), index), "path for leaf {} must exist", i);
    }
}

// SERIALIZATION
// ================================================================================================

#[cfg(feature = "std")]
#[test]
fn test_serialization() -> Result<(), Box<dyn Error>> {
    let mtree = MerkleTree::new(VALUES4)?;
    let store = MerkleStore::from(&mtree);
    let decoded = MerkleStore::read_from_bytes(&store.to_bytes()).expect("deserialization failed");
    assert_eq!(store, decoded);
    Ok(())
}

#[test]
fn deserialize_rejects_oversized_length() {
    let mut bytes = Vec::new();
    u64::MAX.write_into(&mut bytes);

    let result = MerkleStore::read_from_bytes_with_budget(&bytes, bytes.len());
    assert!(matches!(result, Err(DeserializationError::InvalidValue(_))));
}

#[test]
fn deserialize_rejects_truncated_payload() {
    let mut bytes = Vec::new();
    1u64.write_into(&mut bytes);

    let result = MerkleStore::read_from_bytes(&bytes);
    assert!(matches!(result, Err(DeserializationError::UnexpectedEOF)));
}
