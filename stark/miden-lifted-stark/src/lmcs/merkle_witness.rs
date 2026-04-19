//! Merkle witness for batch proof verification.
//!
//! [`MerkleWitness`] reconstructs the minimal subset of a Merkle tree from
//! opened leaves and provided sibling hashes. It supports [`root`](MerkleWitness::root)
//! verification and [`path`](MerkleWitness::path) extraction.

use alloc::vec::Vec;

use crate::lmcs::node_id::NodeId;

/// The minimal subset of a Merkle tree reconstructed from opened leaves and sibling hashes.
///
/// Contains every node on the authentication paths from the opened leaves to the
/// root — the opened leaves themselves, their siblings, and all ancestors up to
/// and including the root. Nodes not on any authentication path are absent.
///
/// Nodes are stored as `(NodeId, value)` pairs sorted by heap index, which gives
/// natural top-down, left-to-right ordering.
pub struct MerkleWitness<T> {
    /// All nodes sorted by NodeId (heap index order).
    nodes: Vec<(NodeId, T)>,
    /// Tree depth (leaves are at this depth, root at 0).
    tree_depth: usize,
}

impl<T: Clone> MerkleWitness<T> {
    /// Look up a node by its ID.
    fn get(&self, id: NodeId) -> Option<&T> {
        self.nodes.binary_search_by_key(&id, |(k, _)| *k).ok().map(|i| &self.nodes[i].1)
    }

    /// Build a witness from sorted leaf hashes.
    ///
    /// Leaves must be sorted by position in ascending order with no duplicates.
    ///
    /// `fetch_sibling` is called with the [`NodeId`] of each missing sibling,
    /// level-by-level, left-to-right, bottom-to-top, matching transcript order.
    pub fn build<E>(
        leaves: impl IntoIterator<Item = (usize, T)>,
        tree_depth: usize,
        mut fetch_sibling: impl FnMut(NodeId) -> Result<T, E>,
        compress: impl Fn(T, T) -> T,
    ) -> Result<Self, E> {
        let mut current: Vec<(NodeId, T)> = leaves
            .into_iter()
            .map(|(pos, val)| (NodeId::new(tree_depth, pos), val))
            .collect();
        debug_assert!(current.windows(2).all(|w| w[0].0 < w[1].0), "leaves must be sorted");

        let mut nodes: Vec<(NodeId, T)> = Vec::new();
        // Each level has at most ceil(n/2) parents; pre-allocate to avoid
        // reallocation on the first level (subsequent levels reuse via swap).
        let mut next: Vec<(NodeId, T)> = Vec::with_capacity(current.len().div_ceil(2));

        for _ in 0..tree_depth {
            let mut iter = current.drain(..).peekable();
            while let Some((node, hash)) = iter.next() {
                let sibling = node.sibling();

                // Get sibling hash: from the set if present, otherwise fetched.
                let sib_hash = iter
                    .next_if(|(id, _)| *id == sibling)
                    .map(|(_, h)| h)
                    .map_or_else(|| fetch_sibling(sibling), Ok)?;

                // Order children left-to-right, compress, and promote.
                let (left, right) = if node < sibling {
                    ((node, hash), (sibling, sib_hash))
                } else {
                    ((sibling, sib_hash), (node, hash))
                };

                let parent_hash = compress(left.1.clone(), right.1.clone());
                next.push((node.parent(), parent_hash));

                nodes.extend([left, right]);
            }
            drop(iter);
            core::mem::swap(&mut current, &mut next);
        }

        // Root level (depth 0).
        nodes.extend(current);

        // Sort by heap index for binary search lookups.
        nodes.sort_by_key(|(id, _)| *id);

        Ok(Self { nodes, tree_depth })
    }

    /// The root hash, or `None` if the tree is empty.
    pub fn root(&self) -> Option<&T> {
        self.get(NodeId::new(0, 0))
    }

    /// Authentication path for a leaf index (sibling hashes, bottom-to-top).
    pub fn path(&self, index: usize) -> Option<Vec<T>> {
        let mut path = Vec::with_capacity(self.tree_depth);
        let mut id = NodeId::new(self.tree_depth, index);
        for _ in 0..self.tree_depth {
            path.push(self.get(id.sibling())?.clone());
            id = id.parent();
        }
        Some(path)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn both_children_known() {
        let tree = MerkleWitness::build(
            [(0, 10u64), (1, 20)],
            1,
            |_| -> Result<u64, ()> { panic!("should not be called") },
            |l, r| l + r,
        )
        .unwrap();
        assert_eq!(tree.root(), Some(&30));
    }

    #[test]
    fn fetches_missing_sibling() {
        let tree = MerkleWitness::build(
            [(0, 10u64)],
            1,
            |sib| {
                assert_eq!(sib, NodeId::new(1, 1));
                Ok::<_, ()>(20)
            },
            |l, r| l + r,
        )
        .unwrap();
        assert_eq!(tree.root(), Some(&30));
    }

    #[test]
    fn path_extraction() {
        // tree_depth=2: 4 leaves, only positions 0 and 3 known.
        let tree = MerkleWitness::build(
            [(0, 1u64), (3, 4)],
            2,
            |sib| match sib {
                s if s == NodeId::new(2, 1) => Ok::<_, ()>(2u64),
                s if s == NodeId::new(2, 2) => Ok(3u64),
                _ => panic!("unexpected sibling request: {sib:?}"),
            },
            |l, r| l + r,
        )
        .unwrap();

        assert_eq!(tree.root(), Some(&10)); // (1+2) + (3+4) = 10

        // path: sibling hashes from leaf to root
        assert_eq!(tree.path(0).unwrap(), vec![2, 7]);
        assert_eq!(tree.path(3).unwrap(), vec![3, 3]);
    }
}
