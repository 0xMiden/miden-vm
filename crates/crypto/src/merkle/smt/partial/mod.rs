use alloc::{collections::VecDeque, string::ToString, vec::Vec};

use super::{EmptySubtreeRoots, LeafIndex, SMT_DEPTH};
use crate::{
    EMPTY_WORD, Map, Set, Word,
    merkle::{
        InnerNodeInfo, MerkleError, NodeIndex, SparseMerklePath,
        smt::{InnerNode, InnerNodes, Leaves, SmtLeaf, SmtLeafError, SmtProof},
    },
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

mod serialization;
#[cfg(test)]
mod tests;

pub use serialization::{NodeValue, UniqueNodes};

/// A partial version of an [`super::Smt`].
///
/// This type can track a subset of the key-value pairs of a full [`super::Smt`] and allows for
/// updating those pairs to compute the new root of the tree, as if the updates had been done on the
/// full tree. This is useful so that not all leaves have to be present and loaded into memory to
/// compute an update.
///
/// A key is considered "tracked" if either:
/// 1. Its merkle path was explicitly added to the tree (via [`PartialSmt::add_path`] or
///    [`PartialSmt::add_proof`]), or
/// 2. The path from the leaf to the root goes through empty subtrees that are consistent with the
///    stored inner nodes (provably empty with zero hash computations).
///
/// The second condition allows updating keys in empty subtrees without explicitly adding their
/// merkle paths. This is verified by walking up from the leaf and checking that any stored
/// inner node has an empty subtree root as the child on our path.
///
/// An important caveat is that only tracked keys can be updated. Attempting to update an
/// untracked key will result in an error. See [`PartialSmt::insert`] for more details.
///
/// Once a partial SMT has been constructed, its root is set in stone. All subsequently added proofs
/// or merkle paths must match that root, otherwise an error is returned.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PartialSmt {
    root: Word,
    num_entries: usize,
    leaves: Leaves<SmtLeaf>,
    inner_nodes: InnerNodes,
}

impl PartialSmt {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The default value used to compute the hash of empty leaves.
    pub const EMPTY_VALUE: Word = EMPTY_WORD;

    /// The root of an empty tree.
    pub const EMPTY_ROOT: Word = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Constructs a [`PartialSmt`] from a root.
    ///
    /// All subsequently added proofs or paths must have the same root.
    pub fn new(root: Word) -> Self {
        Self {
            root,
            num_entries: 0,
            leaves: Leaves::<SmtLeaf>::default(),
            inner_nodes: InnerNodes::default(),
        }
    }

    /// Instantiates a new [`PartialSmt`] by calling [`PartialSmt::add_proof`] for all [`SmtProof`]s
    /// in the provided iterator.
    ///
    /// If the provided iterator is empty, an empty [`PartialSmt`] is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the roots of the provided proofs are not the same.
    pub fn from_proofs<I>(proofs: I) -> Result<Self, MerkleError>
    where
        I: IntoIterator<Item = SmtProof>,
    {
        let mut proofs = proofs.into_iter();

        let Some(first_proof) = proofs.next() else {
            return Ok(Self::default());
        };

        // Add the first path to an empty partial SMT without checking that the existing root
        // matches the new one. This sets the expected root to the root of the first proof and all
        // subsequently added proofs must match it.
        let mut partial_smt = Self::default();
        let (path, leaf) = first_proof.into_parts();
        let path_root = partial_smt.add_path_unchecked(leaf, path);
        partial_smt.root = path_root;

        for proof in proofs {
            partial_smt.add_proof(proof)?;
        }

        Ok(partial_smt)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of the tree.
    pub fn root(&self) -> Word {
        self.root
    }

    /// Returns an opening of the leaf associated with `key`. Conceptually, an opening is a Merkle
    /// path to the leaf, as well as the leaf itself.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked by this partial SMT.
    pub fn open(&self, key: &Word) -> Result<SmtProof, MerkleError> {
        let leaf = self.get_leaf(key)?;
        let merkle_path = self.get_path(key);
        Ok(SmtProof::new_unchecked(merkle_path, leaf))
    }

    /// Returns the leaf to which `key` maps.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked by this partial SMT.
    pub fn get_leaf(&self, key: &Word) -> Result<SmtLeaf, MerkleError> {
        self.get_tracked_leaf(key).ok_or(MerkleError::UntrackedKey(*key))
    }

    /// Returns the value associated with `key`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked by this partial SMT.
    pub fn get_value(&self, key: &Word) -> Result<Word, MerkleError> {
        self.get_tracked_leaf(key)
            .map(|leaf| leaf.get_value(key).unwrap_or_default())
            .ok_or(MerkleError::UntrackedKey(*key))
    }

    /// Returns an iterator over the inner nodes of the [`PartialSmt`].
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.inner_nodes.values().map(|e| InnerNodeInfo {
            value: e.hash(),
            left: e.left,
            right: e.right,
        })
    }

    /// Returns an iterator over the [`InnerNode`] and the respective [`NodeIndex`] of the
    /// [`PartialSmt`].
    pub fn inner_node_indices(&self) -> impl Iterator<Item = (NodeIndex, InnerNode)> + '_ {
        self.inner_nodes.iter().map(|(idx, inner)| (*idx, inner.clone()))
    }

    /// Returns an iterator over the explicitly stored leaves of the [`PartialSmt`] in arbitrary
    /// order.
    ///
    /// Note: This only returns leaves that were explicitly added via [`Self::add_path`] or
    /// [`Self::add_proof`], or created through [`Self::insert`]. It does not include implicitly
    /// trackable leaves in empty subtrees.
    pub fn leaves(&self) -> impl Iterator<Item = (LeafIndex<SMT_DEPTH>, &SmtLeaf)> {
        self.leaves
            .iter()
            .map(|(leaf_index, leaf)| (LeafIndex::new_max_depth(*leaf_index), leaf))
    }

    /// Returns an iterator over the tracked, non-empty key-value pairs of the [`PartialSmt`] in
    /// arbitrary order.
    pub fn entries(&self) -> impl Iterator<Item = &(Word, Word)> {
        self.leaves().flat_map(|(_, leaf)| leaf.entries())
    }

    /// Returns the number of non-empty leaves in this tree.
    ///
    /// Note that this may return a different value from [Self::num_entries()] as a single leaf may
    /// contain more than one key-value pair.
    pub fn num_leaves(&self) -> usize {
        self.leaves.len()
    }

    /// Returns the number of tracked, non-empty key-value pairs in this tree.
    ///
    /// Note that this may return a different value from [Self::num_leaves()] as a single leaf may
    /// contain more than one key-value pair.
    pub fn num_entries(&self) -> usize {
        self.num_entries
    }

    /// Returns a boolean value indicating whether the [`PartialSmt`] tracks any leaves.
    ///
    /// Note that if a partial SMT does not track leaves, its root is not necessarily the empty SMT
    /// root, since it could have been constructed from a different root but without tracking any
    /// leaves.
    pub fn tracks_leaves(&self) -> bool {
        !self.leaves.is_empty()
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Inserts a value at the specified key, returning the previous value associated with that key.
    /// Recall that by definition, any key that hasn't been updated is associated with
    /// [`Self::EMPTY_VALUE`].
    ///
    /// This also recomputes all hashes between the leaf (associated with the key) and the root,
    /// updating the root itself.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked (see the type documentation for the definition of "tracked"). If an
    ///   error is returned the tree is in the same state as before.
    /// - inserting the key-value pair would exceed [`super::MAX_LEAF_ENTRIES`] (1024 entries) in
    ///   the leaf.
    pub fn insert(&mut self, key: Word, value: Word) -> Result<Word, MerkleError> {
        let current_leaf = self.get_tracked_leaf(&key).ok_or(MerkleError::UntrackedKey(key))?;
        let leaf_index = current_leaf.index();
        let previous_value = current_leaf.get_value(&key).unwrap_or(EMPTY_WORD);
        let prev_entries = current_leaf.num_entries();

        let leaf = self
            .leaves
            .entry(leaf_index.position())
            .or_insert_with(|| SmtLeaf::new_empty(leaf_index));

        if value != EMPTY_WORD {
            leaf.insert(key, value).map_err(|e| match e {
                SmtLeafError::TooManyLeafEntries { actual } => {
                    MerkleError::TooManyLeafEntries { actual }
                },
                other => panic!("unexpected SmtLeaf::insert error: {other:?}"),
            })?;
        } else {
            leaf.remove(key);
        }
        let current_entries = leaf.num_entries();
        let new_leaf_hash = leaf.hash();
        self.num_entries = self.num_entries + current_entries - prev_entries;

        // Remove empty leaf
        if current_entries == 0 {
            self.leaves.remove(&leaf_index.position());
        }

        // Recompute the path from leaf to root
        self.recompute_nodes_from_leaf_to_root(leaf_index, new_leaf_hash);

        Ok(previous_value)
    }

    /// Adds an [`SmtProof`] to this [`PartialSmt`].
    ///
    /// This is a convenience method which calls [`Self::add_path`] on the proof. See its
    /// documentation for details on errors.
    pub fn add_proof(&mut self, proof: SmtProof) -> Result<(), MerkleError> {
        let (path, leaf) = proof.into_parts();
        self.add_path(leaf, path)
    }

    /// Adds a leaf and its sparse merkle path to this [`PartialSmt`].
    ///
    /// If this function was called, any key that is part of the `leaf` can subsequently be updated
    /// to a new value and produce a correct new tree root.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the new root after the insertion of the leaf and the path does not match the existing
    ///   root. If an error is returned, the tree is left in an inconsistent state.
    pub fn add_path(&mut self, leaf: SmtLeaf, path: SparseMerklePath) -> Result<(), MerkleError> {
        let path_root = self.add_path_unchecked(leaf, path);

        // Check if the newly added merkle path is consistent with the existing tree. If not, the
        // merkle path was invalid or computed against another tree.
        if self.root() != path_root {
            return Err(MerkleError::ConflictingRoots {
                expected_root: self.root(),
                actual_root: path_root,
            });
        }

        Ok(())
    }

    // UNIQUE NODES
    // --------------------------------------------------------------------------------------------

    /// Converts `self` into the [`UniqueNodes`] serialization representation for compact
    /// serialization.
    ///
    /// This method assumes that the `PartialSmt` is in a valid state.
    ///
    /// # Reconstructable Sets
    ///
    /// We define the notion of a reconstructable set as one which stores the minimum amount of
    /// information necessary in order to reconstruct the full state of the tree. We build this set
    /// as follows:
    ///
    /// 1. Start at the leaves and traverse toward the root.
    /// 2. Wherever a node's value is determined solely by children already implicitly contained
    ///    within the set, store no new information. If additional information is required (e.g. a
    ///    sibling node) store that.
    /// 3. Repeat until the root is reached.
    ///
    /// To reconstruct the tree, we just start at the leaves and compute all intermediary nodes from
    /// the data stored in the reconstructible set.
    pub fn to_unique_nodes(&self) -> UniqueNodes {
        // We start by getting all the known leaves, as these give us the starting point for the
        // reconstruction.
        let leaf_nodes = self
            .leaves()
            .map(|(k, v)| (k, v.clone()))
            .collect::<Map<LeafIndex<SMT_DEPTH>, SmtLeaf>>();

        // We also create storage for the nodes necessary for reconstruction of the tree...
        let mut needed_nodes: Map<NodeIndex, NodeValue> = Map::new();

        // ... and grab the full set of inner nodes to work from as a queue for easy use. We sort
        // them from the bottom of the tree to the top, but retain the standard left-to-right
        // ordering.
        let mut inner_nodes = self.inner_node_indices().collect::<Vec<(NodeIndex, InnerNode)>>();
        inner_nodes.sort_by(|(il, _), (ir, _)| {
            ir.depth().cmp(&il.depth()).then(il.position().cmp(&ir.position()))
        });
        let mut inner_nodes = inner_nodes.into_iter().collect::<VecDeque<(NodeIndex, InnerNode)>>();

        // We also need to store the values for leaves where we ONLY have the hash value, rather
        // than the proper leaf value.
        let mut value_only_leaves = Vec::new();

        // We then need to iterate over all the nodes to work out which ones are reconstructible,
        // and which need us to store additional data to be reconstructible.
        while let Some((ix, v)) = inner_nodes.pop_front() {
            // There must be data available for both of the node's children for it to be
            // reconstructible.
            for (child, val) in [(ix.left_child(), v.left), (ix.right_child(), v.right)] {
                if child.depth() != SMT_DEPTH {
                    // A child of the node `v` can be in one of three states:
                    //
                    // 1. The child does not exist as a physical node in `self`, but its value as
                    //    stored in `v` is real.
                    // 2. The child does not exist as a physical node in `self`, but its value is
                    //    the default empty subtree root.
                    // 3. The child does exist as a physical node in `self`. By induction, as this
                    //    algorithm runs bottom-up, the data to reconstruct the node already exists.
                    if self.get_inner_node(child).is_none() {
                        // In this case, the node does not exist physically, so we have to work out
                        // which of the other cases it is.
                        let new = if val == *EmptySubtreeRoots::entry(SMT_DEPTH, child.depth()) {
                            NodeValue::EmptySubtreeRoot
                        } else {
                            NodeValue::Present(val)
                        };

                        // We allow overwriting existing inserts for algorithmic simplicity, but we
                        // always check that it is the same value if an overwrite occurs as this
                        // indicates a programmer bug.
                        if let Some(v) = needed_nodes.insert(child, new.clone())
                            && v != new
                        {
                            panic!("Overwrite occurred with a different value ")
                        }
                    } else {
                        // Here, the node exists physically, so by induction, it is reconstructible.
                    }
                } else {
                    // Here the child is a leaf node. Leaf nodes can be in one of three states:
                    //
                    // 1. A node that has the default empty value, in which case we encode it using
                    //    absence in the compact representation.
                    // 2. A node that has a hash value, but that does not exist in the physical
                    //    leaves in the PartialSmt. These are encoded using an auxiliary buffer to
                    //    aid in reconstruction.
                    // 3. A node that exists in fully-materialized form. These are encoded with
                    //    their full content.
                    //
                    // Cases 1 and 3 require no special handling here, as they are encoded with the
                    // leaves below. Case 2 needs us to take action here.
                    let empty_leaf_hash =
                        SmtLeaf::new_empty(LeafIndex::new_max_depth(child.position())).hash();

                    if val != empty_leaf_hash && !self.leaves.contains_key(&child.position()) {
                        // We are in case 2 here, as the value is not that of the empty leaf, nor is
                        // there a physical leaf stored in the tree for this. We store this leaf
                        // value in the auxiliary buffer so we can reconstruct correctly in this
                        // scenario.
                        value_only_leaves.push((child.position(), val));
                    }
                }
            }
        }

        // With all the data gathered, we can convert our types as necessary to create our output.
        let leaves = leaf_nodes.into_iter().map(|(i, l)| (i.position(), l)).collect::<Vec<_>>();
        let mut nodes: Map<u8, Vec<(u64, NodeValue)>> = Map::new();

        for (ix, value) in needed_nodes {
            nodes.entry(ix.depth()).or_default().push((ix.position(), value));
        }

        UniqueNodes {
            root: self.root(),
            leaves,
            nodes,
            value_only_leaves,
        }
    }

    /// Constructs a new `PartialSmt` from the provided `unique_nodes`, reconstituting the full data
    /// from the compact representation.
    ///
    /// This method assumes that the `unique_nodes` represent a valid `PartialSmt` instance.
    ///
    /// See the documentation of [`Self::to_unique_nodes`] for the reconstruction algorithm.
    ///
    /// # Errors
    ///
    /// - [`MerkleError::NodeIndexNotFoundInStore`] if any node necessary for reconstruction is not
    ///   available in the provided `unique_nodes` data.
    pub fn from_unique_nodes(unique_nodes: UniqueNodes) -> Result<Self, DeserializationError> {
        // We perform our transformation by directly mutating a new instance of `Self`.
        let mut smt = Self::new(unique_nodes.root);

        // We rely on a minimal set of node values and leaf values to reconstruct the tree, so we
        // have to be able to perform lookups.
        let nodes = unique_nodes
            .nodes
            .into_iter()
            .flat_map(|(depth, nodes)| {
                nodes.into_iter().map(move |(ix, val)| Ok((NodeIndex::new(depth, ix)?, val)))
            })
            .collect::<Result<Map<NodeIndex, NodeValue>, MerkleError>>()
            .map_err(|e| DeserializationError::InvalidValue(e.to_string()))?;
        let all_leaves = unique_nodes
            .leaves
            .into_iter()
            .map(|(ix, l)| {
                let node_index = NodeIndex::new(SMT_DEPTH, ix)
                    .map_err(|e| DeserializationError::InvalidValue(e.to_string()))?;
                if node_index != l.index().index {
                    Err(DeserializationError::InvalidValue(format!(
                        "Node index {ix} did not match the embedded leaf index {}",
                        l.index().index
                    )))
                } else {
                    Ok((
                        NodeIndex::new(SMT_DEPTH, ix)
                            .map_err(|e| DeserializationError::InvalidValue(e.to_string()))?,
                        l,
                    ))
                }
            })
            .collect::<Result<Map<_, _>, DeserializationError>>()?;

        // We also need to grab the buffer of the additional leaf values, and we convert it into a
        // map for easy lookup. It is safe to use `new_unchecked` here as, while this comes from
        // untrusted input, `ix` can correctly take the value of any `u64`.
        let value_only_leaves = unique_nodes
            .value_only_leaves
            .into_iter()
            .map(|(ix, v)| (NodeIndex::new_unchecked(SMT_DEPTH, ix), v))
            .collect::<Map<_, _>>();

        // We then want to process leaf by leaf, with a queue of parent nodes that need visiting.
        // Rather than trying to de-duplicate on the fly, we instead just discard nodes that have
        // already been processed when we see them.
        //
        // It must be ensured that at no point an index that is lower in the tree than any index
        // preceding it is inserted.
        let leaf_based_starting_nodes =
            all_leaves.keys().map(|k| k.parent()).collect::<VecDeque<_>>();

        // We also, however, need to account for inner nodes which are not reachable in a parent
        // chain from a leaf, such as those from an exclusion proof. These are all nodes that do not
        // have a (present) child in the set of nodes or leaves, so to enforce our layering
        // invariant we add them in sorted order from bottom to top, left to right.
        //
        // We process these after the leaf-based nodes to avoid issues with the layering invariant.
        let mut additional_nodes = nodes.keys().map(|ix| ix.parent()).collect::<Vec<_>>();
        additional_nodes
            .sort_by(|il, ir| ir.depth().cmp(&il.depth()).then(il.position().cmp(&ir.position())));
        let additional_nodes = additional_nodes.into_iter().collect::<VecDeque<_>>();

        // We also track the nodes we have seen to avoid re-doing unnecessary work.
        let mut seen_nodes = Set::new();

        for mut active_nodes in [leaf_based_starting_nodes, additional_nodes] {
            seen_nodes.clear();
            while let Some(ix) = active_nodes.pop_front() {
                // To avoid re-doing work we immediately discard a node that is already in our tree.
                if smt.inner_nodes.contains_key(&ix) {
                    continue;
                }

                if ix.depth() + 1 == SMT_DEPTH {
                    // We have to handle the case where the children are the leaves specially.
                    //
                    // If no corresponding leaf is present, then either it was a default value, or
                    // it exists in the value-only leaves buffer, so we have to check both.
                    let left_child = ix.left_child();
                    let left = all_leaves
                        .get(&left_child)
                        .map(SmtLeaf::hash)
                        .or_else(|| value_only_leaves.get(&left_child).copied())
                        .unwrap_or(
                            SmtLeaf::new_empty(LeafIndex::new_max_depth(left_child.position()))
                                .hash(),
                        );
                    let right_child = ix.right_child();
                    let right = all_leaves
                        .get(&right_child)
                        .map(SmtLeaf::hash)
                        .or_else(|| value_only_leaves.get(&right_child).copied())
                        .unwrap_or(
                            SmtLeaf::new_empty(LeafIndex::new_max_depth(right_child.position()))
                                .hash(),
                        );

                    smt.insert_inner_node(ix, InnerNode { left, right })
                } else {
                    // If the children are not in the leaves, they can be either in the tree already
                    // (having been reconstructed) or as a value in the nodes from the unique nodes
                    // structure.
                    let [left, right] = [ix.left_child(), ix.right_child()].map(|ix| {
                        smt.get_inner_node(ix).map(|n| Ok(n.hash())).unwrap_or_else(|| match nodes
                            .get(&ix)
                            .ok_or_else(|| {
                                DeserializationError::InvalidValue(format!(
                                    "Node at {ix} not found but is required"
                                ))
                            })? {
                            NodeValue::EmptySubtreeRoot => {
                                Ok(*EmptySubtreeRoots::entry(SMT_DEPTH, ix.depth()))
                            },
                            NodeValue::Present(v) => Ok(*v),
                        })
                    });
                    let left = left?;
                    let right = right?;

                    smt.insert_inner_node(ix, InnerNode { left, right });
                }

                // Finally, we push the node's parent into the queue if we have not already visited
                // it. While it would be correct to do unconditionally, we operate over untrusted
                // input and hence we have to be careful.
                let parent = ix.parent();
                if !seen_nodes.contains(&parent) {
                    active_nodes.push_back(parent);
                    seen_nodes.insert(parent);
                }
            }
        }

        // With that done, we simply have to write the remaining keys into the tree.
        all_leaves.into_iter().for_each(|(ix, leaf)| {
            smt.num_entries += leaf.num_entries();
            smt.leaves.insert(ix.position(), leaf);
        });

        smt.validate()?;

        Ok(smt)
    }

    // PRIVATE HELPERS
    // --------------------------------------------------------------------------------------------

    /// Adds a leaf and its sparse merkle path to this [`PartialSmt`] and returns the root of the
    /// inserted path.
    ///
    /// This does not check that the path root matches the existing root of the tree and if so, the
    /// tree is left in an inconsistent state. This state can be made consistent again by setting
    /// the root of the SMT to the path root.
    fn add_path_unchecked(&mut self, leaf: SmtLeaf, path: SparseMerklePath) -> Word {
        let mut current_index = leaf.index().index;

        let mut node_hash_at_current_index = leaf.hash();

        let prev_entries = self
            .leaves
            .get(&current_index.position())
            .map(SmtLeaf::num_entries)
            .unwrap_or(0);
        let current_entries = leaf.num_entries();
        // Only store non-empty leaves
        if current_entries > 0 {
            self.leaves.insert(current_index.position(), leaf);
        } else {
            self.leaves.remove(&current_index.position());
        }

        // Guaranteed not to over/underflow. All variables are <= MAX_LEAF_ENTRIES and result > 0.
        self.num_entries = self.num_entries + current_entries - prev_entries;

        for sibling_hash in path {
            // Find the index of the sibling node and compute whether it is a left or right child.
            let is_sibling_right = current_index.sibling().is_position_odd();

            // Move the index up so it points to the parent of the current index and the sibling.
            current_index.move_up();

            // Construct the new parent node from the child that was updated and the sibling from
            // the merkle path.
            let new_parent_node = if is_sibling_right {
                InnerNode {
                    left: node_hash_at_current_index,
                    right: sibling_hash,
                }
            } else {
                InnerNode {
                    left: sibling_hash,
                    right: node_hash_at_current_index,
                }
            };

            node_hash_at_current_index = new_parent_node.hash();

            self.insert_inner_node(current_index, new_parent_node);
        }

        node_hash_at_current_index
    }

    /// Returns the leaf for a key if it can be tracked.
    ///
    /// A key is trackable if:
    /// 1. It was explicitly added via `add_path`/`add_proof`, OR
    /// 2. The path to the leaf goes through empty subtrees (provably empty)
    ///
    /// Returns `None` if the key cannot be tracked (path goes through non-empty
    /// subtrees we don't have data for).
    fn get_tracked_leaf(&self, key: &Word) -> Option<SmtLeaf> {
        let leaf_index = Self::key_to_leaf_index(key);

        // Explicitly stored leaves are always trackable
        if let Some(leaf) = self.leaves.get(&leaf_index.position()) {
            return Some(leaf.clone());
        }

        // Empty tree - all leaves implicitly trackable
        if self.root == Self::EMPTY_ROOT {
            return Some(SmtLeaf::new_empty(leaf_index));
        }

        // Walk from root down towards the leaf
        let target: NodeIndex = leaf_index.into();
        let mut index = NodeIndex::root();

        for i in (0..SMT_DEPTH).rev() {
            let inner_node = self.get_inner_node(index)?;

            let is_right = target.is_nth_bit_odd(i);
            let child_hash = if is_right { inner_node.right } else { inner_node.left };

            // If child is empty subtree root, leaf is implicitly trackable
            if child_hash == *EmptySubtreeRoots::entry(SMT_DEPTH, SMT_DEPTH - i) {
                return Some(SmtLeaf::new_empty(leaf_index));
            }

            index = if is_right {
                index.right_child()
            } else {
                index.left_child()
            };
        }

        // Reached leaf level without finding empty subtree - can't track
        None
    }

    /// Converts a key to a leaf index.
    fn key_to_leaf_index(key: &Word) -> LeafIndex<SMT_DEPTH> {
        let most_significant_felt = key[3];
        LeafIndex::new_max_depth(most_significant_felt.as_canonical_u64())
    }

    /// Returns the inner node at the specified index, or `None` if not stored.
    fn get_inner_node(&self, index: NodeIndex) -> Option<InnerNode> {
        self.inner_nodes.get(&index).cloned()
    }

    /// Returns the inner node at the specified index, falling back to the empty subtree root
    /// if not stored.
    fn get_inner_node_or_empty(&self, index: NodeIndex) -> InnerNode {
        self.get_inner_node(index)
            .unwrap_or_else(|| EmptySubtreeRoots::get_inner_node(SMT_DEPTH, index.depth()))
    }

    /// Inserts an inner node at the specified index, or removes it if it equals the empty
    /// subtree root.
    fn insert_inner_node(&mut self, index: NodeIndex, inner_node: InnerNode) {
        if inner_node == EmptySubtreeRoots::get_inner_node(SMT_DEPTH, index.depth()) {
            self.inner_nodes.remove(&index);
        } else {
            self.inner_nodes.insert(index, inner_node);
        }
    }

    /// Returns the merkle path for a key by walking up the tree from the leaf.
    fn get_path(&self, key: &Word) -> SparseMerklePath {
        let index = NodeIndex::from(Self::key_to_leaf_index(key));

        // Use proof_indices to get sibling indices from leaf to root,
        // and get each sibling's hash
        SparseMerklePath::from_sized_iter(index.proof_indices().map(|idx| self.get_node_hash(idx)))
            .expect("path should be valid since it's from a valid SMT")
    }

    /// Get the hash of a node at an arbitrary index, including the root or leaf hashes.
    ///
    /// The root index simply returns the root. Other hashes are retrieved by looking at
    /// the parent inner node and returning the respective child hash.
    fn get_node_hash(&self, index: NodeIndex) -> Word {
        if index.is_root() {
            return self.root;
        }

        let InnerNode { left, right } = self.get_inner_node_or_empty(index.parent());

        if index.is_position_odd() { right } else { left }
    }

    /// Recomputes all inner nodes from a leaf up to the root after a leaf value change.
    fn recompute_nodes_from_leaf_to_root(
        &mut self,
        leaf_index: LeafIndex<SMT_DEPTH>,
        leaf_hash: Word,
    ) {
        use crate::hash::poseidon2::Poseidon2;

        let mut index: NodeIndex = leaf_index.into();
        let mut node_hash = leaf_hash;

        for _ in (0..index.depth()).rev() {
            let is_right = index.is_position_odd();
            index.move_up();
            let InnerNode { left, right } = self.get_inner_node_or_empty(index);
            let (left, right) = if is_right {
                (left, node_hash)
            } else {
                (node_hash, right)
            };
            node_hash = Poseidon2::merge(&[left, right]);

            // insert_inner_node handles removing empty subtree roots
            self.insert_inner_node(index, InnerNode { left, right });
        }
        self.root = node_hash;
    }

    /// Validates the internal structure during deserialization.
    ///
    /// Checks that:
    /// - Each inner node's hash is consistent with its parent.
    /// - Each leaf's hash is consistent with its parent inner node's left/right child.
    fn validate(&self) -> Result<(), DeserializationError> {
        // Validate each inner node is consistent with its parent
        for (&idx, node) in &self.inner_nodes {
            let node_hash = node.hash();
            let expected_hash = self.get_node_hash(idx);

            if node_hash != expected_hash {
                return Err(DeserializationError::InvalidValue(
                    "inner node hash is inconsistent with parent".into(),
                ));
            }
        }

        // Validate each leaf's hash is consistent with its parent inner node
        for (&leaf_pos, leaf) in &self.leaves {
            let leaf_index = LeafIndex::<SMT_DEPTH>::new_max_depth(leaf_pos);
            let node_index: NodeIndex = leaf_index.into();
            let leaf_hash = leaf.hash();
            let expected_hash = self.get_node_hash(node_index);

            if leaf_hash != expected_hash {
                return Err(DeserializationError::InvalidValue(
                    "leaf hash is inconsistent with parent inner node".into(),
                ));
            }
        }

        Ok(())
    }
}

impl Default for PartialSmt {
    /// Returns a new, empty [`PartialSmt`].
    ///
    /// All leaves in the returned tree are set to [`Self::EMPTY_VALUE`].
    fn default() -> Self {
        Self::new(Self::EMPTY_ROOT)
    }
}

// CONVERSIONS
// ================================================================================================

impl From<super::Smt> for PartialSmt {
    fn from(smt: super::Smt) -> Self {
        Self {
            root: smt.root(),
            num_entries: smt.num_entries(),
            leaves: smt.leaves().map(|(idx, leaf)| (idx.position(), leaf.clone())).collect(),
            inner_nodes: smt.inner_node_indices().collect(),
        }
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for PartialSmt {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let unique_rep = self.to_unique_nodes();
        unique_rep.write_into(target);
    }
}

impl Deserializable for PartialSmt {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let unique_rep = UniqueNodes::read_from(source)?;
        PartialSmt::from_unique_nodes(unique_rep)
            .map_err(|e| DeserializationError::InvalidValue(format!("{e}")))
    }
}
