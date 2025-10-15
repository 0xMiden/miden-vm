use alloc::vec::Vec;

use miden_crypto::hash::{
    Digest,
    blake::{Blake3_256, Blake3Digest},
};

use crate::{
    LookupByIdx, Operation, Word,
    mast::{DecoratorId, MastForest, MastForestError, MastNode, MastNodeId, node::MastNodeExt},
};

// MAST NODE EQUALITY
// ================================================================================================

pub type DecoratorFingerprint = Blake3Digest<32>;

/// Represents the hash used to test for equality between [`MastNode`]s.
///
/// The decorator root will be `None` if and only if there are no decorators attached to the node,
/// and all children have no decorator roots (meaning that there are no decorators in all the
/// descendants).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MastNodeFingerprint {
    mast_root: Word,
    decorator_root: Option<DecoratorFingerprint>,
}

// ------------------------------------------------------------------------------------------------
/// Constructors
impl MastNodeFingerprint {
    /// Creates a new [`MastNodeFingerprint`] from the given MAST root with an empty decorator root.
    pub fn new(mast_root: Word) -> Self {
        Self { mast_root, decorator_root: None }
    }

    /// Creates a new [`MastNodeFingerprint`] from the given MAST root and the given
    /// [`DecoratorFingerprint`].
    pub fn with_decorator_root(mast_root: Word, decorator_root: DecoratorFingerprint) -> Self {
        Self {
            mast_root,
            decorator_root: Some(decorator_root),
        }
    }

    /// Creates a [`MastNodeFingerprint`] from a [`MastNode`].
    ///
    /// The `hash_by_node_id` map must contain all children of the node for efficient lookup of
    /// their fingerprints. This function returns an error if a child of the given `node` is not in
    /// this map.
    pub fn from_mast_node(
        forest: &MastForest,
        hash_by_node_id: &impl LookupByIdx<MastNodeId, MastNodeFingerprint>,
        node: &MastNode,
    ) -> Result<MastNodeFingerprint, MastForestError> {
        match node {
            MastNode::Block(node) => {
                // Check if we have any decorators at all (before_enter, op-indexed, or after_exit)
                let has_before_decorators = !node.before_enter().is_empty();
                let has_after_decorators = !node.after_exit().is_empty();
                let has_op_decorators = node.decorators().next().is_some();

                // If no decorators, return simple fingerprint
                if !has_before_decorators && !has_after_decorators && !has_op_decorators {
                    return Ok(MastNodeFingerprint::new(node.digest()));
                }

                let mut bytes_to_hash = Vec::new();

                // Hash before_enter decorators first
                for decorator_id in node.before_enter() {
                    bytes_to_hash.extend(forest[*decorator_id].fingerprint().as_bytes());
                }

                // Hash op-indexed decorators
                for (idx, decorator_id) in node.indexed_decorator_iter() {
                    bytes_to_hash.extend(idx.to_le_bytes());
                    bytes_to_hash.extend(forest[decorator_id].fingerprint().as_bytes());
                }

                // Hash after_exit decorators last
                for decorator_id in node.after_exit() {
                    bytes_to_hash.extend(forest[*decorator_id].fingerprint().as_bytes());
                }

                // Add any `Assert`, `U32assert2` and `MpVerify` opcodes present, since these are
                // not included in the MAST root.
                for (op_idx, op) in node.operations().enumerate() {
                    if let Operation::U32assert2(inner_value)
                    | Operation::Assert(inner_value)
                    | Operation::MpVerify(inner_value) = op
                    {
                        let op_idx: u32 = op_idx
                            .try_into()
                            .expect("there are more than 2^{32}-1 operations in basic block");

                        // we include the opcode to differentiate between `Assert` and `U32assert2`
                        bytes_to_hash.push(op.op_code());
                        // we include the operation index to distinguish between basic blocks that
                        // would have the same assert instructions, but in a different order
                        bytes_to_hash.extend(op_idx.to_le_bytes());
                        let inner_value = u64::from(*inner_value);
                        bytes_to_hash.extend(inner_value.to_le_bytes());
                    }
                }

                let decorator_root = Blake3_256::hash(&bytes_to_hash);
                Ok(MastNodeFingerprint::with_decorator_root(node.digest(), decorator_root))
            },
            other_node => {
                let mut children = Vec::new();
                other_node.for_each_child(|child_id| children.push(child_id));
                fingerprint_from_parts(
                    forest,
                    hash_by_node_id,
                    other_node.before_enter(),
                    other_node.after_exit(),
                    &children,
                    other_node.digest(),
                )
            },
        }
    }
}

// ------------------------------------------------------------------------------------------------
/// Accessors
impl MastNodeFingerprint {
    pub fn mast_root(&self) -> &Word {
        &self.mast_root
    }
}

fn fingerprint_from_parts(
    forest: &MastForest,
    hash_by_node_id: &impl LookupByIdx<MastNodeId, MastNodeFingerprint>,
    before_enter_ids: &[DecoratorId],
    after_exit_ids: &[DecoratorId],
    children_ids: &[MastNodeId],
    node_digest: Word,
) -> Result<MastNodeFingerprint, MastForestError> {
    let pre_decorator_hash_bytes =
        before_enter_ids.iter().flat_map(|&id| forest[id].fingerprint().as_bytes());
    let post_decorator_hash_bytes =
        after_exit_ids.iter().flat_map(|&id| forest[id].fingerprint().as_bytes());

    let children_decorator_roots = children_ids
        .iter()
        .filter_map(|child_id| {
            hash_by_node_id
                .get(*child_id)
                .ok_or(MastForestError::ChildFingerprintMissing(*child_id))
                .map(|child_fingerprint| child_fingerprint.decorator_root)
                .transpose()
        })
        .collect::<Result<Vec<DecoratorFingerprint>, MastForestError>>()?;

    // Reminder: the `MastNodeFingerprint`'s decorator root will be `None` if and only if there are
    // no decorators attached to the node, and all children have no decorator roots (meaning
    // that there are no decorators in all the descendants).
    if pre_decorator_hash_bytes.clone().next().is_none()
        && post_decorator_hash_bytes.clone().next().is_none()
        && children_decorator_roots.is_empty()
    {
        Ok(MastNodeFingerprint::new(node_digest))
    } else {
        let decorator_bytes_to_hash: Vec<u8> = pre_decorator_hash_bytes
            .chain(post_decorator_hash_bytes)
            .chain(
                children_decorator_roots
                    .into_iter()
                    .flat_map(|decorator_root| decorator_root.as_bytes()),
            )
            .collect();

        let decorator_root = Blake3_256::hash(&decorator_bytes_to_hash);
        Ok(MastNodeFingerprint::with_decorator_root(node_digest, decorator_root))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;

    use super::*;
    use crate::{
        Decorator, Operation,
        mast::{BasicBlockNode, MastNode},
    };

    /// Creates a basic block with the given operations
    fn basic_block_with_ops(ops: Vec<Operation>) -> MastNode {
        BasicBlockNode::new(ops, Vec::new()).unwrap().into()
    }

    /// Creates a decorator and returns its ID
    fn add_trace_decorator(forest: &mut MastForest, value: u8) -> DecoratorId {
        forest.add_decorator(Decorator::Trace(value.into())).unwrap()
    }

    #[test]
    fn basic_block_fingerprint_different_before_decorators() {
        let mut forest = MastForest::new();
        let deco1 = add_trace_decorator(&mut forest, 1);
        let deco2 = add_trace_decorator(&mut forest, 2);

        // Create two identical basic blocks with different before_enter decorators
        let mut block1 = basic_block_with_ops(vec![Operation::Add, Operation::Mul]);
        let mut block2 = basic_block_with_ops(vec![Operation::Add, Operation::Mul]);

        block1.append_before_enter(&[deco1]);
        block2.append_before_enter(&[deco2]);

        // Compute fingerprints
        let empty_map = BTreeMap::new();
        let fp1 = MastNodeFingerprint::from_mast_node(&forest, &empty_map, &block1).unwrap();
        let fp2 = MastNodeFingerprint::from_mast_node(&forest, &empty_map, &block2).unwrap();

        // Fingerprints should be different
        assert_ne!(
            fp1, fp2,
            "Basic blocks with different before_enter decorators should have different fingerprints"
        );
    }

    #[test]
    fn basic_block_fingerprint_different_after_decorators() {
        let mut forest = MastForest::new();
        let deco1 = add_trace_decorator(&mut forest, 1);
        let deco2 = add_trace_decorator(&mut forest, 2);

        // Create two identical basic blocks with different after_exit decorators
        let mut block1 = basic_block_with_ops(vec![Operation::Add, Operation::Mul]);
        let mut block2 = basic_block_with_ops(vec![Operation::Add, Operation::Mul]);

        block1.append_after_exit(&[deco1]);
        block2.append_after_exit(&[deco2]);

        // Compute fingerprints
        let empty_map = BTreeMap::new();
        let fp1 = MastNodeFingerprint::from_mast_node(&forest, &empty_map, &block1).unwrap();
        let fp2 = MastNodeFingerprint::from_mast_node(&forest, &empty_map, &block2).unwrap();

        // Fingerprints should be different
        assert_ne!(
            fp1, fp2,
            "Basic blocks with different after_exit decorators should have different fingerprints"
        );
    }
}
