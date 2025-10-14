use alloc::vec::Vec;

use miden_crypto::hash::{
    Digest,
    blake::{Blake3_256, Blake3Digest},
};

use crate::{
    LookupByIdx, Operation, Word,
    mast::{
        DecoratorId, MastForest, MastForestError, MastNode, MastNodeId,
        node::{MastNodeErrorContext, MastNodeExt},
    },
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
                let mut bytes_to_hash = Vec::new();

                for (idx, decorator_id) in node.decorators() {
                    bytes_to_hash.extend(idx.to_le_bytes());
                    bytes_to_hash.extend(forest[decorator_id].fingerprint().as_bytes());
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

                if bytes_to_hash.is_empty() {
                    Ok(MastNodeFingerprint::new(node.digest()))
                } else {
                    let decorator_root = Blake3_256::hash(&bytes_to_hash);
                    Ok(MastNodeFingerprint::with_decorator_root(node.digest(), decorator_root))
                }
            },
            MastNode::Join(node) => fingerprint_from_parts(
                forest,
                hash_by_node_id,
                node.before_enter(),
                node.after_exit(),
                &[node.first(), node.second()],
                node.digest(),
            ),
            MastNode::Split(node) => fingerprint_from_parts(
                forest,
                hash_by_node_id,
                node.before_enter(),
                node.after_exit(),
                &[node.on_true(), node.on_false()],
                node.digest(),
            ),
            MastNode::Loop(node) => fingerprint_from_parts(
                forest,
                hash_by_node_id,
                node.before_enter(),
                node.after_exit(),
                &[node.body()],
                node.digest(),
            ),
            MastNode::Call(node) => fingerprint_from_parts(
                forest,
                hash_by_node_id,
                node.before_enter(),
                node.after_exit(),
                &[node.callee()],
                node.digest(),
            ),
            MastNode::Dyn(node) => fingerprint_from_parts(
                forest,
                hash_by_node_id,
                node.before_enter(),
                node.after_exit(),
                &[],
                node.digest(),
            ),
            MastNode::External(node) => fingerprint_from_parts(
                forest,
                hash_by_node_id,
                node.before_enter(),
                node.after_exit(),
                &[],
                node.digest(),
            ),
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
