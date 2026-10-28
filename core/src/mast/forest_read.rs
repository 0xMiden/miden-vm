use alloc::collections::{BTreeMap, btree_map};
use core::{iter, slice};

use super::{ExecutableMastForest, MastForest, MastNode, MastNodeId, SparseMastForest};
use crate::Word;

type DenseNodeIter<'a> = iter::Map<
    iter::Enumerate<slice::Iter<'a, MastNode>>,
    fn((usize, &'a MastNode)) -> (MastNodeId, &'a MastNode),
>;

type SparseNodeIter<'a> = iter::Map<
    btree_map::Iter<'a, MastNodeId, MastNode>,
    fn((&'a MastNodeId, &'a MastNode)) -> (MastNodeId, &'a MastNode),
>;

type SparseDigestIter<'a> = iter::Map<
    btree_map::Iter<'a, MastNodeId, Word>,
    fn((&'a MastNodeId, &'a Word)) -> (MastNodeId, Word),
>;

/// Read-only storage access shared by dense and sparse MAST forests.
///
/// Full nodes and opaque digest-only entries are separate. Implementations must iterate only
/// stored entries; a sparse forest's node count describes its ID span rather than its entry count.
pub trait MastForestRead: ExecutableMastForest {
    type NodeIter<'a>: Iterator<Item = (MastNodeId, &'a MastNode)>
    where
        Self: 'a;

    type DigestIter<'a>: Iterator<Item = (MastNodeId, Word)>
    where
        Self: 'a;

    /// Iterates full nodes with their forest-local IDs.
    fn node_entries(&self) -> Self::NodeIter<'_>;

    /// Iterates opaque digest-only entries with their forest-local IDs.
    fn digest_entries(&self) -> Self::DigestIter<'_>;

    /// Returns exported procedure roots in this forest's ID space.
    fn procedure_roots(&self) -> &[MastNodeId];

    /// Returns true when this forest is an exact-ID subset of `source`.
    ///
    /// Full nodes must match at their original IDs, while digest-only entries may match either a
    /// full node or a digest-only entry with the same digest. Exports and advice entries must also
    /// be present in `source`. Use a content-subset check when forest-local IDs may differ.
    fn is_source_subset_of<S: MastForestRead + ?Sized>(&self, source: &S) -> bool {
        self.node_entries().all(|(node_id, node)| {
            ExecutableMastForest::get_node_by_id(source, node_id) == Some(node)
        }) && self
            .digest_entries()
            .all(|(node_id, digest)| source.get_digest_by_id(node_id) == Some(digest))
            && roots_are_subset(self.procedure_roots(), source.procedure_roots())
            && self
                .advice_map()
                .iter()
                .all(|(key, value)| source.advice_map().get(key) == Some(value))
    }
}

fn roots_are_subset(subset: &[MastNodeId], source: &[MastNodeId]) -> bool {
    let mut remaining = BTreeMap::<MastNodeId, usize>::new();
    for &root in source {
        *remaining.entry(root).or_default() += 1;
    }
    for root in subset {
        let Some(count) = remaining.get_mut(root) else {
            return false;
        };
        if *count == 0 {
            return false;
        }
        *count -= 1;
    }
    true
}

impl MastForestRead for MastForest {
    type NodeIter<'a> = DenseNodeIter<'a>;
    type DigestIter<'a> = iter::Empty<(MastNodeId, Word)>;

    fn node_entries(&self) -> Self::NodeIter<'_> {
        self.nodes().iter().enumerate().map(dense_node_entry)
    }

    fn digest_entries(&self) -> Self::DigestIter<'_> {
        iter::empty()
    }

    fn procedure_roots(&self) -> &[MastNodeId] {
        MastForest::procedure_roots(self)
    }
}

impl MastForestRead for SparseMastForest {
    type NodeIter<'a> = SparseNodeIter<'a>;
    type DigestIter<'a> = SparseDigestIter<'a>;

    fn node_entries(&self) -> Self::NodeIter<'_> {
        self.nodes().iter().map(sparse_node_entry)
    }

    fn digest_entries(&self) -> Self::DigestIter<'_> {
        SparseMastForest::digest_entries(self).iter().map(sparse_digest_entry)
    }

    fn procedure_roots(&self) -> &[MastNodeId] {
        SparseMastForest::procedure_roots(self)
    }
}

fn dense_node_entry((index, node): (usize, &MastNode)) -> (MastNodeId, &MastNode) {
    (MastNodeId::new_unchecked(index as u32), node)
}

fn sparse_node_entry<'a>(
    (&node_id, node): (&'a MastNodeId, &'a MastNode),
) -> (MastNodeId, &'a MastNode) {
    (node_id, node)
}

fn sparse_digest_entry((&node_id, &digest): (&MastNodeId, &Word)) -> (MastNodeId, Word) {
    (node_id, digest)
}

#[cfg(test)]
mod tests {
    use alloc::{sync::Arc, vec, vec::Vec};

    use super::*;
    use crate::{
        Felt,
        advice::AdviceMap,
        mast::{BasicBlockNodeBuilder, MastNodeExt, SparseMastForestBuilder, VisitKind},
        operations::Operation,
    };

    #[test]
    fn source_subset_uses_stored_sparse_entries() {
        let mut source = MastForest::new();
        let retained = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut source)
            .unwrap();
        let omitted = BasicBlockNodeBuilder::new(vec![Operation::Mul])
            .add_to_forest(&mut source)
            .unwrap();
        source.make_root(retained);

        let source = Arc::new(source);
        let mut builder = SparseMastForestBuilder::new(Arc::clone(&source));
        builder.record_visit(retained, VisitKind::FullVisit);
        builder.record_visit(omitted, VisitKind::DigestOnly);
        let sparse = builder.finalize();

        assert_eq!(sparse.node_entries().count(), 1);
        assert_eq!(MastForestRead::digest_entries(&sparse).count(), 1);
        assert!(sparse.is_source_subset_of(source.as_ref()));
        assert!(!source.as_ref().is_source_subset_of(&sparse));
    }

    #[test]
    fn source_subset_checks_nodes_digests_exports_and_advice_separately() {
        let advice_key = Word::new([
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
        ]);
        let mut source = MastForest::new();
        let first = BasicBlockNodeBuilder::new(vec![Operation::Assert(Felt::new_unchecked(7))])
            .add_to_forest(&mut source)
            .unwrap();
        let second = BasicBlockNodeBuilder::new(vec![Operation::Mul])
            .add_to_forest(&mut source)
            .unwrap();
        source.make_root(first);
        source = source
            .with_advice_map(AdviceMap::from_iter([(advice_key, vec![Felt::new_unchecked(5)])]));

        let matching = SparseMastForest::from_serialized_parts(
            vec![(first, source[first].clone())],
            vec![(second, source[second].digest())],
            vec![first],
            AdviceMap::default(),
        )
        .unwrap();
        assert!(matching.is_source_subset_of(&source));

        let mut different_source = MastForest::new();
        let different_first =
            BasicBlockNodeBuilder::new(vec![Operation::Assert(Felt::new_unchecked(8))])
                .add_to_forest(&mut different_source)
                .unwrap();
        let wrong_node = SparseMastForest::from_serialized_parts(
            vec![(first, different_source[different_first].clone())],
            Vec::new(),
            vec![first],
            AdviceMap::default(),
        )
        .unwrap();
        assert!(!wrong_node.is_source_subset_of(&source));

        let wrong_digest = SparseMastForest::from_serialized_parts(
            Vec::new(),
            vec![(second, Word::default())],
            vec![first],
            AdviceMap::default(),
        )
        .unwrap();
        assert!(!wrong_digest.is_source_subset_of(&source));

        let wrong_export = SparseMastForest::from_serialized_parts(
            Vec::new(),
            Vec::new(),
            vec![second],
            AdviceMap::default(),
        )
        .unwrap();
        assert!(!wrong_export.is_source_subset_of(&source));

        let duplicate_export = SparseMastForest::from_serialized_parts(
            Vec::new(),
            Vec::new(),
            vec![first, first],
            AdviceMap::default(),
        )
        .unwrap();
        assert!(!duplicate_export.is_source_subset_of(&source));

        let wrong_advice = MastForest::new()
            .with_advice_map(AdviceMap::from_iter([(advice_key, vec![Felt::new_unchecked(6)])]));
        assert!(!wrong_advice.is_source_subset_of(&source));
    }
}
