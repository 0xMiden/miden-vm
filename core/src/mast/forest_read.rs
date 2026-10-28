use alloc::{
    collections::{BTreeMap, BTreeSet, btree_map},
    vec,
    vec::Vec,
};
use core::{iter, slice};

use super::{
    ExecutableMastForest, MastForest, MastNode, MastNodeExt, MastNodeId, SparseMastForest,
};
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

    /// Returns true when this forest's stored contents are a subset of `source`.
    ///
    /// Forest-local node IDs may differ. Full nodes must match by kind, payload, and ordered child
    /// contents. An opaque digest-only entry may match either an opaque entry or a full node with
    /// that digest, but it cannot establish that a full node is present. Export multiplicity and
    /// advice entries are checked independently.
    fn is_content_subset_of<S: MastForestRead + ?Sized>(&self, source: &S) -> bool {
        ContentMatcher::new(self, source).is_subset()
    }
}

struct ContentMatcher<'a, C: MastForestRead + ?Sized, S: MastForestRead + ?Sized> {
    candidate: &'a C,
    source: &'a S,
    source_full_ids_by_digest: BTreeMap<Word, Vec<MastNodeId>>,
    source_digests: BTreeSet<Word>,
    matching_pairs: BTreeSet<(MastNodeId, MastNodeId)>,
}

impl<'a, C: MastForestRead + ?Sized, S: MastForestRead + ?Sized> ContentMatcher<'a, C, S> {
    fn new(candidate: &'a C, source: &'a S) -> Self {
        let mut source_full_ids_by_digest = BTreeMap::<Word, Vec<MastNodeId>>::new();
        let mut source_digests = BTreeSet::new();
        for (node_id, node) in source.node_entries() {
            let digest = node.digest();
            source_full_ids_by_digest.entry(digest).or_default().push(node_id);
            source_digests.insert(digest);
        }
        source_digests.extend(source.digest_entries().map(|(_, digest)| digest));

        Self {
            candidate,
            source,
            source_full_ids_by_digest,
            source_digests,
            matching_pairs: BTreeSet::new(),
        }
    }

    fn is_subset(&mut self) -> bool {
        for (candidate_id, _) in self.candidate.node_entries() {
            if !self.has_matching_full_node(candidate_id) {
                return false;
            }
        }
        for (_, digest) in self.candidate.digest_entries() {
            if !self.source_has_digest(digest) {
                return false;
            }
        }
        if !self.exports_are_subset() {
            return false;
        }
        self.candidate
            .advice_map()
            .iter()
            .all(|(key, value)| self.source.advice_map().get(key) == Some(value))
    }

    fn has_matching_full_node(&mut self, candidate_id: MastNodeId) -> bool {
        let Some(digest) = self.candidate.get_digest_by_id(candidate_id) else {
            return false;
        };
        let Some(num_candidates) = self.source_full_ids_by_digest.get(&digest).map(Vec::len) else {
            return false;
        };
        for index in 0..num_candidates {
            let source_id = self.source_full_ids_by_digest[&digest][index];
            if self.full_nodes_match(candidate_id, source_id) {
                return true;
            }
        }
        false
    }

    fn source_has_digest(&self, digest: Word) -> bool {
        self.source_digests.contains(&digest)
    }

    fn exports_are_subset(&mut self) -> bool {
        let candidate_roots = self.candidate.procedure_roots().to_vec();
        let source_roots = self.source.procedure_roots().to_vec();
        if candidate_roots.len() > source_roots.len() {
            return false;
        }

        let mut source_owners = vec![None; source_roots.len()];
        for candidate_index in 0..candidate_roots.len() {
            let mut visited = vec![false; source_roots.len()];
            if !self.assign_export(
                candidate_index,
                &candidate_roots,
                &source_roots,
                &mut source_owners,
                &mut visited,
            ) {
                return false;
            }
        }
        true
    }

    fn assign_export(
        &mut self,
        candidate_index: usize,
        candidate_roots: &[MastNodeId],
        source_roots: &[MastNodeId],
        source_owners: &mut [Option<usize>],
        visited: &mut [bool],
    ) -> bool {
        for source_index in 0..source_roots.len() {
            if visited[source_index]
                || !self.entries_match(candidate_roots[candidate_index], source_roots[source_index])
            {
                continue;
            }
            visited[source_index] = true;

            if source_owners[source_index].is_none_or(|owner| {
                self.assign_export(owner, candidate_roots, source_roots, source_owners, visited)
            }) {
                source_owners[source_index] = Some(candidate_index);
                return true;
            }
        }
        false
    }

    fn entries_match(&mut self, candidate_id: MastNodeId, source_id: MastNodeId) -> bool {
        if self.candidate.get_node_by_id(candidate_id).is_some() {
            self.source.get_node_by_id(source_id).is_some()
                && self.full_nodes_match(candidate_id, source_id)
        } else if let Some(digest) = self.candidate.get_digest_by_id(candidate_id) {
            self.source.get_digest_by_id(source_id) == Some(digest)
        } else {
            false
        }
    }

    fn full_nodes_match(&mut self, candidate_id: MastNodeId, source_id: MastNodeId) -> bool {
        let pair = (candidate_id, source_id);
        if self.matching_pairs.contains(&pair) {
            return true;
        }

        let Some(candidate) = self.candidate.get_node_by_id(candidate_id) else {
            return false;
        };
        let Some(source) = self.source.get_node_by_id(source_id) else {
            return false;
        };
        if candidate.digest() != source.digest() {
            return false;
        }

        let matches = match (candidate, source) {
            (MastNode::Block(left), MastNode::Block(right)) => left == right,
            (MastNode::Dyn(left), MastNode::Dyn(right)) => left == right,
            (MastNode::External(left), MastNode::External(right)) => left == right,
            (MastNode::Join(left), MastNode::Join(right)) => {
                self.entries_match(left.first(), right.first())
                    && self.entries_match(left.second(), right.second())
            },
            (MastNode::Split(left), MastNode::Split(right)) => {
                self.entries_match(left.on_true(), right.on_true())
                    && self.entries_match(left.on_false(), right.on_false())
            },
            (MastNode::Loop(left), MastNode::Loop(right)) => {
                self.entries_match(left.body(), right.body())
            },
            (MastNode::Call(left), MastNode::Call(right)) => {
                left.is_syscall() == right.is_syscall()
                    && self.entries_match(left.callee(), right.callee())
            },
            _ => false,
        };
        if matches {
            self.matching_pairs.insert(pair);
        }
        matches
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

    #[test]
    fn content_subset_matches_remapped_ordered_children() {
        let mut candidate = MastForest::new();
        let candidate_left = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut candidate)
            .unwrap();
        let candidate_right = BasicBlockNodeBuilder::new(vec![Operation::Mul])
            .add_to_forest(&mut candidate)
            .unwrap();
        let candidate_root = crate::mast::JoinNodeBuilder::new([candidate_left, candidate_right])
            .add_to_forest(&mut candidate)
            .unwrap();
        candidate.make_root(candidate_root);

        let mut source = MastForest::new();
        BasicBlockNodeBuilder::new(vec![Operation::Drop])
            .add_to_forest(&mut source)
            .unwrap();
        let source_left = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut source)
            .unwrap();
        let source_right = BasicBlockNodeBuilder::new(vec![Operation::Mul])
            .add_to_forest(&mut source)
            .unwrap();
        let source_root = crate::mast::JoinNodeBuilder::new([source_left, source_right])
            .add_to_forest(&mut source)
            .unwrap();
        source.make_root(source_root);

        assert!(!candidate.is_source_subset_of(&source));
        assert!(candidate.is_content_subset_of(&source));

        let mut reversed = MastForest::new();
        let reversed_left = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut reversed)
            .unwrap();
        let reversed_right = BasicBlockNodeBuilder::new(vec![Operation::Mul])
            .add_to_forest(&mut reversed)
            .unwrap();
        let reversed_root = crate::mast::JoinNodeBuilder::new([reversed_right, reversed_left])
            .add_to_forest(&mut reversed)
            .unwrap();
        reversed.make_root(reversed_root);
        assert!(!candidate.is_content_subset_of(&reversed));
    }

    #[test]
    fn content_subset_distinguishes_full_nodes_from_opaque_digests_and_error_codes() {
        let mut full = MastForest::new();
        let full_id = BasicBlockNodeBuilder::new(vec![Operation::Assert(Felt::new_unchecked(7))])
            .add_to_forest(&mut full)
            .unwrap();

        let opaque = SparseMastForest::from_serialized_parts(
            Vec::new(),
            vec![(MastNodeId::new_unchecked(19), full[full_id].digest())],
            Vec::new(),
            AdviceMap::default(),
        )
        .unwrap();
        assert!(opaque.is_content_subset_of(&full));
        assert!(!full.is_content_subset_of(&opaque));

        let mut different_error_code = MastForest::new();
        let different_id =
            BasicBlockNodeBuilder::new(vec![Operation::Assert(Felt::new_unchecked(8))])
                .add_to_forest(&mut different_error_code)
                .unwrap();
        assert_eq!(full[full_id].digest(), different_error_code[different_id].digest());
        assert!(!full.is_content_subset_of(&different_error_code));
    }

    #[test]
    fn content_subset_finds_non_greedy_export_pairing() {
        let mut dense = MastForest::new();
        let dense_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut dense)
            .unwrap();
        let digest = dense[dense_id].digest();
        let full_id = MastNodeId::new_unchecked(0);
        let opaque_id = MastNodeId::new_unchecked(1);

        let candidate = SparseMastForest::from_serialized_parts(
            vec![(full_id, dense[dense_id].clone())],
            vec![(opaque_id, digest)],
            vec![opaque_id, full_id],
            AdviceMap::default(),
        )
        .unwrap();
        let source = SparseMastForest::from_serialized_parts(
            vec![(full_id, dense[dense_id].clone())],
            vec![(opaque_id, digest)],
            vec![full_id, opaque_id],
            AdviceMap::default(),
        )
        .unwrap();

        assert!(candidate.is_content_subset_of(&source));
    }
}
