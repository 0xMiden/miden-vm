use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque, btree_map},
    vec,
    vec::Vec,
};
use core::{cmp::Reverse, iter, slice};

use super::{
    ExecutableMastForest, MastForest, MastNode, MastNodeExt, MastNodeId, SparseMastForest,
    serialization::basic_block_content_key,
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
        let mut source_capacity_by_digest = BTreeMap::<Word, usize>::new();
        let mut source_full_roots = FullRootGroups::new();
        let mut source_content_ids = StoredContentIds::new(self.source);
        for &source_root in self.source.procedure_roots() {
            let Some(digest) = self.source.get_digest_by_id(source_root) else {
                continue;
            };
            *source_capacity_by_digest.entry(digest).or_default() += 1;
            if self.source.get_node_by_id(source_root).is_some() {
                let Some(content_id) = source_content_ids.get(source_root) else {
                    continue;
                };
                source_full_roots
                    .entry(digest)
                    .or_default()
                    .entry(content_id)
                    .and_modify(|(_, count)| *count += 1)
                    .or_insert((source_root, 1));
            }
        }

        let mut candidate_full_roots = FullRootGroups::new();
        let mut candidate_opaque_roots = BTreeMap::<Word, usize>::new();
        let mut candidate_content_ids = StoredContentIds::new(self.candidate);
        for &candidate_root in self.candidate.procedure_roots() {
            if self.candidate.get_node_by_id(candidate_root).is_some() {
                let Some(digest) = self.candidate.get_digest_by_id(candidate_root) else {
                    return false;
                };
                let Some(content_id) = candidate_content_ids.get(candidate_root) else {
                    return false;
                };
                candidate_full_roots
                    .entry(digest)
                    .or_default()
                    .entry(content_id)
                    .and_modify(|(_, count)| *count += 1)
                    .or_insert((candidate_root, 1));
            } else if let Some(digest) = self.candidate.get_digest_by_id(candidate_root) {
                *candidate_opaque_roots.entry(digest).or_default() += 1;
            } else {
                return false;
            }
        }

        for (digest, candidate_groups) in candidate_full_roots {
            let Some(source_groups) = source_full_roots.get(&digest) else {
                return false;
            };
            let candidate_groups: Vec<_> = candidate_groups.values().copied().collect();
            let source_groups: Vec<_> = source_groups.values().copied().collect();
            let mut matched_candidate_groups = Vec::with_capacity(candidate_groups.len());
            for &(candidate_root, count) in &candidate_groups {
                let mut matches = Vec::new();
                for (source_index, &(source_root, _)) in source_groups.iter().enumerate() {
                    if self.full_nodes_match(candidate_root, source_root) {
                        matches.push(source_index);
                    }
                }
                if matches.is_empty() {
                    return false;
                }
                matched_candidate_groups.push((count, matches));
            }
            matched_candidate_groups.sort_by_key(|(_, matches)| Reverse(matches.len()));

            let candidate_counts: Vec<_> =
                matched_candidate_groups.iter().map(|(count, _)| *count).collect();
            let compatible_sources: Vec<_> =
                matched_candidate_groups.into_iter().map(|(_, matches)| matches).collect();
            let source_counts: Vec<_> = source_groups.iter().map(|(_, count)| *count).collect();
            let Some(source_used) = assign_export_multiplicities(
                &candidate_counts,
                &source_counts,
                &compatible_sources,
            ) else {
                return false;
            };
            let used: usize = source_used.into_iter().sum();
            let capacity = source_capacity_by_digest
                .get_mut(&digest)
                .expect("source root digest capacity must exist");
            if *capacity < used {
                return false;
            }
            *capacity -= used;
        }

        candidate_opaque_roots.into_iter().all(|(digest, count)| {
            source_capacity_by_digest.get(&digest).copied().unwrap_or_default() >= count
        })
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

type FullRootGroups = BTreeMap<Word, BTreeMap<usize, (MastNodeId, usize)>>;

#[derive(Eq, Ord, PartialEq, PartialOrd)]
enum StoredContentKey {
    Opaque(Word),
    Block(Word, Vec<u8>),
    Join(Word, usize, usize),
    Split(Word, usize, usize),
    Loop(Word, usize),
    Call(Word, bool, usize),
    Dyn(Word, bool),
    External(Word),
}

struct StoredContentIds<'a, F: MastForestRead + ?Sized> {
    forest: &'a F,
    by_node_id: BTreeMap<MastNodeId, usize>,
    by_content: BTreeMap<StoredContentKey, usize>,
    visiting: BTreeSet<MastNodeId>,
}

impl<'a, F: MastForestRead + ?Sized> StoredContentIds<'a, F> {
    fn new(forest: &'a F) -> Self {
        Self {
            forest,
            by_node_id: BTreeMap::new(),
            by_content: BTreeMap::new(),
            visiting: BTreeSet::new(),
        }
    }

    fn get(&mut self, node_id: MastNodeId) -> Option<usize> {
        stored_content_id(
            self.forest,
            node_id,
            &mut self.by_node_id,
            &mut self.by_content,
            &mut self.visiting,
        )
    }
}

fn stored_content_id<F: MastForestRead + ?Sized>(
    forest: &F,
    node_id: MastNodeId,
    by_node_id: &mut BTreeMap<MastNodeId, usize>,
    by_content: &mut BTreeMap<StoredContentKey, usize>,
    visiting: &mut BTreeSet<MastNodeId>,
) -> Option<usize> {
    if let Some(&content_id) = by_node_id.get(&node_id) {
        return Some(content_id);
    }
    if !visiting.insert(node_id) {
        return None;
    }

    let key = (|| {
        let node = match forest.get_node_by_id(node_id) {
            Some(node) => node,
            None => return Some(StoredContentKey::Opaque(forest.get_digest_by_id(node_id)?)),
        };
        let digest = node.digest();
        let key = match node {
            MastNode::Block(block) => {
                StoredContentKey::Block(digest, basic_block_content_key(block))
            },
            MastNode::Join(join) => StoredContentKey::Join(
                digest,
                stored_content_id(forest, join.first(), by_node_id, by_content, visiting)?,
                stored_content_id(forest, join.second(), by_node_id, by_content, visiting)?,
            ),
            MastNode::Split(split) => StoredContentKey::Split(
                digest,
                stored_content_id(forest, split.on_true(), by_node_id, by_content, visiting)?,
                stored_content_id(forest, split.on_false(), by_node_id, by_content, visiting)?,
            ),
            MastNode::Loop(loop_node) => StoredContentKey::Loop(
                digest,
                stored_content_id(forest, loop_node.body(), by_node_id, by_content, visiting)?,
            ),
            MastNode::Call(call) => StoredContentKey::Call(
                digest,
                call.is_syscall(),
                stored_content_id(forest, call.callee(), by_node_id, by_content, visiting)?,
            ),
            MastNode::Dyn(dyn_node) => StoredContentKey::Dyn(digest, dyn_node.is_dyncall()),
            MastNode::External(_) => StoredContentKey::External(digest),
        };
        Some(key)
    })();
    visiting.remove(&node_id);
    let key = key?;

    let next_content_id = by_content.len();
    let content_id = *by_content.entry(key).or_insert(next_content_id);
    by_node_id.insert(node_id, content_id);
    Some(content_id)
}

fn assign_export_multiplicities(
    candidate_counts: &[usize],
    source_counts: &[usize],
    compatible_sources: &[Vec<usize>],
) -> Option<Vec<usize>> {
    let mut candidate_flows = vec![BTreeMap::<usize, usize>::new(); candidate_counts.len()];
    let mut source_flows = vec![BTreeMap::<usize, usize>::new(); source_counts.len()];
    let mut source_used = vec![0usize; source_counts.len()];

    for start_candidate in 0..candidate_counts.len() {
        let mut remaining = candidate_counts[start_candidate];
        while remaining > 0 {
            let mut candidate_seen = vec![false; candidate_counts.len()];
            let mut candidate_parent = vec![None; candidate_counts.len()];
            let mut source_parent = vec![None; source_counts.len()];
            let mut queue = VecDeque::new();
            candidate_seen[start_candidate] = true;
            queue.push_back(start_candidate);

            let mut found_source = None;
            'search: while let Some(candidate_index) = queue.pop_front() {
                for &source_index in &compatible_sources[candidate_index] {
                    if source_parent[source_index].is_some() {
                        continue;
                    }
                    source_parent[source_index] = Some(candidate_index);
                    if source_used[source_index] < source_counts[source_index] {
                        found_source = Some(source_index);
                        break 'search;
                    }
                    for (&assigned_candidate, &flow) in &source_flows[source_index] {
                        if flow > 0 && !candidate_seen[assigned_candidate] {
                            candidate_seen[assigned_candidate] = true;
                            candidate_parent[assigned_candidate] = Some(source_index);
                            queue.push_back(assigned_candidate);
                        }
                    }
                }
            }

            let mut path_source = found_source?;
            let mut flow = remaining.min(source_counts[path_source] - source_used[path_source]);
            loop {
                let candidate_index = source_parent[path_source]
                    .expect("visited source must have a candidate parent");
                if candidate_index == start_candidate {
                    break;
                }
                let previous_source = candidate_parent[candidate_index]
                    .expect("reassigned candidate must have a source parent");
                flow = flow.min(candidate_flows[candidate_index][&previous_source]);
                path_source = previous_source;
            }

            path_source = found_source.expect("found source must remain available");
            loop {
                let candidate_index = source_parent[path_source]
                    .expect("visited source must have a candidate parent");
                *candidate_flows[candidate_index].entry(path_source).or_default() += flow;
                *source_flows[path_source].entry(candidate_index).or_default() += flow;
                source_used[path_source] += flow;

                if candidate_index == start_candidate {
                    break;
                }
                let previous_source = candidate_parent[candidate_index]
                    .expect("reassigned candidate must have a source parent");
                let candidate_flow = candidate_flows[candidate_index]
                    .get_mut(&previous_source)
                    .expect("alternating path must follow assigned flow");
                *candidate_flow -= flow;
                if *candidate_flow == 0 {
                    candidate_flows[candidate_index].remove(&previous_source);
                }
                let source_flow = source_flows[previous_source]
                    .get_mut(&candidate_index)
                    .expect("alternating path must follow assigned flow");
                *source_flow -= flow;
                if *source_flow == 0 {
                    source_flows[previous_source].remove(&candidate_index);
                }
                source_used[previous_source] -= flow;
                path_source = previous_source;
            }
            remaining -= flow;
        }
    }

    Some(source_used)
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
        mast::{
            BasicBlockNode, BasicBlockNodeBuilder, JoinNodeBuilder, MastNodeExt,
            SparseMastForestBuilder, VisitKind,
        },
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
        let candidate_root = JoinNodeBuilder::new([candidate_left, candidate_right])
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
        let source_root = JoinNodeBuilder::new([source_left, source_right])
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
        let reversed_root = JoinNodeBuilder::new([reversed_right, reversed_left])
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

    #[test]
    fn content_subset_reassigns_broad_full_export() {
        let opaque_child = MastNodeId::new_unchecked(0);
        let broad_root = MastNodeId::new_unchecked(1);
        let full_child = MastNodeId::new_unchecked(2);
        let strict_root = MastNodeId::new_unchecked(3);

        let mut low_template = MastForest::new();
        let low_child = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut low_template)
            .unwrap();
        let low_join = JoinNodeBuilder::new([low_child, low_child])
            .add_to_forest(&mut low_template)
            .unwrap();
        assert_eq!((low_child, low_join), (opaque_child, broad_root));

        let mut high_template = MastForest::new();
        BasicBlockNodeBuilder::new(vec![Operation::Drop])
            .add_to_forest(&mut high_template)
            .unwrap();
        BasicBlockNodeBuilder::new(vec![Operation::Mul])
            .add_to_forest(&mut high_template)
            .unwrap();
        let high_child = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut high_template)
            .unwrap();
        let high_join = JoinNodeBuilder::new([high_child, high_child])
            .add_to_forest(&mut high_template)
            .unwrap();
        assert_eq!((high_child, high_join), (full_child, strict_root));

        let child_digest = low_template[low_child].digest();
        let candidate = SparseMastForest::from_serialized_parts(
            vec![
                (broad_root, low_template[low_join].clone()),
                (full_child, high_template[high_child].clone()),
                (strict_root, high_template[high_join].clone()),
            ],
            vec![(opaque_child, child_digest)],
            vec![broad_root, broad_root, broad_root, strict_root, strict_root],
            AdviceMap::default(),
        )
        .unwrap();
        let source = SparseMastForest::from_serialized_parts(
            vec![
                (opaque_child, low_template[low_child].clone()),
                (broad_root, low_template[low_join].clone()),
                (strict_root, high_template[high_join].clone()),
            ],
            vec![(full_child, child_digest)],
            vec![broad_root, broad_root, strict_root, strict_root, strict_root],
            AdviceMap::default(),
        )
        .unwrap();
        let insufficient_source = SparseMastForest::from_serialized_parts(
            vec![
                (opaque_child, low_template[low_child].clone()),
                (broad_root, low_template[low_join].clone()),
                (strict_root, high_template[high_join].clone()),
            ],
            vec![(full_child, child_digest)],
            vec![broad_root, strict_root, strict_root, strict_root, strict_root],
            AdviceMap::default(),
        )
        .unwrap();

        assert!(candidate.is_content_subset_of(&source));
        assert!(!candidate.is_content_subset_of(&insufficient_source));
    }

    #[test]
    fn content_subset_counts_repeated_opaque_exports() {
        let root = MastNodeId::new_unchecked(0);
        let digest = Word::default();
        let candidate = SparseMastForest::from_serialized_parts(
            Vec::new(),
            vec![(root, digest)],
            vec![root; 10_000],
            AdviceMap::default(),
        )
        .unwrap();
        let source = SparseMastForest::from_serialized_parts(
            Vec::new(),
            vec![(root, digest)],
            vec![root; 10_000],
            AdviceMap::default(),
        )
        .unwrap();
        let too_small = SparseMastForest::from_serialized_parts(
            Vec::new(),
            vec![(root, digest)],
            vec![root; 9_999],
            AdviceMap::default(),
        )
        .unwrap();

        assert!(candidate.is_content_subset_of(&source));
        assert!(!candidate.is_content_subset_of(&too_small));
    }

    #[test]
    fn content_subset_groups_distinct_ids_with_identical_full_content() {
        let mut template = MastForest::new();
        let template_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut template)
            .unwrap();
        let node = template[template_id].clone();
        let nodes: Vec<_> = (0..10_000)
            .map(|index| (MastNodeId::new_unchecked(index), node.clone()))
            .collect();
        let roots: Vec<_> = nodes.iter().map(|(node_id, _)| *node_id).collect();
        let candidate = SparseMastForest::from_serialized_parts(
            nodes.clone(),
            Vec::new(),
            roots.clone(),
            AdviceMap::default(),
        )
        .unwrap();
        let source =
            SparseMastForest::from_serialized_parts(nodes, Vec::new(), roots, AdviceMap::default())
                .unwrap();

        assert!(candidate.is_content_subset_of(&source));
    }

    #[test]
    fn content_subset_does_not_group_distinct_blocks_with_colliding_digests() {
        let add = MastNode::Block(BasicBlockNode::new(vec![Operation::Add]).unwrap());
        let add_noop =
            MastNode::Block(BasicBlockNode::new(vec![Operation::Add, Operation::Noop]).unwrap());
        assert_eq!(add.digest(), add_noop.digest());
        assert_ne!(add, add_noop);

        let first = MastNodeId::new_unchecked(0);
        let second = MastNodeId::new_unchecked(1);
        let candidate = SparseMastForest::from_serialized_parts(
            vec![(first, add.clone())],
            Vec::new(),
            vec![first, first],
            AdviceMap::default(),
        )
        .unwrap();
        let source = SparseMastForest::from_serialized_parts(
            vec![(first, add), (second, add_noop)],
            Vec::new(),
            vec![first, second],
            AdviceMap::default(),
        )
        .unwrap();

        assert!(!candidate.is_content_subset_of(&source));
    }

    #[test]
    fn content_subset_interns_many_colliding_export_roots_once() {
        let mut source = MastForest::new();
        let add = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut source)
            .unwrap();
        let add_noop = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Noop])
            .add_to_forest(&mut source)
            .unwrap();
        assert_eq!(source[add].digest(), source[add_noop].digest());

        let mut level = vec![add, add_noop];
        while level.len() < 10_000 {
            let mut next = Vec::with_capacity(level.len() * 2);
            for node_id in level {
                next.push(JoinNodeBuilder::new([node_id, add]).add_to_forest(&mut source).unwrap());
                next.push(
                    JoinNodeBuilder::new([node_id, add_noop]).add_to_forest(&mut source).unwrap(),
                );
            }
            level = next;
        }
        for root in level.into_iter().take(10_000) {
            source.make_root(root);
        }

        let opaque_root = MastNodeId::new_unchecked(0);
        let root_digest = source[source.procedure_roots()[0]].digest();
        let candidate = SparseMastForest::from_serialized_parts(
            Vec::new(),
            vec![(opaque_root, root_digest)],
            vec![opaque_root],
            AdviceMap::default(),
        )
        .unwrap();

        assert!(candidate.is_content_subset_of(&source));
    }
}
