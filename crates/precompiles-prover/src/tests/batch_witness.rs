use alloc::{collections::BTreeMap, vec, vec::Vec};

use miden_core::deferred::{
    DeferredError, Digest, Node, Precompile, PrecompileWitness, PrecompileWitnessEntry, TRUE_DIGEST,
};
use miden_precompiles::{CurvePrecompile, UintPrecompile};

/// Raw committed test graphs, with no runtime evaluator. The shared fixture also supports the
/// pre-existing arithmetic/MSM cases, and permits false claims to reach the importer boundary.
#[derive(Debug)]
pub(super) struct WitnessFixture {
    nodes: BTreeMap<Digest, Node>,
    root: Digest,
}

impl WitnessFixture {
    pub(super) fn new() -> Self {
        Self {
            nodes: UintPrecompile
                .init()
                .into_iter()
                .chain(CurvePrecompile.init())
                .map(|node| (node.digest(), node))
                .collect(),
            root: TRUE_DIGEST,
        }
    }

    pub(super) fn register(&mut self, node: Node) -> Result<Digest, DeferredError> {
        let digest = node.digest();
        if self.nodes.get(&digest).is_some_and(|previous| *previous != node) {
            return Err(DeferredError::ConflictingNode);
        }
        self.nodes.insert(digest, node);
        Ok(digest)
    }

    pub(super) fn log_statement(&mut self, claim: Digest) -> Result<Digest, DeferredError> {
        self.root = self.register(Node::and(self.root, claim))?;
        Ok(self.root)
    }

    pub(super) fn root(&self) -> Digest {
        self.root
    }

    pub(super) fn get_node(&self, digest: &Digest) -> Option<&Node> {
        self.nodes.get(digest)
    }

    pub(super) fn witness(&self) -> PrecompileWitness {
        self.open(self.root)
    }

    fn open(&self, root: Digest) -> PrecompileWitness {
        let mut indices = BTreeMap::from([(TRUE_DIGEST, 0u32)]);
        let mut entries = Vec::new();
        let mut work = vec![(root, false)];
        while let Some((digest, emit)) = work.pop() {
            if indices.contains_key(&digest) {
                continue;
            }
            let node = &self.nodes[&digest];
            let tag = node.tag();
            let children = if let Ok((lhs, rhs)) = node.payload().as_join() {
                vec![(lhs, rhs)]
            } else {
                node.payload().as_pair_list().unwrap_or_default()
            };
            if !emit {
                work.push((digest, true));
                for &(lhs, rhs) in children.iter().rev() {
                    work.push((rhs, false));
                    work.push((lhs, false));
                }
                continue;
            }
            let entry = if let Ok(chunks) = node.payload().as_data() {
                PrecompileWitnessEntry::Data { tag, chunks: chunks.to_vec() }
            } else if let Ok((lhs, rhs)) = node.payload().as_join() {
                PrecompileWitnessEntry::Join {
                    tag,
                    lhs: indices[&lhs],
                    rhs: indices[&rhs],
                }
            } else {
                PrecompileWitnessEntry::PairList {
                    tag,
                    pairs: children.iter().map(|(lhs, rhs)| (indices[lhs], indices[rhs])).collect(),
                }
            };
            entries.push(entry);
            indices.insert(digest, entries.len() as u32);
        }
        let witness = PrecompileWitness::from_entries(entries).unwrap();
        assert_eq!(witness.root(), root);
        witness
    }
}
