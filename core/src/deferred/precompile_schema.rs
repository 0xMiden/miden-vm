//! The [`Precompiles`] registry — dispatches each deferred [`Tag`] to a [`Precompile`].

use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

use super::precompile::{Precompile, precompile_id};
use crate::{
    Felt, ZERO,
    deferred::{
        DeferredError, DeferredState, Digest, Node, PrecompileError, Tag, TagInfo, WitnessBuilder,
    },
};

/// A registry that dispatches each [`Tag`] to the [`Precompile`] selected by its
/// [`Tag::id`](crate::deferred::Tag).
///
/// Precompiles are held in a `BTreeMap<id, Box<dyn Precompile>>`. Order is irrelevant — the id
/// is the only thing that decides routing. This is the single concrete driver of the
/// deferred-DAG semantic layer; there is no trait abstraction over it.
///
/// [`Default`] yields the empty registry, which rejects every tag — the processor's
/// out-of-the-box state when no precompiles are installed.
#[derive(Debug, Default)]
pub struct Precompiles {
    precompiles: BTreeMap<Felt, Box<dyn Precompile>>,
}

impl Precompiles {
    /// Build a registry from any iterable of boxed precompiles. Errors if a precompile's
    /// declared [`Precompile::id`] doesn't match its [`precompile_id`] derivation (the pinned id
    /// drifted) or derives the framework-reserved `ZERO`, or if two precompiles resolve to the
    /// same id.
    pub fn new<I>(precompiles: I) -> Result<Self, PrecompileError>
    where
        I: IntoIterator<Item = Box<dyn Precompile>>,
    {
        let mut map: BTreeMap<Felt, Box<dyn Precompile>> = BTreeMap::new();
        for p in precompiles {
            let id = p.id();
            if id != precompile_id(&*p) {
                return Err(PrecompileError::PrecompileIdMismatch(p.name()));
            }
            // `id == precompile_id` here, so a `ZERO` id means the derivation itself produced
            // the framework-reserved value (a ~2^-64 event). Reject — `ZERO` tags the TRUE /
            // AND nodes and must never route to a precompile.
            if id == ZERO {
                return Err(PrecompileError::PrecompileIdMismatch(p.name()));
            }
            let name = p.name();
            if let Some(prev) = map.insert(id, p) {
                return Err(PrecompileError::DuplicatePrecompileId(prev.name(), name));
            }
        }
        Ok(Self { precompiles: map })
    }

    /// Convenience constructor for a single-precompile registry (common in tests).
    ///
    /// Kept generic over the concrete `P` rather than `impl Into<Box<dyn Precompile>>`: the
    /// orphan rule blocks a blanket `From<P> for Box<dyn Precompile>`, so an `Into` bound would
    /// force callers to hand-box (`single(Box::new(x) as _)`) — strictly worse than `single(x)`.
    pub fn single<P: Precompile + 'static>(precompile: P) -> Result<Self, PrecompileError> {
        Self::new([Box::new(precompile) as Box<dyn Precompile>])
    }

    /// Collect every precompile's canonical constant leaves ([`Precompile::init`]) and intern
    /// them into `state`. Errors with [`DeferredError::ConflictingNode`] if two *different*
    /// precompiles contribute the same node digest (ambiguous canonical-leaf ownership).
    ///
    /// Caller is responsible for invoking this — it is not implicit in [`Self::new`] because
    /// callers may want to build the registry before the state, or to skip it in tests where
    /// determinism of node counts matters.
    pub fn init(&self, state: &mut DeferredState) -> Result<(), PrecompileError> {
        let mut seen: Vec<Digest> = Vec::new();
        for p in self.precompiles.values() {
            let nodes = p.init();
            // Cross-precompile collision: a digest already contributed by a *prior*
            // precompile. Idempotent re-interns within one precompile are harmless.
            let local: Vec<Digest> = nodes.iter().map(Node::digest).collect();
            if local.iter().any(|d| seen.contains(d)) {
                return Err(DeferredError::ConflictingNode.into());
            }
            for node in nodes {
                state.intern(node);
            }
            seen.extend(local);
        }
        Ok(())
    }

    /// Returns the ids present in this registry, in `BTreeMap` order. Mainly for tests and
    /// diagnostics.
    pub fn precompile_ids(&self) -> Vec<Felt> {
        self.precompiles.keys().copied().collect()
    }

    /// Decode `tag` to its [`TagInfo`] by routing [`Tag::imm`](crate::deferred::Tag) to the
    /// precompile owning [`Tag::id`](crate::deferred::Tag). An unknown id is rejected by the
    /// registry itself (not name-wrapped); a precompile's own rejection is name-wrapped.
    pub fn decode(&self, tag: Tag) -> Result<TagInfo, PrecompileError> {
        let p = self.precompiles.get(&tag.id).ok_or(PrecompileError::InvalidNode)?;
        p.decode(tag.imm).ok_or_else(|| PrecompileError::Precompile {
            name: p.name(),
            source: Box::new(PrecompileError::InvalidNode),
        })
    }

    /// Reduce `node` to its canonical form via the precompile owning its
    /// [`Tag::id`](crate::deferred::Tag). The precompile's failure is name-wrapped so dispatch
    /// errors are attributable. See [`Precompile::reduce`] for the per-kind contract.
    pub fn reduce(
        &self,
        node: &Node,
        witness: &mut WitnessBuilder<'_>,
    ) -> Result<Node, PrecompileError> {
        let p = self.precompiles.get(&node.tag.id).ok_or(PrecompileError::InvalidNode)?;
        p.reduce(node, witness).map_err(|source| PrecompileError::Precompile {
            name: p.name(),
            source: Box::new(source),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deferred::{NodeType, Payload};

    /// An honest minimal precompile fixture — its `id()` *is* its `precompile_id`, so it always
    /// passes the `new` validator. Distinct `name`s yield distinct ids; identical names collide
    /// (exercises the duplicate-id path). Enough to exercise the registry's dispatch surface
    /// without depending on a reference precompile.
    #[derive(Debug, Clone, Copy)]
    struct Fixture {
        name: &'static str,
    }

    impl Fixture {
        fn new(name: &'static str) -> Self {
            Self { name }
        }
        fn tag(&self) -> Tag {
            Tag { id: self.id(), imm: [ZERO; 3] }
        }
    }

    impl Precompile for Fixture {
        fn name(&self) -> &'static str {
            self.name
        }
        fn id(&self) -> Felt {
            precompile_id(self)
        }
        fn decode(&self, imm: [Felt; 3]) -> Option<TagInfo> {
            if imm != [ZERO; 3] {
                return None;
            }
            Some(TagInfo {
                node_type: NodeType::Value,
                evaluates_to: self.tag(),
            })
        }
        fn reduce(
            &self,
            node: &Node,
            _witness: &mut WitnessBuilder<'_>,
        ) -> Result<Node, PrecompileError> {
            Ok(node.clone())
        }
    }

    #[test]
    fn dispatches_by_id() {
        let a = Fixture::new("fixture-a");
        let b = Fixture::new("fixture-b");
        let tag_a = a.tag();
        let tag_b = b.tag();
        let registry = Precompiles::new([
            Box::new(a) as Box<dyn Precompile>,
            Box::new(b) as Box<dyn Precompile>,
        ])
        .unwrap();

        assert_eq!(registry.decode(tag_a).unwrap().evaluates_to, tag_a);
        assert_eq!(registry.decode(tag_b).unwrap().evaluates_to, tag_b);
    }

    #[test]
    fn unknown_id_rejected() {
        let registry = Precompiles::single(Fixture::new("known")).unwrap();
        let bogus = Tag {
            id: Felt::new_unchecked(9999),
            imm: [ZERO; 3],
        };
        // Unknown id is rejected by the registry itself (not a precompile), so it is *not*
        // name-wrapped.
        assert!(matches!(registry.decode(bogus), Err(PrecompileError::InvalidNode)));
    }

    #[test]
    fn nonzero_reserved_felt_rejected() {
        let f = Fixture::new("f");
        let mut tag = f.tag();
        tag.imm[2] = Felt::new_unchecked(1);
        let registry = Precompiles::single(f).unwrap();
        // The precompile rejected the immediate, so the registry name-wraps the cause.
        assert!(matches!(registry.decode(tag).unwrap_err().root(), PrecompileError::InvalidNode));
    }

    #[test]
    fn duplicate_id_errors() {
        let err = Precompiles::new([
            Box::new(Fixture::new("dup")) as Box<dyn Precompile>,
            Box::new(Fixture::new("dup")) as Box<dyn Precompile>,
        ])
        .unwrap_err();
        assert!(matches!(err, PrecompileError::DuplicatePrecompileId("dup", "dup")));
    }

    #[test]
    fn reduce_dispatches_to_owning_precompile() {
        let f = Fixture::new("r");
        let tag = f.tag();
        let registry = Precompiles::single(f).unwrap();
        let node = Node::expression(tag, Payload::new([ZERO; 8]));
        let mut state = DeferredState::new();
        // Use the framework's evaluate path so we exercise dispatch end-to-end.
        let canonical = state.evaluate(&registry, node.clone()).unwrap();
        assert_eq!(canonical, node);
    }
}
