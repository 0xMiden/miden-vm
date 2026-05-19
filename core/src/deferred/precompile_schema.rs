//! The composite [`PrecompileSchema`] — a [`Schema`] built from a set of [`Precompile`]s.

use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

use super::precompile::{Precompile, PrecompileTag, precompile_id};
use crate::{
    Felt,
    deferred::{
        DeferredError, DeferredState, Digest, Node, ReduceCtx, Schema, SchemaError, Tag, TagInfo,
    },
};

/// A [`Schema`] that dispatches each tag to a [`Precompile`] selected by `tag[0]` (its id).
///
/// Precompiles are held in a `BTreeMap<id, Box<dyn Precompile>>`. Order is irrelevant — the id
/// is the only thing that decides routing.
#[derive(Debug)]
pub struct PrecompileSchema {
    precompiles: BTreeMap<Felt, Box<dyn Precompile>>,
}

impl PrecompileSchema {
    /// Build a composite from any iterable of boxed precompiles. Errors if a precompile's
    /// declared [`Precompile::id`] doesn't match its [`precompile_id`] derivation (the pinned id
    /// drifted), or if two precompiles resolve to the same id.
    pub fn new<I>(precompiles: I) -> Result<Self, SchemaError>
    where
        I: IntoIterator<Item = Box<dyn Precompile>>,
    {
        let mut map: BTreeMap<Felt, Box<dyn Precompile>> = BTreeMap::new();
        for p in precompiles {
            let id = p.id();
            if id != precompile_id(&*p) {
                return Err(SchemaError::PrecompileIdMismatch(p.name()));
            }
            let name = p.name();
            if let Some(prev) = map.insert(id, p) {
                return Err(SchemaError::DuplicatePrecompileId(prev.name(), name));
            }
        }
        Ok(Self { precompiles: map })
    }

    /// Convenience constructor for a single-precompile schema (common in tests).
    ///
    /// Kept generic over the concrete `P` rather than `impl Into<Box<dyn Precompile>>`: the
    /// orphan rule blocks a blanket `From<P> for Box<dyn Precompile>`, so an `Into` bound would
    /// force callers to hand-box (`single(Box::new(x) as _)`) — strictly worse than `single(x)`.
    pub fn single<P: Precompile + 'static>(precompile: P) -> Result<Self, SchemaError> {
        Self::new([Box::new(precompile) as Box<dyn Precompile>])
    }

    /// Collect every precompile's canonical constant leaves ([`Precompile::init`]) and intern
    /// them into `state`. Errors with [`DeferredError::ConflictingNode`] if two *different*
    /// precompiles contribute the same node digest (ambiguous canonical-leaf ownership).
    ///
    /// Caller is responsible for invoking this — it is not implicit in [`Self::new`] because
    /// callers may want to attach the schema before building the state, or to skip it in tests
    /// where determinism of node counts matters.
    pub fn init(&self, state: &mut DeferredState) -> Result<(), SchemaError> {
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

    /// Returns the ids present in this composite, in `BTreeMap` order. Mainly for tests and
    /// diagnostics.
    pub fn precompile_ids(&self) -> Vec<Felt> {
        self.precompiles.keys().copied().collect()
    }
}

impl Schema for PrecompileSchema {
    fn decode(&self, tag: Tag) -> Result<TagInfo, SchemaError> {
        let p = self.precompiles.get(&tag[0]).ok_or(SchemaError::InvalidNode)?;
        p.decode(PrecompileTag([tag[1], tag[2], tag[3]]))
            .ok_or_else(|| SchemaError::Precompile {
                name: p.name(),
                source: Box::new(SchemaError::InvalidNode),
            })
    }

    fn reduce(&self, node: &Node, ctx: &mut dyn ReduceCtx) -> Result<Node, SchemaError> {
        let p = self.precompiles.get(&node.tag[0]).ok_or(SchemaError::InvalidNode)?;
        p.reduce(node, ctx)
            .map_err(|source| SchemaError::Precompile { name: p.name(), source: Box::new(source) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ZERO,
        deferred::{NodeType, Payload},
    };

    /// An honest minimal precompile fixture — its `id()` *is* its `precompile_id`, so it always
    /// passes the `new` validator. Distinct `name`s yield distinct ids; identical names collide
    /// (exercises the duplicate-id panic). Enough to exercise the composite's dispatch surface
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
            [self.id(), ZERO, ZERO, ZERO]
        }
    }

    impl Precompile for Fixture {
        fn name(&self) -> &'static str {
            self.name
        }
        fn id(&self) -> Felt {
            precompile_id(self)
        }
        fn decode(&self, sub: PrecompileTag) -> Option<TagInfo> {
            if sub.0 != [ZERO; 3] {
                return None;
            }
            Some(TagInfo {
                node_type: NodeType::Value,
                evaluates_to: self.tag(),
            })
        }
        fn reduce(&self, node: &Node, _ctx: &mut dyn ReduceCtx) -> Result<Node, SchemaError> {
            Ok(node.clone())
        }
    }

    #[test]
    fn dispatches_by_id() {
        let a = Fixture::new("fixture-a");
        let b = Fixture::new("fixture-b");
        let tag_a = a.tag();
        let tag_b = b.tag();
        let schema = PrecompileSchema::new([
            Box::new(a) as Box<dyn Precompile>,
            Box::new(b) as Box<dyn Precompile>,
        ])
        .unwrap();

        assert_eq!(schema.decode(tag_a).unwrap().evaluates_to, tag_a);
        assert_eq!(schema.decode(tag_b).unwrap().evaluates_to, tag_b);
    }

    #[test]
    fn unknown_id_rejected() {
        let schema = PrecompileSchema::single(Fixture::new("known")).unwrap();
        let bogus: Tag = [Felt::new_unchecked(9999), ZERO, ZERO, ZERO];
        // Unknown id is rejected by the composite itself (not a precompile), so it is *not*
        // name-wrapped.
        assert!(matches!(schema.decode(bogus), Err(SchemaError::InvalidNode)));
    }

    #[test]
    fn nonzero_tag3_rejected() {
        let f = Fixture::new("f");
        let mut tag = f.tag();
        tag[3] = Felt::new_unchecked(1);
        let schema = PrecompileSchema::single(f).unwrap();
        // The precompile rejected the sub-tag, so the composite name-wraps the cause.
        assert!(matches!(schema.decode(tag).unwrap_err().root(), SchemaError::InvalidNode));
    }

    #[test]
    fn duplicate_id_errors() {
        let err = PrecompileSchema::new([
            Box::new(Fixture::new("dup")) as Box<dyn Precompile>,
            Box::new(Fixture::new("dup")) as Box<dyn Precompile>,
        ])
        .unwrap_err();
        assert!(matches!(err, SchemaError::DuplicatePrecompileId("dup", "dup")));
    }

    #[test]
    fn reduce_dispatches_to_owning_precompile() {
        let f = Fixture::new("r");
        let tag = f.tag();
        let schema = PrecompileSchema::single(f).unwrap();
        let node = Node::expression(tag, Payload::new([ZERO; 8]));
        let mut state = DeferredState::new();
        // Use the framework's evaluate path so we exercise dispatch end-to-end.
        let canonical = state.evaluate(&schema, node.clone()).unwrap();
        assert_eq!(canonical, node);
    }
}
