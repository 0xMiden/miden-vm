//! The composite [`PrecompileSchema`] — a [`Schema`] built from a set of [`Precompile`]s.

use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

use crate::{
    Felt, ZERO,
    deferred::{DeferredState, Node, ReduceCtx, Schema, SchemaError, Tag, TagInfo},
};

use super::precompile::{Precompile, PrecompileTag, precompile_id};

/// A [`Schema`] that dispatches each tag to a [`Precompile`] selected by `tag[0]` (its id).
///
/// Precompiles are held in a `BTreeMap<id, Box<dyn Precompile>>`. Order is irrelevant — the id
/// is the only thing that decides routing.
#[derive(Debug)]
pub struct PrecompileSchema {
    precompiles: BTreeMap<Felt, Box<dyn Precompile>>,
}

impl PrecompileSchema {
    /// Build a composite from any iterable of boxed precompiles. Panics if a precompile's
    /// declared [`Precompile::id`] doesn't match its [`precompile_id`] derivation (a programming
    /// error — the pinned id drifted), or if two precompiles report the same id.
    pub fn new<I>(precompiles: I) -> Self
    where
        I: IntoIterator<Item = Box<dyn Precompile>>,
    {
        let mut map: BTreeMap<Felt, Box<dyn Precompile>> = BTreeMap::new();
        for p in precompiles {
            let id = p.id();
            let derived = precompile_id(&*p);
            if id != derived {
                panic!(
                    "precompile id mismatch: {} declares {id:?} but derives {derived:?}",
                    p.name()
                );
            }
            if map.insert(id, p).is_some() {
                panic!("duplicate precompile id in PrecompileSchema");
            }
        }
        Self { precompiles: map }
    }

    /// Convenience constructor for a single-precompile schema (common in tests).
    pub fn single<P: Precompile + 'static>(precompile: P) -> Self {
        Self::new([Box::new(precompile) as Box<dyn Precompile>])
    }

    /// Pre-register every precompile's canonical constants into `state` via [`Precompile::init`].
    /// Caller is responsible for invoking this — it is not implicit in [`Self::new`] because
    /// callers may want to attach the schema before building the state, or to skip booting in
    /// tests where determinism of node counts matters.
    pub fn boot(&self, state: &mut DeferredState) {
        for p in self.precompiles.values() {
            p.init(state);
        }
    }

    /// Returns the ids present in this composite, in `BTreeMap` order. Mainly for tests and
    /// diagnostics.
    pub fn app_ids(&self) -> Vec<Felt> {
        self.precompiles.keys().copied().collect()
    }
}

impl Schema for PrecompileSchema {
    fn decode(&self, tag: Tag) -> Result<TagInfo, SchemaError> {
        if tag[3] != ZERO {
            return Err(SchemaError::InvalidNode);
        }
        let p = self.precompiles.get(&tag[0]).ok_or(SchemaError::InvalidNode)?;
        p.decode(PrecompileTag { node_disc: tag[1], imm: tag[2] })
    }

    fn reduce(&self, node: &Node, ctx: &mut dyn ReduceCtx) -> Result<Node, SchemaError> {
        let p = self.precompiles.get(&node.tag[0]).ok_or(SchemaError::InvalidNode)?;
        p.reduce(node, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deferred::{NodeType, Payload};

    /// An honest minimal precompile fixture — its `id()` *is* its `precompile_id`, so it always
    /// passes the `new` validator. Distinct `name`s yield distinct ids; identical names collide
    /// (exercises the duplicate-id panic). Enough to exercise the composite's dispatch surface
    /// without depending on a reference app.
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
        fn version(&self) -> u32 {
            1
        }
        fn id(&self) -> Felt {
            precompile_id(self)
        }
        fn decode(&self, local: PrecompileTag) -> Result<TagInfo, SchemaError> {
            if local.imm != ZERO || local.node_disc != ZERO {
                return Err(SchemaError::InvalidNode);
            }
            Ok(TagInfo {
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
        ]);

        assert_eq!(schema.decode(tag_a).unwrap().evaluates_to, tag_a);
        assert_eq!(schema.decode(tag_b).unwrap().evaluates_to, tag_b);
    }

    #[test]
    fn unknown_id_rejected() {
        let schema = PrecompileSchema::single(Fixture::new("known"));
        let bogus: Tag = [Felt::new_unchecked(9999), ZERO, ZERO, ZERO];
        assert!(matches!(schema.decode(bogus), Err(SchemaError::InvalidNode)));
    }

    #[test]
    fn nonzero_tag3_rejected() {
        let f = Fixture::new("f");
        let mut tag = f.tag();
        tag[3] = Felt::new_unchecked(1);
        let schema = PrecompileSchema::single(f);
        assert!(matches!(schema.decode(tag), Err(SchemaError::InvalidNode)));
    }

    #[test]
    #[should_panic(expected = "duplicate precompile id")]
    fn duplicate_id_panics() {
        let _ = PrecompileSchema::new([
            Box::new(Fixture::new("dup")) as Box<dyn Precompile>,
            Box::new(Fixture::new("dup")) as Box<dyn Precompile>,
        ]);
    }

    #[test]
    fn reduce_dispatches_to_owning_precompile() {
        let f = Fixture::new("r");
        let tag = f.tag();
        let schema = PrecompileSchema::single(f);
        let node = Node::expression(tag, Payload::new([ZERO; 8]));
        let mut state = DeferredState::new();
        // Use the framework's evaluate path so we exercise dispatch end-to-end.
        let canonical = state.evaluate(&schema, node.clone()).unwrap();
        assert_eq!(canonical, node);
    }
}
