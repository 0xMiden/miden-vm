//! The [`PrecompileRegistry`] — dispatches each deferred [`Tag`] to a [`Precompile`].

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
/// Build it with [`Default`] + [`with_precompile`](Self::with_precompile); the default empty
/// registry rejects every tag (the processor's out-of-the-box state).
#[derive(Debug, Default)]
pub struct PrecompileRegistry {
    precompiles: BTreeMap<Felt, Box<dyn Precompile>>,
}

impl PrecompileRegistry {
    /// Add a precompile, returning `self` for chaining
    /// (`PrecompileRegistry::default().with_precompile(a).with_precompile(b)`).
    ///
    /// Panics if the precompile is misconfigured: its declared [`Precompile::id`] is
    /// inconsistent with the [`precompile_id`] derivation, it derives the framework-reserved
    /// `ZERO` id, or its id is already present. These are setup-time programming errors, not
    /// runtime conditions — there is intentionally no fallible constructor.
    pub fn with_precompile<P: Precompile + 'static>(mut self, precompile: P) -> Self {
        let p: Box<dyn Precompile> = Box::new(precompile);
        let id = p.id();
        assert!(
            id == precompile_id(&*p),
            "precompile `{}` declares an id inconsistent with its name derivation",
            p.name()
        );
        // `id == precompile_id` here, so a `ZERO` id means the derivation itself produced the
        // framework-reserved value (a ~2^-64 event). `ZERO` tags the TRUE / AND nodes and must
        // never route to a precompile.
        assert!(id != ZERO, "precompile `{}` derives the framework-reserved id ZERO", p.name());
        let name = p.name();
        if let Some(prev) = self.precompiles.insert(id, p) {
            panic!("duplicate precompile id in registry (`{}` and `{name}`)", prev.name());
        }
        self
    }

    /// Collect every precompile's canonical constant leaves ([`Precompile::init`]) and intern
    /// them into `state`. Errors with [`DeferredError::ConflictingNode`] if two *different*
    /// precompiles contribute the same node digest (ambiguous canonical-leaf ownership).
    ///
    /// Caller is responsible for invoking this — it is not implicit in the builder because
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

    /// Reduce `node` via the precompile owning its [`Tag::id`](crate::deferred::Tag). The
    /// registry is the adapter: it hands the precompile only `node.tag.imm` and `node.payload`
    /// (the precompile never re-checks the id), and name-wraps the precompile's failure so
    /// dispatch errors are attributable. See [`Precompile::reduce`] for the per-kind contract.
    pub fn reduce(
        &self,
        node: &Node,
        witness: &mut WitnessBuilder<'_>,
    ) -> Result<Node, PrecompileError> {
        let p = self.precompiles.get(&node.tag.id).ok_or(PrecompileError::InvalidNode)?;
        p.reduce(node.tag.imm, &node.payload, witness).map_err(|source| {
            PrecompileError::Precompile { name: p.name(), source: Box::new(source) }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deferred::{NodeType, Payload};

    /// An honest minimal precompile fixture — its `id()` *is* its `precompile_id`, so it always
    /// passes the builder validator. Distinct `name`s yield distinct ids; identical names
    /// collide (exercises the duplicate-id panic). It *chooses* to reject any non-zero
    /// immediate — a fixture's own decision, not a framework rule.
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
            imm: [Felt; 3],
            payload: &Payload,
            _witness: &mut WitnessBuilder<'_>,
        ) -> Result<Node, PrecompileError> {
            let felts = payload.as_felts()?;
            Ok(Node::expression(Tag::new(self.id(), imm), Payload::new(*felts)))
        }
    }

    #[test]
    fn dispatches_by_id() {
        let a = Fixture::new("fixture-a");
        let b = Fixture::new("fixture-b");
        let tag_a = a.tag();
        let tag_b = b.tag();
        let registry = PrecompileRegistry::default().with_precompile(a).with_precompile(b);

        assert_eq!(registry.decode(tag_a).unwrap().evaluates_to, tag_a);
        assert_eq!(registry.decode(tag_b).unwrap().evaluates_to, tag_b);
    }

    #[test]
    fn unknown_id_rejected() {
        let registry = PrecompileRegistry::default().with_precompile(Fixture::new("known"));
        let bogus = Tag {
            id: Felt::new_unchecked(9999),
            imm: [ZERO; 3],
        };
        // Unknown id is rejected by the registry itself (not a precompile), so it is *not*
        // name-wrapped.
        assert!(matches!(registry.decode(bogus), Err(PrecompileError::InvalidNode)));
    }

    #[test]
    fn fixture_rejects_nonzero_immediate() {
        let f = Fixture::new("f");
        let mut tag = f.tag();
        tag.imm[2] = Felt::new_unchecked(1);
        let registry = PrecompileRegistry::default().with_precompile(f);
        // The fixture chose to reject the immediate, so the registry name-wraps the cause.
        assert!(matches!(registry.decode(tag).unwrap_err().root(), PrecompileError::InvalidNode));
    }

    #[test]
    #[should_panic(expected = "duplicate precompile id in registry")]
    fn duplicate_id_panics() {
        let _ = PrecompileRegistry::default()
            .with_precompile(Fixture::new("dup"))
            .with_precompile(Fixture::new("dup"));
    }

    #[test]
    fn reduce_dispatches_to_owning_precompile() {
        let f = Fixture::new("r");
        let tag = f.tag();
        let registry = PrecompileRegistry::default().with_precompile(f);
        let node = Node::expression(tag, Payload::new([ZERO; 8]));
        let mut state = DeferredState::new();
        // Use the framework's evaluate path so we exercise dispatch end-to-end.
        let canonical = state.evaluate(&registry, node.clone()).unwrap();
        assert_eq!(canonical, node);
    }
}
