//! Registry that routes deferred tags to their owning precompile.

use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

use super::precompile::{Precompile, precompile_id};
use crate::{
    Felt, ZERO,
    deferred::{
        DeferredError, DeferredState, Digest, Node, NodeType, PrecompileError, Tag, WitnessBuilder,
    },
};

/// Installed set of precompiles for deferred-node validation and reduction.
///
/// Routing is entirely id-based. The empty registry is valid but rejects every precompile-owned
/// tag, which is useful for programs that do not use deferred precompiles.
#[derive(Default)]
pub struct PrecompileRegistry {
    precompiles: BTreeMap<Felt, Box<dyn Precompile>>,
}

impl core::fmt::Debug for PrecompileRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrecompileRegistry")
            .field(
                "precompiles",
                &self.precompiles.iter().map(|(id, p)| (id, p.name())).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl PrecompileRegistry {
    /// Adds a precompile to the registry and returns `self` for chaining.
    ///
    /// Panics on setup errors: id drift, the framework-reserved `ZERO` id, or a duplicate id.
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

    /// Boots a state with constants contributed by installed precompiles.
    ///
    /// This is explicit so callers can choose when constants affect node counts. A digest
    /// collision between different precompiles is rejected as ambiguous ownership.
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

    /// Decodes a tag by routing its local arguments to the owning precompile.
    ///
    /// Unknown ids are registry failures; recognized ids whose arguments are invalid are
    /// attributed to the owning precompile.
    pub fn decode(&self, tag: Tag) -> Result<NodeType, PrecompileError> {
        let p = self.precompiles.get(&tag.id).ok_or(PrecompileError::InvalidNode)?;
        p.decode(tag.args).ok_or_else(|| PrecompileError::Precompile {
            name: p.name(),
            source: Box::new(PrecompileError::InvalidNode),
        })
    }

    /// Reduces a node through the precompile selected by its tag id.
    ///
    /// Failures are wrapped with the owning precompile's name so callers can distinguish routing
    /// from precompile-local validation.
    pub fn reduce(
        &self,
        node: &Node,
        witness: &mut WitnessBuilder<'_>,
    ) -> Result<Node, PrecompileError> {
        let p = self.precompiles.get(&node.tag.id).ok_or(PrecompileError::InvalidNode)?;
        p.reduce(node.tag.args, &node.payload, witness).map_err(|source| {
            PrecompileError::Precompile { name: p.name(), source: Box::new(source) }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deferred::Payload;

    /// Minimal honest precompile fixture for registry-routing tests.
    ///
    /// Names control ids, so duplicate names exercise duplicate-id handling. Non-zero arguments
    /// are rejected by the fixture, not by the framework.
    #[derive(Debug, Clone, Copy)]
    struct Fixture {
        name: &'static str,
    }

    impl Fixture {
        fn new(name: &'static str) -> Self {
            Self { name }
        }
        fn tag(&self) -> Tag {
            Tag { id: self.id(), args: [ZERO; 3] }
        }
    }

    impl Precompile for Fixture {
        fn name(&self) -> &'static str {
            self.name
        }
        fn id(&self) -> Felt {
            precompile_id(self)
        }
        fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
            if args != [ZERO; 3] {
                return None;
            }
            Some(NodeType::Value)
        }
        fn reduce(
            &self,
            args: [Felt; 3],
            payload: &Payload,
            _witness: &mut WitnessBuilder<'_>,
        ) -> Result<Node, PrecompileError> {
            let felts = payload.as_felts()?;
            Ok(Node::leaf(Tag::new(self.id(), args), *felts))
        }
    }

    #[test]
    fn dispatches_by_id() {
        let a = Fixture::new("fixture-a");
        let b = Fixture::new("fixture-b");
        let tag_a = a.tag();
        let tag_b = b.tag();
        let registry = PrecompileRegistry::default().with_precompile(a).with_precompile(b);

        assert!(matches!(registry.decode(tag_a).unwrap(), NodeType::Value));
        assert!(matches!(registry.decode(tag_b).unwrap(), NodeType::Value));
    }

    #[test]
    fn unknown_id_rejected() {
        let registry = PrecompileRegistry::default().with_precompile(Fixture::new("known"));
        let bogus = Tag {
            id: Felt::new_unchecked(9999),
            args: [ZERO; 3],
        };
        // Unknown id is rejected by the registry itself (not a precompile), so it is *not*
        // name-wrapped.
        assert!(matches!(registry.decode(bogus), Err(PrecompileError::InvalidNode)));
    }

    #[test]
    fn fixture_rejects_nonzero_immediate() {
        let f = Fixture::new("f");
        let mut tag = f.tag();
        tag.args[2] = Felt::new_unchecked(1);
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
        let node = Node::leaf(tag, [ZERO; 8]);
        let mut state = DeferredState::new();
        // Use the framework's evaluate path so we exercise dispatch end-to-end.
        let canonical = state.evaluate_node(&registry, node.clone()).unwrap();
        assert_eq!(canonical, node);
    }
}
