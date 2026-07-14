//! Registry that routes deferred tags to their owning precompile.

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use super::precompile::{Precompile, precompile_id};
use crate::{
    Felt,
    deferred::{DeferredContext, Node, NodeType, PrecompileError, Tag},
};

/// Installed set of precompiles for deferred-node validation and evaluation.
///
/// Routing is entirely id-based. The empty registry is valid but rejects every precompile-owned
/// tag, which is useful for programs that do not use precompile-backed deferred nodes.
#[derive(Clone, Default)]
pub struct PrecompileRegistry {
    precompiles: BTreeMap<Felt, Arc<dyn Precompile>>,
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
    /// Creates an empty precompile registry.
    pub const fn new() -> Self {
        Self { precompiles: BTreeMap::new() }
    }

    /// Returns whether this registry contains no installed precompiles.
    pub fn is_empty(&self) -> bool {
        self.precompiles.is_empty()
    }

    /// Adds a precompile to the registry and returns `self` for chaining.
    ///
    /// Panics on setup errors: id drift, a framework-reserved id, or a duplicate id.
    pub fn with_precompile<P: Precompile + 'static>(mut self, precompile: P) -> Self {
        self.insert_precompile(Arc::new(precompile));
        self
    }

    /// Merges another registry into this one.
    ///
    /// Panics on duplicate ids, preserving [`Self::with_precompile`]'s setup-failure behavior.
    pub fn merge(&mut self, registry: Self) -> &mut Self {
        for precompile in registry.precompiles.into_values() {
            self.insert_precompile(precompile);
        }
        self
    }

    fn insert_precompile(&mut self, precompile: Arc<dyn Precompile>) {
        let id = precompile.id();
        validate_precompile_id(precompile.name(), id, precompile_id(precompile.name()));
        let name = precompile.name();
        if let Some(prev) = self.precompiles.get(&id) {
            panic!("duplicate precompile id in registry (`{}` and `{name}`)", prev.name());
        }
        self.precompiles.insert(id, precompile);
    }

    /// Returns all precompile initialization nodes in deterministic registry id order.
    ///
    /// [`DeferredState`](super::DeferredState) loads the full returned set before evaluating each
    /// init node, so init nodes may depend on TRUE or on any node in the complete init set. Within
    /// one precompile, nodes retain the order returned by
    /// [`Precompile::init`](super::Precompile::init).
    pub(crate) fn init_nodes(&self) -> Vec<Node> {
        let mut nodes = Vec::new();
        for precompile in self.precompiles.values() {
            nodes.extend(precompile.init());
        }
        nodes
    }

    /// Decodes a precompile-owned tag by routing its local arguments to the owning precompile.
    ///
    /// Unknown ids are registry failures; recognized ids whose arguments are invalid are
    /// attributed to the owning precompile. Framework tags are handled by the internal
    /// framework-aware decoder and rejected here. [`NodeType::True`] is reserved for the framework
    /// TRUE sentinel, so a precompile that returns it is rejected as an invalid node.
    pub fn decode_precompile_tag(&self, tag: Tag) -> Result<NodeType, PrecompileError> {
        if tag.is_framework_reserved() {
            return Err(PrecompileError::InvalidNode);
        }
        let precompile = self.precompiles.get(&tag.id()).ok_or(PrecompileError::InvalidNode)?;
        let invalid =
            || PrecompileError::with_precompile(precompile.name(), PrecompileError::InvalidNode);
        match precompile.decode(tag.args()).ok_or_else(invalid)? {
            NodeType::True => Err(invalid()),
            node_type => Ok(node_type),
        }
    }

    /// Decodes either a framework-owned tag or a precompile-owned tag.
    pub(crate) fn decode_node_type(&self, tag: Tag) -> Result<NodeType, PrecompileError> {
        if tag == Tag::TRUE {
            Ok(NodeType::True)
        } else if tag == Tag::AND {
            Ok(NodeType::Join)
        } else if tag == Tag::CHUNKS {
            Ok(NodeType::Data)
        } else {
            self.decode_precompile_tag(tag)
        }
    }

    /// Validates a node's tag and payload shape under this registry.
    pub(crate) fn validate_node(&self, node: &Node) -> Result<NodeType, PrecompileError> {
        let node_type = self.decode_node_type(node.tag())?;
        node_type.validate_node(node).map_err(|_| PrecompileError::InvalidNode)?;
        Ok(node_type)
    }

    /// Evaluates a node through the precompile selected by its tag id.
    ///
    /// Failures are wrapped with the owning precompile's name so callers can distinguish routing
    /// from precompile-local validation.
    pub(crate) fn evaluate(
        &self,
        node: &Node,
        context: &mut DeferredContext<'_>,
    ) -> Result<Node, PrecompileError> {
        let tag = node.tag();
        if tag.is_framework_reserved() {
            return Err(PrecompileError::InvalidNode);
        }
        let precompile = self.precompiles.get(&tag.id()).ok_or(PrecompileError::InvalidNode)?;
        precompile
            .evaluate(tag.args(), node.payload(), context)
            .map_err(|source| PrecompileError::with_precompile(precompile.name(), source))
    }
}

fn validate_precompile_id(name: &'static str, id: Felt, derived: Felt) {
    assert!(
        id == derived,
        "precompile `{name}` declares an id inconsistent with its name derivation"
    );
    assert!(
        !Tag::is_framework_reserved_id(id),
        "precompile `{name}` derives a framework-reserved id"
    );
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        ONE, ZERO,
        deferred::{DeferredState, Payload},
    };

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
            Tag::precompile(self.id(), [ZERO; 3]).expect("fixture id is precompile-owned")
        }
    }

    impl Precompile for Fixture {
        fn name(&self) -> &'static str {
            self.name
        }
        fn id(&self) -> Felt {
            precompile_id(self.name())
        }
        fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
            if args != [ZERO; 3] {
                return None;
            }
            Some(NodeType::Data)
        }
        fn evaluate(
            &self,
            args: [Felt; 3],
            payload: &Payload,
            _context: &mut DeferredContext<'_>,
        ) -> Result<Node, PrecompileError> {
            let chunk = payload.as_value()?;
            Ok(Node::value(
                Tag::precompile(self.id(), args).expect("fixture id is precompile-owned"),
                *chunk,
            )?)
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct MaliciousTrue;

    impl Precompile for MaliciousTrue {
        fn name(&self) -> &'static str {
            "malicious-true"
        }
        fn id(&self) -> Felt {
            precompile_id(self.name())
        }
        fn decode(&self, _args: [Felt; 3]) -> Option<NodeType> {
            Some(NodeType::True)
        }
        fn evaluate(
            &self,
            _args: [Felt; 3],
            _payload: &Payload,
            _context: &mut DeferredContext<'_>,
        ) -> Result<Node, PrecompileError> {
            unreachable!("registry must reject precompile-owned NodeType::True")
        }
    }

    #[test]
    fn dispatches_by_id_across_inserted_and_merged_registries() {
        let a = Fixture::new("fixture-a");
        let b = Fixture::new("fixture-b");
        let tag_a = a.tag();
        let tag_b = b.tag();
        let mut registry = PrecompileRegistry::default().with_precompile(a);
        registry.merge(PrecompileRegistry::default().with_precompile(b));

        assert_eq!(registry.decode_precompile_tag(tag_a).unwrap(), NodeType::Data);
        assert_eq!(registry.decode_precompile_tag(tag_b).unwrap(), NodeType::Data);
    }

    #[test]
    fn registry_decodes_exact_framework_chunks_as_data_only() {
        let registry = PrecompileRegistry::new();
        assert_eq!(registry.decode_node_type(Tag::CHUNKS).unwrap(), NodeType::Data);
        assert!(matches!(
            registry.decode_precompile_tag(Tag::CHUNKS),
            Err(PrecompileError::InvalidNode)
        ));

        let malformed = Tag::from_word([Tag::CHUNKS.id(), ONE, ZERO, ZERO]);
        assert!(matches!(
            registry.decode_node_type(malformed),
            Err(PrecompileError::InvalidNode)
        ));
    }

    #[test]
    fn registry_rejects_precompile_owned_true_shape() {
        let registry = PrecompileRegistry::default().with_precompile(MaliciousTrue);
        let tag =
            Tag::precompile(MaliciousTrue.id(), [ZERO; 3]).expect("test id is precompile-owned");
        assert!(matches!(
            registry.decode_precompile_tag(tag),
            Err(PrecompileError::Precompile { .. })
        ));
        assert!(matches!(
            registry.decode_precompile_tag(tag).unwrap_err().root(),
            PrecompileError::InvalidNode
        ));
    }

    #[test]
    fn unknown_id_rejected() {
        let registry = PrecompileRegistry::default().with_precompile(Fixture::new("known"));
        let bogus = Tag::precompile(Felt::new_unchecked(9999), [ZERO; 3])
            .expect("bogus id is not framework-reserved");
        // Unknown id is rejected by the registry itself (not a precompile), so it is *not*
        // name-wrapped.
        assert!(matches!(
            registry.decode_precompile_tag(bogus),
            Err(PrecompileError::InvalidNode)
        ));
    }

    #[test]
    fn fixture_rejects_nonzero_immediate() {
        let f = Fixture::new("f");
        let tag = Tag::precompile(f.id(), [ZERO, ZERO, Felt::new_unchecked(1)])
            .expect("fixture id is precompile-owned");
        let registry = PrecompileRegistry::default().with_precompile(f);
        // The fixture chose to reject the immediate, so the registry name-wraps the cause.
        assert!(matches!(
            registry.decode_precompile_tag(tag).unwrap_err().root(),
            PrecompileError::InvalidNode
        ));
    }

    #[test]
    #[should_panic(expected = "framework-reserved id")]
    fn true_id_is_reserved_for_framework() {
        validate_precompile_id("reserved-true", Tag::TRUE.id(), Tag::TRUE.id());
    }

    #[test]
    #[should_panic(expected = "framework-reserved id")]
    fn and_id_is_reserved_for_framework() {
        validate_precompile_id("reserved-and", Tag::AND.id(), Tag::AND.id());
    }

    #[test]
    #[should_panic(expected = "framework-reserved id")]
    fn chunks_id_is_reserved_for_framework() {
        validate_precompile_id("reserved-chunks", Tag::CHUNKS.id(), Tag::CHUNKS.id());
    }

    #[test]
    #[should_panic(expected = "duplicate precompile id in registry")]
    fn duplicate_id_panics() {
        let _ = PrecompileRegistry::default()
            .with_precompile(Fixture::new("dup"))
            .with_precompile(Fixture::new("dup"));
    }

    #[test]
    fn evaluate_dispatches_to_owning_precompile() {
        let f = Fixture::new("r");
        let tag = f.tag();
        let registry = Arc::new(PrecompileRegistry::default().with_precompile(f));
        let node = Node::value(tag, [ZERO; 8]).unwrap();
        let mut state = DeferredState::new(Arc::clone(&registry), usize::MAX).unwrap();
        // Use the framework's evaluation path so we exercise dispatch end-to-end.
        let digest = state.register(node.clone()).unwrap();
        let (canonical_digest, canonical_node) = state.require_canonical_node(digest).unwrap();
        assert_eq!(canonical_digest, node.digest());
        assert_eq!(canonical_node, &node);
    }
}
