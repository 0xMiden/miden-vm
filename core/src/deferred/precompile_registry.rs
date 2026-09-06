//! Registry that routes deferred frames to their owning precompile.

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use miden_crypto::hash::eidos::{DomainTag, EidosDomain, EidosFrame, namespace};

use super::precompile::Precompile;
use crate::{
    deferred::{DEFERRED_AND_FRAME, DeferredContext, Node, NodeType, PrecompileError},
    program::domain::{DeferredChunksDomain, is_vm_precompile_domain},
};

/// Installed set of precompiles for deferred-node validation and evaluation.
///
/// Routing is entirely domain-based. The empty registry is valid but rejects every
/// precompile-owned frame, which is useful for programs that do not use precompile-backed deferred
/// nodes.
#[derive(Clone, Default)]
pub struct PrecompileRegistry {
    precompiles: BTreeMap<DomainTag, Arc<dyn Precompile>>,
}

impl core::fmt::Debug for PrecompileRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrecompileRegistry")
            .field(
                "precompiles",
                &self
                    .precompiles
                    .iter()
                    .map(|(domain, p)| (domain, p.name()))
                    .collect::<Vec<_>>(),
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
    /// Panics if the domain tag is invalid, belongs to `miden-crypto`, is allocated to another VM
    /// construction, or is already registered.
    pub fn with_precompile<P: Precompile + 'static>(mut self, precompile: P) -> Self {
        self.insert_precompile(Arc::new(precompile));
        self
    }

    /// Merges another registry into this one.
    ///
    /// Panics on duplicate domains, preserving [`Self::with_precompile`]'s setup-failure behavior.
    pub fn merge(&mut self, registry: Self) -> &mut Self {
        for precompile in registry.precompiles.into_values() {
            self.insert_precompile(precompile);
        }
        self
    }

    fn insert_precompile(&mut self, precompile: Arc<dyn Precompile>) {
        let domain = precompile.domain();
        validate_precompile_domain(precompile.name(), domain);
        let name = precompile.name();
        if let Some(prev) = self.precompiles.get(&domain) {
            panic!("duplicate precompile domain in registry (`{}` and `{name}`)", prev.name());
        }
        self.precompiles.insert(domain, precompile);
    }

    /// Returns all precompile initialization nodes in deterministic domain-tag order.
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

    /// Decodes a precompile-owned frame by routing its parameters to the owning precompile.
    ///
    /// Unknown domains are registry failures; recognized domains whose parameters are invalid are
    /// attributed to the owning precompile. Framework frames are handled by the internal decoder
    /// and rejected here. [`NodeType::True`] is reserved for the framework
    /// TRUE sentinel, so a precompile that returns it is rejected as an invalid node.
    pub fn decode_precompile_frame(&self, frame: EidosFrame) -> Result<NodeType, PrecompileError> {
        if is_framework_domain(frame.domain()) {
            return Err(PrecompileError::InvalidNode);
        }
        let precompile =
            self.precompiles.get(&frame.domain()).ok_or(PrecompileError::InvalidNode)?;
        let invalid =
            || PrecompileError::with_precompile(precompile.name(), PrecompileError::InvalidNode);
        match precompile.decode(frame.params()).ok_or_else(invalid)? {
            NodeType::True => Err(invalid()),
            node_type => Ok(node_type),
        }
    }

    /// Decodes either a framework-owned frame or a precompile-owned frame.
    pub(crate) fn decode_node_type(&self, frame: EidosFrame) -> Result<NodeType, PrecompileError> {
        if frame == DEFERRED_AND_FRAME {
            Ok(NodeType::Join)
        } else if frame.domain() == DeferredChunksDomain::TAG
            && matches!(frame.params(), [n_felts, 0, 0] if n_felts != 0 && n_felts % 8 == 0)
        {
            Ok(NodeType::Data)
        } else {
            self.decode_precompile_frame(frame)
        }
    }

    /// Validates a node's frame and payload shape under this registry.
    pub(crate) fn validate_node(&self, node: &Node) -> Result<NodeType, PrecompileError> {
        if node.is_true() {
            return Ok(NodeType::True);
        }
        let frame = node.frame().ok_or(PrecompileError::InvalidNode)?;
        let node_type = self.decode_node_type(frame)?;
        node_type.validate_node(node).map_err(|_| PrecompileError::InvalidNode)?;

        if frame.domain() == DeferredChunksDomain::TAG {
            let [n_felts, 0, 0] = frame.params() else {
                return Err(PrecompileError::InvalidNode);
            };
            if node.payload().as_chunks().len().checked_mul(8) != Some(n_felts as usize) {
                return Err(PrecompileError::InvalidNode);
            }
        } else if frame != DEFERRED_AND_FRAME {
            let precompile =
                self.precompiles.get(&frame.domain()).ok_or(PrecompileError::InvalidNode)?;
            if !precompile.validate_payload(frame.params(), node.payload()) {
                return Err(PrecompileError::with_precompile(
                    precompile.name(),
                    PrecompileError::InvalidNode,
                ));
            }
        }
        Ok(node_type)
    }

    /// Evaluates a node through the precompile selected by its domain tag.
    ///
    /// Failures are wrapped with the owning precompile's name so callers can distinguish routing
    /// from precompile-local validation.
    pub(crate) fn evaluate(
        &self,
        node: &Node,
        context: &mut DeferredContext<'_>,
    ) -> Result<Node, PrecompileError> {
        let frame = node.frame().ok_or(PrecompileError::InvalidNode)?;
        if is_framework_domain(frame.domain()) {
            return Err(PrecompileError::InvalidNode);
        }
        let precompile =
            self.precompiles.get(&frame.domain()).ok_or(PrecompileError::InvalidNode)?;
        precompile
            .evaluate(frame.params(), node.payload(), context)
            .map_err(|source| PrecompileError::with_precompile(precompile.name(), source))
    }
}

fn is_framework_domain(domain: DomainTag) -> bool {
    domain == DEFERRED_AND_FRAME.domain() || domain == DeferredChunksDomain::TAG
}

fn validate_precompile_domain(name: &'static str, domain: DomainTag) {
    assert!(
        domain.namespace() != namespace::MIDEN_CRYPTO,
        "precompile `{name}` uses a miden-crypto domain tag"
    );
    assert!(
        domain.namespace() != namespace::MIDEN_VM || is_vm_precompile_domain(domain),
        "precompile `{name}` uses an unallocated miden-vm domain tag"
    );
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        ZERO,
        deferred::{
            DeferredState, Payload, deferred_chunks_frame, precompile::test_precompile_domain_tag,
        },
        program::domain::MidenVmDomainRegistry,
    };

    /// Minimal honest precompile fixture for registry-routing tests.
    ///
    /// Domains control routing. Non-zero parameters are rejected by the fixture, not the framework.
    #[derive(Debug, Clone, Copy)]
    struct Fixture {
        name: &'static str,
        domain: DomainTag,
    }

    impl Fixture {
        fn new(name: &'static str, discriminant: u8) -> Self {
            Self {
                name,
                domain: test_precompile_domain_tag(discriminant),
            }
        }

        fn frame(&self, params: [u32; 3]) -> EidosFrame {
            EidosFrame::new(self.domain, params)
        }
    }

    impl Precompile for Fixture {
        fn name(&self) -> &'static str {
            self.name
        }
        fn domain(&self) -> DomainTag {
            self.domain
        }
        fn decode(&self, params: [u32; 3]) -> Option<NodeType> {
            if params != [0; 3] {
                return None;
            }
            Some(NodeType::Data)
        }
        fn evaluate(
            &self,
            params: [u32; 3],
            payload: &Payload,
            _context: &mut DeferredContext<'_>,
        ) -> Result<Node, PrecompileError> {
            let chunk = payload.as_value()?;
            Ok(Node::value(self.frame(params), *chunk)?)
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct MaliciousTrue;

    impl Precompile for MaliciousTrue {
        fn name(&self) -> &'static str {
            "malicious-true"
        }
        fn domain(&self) -> DomainTag {
            test_precompile_domain_tag(6)
        }
        fn decode(&self, _params: [u32; 3]) -> Option<NodeType> {
            Some(NodeType::True)
        }
        fn evaluate(
            &self,
            _params: [u32; 3],
            _payload: &Payload,
            _context: &mut DeferredContext<'_>,
        ) -> Result<Node, PrecompileError> {
            unreachable!("registry must reject precompile-owned NodeType::True")
        }
    }

    #[test]
    fn dispatches_by_domain_across_inserted_and_merged_registries() {
        let a = Fixture::new("fixture-a", 4);
        let b = Fixture::new("fixture-b", 5);
        let frame_a = a.frame([0; 3]);
        let frame_b = b.frame([0; 3]);
        let mut registry = PrecompileRegistry::default().with_precompile(a);
        registry.merge(PrecompileRegistry::default().with_precompile(b));

        assert_eq!(registry.decode_precompile_frame(frame_a).unwrap(), NodeType::Data);
        assert_eq!(registry.decode_precompile_frame(frame_b).unwrap(), NodeType::Data);
    }

    #[test]
    fn registry_decodes_only_well_formed_framework_chunks() {
        let registry = PrecompileRegistry::new();
        let frame = deferred_chunks_frame(1);
        assert_eq!(registry.decode_node_type(frame).unwrap(), NodeType::Data);
        assert!(matches!(
            registry.decode_precompile_frame(frame),
            Err(PrecompileError::InvalidNode)
        ));

        for malformed in [
            EidosFrame::new(DeferredChunksDomain::TAG, [0, 0, 0]),
            EidosFrame::new(DeferredChunksDomain::TAG, [1, 0, 0]),
            EidosFrame::new(DeferredChunksDomain::TAG, [1, 1, 0]),
        ] {
            assert!(matches!(
                registry.decode_node_type(malformed),
                Err(PrecompileError::InvalidNode)
            ));
        }
    }

    #[test]
    fn registry_rejects_precompile_owned_true_shape() {
        let registry = PrecompileRegistry::default().with_precompile(MaliciousTrue);
        let frame = EidosFrame::new(MaliciousTrue.domain(), [0; 3]);
        assert!(matches!(
            registry.decode_precompile_frame(frame),
            Err(PrecompileError::Precompile { .. })
        ));
        assert!(matches!(
            registry.decode_precompile_frame(frame).unwrap_err().root(),
            PrecompileError::InvalidNode
        ));
    }

    #[test]
    fn unknown_domain_rejected() {
        let registry = PrecompileRegistry::default().with_precompile(Fixture::new("known", 7));
        let bogus = EidosFrame::new(test_precompile_domain_tag(8), [0; 3]);
        // An unknown domain is rejected by the registry itself, so it is not
        // name-wrapped.
        assert!(matches!(
            registry.decode_precompile_frame(bogus),
            Err(PrecompileError::InvalidNode)
        ));
    }

    #[test]
    fn fixture_rejects_nonzero_parameter() {
        let f = Fixture::new("f", 8);
        let frame = f.frame([1, 0, 0]);
        let registry = PrecompileRegistry::default().with_precompile(f);
        // The fixture chose to reject the parameter, so the registry name-wraps the cause.
        assert!(matches!(
            registry.decode_precompile_frame(frame).unwrap_err().root(),
            PrecompileError::InvalidNode
        ));
    }

    #[test]
    fn framework_domains_are_not_precompile_domains() {
        for domain in [DEFERRED_AND_FRAME.domain(), DeferredChunksDomain::TAG] {
            let result = std::panic::catch_unwind(|| {
                validate_precompile_domain("framework-domain", domain);
            });
            assert!(result.is_err(), "framework domain {domain} was accepted");
        }
    }

    #[test]
    #[should_panic(expected = "miden-crypto domain tag")]
    fn crypto_domain_tag_is_rejected() {
        validate_precompile_domain(
            "crypto-domain",
            miden_crypto::hash::eidos::domains::SmtBucketLeafDomain::TAG,
        );
    }

    #[test]
    fn domain_tags_allocated_to_other_vm_constructions_are_rejected() {
        for domain in MidenVmDomainRegistry::domains()
            .iter()
            .filter(|domain| !is_vm_precompile_domain(domain.tag))
        {
            let result = std::panic::catch_unwind(|| {
                validate_precompile_domain("conflicting-domain", domain.tag);
            });
            assert!(result.is_err(), "domain tag {} was accepted", domain.tag);
        }
    }

    #[test]
    #[should_panic(expected = "duplicate precompile domain in registry")]
    fn duplicate_domain_panics() {
        let _ = PrecompileRegistry::default()
            .with_precompile(Fixture::new("dup-a", 9))
            .with_precompile(Fixture::new("dup-b", 9));
    }

    #[test]
    fn evaluate_dispatches_to_owning_precompile() {
        let f = Fixture::new("r", 10);
        let frame = f.frame([0; 3]);
        let registry = Arc::new(PrecompileRegistry::default().with_precompile(f));
        let node = Node::value(frame, [ZERO; 8]).unwrap();
        let mut state = DeferredState::new(Arc::clone(&registry)).unwrap();
        // Use the framework's evaluation path so we exercise dispatch end-to-end.
        let digest = state.register(node.clone()).unwrap();
        let (canonical_digest, canonical_node) = state.require_canonical_node(digest).unwrap();
        assert_eq!(canonical_digest, node.digest());
        assert_eq!(canonical_node, &node);
    }
}
