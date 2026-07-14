//! Precompile for fixed 256-bit uint arithmetic domains in the deferred framework.

use alloc::vec::Vec;

use miden_core::{
    Felt, ZERO,
    deferred::{
        DeferredContext, DeferredError, Digest, Node, NodeType, Payload, Precompile,
        PrecompileError, Tag, precompile_id,
    },
};

use super::{Limbs, ONE_LIMBS, TWO_LIMBS, UintDomain, ZERO_LIMBS};

/// Recognized uint binary operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UintBinaryOp {
    Add,
    Sub,
    Mul,
}

/// Structural view of a uint precompile node.
///
/// Operation variants expose only the structural child digests in the node payload. Value variants
/// expose the canonical domain and limbs after the same payload checks used by evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UintNodeRef {
    /// Canonical uint value.
    Value { domain: UintDomain, limbs: Limbs },
    /// Addition over two structural child digests.
    Add { lhs: Digest, rhs: Digest },
    /// Subtraction over two structural child digests.
    Sub { lhs: Digest, rhs: Digest },
    /// Multiplication over two structural child digests.
    Mul { lhs: Digest, rhs: Digest },
    /// Equality assertion over two structural child digests.
    Eq { lhs: Digest, rhs: Digest },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UintOp {
    Value(UintDomain),
    Binary(UintBinaryOp),
    Eq,
}

impl UintOp {
    fn decode(args: [Felt; 3]) -> Option<Self> {
        match args[0].as_canonical_u64() {
            UintPrecompile::VALUE_OP_ID if args[2] == ZERO => {
                Some(Self::Value(domain_from_bound_ptr_arg(args[1])?))
            },
            UintPrecompile::ADD_OP_ID if args[1] == ZERO && args[2] == ZERO => {
                Some(Self::Binary(UintBinaryOp::Add))
            },
            UintPrecompile::SUB_OP_ID if args[1] == ZERO && args[2] == ZERO => {
                Some(Self::Binary(UintBinaryOp::Sub))
            },
            UintPrecompile::MUL_OP_ID if args[1] == ZERO && args[2] == ZERO => {
                Some(Self::Binary(UintBinaryOp::Mul))
            },
            UintPrecompile::EQ_OP_ID if args[1] == ZERO && args[2] == ZERO => Some(Self::Eq),
            _ => None,
        }
    }

    const fn node_type(self) -> NodeType {
        match self {
            Self::Value(_) => NodeType::Data,
            Self::Binary(_) | Self::Eq => NodeType::Join,
        }
    }
}

fn domain_from_bound_ptr_arg(bound_ptr: Felt) -> Option<UintDomain> {
    let ptr = bound_ptr.as_canonical_u64();
    if ptr > u32::MAX as u64 {
        return None;
    }
    UintDomain::from_bound_ptr(ptr as u32)
}

enum UintNode {
    Value {
        domain: UintDomain,
        limbs: Limbs,
    },
    BinaryOp {
        op: UintBinaryOp,
        lhs: Digest,
        rhs: Digest,
    },
    Eq {
        lhs: Digest,
        rhs: Digest,
    },
}

impl UintNode {
    fn parse(op: UintOp, payload: &Payload) -> Result<Self, PrecompileError> {
        Ok(match op {
            UintOp::Value(domain) => {
                let limbs = decode_limbs(payload.as_value()?)?;
                if !domain.is_canonical(&limbs) {
                    return Err(DeferredError::InvalidPayload.into());
                }
                Self::Value { domain, limbs }
            },
            UintOp::Binary(op) => {
                let (lhs, rhs) = payload.as_join()?;
                Self::BinaryOp { op, lhs, rhs }
            },
            UintOp::Eq => {
                let (lhs, rhs) = payload.as_join()?;
                Self::Eq { lhs, rhs }
            },
        })
    }
}

/// Precompile for 256-bit arithmetic over fixed uint domains.
#[derive(Clone, Copy, Debug, Default)]
pub struct UintPrecompile;

impl UintPrecompile {
    /// Stable precompile name used to derive this precompile's tag id.
    pub const NAME: &'static str = "uint256";

    /// Operation discriminants owned by this precompile.
    pub const VALUE_OP_ID: u64 = 0;
    pub const ADD_OP_ID: u64 = 1;
    pub const SUB_OP_ID: u64 = 2;
    pub const MUL_OP_ID: u64 = 3;
    pub const EQ_OP_ID: u64 = 4;

    /// Stable precompile id derived from [`Self::NAME`].
    pub fn id() -> Felt {
        precompile_id(Self::NAME)
    }

    /// Builds a canonical uint `VALUE` tag for `domain`.
    pub fn value_tag(domain: UintDomain) -> Tag {
        let op_id = Felt::new(Self::VALUE_OP_ID).expect("uint VALUE op id must fit in a felt");
        Tag::precompile(Self::id(), [op_id, Felt::from(domain.bound_ptr()), ZERO])
            .expect("uint precompile id is not framework-reserved")
    }

    /// Builds a uint operation tag from `op_id`.
    ///
    /// Known operation ids decode to their declared shapes; unknown ids produce a tag that this
    /// precompile rejects. Operand `VALUE` nodes carry the concrete domain.
    pub fn op_tag(op_id: u64) -> Tag {
        let op_id = Felt::new(op_id).expect("uint op id must fit in a felt");
        Tag::precompile(Self::id(), [op_id, ZERO, ZERO])
            .expect("uint precompile id is not framework-reserved")
    }

    /// Builds a uint `VALUE` node from trusted canonical limbs.
    ///
    /// Callers must ensure `limbs` is canonical for `domain`. Debug builds assert this
    /// precondition; registration and evaluation validate nodes constructed from untrusted
    /// limbs.
    pub fn value_node(domain: UintDomain, limbs: Limbs) -> Node {
        debug_assert!(domain.is_canonical(&limbs));
        Node::value(Self::value_tag(domain), limbs.map(Felt::from_u32))
            .expect("value tag is precompile-owned")
    }

    /// Decodes a canonical uint `VALUE` node for `domain`.
    pub fn decode_value_node(node: &Node, domain: UintDomain) -> Result<Limbs, DeferredError> {
        Self::limbs_from_value_node(node, domain)
    }

    /// Decodes a uint precompile node without evaluating its children.
    ///
    /// Returns `Ok(None)` when `node` belongs to another precompile. Owned operation nodes return
    /// their structural child digests directly from the payload.
    pub fn decode_node(node: &Node) -> Result<Option<UintNodeRef>, PrecompileError> {
        if node.tag().id() != Self::id() {
            return Ok(None);
        }

        let op = UintOp::decode(node.tag().args()).ok_or(PrecompileError::InvalidNode)?;
        let parsed = UintNode::parse(op, node.payload())?;
        Ok(Some(match parsed {
            UintNode::Value { domain, limbs } => UintNodeRef::Value { domain, limbs },
            UintNode::BinaryOp { op: UintBinaryOp::Add, lhs, rhs } => UintNodeRef::Add { lhs, rhs },
            UintNode::BinaryOp { op: UintBinaryOp::Sub, lhs, rhs } => UintNodeRef::Sub { lhs, rhs },
            UintNode::BinaryOp { op: UintBinaryOp::Mul, lhs, rhs } => UintNodeRef::Mul { lhs, rhs },
            UintNode::Eq { lhs, rhs } => UintNodeRef::Eq { lhs, rhs },
        }))
    }

    pub(crate) fn limbs_from_typed_value_node(
        node: &Node,
    ) -> Result<(UintDomain, Limbs), DeferredError> {
        let Some(UintOp::Value(domain)) = UintOp::decode(node.tag().args()) else {
            return Err(DeferredError::InvalidPayload);
        };
        let payload = node.payload_for_tag(Self::value_tag(domain))?;
        let limbs = decode_limbs(payload.as_value()?)?;
        if !domain.is_canonical(&limbs) {
            return Err(DeferredError::InvalidPayload);
        }
        Ok((domain, limbs))
    }

    pub(crate) fn limbs_from_value_node(
        node: &Node,
        domain: UintDomain,
    ) -> Result<Limbs, DeferredError> {
        let (actual_domain, limbs) = Self::limbs_from_typed_value_node(node)?;
        if actual_domain != domain {
            return Err(DeferredError::InvalidPayload);
        }
        Ok(limbs)
    }

    fn evaluate_value_pair(
        context: &mut DeferredContext<'_>,
        lhs: Digest,
        rhs: Digest,
    ) -> Result<(UintDomain, Limbs, Limbs), PrecompileError> {
        let (lhs, rhs) = context.evaluate_digest_pair(lhs, rhs)?;
        let lhs = context.get_node(&lhs).ok_or(PrecompileError::MissingNode)?;
        let rhs = context.get_node(&rhs).ok_or(PrecompileError::MissingNode)?;

        let (lhs_domain, lhs) = Self::limbs_from_typed_value_node(lhs)?;
        let (rhs_domain, rhs) = Self::limbs_from_typed_value_node(rhs)?;
        if lhs_domain != rhs_domain {
            return Err(DeferredError::InvalidPayload.into());
        }

        Ok((lhs_domain, lhs, rhs))
    }
}

impl Precompile for UintPrecompile {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn id(&self) -> Felt {
        Self::id()
    }

    fn init(&self) -> Vec<Node> {
        let mut nodes = Vec::new();
        for domain in UintDomain::ALL {
            for value in [ZERO_LIMBS, ONE_LIMBS, TWO_LIMBS] {
                nodes.push(Self::value_node(domain, value));
            }
            if let Some(max) = domain.max() {
                nodes.push(Self::value_node(domain, max));
            }
            if let Some(constants) = domain.field_constants() {
                for value in constants {
                    nodes.push(Self::value_node(domain, value));
                }
            }
        }
        nodes
    }

    fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
        let op = UintOp::decode(args)?;
        Some(op.node_type())
    }

    fn evaluate(
        &self,
        args: [Felt; 3],
        payload: &Payload,
        context: &mut DeferredContext<'_>,
    ) -> Result<Node, PrecompileError> {
        let op = UintOp::decode(args).ok_or(PrecompileError::InvalidNode)?;

        match UintNode::parse(op, payload)? {
            UintNode::Value { domain, limbs } => Ok(Self::value_node(domain, limbs)),
            UintNode::BinaryOp { op, lhs, rhs } => {
                let (domain, lhs, rhs) = Self::evaluate_value_pair(context, lhs, rhs)?;
                let value = match op {
                    UintBinaryOp::Add => domain.add(lhs, rhs),
                    UintBinaryOp::Sub => domain.sub(lhs, rhs),
                    UintBinaryOp::Mul => domain.mul(lhs, rhs),
                };
                Ok(Self::value_node(domain, value))
            },
            UintNode::Eq { lhs, rhs } => {
                let (_, lhs, rhs) = Self::evaluate_value_pair(context, lhs, rhs)?;
                if lhs == rhs {
                    Ok(Node::TRUE)
                } else {
                    Err(PrecompileError::AssertionFailed)
                }
            },
        }
    }
}

pub(crate) fn decode_limbs(felts: &[Felt; 8]) -> Result<Limbs, DeferredError> {
    let mut limbs = [0u32; 8];
    for (i, felt) in felts.iter().enumerate() {
        let v = felt.as_canonical_u64();
        if v > u32::MAX as u64 {
            return Err(DeferredError::InvalidPayload);
        }
        limbs[i] = v as u32;
    }
    Ok(limbs)
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use miden_core::deferred::DeferredState;

    use super::*;

    fn state() -> DeferredState {
        DeferredState::new(Arc::new(crate::registry()), usize::MAX)
            .expect("precompile init must succeed")
    }

    fn evaluate(state: &mut DeferredState, node: Node) -> Result<Node, PrecompileError> {
        let digest = state.register(node)?;
        state.require_canonical_node(digest).map(|(_, node)| node.clone())
    }

    fn assert_invalid_payload<T>(result: Result<T, PrecompileError>) {
        let Err(error) = result else {
            panic!("expected invalid payload");
        };
        assert!(
            matches!(error.root(), PrecompileError::Other(DeferredError::InvalidPayload)),
            "expected invalid payload, got {error:?}",
        );
    }

    fn limbs(value: u32) -> Limbs {
        let mut limbs = [0; 8];
        limbs[0] = value;
        limbs
    }

    #[test]
    fn decode_uses_bound_ptr_value_and_op_tags() {
        let precompile = UintPrecompile;
        let domain = UintDomain::K1Base;
        let bound_ptr = Felt::from(domain.bound_ptr());

        assert_eq!(
            UintPrecompile::value_tag(domain).as_word(),
            [UintPrecompile::id(), Felt::from_u32(0), bound_ptr, ZERO],
        );
        assert_eq!(
            precompile.decode(UintPrecompile::value_tag(domain).args()),
            Some(NodeType::Data)
        );

        assert_eq!(
            UintPrecompile::op_tag(UintPrecompile::ADD_OP_ID).as_word(),
            [UintPrecompile::id(), Felt::from_u32(1), ZERO, ZERO],
        );
        assert_eq!(
            precompile.decode(UintPrecompile::op_tag(UintPrecompile::ADD_OP_ID).args()),
            Some(NodeType::Join)
        );

        let mut add_with_bound = UintPrecompile::op_tag(UintPrecompile::ADD_OP_ID).args();
        add_with_bound[1] = bound_ptr;
        assert_eq!(precompile.decode(add_with_bound), None);
        assert_eq!(precompile.decode(UintPrecompile::op_tag(99).args()), None);

        assert_eq!(precompile.decode([Felt::from_u32(0), Felt::new_unchecked(99), ZERO]), None);
        assert_eq!(precompile.decode([Felt::from_u32(0), ZERO, ZERO]), None);
        assert_eq!(precompile.decode([Felt::from_u32(0), bound_ptr, Felt::from_u32(1)]), None);
        assert_eq!(
            precompile.decode([Felt::from_u32(0), Felt::new_unchecked(u32::MAX as u64 + 1), ZERO,]),
            None
        );
    }

    #[test]
    fn data_shape_does_not_bypass_one_chunk_value_semantics() {
        let domain = UintDomain::K1Base;
        let tag = UintPrecompile::value_tag(domain);
        let node = Node::try_data(tag, alloc::vec![[ZERO; 8], [ZERO; 8]])
            .expect("multi-chunk data is structurally valid");
        let precompile = UintPrecompile;
        assert_eq!(precompile.decode(tag.args()), Some(NodeType::Data));

        let mut state = state();
        assert_invalid_payload(state.register(node));
    }

    #[test]
    fn decode_node_exposes_structural_uint_nodes() {
        let domain = UintDomain::K1Base;
        let lhs = UintPrecompile::value_node(domain, limbs(9));
        let rhs = UintPrecompile::value_node(domain, limbs(4));

        assert_eq!(
            UintPrecompile::decode_node(&lhs).unwrap(),
            Some(UintNodeRef::Value { domain, limbs: limbs(9) })
        );
        assert_eq!(UintPrecompile::decode_node(&Node::TRUE).unwrap(), None);

        for (op_id, expected) in [
            (
                UintPrecompile::ADD_OP_ID,
                UintNodeRef::Add { lhs: lhs.digest(), rhs: rhs.digest() },
            ),
            (
                UintPrecompile::SUB_OP_ID,
                UintNodeRef::Sub { lhs: lhs.digest(), rhs: rhs.digest() },
            ),
            (
                UintPrecompile::MUL_OP_ID,
                UintNodeRef::Mul { lhs: lhs.digest(), rhs: rhs.digest() },
            ),
            (
                UintPrecompile::EQ_OP_ID,
                UintNodeRef::Eq { lhs: lhs.digest(), rhs: rhs.digest() },
            ),
        ] {
            let node = Node::join(UintPrecompile::op_tag(op_id), lhs.digest(), rhs.digest())
                .expect("tag is uint-owned");
            assert_eq!(UintPrecompile::decode_node(&node).unwrap(), Some(expected));
        }

        let invalid_tag = Tag::precompile(UintPrecompile::id(), [Felt::from_u32(99), ZERO, ZERO])
            .expect("tag is precompile-owned");
        let invalid = Node::join(invalid_tag, lhs.digest(), rhs.digest()).unwrap();
        assert!(matches!(
            UintPrecompile::decode_node(&invalid),
            Err(PrecompileError::InvalidNode)
        ));
    }

    #[test]
    fn same_domain_binary_operation_succeeds() {
        let mut state = state();
        let lhs = UintPrecompile::value_node(UintDomain::U256, limbs(3));
        let rhs = UintPrecompile::value_node(UintDomain::U256, limbs(4));
        state.register(lhs.clone()).expect("lhs must register");
        state.register(rhs.clone()).expect("rhs must register");

        let node = Node::join(
            UintPrecompile::op_tag(UintPrecompile::ADD_OP_ID),
            lhs.digest(),
            rhs.digest(),
        )
        .expect("tag is uint-owned");
        let expected = UintPrecompile::value_node(UintDomain::U256, limbs(7));

        assert_eq!(evaluate(&mut state, node).unwrap(), expected);
    }

    #[test]
    fn mixed_domain_binary_operation_fails() {
        let mut state = state();
        let lhs = UintPrecompile::value_node(UintDomain::U256, limbs(1));
        let rhs = UintPrecompile::value_node(UintDomain::K1Base, limbs(1));
        state.register(lhs.clone()).expect("lhs must register");
        state.register(rhs.clone()).expect("rhs must register");

        let node = Node::join(
            UintPrecompile::op_tag(UintPrecompile::ADD_OP_ID),
            lhs.digest(),
            rhs.digest(),
        )
        .expect("tag is uint-owned");

        assert_invalid_payload(evaluate(&mut state, node));
    }

    #[test]
    fn decode_limbs_accepts_u32_boundary_and_rejects_larger_felts() {
        let felts = [Felt::from_u32(u32::MAX); 8];
        assert_eq!(decode_limbs(&felts).unwrap(), [u32::MAX; 8]);

        let mut felts = [Felt::from_u32(0); 8];
        felts[3] = Felt::new_unchecked(u32::MAX as u64 + 1);
        assert_eq!(decode_limbs(&felts), Err(DeferredError::InvalidPayload));
    }
}
