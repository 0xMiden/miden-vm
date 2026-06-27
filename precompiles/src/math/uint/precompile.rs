//! Deferred precompile for fixed 256-bit uint arithmetic domains.

use alloc::vec::Vec;

use miden_core::{
    Felt, ZERO,
    deferred::{
        DeferredContext, DeferredError, Digest, Node, NodeType, Payload, Precompile,
        PrecompileError, Tag, precompile_id,
    },
};

use super::domain::{Limbs, ONE_LIMBS, TWO_LIMBS, UintDomain, ZERO_LIMBS};

/// Recognized uint binary operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UintBinaryOp {
    Add,
    Sub,
    Mul,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UintOp {
    Value(UintDomain),
    Binary(UintBinaryOp),
    Eq,
}

impl UintOp {
    fn decode(args: [Felt; 3]) -> Option<Self> {
        if args[2] != ZERO {
            return None;
        }

        match args[0].as_canonical_u64() {
            UintPrecompile::VALUE_OP_ID => Some(Self::Value(UintDomain::from_id(args[1])?)),
            UintPrecompile::ADD_OP_ID if args[1] == ZERO => Some(Self::Binary(UintBinaryOp::Add)),
            UintPrecompile::SUB_OP_ID if args[1] == ZERO => Some(Self::Binary(UintBinaryOp::Sub)),
            UintPrecompile::MUL_OP_ID if args[1] == ZERO => Some(Self::Binary(UintBinaryOp::Mul)),
            UintPrecompile::EQ_OP_ID if args[1] == ZERO => Some(Self::Eq),
            _ => None,
        }
    }

    const fn node_type(self) -> NodeType {
        match self {
            Self::Value(_) => NodeType::value(),
            Self::Binary(_) | Self::Eq => NodeType::Join,
        }
    }
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

/// Deferred precompile for 256-bit arithmetic over fixed uint domains.
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
        Tag::precompile(Self::id(), [op_id, domain.id(), ZERO])
            .expect("uint precompile id is not framework-reserved")
    }

    /// Builds a canonical uint operation tag. Operand `VALUE` nodes carry the concrete domain.
    pub fn op_tag(op_id: u64) -> Tag {
        let op_id = Felt::new(op_id).expect("uint op id must fit in a felt");
        Tag::precompile(Self::id(), [op_id, ZERO, ZERO])
            .expect("uint precompile id is not framework-reserved")
    }

    /// Builds a canonical value node.
    pub fn value_node(domain: UintDomain, limbs: Limbs) -> Node {
        debug_assert!(domain.is_canonical(&limbs));
        Node::value(Self::value_tag(domain), limbs.map(Felt::from_u32))
            .expect("value tag is precompile-owned")
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
        let canonical = state.evaluate_digest(digest)?;
        state.get_node(&canonical).cloned().ok_or(PrecompileError::InvalidNode)
    }

    fn assert_invalid_payload(result: Result<Node, PrecompileError>) {
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
    fn decode_uses_domain_only_for_value_tags() {
        let precompile = UintPrecompile;

        assert_eq!(
            precompile.decode(UintPrecompile::value_tag(UintDomain::K1Base).args()),
            Some(NodeType::value())
        );
        assert_eq!(
            precompile.decode(UintPrecompile::op_tag(UintPrecompile::ADD_OP_ID).args()),
            Some(NodeType::Join)
        );

        let mut add_with_domain = UintPrecompile::op_tag(UintPrecompile::ADD_OP_ID).args();
        add_with_domain[1] = UintDomain::K1Base.id();
        assert_eq!(precompile.decode(add_with_domain), None);

        assert_eq!(precompile.decode([Felt::from_u32(0), Felt::new_unchecked(99), ZERO]), None);
        assert_eq!(
            precompile.decode([Felt::from_u32(0), UintDomain::U256.id(), Felt::from_u32(1)]),
            None
        );
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
