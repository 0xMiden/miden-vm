//! Deferred precompile for fixed 256-bit uint arithmetic domains.

use alloc::vec::Vec;

use miden_core::{
    Felt, ZERO,
    deferred::{
        DeferredContext, DeferredError, Digest, Node, NodeType, Payload, Precompile,
        PrecompileError, Tag,
    },
};
use miden_precompiles_codegen::UintPrecompileDescriptor;

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
            Self::Value(_) => NodeType::value(),
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

/// Deferred precompile for 256-bit arithmetic over fixed uint domains.
#[derive(Clone, Copy, Debug, Default)]
pub struct UintPrecompile;

impl UintPrecompile {
    /// Stable precompile name used to derive this precompile's tag id.
    pub const NAME: &'static str = UintPrecompileDescriptor::NAME;

    /// Operation discriminants owned by this precompile.
    pub const VALUE_OP_ID: u64 = UintPrecompileDescriptor::VALUE_OP_ID;
    pub const ADD_OP_ID: u64 = UintPrecompileDescriptor::ADD_OP_ID;
    pub const SUB_OP_ID: u64 = UintPrecompileDescriptor::SUB_OP_ID;
    pub const MUL_OP_ID: u64 = UintPrecompileDescriptor::MUL_OP_ID;
    pub const EQ_OP_ID: u64 = UintPrecompileDescriptor::EQ_OP_ID;

    /// Stable precompile id derived from [`Self::NAME`].
    pub fn id() -> Felt {
        UintPrecompileDescriptor::id()
    }

    /// Builds a canonical uint `VALUE` tag for `domain`.
    pub fn value_tag(domain: UintDomain) -> Tag {
        UintPrecompileDescriptor::value_tag(domain)
    }

    /// Builds a canonical uint operation tag. Operand `VALUE` nodes carry the concrete domain.
    pub fn op_tag(op_id: u64) -> Tag {
        UintPrecompileDescriptor::op_tag(op_id)
    }

    /// Builds a canonical value node.
    pub fn value_node(domain: UintDomain, limbs: Limbs) -> Node {
        UintPrecompileDescriptor::value_node(domain, limbs)
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
            Some(NodeType::value())
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

        assert_eq!(precompile.decode([Felt::from_u32(0), Felt::new_unchecked(99), ZERO]), None);
        assert_eq!(
            precompile.decode([
                Felt::from_u32(0),
                Felt::from(UintDomain::U256.bound_ptr()),
                Felt::from_u32(1)
            ]),
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
