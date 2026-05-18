//! `Group` — compound-canonical reference precompile, demonstrating mid-`reduce` minting.
//!
//! A mock group over [`Uint`] (NOT a real curve). A group element is a self-evaluating
//! `combine` bin-op node whose payload is two `Uint` field-leaf digests `(h_x, h_y)`. The two
//! **producing** ops (`add`, `sub`) reduce by pulling limbs from both operands' coordinates,
//! performing coordinate-wise wrapping arithmetic, minting new field leaves for the resulting
//! `(x3, y3)` via [`ReduceCtx::intern`], and returning a `combine` leaf referencing those
//! minted digests.

use miden_core::{
    Felt, ZERO,
    deferred::{
        Digest, Node, NodeType, Payload, Precompile, PrecompileTag, ReduceCtx, SchemaError,
        TRUE_TAG, Tag, TagInfo, precompile_id, true_node,
    },
};

use super::uint::Uint;

// PUBLIC APP TYPE
// ================================================================================================

/// Zero-sized handle for the `Group` app (mock group over [`Uint`]).
#[derive(Debug, Default, Clone, Copy)]
pub struct Group;

impl Group {
    pub const NAME: &'static str = "mock_group";
    pub const VERSION: u32 = 1;

    /// Discriminant indices.
    pub const COMBINE_TAG_ID: u32 = 0;
    pub const ADD_TAG_ID: u32 = 1;
    pub const SUB_TAG_ID: u32 = 2;
    pub const EQ_TAG_ID: u32 = 3;

    /// Derive the precompile id. Pure function over `Group`'s metadata.
    pub fn app_id() -> Felt {
        precompile_id(&Group)
    }

    pub fn combine_tag() -> Tag {
        [Self::app_id(), Felt::from_u32(Self::COMBINE_TAG_ID), ZERO, ZERO]
    }
    pub fn add_tag() -> Tag {
        [Self::app_id(), Felt::from_u32(Self::ADD_TAG_ID), ZERO, ZERO]
    }
    pub fn sub_tag() -> Tag {
        [Self::app_id(), Felt::from_u32(Self::SUB_TAG_ID), ZERO, ZERO]
    }
    pub fn eq_tag() -> Tag {
        [Self::app_id(), Felt::from_u32(Self::EQ_TAG_ID), ZERO, ZERO]
    }

    /// Build a `combine` node referencing two field-leaf digests.
    pub fn combine_node(h_x: Digest, h_y: Digest) -> Node {
        Node::expression(Self::combine_tag(), Payload::binary_op(h_x, h_y))
    }
    /// Build an `add` op node referencing two group-element digests.
    pub fn add_node(h_g1: Digest, h_g2: Digest) -> Node {
        Node::expression(Self::add_tag(), Payload::binary_op(h_g1, h_g2))
    }
    /// Build a `sub` op node referencing two group-element digests.
    pub fn sub_node(h_g1: Digest, h_g2: Digest) -> Node {
        Node::expression(Self::sub_tag(), Payload::binary_op(h_g1, h_g2))
    }
    /// Build an `eq` predicate referencing two group-element digests.
    pub fn eq_node(h_g1: Digest, h_g2: Digest) -> Node {
        Node::expression(Self::eq_tag(), Payload::binary_op(h_g1, h_g2))
    }
}

impl Precompile for Group {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn version(&self) -> u32 {
        Self::VERSION
    }

    fn id(&self) -> Felt {
        Self::app_id()
    }

    fn decode(&self, sub: PrecompileTag) -> Result<TagInfo, SchemaError> {
        let [disc, imm, reserved] = sub.0;
        if imm != ZERO || reserved != ZERO {
            return Err(SchemaError::InvalidNode);
        }
        // All Group nodes pack two child digests in their payload — `combine` references the
        // coordinate leaves, `add`/`sub` reference the group operands, `eq` references the two
        // compared group elements. So every tag is `NodeType::Binary`.
        let evaluates_to = match Discriminant::classify(disc)
            .ok_or(SchemaError::InvalidNode)?
        {
            Discriminant::Combine | Discriminant::Add | Discriminant::Sub => Self::combine_tag(),
            Discriminant::Eq => TRUE_TAG,
        };
        Ok(TagInfo { node_type: NodeType::Binary, evaluates_to })
    }

    fn reduce(&self, node: &Node, ctx: &mut dyn ReduceCtx) -> Result<Node, SchemaError> {
        let kind = Discriminant::classify(node.tag[1]).ok_or(SchemaError::InvalidNode)?;
        if node.tag[0] != Self::app_id() || node.tag[2] != ZERO || node.tag[3] != ZERO {
            return Err(SchemaError::InvalidNode);
        }
        let payload = node.expression_payload().ok_or(SchemaError::InvalidNode)?;
        let (h_lhs, h_rhs) = payload.binary_op_children();

        match kind {
            Discriminant::Combine => {
                // Canonicalise the two coordinates to field leaves; reject if either child
                // resolves to something that isn't a `Uint` field leaf.
                let x_leaf = ctx.resolve(h_lhs)?;
                let y_leaf = ctx.resolve(h_rhs)?;
                Uint::limbs_of(&x_leaf).map_err(SchemaError::from)?;
                Uint::limbs_of(&y_leaf).map_err(SchemaError::from)?;
                Ok(Self::combine_node(x_leaf.digest(), y_leaf.digest()))
            },
            Discriminant::Add | Discriminant::Sub => {
                let op = match kind {
                    Discriminant::Add => BinaryOp::Add,
                    Discriminant::Sub => BinaryOp::Sub,
                    _ => unreachable!(),
                };
                let g1 = ctx.resolve(h_lhs)?;
                let g2 = ctx.resolve(h_rhs)?;
                let (h_x1, h_y1) = combine_coords(&g1)?;
                let (h_x2, h_y2) = combine_coords(&g2)?;
                let x1 = Uint::limbs_of(&ctx.resolve(h_x1)?).map_err(SchemaError::from)?;
                let y1 = Uint::limbs_of(&ctx.resolve(h_y1)?).map_err(SchemaError::from)?;
                let x2 = Uint::limbs_of(&ctx.resolve(h_x2)?).map_err(SchemaError::from)?;
                let y2 = Uint::limbs_of(&ctx.resolve(h_y2)?).map_err(SchemaError::from)?;
                let (x3, y3) = match op {
                    BinaryOp::Add => (Uint::wrap_add(x1, x2), Uint::wrap_add(y1, y2)),
                    BinaryOp::Sub => (Uint::wrap_sub(x1, x2), Uint::wrap_sub(y1, y2)),
                };
                // *** MINT ***  new field leaves for the result coordinates.
                let h_x3 = ctx.intern(Uint::leaf_node(x3));
                let h_y3 = ctx.intern(Uint::leaf_node(y3));
                Ok(Self::combine_node(h_x3, h_y3))
            },
            Discriminant::Eq => {
                if ctx.resolve(h_lhs)? != ctx.resolve(h_rhs)? {
                    return Err(SchemaError::AssertionFailed);
                }
                Ok(true_node())
            },
        }
    }
}

// HELPERS
// ================================================================================================

/// Extract the two field-leaf child digests from a canonical `combine` node. Errors if `node`
/// isn't tagged as `Group::combine_tag()`.
fn combine_coords(node: &Node) -> Result<(Digest, Digest), SchemaError> {
    if node.tag != Group::combine_tag() {
        return Err(SchemaError::InvalidNode);
    }
    let payload = node.expression_payload().ok_or(SchemaError::InvalidNode)?;
    Ok(payload.binary_op_children())
}

// TYPED DISCRIMINANT
// ================================================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Discriminant {
    Combine,
    Add,
    Sub,
    Eq,
}

impl Discriminant {
    fn classify(disc: Felt) -> Option<Self> {
        match disc.as_canonical_u64() {
            0 => Some(Self::Combine),
            1 => Some(Self::Add),
            2 => Some(Self::Sub),
            3 => Some(Self::Eq),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinaryOp {
    Add,
    Sub,
}
