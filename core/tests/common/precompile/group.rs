//! `Group<F>` — compound-canonical reference precompile, demonstrating mid-`reduce` minting.
//!
//! A group element is represented as a self-evaluating `combine` bin-op node whose payload is
//! two field-leaf digests `(h_x, h_y)`. The two **producing** ops (`add`, `sub`) reduce by
//! pulling limbs from both operands' coordinates, performing **mock** coordinate-wise wrapping
//! arithmetic (NOT a real curve), minting new field leaves for the resulting `(x3, y3)` via
//! [`ReduceCtx::intern`], and returning a `combine` leaf that references those minted digests.
//!
//! Parameterised over a [`FieldOps`] implementor — `Group<Uint>` is the only intended
//! instantiation, but the bound makes the dependency explicit and exercises the planned
//! `Field<P>` → `Curve<C>` cross-app linkage pattern.

use core::marker::PhantomData;

use miden_core::{
    Felt, ZERO,
    deferred::{
        App, AppTag, Digest, Node, NodeType, Payload, ReduceCtx, SchemaError, TRUE_TAG, Tag,
        TagInfo, app_id_from, true_node,
    },
};

use super::uint::FieldOps;

// PUBLIC APP TYPE
// ================================================================================================

/// Mock group app over a [`FieldOps`] implementor. Default-constructible; carries no state.
#[derive(Debug, Default, Clone, Copy)]
pub struct Group<F: FieldOps> {
    _phantom: PhantomData<F>,
}

impl<F: FieldOps> Group<F> {
    pub const NAME: &'static str = "mock_group";
    pub const VERSION: u32 = 1;
    pub const DISCS: &'static [&'static str] = &["combine", "add", "sub", "eq"];

    /// Discriminant indices.
    pub const D_COMBINE: Felt = Felt::new_unchecked(0);
    pub const D_ADD: Felt = Felt::new_unchecked(1);
    pub const D_SUB: Felt = Felt::new_unchecked(2);
    pub const D_EQ: Felt = Felt::new_unchecked(3);

    /// App identifier. Mixes the underlying field's leaf-tag into the params bytes so that
    /// `Group<F1>` and `Group<F2>` get distinct ids.
    pub fn app_id() -> Felt {
        let field_tag = F::leaf_tag();
        let mut params = [0u8; 32];
        for (i, f) in field_tag.iter().enumerate() {
            let bytes = f.as_canonical_u64().to_le_bytes();
            params[i * 8..i * 8 + 8].copy_from_slice(&bytes);
        }
        app_id_from(Self::NAME, Self::VERSION, &params, Self::DISCS)
    }

    pub fn combine_tag() -> Tag {
        [Self::app_id(), Self::D_COMBINE, ZERO, ZERO]
    }
    pub fn add_tag() -> Tag {
        [Self::app_id(), Self::D_ADD, ZERO, ZERO]
    }
    pub fn sub_tag() -> Tag {
        [Self::app_id(), Self::D_SUB, ZERO, ZERO]
    }
    pub fn eq_tag() -> Tag {
        [Self::app_id(), Self::D_EQ, ZERO, ZERO]
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

impl<F: FieldOps> App for Group<F> {
    fn id(&self) -> Felt {
        Self::app_id()
    }

    fn decode(&self, local: AppTag) -> Result<TagInfo, SchemaError> {
        if local.imm != ZERO {
            return Err(SchemaError::InvalidNode);
        }
        // All Group nodes pack two child digests in their payload — `combine` references the
        // coordinate leaves, `add`/`sub` reference the group operands, `eq` references the two
        // compared group elements. So every tag is `NodeType::Binary`.
        let evaluates_to = match Discriminant::classify(local.node_disc)
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
                // resolves to something that isn't a field leaf.
                let x_leaf = ctx.resolve(h_lhs)?;
                let y_leaf = ctx.resolve(h_rhs)?;
                F::limbs_of(&x_leaf).map_err(SchemaError::from)?;
                F::limbs_of(&y_leaf).map_err(SchemaError::from)?;
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
                let (h_x1, h_y1) = combine_coords::<F>(&g1)?;
                let (h_x2, h_y2) = combine_coords::<F>(&g2)?;
                let x1 = F::limbs_of(&ctx.resolve(h_x1)?).map_err(SchemaError::from)?;
                let y1 = F::limbs_of(&ctx.resolve(h_y1)?).map_err(SchemaError::from)?;
                let x2 = F::limbs_of(&ctx.resolve(h_x2)?).map_err(SchemaError::from)?;
                let y2 = F::limbs_of(&ctx.resolve(h_y2)?).map_err(SchemaError::from)?;
                let (x3, y3) = match op {
                    BinaryOp::Add => (F::wrap_add(x1, x2), F::wrap_add(y1, y2)),
                    BinaryOp::Sub => (F::wrap_sub(x1, x2), F::wrap_sub(y1, y2)),
                };
                // *** MINT ***  new field leaves for the result coordinates.
                let h_x3 = ctx.intern(F::leaf_node(x3));
                let h_y3 = ctx.intern(F::leaf_node(y3));
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
/// isn't tagged as `Group<F>::combine_tag()`.
fn combine_coords<F: FieldOps>(node: &Node) -> Result<(Digest, Digest), SchemaError> {
    if node.tag != Group::<F>::combine_tag() {
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
