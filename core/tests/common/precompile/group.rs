//! `Group` — compound-canonical reference precompile, demonstrating mid-`reduce` minting.
//!
//! A mock group over [`Uint`] (NOT a real curve). A group element is a self-evaluating
//! `new` bin-op node whose payload is two `Uint` field-leaf digests `(h_x, h_y)`. The two
//! **producing** ops (`add`, `sub`) reduce by pulling limbs from both operands' coordinates,
//! performing coordinate-wise wrapping arithmetic, minting new field leaves for the resulting
//! `(x3, y3)` via [`WitnessBuilder::intern`], and returning a `new` leaf referencing those
//! minted digests.

use miden_core::{
    Felt, ZERO,
    deferred::{
        Digest, Node, NodeType, Payload, Precompile, PrecompileError, TRUE_TAG, Tag, TagInfo,
        WitnessBuilder, precompile_id, true_node,
    },
};

use super::uint::Uint;

// PUBLIC PRECOMPILE TYPE
// ================================================================================================

/// Zero-sized handle for the `Group` precompile (mock group over [`Uint`]).
#[derive(Debug, Default, Clone, Copy)]
pub struct Group;

impl Group {
    pub const NAME: &'static str = "mock_group";

    /// Discriminant indices.
    pub const NEW_TAG_ID: u32 = 0;
    pub const ADD_TAG_ID: u32 = 1;
    pub const SUB_TAG_ID: u32 = 2;
    pub const EQ_TAG_ID: u32 = 3;

    /// Derive the precompile id. Pure function over `Group`'s metadata.
    pub fn id() -> Felt {
        precompile_id(&Group)
    }

    pub fn new_tag() -> Tag {
        Tag {
            id: Self::id(),
            imm: [Felt::from_u32(Self::NEW_TAG_ID), ZERO, ZERO],
        }
    }
    pub fn add_tag() -> Tag {
        Tag {
            id: Self::id(),
            imm: [Felt::from_u32(Self::ADD_TAG_ID), ZERO, ZERO],
        }
    }
    pub fn sub_tag() -> Tag {
        Tag {
            id: Self::id(),
            imm: [Felt::from_u32(Self::SUB_TAG_ID), ZERO, ZERO],
        }
    }
    pub fn eq_tag() -> Tag {
        Tag {
            id: Self::id(),
            imm: [Felt::from_u32(Self::EQ_TAG_ID), ZERO, ZERO],
        }
    }

    /// Build a `new` node referencing two field-leaf digests.
    pub fn new_node(h_x: Digest, h_y: Digest) -> Node {
        Node::expression(Self::new_tag(), Payload::binary_op(h_x, h_y))
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

    fn id(&self) -> Felt {
        Self::id()
    }

    fn decode(&self, imm: [Felt; 3]) -> Option<TagInfo> {
        let [disc, immediate, reserved] = imm;
        if immediate != ZERO || reserved != ZERO {
            return None;
        }
        // All Group nodes pack two child digests in their payload — `new` references the
        // coordinate leaves, `add`/`sub` reference the group operands, `eq` references the two
        // compared group elements. So every tag is `NodeType::Binary`.
        let evaluates_to = match Discriminant::classify(disc)? {
            Discriminant::New | Discriminant::Add | Discriminant::Sub => Self::new_tag(),
            Discriminant::Eq => TRUE_TAG,
        };
        Some(TagInfo {
            node_type: NodeType::Binary,
            evaluates_to,
        })
    }

    fn reduce(
        &self,
        node: &Node,
        witness: &mut WitnessBuilder<'_>,
    ) -> Result<Node, PrecompileError> {
        let kind = Discriminant::classify(node.tag.imm[0]).ok_or(PrecompileError::InvalidNode)?;
        if node.tag.id != Self::id() || node.tag.imm[1] != ZERO || node.tag.imm[2] != ZERO {
            return Err(PrecompileError::InvalidNode);
        }
        let payload = node.expression_payload().ok_or(PrecompileError::InvalidNode)?;
        let (h_lhs, h_rhs) = payload.binary_op_children();

        match kind {
            Discriminant::New => {
                // Canonicalise the two coordinates to field leaves; reject if either child
                // resolves to something that isn't a `Uint` field leaf.
                let x_leaf = witness.resolve(h_lhs)?;
                let y_leaf = witness.resolve(h_rhs)?;
                Uint::limbs_of(&x_leaf).map_err(PrecompileError::from)?;
                Uint::limbs_of(&y_leaf).map_err(PrecompileError::from)?;
                Ok(Self::new_node(x_leaf.digest(), y_leaf.digest()))
            },
            Discriminant::Add | Discriminant::Sub => {
                let op = match kind {
                    Discriminant::Add => BinaryOp::Add,
                    Discriminant::Sub => BinaryOp::Sub,
                    _ => unreachable!(),
                };
                let g1 = witness.resolve(h_lhs)?;
                let g2 = witness.resolve(h_rhs)?;
                let (h_x1, h_y1) = new_coords(&g1)?;
                let (h_x2, h_y2) = new_coords(&g2)?;
                let x1 = Uint::limbs_of(&witness.resolve(h_x1)?).map_err(PrecompileError::from)?;
                let y1 = Uint::limbs_of(&witness.resolve(h_y1)?).map_err(PrecompileError::from)?;
                let x2 = Uint::limbs_of(&witness.resolve(h_x2)?).map_err(PrecompileError::from)?;
                let y2 = Uint::limbs_of(&witness.resolve(h_y2)?).map_err(PrecompileError::from)?;
                let (x3, y3) = match op {
                    BinaryOp::Add => (Uint::wrap_add(x1, x2), Uint::wrap_add(y1, y2)),
                    BinaryOp::Sub => (Uint::wrap_sub(x1, x2), Uint::wrap_sub(y1, y2)),
                };
                // *** MINT ***  new field leaves for the result coordinates.
                let h_x3 = witness.intern(Uint::leaf_node(x3));
                let h_y3 = witness.intern(Uint::leaf_node(y3));
                Ok(Self::new_node(h_x3, h_y3))
            },
            Discriminant::Eq => {
                if witness.resolve(h_lhs)? != witness.resolve(h_rhs)? {
                    return Err(PrecompileError::AssertionFailed);
                }
                Ok(true_node())
            },
        }
    }
}

// HELPERS
// ================================================================================================

/// Extract the two field-leaf child digests from a canonical `new` node. Errors if `node`
/// isn't tagged as `Group::new_tag()`.
fn new_coords(node: &Node) -> Result<(Digest, Digest), PrecompileError> {
    if node.tag != Group::new_tag() {
        return Err(PrecompileError::InvalidNode);
    }
    let payload = node.expression_payload().ok_or(PrecompileError::InvalidNode)?;
    Ok(payload.binary_op_children())
}

// TYPED DISCRIMINANT
// ================================================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Discriminant {
    New,
    Add,
    Sub,
    Eq,
}

impl Discriminant {
    fn classify(disc: Felt) -> Option<Self> {
        match disc.as_canonical_u64() {
            0 => Some(Self::New),
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
