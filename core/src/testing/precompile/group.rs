//! Mock group precompile for exercising compound canonical nodes.
//!
//! Group elements preserve committed coordinate expressions, while `add` and `sub` mint new
//! `Uint` leaves during reduction. This stresses the witness path where a canonical result
//! references helper nodes created by the precompile itself.

use super::uint::Uint;
use crate::{
    Felt, ZERO,
    deferred::{
        Digest, Node, NodeType, Payload, Precompile, PrecompileError, Tag, WitnessBuilder,
        precompile_id,
    },
};

// PUBLIC PRECOMPILE TYPE
// ================================================================================================

/// Zero-sized handle for the mock group precompile.
#[derive(Debug, Default, Clone, Copy)]
pub struct Group;

impl Group {
    pub const NAME: &'static str = "mock_group";

    /// Tag discriminants owned by this fixture.
    pub const NEW_TAG_ID: u32 = 0;
    pub const ADD_TAG_ID: u32 = 1;
    pub const SUB_TAG_ID: u32 = 2;
    pub const EQ_TAG_ID: u32 = 3;

    /// Stable precompile id derived from the fixture name.
    pub fn id() -> Felt {
        precompile_id(&Group)
    }

    pub fn new_tag() -> Tag {
        Tag {
            id: Self::id(),
            args: [Felt::from_u32(Self::NEW_TAG_ID), ZERO, ZERO],
        }
    }
    pub fn add_tag() -> Tag {
        Tag {
            id: Self::id(),
            args: [Felt::from_u32(Self::ADD_TAG_ID), ZERO, ZERO],
        }
    }
    pub fn sub_tag() -> Tag {
        Tag {
            id: Self::id(),
            args: [Felt::from_u32(Self::SUB_TAG_ID), ZERO, ZERO],
        }
    }
    pub fn eq_tag() -> Tag {
        Tag {
            id: Self::id(),
            args: [Felt::from_u32(Self::EQ_TAG_ID), ZERO, ZERO],
        }
    }

    /// Builds a group element from committed coordinate-expression digests.
    pub fn new_node(h_x: Digest, h_y: Digest) -> Node {
        Node::join(Self::new_tag(), h_x, h_y)
    }
    /// Builds a group-add node over two group-element digests.
    pub fn add_node(h_g1: Digest, h_g2: Digest) -> Node {
        Node::join(Self::add_tag(), h_g1, h_g2)
    }
    /// Builds a group-sub node over two group-element digests.
    pub fn sub_node(h_g1: Digest, h_g2: Digest) -> Node {
        Node::join(Self::sub_tag(), h_g1, h_g2)
    }
    /// Builds a predicate comparing two group elements by value.
    pub fn eq_node(h_g1: Digest, h_g2: Digest) -> Node {
        Node::join(Self::eq_tag(), h_g1, h_g2)
    }
}

impl Precompile for Group {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn id(&self) -> Felt {
        Self::id()
    }

    fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
        // All Group nodes pack two child digests in their payload — `new` references committed
        // coordinate-expression digests, `add`/`sub` reference the group operands, and `eq`
        // references the two compared group elements. So every tag is `NodeType::Join`.
        Discriminant::classify(args[0])?;
        Some(NodeType::Join)
    }

    fn reduce(
        &self,
        args: [Felt; 3],
        payload: &Payload,
        witness: &mut WitnessBuilder<'_>,
    ) -> Result<Node, PrecompileError> {
        let kind = Discriminant::classify(args[0]).ok_or(PrecompileError::InvalidNode)?;
        let (h_lhs, h_rhs) = payload.join_children()?;

        match kind {
            Discriminant::New => {
                // Validate that both committed coordinate expressions resolve to field leaves,
                // but preserve their original commitments in the canonical group element.
                let x_leaf = witness.resolve(h_lhs)?;
                let y_leaf = witness.resolve(h_rhs)?;
                Uint::limbs_of(&x_leaf).map_err(PrecompileError::from)?;
                Uint::limbs_of(&y_leaf).map_err(PrecompileError::from)?;
                Ok(Self::new_node(h_lhs, h_rhs))
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
                // Mint new field leaves for the result coordinates.
                let h_x3 = witness.intern(Uint::leaf_node(x3))?;
                let h_y3 = witness.intern(Uint::leaf_node(y3))?;
                Ok(Self::new_node(h_x3, h_y3))
            },
            Discriminant::Eq => {
                let g1 = witness.resolve(h_lhs)?;
                let g2 = witness.resolve(h_rhs)?;
                let (h_x1, h_y1) = new_coords(&g1)?;
                let (h_x2, h_y2) = new_coords(&g2)?;

                if witness.resolve(h_x1)? != witness.resolve(h_x2)?
                    || witness.resolve(h_y1)? != witness.resolve(h_y2)?
                {
                    return Err(PrecompileError::AssertionFailed);
                }
                Ok(Node::TRUE)
            },
        }
    }
}

// HELPERS
// ================================================================================================

/// Extracts coordinate-expression digests from a canonical group element.
fn new_coords(node: &Node) -> Result<(Digest, Digest), PrecompileError> {
    if node.tag != Group::new_tag() {
        return Err(PrecompileError::InvalidNode);
    }
    Ok(node.payload.join_children()?)
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
