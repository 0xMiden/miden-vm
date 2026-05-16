//! `MockGroup<F>` — first compound-canonical [`App`], demonstrating mid-`reduce` minting.
//!
//! A group element is represented as a self-evaluating `combine` bin-op node whose payload is
//! two field-leaf digests `(h_x, h_y)`. The two **producing** ops (`add`, `sub`) reduce by
//! pulling limbs from both operands' coordinates, performing **mock** coordinate-wise wrapping
//! arithmetic (NOT a real curve), minting new field leaves for the resulting `(x3, y3)` via
//! [`ReduceCtx::intern`], and returning a `combine` leaf that references those minted digests.
//!
//! Parameterised over a [`FieldOps`] implementor — `MockGroup<Uint256>` is the only intended
//! instantiation in v1, but the bound makes the dependency explicit and exercises the planned
//! `Field<P>` → `Curve<C>` cross-app linkage pattern.

use core::marker::PhantomData;

use crate::{
    Felt, ZERO,
    deferred::{
        BodyShape, DeferredState, Digest, Node, Payload, ReduceCtx, SchemaError, TRUE_TAG, Tag,
        TagInfo, true_node,
    },
};

use super::{App, AppTag, FieldOps, app_id_from};

// PUBLIC APP TYPE
// ================================================================================================

/// Mock group app over a [`FieldOps`] implementor. Default-constructible; carries no state.
#[derive(Debug, Default, Clone, Copy)]
pub struct MockGroup<F: FieldOps> {
    _phantom: PhantomData<F>,
}

impl<F: FieldOps> MockGroup<F> {
    pub const NAME: &'static str = "mock_group";
    pub const VERSION: u32 = 1;
    pub const DISCS: &'static [&'static str] = &["combine", "add", "sub", "eq"];

    /// Discriminant indices.
    pub const D_COMBINE: Felt = Felt::new_unchecked(0);
    pub const D_ADD: Felt = Felt::new_unchecked(1);
    pub const D_SUB: Felt = Felt::new_unchecked(2);
    pub const D_EQ: Felt = Felt::new_unchecked(3);

    /// App identifier. Mixes the underlying field's leaf-tag into the params bytes so that
    /// `MockGroup<F1>` and `MockGroup<F2>` get distinct ids.
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

impl<F: FieldOps> App for MockGroup<F> {
    fn id(&self) -> Felt {
        Self::app_id()
    }

    fn init(&self, _state: &mut DeferredState) {
        // No pre-registered constants for the mock variant. A real curve app would register the
        // generator and the point-at-infinity here.
    }

    fn decode(&self, local: AppTag) -> Result<TagInfo, SchemaError> {
        if local.imm != ZERO {
            return Err(SchemaError::InvalidNode);
        }
        let evaluates_to = match Discriminant::classify(local.node_disc)
            .ok_or(SchemaError::InvalidNode)?
        {
            Discriminant::Combine | Discriminant::Add | Discriminant::Sub => Self::combine_tag(),
            Discriminant::Eq => TRUE_TAG,
        };
        Ok(TagInfo { body: BodyShape::Expression, evaluates_to })
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
/// isn't tagged as `MockGroup<F>::combine_tag()`.
fn combine_coords<F: FieldOps>(node: &Node) -> Result<(Digest, Digest), SchemaError> {
    if node.tag != MockGroup::<F>::combine_tag() {
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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;

    use super::*;
    use crate::deferred::{DeferredState, PrecompileSchema, Uint256};

    type Group = MockGroup<Uint256>;

    /// Build a `Uint256` leaf from a low-u64 value, for compact test fixtures.
    fn leaf(low: u64) -> Node {
        let mut limbs = [0u32; 8];
        limbs[0] = low as u32;
        limbs[1] = (low >> 32) as u32;
        Uint256::leaf_node(limbs)
    }

    /// Build a two-app schema and an empty state for a test.
    fn fresh() -> (PrecompileSchema, DeferredState) {
        let schema = PrecompileSchema::new([
            Box::new(Uint256) as Box<dyn App>,
            Box::new(Group::default()) as Box<dyn App>,
        ]);
        (schema, DeferredState::new())
    }

    fn register_group(
        schema: &PrecompileSchema,
        state: &mut DeferredState,
        x: u64,
        y: u64,
    ) -> Digest {
        let h_x = state.register(schema, leaf(x)).unwrap();
        let h_y = state.register(schema, leaf(y)).unwrap();
        state.register(schema, Group::combine_node(h_x, h_y)).unwrap()
    }

    #[test]
    fn app_id_depends_on_field_param() {
        // Reusing a field's leaf tag must propagate into MockGroup's id. We don't have a second
        // FieldOps impl in core, so verify the params encoding actually changes the result by
        // hashing a different (synthetic) tag and observing a different id.
        let real_id = Group::app_id();
        // Hand-hash with a perturbed tag.
        let mut perturbed_tag = Uint256::leaf_tag();
        perturbed_tag[0] = Felt::new_unchecked(perturbed_tag[0].as_canonical_u64() ^ 1);
        let mut params = [0u8; 32];
        for (i, f) in perturbed_tag.iter().enumerate() {
            params[i * 8..i * 8 + 8].copy_from_slice(&f.as_canonical_u64().to_le_bytes());
        }
        let perturbed = app_id_from(
            Group::NAME,
            Group::VERSION,
            &params,
            Group::DISCS,
        );
        assert_ne!(real_id, perturbed);
    }

    #[test]
    fn combine_self_evaluates_when_children_are_leaves() {
        let (schema, mut state) = fresh();
        let h_g = register_group(&schema, &mut state, 3, 4);
        let g = state.get(&h_g).unwrap().clone();
        let canonical = state.evaluate(&schema, g.clone()).unwrap();
        assert_eq!(canonical, g, "combine over field leaves is self-evaluating");
    }

    #[test]
    fn combine_canonicalises_field_expression_children() {
        // Build x = leaf(3) + leaf(4) as a Uint256 expression; build combine(x_expr, y_leaf);
        // evaluate — combine's canonical must reference the *leaf* digest of the canonical x
        // (= leaf(7)), not the expression digest.
        let (schema, mut state) = fresh();
        let h_3 = state.register(&schema, leaf(3)).unwrap();
        let h_4 = state.register(&schema, leaf(4)).unwrap();
        let h_x_expr = state
            .register(&schema, Node::expression(Uint256::add_tag(), Payload::binary_op(h_3, h_4)))
            .unwrap();
        let h_y = state.register(&schema, leaf(5)).unwrap();
        let combine_over_expr = Group::combine_node(h_x_expr, h_y);
        let h_combine = state.register(&schema, combine_over_expr).unwrap();

        let canonical = state.evaluate(&schema, state.get(&h_combine).unwrap().clone()).unwrap();
        let expected = Group::combine_node(leaf(7).digest(), leaf(5).digest());
        assert_eq!(canonical, expected);
        // The minted x-leaf (leaf(7)) must have been interned by the field expression's reduce.
        assert!(state.contains(&leaf(7).digest()));
    }

    #[test]
    fn add_mints_new_field_leaves_and_returns_combine() {
        let (schema, mut state) = fresh();
        let h_g1 = register_group(&schema, &mut state, 3, 4);
        let h_g2 = register_group(&schema, &mut state, 10, 20);

        let canonical = state.evaluate(&schema, Group::add_node(h_g1, h_g2)).unwrap();
        let expected = Group::combine_node(leaf(13).digest(), leaf(24).digest());
        assert_eq!(canonical, expected);
        assert!(state.contains(&leaf(13).digest()), "minted x-coord leaf must be interned");
        assert!(state.contains(&leaf(24).digest()), "minted y-coord leaf must be interned");
    }

    #[test]
    fn sub_mints_new_field_leaves_and_returns_combine() {
        let (schema, mut state) = fresh();
        let h_g1 = register_group(&schema, &mut state, 100, 50);
        let h_g2 = register_group(&schema, &mut state, 30, 20);

        let canonical = state.evaluate(&schema, Group::sub_node(h_g1, h_g2)).unwrap();
        let expected = Group::combine_node(leaf(70).digest(), leaf(30).digest());
        assert_eq!(canonical, expected);
    }

    #[test]
    fn eq_predicate_matches_on_canonical_equality() {
        let (schema, mut state) = fresh();
        let h_g = register_group(&schema, &mut state, 7, 11);
        let result = state.evaluate(&schema, Group::eq_node(h_g, h_g)).unwrap();
        assert!(result.is_true_node());
    }

    #[test]
    fn eq_predicate_errors_on_mismatch() {
        let (schema, mut state) = fresh();
        let h_g1 = register_group(&schema, &mut state, 7, 11);
        let h_g2 = register_group(&schema, &mut state, 7, 12);
        let err = state.evaluate(&schema, Group::eq_node(h_g1, h_g2));
        assert!(matches!(err, Err(SchemaError::AssertionFailed)));
    }

    #[test]
    fn reduce_rejects_combine_with_non_field_leaf_children() {
        // Children resolve to canonical leaves but their tag is *not* the field leaf tag —
        // combine must reject.
        let (schema, mut state) = fresh();
        // A group element used in the wrong position: its digest is a combine, not a field leaf.
        let h_g = register_group(&schema, &mut state, 1, 1);
        let h_y = state.register(&schema, leaf(2)).unwrap();
        let bad_combine = Group::combine_node(h_g, h_y);
        let err = state.evaluate(&schema, bad_combine);
        assert!(matches!(err, Err(SchemaError::Other(_)) | Err(SchemaError::InvalidNode)));
    }
}
