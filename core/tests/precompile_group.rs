//! Integration coverage for the `Group` reference precompile: the compound-canonical /
//! mid-`reduce` minting capability of the framework (mock group over `Uint`).

mod common;

use common::precompile::{group::Group, uint::Uint};
use miden_core::deferred::{
    DeferredState, Digest, Node, Payload, PrecompileError, PrecompileRegistry,
};

fn leaf(low: u64) -> Node {
    let mut limbs = [0u32; 8];
    limbs[0] = low as u32;
    limbs[1] = (low >> 32) as u32;
    Uint::leaf_node(limbs)
}

/// Two-precompile schema with `Uint`'s constants pre-registered.
fn schema_and_state() -> (PrecompileRegistry, DeferredState) {
    let schema = PrecompileRegistry::default().with_precompile(Uint).with_precompile(Group);
    let mut state = DeferredState::new();
    schema.init(&mut state).unwrap();
    (schema, state)
}

/// Two-precompile schema without booting (some tests assert exact node counts).
fn fresh() -> (PrecompileRegistry, DeferredState) {
    let schema = PrecompileRegistry::default().with_precompile(Uint).with_precompile(Group);
    (schema, DeferredState::new())
}

fn register_group(
    schema: &PrecompileRegistry,
    state: &mut DeferredState,
    x: u64,
    y: u64,
) -> Digest {
    let h_x = state.register(schema, leaf(x)).unwrap();
    let h_y = state.register(schema, leaf(y)).unwrap();
    state.register(schema, Group::new_node(h_x, h_y)).unwrap()
}

// END-TO-END (relocated from deferred_mock_group.rs)
// ================================================================================================

#[test]
fn add_produces_minted_new_and_passes_eq_against_expected() {
    let (schema, mut state) = schema_and_state();

    let h_g1 = register_group(&schema, &mut state, 3, 4);
    let h_g2 = register_group(&schema, &mut state, 10, 20);

    // Evaluate add: returns new(h_x3_leaf, h_y3_leaf) where leaves are minted.
    let add_canonical = state.evaluate(&schema, Group::add_node(h_g1, h_g2)).unwrap();
    let expected = Group::new_node(leaf(13).digest(), leaf(24).digest());
    assert_eq!(add_canonical, expected);

    // Both minted field leaves must be in the DAG.
    assert!(state.contains(&leaf(13).digest()));
    assert!(state.contains(&leaf(24).digest()));

    // Build expected group element via registration, then assert eq.
    let h_expected = register_group(&schema, &mut state, 13, 24);
    let h_add = state.register(&schema, Group::add_node(h_g1, h_g2)).unwrap();
    let eq_result = state.evaluate(&schema, Group::eq_node(h_add, h_expected)).unwrap();
    assert!(eq_result.is_true_node());
}

#[test]
fn sub_chains_through_add_with_mint_at_every_step() {
    let (schema, mut state) = schema_and_state();

    // ((g1 + g2) - g1)  should equal g2 under coord-wise mock arithmetic.
    let h_g1 = register_group(&schema, &mut state, 7, 11);
    let h_g2 = register_group(&schema, &mut state, 100, 200);

    let h_sum = state.register(&schema, Group::add_node(h_g1, h_g2)).unwrap();
    let h_diff = state.register(&schema, Group::sub_node(h_sum, h_g1)).unwrap();

    let canonical = state.evaluate(&schema, state.get(&h_diff).unwrap().clone()).unwrap();
    assert_eq!(canonical, Group::new_node(leaf(100).digest(), leaf(200).digest()));
}

#[test]
fn new_canonicalises_field_expression_children_end_to_end() {
    let (schema, mut state) = schema_and_state();
    // x as field expression leaf(3)+leaf(4), y as a plain leaf.
    let h_3 = state.register(&schema, leaf(3)).unwrap();
    let h_4 = state.register(&schema, leaf(4)).unwrap();
    let h_x_expr = state
        .register(&schema, Node::expression(Uint::add_tag(), Payload::binary_op(h_3, h_4)))
        .unwrap();
    let h_y = state.register(&schema, leaf(5)).unwrap();
    let h_new = state.register(&schema, Group::new_node(h_x_expr, h_y)).unwrap();

    let canonical = state.evaluate(&schema, state.get(&h_new).unwrap().clone()).unwrap();
    let expected = Group::new_node(leaf(7).digest(), leaf(5).digest());
    assert_eq!(canonical, expected);
}

// CAPABILITY UNIT TESTS (relocated from the old in-lib `mock_group` unit tests)
// ================================================================================================

#[test]
fn new_self_evaluates_when_children_are_leaves() {
    let (schema, mut state) = fresh();
    let h_g = register_group(&schema, &mut state, 3, 4);
    let g = state.get(&h_g).unwrap().clone();
    let canonical = state.evaluate(&schema, g.clone()).unwrap();
    assert_eq!(canonical, g, "new over field leaves is self-evaluating");
}

#[test]
fn new_canonicalises_field_expression_children() {
    let (schema, mut state) = fresh();
    let h_3 = state.register(&schema, leaf(3)).unwrap();
    let h_4 = state.register(&schema, leaf(4)).unwrap();
    let h_x_expr = state
        .register(&schema, Node::expression(Uint::add_tag(), Payload::binary_op(h_3, h_4)))
        .unwrap();
    let h_y = state.register(&schema, leaf(5)).unwrap();
    let new_over_expr = Group::new_node(h_x_expr, h_y);
    let h_new = state.register(&schema, new_over_expr).unwrap();

    let canonical = state.evaluate(&schema, state.get(&h_new).unwrap().clone()).unwrap();
    let expected = Group::new_node(leaf(7).digest(), leaf(5).digest());
    assert_eq!(canonical, expected);
}

#[test]
fn add_mints_new_field_leaves_and_returns_new() {
    let (schema, mut state) = fresh();
    let h_g1 = register_group(&schema, &mut state, 3, 4);
    let h_g2 = register_group(&schema, &mut state, 10, 20);

    let canonical = state.evaluate(&schema, Group::add_node(h_g1, h_g2)).unwrap();
    let expected = Group::new_node(leaf(13).digest(), leaf(24).digest());
    assert_eq!(canonical, expected);
    assert!(state.contains(&leaf(13).digest()), "minted x-coord leaf must be interned");
    assert!(state.contains(&leaf(24).digest()), "minted y-coord leaf must be interned");
}

#[test]
fn sub_mints_new_field_leaves_and_returns_new() {
    let (schema, mut state) = fresh();
    let h_g1 = register_group(&schema, &mut state, 100, 50);
    let h_g2 = register_group(&schema, &mut state, 30, 20);

    let canonical = state.evaluate(&schema, Group::sub_node(h_g1, h_g2)).unwrap();
    let expected = Group::new_node(leaf(70).digest(), leaf(30).digest());
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
    assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
}

#[test]
fn eq_predicate_commutes_over_minted_children() {
    // Locks in that `witness.intern` writes minted children to `state.nodes`. After `Group::Add`
    // evaluates and mints x3=13 / y3=24, a separately-registered
    // `val = Group::new(leaf(13).digest(), leaf(24).digest())` references those digests directly
    // without the leaves being explicitly registered. The eq predicate must succeed regardless
    // of operand order — i.e. resolution must not depend on which side reduces first.
    let (schema, mut state) = fresh();
    let h_g1 = register_group(&schema, &mut state, 3, 4);
    let h_g2 = register_group(&schema, &mut state, 10, 20);
    let h_g_add = state.register(&schema, Group::add_node(h_g1, h_g2)).unwrap();
    let h_val = state
        .register(&schema, Group::new_node(leaf(13).digest(), leaf(24).digest()))
        .unwrap();

    // Pre-evaluate g_add so its mints (leaf(13), leaf(24)) land in state.nodes.
    state.evaluate(&schema, state.get(&h_g_add).unwrap().clone()).unwrap();
    assert!(state.contains(&leaf(13).digest()), "x3 minted into nodes");
    assert!(state.contains(&leaf(24).digest()), "y3 minted into nodes");

    let mut state_normal = state.clone();
    let normal = state_normal.evaluate(&schema, Group::eq_node(h_g_add, h_val)).unwrap();
    assert!(normal.is_true_node(), "Eq(g_add, val) holds");

    let mut state_swapped = state.clone();
    let swapped = state_swapped.evaluate(&schema, Group::eq_node(h_val, h_g_add)).unwrap();
    assert!(swapped.is_true_node(), "Eq(val, g_add) holds — operand order doesn't matter");
}

#[test]
fn reduce_rejects_new_with_non_field_leaf_children() {
    // Children resolve to canonical leaves but their tag is *not* the field leaf tag —
    // new must reject.
    let (schema, mut state) = fresh();
    let h_g = register_group(&schema, &mut state, 1, 1);
    let h_y = state.register(&schema, leaf(2)).unwrap();
    let bad_new = Group::new_node(h_g, h_y);
    let err = state.evaluate(&schema, bad_new);
    assert!(matches!(
        err.unwrap_err().root(),
        PrecompileError::Other(_) | PrecompileError::InvalidNode
    ));
}
