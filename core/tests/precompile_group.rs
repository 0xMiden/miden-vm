//! Integration coverage for compound canonicals minted by the mock group precompile.

mod common;

use common::leaf;
use miden_core::{
    deferred::{DeferredState, Digest, Node, PrecompileError, PrecompileRegistry},
    testing::precompile::{Group, Uint},
};

/// Builds a uint+group schema with an empty state for tests that assert node counts.
fn fresh() -> (PrecompileRegistry, DeferredState) {
    let schema = PrecompileRegistry::default().with_precompile(Uint).with_precompile(Group);
    (schema, DeferredState::new())
}

/// Builds the same schema with uint constants pre-registered.
fn schema_and_state() -> (PrecompileRegistry, DeferredState) {
    let (schema, mut state) = fresh();
    schema.init(&mut state).unwrap();
    (schema, state)
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

#[test]
fn add_produces_minted_new_and_passes_eq_against_expected() {
    let (schema, mut state) = schema_and_state();

    let h_g1 = register_group(&schema, &mut state, 3, 4);
    let h_g2 = register_group(&schema, &mut state, 10, 20);

    // Evaluate add: returns new(h_x3_leaf, h_y3_leaf) where leaves are minted.
    let add_canonical = state.evaluate_node(&schema, Group::add_node(h_g1, h_g2)).unwrap();
    let expected = Group::new_node(leaf(13).digest(), leaf(24).digest());
    assert_eq!(add_canonical, expected);

    // Both minted field leaves must be in the DAG.
    assert!(state.contains(&leaf(13).digest()));
    assert!(state.contains(&leaf(24).digest()));

    // Build expected group element via registration, then assert eq.
    let h_expected = register_group(&schema, &mut state, 13, 24);
    let h_add = state.register(&schema, Group::add_node(h_g1, h_g2)).unwrap();
    let eq_result = state.evaluate_node(&schema, Group::eq_node(h_add, h_expected)).unwrap();
    assert!(eq_result.is_true_node());

    // Defense-in-depth: log the proven equality and round-trip the transcript — this re-runs
    // the Group reduce (including its mid-`reduce` minting) through rehydrate.
    common::log_and_verify(&schema, &mut state, Group::eq_node(h_add, h_expected));
}

#[test]
fn sub_chains_through_add_with_mint_at_every_step() {
    let (schema, mut state) = schema_and_state();

    // ((g1 + g2) - g1)  should equal g2 under coord-wise mock arithmetic.
    let h_g1 = register_group(&schema, &mut state, 7, 11);
    let h_g2 = register_group(&schema, &mut state, 100, 200);

    let h_sum = state.register(&schema, Group::add_node(h_g1, h_g2)).unwrap();
    let h_diff = state.register(&schema, Group::sub_node(h_sum, h_g1)).unwrap();

    let canonical = state.evaluate_digest(&schema, h_diff).unwrap();
    assert_eq!(canonical, Group::new_node(leaf(100).digest(), leaf(200).digest()));
}

#[test]
fn new_self_evaluates_when_children_are_leaves() {
    let (schema, mut state) = fresh();
    let h_g = register_group(&schema, &mut state, 3, 4);
    let g = state.get(&h_g).unwrap().clone();
    let canonical = state.evaluate_node(&schema, g.clone()).unwrap();
    assert_eq!(canonical, g, "new over field leaves is self-evaluating");
}

#[test]
fn new_preserves_field_expression_commitments() {
    let (schema, mut state) = fresh();

    let h_3 = state.register(&schema, leaf(3)).unwrap();
    let h_4 = state.register(&schema, leaf(4)).unwrap();
    let h_5 = state.register(&schema, leaf(5)).unwrap();
    let h_6 = state.register(&schema, leaf(6)).unwrap();

    let h_x_expr = state.register(&schema, Node::join(Uint::add_tag(), h_3, h_4)).unwrap();
    let h_y_expr = state.register(&schema, Node::join(Uint::add_tag(), h_5, h_6)).unwrap();

    let h_group = state.register(&schema, Group::new_node(h_x_expr, h_y_expr)).unwrap();

    let canonical = state.evaluate_digest(&schema, h_group).unwrap();

    assert_eq!(
        canonical,
        Group::new_node(h_x_expr, h_y_expr),
        "new must preserve coordinate expression commitments"
    );

    assert_ne!(
        canonical,
        Group::new_node(leaf(7).digest(), leaf(11).digest()),
        "new must not reduce coordinates to value leaves in its canonical payload"
    );

    let (h_x, h_y) = canonical.payload.join_children().unwrap();
    assert_eq!(h_x, h_x_expr);
    assert_eq!(h_y, h_y_expr);

    let h_value_group = register_group(&schema, &mut state, 7, 11);
    common::log_and_verify(&schema, &mut state, Group::eq_node(h_group, h_value_group));
}

#[test]
fn add_mints_new_field_leaves_and_returns_new() {
    let (schema, mut state) = fresh();
    let h_g1 = register_group(&schema, &mut state, 3, 4);
    let h_g2 = register_group(&schema, &mut state, 10, 20);

    let canonical = state.evaluate_node(&schema, Group::add_node(h_g1, h_g2)).unwrap();
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

    let canonical = state.evaluate_node(&schema, Group::sub_node(h_g1, h_g2)).unwrap();
    let expected = Group::new_node(leaf(70).digest(), leaf(30).digest());
    assert_eq!(canonical, expected);
}

#[test]
fn eq_predicate_matches_on_canonical_equality() {
    let (schema, mut state) = fresh();
    let h_g = register_group(&schema, &mut state, 7, 11);
    let result = state.evaluate_node(&schema, Group::eq_node(h_g, h_g)).unwrap();
    assert!(result.is_true_node());
}

#[test]
fn eq_predicate_errors_on_mismatch() {
    let (schema, mut state) = fresh();
    let h_g1 = register_group(&schema, &mut state, 7, 11);
    let h_g2 = register_group(&schema, &mut state, 7, 12);
    let err = state.evaluate_node(&schema, Group::eq_node(h_g1, h_g2));
    assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
}

#[test]
fn eq_compares_coordinate_values_not_coordinate_commitments() {
    let (schema, mut state) = fresh();

    let h_3 = state.register(&schema, leaf(3)).unwrap();
    let h_4 = state.register(&schema, leaf(4)).unwrap();
    let h_5 = state.register(&schema, leaf(5)).unwrap();

    let h_x_expr = state.register(&schema, Node::join(Uint::add_tag(), h_3, h_4)).unwrap();
    let h_expr_group = state.register(&schema, Group::new_node(h_x_expr, h_5)).unwrap();

    let h_value_group = register_group(&schema, &mut state, 7, 5);

    let result = state
        .evaluate_node(&schema, Group::eq_node(h_expr_group, h_value_group))
        .unwrap();

    assert!(result.is_true_node(), "new(add(3, 4), 5) must equal new(7, 5)");

    let swapped = state
        .evaluate_node(&schema, Group::eq_node(h_value_group, h_expr_group))
        .unwrap();

    assert!(swapped.is_true_node(), "group equality should not depend on operand order");

    common::log_and_verify(&schema, &mut state, Group::eq_node(h_expr_group, h_value_group));
    common::log_and_verify(&schema, &mut state, Group::eq_node(h_value_group, h_expr_group));
}

#[test]
fn expression_backed_group_eq_round_trips_through_wire() {
    let (schema, mut state) = fresh();

    let h_3 = state.register(&schema, leaf(3)).unwrap();
    let h_4 = state.register(&schema, leaf(4)).unwrap();
    let h_5 = state.register(&schema, leaf(5)).unwrap();

    let h_x_expr = state.register(&schema, Node::join(Uint::add_tag(), h_3, h_4)).unwrap();
    let h_expr_group = state.register(&schema, Group::new_node(h_x_expr, h_5)).unwrap();

    let h_value_group = register_group(&schema, &mut state, 7, 5);

    common::log_and_verify(&schema, &mut state, Group::eq_node(h_expr_group, h_value_group));
}

#[test]
fn add_resolves_expression_backed_coordinates_and_mints_value_leaves() {
    let (schema, mut state) = fresh();

    let h_3 = state.register(&schema, leaf(3)).unwrap();
    let h_4 = state.register(&schema, leaf(4)).unwrap();
    let h_5 = state.register(&schema, leaf(5)).unwrap();
    let h_6 = state.register(&schema, leaf(6)).unwrap();

    let h_x_expr = state.register(&schema, Node::join(Uint::add_tag(), h_3, h_4)).unwrap();
    let h_y_expr = state.register(&schema, Node::join(Uint::add_tag(), h_5, h_6)).unwrap();

    let h_g1 = state.register(&schema, Group::new_node(h_x_expr, h_y_expr)).unwrap();

    let h_g2 = register_group(&schema, &mut state, 10, 20);

    let canonical = state.evaluate_node(&schema, Group::add_node(h_g1, h_g2)).unwrap();

    let expected = Group::new_node(leaf(17).digest(), leaf(31).digest());
    assert_eq!(canonical, expected);

    assert!(state.contains(&leaf(17).digest()));
    assert!(state.contains(&leaf(31).digest()));

    let h_add = state.register(&schema, Group::add_node(h_g1, h_g2)).unwrap();
    let h_expected = register_group(&schema, &mut state, 17, 31);
    common::log_and_verify(&schema, &mut state, Group::eq_node(h_add, h_expected));
}

#[test]
fn new_requires_coordinate_expression_commitments_not_eval_memo_only() {
    let (schema, mut state) = fresh();

    let h_3 = state.register(&schema, leaf(3)).unwrap();
    let h_4 = state.register(&schema, leaf(4)).unwrap();
    let h_y = state.register(&schema, leaf(5)).unwrap();

    let x_expr = Node::join(Uint::add_tag(), h_3, h_4);
    let h_x_expr = x_expr.digest();

    // Evaluate directly, but do not register the expression node.
    let x_canonical = state.evaluate_node(&schema, x_expr).unwrap();
    assert_eq!(x_canonical, leaf(7));
    assert!(
        !state.contains(&h_x_expr),
        "direct evaluate should not register the input expression"
    );

    let err = state.evaluate_node(&schema, Group::new_node(h_x_expr, h_y)).unwrap_err();

    assert!(matches!(err.root(), PrecompileError::MissingNode));
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
    state.evaluate_digest(&schema, h_g_add).unwrap();
    assert!(state.contains(&leaf(13).digest()), "x3 minted into nodes");
    assert!(state.contains(&leaf(24).digest()), "y3 minted into nodes");

    let mut state_normal = state.clone();
    let normal = state_normal.evaluate_node(&schema, Group::eq_node(h_g_add, h_val)).unwrap();
    assert!(normal.is_true_node(), "Eq(g_add, val) holds");

    let mut state_swapped = state.clone();
    let swapped = state_swapped.evaluate_node(&schema, Group::eq_node(h_val, h_g_add)).unwrap();
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
    let err = state.evaluate_node(&schema, bad_new);
    assert!(matches!(
        err.unwrap_err().root(),
        PrecompileError::Other(_) | PrecompileError::InvalidNode
    ));
}
