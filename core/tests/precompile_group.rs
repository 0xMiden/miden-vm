//! Integration coverage for compound canonicals minted by the mock group precompile.

mod common;

use std::sync::Arc;

use common::{leaf, register_and_evaluate};
use miden_core::{
    deferred::{DeferredState, Digest, Node, PrecompileError, PrecompileRegistry},
    testing::precompile::{Group, Uint},
};

/// Builds a uint+group registry with an empty state for tests that assert node counts.
fn fresh() -> (Arc<PrecompileRegistry>, DeferredState) {
    let registry =
        Arc::new(PrecompileRegistry::default().with_precompile(Uint).with_precompile(Group));
    let state = DeferredState::new(Arc::clone(&registry), usize::MAX).unwrap();
    (registry, state)
}

/// Builds the same registry with uint constants pre-registered.
fn registry_and_state() -> (Arc<PrecompileRegistry>, DeferredState) {
    fresh()
}

fn register_group(
    _registry: &Arc<PrecompileRegistry>,
    state: &mut DeferredState,
    x: u64,
    y: u64,
) -> Digest {
    let h_x = state.register(leaf(x)).unwrap();
    let h_y = state.register(leaf(y)).unwrap();
    state.register(Group::new_node(h_x, h_y)).unwrap()
}

#[test]
fn add_produces_minted_new_and_passes_eq_against_expected() {
    let (registry, mut state) = registry_and_state();

    let h_g1 = register_group(&registry, &mut state, 3, 4);
    let h_g2 = register_group(&registry, &mut state, 10, 20);

    // Evaluate add: returns new(h_x3_leaf, h_y3_leaf) where leaves are minted.
    let add_canonical = register_and_evaluate(&registry, &mut state, Group::add_node(h_g1, h_g2));
    let expected = Group::new_node(leaf(13).digest(), leaf(24).digest());
    assert_eq!(add_canonical, expected);

    // Both minted field leaves must be in the DAG.
    assert_eq!(state.evaluate(leaf(13).digest()).unwrap(), leaf(13));
    assert_eq!(state.evaluate(leaf(24).digest()).unwrap(), leaf(24));

    // Build expected group element via registration, then assert eq.
    let h_expected = register_group(&registry, &mut state, 13, 24);
    let h_add = state.register(Group::add_node(h_g1, h_g2)).unwrap();
    let eq_result = register_and_evaluate(&registry, &mut state, Group::eq_node(h_add, h_expected));
    assert!(eq_result.is_true_node());

    // Defense-in-depth: log the proven equality and round-trip the transcript — this re-runs
    // the Group evaluation (including its mid-evaluation minting) through rehydrate.
    common::log_and_verify(&registry, &mut state, Group::eq_node(h_add, h_expected));
}

#[test]
fn sub_chains_through_add_with_mint_at_every_step() {
    let (registry, mut state) = registry_and_state();

    // ((g1 + g2) - g1)  should equal g2 under coord-wise mock arithmetic.
    let h_g1 = register_group(&registry, &mut state, 7, 11);
    let h_g2 = register_group(&registry, &mut state, 100, 200);

    let h_sum = state.register(Group::add_node(h_g1, h_g2)).unwrap();
    let h_diff = state.register(Group::sub_node(h_sum, h_g1)).unwrap();

    let canonical = state.evaluate(h_diff).unwrap();
    assert_eq!(canonical, Group::new_node(leaf(100).digest(), leaf(200).digest()));
}

#[test]
fn new_preserves_field_expression_commitments() {
    let (registry, mut state) = fresh();

    let h_3 = state.register(leaf(3)).unwrap();
    let h_4 = state.register(leaf(4)).unwrap();
    let h_5 = state.register(leaf(5)).unwrap();
    let h_6 = state.register(leaf(6)).unwrap();

    let h_x_expr = state.register(Node::join(Uint::add_tag(), h_3, h_4)).unwrap();
    let h_y_expr = state.register(Node::join(Uint::add_tag(), h_5, h_6)).unwrap();

    let h_group = state.register(Group::new_node(h_x_expr, h_y_expr)).unwrap();

    let canonical = state.evaluate(h_group).unwrap();

    assert_eq!(
        canonical,
        Group::new_node(h_x_expr, h_y_expr),
        "new must preserve coordinate expression commitments"
    );

    assert_ne!(
        canonical,
        Group::new_node(leaf(7).digest(), leaf(11).digest()),
        "new must not evaluate coordinates to value leaves in its canonical payload"
    );

    let (h_x, h_y) = canonical.payload.join_children().unwrap();
    assert_eq!(h_x, h_x_expr);
    assert_eq!(h_y, h_y_expr);

    let h_value_group = register_group(&registry, &mut state, 7, 11);
    common::log_and_verify(&registry, &mut state, Group::eq_node(h_group, h_value_group));
}

#[test]
fn eq_predicate_errors_on_mismatch() {
    let (registry, mut state) = fresh();
    let h_g1 = register_group(&registry, &mut state, 7, 11);
    let h_g2 = register_group(&registry, &mut state, 7, 12);
    let eq_digest = state.register(Group::eq_node(h_g1, h_g2)).unwrap();
    let err = state.evaluate(eq_digest);
    assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
}

#[test]
fn eq_compares_coordinate_values_not_coordinate_commitments() {
    let (registry, mut state) = fresh();

    let h_3 = state.register(leaf(3)).unwrap();
    let h_4 = state.register(leaf(4)).unwrap();
    let h_5 = state.register(leaf(5)).unwrap();

    let h_x_expr = state.register(Node::join(Uint::add_tag(), h_3, h_4)).unwrap();
    let h_expr_group = state.register(Group::new_node(h_x_expr, h_5)).unwrap();

    let h_value_group = register_group(&registry, &mut state, 7, 5);

    let result =
        register_and_evaluate(&registry, &mut state, Group::eq_node(h_expr_group, h_value_group));

    assert!(result.is_true_node(), "new(add(3, 4), 5) must equal new(7, 5)");

    let swapped =
        register_and_evaluate(&registry, &mut state, Group::eq_node(h_value_group, h_expr_group));

    assert!(swapped.is_true_node(), "group equality should not depend on operand order");

    common::log_and_verify(&registry, &mut state, Group::eq_node(h_expr_group, h_value_group));
    common::log_and_verify(&registry, &mut state, Group::eq_node(h_value_group, h_expr_group));
}

#[test]
fn add_resolves_expression_backed_coordinates_and_mints_value_leaves() {
    let (registry, mut state) = fresh();

    let h_3 = state.register(leaf(3)).unwrap();
    let h_4 = state.register(leaf(4)).unwrap();
    let h_5 = state.register(leaf(5)).unwrap();
    let h_6 = state.register(leaf(6)).unwrap();

    let h_x_expr = state.register(Node::join(Uint::add_tag(), h_3, h_4)).unwrap();
    let h_y_expr = state.register(Node::join(Uint::add_tag(), h_5, h_6)).unwrap();

    let h_g1 = state.register(Group::new_node(h_x_expr, h_y_expr)).unwrap();

    let h_g2 = register_group(&registry, &mut state, 10, 20);

    let canonical = register_and_evaluate(&registry, &mut state, Group::add_node(h_g1, h_g2));

    let expected = Group::new_node(leaf(17).digest(), leaf(31).digest());
    assert_eq!(canonical, expected);

    assert_eq!(state.evaluate(leaf(17).digest()).unwrap(), leaf(17));
    assert_eq!(state.evaluate(leaf(31).digest()).unwrap(), leaf(31));

    let h_add = state.register(Group::add_node(h_g1, h_g2)).unwrap();
    let h_expected = register_group(&registry, &mut state, 17, 31);
    common::log_and_verify(&registry, &mut state, Group::eq_node(h_add, h_expected));
}

#[test]
fn new_requires_coordinate_expression_commitments_to_be_registered() {
    let (_registry, mut state) = fresh();

    let h_3 = state.register(leaf(3)).unwrap();
    let h_4 = state.register(leaf(4)).unwrap();
    let h_y = state.register(leaf(5)).unwrap();

    let x_expr = Node::join(Uint::add_tag(), h_3, h_4);
    let h_x_expr = x_expr.digest();

    let err = state.register(Group::new_node(h_x_expr, h_y)).unwrap_err();
    assert!(matches!(err.root(), PrecompileError::MissingNode));

    state.register(x_expr).unwrap();
    let h_group = state.register(Group::new_node(h_x_expr, h_y)).unwrap();
    let canonical = state.evaluate(h_group).unwrap();
    assert_eq!(canonical, Group::new_node(h_x_expr, h_y));
}

#[test]
fn eq_predicate_commutes_over_minted_children() {
    // Locks in that `DeferredContext::register` writes minted children to `state.nodes`. After
    // `Group::Add` evaluates and mints x3=13 / y3=24, a separately-registered
    // `val = Group::new(leaf(13).digest(), leaf(24).digest())` references those digests directly
    // without the leaves being explicitly registered. The eq predicate must succeed regardless
    // of operand order — i.e. resolution must not depend on which side evaluates first.
    let (registry, mut state) = fresh();
    let h_g1 = register_group(&registry, &mut state, 3, 4);
    let h_g2 = register_group(&registry, &mut state, 10, 20);
    let h_g_add = state.register(Group::add_node(h_g1, h_g2)).unwrap();

    // Pre-evaluate g_add so its mints (leaf(13), leaf(24)) land in state.nodes.
    state.evaluate(h_g_add).unwrap();
    let h_val = state.register(Group::new_node(leaf(13).digest(), leaf(24).digest())).unwrap();
    assert_eq!(state.evaluate(leaf(13).digest()).unwrap(), leaf(13));
    assert_eq!(state.evaluate(leaf(24).digest()).unwrap(), leaf(24));

    let mut state_normal = state.clone();
    let normal =
        register_and_evaluate(&registry, &mut state_normal, Group::eq_node(h_g_add, h_val));
    assert!(normal.is_true_node(), "Eq(g_add, val) holds");

    let mut state_swapped = state.clone();
    let swapped =
        register_and_evaluate(&registry, &mut state_swapped, Group::eq_node(h_val, h_g_add));
    assert!(swapped.is_true_node(), "Eq(val, g_add) holds — operand order doesn't matter");
}

#[test]
fn evaluate_rejects_new_with_non_field_leaf_children() {
    // Children resolve to canonical leaves but their tag is *not* the field leaf tag —
    // new must reject.
    let (registry, mut state) = fresh();
    let h_g = register_group(&registry, &mut state, 1, 1);
    let h_y = state.register(leaf(2)).unwrap();
    let bad_new = state.register(Group::new_node(h_g, h_y)).unwrap();
    let err = state.evaluate(bad_new);
    assert!(matches!(
        err.unwrap_err().root(),
        PrecompileError::Other(_) | PrecompileError::InvalidNode
    ));
}
