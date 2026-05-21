//! Integration coverage for the `Uint` reference precompile.
//!
//! Two layers: (1) an end-to-end canary that `miden_core::deferred`'s public surface is
//! sufficient to build a real precompile and drive register/evaluate/assert; (2) the `Uint`
//! arithmetic / canonicality behaviour relocated from the old in-lib unit tests, re-expressed
//! against the public API.

mod common;

use common::precompile::uint::Uint;
use miden_core::deferred::{
    DeferredError, DeferredState, Node, Payload, PrecompileError, PrecompileRegistry,
};

fn leaf(low: u64) -> Node {
    let mut limbs = [0u32; 8];
    limbs[0] = low as u32;
    limbs[1] = (low >> 32) as u32;
    Uint::leaf_node(limbs)
}

// PUBLIC-API CANARY
// ================================================================================================

#[test]
fn end_to_end_register_evaluate_assert_extract() {
    let schema = PrecompileRegistry::default().with_precompile(Uint);
    let mut state = DeferredState::new();

    let a = state.register(&schema, leaf(3)).unwrap();
    let b = state.register(&schema, leaf(4)).unwrap();
    let c = state.register(&schema, leaf(5)).unwrap();
    let expected = state.register(&schema, leaf(35)).unwrap();
    let add = state
        .register(&schema, Node::expression(Uint::add_tag(), Payload::join(a, b)))
        .unwrap();
    let mul = state
        .register(&schema, Node::expression(Uint::mul_tag(), Payload::join(add, c)))
        .unwrap();

    let canonical = state.evaluate(&schema, state.get(&mul).unwrap().clone()).unwrap();
    assert_eq!(canonical, leaf(35));

    // Predicate verification: register interns the eq node; evaluate returns Node::TRUE.
    let assertion = Node::expression(Uint::eq_tag(), Payload::join(mul, expected));
    state.register(&schema, assertion.clone()).unwrap();
    let result = state.evaluate(&schema, assertion).unwrap();
    assert!(result.is_true_node());

    // 6 registered expression nodes + 1 registered eq predicate. evaluate writes only to the
    // canonical_of cache, so canonical(add) = leaf(7) does not appear in `nodes`.
    assert_eq!(state.nodes().len(), 7);
    assert!(!state.contains(&leaf(7).digest()));

    // Defense-in-depth: log the proven equality and round-trip the whole transcript.
    common::log_and_verify(
        &schema,
        &mut state,
        Node::expression(Uint::eq_tag(), Payload::join(mul, expected)),
    );
}

#[test]
fn predicate_mismatch_surfaces_as_error_on_evaluate() {
    let schema = PrecompileRegistry::default().with_precompile(Uint);
    let mut state = DeferredState::new();
    let a = state.register(&schema, leaf(7)).unwrap();
    let b = state.register(&schema, leaf(8)).unwrap();
    let assertion = Node::expression(Uint::eq_tag(), Payload::join(a, b));
    // Register is a pure hint — succeeds even when the predicate doesn't hold.
    state.register(&schema, assertion.clone()).unwrap();
    // The mismatch surfaces only when we explicitly verify.
    let err = state.evaluate(&schema, assertion);
    // The registry wraps the precompile's error with its name; assert the root cause.
    assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
}

#[test]
fn empty_registry_rejects_all_uint_nodes() {
    let schema = PrecompileRegistry::default();
    let mut state = DeferredState::new();
    let err = state.register(&schema, leaf(0));
    assert!(matches!(err, Err(PrecompileError::InvalidNode)));
}

#[test]
fn init_pre_registers_uint_constants() {
    let schema = PrecompileRegistry::default().with_precompile(Uint);
    let mut state = DeferredState::new();
    schema.init(&mut state).unwrap();
    // Three constants: ZERO, ONE, P_MINUS_1.
    assert_eq!(state.nodes().len(), 3);
    assert!(state.contains(&leaf(0).digest()));
    assert!(state.contains(&leaf(1).digest()));
    assert!(state.contains(&Uint::leaf_node([u32::MAX; 8]).digest()));
}

// ARITHMETIC / CANONICALITY (relocated from the old in-lib `uint256` unit tests)
// ================================================================================================

fn leaf_from_u32s(limbs: [u32; 8]) -> Node {
    Uint::leaf_node(limbs)
}

fn leaf_from_low_u64(value: u64) -> Node {
    let mut limbs = [0u32; 8];
    limbs[0] = value as u32;
    limbs[1] = (value >> 32) as u32;
    leaf_from_u32s(limbs)
}

/// Public-API re-expression of the old private `eval_binary`: decode both operands' limbs via
/// the public `Uint::limbs_of`, apply the wrapping op, rebuild a canonical leaf.
fn eval(
    op: fn([u32; 8], [u32; 8]) -> [u32; 8],
    lhs: Node,
    rhs: Node,
) -> Result<Node, DeferredError> {
    let a = Uint::limbs_of(&lhs)?;
    let b = Uint::limbs_of(&rhs)?;
    Ok(Uint::leaf_node(op(a, b)))
}

#[test]
fn add_small_values() {
    let out = eval(Uint::wrap_add, leaf_from_low_u64(3), leaf_from_low_u64(5)).unwrap();
    assert_eq!(out.tag, Uint::leaf_tag());
    assert_eq!(out, leaf_from_low_u64(8));
}

#[test]
fn add_propagates_carry_across_limbs() {
    let mut a_limbs = [0u32; 8];
    a_limbs[0] = u32::MAX;
    let mut b_limbs = [0u32; 8];
    b_limbs[0] = 1;
    let out = eval(Uint::wrap_add, leaf_from_u32s(a_limbs), leaf_from_u32s(b_limbs)).unwrap();
    let mut expected = [0u32; 8];
    expected[1] = 1;
    assert_eq!(out, leaf_from_u32s(expected));
}

#[test]
fn add_wraps_at_2_to_256() {
    let max = leaf_from_u32s([u32::MAX; 8]);
    let one = leaf_from_low_u64(1);
    let out = eval(Uint::wrap_add, max, one).unwrap();
    assert_eq!(out, leaf_from_u32s([0; 8]));
}

#[test]
fn sub_small_values() {
    let out = eval(Uint::wrap_sub, leaf_from_low_u64(10), leaf_from_low_u64(3)).unwrap();
    assert_eq!(out, leaf_from_low_u64(7));
}

#[test]
fn sub_borrows_across_limbs() {
    let mut a_limbs = [0u32; 8];
    a_limbs[1] = 1; // a = 2^32
    let mut b_limbs = [0u32; 8];
    b_limbs[0] = 1;
    let out = eval(Uint::wrap_sub, leaf_from_u32s(a_limbs), leaf_from_u32s(b_limbs)).unwrap();
    // 2^32 - 1 = 0xffffffff in limb 0, zero elsewhere.
    let mut expected = [0u32; 8];
    expected[0] = u32::MAX;
    assert_eq!(out, leaf_from_u32s(expected));
}

#[test]
fn sub_wraps_below_zero() {
    let zero = leaf_from_low_u64(0);
    let one = leaf_from_low_u64(1);
    // 0 - 1 = 2^256 - 1 = [u32::MAX; 8].
    let out = eval(Uint::wrap_sub, zero, one).unwrap();
    assert_eq!(out, leaf_from_u32s([u32::MAX; 8]));
}

#[test]
fn mul_small_values() {
    let out = eval(Uint::wrap_mul, leaf_from_low_u64(6), leaf_from_low_u64(7)).unwrap();
    assert_eq!(out, leaf_from_low_u64(42));
}

#[test]
fn mul_propagates_across_limbs() {
    let mut a_limbs = [0u32; 8];
    a_limbs[1] = 1;
    let b_limbs = a_limbs;
    let out = eval(Uint::wrap_mul, leaf_from_u32s(a_limbs), leaf_from_u32s(b_limbs)).unwrap();
    let mut expected = [0u32; 8];
    expected[2] = 1;
    assert_eq!(out, leaf_from_u32s(expected));
}

#[test]
fn mul_truncates_overflow_above_2_to_256() {
    let mut a_limbs = [0u32; 8];
    a_limbs[7] = 1 << 31;
    let two = leaf_from_low_u64(2);
    let out = eval(Uint::wrap_mul, leaf_from_u32s(a_limbs), two).unwrap();
    assert_eq!(out, leaf_from_u32s([0; 8]));
}

#[test]
fn non_canonical_limb_errors() {
    let bad = Node::expression(
        Uint::leaf_tag(),
        Payload::new([
            miden_core::Felt::new_unchecked(1u64 << 32),
            miden_core::Felt::from_u32(0),
            miden_core::Felt::from_u32(0),
            miden_core::Felt::from_u32(0),
            miden_core::Felt::from_u32(0),
            miden_core::Felt::from_u32(0),
            miden_core::Felt::from_u32(0),
            miden_core::Felt::from_u32(0),
        ]),
    );
    let ok = leaf_from_low_u64(1);
    let err = eval(Uint::wrap_add, bad, ok);
    assert!(matches!(err, Err(DeferredError::InvalidPayload)));
}

#[test]
fn non_leaf_operand_errors() {
    let a = Node::expression(Uint::add_tag(), Payload::new([miden_core::Felt::from_u32(0); 8]));
    let b = leaf_from_low_u64(1);
    let err = eval(Uint::wrap_add, a, b);
    assert!(matches!(err, Err(DeferredError::InvalidPayload)));
}

#[test]
fn id_is_stable_across_calls() {
    assert_eq!(Uint::id(), Uint::id());
}

#[test]
fn init_interns_zero_one_pminus1() {
    let schema = PrecompileRegistry::default().with_precompile(Uint);
    let mut state = DeferredState::new();
    schema.init(&mut state).unwrap();
    assert!(state.contains(&Uint::leaf_node([0; 8]).digest()));
    let mut one = [0u32; 8];
    one[0] = 1;
    assert!(state.contains(&Uint::leaf_node(one).digest()));
    assert!(state.contains(&Uint::leaf_node([u32::MAX; 8]).digest()));
}
