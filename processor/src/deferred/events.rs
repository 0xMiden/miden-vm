//! The three generic system event handlers for the deferred-DAG subsystem.
//!
//! These are intercepted by [`DefaultHost`](crate::DefaultHost) before its event-registry
//! dispatch (mirroring how the VM intercepts `SystemEvent`s): the [`EventHandler`] trait's
//! `&self` signature precludes mutating the host-owned deferred state, so handlers live here as
//! free functions with `&mut DeferredState` access.
//!
//! v1 stack layout (position 0 is top, event_id already consumed by the caller):
//! - `RegisterLeaf` / `RegisterOp`: positions `1..5` hold tag felts, positions `5..13` hold
//!   payload felts.
//! - `AssertEq`: positions `1..5` hold tag felts, `5..9` hold `lhs_digest`, `9..13` hold
//!   `rhs_digest`.

use alloc::vec::Vec;

use miden_core::{
    Felt,
    deferred::{DeferredError, DeferredTag, Digest, Node, Payload, TagKind, hash_node},
};

use super::{
    registry::TypeHandlerRegistry,
    state::DeferredState,
    transaction::{DeferredMutation, HandlerTransaction},
};

// EVENT NAMES
// ================================================================================================

/// Event name for the "register a canonical-leaf node" system event.
pub const EVENT_REGISTER_LEAF: &str = "deferred::register_leaf";
/// Event name for the "register a binary-op node" system event.
pub const EVENT_REGISTER_OP: &str = "deferred::register_op";
/// Event name for the "assert two DAG values evaluate equal" system event.
pub const EVENT_ASSERT_EQ: &str = "deferred::assert_eq";

// REGISTER (LEAF | OP)
// ================================================================================================

/// Decode a (tag, payload) from the stack, insert the resulting node into the DAG, and return
/// the digest so the caller can push it onto the advice stack.
///
/// `expected_kind` is `Leaf` for `RegisterLeaf` and `BinaryOp` for `RegisterOp`; a tag whose
/// `kind()` does not match is rejected as `InvalidTag`. The handler does not validate payload
/// well-formedness — that is the type-handler's job and only surfaces when an evaluator visits
/// the node.
pub fn register_node(
    state: &mut DeferredState,
    registry: &TypeHandlerRegistry,
    tag: DeferredTag,
    payload: Payload,
    expected_kind: TagKind,
) -> Result<Digest, DeferredError> {
    if tag.kind() != expected_kind {
        return Err(DeferredError::InvalidTag);
    }
    // Routing-only check: an unknown prefix can never be evaluated, so reject at registration.
    registry.get(tag.type_prefix())?;

    let node = Node::new(tag, payload);
    let digest = hash_node(tag, &payload);

    let txn = HandlerTransaction {
        deferred: alloc::vec![DeferredMutation::InsertNode { digest, node }],
        vm: Vec::new(),
    };
    state.apply(&txn)?;
    Ok(digest)
}

// ASSERT-EQ EVALUATION
// ================================================================================================

/// Recursively evaluate the node at `digest` to a canonical-leaf `(tag, payload)` pair.
///
/// Reduction is delegated to the value type's handler at every internal node — this function
/// owns only the recursion plumbing. Cycles are impossible by construction (digests address
/// children) so no visited-set is needed.
fn evaluate(
    state: &DeferredState,
    registry: &TypeHandlerRegistry,
    digest: Digest,
) -> Result<(DeferredTag, Payload), DeferredError> {
    let node = state.get(&digest).ok_or(DeferredError::MissingNode)?;
    match node.tag.kind() {
        TagKind::Leaf => Ok((node.tag, node.payload)),
        TagKind::BinaryOp => {
            let (lhs_digest, rhs_digest) =
                node.binary_op_children().ok_or(DeferredError::InvalidTag)?;
            let lhs = evaluate(state, registry, lhs_digest)?;
            let rhs = evaluate(state, registry, rhs_digest)?;
            let handler = registry.get(node.tag.type_prefix())?;
            handler.eval_op(node.tag, lhs, rhs)
        },
        TagKind::AssertEq => Err(DeferredError::InvalidTag),
    }
}

/// Drives an `AssertEq` event: evaluate both sides, compare via the type handler's equality,
/// then record the assertion. The processor is not the verifier — recording is the point.
pub fn assert_eq(
    state: &mut DeferredState,
    registry: &TypeHandlerRegistry,
    tag: DeferredTag,
    lhs_digest: Digest,
    rhs_digest: Digest,
) -> Result<(), DeferredError> {
    if tag.kind() != TagKind::AssertEq {
        return Err(DeferredError::InvalidTag);
    }
    let handler = registry.get(tag.type_prefix())?;

    let (_, lhs_value) = evaluate(state, registry, lhs_digest)?;
    let (_, rhs_value) = evaluate(state, registry, rhs_digest)?;

    if !handler.values_equal(&lhs_value, &rhs_value) {
        return Err(DeferredError::AssertionFailed);
    }

    let txn = HandlerTransaction {
        deferred: alloc::vec![DeferredMutation::AppendAssertion(
            miden_core::deferred::Assertion::new(tag, lhs_digest, rhs_digest),
        )],
        vm: Vec::new(),
    };
    state.apply(&txn)
}

// PAYLOAD HELPERS
// ================================================================================================

/// Build the payload of a binary-op node from two child digests in `(lhs, rhs)` order.
pub fn binary_op_payload(lhs: Digest, rhs: Digest) -> Payload {
    let mut felts: [Felt; 8] = [Felt::from_u32(0); 8];
    felts[0..4].copy_from_slice(lhs.as_elements());
    felts[4..8].copy_from_slice(rhs.as_elements());
    Payload::new(felts)
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use miden_core::{
        Felt, Word,
        deferred::{DeferredTag, Payload},
    };

    use super::*;
    use crate::deferred::handlers::Field0Handler;

    fn make_registry() -> TypeHandlerRegistry {
        let mut reg = TypeHandlerRegistry::new();
        reg.register(Arc::new(Field0Handler)).unwrap();
        reg
    }

    fn field0_leaf(low: u64) -> (DeferredTag, Payload) {
        let mut limbs = [Felt::from_u32(0); 8];
        limbs[0] = Felt::from_u32(low as u32);
        limbs[1] = Felt::from_u32((low >> 32) as u32);
        (DeferredTag::Field0Leaf, Payload::new(limbs))
    }

    #[test]
    fn register_leaf_stores_node_and_returns_correct_digest() {
        let mut state = DeferredState::new();
        let reg = make_registry();
        let (tag, payload) = field0_leaf(7);

        let digest = register_node(&mut state, &reg, tag, payload, TagKind::Leaf).unwrap();

        assert_eq!(digest, hash_node(tag, &payload));
        assert_eq!(state.get(&digest), Some(&Node::new(tag, payload)));
    }

    #[test]
    fn register_with_wrong_kind_errors() {
        let mut state = DeferredState::new();
        let reg = make_registry();
        let (tag, payload) = field0_leaf(1);

        // Calling register_node with BinaryOp expectation on a Leaf tag must fail.
        let err = register_node(&mut state, &reg, tag, payload, TagKind::BinaryOp);
        assert!(matches!(err, Err(DeferredError::InvalidTag)));
    }

    #[test]
    fn register_op_stores_op_node() {
        let mut state = DeferredState::new();
        let reg = make_registry();
        let (a_tag, a_payload) = field0_leaf(3);
        let (b_tag, b_payload) = field0_leaf(4);
        let a = register_node(&mut state, &reg, a_tag, a_payload, TagKind::Leaf).unwrap();
        let b = register_node(&mut state, &reg, b_tag, b_payload, TagKind::Leaf).unwrap();

        let op_payload = binary_op_payload(a, b);
        let digest =
            register_node(&mut state, &reg, DeferredTag::Field0Add, op_payload, TagKind::BinaryOp)
                .unwrap();

        assert!(state.contains(&digest));
    }

    #[test]
    fn assert_eq_succeeds_when_values_match() {
        let mut state = DeferredState::new();
        let reg = make_registry();
        let (a_tag, a_payload) = field0_leaf(3);
        let (b_tag, b_payload) = field0_leaf(4);
        let (sum_tag, sum_payload) = field0_leaf(7);
        let a = register_node(&mut state, &reg, a_tag, a_payload, TagKind::Leaf).unwrap();
        let b = register_node(&mut state, &reg, b_tag, b_payload, TagKind::Leaf).unwrap();
        let sum = register_node(&mut state, &reg, sum_tag, sum_payload, TagKind::Leaf).unwrap();
        let add = register_node(
            &mut state,
            &reg,
            DeferredTag::Field0Add,
            binary_op_payload(a, b),
            TagKind::BinaryOp,
        )
        .unwrap();

        assert_eq(&mut state, &reg, DeferredTag::Field0AssertEq, add, sum).unwrap();
        assert_eq!(state.assertions().len(), 1);
    }

    #[test]
    fn assert_eq_fails_on_mismatch() {
        let mut state = DeferredState::new();
        let reg = make_registry();
        let (a_tag, a_payload) = field0_leaf(3);
        let (b_tag, b_payload) = field0_leaf(4);
        let (wrong_tag, wrong_payload) = field0_leaf(99);
        let a = register_node(&mut state, &reg, a_tag, a_payload, TagKind::Leaf).unwrap();
        let b = register_node(&mut state, &reg, b_tag, b_payload, TagKind::Leaf).unwrap();
        let wrong =
            register_node(&mut state, &reg, wrong_tag, wrong_payload, TagKind::Leaf).unwrap();
        let add = register_node(
            &mut state,
            &reg,
            DeferredTag::Field0Add,
            binary_op_payload(a, b),
            TagKind::BinaryOp,
        )
        .unwrap();

        let err = assert_eq(&mut state, &reg, DeferredTag::Field0AssertEq, add, wrong);
        assert!(matches!(err, Err(DeferredError::AssertionFailed)));
        // Failed assertion is not recorded.
        assert!(state.assertions().is_empty());
    }

    #[test]
    fn assert_eq_missing_node_errors() {
        let mut state = DeferredState::new();
        let reg = make_registry();
        let (a_tag, a_payload) = field0_leaf(1);
        let a = register_node(&mut state, &reg, a_tag, a_payload, TagKind::Leaf).unwrap();
        let dangling = Word::new([Felt::from_u32(0xdead); 4]);

        let err = assert_eq(&mut state, &reg, DeferredTag::Field0AssertEq, a, dangling);
        assert!(matches!(err, Err(DeferredError::MissingNode)));
    }

    #[test]
    fn assert_eq_with_non_asserteq_tag_errors() {
        let mut state = DeferredState::new();
        let reg = make_registry();
        let (a_tag, a_payload) = field0_leaf(1);
        let a = register_node(&mut state, &reg, a_tag, a_payload, TagKind::Leaf).unwrap();

        let err = assert_eq(&mut state, &reg, DeferredTag::Field0Add, a, a);
        assert!(matches!(err, Err(DeferredError::InvalidTag)));
    }

    #[test]
    fn nested_evaluation_reduces_through_op_tree() {
        // Build (a + b) * c, then assert equal to a leaf holding (a + b) * c precomputed.
        let mut state = DeferredState::new();
        let reg = make_registry();
        let (a_tag, a_payload) = field0_leaf(3);
        let (b_tag, b_payload) = field0_leaf(4);
        let (c_tag, c_payload) = field0_leaf(5);
        let (expected_tag, expected_payload) = field0_leaf(35); // (3 + 4) * 5
        let a = register_node(&mut state, &reg, a_tag, a_payload, TagKind::Leaf).unwrap();
        let b = register_node(&mut state, &reg, b_tag, b_payload, TagKind::Leaf).unwrap();
        let c = register_node(&mut state, &reg, c_tag, c_payload, TagKind::Leaf).unwrap();
        let expected =
            register_node(&mut state, &reg, expected_tag, expected_payload, TagKind::Leaf).unwrap();
        let add = register_node(
            &mut state,
            &reg,
            DeferredTag::Field0Add,
            binary_op_payload(a, b),
            TagKind::BinaryOp,
        )
        .unwrap();
        let mul = register_node(
            &mut state,
            &reg,
            DeferredTag::Field0Mul,
            binary_op_payload(add, c),
            TagKind::BinaryOp,
        )
        .unwrap();

        assert_eq(&mut state, &reg, DeferredTag::Field0AssertEq, mul, expected).unwrap();
        assert_eq!(state.assertions().len(), 1);
    }
}
