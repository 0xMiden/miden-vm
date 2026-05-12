mod field0;

pub use field0::Field0Handler;

use alloc::vec::Vec;

use miden_core::{
    Felt,
    deferred::{DeferredError, DeferredTag, Payload, ValueType},
};

/// Per-value-type semantics for the deferred DAG.
///
/// One implementor per `ValueType` (e.g. `Field0Handler` for native-field arithmetic). Generic
/// DAG plumbing — stack parsing, hashing, insertion, reachability — lives in the system event
/// handlers and the [`super::DeferredState`]; this trait owns only the algebraic operations.
///
/// Tag dispatch lives in [`super::registry::TypeHandlerRegistry`]: every `DeferredTag` is routed
/// to the handler whose [`type_prefix`](Self::type_prefix) matches the tag's first two felts.
pub trait DeferredTypeHandler: Send + Sync {
    /// The value type this handler implements.
    fn value_type(&self) -> ValueType;

    /// The two-felt prefix that identifies all tags this handler claims.
    ///
    /// Must equal `tag.type_prefix()` for every variant this handler accepts in
    /// [`eval_op`](Self::eval_op).
    fn type_prefix(&self) -> [Felt; 2];

    /// The tag used for canonical (already-evaluated) leaves of this value type.
    fn canonical_leaf_tag(&self) -> DeferredTag;

    /// Reduce a binary op on two evaluated operands to a new canonical leaf.
    ///
    /// `op_tag.kind()` is guaranteed by the caller to be `BinaryOp` and to route to this
    /// handler's prefix. `lhs` and `rhs` are the recursively-evaluated operands as
    /// `(tag, payload)` pairs — typically both this handler's canonical leaf tag, but the
    /// trait does not constrain that. The handler is responsible for rejecting operand-tag
    /// combinations it does not support (e.g. mixed value types) with
    /// [`DeferredError::InvalidPayload`].
    fn eval_op(
        &self,
        op_tag: DeferredTag,
        lhs: (DeferredTag, Payload),
        rhs: (DeferredTag, Payload),
    ) -> Result<(DeferredTag, Payload), DeferredError>;

    /// Equality on canonical-leaf payloads of this value type.
    ///
    /// Default is bitwise. Override for value types whose canonical representation is
    /// non-unique (e.g. unreduced limbs that must be normalized before comparison).
    fn values_equal(&self, lhs: &Payload, rhs: &Payload) -> bool {
        lhs.0 == rhs.0
    }

    /// Encode a canonical-leaf payload as advice felts.
    ///
    /// Shim for the future `GetValue` system event. Not exercised in v1 but defined now so the
    /// trait surface is stable.
    fn encode_advice(&self, payload: &Payload) -> Result<Vec<Felt>, DeferredError>;
}
