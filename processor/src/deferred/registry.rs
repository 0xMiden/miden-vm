use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::fmt;

use miden_core::{Felt, deferred::DeferredError};

use super::handlers::DeferredTypeHandler;

/// Routes [`DeferredTag`](miden_core::deferred::DeferredTag)s to their value-type handler.
///
/// Lookup keys on the tag's two-felt type prefix. Every registered handler's
/// [`type_prefix`](DeferredTypeHandler::type_prefix) must be unique — duplicate registrations
/// are rejected.
#[derive(Clone, Default)]
pub struct TypeHandlerRegistry {
    by_prefix: BTreeMap<[Felt; 2], Arc<dyn DeferredTypeHandler>>,
}

impl TypeHandlerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `handler` under its declared `type_prefix()`.
    ///
    /// Returns `ConflictingNode` (reused as a generic "already-registered" signal in v1) if a
    /// handler with the same prefix is already present. Replace by removing the old entry first
    /// in tests; production registrations happen once at host construction.
    pub fn register(&mut self, handler: Arc<dyn DeferredTypeHandler>) -> Result<(), DeferredError> {
        let prefix = handler.type_prefix();
        if self.by_prefix.contains_key(&prefix) {
            return Err(DeferredError::ConflictingNode);
        }
        self.by_prefix.insert(prefix, handler);
        Ok(())
    }

    /// Look up the handler claiming `prefix`, or `InvalidTag` if none is registered.
    pub fn get(&self, prefix: [Felt; 2]) -> Result<&Arc<dyn DeferredTypeHandler>, DeferredError> {
        self.by_prefix.get(&prefix).ok_or(DeferredError::InvalidTag)
    }

    pub fn contains(&self, prefix: [Felt; 2]) -> bool {
        self.by_prefix.contains_key(&prefix)
    }
}

impl fmt::Debug for TypeHandlerRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefixes: Vec<_> = self.by_prefix.keys().collect();
        f.debug_struct("TypeHandlerRegistry").field("prefixes", &prefixes).finish()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use miden_core::{
        Felt,
        deferred::{DeferredError, DeferredTag, FIELD, FIELD_0, Payload, ValueType},
    };

    use super::*;

    /// Test handler that claims a configurable prefix and rejects every op.
    struct MockHandler {
        prefix: [Felt; 2],
        leaf: DeferredTag,
        value_type: ValueType,
    }

    impl DeferredTypeHandler for MockHandler {
        fn value_type(&self) -> ValueType {
            self.value_type
        }

        fn type_prefix(&self) -> [Felt; 2] {
            self.prefix
        }

        fn canonical_leaf_tag(&self) -> DeferredTag {
            self.leaf
        }

        fn eval_op(
            &self,
            _op_tag: DeferredTag,
            _lhs: (DeferredTag, Payload),
            _rhs: (DeferredTag, Payload),
        ) -> Result<(DeferredTag, Payload), DeferredError> {
            Err(DeferredError::Unsupported)
        }

        fn encode_advice(&self, payload: &Payload) -> Result<vec::Vec<Felt>, DeferredError> {
            Ok(payload.0.to_vec())
        }
    }

    fn field0_handler() -> Arc<dyn DeferredTypeHandler> {
        Arc::new(MockHandler {
            prefix: [FIELD, FIELD_0],
            leaf: DeferredTag::Field0Leaf,
            value_type: ValueType::Field0,
        })
    }

    #[test]
    fn register_then_get_returns_same_prefix() {
        let mut reg = TypeHandlerRegistry::new();
        let h = field0_handler();
        reg.register(h.clone()).unwrap();
        let got = reg.get([FIELD, FIELD_0]).unwrap();
        assert_eq!(got.type_prefix(), [FIELD, FIELD_0]);
        assert_eq!(got.canonical_leaf_tag(), DeferredTag::Field0Leaf);
    }

    #[test]
    fn duplicate_registration_errors() {
        let mut reg = TypeHandlerRegistry::new();
        reg.register(field0_handler()).unwrap();
        assert_eq!(reg.register(field0_handler()), Err(DeferredError::ConflictingNode));
    }

    #[test]
    fn unknown_prefix_errors() {
        let reg = TypeHandlerRegistry::new();
        assert!(matches!(reg.get([FIELD, FIELD_0]), Err(DeferredError::InvalidTag)));
    }

    #[test]
    fn dispatch_routes_to_correct_handler_by_prefix() {
        let mut reg = TypeHandlerRegistry::new();
        let unused_prefix = [Felt::new_unchecked(42), Felt::new_unchecked(7)];
        let other = Arc::new(MockHandler {
            prefix: unused_prefix,
            leaf: DeferredTag::Field0Leaf,
            value_type: ValueType::Field0,
        });
        reg.register(field0_handler()).unwrap();
        reg.register(other).unwrap();

        assert_eq!(reg.get([FIELD, FIELD_0]).unwrap().type_prefix(), [FIELD, FIELD_0]);
        assert_eq!(reg.get(unused_prefix).unwrap().type_prefix(), unused_prefix);
    }
}
