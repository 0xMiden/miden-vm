//! Host event handlers for uint wrapper advice.

use alloc::{sync::Arc, vec, vec::Vec};

use miden_core::{Felt, ZERO, events::EventName};
use miden_processor::{
    ProcessorState,
    advice::AdviceMutation,
    event::{EventError, EventHandler},
};

use super::{UintDomain, precompile::UintPrecompile};

/// Event used by generated field uint wrappers to request an inverse witness from the host.
pub(crate) const UINT_FIELD_INV_EVENT_NAME: EventName =
    EventName::new("miden::precompiles::math::uint::field_inv");

/// Returns the uint field inverse handler entry expected by [`miden_processor::HostLibrary`].
pub(crate) fn field_inv_event_handler() -> (EventName, Arc<dyn EventHandler>) {
    (UINT_FIELD_INV_EVENT_NAME, Arc::new(UintFieldInvHandler))
}

struct UintFieldInvHandler;

impl EventHandler for UintFieldInvHandler {
    fn on_event(&self, process: &ProcessorState<'_>) -> Result<Vec<AdviceMutation>, EventError> {
        let input_digest = process.get_stack_word(1);
        let (_, canonical_node) = process.require_canonical_deferred_node(input_digest)?;

        let tag = canonical_node.tag();
        let [op_id, bound_ptr, reserved] = tag.args();
        if op_id.as_canonical_u64() != UintPrecompile::VALUE_OP_ID || reserved != ZERO {
            return Err(UintFieldInvError::ExpectedUintValue.into());
        }

        if tag.id() != UintPrecompile::id() {
            return Err(UintFieldInvError::ExpectedUintPrecompile.into());
        }
        let bound_ptr = bound_ptr.as_canonical_u64();
        if bound_ptr > u32::MAX as u64 {
            return Err(UintFieldInvError::UnknownDomain.into());
        }
        let domain =
            UintDomain::from_bound_ptr(bound_ptr as u32).ok_or(UintFieldInvError::UnknownDomain)?;
        if !domain.is_prime_field() {
            return Err(UintFieldInvError::UnsupportedDomain.into());
        }

        let value = UintPrecompile::limbs_from_value_node(canonical_node, domain)
            .map_err(|_| UintFieldInvError::ExpectedUintValue)?;
        let inverse = domain.inv(value).ok_or(UintFieldInvError::ZeroValue)?;

        Ok(vec![AdviceMutation::extend_stack(inverse.map(Felt::from_u32))])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum UintFieldInvError {
    #[error("expected uint deferred precompile")]
    ExpectedUintPrecompile,
    #[error("expected a canonical uint VALUE node")]
    ExpectedUintValue,
    #[error("unknown uint domain")]
    UnknownDomain,
    #[error("uint domain is not a declared prime field")]
    UnsupportedDomain,
    #[error("cannot invert zero in a finite field")]
    ZeroValue,
}
