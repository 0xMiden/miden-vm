//! Host event handler for generated uint prime-field inverse wrappers.

use miden_core::{Felt, events::EventName};
use miden_event_handler::{AdviceRecorder, EventContext, EventError, InvocationKind};
use miden_precompiles::UintDomain;

/// Event used by generated field uint wrappers to request an inverse witness from the host.
pub const UINT_FIELD_INV_EVENT_NAME: EventName =
    EventName::new("miden::precompiles::fields::field_inv");

/// Reads `[bound_ptr, VALUE_LO, VALUE_HI, ...]` from the event payload and returns inverse limbs
/// as advice. Generated MASM binds the result to the original expression digest.
pub fn handle_uint_field_inv(
    context: EventContext<'_>,
    advice: &mut AdviceRecorder<'_>,
) -> Result<(), EventError> {
    context.kind().require(InvocationKind::Event)?;
    let bound_ptr = u32::try_from(context.stack_item(0).as_canonical_u64())
        .map_err(|_| UintFieldInvError::UnknownDomain)?;
    let domain = UintDomain::from_bound_ptr(bound_ptr).ok_or(UintFieldInvError::UnknownDomain)?;
    if !domain.is_prime_field() {
        return Err(UintFieldInvError::UnsupportedDomain.into());
    }

    let payload = context.read_stack_array::<8>(1);
    let mut value = [0u32; 8];
    for (limb, felt) in value.iter_mut().zip(payload) {
        *limb = u32::try_from(felt.as_canonical_u64())
            .map_err(|_| UintFieldInvError::ExpectedUintValue)?;
    }
    if !domain.is_canonical(&value) {
        return Err(UintFieldInvError::ExpectedUintValue.into());
    }
    let inverse = domain.inv(value).ok_or(UintFieldInvError::ZeroValue)?;

    let inverse = inverse.map(Felt::from_u32);
    // Generated MASM consumes low limbs, then high limbs.
    advice.prepend_stack(inverse);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum UintFieldInvError {
    #[error("expected a canonical uint value")]
    ExpectedUintValue,
    #[error("unknown uint domain")]
    UnknownDomain,
    #[error("uint domain is not a declared prime field")]
    UnsupportedDomain,
    #[error("cannot invert zero in a finite field")]
    ZeroValue,
}
