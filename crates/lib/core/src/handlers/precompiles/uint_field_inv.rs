//! Host event handler for generated uint prime-field inverse wrappers.

use alloc::{vec, vec::Vec};

use miden_core::{Felt, Word, events::EventName};
use miden_precompiles::{UintNodeRef, UintPrecompile};
use miden_processor::{
    ProcessorState,
    advice::{AdviceMutation, AdviceStack},
    event::EventError,
};

/// Event used by generated field uint wrappers to request an inverse witness from the host.
pub const UINT_FIELD_INV_EVENT_NAME: EventName =
    EventName::new("miden::precompiles::fields::field_inv");

/// Resolves the input uint value digest from deferred state, computes its inverse in the encoded
/// prime-field domain, and pushes the inverse limbs onto the advice stack for MASM validation.
pub fn handle_uint_field_inv(
    process: &ProcessorState<'_>,
) -> Result<Vec<AdviceMutation>, EventError> {
    let input_digest = process.get_stack_word(1);
    let (_, canonical_node) = process.require_canonical_deferred_node(input_digest)?;

    let Some(UintNodeRef::Value { domain, limbs: value }) =
        UintPrecompile::decode_node(canonical_node)?
    else {
        return Err(UintFieldInvError::ExpectedUintValue.into());
    };
    if !domain.is_prime_field() {
        return Err(UintFieldInvError::UnsupportedDomain.into());
    }

    let inverse = domain.inv(value).ok_or(UintFieldInvError::ZeroValue)?;

    let inverse = inverse.map(Felt::from_u32);
    let mut advice_stack = AdviceStack::new();
    // Generated MASM consumes the inverse with two `adv_pushw` calls: low limbs, then high limbs.
    advice_stack.append_dword([
        Word::new([inverse[0], inverse[1], inverse[2], inverse[3]]),
        Word::new([inverse[4], inverse[5], inverse[6], inverse[7]]),
    ]);

    Ok(vec![AdviceMutation::extend_advice_stack(advice_stack)])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum UintFieldInvError {
    #[error("expected a canonical uint VALUE node")]
    ExpectedUintValue,
    #[error("uint domain is not a declared prime field")]
    UnsupportedDomain,
    #[error("cannot invert zero in a finite field")]
    ZeroValue,
}
