//! Host event handler for generated uint prime-field inverse wrappers.

use alloc::{vec, vec::Vec};

use miden_core::{
    Felt, ZERO,
    deferred::{DeferredError, Node},
    events::EventName,
};
use miden_precompiles::{Limbs, UintDomain, UintPrecompile};
use miden_processor::{ProcessorState, advice::AdviceMutation, event::EventError};

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

    let tag = canonical_node.tag();
    let [op_id, bound_ptr, reserved] = tag.args();
    if op_id.as_canonical_u64() != UintPrecompile::VALUE_OP_ID || reserved != ZERO {
        return Err(UintFieldInvError::ExpectedUintValue.into());
    }

    if tag.id() != UintPrecompile::id() {
        return Err(UintFieldInvError::ExpectedUintPrecompile.into());
    }
    let bound_ptr = u32::try_from(bound_ptr.as_canonical_u64())
        .map_err(|_| UintFieldInvError::UnknownDomain)?;
    let domain = UintDomain::from_bound_ptr(bound_ptr).ok_or(UintFieldInvError::UnknownDomain)?;
    if !domain.is_prime_field() {
        return Err(UintFieldInvError::UnsupportedDomain.into());
    }

    let value = limbs_from_value_node(canonical_node, domain)
        .map_err(|_| UintFieldInvError::ExpectedUintValue)?;
    let inverse = domain.inv(value).ok_or(UintFieldInvError::ZeroValue)?;

    Ok(vec![AdviceMutation::extend_stack(inverse.map(Felt::from_u32))])
}

fn limbs_from_value_node(node: &Node, domain: UintDomain) -> Result<Limbs, DeferredError> {
    let payload = node.payload_for_tag(UintPrecompile::value_tag(domain))?;
    let limbs = decode_limbs(payload.as_value()?)?;
    if !domain.is_canonical(&limbs) {
        return Err(DeferredError::InvalidPayload);
    }
    Ok(limbs)
}

fn decode_limbs(felts: &[Felt; 8]) -> Result<Limbs, DeferredError> {
    let mut limbs = [0u32; 8];
    for (i, felt) in felts.iter().enumerate() {
        let value = felt.as_canonical_u64();
        if value > u32::MAX as u64 {
            return Err(DeferredError::InvalidPayload);
        }
        limbs[i] = value as u32;
    }
    Ok(limbs)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum UintFieldInvError {
    #[error("expected uint precompile tag")]
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
