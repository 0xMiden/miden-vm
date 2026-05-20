//! Hint provider for `k1_point::decompress`. The square root is computed by the host in native
//! `BigUint` arithmetic (a `modpow`); the VM never runs the exponentiation chain. The VM only
//! verifies the returned `y` by checking `y^2 == x^3 + 7 mod p_k1` (3 modmul calls plus an
//! equality test) and that `y mod 2 == parity`.
//!
//! For the secp256k1 base prime `p_k1`, `p_k1 mod 4 == 3`, so any square root of `rhs` is
//! given by `rhs^((p_k1 + 1) / 4) mod p_k1`. If `rhs` is not a quadratic residue (the given x
//! does not correspond to any curve point), the value returned here squares to something
//! other than `rhs`, and the VM-side curve-equation check zeros the validity flag.
//!
//! The handler must never error: the VM-side `_decompress_no_trap` accumulates the validity
//! flag without trapping, and a handler error would short-circuit that and break the no-trap
//! contract that `verify_prehash_native` depends on.

use alloc::{vec, vec::Vec};

use miden_core::Felt;
use miden_processor::{
    ProcessorState,
    advice::AdviceMutation,
    event::{EventError, EventName},
};
use num::BigUint;

use crate::handlers::secp256k1_constants::SECP256K1_BASE_PRIME_U32;

/// Event name for the `k1_point::decompress` witness operation.
pub const K1_POINT_DECOMPRESS_EVENT_NAME: EventName =
    EventName::new("miden::core::math::k1_point::decompress");

pub fn handle_k1_point_decompress(
    process: &ProcessorState,
) -> Result<Vec<AdviceMutation>, EventError> {
    // Stack at event-fire time: [event_id, x[0..8], parity, ...]. Non-u32 limbs are truncated
    // and out-of-range parity is masked to the low bit; the VM-side canonical/parity/curve
    // checks catch any resulting mismatch and zero the flag.
    let mut x_u32 = [0u32; 8];
    for i in 0..8 {
        x_u32[i] = process.get_stack_item(1 + i).as_canonical_u64() as u32;
    }
    let parity = (process.get_stack_item(9).as_canonical_u64() as u32) & 1;

    let bn_x = BigUint::from_slice(&x_u32);
    let bn_p = BigUint::from_slice(&SECP256K1_BASE_PRIME_U32);

    let bn_rhs = (&bn_x * &bn_x * &bn_x + BigUint::from(7u32)) % &bn_p;
    let bn_exp = (&bn_p + 1u32) / 4u32;
    let bn_y = bn_rhs.modpow(&bn_exp, &bn_p);

    // Pick the root with the requested parity. y mod 2 = bottom bit of y's lowest u32 limb.
    let y_digits = bn_y.to_u32_digits();
    let y_parity = y_digits.first().copied().unwrap_or(0) & 1;
    let bn_y_correct = if y_parity == parity {
        bn_y
    } else {
        (&bn_p - &bn_y) % &bn_p
    };

    // Pack into 8 u32 limbs (little-endian).
    let y_correct_digits = bn_y_correct.to_u32_digits();
    let mut y_u32 = [0u32; 8];
    for (i, &limb) in y_correct_digits.iter().enumerate().take(8) {
        y_u32[i] = limb;
    }

    // Push to advice stack: vec[0] is on top of the advice and is popped first. The MASM proc
    // consumes y[0..3] via the first `adv_pushw` and y[4..7] via the next.
    let advice: Vec<Felt> = y_u32.iter().map(|&v| Felt::from_u32(v)).collect();
    Ok(vec![AdviceMutation::extend_stack(advice)])
}
