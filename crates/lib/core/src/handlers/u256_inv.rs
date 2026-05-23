//! Generic witness handler for u256 modular inverse via the hint-and-verify pattern.
//!
//! Reads `a` from operand-stack offsets `[1..9]`, computes `inv = a^(-1) mod p` on the host via
//! `BigUint::modpow(a, p-2, p)`, and pushes the 8 u32 limbs of `inv` onto the advice stack in
//! little-endian order so the MASM proc can `adv_pushw` them into local memory.
//!
//! For `a = 0` (or any `a` with no inverse) the host returns 0; the VM-side check
//! `a * inv == 1 mod p` then catches the non-inverse. The handler never errors: the VM-side
//! verifier is the authority for input validation, so any malformed input gets rejected
//! there rather than via a host-side trap.

use alloc::{vec, vec::Vec};

use miden_core::Felt;
use miden_processor::{ProcessorState, advice::AdviceMutation, event::EventError};
use num::{BigUint, traits::Zero};

/// Generic u256 inverse witness handler. Caller supplies the prime as 8 u32 limbs
/// (little-endian); the per-curve wrapper holds the constant.
pub fn handle_inv(
    process: &ProcessorState,
    prime_u32: &[u32; 8],
) -> Result<Vec<AdviceMutation>, EventError> {
    let mut a_u32 = [0u32; 8];
    for (i, limb) in a_u32.iter_mut().enumerate() {
        *limb = process.get_stack_item(1 + i).as_canonical_u64() as u32;
    }

    let bn_a = BigUint::from_slice(&a_u32);
    let bn_p = BigUint::from_slice(prime_u32);

    let bn_inv = if bn_a.is_zero() {
        BigUint::zero()
    } else {
        let bn_p_minus_2 = &bn_p - 2u32;
        bn_a.modpow(&bn_p_minus_2, &bn_p)
    };

    let inv_u32_vec = bn_inv.to_u32_digits();
    let mut inv_u32 = [0u32; 8];
    for (i, &limb) in inv_u32_vec.iter().enumerate().take(8) {
        inv_u32[i] = limb;
    }

    // Push to advice stack: vec[0] is on top of the advice stack and is popped first. The
    // MASM proc consumes inv[0..3] via the first `adv_pushw` and inv[4..7] via the next,
    // landing inv[0] at mem[0] and inv[7] at mem[7].
    let advice: Vec<Felt> = inv_u32.iter().map(|&v| Felt::from_u32(v)).collect();
    Ok(vec![AdviceMutation::extend_stack(advice)])
}
