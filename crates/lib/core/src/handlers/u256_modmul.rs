//! Shared witness logic for the generated Schwartz-Zippel u256 modmul verifiers. The MASM
//! verifier checks
//! `a(x) * b(x) - q(x) * m(x) - c(x) - (W - x) * (e_shifted(x) - offset(x)) = 0`
//! at a Fiat-Shamir-derived point in the quadratic extension of the Miden base field. The carry
//! polynomial is shifted (`e_shifted = signed_carry + CARRY_SHIFT` per coefficient) so every
//! landed felt is a valid u32; the fixed `offset = [CARRY_SHIFT; NUM_CARRY_COEFFS]` polynomial,
//! pinned alongside the modulus, undoes the shift inside the identity.
//!
//! Contract mirrored by the generated MASM:
//! - operand-stack inputs are u256 values: 8 limbs, each bounded to u32;
//! - accepted witnesses return a canonical residue `c = a * b mod m`, with `c < m`;
//! - the standard handler is complete when `floor(a * b / m) < 2^256`;
//! - this holds if either input is canonical (`< m`) and the other is any well-formed u256;
//! - malformed witness advice traps.
//!
//! Per-curve event handlers in `u256_modmul_k1.rs` are thin wrappers that supply the modulus
//! constants and delegate to [`handle_modmul`].

use alloc::{vec, vec::Vec};

use miden_core::{Felt, crypto::hash::Poseidon2};
use miden_processor::{ProcessorState, advice::AdviceMutation, event::EventError};

pub(crate) const U16_LIMBS_PER_OPERAND: usize = 16;
/// Slot count for the shifted carry polynomial. The verifier pins the top two slots to
/// [`CARRY_SHIFT`] (the shifted encoding of zero).
pub(crate) const NUM_CARRY_COEFFS: usize = 32;
/// Limb base for the u16-limb Schwartz-Zippel modmul family.
const W: i64 = 1 << 16;
/// Host-side shift added to every signed-carry coefficient so the landed felt is always a valid
/// u32. The verifier subtracts the fixed offset polynomial inside the identity.
pub(crate) const CARRY_SHIFT: u32 = 1 << 31;

/// Output of [`compute_modmul_witness`]: everything the SZ verifier needs to check
/// `a * b = q * m + c`.
///
/// Fields:
/// - `q_u16`, `c_u16`: quotient and remainder, as u16 limbs.
/// - `e_shifted`: signed carry polynomial in shifted form (`signed + CARRY_SHIFT` per coefficient).
/// - `alpha`: Fiat-Shamir challenge in the quadratic extension, as two base felts.
///
/// `#[doc(hidden)]`: exposed only for verifier-level negative tests
/// (see `tests/math/u256_modmul_k1_traps.rs`). Not a stable public API.
#[doc(hidden)]
pub struct ModmulWitness {
    pub q_u16: [u16; U16_LIMBS_PER_OPERAND],
    pub c_u16: [u16; U16_LIMBS_PER_OPERAND],
    pub e_shifted: [u32; NUM_CARRY_COEFFS],
    pub alpha: [Felt; 2],
}

/// Reads `b` from operand-stack offsets 1..9 and `a` from offsets 9..17, requiring every limb
/// to be a valid u32. Computes the witness for the Schwartz-Zippel check that
/// `a * b = q * m + c` holds, and derives the Fiat-Shamir challenge `alpha`.
///
/// Returns an error if the quotient does not fit in u256. That is a completeness condition for
/// the standard handler, not a soundness assumption for an accepted MASM execution.
///
/// `#[doc(hidden)]`: exposed only for verifier-level negative tests. Not a stable public API.
#[doc(hidden)]
pub fn compute_modmul_witness(
    process: &ProcessorState,
    modulus_u16: &[u16; U16_LIMBS_PER_OPERAND],
    modulus_u32: &[u32; 8],
) -> Result<ModmulWitness, EventError> {
    let b_u32 = read_u32_limbs(process, 1, "b")?;
    let a_u32 = read_u32_limbs(process, 9, "a")?;
    let ab_u32x16 = full_mul_u32(&a_u32, &b_u32);
    let (q_u32, c_u32) = u512_divmod_u256(ab_u32x16, *modulus_u32)?;
    let a_u16 = u32_to_u16_limbs(&a_u32);
    let b_u16 = u32_to_u16_limbs(&b_u32);
    let q_u16 = u32_to_u16_limbs(&q_u32);
    let c_u16 = u32_to_u16_limbs(&c_u32);
    let e_shifted = compute_carry_poly(&a_u16, &b_u16, &q_u16, &c_u16, modulus_u16);
    let alpha = derive_alpha(modulus_u16, &a_u32, &b_u32, &q_u16, &c_u16, &e_shifted);
    Ok(ModmulWitness { q_u16, c_u16, e_shifted, alpha })
}

/// Poseidon2 sponge state after the verifier absorbs the fixed-statement prefix: modulus
/// followed by `[CARRY_SHIFT; NUM_CARRY_COEFFS]`. Both are absorbed high-limb first, 8 limbs
/// per chunk, matching the MASM verifier's `adv_pipe` consumption.
///
/// Mirrored by `sz-codegen`'s `fixed_prefix_seeded_initial_state`; cross-crate agreement is
/// pinned by `k1_{base,scalar}_precomputed_initial_state_pin`.
#[doc(hidden)]
pub fn fixed_prefix_seeded_initial_state(
    modulus_u16: &[u16; U16_LIMBS_PER_OPERAND],
) -> [Felt; Poseidon2::STATE_WIDTH] {
    const RATE: usize = 8;
    const _: () = assert!(U16_LIMBS_PER_OPERAND.is_multiple_of(8));
    const _: () = assert!(NUM_CARRY_COEFFS.is_multiple_of(8));
    let mut state = [Felt::ZERO; Poseidon2::STATE_WIDTH];
    for chunk_idx in 0..(U16_LIMBS_PER_OPERAND / RATE) {
        for j in 0..RATE {
            state[j] =
                Felt::from_u32(modulus_u16[modulus_u16.len() - 1 - (chunk_idx * RATE + j)] as u32);
        }
        Poseidon2::apply_permutation(&mut state);
    }
    for _ in 0..(NUM_CARRY_COEFFS / RATE) {
        for cell in state.iter_mut().take(RATE) {
            *cell = Felt::from_u32(CARRY_SHIFT);
        }
        Poseidon2::apply_permutation(&mut state);
    }
    state
}

/// Witness handler for the generated SZ u256 modmul verifier. Pushes
/// `[alpha_1, alpha_0, modulus_15..modulus_0, offset_31..offset_0, q_15..q_0, c_15..c_0,
/// e_shifted_31..e_shifted_0]` for the MASM verifier in `u256_sz_modmul_*` to consume. The
/// offset block is the constant `[CARRY_SHIFT; NUM_CARRY_COEFFS]` vector pinned with the
/// modulus, not a witness commitment.
pub fn handle_modmul(
    process: &ProcessorState,
    modulus_u16: &[u16; U16_LIMBS_PER_OPERAND],
    modulus_u32: &[u32; 8],
) -> Result<Vec<AdviceMutation>, EventError> {
    let w = compute_modmul_witness(process, modulus_u16, modulus_u32)?;

    let capacity = 2 + 3 * U16_LIMBS_PER_OPERAND + 2 * NUM_CARRY_COEFFS;
    let mut advice: Vec<Felt> = Vec::with_capacity(capacity);
    advice.push(w.alpha[1]);
    advice.push(w.alpha[0]);
    advice.extend(modulus_u16.iter().rev().map(|&v| Felt::from_u32(v as u32)));
    advice.extend(core::iter::repeat_n(Felt::from_u32(CARRY_SHIFT), NUM_CARRY_COEFFS));
    advice.extend(w.q_u16.iter().rev().map(|&v| Felt::from_u32(v as u32)));
    advice.extend(w.c_u16.iter().rev().map(|&v| Felt::from_u32(v as u32)));
    advice.extend(w.e_shifted.iter().rev().map(|&v| Felt::from_u32(v)));

    debug_assert_eq!(advice.len(), capacity);
    Ok(vec![AdviceMutation::extend_stack(advice)])
}

/// Derives the Fiat-Shamir challenge alpha by starting from [`fixed_prefix_seeded_initial_state`]
/// (the post-(modulus + offset) sponge state) and hashing the 80-felt transcript
/// `a (8) || b (8) || q_reversed (16) || c_reversed (16) || e_shifted_reversed (32)`. The MASM
/// verifier reaches the same seeded state via the combined-pin check and the same transcript
/// order, so the two derivations agree.
///
/// `#[doc(hidden)]`: exposed only so verifier-level negative tests can re-derive alpha for
/// synthetic witnesses (see `tests/math/u256_modmul_k1_traps.rs`). Not a stable public API.
#[doc(hidden)]
pub fn derive_alpha(
    modulus_u16: &[u16; U16_LIMBS_PER_OPERAND],
    a_u32: &[u32; 8],
    b_u32: &[u32; 8],
    q_u16: &[u16; U16_LIMBS_PER_OPERAND],
    c_u16: &[u16; U16_LIMBS_PER_OPERAND],
    e_shifted: &[u32; NUM_CARRY_COEFFS],
) -> [Felt; 2] {
    const HASH_INPUT_LEN: usize =
        8 + 8 + U16_LIMBS_PER_OPERAND + U16_LIMBS_PER_OPERAND + NUM_CARRY_COEFFS;
    const _: () = assert!(HASH_INPUT_LEN.is_multiple_of(8));

    let mut input: Vec<Felt> = Vec::with_capacity(HASH_INPUT_LEN);
    input.extend(a_u32.iter().map(|&v| Felt::from_u32(v)));
    input.extend(b_u32.iter().map(|&v| Felt::from_u32(v)));
    input.extend(q_u16.iter().rev().map(|&v| Felt::from_u32(v as u32)));
    input.extend(c_u16.iter().rev().map(|&v| Felt::from_u32(v as u32)));
    input.extend(e_shifted.iter().rev().map(|&v| Felt::from_u32(v)));
    debug_assert_eq!(input.len(), HASH_INPUT_LEN);

    let mut state = fixed_prefix_seeded_initial_state(modulus_u16);
    for chunk in input.chunks_exact(8) {
        state[..8].copy_from_slice(chunk);
        Poseidon2::apply_permutation(&mut state);
    }
    [state[0], state[1]]
}

// INPUT READING
// ================================================================================================

fn read_u32_limbs(
    process: &ProcessorState,
    start: usize,
    name: &'static str,
) -> Result<[u32; 8], EventError> {
    let mut out = [0u32; 8];
    for (i, slot) in out.iter_mut().enumerate() {
        let limb = process.get_stack_item(start + i).as_canonical_u64();
        if limb > u32::MAX as u64 {
            return Err(ModMulError::NotU32Value {
                value: limb,
                position: name,
                limb_index: i,
            }
            .into());
        }
        *slot = limb as u32;
    }
    Ok(out)
}

fn u32_to_u16_limbs(v: &[u32; 8]) -> [u16; U16_LIMBS_PER_OPERAND] {
    let mut out = [0u16; U16_LIMBS_PER_OPERAND];
    for i in 0..8 {
        out[2 * i] = v[i] as u16;
        out[2 * i + 1] = (v[i] >> 16) as u16;
    }
    out
}

// FULL 256x256 -> 512 PRODUCT
// ================================================================================================

/// Computes the full 512-bit product `a * b` as 16 u32 limbs (little-endian). Uses u128 limb
/// accumulators because per-limb sums of `u32 * u32` products can exceed u64 (up to 8 terms of
/// ~2^64 each).
fn full_mul_u32(a: &[u32; 8], b: &[u32; 8]) -> [u32; 16] {
    let mut acc = [0u128; 16];
    for i in 0..8 {
        for j in 0..8 {
            acc[i + j] += a[i] as u128 * b[j] as u128;
        }
    }
    let mut out = [0u32; 16];
    let mut carry: u128 = 0;
    for k in 0..16 {
        let s = acc[k] + carry;
        out[k] = s as u32;
        carry = s >> 32;
    }
    debug_assert_eq!(carry, 0, "u512 product overflow not possible: a, b < 2^256");
    out
}

// 512/256 LONG DIVISION
// ================================================================================================

/// Computes `(dividend / divisor, dividend % divisor)` for a 512-bit dividend and a 256-bit
/// divisor.
///
/// Preconditions:
/// - `divisor != 0`.
/// - `quotient < 2^256` (i.e. `dividend < divisor * 2^256`); the caller is responsible for ensuring
///   this.
///
/// Correct for any nonzero 256-bit divisor, including divisors with bit 255 set (e.g. the
/// secp256k1 base prime `p_k1 = 2^256 - 2^32 - 977`). The running remainder is shifted left
/// by one bit each iteration and can momentarily occupy 257 bits when the divisor approaches
/// `2^256`; that overflow bit is tracked in `r_overflow`.
fn u512_divmod_u256(
    dividend: [u32; 16],
    divisor: [u32; 8],
) -> Result<([u32; 8], [u32; 8]), ModMulError> {
    if divisor == [0u32; 8] {
        return Err(ModMulError::DivideByZero);
    }

    let d: [u128; 4] = [
        u128_from_u32x4(&dividend[0..4]),
        u128_from_u32x4(&dividend[4..8]),
        u128_from_u32x4(&dividend[8..12]),
        u128_from_u32x4(&dividend[12..16]),
    ];
    let b_lo = u128_from_u32x4(&divisor[0..4]);
    let b_hi = u128_from_u32x4(&divisor[4..8]);

    let (mut q_lo, mut q_hi) = (0u128, 0u128);
    let (mut r_lo, mut r_hi) = (0u128, 0u128);

    for bit in (0..512).rev() {
        // The 257th (overflow) bit of r is whatever was about to fall off the top of r_hi
        // when we shift left below.
        let r_overflow = (r_hi >> 127) & 1 == 1;
        r_hi = (r_hi << 1) | (r_lo >> 127);
        r_lo <<= 1;
        let chunk = bit / 128;
        let bit_in_chunk = bit % 128;
        r_lo |= (d[chunk] >> bit_in_chunk) & 1;

        // r >= b? With r_overflow set, r >= 2^256 > b is automatic.
        let take = r_overflow || r_hi > b_hi || (r_hi == b_hi && r_lo >= b_lo);
        if take {
            let (new_lo, borrow1) = r_lo.overflowing_sub(b_lo);
            r_lo = new_lo;
            let (new_hi, borrow2) = r_hi.overflowing_sub(b_hi);
            let (new_hi, borrow3) = new_hi.overflowing_sub(borrow1 as u128);
            r_hi = new_hi;
            // r >= b before subtraction (we just checked), so any borrow out of r_hi must
            // be paid by r_overflow. After subtraction r_overflow is zero again, which the
            // next iteration recomputes from the new r_hi.
            debug_assert_eq!(borrow2 || borrow3, r_overflow);

            if bit >= 256 {
                return Err(ModMulError::QuotientOverflow { bit });
            }
            if bit < 128 {
                q_lo |= 1u128 << bit;
            } else {
                q_hi |= 1u128 << (bit - 128);
            }
        }
    }

    Ok((u32x8_from_u128_pair(q_lo, q_hi), u32x8_from_u128_pair(r_lo, r_hi)))
}

fn u128_from_u32x4(s: &[u32]) -> u128 {
    debug_assert_eq!(s.len(), 4);
    (s[0] as u128) | ((s[1] as u128) << 32) | ((s[2] as u128) << 64) | ((s[3] as u128) << 96)
}

fn u32x8_from_u128_pair(lo: u128, hi: u128) -> [u32; 8] {
    [
        lo as u32,
        (lo >> 32) as u32,
        (lo >> 64) as u32,
        (lo >> 96) as u32,
        hi as u32,
        (hi >> 32) as u32,
        (hi >> 64) as u32,
        (hi >> 96) as u32,
    ]
}

// CARRY POLYNOMIALS
// ================================================================================================

/// Computes the shifted carry polynomial `e_shifted` for the identity
/// `a(x) * b(x) - q(x) * m(x) - c(x) = (W - x) * (e_shifted(x) - offset(x))` over u16 limbs.
///
/// The signed integer carry `e[k] = (conv_k(a,b) - conv_k(q,m) - c_k + e[k-1]) / W` satisfies
/// `|e[k]| < 2^21`; shifting by [`CARRY_SHIFT`] keeps each coefficient inside u32 while staying
/// far from the wrap boundary. Because `(W - x) * e(x)` has degree 30, `deg(e) <= 29`, so
/// `e_shifted[30] = e_shifted[31] = CARRY_SHIFT` always.
///
/// `#[doc(hidden)]`: exposed only so verifier-level negative tests can recompute the carry
/// polynomial for synthetic witnesses (see `tests/math/u256_modmul_k1_traps.rs`). Not a
/// stable public API.
#[doc(hidden)]
pub fn compute_carry_poly(
    a: &[u16; U16_LIMBS_PER_OPERAND],
    b: &[u16; U16_LIMBS_PER_OPERAND],
    q: &[u16; U16_LIMBS_PER_OPERAND],
    c: &[u16; U16_LIMBS_PER_OPERAND],
    modulus: &[u16; U16_LIMBS_PER_OPERAND],
) -> [u32; NUM_CARRY_COEFFS] {
    const N: usize = U16_LIMBS_PER_OPERAND;
    const CONV_LEN: usize = 2 * N - 1;

    let mut conv_ab = [0i64; CONV_LEN];
    let mut conv_qm = [0i64; CONV_LEN];
    for i in 0..N {
        for j in 0..N {
            conv_ab[i + j] += (a[i] as i64) * (b[j] as i64);
            conv_qm[i + j] += (q[i] as i64) * (modulus[j] as i64);
        }
    }

    let mut e_signed = [0i64; NUM_CARRY_COEFFS];
    let mut prev_carry: i64 = 0;
    for k in 0..CONV_LEN {
        let c_k = if k < N { c[k] as i64 } else { 0 };
        let lhs = conv_ab[k] - conv_qm[k] - c_k + prev_carry;
        debug_assert!(lhs.rem_euclid(W) == 0, "carry recurrence not divisible by W");
        let next = lhs.div_euclid(W);
        debug_assert!(next.unsigned_abs() < 1 << 24, "|carry| larger than expected (got {next})");
        e_signed[k] = next;
        prev_carry = next;
    }
    debug_assert_eq!(prev_carry, 0, "final carry must be 0 (a*b = q*m + c as integers)");

    let mut e_shifted = [CARRY_SHIFT; NUM_CARRY_COEFFS];
    for k in 0..NUM_CARRY_COEFFS {
        e_shifted[k] = (e_signed[k] + CARRY_SHIFT as i64) as u32;
    }
    e_shifted
}

// ERROR TYPES
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum ModMulError {
    #[error("division by zero")]
    DivideByZero,

    #[error("quotient overflows u256 at bit {bit}; caller violated reduced-input precondition")]
    QuotientOverflow { bit: usize },

    #[error("value {value} at {position} limb {limb_index} is not a valid u32")]
    NotU32Value {
        value: u64,
        position: &'static str,
        limb_index: usize,
    },
}
