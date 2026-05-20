//! Generic Schwartz-Zippel-based u256 modmul. The MASM verifier checks
//! `a(x) * b(x) - q(x) * p(x) - c(x) - (W - x) * (e_pos(x) - e_neg(x)) = 0`
//! at a Fiat-Shamir-derived point in the quadratic extension of the Miden base field, where
//! `e_pos` and `e_neg` are the non-negative halves of the signed carry polynomial.
//!
//! This module derives the advice witness and Fiat-Shamir challenge consumed by the generated
//! MASM verifiers. Per-curve event handlers in `u256_modmul_k1.rs` are thin wrappers that supply
//! the prime constants and delegate to [`handle_modmul`].

use alloc::{vec, vec::Vec};

use miden_core::{Felt, crypto::hash::Poseidon2};
use miden_processor::{ProcessorState, advice::AdviceMutation, event::EventError};

pub(crate) const U16_LIMBS_PER_OPERAND: usize = 16;
/// Each signed-carry half is stored in 32 slots; the VM asserts that the top two slots are zero.
pub(crate) const NUM_CARRY_COEFFS: usize = 32;
/// Limb base for the u16-limb Schwartz-Zippel modmul family.
const W: i64 = 1 << 16;

/// Output of [`compute_modmul_witness`]: everything the SZ verifier needs to check
/// `a * b = q * p + c`.
///
/// Fields:
/// - `q_u16`, `c_u16`: quotient and remainder of the division, as u16 limbs.
/// - `e_pos`, `e_neg`: non-negative halves of the signed carry polynomial (verified carry
///   is `e_pos - e_neg`).
/// - `alpha`: Fiat-Shamir challenge in the quadratic extension of the Miden base field,
///   stored as two base felts.
///
/// `#[doc(hidden)]`: exposed only for verifier-level negative tests
/// (see `tests/math/u256_modmul_k1_traps.rs`). Not a stable public API.
#[doc(hidden)]
pub struct ModmulWitness {
    pub q_u16: [u16; U16_LIMBS_PER_OPERAND],
    pub c_u16: [u16; U16_LIMBS_PER_OPERAND],
    pub e_pos: [u32; NUM_CARRY_COEFFS],
    pub e_neg: [u32; NUM_CARRY_COEFFS],
    pub alpha: [Felt; 2],
}

/// Reads `b` from operand-stack offsets 1..9 and `a` from offsets 9..17, computes the
/// witness for the Schwartz-Zippel check that `a * b = q * p + c` holds, and derives the
/// Fiat-Shamir challenge `alpha`. Returns everything in a [`ModmulWitness`].
///
/// `#[doc(hidden)]`: exposed only for verifier-level negative tests. Not a stable public API.
#[doc(hidden)]
pub fn compute_modmul_witness(
    process: &ProcessorState,
    prime_u16: &[u16; U16_LIMBS_PER_OPERAND],
    prime_u32: &[u32; 8],
) -> Result<ModmulWitness, EventError> {
    let b_u32 = read_u32_limbs(process, 1, "b")?;
    let a_u32 = read_u32_limbs(process, 9, "a")?;
    let ab_u32x16 = full_mul_u32(&a_u32, &b_u32);
    let (q_u32, c_u32) = u512_divmod_u256(ab_u32x16, *prime_u32)?;
    let a_u16 = u32_to_u16_limbs(&a_u32);
    let b_u16 = u32_to_u16_limbs(&b_u32);
    let q_u16 = u32_to_u16_limbs(&q_u32);
    let c_u16 = u32_to_u16_limbs(&c_u32);
    let (e_pos, e_neg) = compute_carry_polys(&a_u16, &b_u16, &q_u16, &c_u16, prime_u16);
    let alpha = derive_alpha(prime_u16, &a_u32, &b_u32, &q_u16, &c_u16, &e_pos, &e_neg);
    Ok(ModmulWitness { q_u16, c_u16, e_pos, e_neg, alpha })
}

/// Poseidon2 sponge state after absorbing the modulus (16 u16 limbs, natural low-to-high
/// order, two rate-8 chunks) from a zero-initialized state.
///
/// Used as the initial FS transcript state in place of zeros. This domain-separates each
/// modulus: an alpha derived for `a * b mod p` cannot be reused for `a * b mod n` even with
/// identical witness limbs.
///
/// Only the capacity lanes (`state[8..12]`) are load-bearing. The first online absorb
/// overwrites the rate lanes before the next permutation, so the MASM verifier embeds just
/// those four felts and uses `padw padw` for the rate.
///
/// Mirrored by `sz-codegen`'s `modulus_seeded_initial_state`. Cross-crate agreement is
/// pinned by `k1_{base,scalar}_precomputed_initial_state_pin`.
#[doc(hidden)]
pub fn modulus_seeded_initial_state(
    prime_u16: &[u16; U16_LIMBS_PER_OPERAND],
) -> [Felt; Poseidon2::STATE_WIDTH] {
    const RATE: usize = 8;
    const _: () = assert!(U16_LIMBS_PER_OPERAND.is_multiple_of(8));
    let n_chunks = U16_LIMBS_PER_OPERAND / RATE;
    let mut state = [Felt::ZERO; Poseidon2::STATE_WIDTH];
    for chunk_idx in 0..n_chunks {
        for j in 0..RATE {
            state[j] = Felt::from_u32(prime_u16[chunk_idx * RATE + j] as u32);
        }
        Poseidon2::apply_permutation(&mut state);
    }
    state
}

/// Witness handler for the generated SZ u256 modmul verifier. Pushes
/// `[alpha_1, alpha_0, q_15..q_0, c_15..c_0, e_pos_31..e_pos_0, e_neg_31..e_neg_0]` (98 felts)
/// for the MASM verifier in `u256_sz_modmul_*` to consume.
pub fn handle_modmul(
    process: &ProcessorState,
    prime_u16: &[u16; U16_LIMBS_PER_OPERAND],
    prime_u32: &[u32; 8],
) -> Result<Vec<AdviceMutation>, EventError> {
    let w = compute_modmul_witness(process, prime_u16, prime_u32)?;

    let capacity = 2 + 2 * U16_LIMBS_PER_OPERAND + 2 * NUM_CARRY_COEFFS;
    let mut advice: Vec<Felt> = Vec::with_capacity(capacity);
    advice.push(w.alpha[1]);
    advice.push(w.alpha[0]);
    advice.extend(w.q_u16.iter().rev().map(|&v| Felt::from_u32(v as u32)));
    advice.extend(w.c_u16.iter().rev().map(|&v| Felt::from_u32(v as u32)));
    advice.extend(w.e_pos.iter().rev().map(|&v| Felt::from_u32(v)));
    advice.extend(w.e_neg.iter().rev().map(|&v| Felt::from_u32(v)));

    debug_assert_eq!(advice.len(), capacity);
    Ok(vec![AdviceMutation::extend_stack(advice)])
}

/// Derives the Fiat-Shamir challenge alpha by hashing the 112-felt transcript
/// `a (8) || b (8) || q_reversed (16) || c_reversed (16) || e_pos_reversed (32)
/// || e_neg_reversed (32)` into a Poseidon2 sponge seeded by [`modulus_seeded_initial_state`].
///
/// The MASM verifier in `u256_sz_modmul_*` performs the same absorption: precomputed capacity
/// + zero rate, then `mem_stream` of (a, b), then `adv_pipe` of the 96-felt packed witness.
///
/// `#[doc(hidden)]`: exposed only so verifier-level negative tests can re-derive alpha for
/// synthetic witnesses (see `tests/math/u256_modmul_k1_traps.rs`). Not a stable public API.
#[doc(hidden)]
pub fn derive_alpha(
    prime_u16: &[u16; U16_LIMBS_PER_OPERAND],
    a_u32: &[u32; 8],
    b_u32: &[u32; 8],
    q_u16: &[u16; U16_LIMBS_PER_OPERAND],
    c_u16: &[u16; U16_LIMBS_PER_OPERAND],
    e_pos: &[u32; NUM_CARRY_COEFFS],
    e_neg: &[u32; NUM_CARRY_COEFFS],
) -> [Felt; 2] {
    const HASH_INPUT_LEN: usize =
        8 + 8 + U16_LIMBS_PER_OPERAND + U16_LIMBS_PER_OPERAND + 2 * NUM_CARRY_COEFFS;
    const _: () = assert!(HASH_INPUT_LEN.is_multiple_of(8));

    let mut input: Vec<Felt> = Vec::with_capacity(HASH_INPUT_LEN);
    input.extend(a_u32.iter().map(|&v| Felt::from_u32(v)));
    input.extend(b_u32.iter().map(|&v| Felt::from_u32(v)));
    input.extend(q_u16.iter().rev().map(|&v| Felt::from_u32(v as u32)));
    input.extend(c_u16.iter().rev().map(|&v| Felt::from_u32(v as u32)));
    input.extend(e_pos.iter().rev().map(|&v| Felt::from_u32(v)));
    input.extend(e_neg.iter().rev().map(|&v| Felt::from_u32(v)));
    debug_assert_eq!(input.len(), HASH_INPUT_LEN);

    let mut state = modulus_seeded_initial_state(prime_u16);
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
    for i in 0..8 {
        let limb = process.get_stack_item(start + i).as_canonical_u64();
        if limb > u32::MAX as u64 {
            return Err(ModMulError::NotU32Value {
                value: limb,
                position: name,
                limb_index: i,
            }
            .into());
        }
        out[i] = limb as u32;
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

/// Computes the split carry polynomials `(e_pos, e_neg)` for
/// `a(x) * b(x) - q(x) * p(x) - c(x) = (W - x) * (e_pos(x) - e_neg(x))` over u16 limbs.
/// The signed integer carry `e[k] = (conv_k(a,b) - conv_k(q,p) - c_k + e[k-1]) / W` is split
/// into two non-negative parts: `e_pos[k] = max(e[k], 0)`, `e_neg[k] = max(-e[k], 0)`. Each
/// is bounded by ~2^21 (well within u32).
///
/// For 16-limb modmul, `a*b - q*p - c` has degree at most 30, so `(W - x) * e(x)` forces
/// `deg(e) <= 29`. We still store each signed-carry half in 32 slots so each half occupies
/// four rate-8 advice/Horner chunks; slots 30 and 31 are therefore zero and asserted by the
/// MASM verifier.
///
/// `#[doc(hidden)]`: exposed only so verifier-level negative tests can recompute the carry
/// polynomials for synthetic witnesses (see `tests/math/u256_modmul_k1_traps.rs`). Not a
/// stable public API.
#[doc(hidden)]
pub fn compute_carry_polys(
    a: &[u16; U16_LIMBS_PER_OPERAND],
    b: &[u16; U16_LIMBS_PER_OPERAND],
    q: &[u16; U16_LIMBS_PER_OPERAND],
    c: &[u16; U16_LIMBS_PER_OPERAND],
    p: &[u16; U16_LIMBS_PER_OPERAND],
) -> ([u32; NUM_CARRY_COEFFS], [u32; NUM_CARRY_COEFFS]) {
    const N: usize = U16_LIMBS_PER_OPERAND;
    const CONV_LEN: usize = 2 * N - 1;

    // conv_ab[k] = sum_{i+j=k} a_i * b_j; conv_qp[k] = sum_{i+j=k} q_i * p_j.
    let mut conv_ab = [0i64; CONV_LEN];
    let mut conv_qp = [0i64; CONV_LEN];
    for i in 0..N {
        for j in 0..N {
            conv_ab[i + j] += (a[i] as i64) * (b[j] as i64);
            conv_qp[i + j] += (q[i] as i64) * (p[j] as i64);
        }
    }

    let mut e_signed = [0i64; NUM_CARRY_COEFFS];
    let mut prev_carry: i64 = 0;
    for k in 0..CONV_LEN {
        let c_k = if k < N { c[k] as i64 } else { 0 };
        let lhs = conv_ab[k] - conv_qp[k] - c_k + prev_carry;
        debug_assert!(lhs.rem_euclid(W) == 0, "carry recurrence not divisible by W");
        let next = lhs.div_euclid(W);
        // Bound is ~2^21; soundness only needs the u32 check on the verifier side.
        debug_assert!(next.unsigned_abs() < 1 << 24, "|carry| larger than expected (got {next})");
        e_signed[k] = next;
        prev_carry = next;
    }
    // `prev_carry` after the final iteration equals `e_signed[CONV_LEN - 1] = e_signed[30]`;
    // zero means the carry recurrence closes. The Rust witness array is explicitly initialized
    // to zero, and this loop never writes `e_signed[31]`, so the honest witness has slot 31 = 0.
    // The generated MASM still asserts both top slots against the prover-supplied advice.
    debug_assert_eq!(prev_carry, 0, "final carry must be 0 (a*b = q*p + c as integers)");

    let mut e_pos = [0u32; NUM_CARRY_COEFFS];
    let mut e_neg = [0u32; NUM_CARRY_COEFFS];
    for k in 0..NUM_CARRY_COEFFS {
        if e_signed[k] >= 0 {
            e_pos[k] = e_signed[k] as u32;
        } else {
            e_neg[k] = (-e_signed[k]) as u32;
        }
    }
    (e_pos, e_neg)
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
