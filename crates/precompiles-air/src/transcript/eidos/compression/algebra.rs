//! Shared expression-level helpers for the Eidos compression main and lookup constraints.

use miden_core::field::PrimeCharacteristicRing;

use super::{layout::*, schedule::EIDOS_COMPRESSION_IV};

#[inline]
pub(super) fn xor_from_and<E: PrimeCharacteristicRing>(lhs: E, rhs: E, and: E) -> E {
    lhs + rhs - and.clone() - and
}

#[inline]
pub(super) fn pack_u32_le<E: PrimeCharacteristicRing>(b0: E, b1: E, b2: E, b3: E) -> E {
    b0 + E::from_u64(1 << 8) * b1 + E::from_u64(1 << 16) * b2 + E::from_u64(1 << 24) * b3
}

/// Sum of the four B input words represented by one row's rotation-input byte fields.
pub(super) fn sum_input_b<E, A>(at: A) -> E
where
    E: PrimeCharacteristicRing,
    A: Fn(usize) -> E,
{
    (0..NUM_G).fold(E::ZERO, |sum, g| sum + packed_fused_bytes(&at, G_BD_ROT_SLOT_BASE_COL, g, 0))
}

/// Reconstructs the one uncommitted rotation result from the next row's total B input and the
/// other fifteen committed rotation contributions.
pub(super) fn missing_rotation_result<E, A, B>(local: A, next: B) -> E
where
    E: PrimeCharacteristicRing,
    A: Fn(usize) -> E,
    B: Fn(usize) -> E,
{
    let stored_results = (0..NUM_G).fold(E::ZERO, |sum, g| {
        sum + (0..BYTES_PER_WORD).fold(E::ZERO, |lane_sum, byte| {
            match g_bd_rot_result_col(g, byte) {
                Some(col) => lane_sum + local(col),
                None => lane_sum,
            }
        })
    });
    sum_input_b(next) - stored_results
}

/// Returns one raw initial-CV word through a row-independent linear expression.
///
/// For lanes zero through three the expression is `A + C - IV`, reconstructed from the fused
/// additions. On the first fused row `C = IV`, so it equals the input A word. A footer row uses its
/// otherwise-unconstrained k2 coordinate to correct the same expression to the required CV word.
///
/// For lanes four through seven the expression is the fused B input. One byte coordinate per lane
/// is reserved as the footer correction. All eight encodings remain linear in committed cells.
pub(in crate::transcript::eidos) fn universal_cv_word<E, A>(at: A, idx: usize) -> E
where
    E: PrimeCharacteristicRing,
    A: Fn(usize) -> E,
{
    cv_word_base(&at, idx) + cv_storage_coefficient::<E>(idx) * at(F_CV_STORAGE_COLS[idx])
        - cv_storage_offset::<E>(idx)
}

pub(super) fn cv_word_base<E, A>(at: &A, idx: usize) -> E
where
    E: PrimeCharacteristicRing,
    A: Fn(usize) -> E,
{
    if idx < NUM_G {
        let a_new = packed_fused_bytes(at, G_AC_BYTE_SLOT_BASE_COL, idx, 1);
        let b = packed_fused_bytes(at, G_BD_ROT_SLOT_BASE_COL, idx, 0);
        let c_new = packed_fused_bytes(at, G_BD_ROT_SLOT_BASE_COL, idx, 1);
        let input_a =
            a_new + E::from_u64(1u64 << 32) * at(g_k3_col(idx)) - b - at(g_msg_word_col(idx));
        input_a + c_new - d_new_rot16(at, idx)
    } else {
        let g = idx - NUM_G;
        let storage_byte = F_CV_B_STORAGE_BYTES[g];
        (0..BYTES_PER_WORD).fold(E::ZERO, |acc, byte| {
            if byte == storage_byte {
                acc
            } else {
                acc + E::from_u64(1 << (8 * byte)) * at(g_bd_rot_slot_col(g, byte, 0))
            }
        })
    }
}

pub(super) fn cv_storage_coefficient<E: PrimeCharacteristicRing>(idx: usize) -> E {
    if idx < NUM_G {
        E::from_u64(1u64 << 32)
    } else {
        E::from_u64(1 << (8 * F_CV_B_STORAGE_BYTES[idx - NUM_G]))
    }
}

pub(super) fn cv_storage_offset<E: PrimeCharacteristicRing>(idx: usize) -> E {
    match idx {
        0..NUM_G => E::from_u32(EIDOS_COMPRESSION_IV[idx]),
        NUM_G..8 => E::ZERO,
        _ => unreachable!("full-CV coordinate index must be in 0..8"),
    }
}

fn packed_fused_bytes<E, A>(at: &A, base: usize, g: usize, field: usize) -> E
where
    E: PrimeCharacteristicRing,
    A: Fn(usize) -> E,
{
    pack_u32_le(
        at(byte_slot_base(base, g * BYTES_PER_WORD) + field),
        at(byte_slot_base(base, g * BYTES_PER_WORD + 1) + field),
        at(byte_slot_base(base, g * BYTES_PER_WORD + 2) + field),
        at(byte_slot_base(base, g * BYTES_PER_WORD + 3) + field),
    )
}

fn d_new_rot16<E, A>(at: &A, g: usize) -> E
where
    E: PrimeCharacteristicRing,
    A: Fn(usize) -> E,
{
    let xor = core::array::from_fn::<_, BYTES_PER_WORD, _>(|byte| {
        let base = g_ac_byte_slot_col(g, byte, 0);
        xor_from_and(at(base), at(base + 1), at(base + 2))
    });
    let [x0, x1, x2, x3] = xor;
    pack_u32_le(x2, x3, x0, x1)
}
