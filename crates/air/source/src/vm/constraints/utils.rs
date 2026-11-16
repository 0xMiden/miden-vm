//! Utility extension traits for constraint code.

use miden_core::field::{Algebra, PrimeCharacteristicRing};
use p3_field::Dup;

use crate::vm::{
    Felt,
    constraints::constants::{TWO_POW_8, TWO_POW_16, TWO_POW_24},
};

/// Extension trait adding `.not()` for boolean negation (`1 - self`).
pub trait BoolNot: PrimeCharacteristicRing {
    fn not(&self) -> Self {
        Self::ONE - self.clone()
    }
}

impl<T: PrimeCharacteristicRing> BoolNot for T {}

/// Aggregate bits into a value (little-endian) using Horner's method: `sum(2^i * limbs[i])`.
///
/// Evaluates as `((limbs[N-1]*2 + limbs[N-2])*2 + ...)*2 + limbs[0]`.
#[inline]
pub fn horner_eval_bits<const N: usize, T: Clone + Into<E>, E: PrimeCharacteristicRing>(
    limbs: &[T; N],
) -> E {
    const {
        assert! { N >= 1};
    }
    limbs
        .iter()
        .rev()
        .cloned()
        .map(Into::into)
        .reduce(|acc, bit| acc.double() + bit)
        .expect("non-empty array")
}

/// Packs four little-endian byte limbs into a u32 field expression.
#[inline]
pub fn pack_u32_bytes_le<T: Into<E>, E: Algebra<Felt>>(bytes: [T; 4]) -> E {
    <E as Algebra<Felt>>::mixed_dot_product(
        &bytes.map(Into::into),
        &[Felt::ONE, TWO_POW_8, TWO_POW_16, TWO_POW_24],
    )
}

/// Recomposes a u32 XOR from little-endian byte witnesses `[a[4], b[4], a_and_b[4]]`.
#[inline]
pub(crate) fn pack_u32_xor_bytes_le<T, E>(bytes: [T; 12]) -> E
where
    T: Dup + Into<E>,
    E: Algebra<Felt>,
{
    let xor_bytes: [E; 4] = core::array::from_fn(|i| {
        let lhs: E = bytes[i].dup().into();
        let rhs: E = bytes[i + 4].dup().into();
        let and: E = bytes[i + 8].dup().into();
        lhs + rhs - and.double()
    });
    pack_u32_bytes_le::<_, E>(xor_bytes)
}
