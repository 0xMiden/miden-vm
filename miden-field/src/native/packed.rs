//! SIMD-packed [`Felt`], wrapping Plonky3's packed Goldilocks vectors.
//!
//! [`PackedFelt`] stores `[Felt; WIDTH]` (matching the layout of the underlying
//! Plonky3 packing for the target architecture) and delegates all arithmetic to
//! the architecture-specific packed Goldilocks implementation. Since `Felt` is
//! `#[repr(transparent)]` over `Goldilocks` and both wrappers are
//! `#[repr(transparent)]` over `[_; WIDTH]`, the conversions are free.

use alloc::vec::Vec;
use core::{
    iter::{Product, Sum},
    mem::ManuallyDrop,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use p3_field::{
    Algebra, Field, InjectiveMonomial, PackedField, PackedFieldPow2, PackedValue,
    PermutationMonomial, PrimeCharacteristicRing,
    op_assign_macros::{
        impl_add_assign, impl_add_base_field, impl_div_methods, impl_mul_base_field,
        impl_mul_methods, impl_packed_field_div, impl_packed_value, impl_rng, impl_sub_assign,
        impl_sub_base_field, impl_sum_prod_base_field, ring_sum,
    },
};
use p3_goldilocks::Goldilocks;
use rand::{
    Rng, RngExt,
    distr::{Distribution, StandardUniform},
};

use super::{Felt, felts_as_goldilocks_array};

#[cfg(all(target_arch = "x86_64", target_feature = "avx2", not(target_feature = "avx512f")))]
type PackedGoldilocks = p3_goldilocks::PackedGoldilocksAVX2;

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
type PackedGoldilocks = p3_goldilocks::PackedGoldilocksAVX512;

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
type PackedGoldilocks = p3_goldilocks::PackedGoldilocksNeon;

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
type PackedGoldilocks = p3_goldilocks::PackedGoldilocksWasmSimd128;

/// Number of [`Felt`] lanes packed together on this architecture.
const WIDTH: usize = <PackedGoldilocks as PackedValue>::WIDTH;

/// A vector of [`Felt`] elements processed with SIMD operations.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
#[must_use]
pub struct PackedFelt(pub(crate) [Felt; WIDTH]);

impl PackedFelt {
    #[inline]
    fn to_inner(self) -> PackedGoldilocks {
        const _: () = {
            assert!(size_of::<PackedFelt>() == size_of::<PackedGoldilocks>());
            assert!(align_of::<PackedFelt>() == align_of::<PackedGoldilocks>());
        };
        // SAFETY: `PackedFelt` is `repr(transparent)` over `[Felt; WIDTH]`,
        // `PackedGoldilocks` is `repr(transparent)` over `[Goldilocks; WIDTH]`, and
        // `Felt` is `repr(transparent)` over `Goldilocks`, so the layouts match.
        unsafe { core::mem::transmute(self) }
    }

    #[inline]
    fn from_inner(value: PackedGoldilocks) -> Self {
        // SAFETY: same layout as `to_inner`, in the other direction.
        unsafe { core::mem::transmute(value) }
    }

    #[inline]
    const fn broadcast(value: Felt) -> Self {
        Self([value; WIDTH])
    }

    /// Reinterprets a mutable `PackedFelt` array as the underlying Plonky3 packed Goldilocks
    /// array for this architecture (i.e. `<Goldilocks as Field>::Packing`).
    #[inline]
    pub fn as_goldilocks_array_mut<const N: usize>(
        a: &mut [PackedFelt; N],
    ) -> &mut [PackedGoldilocks; N] {
        // SAFETY: `PackedFelt` and `PackedGoldilocks` have identical layouts (see
        // `PackedFelt::to_inner`), so `[PackedFelt; N]` matches `[PackedGoldilocks; N]`.
        unsafe { &mut *(a as *mut [PackedFelt; N] as *mut [PackedGoldilocks; N]) }
    }
}

/// Reinterprets a `PackedFelt` array as `PackedGoldilocks`.
#[inline]
fn packed_as_goldilocks_array<const N: usize>(a: &[PackedFelt; N]) -> &[PackedGoldilocks; N] {
    // SAFETY: `PackedFelt` and `PackedGoldilocks` have identical layouts (see
    // `PackedFelt::to_inner`), so `[PackedFelt; N]` matches `[PackedGoldilocks; N]`.
    unsafe { &*(a as *const [PackedFelt; N] as *const [PackedGoldilocks; N]) }
}

impl From<Felt> for PackedFelt {
    #[inline]
    fn from(value: Felt) -> Self {
        Self::broadcast(value)
    }
}

impl Add for PackedFelt {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self::from_inner(self.to_inner() + rhs.to_inner())
    }
}

impl Sub for PackedFelt {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self::from_inner(self.to_inner() - rhs.to_inner())
    }
}

impl Neg for PackedFelt {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        Self::from_inner(-self.to_inner())
    }
}

impl Mul for PackedFelt {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Self::from_inner(self.to_inner() * rhs.to_inner())
    }
}

impl_add_assign!(PackedFelt);
impl_sub_assign!(PackedFelt);
impl_mul_methods!(PackedFelt);
ring_sum!(PackedFelt);
impl_rng!(PackedFelt);

impl PrimeCharacteristicRing for PackedFelt {
    type PrimeSubfield = Goldilocks;

    const ZERO: Self = Self::broadcast(Felt::ZERO);
    const ONE: Self = Self::broadcast(Felt::ONE);
    const TWO: Self = Self::broadcast(Felt(Goldilocks::TWO));
    const NEG_ONE: Self = Self::broadcast(Felt(Goldilocks::NEG_ONE));

    #[inline]
    fn from_prime_subfield(f: Self::PrimeSubfield) -> Self {
        Self::broadcast(Felt(f))
    }

    #[inline]
    fn double(&self) -> Self {
        Self::from_inner(self.to_inner().double())
    }

    #[inline]
    fn halve(&self) -> Self {
        Self::from_inner(self.to_inner().halve())
    }

    #[inline]
    fn square(&self) -> Self {
        Self::from_inner(self.to_inner().square())
    }

    #[inline]
    fn mul_2exp_u64(&self, exp: u64) -> Self {
        Self::from_inner(self.to_inner().mul_2exp_u64(exp))
    }

    #[inline]
    fn div_2exp_u64(&self, exp: u64) -> Self {
        Self::from_inner(self.to_inner().div_2exp_u64(exp))
    }

    #[inline]
    fn exp_u64(&self, power: u64) -> Self {
        Self::from_inner(self.to_inner().exp_u64(power))
    }

    #[inline]
    fn dot_product<const N: usize>(lhs: &[Self; N], rhs: &[Self; N]) -> Self {
        Self::from_inner(PackedGoldilocks::dot_product(
            packed_as_goldilocks_array(lhs),
            packed_as_goldilocks_array(rhs),
        ))
    }

    #[inline]
    fn zero_vec(len: usize) -> Vec<Self> {
        let mut inner = ManuallyDrop::new(PackedGoldilocks::zero_vec(len));
        let (ptr, len, cap) = (inner.as_mut_ptr(), inner.len(), inner.capacity());
        // SAFETY: `PackedFelt` and `PackedGoldilocks` have identical layouts (see
        // `PackedFelt::to_inner`), and the source vector is not dropped.
        unsafe { Vec::from_raw_parts(ptr.cast::<Self>(), len, cap) }
    }
}

impl InjectiveMonomial<7> for PackedFelt {}

impl PermutationMonomial<7> for PackedFelt {
    #[inline]
    fn injective_exp_root_n(&self) -> Self {
        Self::from_inner(self.to_inner().injective_exp_root_n())
    }
}

impl_add_base_field!(PackedFelt, Felt);
impl_sub_base_field!(PackedFelt, Felt);
impl_mul_base_field!(PackedFelt, Felt);
impl_div_methods!(PackedFelt, Felt);
impl_packed_field_div!(PackedFelt);
impl_sum_prod_base_field!(PackedFelt, Felt);

impl Algebra<Felt> for PackedFelt {
    const BATCHED_LC_CHUNK: usize = <PackedGoldilocks as Algebra<Goldilocks>>::BATCHED_LC_CHUNK;

    #[inline]
    fn mixed_dot_product<const N: usize>(a: &[Self; N], f: &[Felt; N]) -> Self {
        Self::from_inner(PackedGoldilocks::mixed_dot_product(
            packed_as_goldilocks_array(a),
            felts_as_goldilocks_array(f),
        ))
    }
}

impl_packed_value!(PackedFelt, Felt, WIDTH);

unsafe impl PackedField for PackedFelt {
    type Scalar = Felt;
}

unsafe impl PackedFieldPow2 for PackedFelt {
    #[inline]
    fn interleave(&self, other: Self, block_len: usize) -> (Self, Self) {
        let (a, b) = self.to_inner().interleave(other.to_inner(), block_len);
        (Self::from_inner(a), Self::from_inner(b))
    }
}

#[cfg(test)]
mod tests {
    use p3_field::Field;
    use rand::{SeedableRng, rngs::SmallRng};

    use super::*;

    const _: () = assert!(WIDTH > 1, "packed module must only compile with real SIMD lanes");

    // `Felt::Packing` must resolve to `PackedFelt` whenever this module compiles.
    const _: fn(PackedFelt) -> <Felt as Field>::Packing = |x| x;

    fn random_packed(rng: &mut SmallRng) -> PackedFelt {
        rng.random()
    }

    /// Packed ops must agree with lane-wise scalar `Felt` ops.
    #[test]
    fn packed_ops_match_scalar_lanes() {
        let mut rng = SmallRng::seed_from_u64(7);
        for _ in 0..50 {
            let a = random_packed(&mut rng);
            let b = random_packed(&mut rng);

            for lane in 0..WIDTH {
                assert_eq!((a + b).0[lane], a.0[lane] + b.0[lane]);
                assert_eq!((a - b).0[lane], a.0[lane] - b.0[lane]);
                assert_eq!((a * b).0[lane], a.0[lane] * b.0[lane]);
                assert_eq!((-a).0[lane], -a.0[lane]);
                assert_eq!(a.square().0[lane], a.0[lane].square());
                assert_eq!(a.halve().0[lane], a.0[lane].halve());
                assert_eq!(a.double().0[lane], a.0[lane].double());
                assert_eq!(a.exp_u64(11).0[lane], a.0[lane].exp_u64(11));
                assert_eq!((a / b).0[lane], (a.0[lane] / b.0[lane]));
            }
        }
    }

    /// `dot_product` and `mixed_dot_product` must agree with lane-wise scalar reductions.
    #[test]
    fn packed_dot_products_match_scalar_lanes() {
        let mut rng = SmallRng::seed_from_u64(8);
        let lhs: [PackedFelt; 4] = core::array::from_fn(|_| random_packed(&mut rng));
        let rhs: [PackedFelt; 4] = core::array::from_fn(|_| random_packed(&mut rng));
        let scalars: [Felt; 4] = core::array::from_fn(|_| rng.random());

        let dot = PackedFelt::dot_product(&lhs, &rhs);
        let mixed = PackedFelt::mixed_dot_product(&lhs, &scalars);
        for lane in 0..WIDTH {
            let lhs_lane: [Felt; 4] = core::array::from_fn(|i| lhs[i].0[lane]);
            let rhs_lane: [Felt; 4] = core::array::from_fn(|i| rhs[i].0[lane]);
            assert_eq!(dot.0[lane], Felt::dot_product(&lhs_lane, &rhs_lane));
            assert_eq!(mixed.0[lane], Felt::dot_product(&lhs_lane, &scalars));
        }
    }

    /// `interleave` must match the reference semantics from `PackedFieldPow2`.
    #[test]
    fn interleave_matches_reference() {
        let mut rng = SmallRng::seed_from_u64(9);
        let a = random_packed(&mut rng);
        let b = random_packed(&mut rng);

        // block_len == WIDTH is the identity.
        assert_eq!(a.interleave(b, WIDTH), (a, b));

        // Reference semantics: stacking the two vectors and viewing them as 2×2
        // matrices of `block_len`-sized blocks, interleave transposes each matrix.
        // Output `r` at block `j` holds `a`'s block `j + r` when `j` is even and
        // `b`'s block `j - 1 + r` when `j` is odd.
        let mut block_len = 1;
        while block_len < WIDTH {
            let (x, y) = a.interleave(b, block_len);
            let n_blocks = WIDTH / block_len;
            for (r, out) in [x, y].iter().enumerate() {
                for j in 0..n_blocks {
                    for k in 0..block_len {
                        let expected = if j % 2 == 0 {
                            a.0[(j + r) * block_len + k]
                        } else {
                            b.0[(j - 1 + r) * block_len + k]
                        };
                        assert_eq!(
                            out.0[j * block_len + k],
                            expected,
                            "block_len {block_len} output {r} block {j} lane {k}"
                        );
                    }
                }
            }
            block_len *= 2;
        }
    }

    /// Slice/`from_fn` packing round-trips and `zero_vec` semantics.
    #[test]
    fn packed_value_round_trips() {
        let mut rng = SmallRng::seed_from_u64(10);
        let values: Vec<Felt> = (0..WIDTH).map(|_| rng.random()).collect();

        let packed = *PackedFelt::from_slice(&values);
        assert_eq!(packed.as_slice(), values.as_slice());

        let from_fn = PackedFelt::from_fn(|i| values[i]);
        assert_eq!(from_fn, packed);

        let zeros = PackedFelt::zero_vec(3);
        assert_eq!(zeros, alloc::vec![PackedFelt::ZERO; 3]);
    }
}
