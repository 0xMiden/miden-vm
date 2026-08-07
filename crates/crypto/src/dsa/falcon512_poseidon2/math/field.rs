//! The prime field over which Falcon polynomials are defined.
//!
//! Falcon works modulo `q = 12289 = 3 * 2^12 + 1`. The multiplicative group therefore has order
//! `3 * 2^12`, which is what makes the radix-2 NTT in [`super::fft`] possible for every power of
//! two up to 4096.

use alloc::string::String;
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use num::{One, Zero};

use super::{Inverse, MODULUS, fft::CyclotomicFourier};

/// An element of the Falcon base field `F_q`, with `q = 12289`.
///
/// The wrapped value is the canonical representative in `[0, q)`. Falcon also uses a balanced
/// representation centred on zero, which [`FalconFelt::balanced_value`] produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FalconFelt(u32);

impl FalconFelt {
    /// Reduces `value` modulo `q` and returns it as a field element.
    ///
    /// Negative inputs are mapped into `[0, q)` by adding the modulus, so `new(-1)` is `q - 1`.
    ///
    /// # Note
    /// `value` is expected to satisfy `value > -q`, which holds for every call site in this crate
    /// because coefficients are reduced before they reach this constructor. A negative multiple of
    /// the modulus, such as `-q` itself, is mapped to `q` rather than to `0`, i.e. to a
    /// representative that is congruent to zero but outside the canonical range, and one which
    /// [`Zero::is_zero`] does not recognise.
    pub const fn new(value: i16) -> Self {
        let gtz_bool = value >= 0;
        let gtz_int = gtz_bool as i16;
        let gtz_sign = gtz_int - ((!gtz_bool) as i16);
        let reduced = gtz_sign * (gtz_sign * value) % MODULUS;
        let canonical_representative = (reduced + MODULUS * (1 - gtz_int)) as u32;
        FalconFelt(canonical_representative)
    }

    /// Returns the canonical representative of this element, in `[0, q)`.
    pub const fn value(self) -> i16 {
        self.0 as i16
    }

    /// Returns the balanced representative of this element, in `[-(q - 1) / 2, (q - 1) / 2]`.
    ///
    /// This is the representation Falcon uses when it needs the norm of a polynomial, since the
    /// canonical representative of a small negative coefficient is close to `q` rather than to 0.
    pub fn balanced_value(self) -> i16 {
        let value = self.value();
        let g = (value > ((MODULUS) / 2)) as i16;
        value - (MODULUS) * g
    }

    /// Multiplies two field elements.
    ///
    /// This is the `const` counterpart of the [`Mul`] implementation, which it matches exactly.
    pub const fn multiply(self, other: Self) -> Self {
        FalconFelt((self.0 * other.0) % MODULUS as u32)
    }
}

impl Add for FalconFelt {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        let (s, _) = self.0.overflowing_add(rhs.0);
        let (d, n) = s.overflowing_sub(MODULUS as u32);
        let (r, _) = d.overflowing_add(MODULUS as u32 * (n as u32));
        FalconFelt(r)
    }
}

impl AddAssign for FalconFelt {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for FalconFelt {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + -rhs
    }
}

impl SubAssign for FalconFelt {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Neg for FalconFelt {
    type Output = FalconFelt;

    fn neg(self) -> Self::Output {
        let is_nonzero = self.0 != 0;
        let r = MODULUS as u32 - self.0;
        FalconFelt(r * (is_nonzero as u32))
    }
}

impl Mul for FalconFelt {
    fn mul(self, rhs: Self) -> Self::Output {
        FalconFelt((self.0 * rhs.0) % MODULUS as u32)
    }

    type Output = Self;
}

impl MulAssign for FalconFelt {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Div for FalconFelt {
    type Output = FalconFelt;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inverse_or_zero()
    }
}

impl DivAssign for FalconFelt {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs
    }
}

impl Zero for FalconFelt {
    fn zero() -> Self {
        FalconFelt::new(0)
    }

    fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

impl One for FalconFelt {
    fn one() -> Self {
        FalconFelt::new(1)
    }
}

impl Inverse for FalconFelt {
    /// Returns `self^(q - 2)`, which is the multiplicative inverse of `self` for every non-zero
    /// element by Fermat's little theorem, and zero for zero.
    ///
    /// The exponentiation is spelled out as a fixed addition chain rather than a loop, so that it
    /// runs in constant time. Writing `q - 2 = 12287` in binary as `0b10_11_11_11_11_11_11` shows
    /// the shape of the chain: twelve set bits produce `all_ones = self^4095`, and the leading
    /// `0b10` contributes the `self^8192` factor.
    fn inverse_or_zero(self) -> Self {
        // q-2 = 0b10 11 11 11  11 11 11
        let two = self.multiply(self);
        let three = two.multiply(self);
        let six = three.multiply(three);
        let twelve = six.multiply(six);
        let fifteen = twelve.multiply(three);
        let thirty = fifteen.multiply(fifteen);
        let sixty = thirty.multiply(thirty);
        let sixty_three = sixty.multiply(three);

        let sixty_three_sq = sixty_three.multiply(sixty_three);
        let sixty_three_qu = sixty_three_sq.multiply(sixty_three_sq);
        let sixty_three_oc = sixty_three_qu.multiply(sixty_three_qu);
        let sixty_three_hx = sixty_three_oc.multiply(sixty_three_oc);
        let sixty_three_tt = sixty_three_hx.multiply(sixty_three_hx);
        let sixty_three_sf = sixty_three_tt.multiply(sixty_three_tt);

        let all_ones = sixty_three_sf.multiply(sixty_three);
        let two_e_twelve = all_ones.multiply(self);
        let two_e_thirteen = two_e_twelve.multiply(two_e_twelve);

        two_e_thirteen.multiply(all_ones)
    }
}

impl CyclotomicFourier for FalconFelt {
    /// Returns a primitive `n`-th root of unity, where `n` is a power of two of at most 4096.
    ///
    /// 1331 is a primitive `2^12`-th root of unity modulo `q`, so squaring it `12 - log2(n)` times
    /// gives an element of order `n`.
    ///
    /// # Panics
    /// Panics if `n` exceeds `2^12`, the largest power of two dividing `q - 1`.
    fn primitive_root_of_unity(n: usize) -> Self {
        let log2n = n.ilog2();
        assert!(log2n <= 12);
        // and 1331 is a twelfth root of unity
        let mut a = FalconFelt::new(1331);
        let num_squarings = 12 - n.ilog2();
        for _ in 0..num_squarings {
            a *= a;
        }
        a
    }
}

impl TryFrom<u32> for FalconFelt {
    type Error = String;

    /// Converts `value` into a field element, rejecting anything that is not already a canonical
    /// representative.
    ///
    /// # Errors
    /// Returns an error if `value >= q`.
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value >= MODULUS as u32 {
            Err(format!("value {value} is greater than or equal to the field modulus {MODULUS}"))
        } else {
            Ok(FalconFelt::new(value as i16))
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use proptest::prelude::*;

    use super::*;

    const Q: i32 = MODULUS as i32;

    /// Returns every element of the field, in canonical order.
    fn all_elements() -> impl Iterator<Item = FalconFelt> {
        (0..MODULUS).map(FalconFelt::new)
    }

    /// Reduces `value` into `[0, q)` the straightforward way, as a reference for the constructor.
    fn reduce(value: i32) -> i32 {
        value.rem_euclid(Q)
    }

    // REPRESENTATION
    // --------------------------------------------------------------------------------------------

    #[test]
    fn new_maps_the_documented_input_range_onto_canonical_representatives() {
        for value in -(MODULUS - 1)..MODULUS {
            let element = FalconFelt::new(value);
            assert_eq!(i32::from(element.value()), reduce(i32::from(value)), "for value {value}");
            assert!((0..MODULUS).contains(&element.value()), "for value {value}");
        }
    }

    #[test]
    fn balanced_value_lies_in_the_symmetric_range() {
        let half = (MODULUS - 1) / 2;
        for element in all_elements() {
            let balanced = element.balanced_value();
            assert!((-half..=half).contains(&balanced), "for element {}", element.value());
            assert_eq!(reduce(i32::from(balanced)), i32::from(element.value()));
        }
    }

    #[test]
    fn try_from_accepts_canonical_values_and_rejects_the_rest() {
        for value in 0..MODULUS as u32 {
            assert_eq!(FalconFelt::try_from(value).unwrap().value(), value as i16);
        }

        for value in [MODULUS as u32, MODULUS as u32 + 1, u32::MAX] {
            assert!(FalconFelt::try_from(value).is_err());
        }
    }

    // ARITHMETIC
    // --------------------------------------------------------------------------------------------

    #[test]
    fn zero_and_one_are_the_identities() {
        for element in all_elements() {
            assert_eq!(element + FalconFelt::zero(), element);
            assert_eq!(element * FalconFelt::one(), element);
            assert_eq!(element * FalconFelt::zero(), FalconFelt::zero());
            assert_eq!(element + -element, FalconFelt::zero());
        }

        assert!(FalconFelt::zero().is_zero());
        assert!(!FalconFelt::one().is_zero());
    }

    #[test]
    fn multiply_matches_the_mul_impl() {
        for a in all_elements().step_by(97) {
            for b in all_elements().step_by(89) {
                assert_eq!(a.multiply(b), a * b);
            }
        }
    }

    proptest! {
        #[test]
        fn add_sub_and_mul_agree_with_integer_arithmetic(
            a in 0i32..Q,
            b in 0i32..Q,
        ) {
            let x = FalconFelt::new(a as i16);
            let y = FalconFelt::new(b as i16);

            prop_assert_eq!(i32::from((x + y).value()), reduce(a + b));
            prop_assert_eq!(i32::from((x - y).value()), reduce(a - b));
            prop_assert_eq!(i32::from((x * y).value()), reduce(a * b));
            prop_assert_eq!(i32::from((-x).value()), reduce(-a));
        }

        #[test]
        fn assigning_operators_match_their_non_assigning_counterparts(
            a in 0i32..Q,
            b in 0i32..Q,
        ) {
            let x = FalconFelt::new(a as i16);
            let y = FalconFelt::new(b as i16);

            let mut sum = x;
            sum += y;
            let mut difference = x;
            difference -= y;
            let mut product = x;
            product *= y;
            let mut quotient = x;
            quotient /= y;

            prop_assert_eq!(sum, x + y);
            prop_assert_eq!(difference, x - y);
            prop_assert_eq!(product, x * y);
            prop_assert_eq!(quotient, x / y);
        }
    }

    // INVERSION
    // --------------------------------------------------------------------------------------------

    #[test]
    fn inverse_or_zero_inverts_every_non_zero_element() {
        for element in all_elements().filter(|e| !e.is_zero()) {
            assert_eq!(element * element.inverse_or_zero(), FalconFelt::one());
        }
    }

    #[test]
    fn inverse_or_zero_maps_zero_to_zero() {
        assert_eq!(FalconFelt::zero().inverse_or_zero(), FalconFelt::zero());
    }

    #[test]
    fn div_multiplies_by_the_inverse() {
        for a in all_elements().step_by(97) {
            for b in all_elements().step_by(89) {
                assert_eq!(a / b, a * b.inverse_or_zero());
            }
        }
    }

    #[test]
    fn batch_inverse_or_zero_matches_inverting_one_by_one() {
        let batch: Vec<FalconFelt> = all_elements().step_by(53).collect();
        let expected: Vec<FalconFelt> = batch.iter().map(|e| e.inverse_or_zero()).collect();

        assert_eq!(FalconFelt::batch_inverse_or_zero(&batch), expected);
    }

    #[test]
    fn batch_inverse_or_zero_skips_zeros_without_disturbing_its_neighbours() {
        let batch = [
            FalconFelt::new(7),
            FalconFelt::zero(),
            FalconFelt::new(12288),
            FalconFelt::zero(),
            FalconFelt::new(1331),
        ];

        let inverses = FalconFelt::batch_inverse_or_zero(&batch);

        for (element, inverse) in batch.iter().zip(inverses.iter()) {
            if element.is_zero() {
                assert!(inverse.is_zero());
            } else {
                assert_eq!(*element * *inverse, FalconFelt::one());
            }
        }
    }

    #[test]
    fn batch_inverse_or_zero_handles_an_empty_batch() {
        assert!(FalconFelt::batch_inverse_or_zero(&[]).is_empty());
    }

    // ROOTS OF UNITY
    // --------------------------------------------------------------------------------------------

    #[test]
    fn primitive_root_of_unity_has_the_requested_order() {
        for log2n in 1..=12u32 {
            let n = 1usize << log2n;
            let root = FalconFelt::primitive_root_of_unity(n);

            // `root^n == 1` while `root^(n / 2) != 1`, i.e. the order is exactly `n`.
            let mut power = root;
            for _ in 1..log2n {
                power *= power;
            }
            assert_ne!(power, FalconFelt::one(), "root of unity for n = {n} has order below n");
            assert_eq!(power * power, FalconFelt::one(), "root of unity for n = {n} is not one");
        }
    }

    #[test]
    #[should_panic]
    fn primitive_root_of_unity_rejects_orders_above_the_two_adicity() {
        // `q - 1 = 3 * 2^12`, so there is no element of order `2^13`.
        FalconFelt::primitive_root_of_unity(1 << 13);
    }
}
