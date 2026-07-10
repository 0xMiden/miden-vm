//! Generic polynomial type and operations used in Falcon.

use alloc::vec::Vec;
use core::{
    default::Default,
    fmt::Debug,
    ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign},
};

use num::{One, Zero};

use super::{Inverse, field::FalconFelt};
use crate::{
    Felt,
    dsa::falcon512_poseidon2::{MODULUS, N},
    utils::zeroize::{Zeroize, ZeroizeOnDrop},
};

/// Represents a polynomial with coefficients of type F.
#[derive(Debug, Clone, Default)]
pub struct Polynomial<F> {
    /// Coefficients of the polynomial, ordered from lowest to highest degree.
    pub coefficients: Vec<F>,
}

impl<F> Polynomial<F>
where
    F: Clone,
{
    /// Creates a new polynomial from the provided coefficients.
    pub fn new(coefficients: Vec<F>) -> Self {
        Self { coefficients }
    }
}

impl<F: Mul<Output = F> + Sub<Output = F> + AddAssign + Zero + Div<Output = F> + Clone + Inverse>
    Polynomial<F>
{
    /// Multiplies two polynomials coefficient-wise (Hadamard multiplication).
    pub fn hadamard_mul(&self, other: &Self) -> Self {
        Polynomial::new(
            self.coefficients
                .iter()
                .zip(other.coefficients.iter())
                .map(|(a, b)| *a * *b)
                .collect(),
        )
    }
    /// Divides two polynomials coefficient-wise (Hadamard division).
    pub fn hadamard_div(&self, other: &Self) -> Self {
        let other_coefficients_inverse = F::batch_inverse_or_zero(&other.coefficients);
        Polynomial::new(
            self.coefficients
                .iter()
                .zip(other_coefficients_inverse.iter())
                .map(|(a, b)| *a * *b)
                .collect(),
        )
    }

    /// Computes the coefficient-wise inverse (Hadamard inverse).
    pub fn hadamard_inv(&self) -> Self {
        let coefficients_inverse = F::batch_inverse_or_zero(&self.coefficients);
        Polynomial::new(coefficients_inverse)
    }
}

impl<F: Zero + PartialEq + Clone> Polynomial<F> {
    /// Returns the degree of the polynomial.
    pub fn degree(&self) -> Option<usize> {
        if self.coefficients.is_empty() {
            return None;
        }
        let mut max_index = self.coefficients.len() - 1;
        while self.coefficients[max_index] == F::zero() {
            if let Some(new_index) = max_index.checked_sub(1) {
                max_index = new_index;
            } else {
                return None;
            }
        }
        Some(max_index)
    }

    /// Returns the leading coefficient of the polynomial.
    pub fn lc(&self) -> F {
        match self.degree() {
            Some(non_negative_degree) => self.coefficients[non_negative_degree].clone(),
            None => F::zero(),
        }
    }
}

/// The following implementations are specific to cyclotomic polynomial rings,
/// i.e., F\[ X \] / <X^n + 1>, and are used extensively in Falcon.
impl<
    F: One
        + Zero
        + Clone
        + Neg<Output = F>
        + MulAssign
        + AddAssign
        + Div<Output = F>
        + Sub<Output = F>
        + PartialEq,
> Polynomial<F>
{
    /// Reduce the polynomial by X^n + 1.
    pub fn reduce_by_cyclotomic(&self, n: usize) -> Self {
        let mut coefficients = vec![F::zero(); n];
        let mut sign = -F::one();
        for (i, c) in self.coefficients.iter().cloned().enumerate() {
            if i.is_multiple_of(n) {
                sign *= -F::one();
            }
            coefficients[i % n] += sign.clone() * c;
        }
        Polynomial::new(coefficients)
    }

    /// Computes the field norm of the polynomial as an element of the cyclotomic ring
    ///  F\[ X \] / <X^n + 1 > relative to one of half the size, i.e., F\[ X \] / <X^(n/2) + 1> .
    ///
    /// Corresponds to formula 3.25 in the spec [1, p.30].
    ///
    /// [1]: <https://falcon-sign.info/falcon.pdf>
    pub fn field_norm(&self) -> Self {
        let n = self.coefficients.len();
        let mut f0_coefficients = vec![F::zero(); n / 2];
        let mut f1_coefficients = vec![F::zero(); n / 2];
        for i in 0..n / 2 {
            f0_coefficients[i] = self.coefficients[2 * i].clone();
            f1_coefficients[i] = self.coefficients[2 * i + 1].clone();
        }
        let f0 = Polynomial::new(f0_coefficients);
        let f1 = Polynomial::new(f1_coefficients);
        let f0_squared = (f0.clone() * f0).reduce_by_cyclotomic(n / 2);
        let f1_squared = (f1.clone() * f1).reduce_by_cyclotomic(n / 2);
        let x = Polynomial::new(vec![F::zero(), F::one()]);
        f0_squared - (x * f1_squared).reduce_by_cyclotomic(n / 2)
    }

    /// Lifts an element from a cyclotomic polynomial ring to one of double the size.
    pub fn lift_next_cyclotomic(&self) -> Self {
        let n = self.coefficients.len();
        let mut coefficients = vec![F::zero(); n * 2];
        for i in 0..n {
            coefficients[2 * i] = self.coefficients[i].clone();
        }
        Self::new(coefficients)
    }

    /// Computes the galois adjoint of the polynomial in the cyclotomic ring F\[ X \] / < X^n + 1 >
    /// , which corresponds to f(x^2).
    pub fn galois_adjoint(&self) -> Self {
        Self::new(
            self.coefficients
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    if i.is_multiple_of(2) {
                        c.clone()
                    } else {
                        c.clone().neg()
                    }
                })
                .collect(),
        )
    }
}

impl<F: Clone + Into<f64>> Polynomial<F> {
    pub(crate) fn l2_norm_squared(&self) -> f64 {
        self.coefficients
            .iter()
            .map(|i| Into::<f64>::into(i.clone()))
            .map(|i| i * i)
            .sum::<f64>()
    }
}

impl<F> PartialEq for Polynomial<F>
where
    F: Zero + PartialEq + Clone + AddAssign,
{
    fn eq(&self, other: &Self) -> bool {
        if self.is_zero() && other.is_zero() {
            true
        } else if self.is_zero() || other.is_zero() {
            false
        } else {
            let self_degree = self.degree().unwrap();
            let other_degree = other.degree().unwrap();
            self.coefficients[0..=self_degree] == other.coefficients[0..=other_degree]
        }
    }
}

impl<F> Eq for Polynomial<F> where F: Zero + PartialEq + Clone + AddAssign {}

impl<F> Add for &Polynomial<F>
where
    F: Add<Output = F> + AddAssign + Clone,
{
    type Output = Polynomial<F>;

    fn add(self, rhs: Self) -> Self::Output {
        let coefficients = if self.coefficients.len() >= rhs.coefficients.len() {
            let mut coefficients = self.coefficients.clone();
            for (i, c) in rhs.coefficients.iter().enumerate() {
                coefficients[i] += c.clone();
            }
            coefficients
        } else {
            let mut coefficients = rhs.coefficients.clone();
            for (i, c) in self.coefficients.iter().enumerate() {
                coefficients[i] += c.clone();
            }
            coefficients
        };
        Self::Output { coefficients }
    }
}

impl<F> Add for Polynomial<F>
where
    F: Add<Output = F> + AddAssign + Clone,
{
    type Output = Polynomial<F>;
    fn add(self, rhs: Self) -> Self::Output {
        let coefficients = if self.coefficients.len() >= rhs.coefficients.len() {
            let mut coefficients = self.coefficients;
            for (i, c) in rhs.coefficients.into_iter().enumerate() {
                coefficients[i] += c;
            }
            coefficients
        } else {
            let mut coefficients = rhs.coefficients;
            for (i, c) in self.coefficients.into_iter().enumerate() {
                coefficients[i] += c;
            }
            coefficients
        };
        Self::Output { coefficients }
    }
}

impl<F> AddAssign for Polynomial<F>
where
    F: Add<Output = F> + AddAssign + Clone,
{
    fn add_assign(&mut self, rhs: Self) {
        if self.coefficients.len() >= rhs.coefficients.len() {
            for (i, c) in rhs.coefficients.into_iter().enumerate() {
                self.coefficients[i] += c;
            }
        } else {
            let mut coefficients = rhs.coefficients;
            for (i, c) in self.coefficients.iter().enumerate() {
                coefficients[i] += c.clone();
            }
            self.coefficients = coefficients;
        }
    }
}

impl<F> Sub for &Polynomial<F>
where
    F: Sub<Output = F> + Clone + Neg<Output = F> + Add<Output = F> + AddAssign,
{
    type Output = Polynomial<F>;

    fn sub(self, rhs: Self) -> Self::Output {
        self + &(-rhs)
    }
}

impl<F> Sub for Polynomial<F>
where
    F: Sub<Output = F> + Clone + Neg<Output = F> + Add<Output = F> + AddAssign,
{
    type Output = Polynomial<F>;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

impl<F> SubAssign for Polynomial<F>
where
    F: Add<Output = F> + Neg<Output = F> + AddAssign + Clone + Sub<Output = F>,
{
    fn sub_assign(&mut self, rhs: Self) {
        self.coefficients = self.clone().sub(rhs).coefficients;
    }
}

impl<F: Neg<Output = F> + Clone> Neg for &Polynomial<F> {
    type Output = Polynomial<F>;

    fn neg(self) -> Self::Output {
        Self::Output {
            coefficients: self.coefficients.iter().cloned().map(|a| -a).collect(),
        }
    }
}

impl<F: Neg<Output = F> + Clone> Neg for Polynomial<F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self::Output {
            coefficients: self.coefficients.iter().cloned().map(|a| -a).collect(),
        }
    }
}

impl<F> Mul for &Polynomial<F>
where
    F: Add + AddAssign + Mul<Output = F> + Sub<Output = F> + Zero + PartialEq + Clone,
{
    type Output = Polynomial<F>;

    fn mul(self, other: Self) -> Self::Output {
        if self.is_zero() || other.is_zero() {
            return Polynomial::<F>::zero();
        }
        let mut coefficients =
            vec![F::zero(); self.coefficients.len() + other.coefficients.len() - 1];
        for i in 0..self.coefficients.len() {
            for j in 0..other.coefficients.len() {
                coefficients[i + j] += self.coefficients[i].clone() * other.coefficients[j].clone();
            }
        }
        Polynomial { coefficients }
    }
}

impl<F> Mul for Polynomial<F>
where
    F: Add + AddAssign + Mul<Output = F> + Zero + PartialEq + Clone,
{
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        let mut coefficients =
            vec![F::zero(); self.coefficients.len() + other.coefficients.len() - 1];
        for i in 0..self.coefficients.len() {
            for j in 0..other.coefficients.len() {
                coefficients[i + j] += self.coefficients[i].clone() * other.coefficients[j].clone();
            }
        }
        Self { coefficients }
    }
}

impl<F: Add + Mul<Output = F> + Zero + Clone> Mul<F> for &Polynomial<F> {
    type Output = Polynomial<F>;

    fn mul(self, other: F) -> Self::Output {
        Polynomial {
            coefficients: self.coefficients.iter().cloned().map(|i| i * other.clone()).collect(),
        }
    }
}

impl<F: Add + Mul<Output = F> + Zero + Clone> Mul<F> for Polynomial<F> {
    type Output = Polynomial<F>;

    fn mul(self, other: F) -> Self::Output {
        Polynomial {
            coefficients: self.coefficients.iter().cloned().map(|i| i * other.clone()).collect(),
        }
    }
}

impl<F: Mul<Output = F> + Sub<Output = F> + AddAssign + Zero + Div<Output = F> + Clone>
    Polynomial<F>
{
    /// Multiply two polynomials using Karatsuba's divide-and-conquer algorithm.
    pub fn karatsuba(&self, other: &Self) -> Self {
        Polynomial::new(vector_karatsuba(&self.coefficients, &other.coefficients))
    }
}

impl<F> One for Polynomial<F>
where
    F: Clone + One + PartialEq + Zero + AddAssign,
{
    fn one() -> Self {
        Self { coefficients: vec![F::one()] }
    }
}

impl<F> Zero for Polynomial<F>
where
    F: Zero + PartialEq + Clone + AddAssign,
{
    fn zero() -> Self {
        Self { coefficients: vec![] }
    }

    fn is_zero(&self) -> bool {
        self.degree().is_none()
    }
}

impl<F: Zero + Clone> Polynomial<F> {
    /// Shifts the polynomial by the specified amount (adds leading zeros).
    pub fn shift(&self, shamt: usize) -> Self {
        Self {
            coefficients: [vec![F::zero(); shamt], self.coefficients.clone()].concat(),
        }
    }

    /// Creates a constant polynomial with a single coefficient.
    pub fn constant(f: F) -> Self {
        Self { coefficients: vec![f] }
    }

    /// Applies a function to each coefficient and returns a new polynomial.
    pub fn map<G: Clone, C: FnMut(&F) -> G>(&self, closure: C) -> Polynomial<G> {
        Polynomial::<G>::new(self.coefficients.iter().map(closure).collect())
    }

    /// Folds the coefficients using the provided function and initial value.
    pub fn fold<G, C: FnMut(G, &F) -> G + Clone>(&self, mut initial_value: G, closure: C) -> G {
        for c in self.coefficients.iter() {
            initial_value = (closure.clone())(initial_value, c);
        }
        initial_value
    }
}

impl<F> Div<Polynomial<F>> for Polynomial<F>
where
    F: Zero
        + One
        + PartialEq
        + AddAssign
        + Clone
        + Mul<Output = F>
        + MulAssign
        + Div<Output = F>
        + Neg<Output = F>
        + Sub<Output = F>,
{
    type Output = Polynomial<F>;

    fn div(self, denominator: Self) -> Self::Output {
        if denominator.is_zero() {
            panic!();
        }
        if self.is_zero() {
            Self::zero();
        }
        let mut remainder = self;
        let mut quotient = Polynomial::<F>::zero();
        while remainder.degree().unwrap() >= denominator.degree().unwrap() {
            let shift = remainder.degree().unwrap() - denominator.degree().unwrap();
            let quotient_coefficient = remainder.lc() / denominator.lc();
            let monomial = Self::constant(quotient_coefficient).shift(shift);
            quotient += monomial.clone();
            remainder -= monomial * denominator.clone();
            if remainder.is_zero() {
                break;
            }
        }
        quotient
    }
}

fn vector_karatsuba<
    F: Zero + AddAssign + Mul<Output = F> + Sub<Output = F> + Div<Output = F> + Clone,
>(
    left: &[F],
    right: &[F],
) -> Vec<F> {
    let n = left.len();
    if n <= 8 {
        let mut product = vec![F::zero(); left.len() + right.len() - 1];
        for (i, l) in left.iter().enumerate() {
            for (j, r) in right.iter().enumerate() {
                product[i + j] += l.clone() * r.clone();
            }
        }
        return product;
    }
    let n_over_2 = n / 2;
    let mut product = vec![F::zero(); 2 * n - 1];
    let left_lo = &left[0..n_over_2];
    let right_lo = &right[0..n_over_2];
    let left_hi = &left[n_over_2..];
    let right_hi = &right[n_over_2..];
    let left_sum: Vec<F> =
        left_lo.iter().zip(left_hi).map(|(a, b)| a.clone() + b.clone()).collect();
    let right_sum: Vec<F> =
        right_lo.iter().zip(right_hi).map(|(a, b)| a.clone() + b.clone()).collect();

    let prod_lo = vector_karatsuba(left_lo, right_lo);
    let prod_hi = vector_karatsuba(left_hi, right_hi);
    let prod_mid: Vec<F> = vector_karatsuba(&left_sum, &right_sum)
        .iter()
        .zip(prod_lo.iter().zip(prod_hi.iter()))
        .map(|(s, (l, h))| s.clone() - (l.clone() + h.clone()))
        .collect();

    for (i, l) in prod_lo.into_iter().enumerate() {
        product[i] = l;
    }
    for (i, m) in prod_mid.into_iter().enumerate() {
        product[i + n_over_2] += m;
    }
    for (i, h) in prod_hi.into_iter().enumerate() {
        product[i + n] += h
    }
    product
}

impl From<Polynomial<FalconFelt>> for Polynomial<Felt> {
    fn from(item: Polynomial<FalconFelt>) -> Self {
        let res: Vec<Felt> =
            item.coefficients.iter().map(|a| Felt::from_u16(a.value() as u16)).collect();
        Polynomial::new(res)
    }
}

impl From<&Polynomial<FalconFelt>> for Polynomial<Felt> {
    fn from(item: &Polynomial<FalconFelt>) -> Self {
        let res: Vec<Felt> =
            item.coefficients.iter().map(|a| Felt::from_u16(a.value() as u16)).collect();
        Polynomial::new(res)
    }
}

impl From<Polynomial<i16>> for Polynomial<FalconFelt> {
    fn from(item: Polynomial<i16>) -> Self {
        let res: Vec<FalconFelt> = item.coefficients.iter().map(|&a| FalconFelt::new(a)).collect();
        Polynomial::new(res)
    }
}

impl From<&Polynomial<i16>> for Polynomial<FalconFelt> {
    fn from(item: &Polynomial<i16>) -> Self {
        let res: Vec<FalconFelt> = item.coefficients.iter().map(|&a| FalconFelt::new(a)).collect();
        Polynomial::new(res)
    }
}

impl From<Vec<i16>> for Polynomial<FalconFelt> {
    fn from(item: Vec<i16>) -> Self {
        let res: Vec<FalconFelt> = item.iter().map(|&a| FalconFelt::new(a)).collect();
        Polynomial::new(res)
    }
}

impl From<&Vec<i16>> for Polynomial<FalconFelt> {
    fn from(item: &Vec<i16>) -> Self {
        let res: Vec<FalconFelt> = item.iter().map(|&a| FalconFelt::new(a)).collect();
        Polynomial::new(res)
    }
}

impl Polynomial<FalconFelt> {
    /// Computes the squared L2 norm of the polynomial.
    pub fn norm_squared(&self) -> u64 {
        self.coefficients
            .iter()
            .map(|&i| i.balanced_value() as i64)
            .map(|i| (i * i) as u64)
            .sum::<u64>()
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the coefficients of this polynomial as field elements.
    pub fn to_elements(&self) -> Vec<Felt> {
        self.coefficients.iter().map(|&a| Felt::from_u16(a.value() as u16)).collect()
    }

    /// Returns the coefficients of this polynomial as balanced signed values.
    pub fn to_balanced_values(&self) -> Vec<i16> {
        self.coefficients.iter().copied().map(FalconFelt::balanced_value).collect()
    }

    // POLYNOMIAL OPERATIONS
    // --------------------------------------------------------------------------------------------

    /// Multiplies two polynomials over Z_p\[x\] without reducing modulo p. Given that the degrees
    /// of the input polynomials are less than 512 and their coefficients are less than the modulus
    /// q equal to 12289, the resulting product polynomial is guaranteed to have coefficients less
    /// than the Miden prime.
    ///
    /// Note that this multiplication is not over Z_p\[x\]/(phi).
    pub fn mul_modulo_p(a: &Self, b: &Self) -> [u64; 1024] {
        let mut c = [0; 2 * N];
        for i in 0..N {
            for j in 0..N {
                c[i + j] += a.coefficients[i].value() as u64 * b.coefficients[j].value() as u64;
            }
        }

        c
    }

    /// Reduces a polynomial, that is the product of two polynomials over Z_p\[x\], modulo
    /// the irreducible polynomial phi. This results in an element in Z_p\[x\]/(phi).
    pub fn reduce_negacyclic(a: &[u64; 1024]) -> Self {
        let mut c = [FalconFelt::zero(); N];
        let modulus = MODULUS as u16;
        for i in 0..N {
            let ai = a[N + i] % modulus as u64;
            let neg_ai = (modulus - ai as u16) % modulus;

            let bi = (a[i] % modulus as u64) as u16;
            c[i] = FalconFelt::new(((neg_ai + bi) % modulus) as i16);
        }

        Self::new(c.to_vec())
    }
}

impl Polynomial<Felt> {
    /// Returns the coefficients of this polynomial as Miden field elements.
    pub fn to_elements(&self) -> Vec<Felt> {
        self.coefficients.clone()
    }
}

impl Polynomial<i16> {
    /// Returns the balanced values of the coefficients of this polynomial.
    pub fn to_balanced_values(&self) -> Vec<i16> {
        self.coefficients.iter().map(|c| FalconFelt::new(*c).balanced_value()).collect()
    }
}

// ZEROIZE IMPLEMENTATIONS
// ================================================================================================

impl<F: Zeroize> Zeroize for Polynomial<F> {
    fn zeroize(&mut self) {
        self.coefficients.zeroize();
    }
}

impl<F: Zeroize> ZeroizeOnDrop for Polynomial<F> {}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{FalconFelt, N, Polynomial};
    use crate::rand::test_utils::prng_array;

    #[test]
    fn test_negacyclic_reduction() {
        let coef1: [u8; N] = prng_array([0u8; 32]);
        let coef2: [u8; N] = prng_array([1u8; 32]);

        let poly1 = Polynomial::new(coef1.iter().map(|&a| FalconFelt::new(a as i16)).collect());
        let poly2 = Polynomial::new(coef2.iter().map(|&a| FalconFelt::new(a as i16)).collect());
        let prod = poly1.clone() * poly2.clone();

        assert_eq!(
            prod.reduce_by_cyclotomic(N),
            Polynomial::reduce_negacyclic(&Polynomial::mul_modulo_p(&poly1, &poly2))
        );
    }
}
