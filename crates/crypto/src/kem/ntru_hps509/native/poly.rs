use super::{N, Q, WEIGHT};
use crate::utils::zeroize::Zeroize;

/// Coefficients in increasing degree order, with N = 509 and q = 2048.
///
/// Rq reduces modulo (q, x^N - 1). Sq and S3 reduce modulo Phi = 1 + x + ... + x^(N-1),
/// over Z_q and Z_3 respectively. A representative modulo Phi can have its last coefficient
/// set to zero by subtracting that coefficient from every coefficient.
pub(super) struct Poly(pub [u16; N]);

impl Drop for Poly {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Poly {
    pub fn zero() -> Self {
        Self([0; N])
    }

    pub fn is_one(&self) -> bool {
        self.0[0] == 1 && self.0[1..].iter().all(|&c| c == 0)
    }

    /// Product modulo (q, x^N - 1). Wrapping arithmetic is valid because q divides 2^16.
    pub fn mul_rq(&self, other: &Self) -> Self {
        let mut result = Self::zero();
        for (i, &a) in self.0.iter().enumerate() {
            for (c, &b) in result.0[i..].iter_mut().zip(&other.0[..N - i]) {
                *c = c.wrapping_add(a.wrapping_mul(b));
            }
            for (c, &b) in result.0[..i].iter_mut().zip(&other.0[N - i..]) {
                *c = c.wrapping_add(a.wrapping_mul(b));
            }
        }
        for c in &mut result.0 {
            *c &= Q - 1;
        }
        result
    }

    pub fn mul_sq(&self, other: &Self) -> Self {
        let mut result = self.mul_rq(other);
        let last = result.0[N - 1];
        for c in &mut result.0 {
            *c = c.wrapping_sub(last) & (Q - 1);
        }
        result
    }

    /// Product modulo (3, Phi). Both inputs must have coefficients in {0, 1, 2}.
    pub fn mul_s3(&self, other: &Self) -> Self {
        // Each unreduced coefficient is at most 4*N = 2036 < q, so the Rq product
        // loses no information needed by the subsequent reduction modulo 3.
        let mut result = self.mul_rq(other);
        let last = result.0[N - 1];
        for c in &mut result.0 {
            *c = (*c + 2 * last) % 3;
        }
        result
    }

    /// Maps trits 0, 1, 2 to their representatives 0, 1, q-1 in Rq.
    pub fn lift(&self) -> Self {
        Self(self.0.map(|c| c | (0u16.wrapping_sub(c >> 1) & (Q - 1))))
    }

    /// Maps coefficients in {0, 1, q-1} back to trits 0, 1, 2.
    pub fn unlift(&self) -> Self {
        Self(self.0.map(|c| (c ^ (c >> 10)) & 3))
    }

    pub fn center_to_s3(&self) -> Self {
        // For c >= q/2, use c-q before reducing modulo 3. Here -q = 1 (mod 3).
        let mut result = Self(self.0.map(|c| c + (c >> 10)));
        let last = result.0[N - 1];
        for c in &mut result.0 {
            *c = (*c + 2 * last) % 3;
        }
        result
    }

    pub fn invert_s3(&self) -> Self {
        self.invert_prime::<3>()
    }

    /// Inverse modulo (q, Phi), lifted from modulo 2 by Newton iteration.
    ///
    /// The result need not have zero last coefficient. Before encoding it as Sq, subtract
    /// that coefficient from every coefficient modulo q. For untrusted inputs, check that
    /// input * result = 1 modulo (q, Phi).
    pub fn invert_sq(&self) -> Self {
        let mut inverse = self.invert_prime::<2>();
        let negative = Self(self.0.map(u16::wrapping_neg));
        // Each update doubles the precision, up to q's 11 bits. Four updates suffice.
        for _ in 0..4 {
            let mut correction = inverse.mul_rq(&negative);
            correction.0[0] = correction.0[0].wrapping_add(2);
            inverse = inverse.mul_rq(&correction);
        }
        inverse
    }

    /// Inversion modulo (prime, Phi), for prime = 2 or 3, in a fixed 2*N-3 divsteps.
    ///
    /// f and g hold reversed Euclidean remainders; v and w track the corresponding
    /// coefficients of the input. A step swaps the pairs when delta > 0 and g[0] != 0,
    /// cancels g's constant coefficient, and divides g by x. The same transformation
    /// updates v and w. Both primes use this schedule; only the coefficient arithmetic
    /// differs. The returned inverse is normalized to have zero last coefficient.
    fn invert_prime<const PRIME: u16>(&self) -> Self {
        let reduce = |x: u16| x % PRIME;
        let mut f = Self([1; N]);
        let mut g = Self::zero();
        let mut v = Self::zero();
        let mut w = Self::zero();
        w.0[0] = 1;
        for i in 0..N - 1 {
            g.0[N - 2 - i] = reduce(self.0[i] + (PRIME - 1) * self.0[N - 1]);
        }
        let mut delta = 1i16;

        for _ in 0..2 * N - 3 {
            v.0.copy_within(..N - 1, 1);
            v.0[0] = 0;
            let sign = reduce((PRIME - 1) * g.0[0] * f.0[0]);
            let swap = (-delta & -(g.0[0] as i16)) >> 15;
            delta ^= swap & (delta ^ -delta);
            delta += 1;
            for i in 0..N {
                let exchange_fg = (swap as u16) & (f.0[i] ^ g.0[i]);
                f.0[i] ^= exchange_fg;
                g.0[i] ^= exchange_fg;
                let exchange_vw = (swap as u16) & (v.0[i] ^ w.0[i]);
                v.0[i] ^= exchange_vw;
                w.0[i] ^= exchange_vw;
                g.0[i] = reduce(g.0[i] + sign * f.0[i]);
                w.0[i] = reduce(w.0[i] + sign * v.0[i]);
            }
            g.0.copy_within(1.., 0);
            g.0[N - 1] = 0;
        }

        let mut inverse = Self::zero();
        for i in 0..N - 1 {
            inverse.0[i] = reduce(f.0[0] * v.0[N - 2 - i]);
        }
        inverse
    }

    /// For trits in {0, 1, 2}, returns zero iff each nonzero trit occurs WEIGHT/2 times.
    pub fn weight_failure(&self) -> u16 {
        let mut positive = 0u16;
        let mut negative_twice = 0u16;
        for &c in &self.0 {
            positive += c & 1;
            negative_twice += c & 2;
        }
        (positive ^ (negative_twice >> 1)) | (negative_twice ^ WEIGHT)
    }

    /// For coefficients below q, returns zero iff all are in {0, 1, q-1} and the last is zero.
    pub fn trinary_failure(&self) -> u16 {
        let mut invalid = self.0[N - 1];
        for &c in &self.0[..N - 1] {
            invalid |= (c + 1) & (Q - 4);
            invalid |= (c + 2) & 4;
        }
        invalid
    }
}
