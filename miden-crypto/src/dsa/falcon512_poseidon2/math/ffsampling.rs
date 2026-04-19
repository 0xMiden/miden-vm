use alloc::boxed::Box;

use num::Zero;
use num_complex::{Complex, Complex64};
use rand::Rng;

use super::{fft::FastFft, polynomial::Polynomial, samplerz::sampler_z};
use crate::utils::zeroize::{Zeroize, ZeroizeOnDrop};

const SIGMIN: f64 = 1.2778336969128337;

/// Computes the Gram matrix. The argument must be a 2x2 matrix
/// whose elements are equal-length vectors of complex numbers,
/// representing polynomials in FFT domain.
pub fn gram(b: [Polynomial<Complex64>; 4]) -> [Polynomial<Complex64>; 4] {
    const N: usize = 2;
    let mut g: [Polynomial<Complex<f64>>; 4] =
        [Polynomial::zero(), Polynomial::zero(), Polynomial::zero(), Polynomial::zero()];
    for i in 0..N {
        for j in 0..N {
            for k in 0..N {
                g[N * i + j] = g[N * i + j].clone()
                    + b[N * i + k].hadamard_mul(&b[N * j + k].map(Complex::conj));
            }
        }
    }
    g
}

/// Computes the LDL decomposition of a 2×2 Hermitian matrix G such that L·D·L* = G
/// where D is diagonal, and L is lower-triangular with 1s on the diagonal.
///
/// # Input
/// A 2×2 Hermitian (self-adjoint) matrix G represented as a 4-element array in row-major order:
/// ```text
/// G = [g[0]     g[1]  ]
///     [g[2]     g[3]  ]
/// ```
/// where `g[1] = conj(g[2])` (Hermitian) and all elements are polynomials in FFT domain.
///
/// # Output
/// Returns only the non-trivial elements: (l10, d00, d11) representing:
/// ```text
/// L = [1    0  ]    D = [d00   0  ]
///     [l10  1  ]        [0    d11 ]
/// ```
///
/// More specifically:
///
/// From the equation L·D·L* = G, we can derive:
/// 1. From position (0,0): 1·d00·1 = `g[0]` → **d00 = `g[0]`**
///
/// 2. From position (1,0): l10·d00·1 = `g[2]` → **l10 = `g[2]` / `g[0]`**
///
/// 3. From position (1,1): l10·d00·conj(l10) + 1·d11·1 = `g[3]` → d11 = `g[3]` - l10·d00·conj(l10)
///    → **d11 = `g[3]` - |l10|²·`g[0]`**
pub fn ldl(
    g: [Polynomial<Complex64>; 4],
) -> (Polynomial<Complex64>, Polynomial<Complex64>, Polynomial<Complex64>) {
    // Compute l10 = g[2] / g[0]
    let l10 = g[2].hadamard_div(&g[0]);

    // Compute |l10|² = l10 * conj(l10)
    let l10_squared_norm = l10.map(|c| c * c.conj());

    // Compute d11 = g[3] - |l10|² * g[0]
    let d11 = g[3].clone() - g[0].hadamard_mul(&l10_squared_norm);

    (l10, g[0].clone(), d11)
}

#[derive(Debug, Clone)]
pub enum LdlTree {
    Branch(Polynomial<Complex64>, Box<LdlTree>, Box<LdlTree>),
    Leaf([Complex64; 2]),
}

impl Zeroize for LdlTree {
    fn zeroize(&mut self) {
        match self {
            LdlTree::Branch(poly, left, right) => {
                // Zeroize polynomial coefficients using write_volatile to prevent compiler
                // optimizations (dead store elimination)
                for coeff in poly.coefficients.iter_mut() {
                    unsafe {
                        core::ptr::write_volatile(coeff, Complex64::new(0.0, 0.0));
                    }
                }

                // Recursively zeroize child nodes
                left.zeroize();
                right.zeroize();

                // Compiler fence AFTER all zeroing operations to prevent reordering.
                // This ensures all writes (both at this level and in recursive calls) are
                // completed before any subsequent code can observe them.
                core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            },
            LdlTree::Leaf(arr) => {
                // Zeroize leaf array using write_volatile
                for val in arr.iter_mut() {
                    unsafe {
                        core::ptr::write_volatile(val, Complex64::new(0.0, 0.0));
                    }
                }

                // Compiler fence after all writes to prevent reordering with subsequent code
                core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            },
        }
    }
}

// Manual Drop implementation to ensure zeroization on drop.
// Cannot use #[derive(ZeroizeOnDrop)] because Complex64 doesn't implement Zeroize,
// so we manually implement Drop to call our Zeroize impl.
impl Drop for LdlTree {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for LdlTree {}

/// Computes the LDL Tree of G. Corresponds to Algorithm 9 of the specification [1, p.37].
/// The argument is a 2x2 matrix of polynomials, given in FFT form.
///
/// [1]: <https://falcon-sign.info/falcon.pdf>
pub fn ffldl(gram_matrix: [Polynomial<Complex64>; 4]) -> LdlTree {
    let n = gram_matrix[0].coefficients.len();
    let (l10, d00, d11) = ldl(gram_matrix);

    if n > 2 {
        let (d00_left, d00_right) = d00.split_fft();
        let (d11_left, d11_right) = d11.split_fft();
        let g0 = [d00_left.clone(), d00_right.clone(), d00_right.map(Complex::conj), d00_left];
        let g1 = [d11_left.clone(), d11_right.clone(), d11_right.map(Complex::conj), d11_left];
        LdlTree::Branch(l10, Box::new(ffldl(g0)), Box::new(ffldl(g1)))
    } else {
        LdlTree::Branch(
            l10,
            Box::new(LdlTree::Leaf(d00.coefficients.try_into().unwrap())),
            Box::new(LdlTree::Leaf(d11.coefficients.try_into().unwrap())),
        )
    }
}

/// Normalizes the leaves of an LDL tree using a given normalization value `sigma`.
pub fn normalize_tree(tree: &mut LdlTree, sigma: f64) {
    match tree {
        LdlTree::Branch(_ell, left, right) => {
            normalize_tree(left, sigma);
            normalize_tree(right, sigma);
        },
        LdlTree::Leaf(vector) => {
            vector[0] = Complex::new(sigma / vector[0].re.sqrt(), 0.0);
            vector[1] = Complex64::zero();
        },
    }
}

/// Samples short polynomials using a Falcon tree. Algorithm 11 from the spec [1, p.40].
///
/// [1]: <https://falcon-sign.info/falcon.pdf>
pub fn ffsampling<R: Rng>(
    t: &(Polynomial<Complex64>, Polynomial<Complex64>),
    tree: &LdlTree,
    mut rng: &mut R,
) -> (Polynomial<Complex64>, Polynomial<Complex64>) {
    match tree {
        LdlTree::Branch(ell, left, right) => {
            let bold_t1 = t.1.split_fft();
            let bold_z1 = ffsampling(&bold_t1, right, rng);
            let z1 = Polynomial::<Complex64>::merge_fft(&bold_z1.0, &bold_z1.1);

            // t0' = t0  + (t1 - z1) * l
            let t0_prime = t.0.clone() + (t.1.clone() - z1.clone()).hadamard_mul(ell);

            let bold_t0 = t0_prime.split_fft();
            let bold_z0 = ffsampling(&bold_t0, left, rng);
            let z0 = Polynomial::<Complex64>::merge_fft(&bold_z0.0, &bold_z0.1);

            (z0, z1)
        },
        LdlTree::Leaf(value) => {
            let z0 = sampler_z(t.0.coefficients[0].re, value[0].re, SIGMIN, &mut rng);
            let z1 = sampler_z(t.1.coefficients[0].re, value[0].re, SIGMIN, &mut rng);
            (
                Polynomial::new(vec![Complex64::new(z0 as f64, 0.0)]),
                Polynomial::new(vec![Complex64::new(z1 as f64, 0.0)]),
            )
        },
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use num_complex::Complex64;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use super::*;

    /// Helper to reconstruct G from L and D matrices by computing L·D·L*
    ///
    /// All polynomials are in FFT domain, so we use Hadamard (element-wise) operations.
    ///
    /// Given L = [1    0 ]  and D = [d00  0  ]
    ///           [l10  1 ]          [0    d11]
    ///
    /// We compute G = L·D·L* = [1    0 ] [d00  0  ] [1       conj(l10)]
    ///                         [l10  1 ] [0    d11] [0       1        ]
    fn reconstruct_g(
        l10: &Polynomial<Complex64>,
        d00: &Polynomial<Complex64>,
        d11: &Polynomial<Complex64>,
    ) -> [Polynomial<Complex64>; 4] {
        // Compute conj(l10) for use in L*
        let l10_conj = l10.map(Complex::conj);

        // Compute G = L·D·L* using Hadamard operations (FFT domain)
        // G[0,0] = 1*d00*1 + 0*d11*0 = d00
        let g00 = d00.clone();

        // G[0,1] = 1*d00*conj(l10) + 0*d11*1 = d00 * conj(l10)
        let g01 = d00.hadamard_mul(&l10_conj);

        // G[1,0] = l10*d00*1 + 1*d11*0 = l10 * d00
        let g10 = l10.hadamard_mul(d00);

        // G[1,1] = l10*d00*conj(l10) + 1*d11*1 = l10 * d00 * conj(l10) + d11
        let g11 = l10.hadamard_mul(d00).hadamard_mul(&l10_conj) + d11.clone();

        [g00, g01, g10, g11]
    }

    /// Helper to create a random Hermitian matrix G.
    ///
    /// The polynomials are in FFT domain (each coefficient represents an evaluation point).
    /// Returns a 2×2 matrix as [g00, g01, g10, g11] where:
    /// - g00 and g11 are self-adjoint (real-valued in FFT domain)
    /// - g10 = conj(g01) (Hermitian property)
    fn random_hermitian_matrix(n: usize, rng: &mut impl Rng) -> [Polynomial<Complex64>; 4] {
        let mut g00 = vec![Complex64::new(0.0, 0.0); n];
        let mut g01 = vec![Complex64::new(0.0, 0.0); n];
        let mut g11 = vec![Complex64::new(0.0, 0.0); n];

        for i in 0..n {
            // Diagonal elements must be real (self-adjoint property)
            g00[i] = Complex64::new(rng.random_range(-10.0..10.0), 0.0);
            g11[i] = Complex64::new(rng.random_range(-10.0..10.0), 0.0);

            // Off-diagonal can be any complex number
            g01[i] = Complex64::new(rng.random_range(-10.0..10.0), rng.random_range(-10.0..10.0));
        }

        // Ensure Hermitian property: g10 = conj(g01)
        let g10 = g01.iter().map(Complex::conj).collect();

        [
            Polynomial::new(g00),
            Polynomial::new(g01),
            Polynomial::new(g10),
            Polynomial::new(g11),
        ]
    }

    /// Helper to check if two polynomials are approximately equal
    fn polynomials_approx_eq(
        a: &Polynomial<Complex64>,
        b: &Polynomial<Complex64>,
        eps: f64,
    ) -> bool {
        if a.coefficients.len() != b.coefficients.len() {
            return false;
        }
        a.coefficients
            .iter()
            .zip(b.coefficients.iter())
            .all(|(x, y)| (x.re - y.re).abs() < eps && (x.im - y.im).abs() < eps)
    }

    /// Test that LDL decomposition satisfies L·D·L* = G for random polynomials in FFT domain.
    ///
    /// This test verifies the mathematical correctness by:
    /// 1. Creating random Hermitian matrices G (in FFT domain)
    /// 2. Computing their LDL decomposition
    /// 3. Reconstructing G from L and D using Hadamard operations
    /// 4. Verifying the reconstruction matches the original
    #[test]
    fn test_ldl_decomposition_random() {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

        // Test with various polynomial sizes
        for degree in [1, 2, 16, 512] {
            let g = random_hermitian_matrix(degree, &mut rng);

            // Compute LDL decomposition
            let (l10, d00, d11) = ldl(g.clone());

            // Reconstruct G from L·D·L*
            let g_reconstructed = reconstruct_g(&l10, &d00, &d11);

            // Verify reconstruction matches original (L·D·L* = G)
            assert!(
                polynomials_approx_eq(&g_reconstructed[0], &g[0], 1e-10),
                "degree {degree}: G[0,0] mismatch"
            );
            assert!(
                polynomials_approx_eq(&g_reconstructed[1], &g[1], 1e-10),
                "degree {degree}: G[0,1] mismatch"
            );
            assert!(
                polynomials_approx_eq(&g_reconstructed[2], &g[2], 1e-10),
                "degree {degree}: G[1,0] mismatch"
            );
            assert!(
                polynomials_approx_eq(&g_reconstructed[3], &g[3], 1e-10),
                "degree {degree}: G[1,1] mismatch"
            );
        }
    }
}
