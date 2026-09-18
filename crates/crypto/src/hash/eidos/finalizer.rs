//! Linear finalization of the raw Eidos XOF output.
//!
//! The fixed matrix is publicly derived with SHAKE256 and modeled as a random transparent setup.
//! Under the ideal-output model for the compression core, the leftover-hash-lemma bound gives
//! average-setup statistical distance below `2^-129` from uniform over four Goldilocks elements.
//! This is a random-setup assumption, not a fixed-instance extractor certificate.

/// Matrix mapping the sixteen raw Eidos XOF words to four Goldilocks field elements.
///
/// The entries were derived with SHAKE256 from the domain string
/// `BlakeG Finalizer Matrix m=4 n=16 v1`, using rejection sampling into the Goldilocks field.
/// Rows are output coordinates and columns follow the raw XOF word order.
#[doc(hidden)]
pub const FINALIZER_MATRIX: [[u64; 16]; 4] = [
    [
        15904662775280568261,
        11248103468244892543,
        9896915777956725816,
        185045353106015793,
        8500216796624591099,
        8360920247338155255,
        10180691449194265163,
        9837003373551522125,
        17467273734926731113,
        2417479524490811079,
        11233314090082918225,
        2233533576056214764,
        17209626757598516148,
        1311325837214623087,
        17541990409531268444,
        8778650702833371576,
    ],
    [
        10351818539131852076,
        16011254545682850612,
        17088821416796162493,
        288129510519252377,
        13610881561350213016,
        3540193630759490816,
        6810056141036989685,
        2582601007098108630,
        12095802721559781052,
        4693227732633196995,
        7475118991187684203,
        3613121121392294874,
        4075547714329698345,
        133921402081467462,
        2232830006922210412,
        9983172029845936448,
    ],
    [
        43492802588642506,
        3224823005913593020,
        16350268760635732189,
        3235941269094163408,
        12211684808931190196,
        11036966493196891711,
        18142572304476028282,
        8994326269973484641,
        13283425880831860268,
        858512574931661773,
        2994039940363751996,
        1639666242891561583,
        10544831527494131096,
        5657627761754840060,
        8399352252962716189,
        7729055846046801067,
    ],
    [
        5791738195767590909,
        8616178313052031618,
        9917353469636318118,
        5622607317059886827,
        9180561841259757438,
        8570780836823824523,
        10644109930340636559,
        5023452280734745604,
        16936908147648204300,
        13390427418905232145,
        167198939826968494,
        14327318216038165875,
        5175145684803592810,
        1063676696373794935,
        7285040222901297781,
        9407507053369299131,
    ],
];

const GOLDILOCKS_EPSILON: u64 = 0xffff_ffff;
const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;

/// Returns the canonical Goldilocks representative of `value`.
#[inline(always)]
fn reduce_u128(value: u128) -> u64 {
    let lo = value as u64;
    let hi = (value >> 64) as u64;
    let hi_hi = hi >> 32;
    let hi_lo = hi & 0xffff_ffff;

    let (mut reduced, borrow) = lo.overflowing_sub(hi_hi);
    if borrow {
        reduced = reduced.wrapping_sub(GOLDILOCKS_EPSILON);
    }

    let folded_hi = (hi_lo << 32).wrapping_sub(hi_lo);
    let (mut reduced, carry) = reduced.overflowing_add(folded_hi);
    if carry {
        reduced = reduced.wrapping_add(GOLDILOCKS_EPSILON);
    }
    if reduced >= GOLDILOCKS_MODULUS {
        reduced -= GOLDILOCKS_MODULUS;
    }
    reduced
}

/// Applies the finalizer matrix to one raw XOF output.
///
/// Output words `2 * j` and `2 * j + 1` are the low and high limbs of canonical coordinate `j`.
#[inline(always)]
pub(super) fn finalize_to_cv(input: &[u32; 16]) -> [u32; 8] {
    let mut accumulators = [0u128; 4];
    for (column, &word) in input.iter().enumerate() {
        let word = word as u128;
        for row in 0..4 {
            accumulators[row] += FINALIZER_MATRIX[row][column] as u128 * word;
        }
    }

    let output = accumulators.map(reduce_u128);
    core::array::from_fn(|word| {
        let value = output[word / 2];
        if word.is_multiple_of(2) {
            value as u32
        } else {
            (value >> 32) as u32
        }
    })
}

#[cfg(any(
    test,
    all(target_arch = "x86_64", feature = "std"),
    all(
        target_arch = "x86_64",
        not(feature = "std"),
        not(target_feature = "avx2"),
        not(target_feature = "avx512f"),
    ),
    all(target_arch = "wasm32", not(target_feature = "simd128")),
    all(
        not(target_arch = "aarch64"),
        not(target_arch = "x86_64"),
        not(target_arch = "wasm32"),
    ),
))]
/// Portable lane-wise form of [`finalize_to_cv`].
///
/// Lane `i` of the result equals `finalize_to_cv` applied to lane `i` of the input.
#[inline(always)]
pub(super) fn finalize_packed_to_cv<const LANES: usize>(
    input: &[[u32; LANES]; 16],
) -> [[u32; LANES]; 8] {
    let mut accumulators = [[0u128; LANES]; 4];
    for (column, words) in input.iter().enumerate() {
        for (lane, &word) in words.iter().enumerate() {
            let word = word as u128;
            for row in 0..4 {
                accumulators[row][lane] += FINALIZER_MATRIX[row][column] as u128 * word;
            }
        }
    }

    let output: [[u64; LANES]; 4] = core::array::from_fn(|row| {
        core::array::from_fn(|lane| reduce_u128(accumulators[row][lane]))
    });
    core::array::from_fn(|word| {
        core::array::from_fn(|lane| {
            let value = output[word / 2][lane];
            if word.is_multiple_of(2) {
                value as u32
            } else {
                (value >> 32) as u32
            }
        })
    })
}

/// Coefficient limbs for the backends that accumulate without carries.
///
/// Each matrix coefficient is split into three 22-bit limbs. A limb times a `u32` word is below
/// `2^54`, so the sixteen products of one dot product sum in a `u64` without overflow. The three
/// sums recombine as `s0 + 2^22 * s1 + 2^44 * s2`, which is below `2^103`.
///
/// The AVX2 and AVX-512 backends recombine in vector registers. With `M32 = 2^32 - 1`, regroup the
/// total by powers of `2^32` as `L0 + 2^32 * L1 + 2^64 * L2`:
///
/// ```text
/// L0 = (s0 & M32) + ((s1 & (2^10 - 1)) << 22)                  < 2^33
/// L1 = (s0 >> 32) + (s1 >> 10) + ((s2 & (2^20 - 1)) << 12)     < 2^49
/// L2 = s2 >> 20                                                < 2^38
/// ```
///
/// Since `2^64 = 2^32 - 1 (mod p)`, the total is `(L0 - L2) + 2^32 * (L1 + L2)`. Split
/// `L1 + L2 = h0 + 2^32 * h1` with `h0 < 2^32` and `h1 < 2^18`. Then
/// `2^32 * (L1 + L2) = 2^32 * h0 + (2^32 - 1) * h1 (mod p)`, so the total is
///
/// ```text
/// 2^32 * h0 + ((h1 << 32) + L0) - (h1 + L2)
/// ```
///
/// where `2^32 * h0 <= p - 1`, the added term is below `2^51`, and the subtracted term is below
/// `2^39`. A carry out of the addition is worth `2^32 - 1`, a borrow from the subtraction costs
/// `2^32 - 1`, and one conditional subtraction of `p` makes the result canonical.
#[cfg(any(
    target_arch = "aarch64",
    all(
        target_arch = "x86_64",
        any(
            feature = "std",
            all(target_feature = "avx2", not(target_feature = "avx512f")),
            all(target_feature = "avx512f", not(target_feature = "avx512ifma")),
        ),
    ),
))]
mod limbs {
    use super::FINALIZER_MATRIX;
    #[cfg(any(target_arch = "aarch64", test))]
    use super::reduce_u128;

    pub(super) const LIMB_BITS: u32 = 22;
    const LIMB_MASK: u64 = (1 << LIMB_BITS) - 1;

    // Sixteen products of a limb and a `u32` word fit in a `u64`.
    const _: () = assert!(16 * (LIMB_MASK as u128) * (u32::MAX as u128) <= u64::MAX as u128);

    /// `COEFFICIENT_LIMBS[column][limb][row]`.
    pub(super) const COEFFICIENT_LIMBS: [[[u32; 4]; 3]; 16] = {
        let mut limbs = [[[0u32; 4]; 3]; 16];
        let mut column = 0;
        while column < 16 {
            let mut row = 0;
            while row < 4 {
                let coefficient = FINALIZER_MATRIX[row][column];
                limbs[column][0][row] = (coefficient & LIMB_MASK) as u32;
                limbs[column][1][row] = ((coefficient >> LIMB_BITS) & LIMB_MASK) as u32;
                limbs[column][2][row] = (coefficient >> (2 * LIMB_BITS)) as u32;
                row += 1;
            }
            column += 1;
        }
        limbs
    };

    /// Returns the canonical value of `s0 + 2^22 * s1 + 2^44 * s2`.
    ///
    /// Every input must be below `2^58`.
    #[cfg(any(target_arch = "aarch64", test))]
    #[inline(always)]
    pub(super) fn recombine(s0: u64, s1: u64, s2: u64) -> u64 {
        debug_assert!(s0 < 1 << 58 && s1 < 1 << 58 && s2 < 1 << 58);
        reduce_u128(s0 as u128 + ((s1 as u128) << LIMB_BITS) + ((s2 as u128) << (2 * LIMB_BITS)))
    }
}

/// Computes [`finalize_packed_to_cv`] with the backend selected for the target.
#[inline(always)]
pub(super) fn finalize_packed_native_to_cv(
    input: &[[u32; super::PACKED_LANES]; 16],
) -> [[u32; super::PACKED_LANES]; 8] {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64_neon::finalize(input)
    }

    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    {
        if std::is_x86_feature_detected!("avx512f") && std::is_x86_feature_detected!("avx512ifma") {
            // SAFETY: runtime feature detection confirmed AVX-512F and AVX-512 IFMA support.
            return unsafe { x86_64_avx512ifma::finalize(input) };
        }
        if std::is_x86_feature_detected!("avx512f") {
            // SAFETY: runtime feature detection confirmed AVX-512F support.
            return unsafe { x86_64_avx512::finalize(input) };
        }
        if std::is_x86_feature_detected!("avx2") {
            // SAFETY: runtime feature detection confirmed AVX2 support.
            return unsafe { x86_64_avx2::finalize(input) };
        }
        finalize_packed_to_cv(input)
    }

    #[cfg(all(target_arch = "x86_64", not(feature = "std"), target_feature = "avx512ifma"))]
    {
        // SAFETY: AVX-512F and AVX-512 IFMA are enabled crate-wide in this configuration.
        unsafe { x86_64_avx512ifma::finalize(input) }
    }

    #[cfg(all(
        target_arch = "x86_64",
        not(feature = "std"),
        target_feature = "avx512f",
        not(target_feature = "avx512ifma"),
    ))]
    {
        // SAFETY: AVX-512F is enabled crate-wide in this configuration.
        unsafe { x86_64_avx512::finalize(input) }
    }

    #[cfg(all(
        target_arch = "x86_64",
        not(feature = "std"),
        not(target_feature = "avx512f"),
        target_feature = "avx2",
    ))]
    {
        // SAFETY: AVX2 is enabled crate-wide in this configuration.
        unsafe { x86_64_avx2::finalize(input) }
    }

    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    {
        packed_field::finalize(input)
    }

    #[cfg(all(
        not(target_arch = "aarch64"),
        not(all(target_arch = "x86_64", feature = "std")),
        not(all(target_arch = "x86_64", not(feature = "std"), target_feature = "avx512f")),
        not(all(
            target_arch = "x86_64",
            not(feature = "std"),
            not(target_feature = "avx512f"),
            target_feature = "avx2",
        )),
        not(all(target_arch = "wasm32", target_feature = "simd128")),
    ))]
    {
        finalize_packed_to_cv(input)
    }
}

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
mod packed_field {
    use miden_field::{Algebra, Felt, PackedFelt, PackedValue};

    use super::FINALIZER_MATRIX;

    #[inline(never)]
    pub(super) fn finalize(input: &[[u32; 16]; 16]) -> [[u32; 16]; 8] {
        const LANES: usize = 16;
        let coefficients = FINALIZER_MATRIX.map(|row| row.map(Felt::new_unchecked));
        let mut output = [[0u32; LANES]; 8];

        for first_lane in (0..LANES).step_by(PackedFelt::WIDTH) {
            let packed_input: [PackedFelt; 16] = core::array::from_fn(|column| {
                PackedFelt::from_fn(|lane| Felt::from_u32(input[column][first_lane + lane]))
            });

            for row in 0..4 {
                let finalized = PackedFelt::mixed_dot_product(&packed_input, &coefficients[row]);
                for lane in 0..PackedFelt::WIDTH {
                    let value = finalized.as_slice()[lane].as_canonical_u64();
                    output[2 * row][first_lane + lane] = value as u32;
                    output[2 * row + 1][first_lane + lane] = (value >> 32) as u32;
                }
            }
        }

        output
    }
}

#[cfg(all(target_arch = "x86_64", any(feature = "std", target_feature = "avx512f"),))]
mod x86_64_avx512_reduce {
    //! Reduction shared by the AVX-512 backends; see [`limbs`](super::limbs) for the derivation.

    use core::arch::x86_64::*;

    use super::{GOLDILOCKS_EPSILON, GOLDILOCKS_MODULUS};

    /// Returns the canonical value of `l0 + 2^32 * l1 + 2^64 * l2` in every lane.
    ///
    /// Requires `l0 < 2^33` and `l1 + l2 < 2^50`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the CPU supports AVX-512F.
    #[inline(always)]
    pub(super) unsafe fn reduce_radix32(l0: __m512i, l1: __m512i, l2: __m512i) -> __m512i {
        unsafe {
            debug_assert_eq!(_mm512_cmplt_epu64_mask(l0, _mm512_set1_epi64(1 << 33)), 0xff);
            debug_assert_eq!(
                _mm512_cmplt_epu64_mask(_mm512_add_epi64(l1, l2), _mm512_set1_epi64(1 << 50)),
                0xff
            );

            let mask32 = _mm512_set1_epi64(0xffff_ffff);
            let epsilon = _mm512_set1_epi64(GOLDILOCKS_EPSILON as i64);
            let modulus = _mm512_set1_epi64(GOLDILOCKS_MODULUS as i64);

            let h = _mm512_add_epi64(l1, l2);
            let h0 = _mm512_and_si512(h, mask32);
            let h1 = _mm512_srli_epi64::<32>(h);
            let added = _mm512_add_epi64(_mm512_slli_epi64::<32>(h1), l0);
            let subtracted = _mm512_add_epi64(h1, l2);

            let base = _mm512_slli_epi64::<32>(h0);
            let sum = _mm512_add_epi64(base, added);
            let carry = _mm512_cmplt_epu64_mask(sum, base);
            let sum = _mm512_mask_add_epi64(sum, carry, sum, epsilon);

            let borrow = _mm512_cmplt_epu64_mask(sum, subtracted);
            let difference = _mm512_sub_epi64(sum, subtracted);
            let difference = _mm512_mask_sub_epi64(difference, borrow, difference, epsilon);

            let above = _mm512_cmpge_epu64_mask(difference, modulus);
            _mm512_mask_sub_epi64(difference, above, difference, modulus)
        }
    }
}

#[cfg(all(
    target_arch = "x86_64",
    any(
        feature = "std",
        all(target_feature = "avx512f", not(target_feature = "avx512ifma")),
    ),
))]
mod x86_64_avx512 {
    //! AVX-512F finalizer for CPUs without AVX-512 IFMA. Each pass covers eight lanes and all four
    //! matrix rows: one `vpmuludq` and one `vpaddq` add the products of a coefficient limb with
    //! eight lanes to a `u64` accumulator vector. The limb sums are recombined in vector registers
    //! as described in [`limbs`](super::limbs).

    use core::arch::x86_64::*;

    use super::{
        limbs::{COEFFICIENT_LIMBS, LIMB_BITS},
        x86_64_avx512_reduce::reduce_radix32,
    };

    const LANES: usize = 16;
    const SIMD_LANES: usize = 8;

    // The shift counts in `recombine` are written for 22-bit limbs.
    const _: () = assert!(LIMB_BITS == 22);

    /// Returns the canonical value of `s0 + 2^22 * s1 + 2^44 * s2` in every lane.
    ///
    /// Every lane of every input must be below `2^58`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the CPU supports AVX-512F.
    #[inline(always)]
    pub(super) unsafe fn recombine(s0: __m512i, s1: __m512i, s2: __m512i) -> __m512i {
        unsafe {
            let limit = _mm512_set1_epi64(1 << 58);
            debug_assert_eq!(_mm512_cmplt_epu64_mask(s0, limit), 0xff);
            debug_assert_eq!(_mm512_cmplt_epu64_mask(s1, limit), 0xff);
            debug_assert_eq!(_mm512_cmplt_epu64_mask(s2, limit), 0xff);

            let mask32 = _mm512_set1_epi64(0xffff_ffff);
            let l0 = _mm512_add_epi64(
                _mm512_and_si512(s0, mask32),
                _mm512_slli_epi64::<22>(_mm512_and_si512(s1, _mm512_set1_epi64(0x3ff))),
            );
            let l1 = _mm512_add_epi64(
                _mm512_add_epi64(_mm512_srli_epi64::<32>(s0), _mm512_srli_epi64::<10>(s1)),
                _mm512_slli_epi64::<12>(_mm512_and_si512(s2, _mm512_set1_epi64(0xf_ffff))),
            );
            let l2 = _mm512_srli_epi64::<20>(s2);
            reduce_radix32(l0, l1, l2)
        }
    }

    #[inline(never)]
    #[target_feature(enable = "avx512f")]
    pub(super) unsafe fn finalize(input: &[[u32; LANES]; 16]) -> [[u32; LANES]; 8] {
        let mut output = [[0u32; LANES]; 8];
        for first_lane in (0..LANES).step_by(SIMD_LANES) {
            // SAFETY: this function requires AVX-512F. Every load reads eight words of a
            // sixteen-word row, and every store writes eight words of a sixteen-word row. The
            // accumulators stay below `2^58`, as `recombine` requires.
            unsafe {
                let mut acc = [[_mm512_setzero_si512(); 3]; 4];
                for column in 0..16 {
                    let words = _mm512_cvtepu32_epi64(_mm256_loadu_si256(
                        input[column].as_ptr().add(first_lane).cast(),
                    ));
                    for row in 0..4 {
                        for limb in 0..3 {
                            let coefficient =
                                _mm512_set1_epi64(COEFFICIENT_LIMBS[column][limb][row] as i64);
                            acc[row][limb] = _mm512_add_epi64(
                                acc[row][limb],
                                _mm512_mul_epu32(words, coefficient),
                            );
                        }
                    }
                }
                for row in 0..4 {
                    let value = recombine(acc[row][0], acc[row][1], acc[row][2]);
                    _mm256_storeu_si256(
                        output[2 * row].as_mut_ptr().add(first_lane).cast(),
                        _mm512_cvtepi64_epi32(value),
                    );
                    _mm256_storeu_si256(
                        output[2 * row + 1].as_mut_ptr().add(first_lane).cast(),
                        _mm512_cvtepi64_epi32(_mm512_srli_epi64::<32>(value)),
                    );
                }
            }
        }
        output
    }
}

#[cfg(all(target_arch = "x86_64", any(feature = "std", target_feature = "avx512ifma"),))]
mod x86_64_avx512ifma {
    //! AVX-512 IFMA finalizer. Each coefficient splits into a 52-bit limb `a0` and a 12-bit limb
    //! `a1`. For a `u32` word `x`, `x * a0` is below `2^84` and `x * a1` is below `2^44`, so with
    //!
    //! ```text
    //! A = sum of lo52(x * a0)                        < 2^56
    //! B = sum of hi52(x * a0) + sum of lo52(x * a1)  < 2^49
    //! ```
    //!
    //! the dot product is `A + 2^52 * B`. Each pass covers eight lanes and all four matrix rows
    //! with three fused multiply-adds per product vector and two accumulators per output.

    use core::arch::x86_64::*;

    use super::{FINALIZER_MATRIX, x86_64_avx512_reduce::reduce_radix32};

    const LANES: usize = 16;
    const SIMD_LANES: usize = 8;

    /// `IFMA_LIMBS[column][limb][row]`.
    const IFMA_LIMBS: [[[u64; 4]; 2]; 16] = {
        let mut limbs = [[[0u64; 4]; 2]; 16];
        let mut column = 0;
        while column < 16 {
            let mut row = 0;
            while row < 4 {
                let coefficient = FINALIZER_MATRIX[row][column];
                limbs[column][0][row] = coefficient & ((1 << 52) - 1);
                limbs[column][1][row] = coefficient >> 52;
                row += 1;
            }
            column += 1;
        }
        limbs
    };

    /// Returns the canonical value of `a + 2^52 * b` in every lane.
    ///
    /// Requires `a < 2^56` and `b < 2^49`. Regrouped by powers of `2^32`, the total is
    /// `l0 + 2^32 * l1 + 2^64 * l2` with `l0 = a & (2^32 - 1)`,
    /// `l1 = (a >> 32) + ((b & (2^12 - 1)) << 20)`, and `l2 = b >> 12`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the CPU supports AVX-512F.
    #[inline(always)]
    pub(super) unsafe fn recombine(a: __m512i, b: __m512i) -> __m512i {
        unsafe {
            debug_assert_eq!(_mm512_cmplt_epu64_mask(a, _mm512_set1_epi64(1 << 56)), 0xff);
            debug_assert_eq!(_mm512_cmplt_epu64_mask(b, _mm512_set1_epi64(1 << 49)), 0xff);

            let l0 = _mm512_and_si512(a, _mm512_set1_epi64(0xffff_ffff));
            let l1 = _mm512_add_epi64(
                _mm512_srli_epi64::<32>(a),
                _mm512_slli_epi64::<20>(_mm512_and_si512(b, _mm512_set1_epi64(0xfff))),
            );
            let l2 = _mm512_srli_epi64::<12>(b);
            reduce_radix32(l0, l1, l2)
        }
    }

    #[inline(never)]
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(super) unsafe fn finalize(input: &[[u32; LANES]; 16]) -> [[u32; LANES]; 8] {
        let mut output = [[0u32; LANES]; 8];
        for first_lane in (0..LANES).step_by(SIMD_LANES) {
            // SAFETY: this function requires AVX-512F and AVX-512 IFMA. Every load reads eight
            // words of a sixteen-word row, and every store writes eight words of a sixteen-word
            // row. The multiply-add operands are below `2^52`, and the accumulators stay within
            // the bounds `recombine` requires.
            unsafe {
                let mut acc_a = [_mm512_setzero_si512(); 4];
                let mut acc_b = [_mm512_setzero_si512(); 4];
                for column in 0..16 {
                    let words = _mm512_cvtepu32_epi64(_mm256_loadu_si256(
                        input[column].as_ptr().add(first_lane).cast(),
                    ));
                    for row in 0..4 {
                        let limb0 = _mm512_set1_epi64(IFMA_LIMBS[column][0][row] as i64);
                        let limb1 = _mm512_set1_epi64(IFMA_LIMBS[column][1][row] as i64);
                        acc_a[row] = _mm512_madd52lo_epu64(acc_a[row], words, limb0);
                        acc_b[row] = _mm512_madd52hi_epu64(acc_b[row], words, limb0);
                        acc_b[row] = _mm512_madd52lo_epu64(acc_b[row], words, limb1);
                    }
                }
                for row in 0..4 {
                    let value = recombine(acc_a[row], acc_b[row]);
                    _mm256_storeu_si256(
                        output[2 * row].as_mut_ptr().add(first_lane).cast(),
                        _mm512_cvtepi64_epi32(value),
                    );
                    _mm256_storeu_si256(
                        output[2 * row + 1].as_mut_ptr().add(first_lane).cast(),
                        _mm512_cvtepi64_epi32(_mm512_srli_epi64::<32>(value)),
                    );
                }
            }
        }
        output
    }
}

#[cfg(all(
    target_arch = "x86_64",
    any(feature = "std", all(not(target_feature = "avx512f"), target_feature = "avx2"),),
))]
mod x86_64_avx2 {
    //! AVX2 finalizer. Each pass covers four lanes and all four matrix rows: one `vpmuludq` and
    //! one `vpaddq` add the products of a coefficient limb with four lanes to a `u64` accumulator
    //! vector. The limb sums are recombined in vector registers as described in
    //! [`limbs`](super::limbs).

    use core::arch::x86_64::*;

    use super::{
        GOLDILOCKS_EPSILON, GOLDILOCKS_MODULUS,
        limbs::{COEFFICIENT_LIMBS, LIMB_BITS},
    };

    const LANES: usize = 16;
    const SIMD_LANES: usize = 4;

    // The shift counts in `recombine` are written for 22-bit limbs.
    const _: () = assert!(LIMB_BITS == 22);

    /// Returns all ones in lanes where `lhs < rhs` as unsigned integers, and zero otherwise.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the CPU supports AVX2.
    #[inline(always)]
    unsafe fn less_than_unsigned(lhs: __m256i, rhs: __m256i) -> __m256i {
        unsafe {
            let sign = _mm256_set1_epi64x(i64::MIN);
            _mm256_cmpgt_epi64(_mm256_xor_si256(rhs, sign), _mm256_xor_si256(lhs, sign))
        }
    }

    /// Returns the canonical value of `s0 + 2^22 * s1 + 2^44 * s2` in every lane.
    ///
    /// Every lane of every input must be below `2^58`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the CPU supports AVX2.
    #[inline(always)]
    pub(super) unsafe fn recombine(s0: __m256i, s1: __m256i, s2: __m256i) -> __m256i {
        unsafe {
            let limit = _mm256_set1_epi64x(1 << 58);
            debug_assert_eq!(
                _mm256_movemask_pd(_mm256_castsi256_pd(less_than_unsigned(s0, limit))),
                0xf
            );
            debug_assert_eq!(
                _mm256_movemask_pd(_mm256_castsi256_pd(less_than_unsigned(s1, limit))),
                0xf
            );
            debug_assert_eq!(
                _mm256_movemask_pd(_mm256_castsi256_pd(less_than_unsigned(s2, limit))),
                0xf
            );

            let mask32 = _mm256_set1_epi64x(0xffff_ffff);
            let epsilon = _mm256_set1_epi64x(GOLDILOCKS_EPSILON as i64);
            let modulus = _mm256_set1_epi64x(GOLDILOCKS_MODULUS as i64);

            let l0 = _mm256_add_epi64(
                _mm256_and_si256(s0, mask32),
                _mm256_slli_epi64::<22>(_mm256_and_si256(s1, _mm256_set1_epi64x(0x3ff))),
            );
            let l1 = _mm256_add_epi64(
                _mm256_add_epi64(_mm256_srli_epi64::<32>(s0), _mm256_srli_epi64::<10>(s1)),
                _mm256_slli_epi64::<12>(_mm256_and_si256(s2, _mm256_set1_epi64x(0xf_ffff))),
            );
            let l2 = _mm256_srli_epi64::<20>(s2);

            let h = _mm256_add_epi64(l1, l2);
            let h0 = _mm256_and_si256(h, mask32);
            let h1 = _mm256_srli_epi64::<32>(h);
            let added = _mm256_add_epi64(_mm256_slli_epi64::<32>(h1), l0);
            let subtracted = _mm256_add_epi64(h1, l2);

            let base = _mm256_slli_epi64::<32>(h0);
            let sum = _mm256_add_epi64(base, added);
            let carry = less_than_unsigned(sum, base);
            let sum = _mm256_add_epi64(sum, _mm256_and_si256(carry, epsilon));

            let borrow = less_than_unsigned(sum, subtracted);
            let difference = _mm256_sub_epi64(sum, subtracted);
            let difference = _mm256_sub_epi64(difference, _mm256_and_si256(borrow, epsilon));

            let below = less_than_unsigned(difference, modulus);
            _mm256_sub_epi64(difference, _mm256_andnot_si256(below, modulus))
        }
    }

    #[inline(never)]
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn finalize(input: &[[u32; LANES]; 16]) -> [[u32; LANES]; 8] {
        let mut output = [[0u32; LANES]; 8];
        for first_lane in (0..LANES).step_by(SIMD_LANES) {
            // SAFETY: this function requires AVX2. Every load reads four words of a sixteen-word
            // row, and every store writes four words of a sixteen-word row. The accumulators stay
            // below `2^58`, as `recombine` requires.
            unsafe {
                let mut acc = [[_mm256_setzero_si256(); 3]; 4];
                for column in 0..16 {
                    let words = _mm256_cvtepu32_epi64(_mm_loadu_si128(
                        input[column].as_ptr().add(first_lane).cast(),
                    ));
                    for row in 0..4 {
                        for limb in 0..3 {
                            let coefficient =
                                _mm256_set1_epi64x(COEFFICIENT_LIMBS[column][limb][row] as i64);
                            acc[row][limb] = _mm256_add_epi64(
                                acc[row][limb],
                                _mm256_mul_epu32(words, coefficient),
                            );
                        }
                    }
                }
                // Gather the low and the high `u32` of each `u64` lane into the low half.
                let low_words = _mm256_setr_epi32(0, 2, 4, 6, 0, 0, 0, 0);
                let high_words = _mm256_setr_epi32(1, 3, 5, 7, 0, 0, 0, 0);
                for row in 0..4 {
                    let value = recombine(acc[row][0], acc[row][1], acc[row][2]);
                    _mm_storeu_si128(
                        output[2 * row].as_mut_ptr().add(first_lane).cast(),
                        _mm256_castsi256_si128(_mm256_permutevar8x32_epi32(value, low_words)),
                    );
                    _mm_storeu_si128(
                        output[2 * row + 1].as_mut_ptr().add(first_lane).cast(),
                        _mm256_castsi256_si128(_mm256_permutevar8x32_epi32(value, high_words)),
                    );
                }
            }
        }
        output
    }
}

#[cfg(target_arch = "aarch64")]
mod aarch64_neon {
    //! aarch64 finalizer built on NEON widening multiply-accumulate.
    //!
    //! Each pass covers four lanes and all four matrix rows: one `umlal` adds the products of a
    //! coefficient limb with two lanes to a `u64` accumulator pair. The three limb sums of every
    //! output are recombined and reduced in scalar code. The output equals
    //! `finalize_packed_to_cv`, which the tests use as the reference.

    use core::arch::aarch64::*;

    use super::limbs::{COEFFICIENT_LIMBS, recombine};

    /// Accumulators indexed by `[row][limb][half]`; each half holds two lanes.
    type Accumulators = [[[uint64x2_t; 2]; 3]; 4];

    /// Adds the products of limb `$limb` of all four rows with the four lanes in `$words`.
    macro_rules! accumulate_limb {
        ($acc:ident, $limb:literal, $words:ident, $coefficients:ident) => {
            let low = vget_low_u32($words);
            $acc[0][$limb][0] = vmlal_laneq_u32::<0>($acc[0][$limb][0], low, $coefficients);
            $acc[0][$limb][1] = vmlal_high_laneq_u32::<0>($acc[0][$limb][1], $words, $coefficients);
            $acc[1][$limb][0] = vmlal_laneq_u32::<1>($acc[1][$limb][0], low, $coefficients);
            $acc[1][$limb][1] = vmlal_high_laneq_u32::<1>($acc[1][$limb][1], $words, $coefficients);
            $acc[2][$limb][0] = vmlal_laneq_u32::<2>($acc[2][$limb][0], low, $coefficients);
            $acc[2][$limb][1] = vmlal_high_laneq_u32::<2>($acc[2][$limb][1], $words, $coefficients);
            $acc[3][$limb][0] = vmlal_laneq_u32::<3>($acc[3][$limb][0], low, $coefficients);
            $acc[3][$limb][1] = vmlal_high_laneq_u32::<3>($acc[3][$limb][1], $words, $coefficients);
        };
    }

    #[inline(never)]
    pub(super) fn finalize(input: &[[u32; 16]; 16]) -> [[u32; 16]; 8] {
        let mut output = [[0u32; 16]; 8];
        for first_lane in (0..16).step_by(4) {
            let mut sums = [[[0u64; 4]; 3]; 4];
            // SAFETY: NEON is part of the aarch64 baseline. Every load reads four words of a
            // sixteen-word row or a four-word limb vector, and every store writes two words of a
            // four-word sum array.
            unsafe {
                let mut acc: Accumulators = [[[vdupq_n_u64(0); 2]; 3]; 4];
                for column in 0..16 {
                    let words = vld1q_u32(input[column].as_ptr().add(first_lane));
                    let limb0 = vld1q_u32(COEFFICIENT_LIMBS[column][0].as_ptr());
                    let limb1 = vld1q_u32(COEFFICIENT_LIMBS[column][1].as_ptr());
                    let limb2 = vld1q_u32(COEFFICIENT_LIMBS[column][2].as_ptr());
                    accumulate_limb!(acc, 0, words, limb0);
                    accumulate_limb!(acc, 1, words, limb1);
                    accumulate_limb!(acc, 2, words, limb2);
                }
                for row in 0..4 {
                    for limb in 0..3 {
                        vst1q_u64(sums[row][limb].as_mut_ptr(), acc[row][limb][0]);
                        vst1q_u64(sums[row][limb].as_mut_ptr().add(2), acc[row][limb][1]);
                    }
                }
            }

            for row in 0..4 {
                for lane in 0..4 {
                    let value =
                        recombine(sums[row][0][lane], sums[row][1][lane], sums[row][2][lane]);
                    output[2 * row][first_lane + lane] = value as u32;
                    output[2 * row + 1][first_lane + lane] = (value >> 32) as u32;
                }
            }
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use shake::{
        Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };

    use super::*;
    use crate::{Felt, field::Field};

    /// The four matrix outputs computed in field arithmetic, which shares no code with the
    /// optimized paths.
    fn field_reference(input: &[u32; 16]) -> [u64; 4] {
        core::array::from_fn(|row| {
            input
                .iter()
                .enumerate()
                .fold(Felt::ZERO, |sum, (column, &word)| {
                    sum + Felt::new_unchecked(FINALIZER_MATRIX[row][column]) * Felt::from_u32(word)
                })
                .as_canonical_u64()
        })
    }

    /// Joins the low and high limbs of a finalized chaining value into its four coordinates.
    fn coordinates(cv: &[u32; 8]) -> [u64; 4] {
        core::array::from_fn(|row| cv[2 * row] as u64 + ((cv[2 * row + 1] as u64) << 32))
    }

    /// Words that stress the accumulators and the reduction: random, zero, and at or near the
    /// maximum.
    fn word() -> impl Strategy<Value = u32> {
        prop_oneof![
            4 => any::<u32>(),
            1 => Just(0u32),
            1 => Just(u32::MAX),
            1 => (u32::MAX - 1024)..=u32::MAX,
        ]
    }

    fn raw_xof() -> impl Strategy<Value = [u32; 16]> {
        proptest::array::uniform16(word())
    }

    /// Built from a vector so that the strategy's state lives on the heap, not the test stack.
    fn packed_raw_xof() -> impl Strategy<Value = [[u32; super::super::PACKED_LANES]; 16]> {
        proptest::collection::vec(word(), 16 * super::super::PACKED_LANES).prop_map(|words| {
            core::array::from_fn(|column| {
                core::array::from_fn(|lane| words[column * super::super::PACKED_LANES + lane])
            })
        })
    }

    proptest! {
        /// The scalar path against field arithmetic.
        #[test]
        fn scalar_finalizer_matches_field_arithmetic(input in raw_xof()) {
            prop_assert_eq!(coordinates(&finalize_to_cv(&input)), field_reference(&input));
        }

        /// Whatever backend this machine dispatches to, lane by lane, against field arithmetic
        /// and against the portable path.
        #[test]
        fn native_packed_finalizer_matches_field_arithmetic(input in packed_raw_xof()) {
            let native = finalize_packed_native_to_cv(&input);
            prop_assert_eq!(native, finalize_packed_to_cv(&input));
            for lane in 0..super::super::PACKED_LANES {
                let single: [u32; 16] = core::array::from_fn(|column| input[column][lane]);
                let cv: [u32; 8] = core::array::from_fn(|word| native[word][lane]);
                prop_assert_eq!(coordinates(&cv), field_reference(&single), "lane {}", lane);
            }
        }
    }

    #[cfg(any(
        all(target_arch = "wasm32", target_feature = "simd128"),
        all(target_arch = "x86_64", feature = "std"),
        target_arch = "aarch64",
    ))]
    fn assert_packed_finalizer_matches(
        mut finalizer: impl FnMut(&[[u32; 16]; 16]) -> [[u32; 16]; 8],
    ) {
        let fixed_inputs = [
            [[0u32; 16]; 16],
            [[u32::MAX; 16]; 16],
            core::array::from_fn(|word| {
                core::array::from_fn(|lane| {
                    (word as u32)
                        .wrapping_mul(0x9e37_79b9)
                        .wrapping_add((lane as u32).wrapping_mul(0x85eb_ca6b))
                })
            }),
        ];
        for input in fixed_inputs {
            assert_eq!(finalizer(&input), finalize_packed_to_cv(&input));
        }

        // A single saturated lane or word must not leak into any other lane.
        for hot in 0..16 {
            let one_lane = core::array::from_fn(|_| {
                core::array::from_fn(|lane| if lane == hot { u32::MAX } else { 0 })
            });
            assert_eq!(finalizer(&one_lane), finalize_packed_to_cv(&one_lane));

            let one_word =
                core::array::from_fn(|word| if word == hot { [u32::MAX; 16] } else { [0; 16] });
            assert_eq!(finalizer(&one_word), finalize_packed_to_cv(&one_word));
        }

        let mut state = 0x243f_6a88_85a3_08d3u64;
        for _ in 0..1_000 {
            let input = core::array::from_fn(|_| {
                core::array::from_fn(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u32
                })
            });
            assert_eq!(finalizer(&input), finalize_packed_to_cv(&input));
        }
    }

    #[test]
    fn matrix_matches_its_public_derivation_and_has_full_row_rank() {
        let mut shake = Shake256::default();
        shake.update(b"BlakeG Finalizer Matrix m=4 n=16 v1");
        let mut reader = shake.finalize_xof();
        let derived = core::array::from_fn(|_| {
            core::array::from_fn(|_| {
                loop {
                    let mut bytes = [0u8; 8];
                    reader.read(&mut bytes);
                    let value = u64::from_le_bytes(bytes);
                    if value < GOLDILOCKS_MODULUS {
                        break value;
                    }
                }
            })
        });
        assert_eq!(derived, FINALIZER_MATRIX);

        let mut reduced = FINALIZER_MATRIX.map(|row| row.map(Felt::new_unchecked));
        let mut rank = 0;
        for column in 0..16 {
            let Some(pivot) = (rank..4).find(|&row| reduced[row][column] != Felt::ZERO) else {
                continue;
            };
            reduced.swap(rank, pivot);

            let inverse = reduced[rank][column].inverse();
            for entry in &mut reduced[rank][column..] {
                *entry *= inverse;
            }
            let pivot_row = reduced[rank];
            for row in reduced.iter_mut().skip(rank + 1) {
                let factor = row[column];
                for idx in column..16 {
                    row[idx] -= factor * pivot_row[idx];
                }
            }
            rank += 1;
            if rank == 4 {
                break;
            }
        }
        assert_eq!(rank, 4);
    }

    #[test]
    fn reduction_matches_direct_modulo_on_edges() {
        const MODULUS: u128 = GOLDILOCKS_MODULUS as u128;
        const MAX_MATRIX_ACCUMULATOR: u128 = 16 * (u64::MAX as u128) * (u32::MAX as u128);

        for value in [
            0,
            1,
            MODULUS - 1,
            MODULUS,
            MODULUS + 1,
            u64::MAX as u128,
            1u128 << 64,
            (1u128 << 64) + (1u128 << 32),
            // The subtraction of the top 32 bits borrows only when they exceed the low 64 bits.
            1u128 << 96,
            (u32::MAX as u128) << 96,
            ((u32::MAX as u128) << 96) + (u32::MAX as u128 - 1),
            ((u32::MAX as u128) << 96) + ((u32::MAX as u128) << 64),
            MAX_MATRIX_ACCUMULATOR,
            u128::MAX,
        ] {
            assert_eq!(reduce_u128(value), (value % MODULUS) as u64);
        }
    }

    /// A 128-bit value assembled from the three parts the reduction treats differently, each
    /// drawn from its own edges so that the borrow and carry corrections fire routinely.
    fn reduction_input() -> impl Strategy<Value = u128> {
        let low = prop_oneof![
            3 => any::<u64>(),
            2 => 0u64..1 << 32,
            1 => Just(0u64),
            1 => Just(u64::MAX),
        ];
        let high_part = prop_oneof![
            3 => any::<u32>(),
            1 => Just(0u32),
            1 => Just(1u32),
            1 => Just(u32::MAX),
        ];
        (low, high_part.clone(), high_part).prop_map(|(lo, hi_lo, hi_hi)| {
            lo as u128 + ((hi_lo as u128) << 64) + ((hi_hi as u128) << 96)
        })
    }

    proptest! {
        #[test]
        fn reduction_matches_direct_modulo(value in reduction_input()) {
            prop_assert_eq!(reduce_u128(value), (value % GOLDILOCKS_MODULUS as u128) as u64);
        }
    }

    #[test]
    fn reduction_matches_native_field_arithmetic() {
        let inputs = [
            [0u32; 16],
            [u32::MAX; 16],
            core::array::from_fn(|idx| idx as u32),
            core::array::from_fn(|idx| (idx as u32).wrapping_mul(0x9e37_79b9)),
        ];

        for input in inputs {
            assert_eq!(coordinates(&finalize_to_cv(&input)), field_reference(&input));
        }
    }

    /// Largest sum of sixteen products of a limb and a `u32` word.
    #[cfg(any(
        target_arch = "aarch64",
        all(
            target_arch = "x86_64",
            any(
                feature = "std",
                all(target_feature = "avx2", not(target_feature = "avx512f")),
                all(target_feature = "avx512f", not(target_feature = "avx512ifma")),
            ),
        ),
    ))]
    const MAX_LIMB_SUM: u64 = 16 * ((1 << limbs::LIMB_BITS) - 1) * (u32::MAX as u64);

    #[cfg(any(
        target_arch = "aarch64",
        all(
            target_arch = "x86_64",
            any(
                feature = "std",
                all(target_feature = "avx2", not(target_feature = "avx512f")),
                all(target_feature = "avx512f", not(target_feature = "avx512ifma")),
            ),
        ),
    ))]
    #[test]
    fn coefficient_limbs_recompose_the_matrix() {
        use limbs::{COEFFICIENT_LIMBS, LIMB_BITS};

        for (column, column_limbs) in COEFFICIENT_LIMBS.iter().enumerate() {
            for row in 0..4 {
                let [limb0, limb1, limb2] = column_limbs.map(|limb| limb[row] as u64);
                assert!(limb0 < 1 << LIMB_BITS && limb1 < 1 << LIMB_BITS);
                assert_eq!(
                    limb0 + (limb1 << LIMB_BITS) + (limb2 << (2 * LIMB_BITS)),
                    FINALIZER_MATRIX[row][column],
                );
            }
        }
    }

    #[cfg(any(
        target_arch = "aarch64",
        all(
            target_arch = "x86_64",
            any(
                feature = "std",
                all(target_feature = "avx2", not(target_feature = "avx512f")),
                all(target_feature = "avx512f", not(target_feature = "avx512ifma")),
            ),
        ),
    ))]
    #[test]
    fn limb_recombination_matches_direct_modulo_on_edges() {
        use limbs::{LIMB_BITS, recombine};

        const MODULUS: u128 = GOLDILOCKS_MODULUS as u128;
        let edges = [
            0,
            1,
            (1 << LIMB_BITS) - 1,
            1 << LIMB_BITS,
            1 << 32,
            MAX_LIMB_SUM - 1,
            MAX_LIMB_SUM,
        ];
        for s0 in edges {
            for s1 in edges {
                for s2 in edges {
                    let direct = (s0 as u128
                        + ((s1 as u128) << LIMB_BITS)
                        + ((s2 as u128) << (2 * LIMB_BITS)))
                        % MODULUS;
                    assert_eq!(recombine(s0, s1, s2), direct as u64);
                }
            }
        }
    }

    #[cfg(any(
        target_arch = "aarch64",
        all(
            target_arch = "x86_64",
            any(
                feature = "std",
                all(target_feature = "avx2", not(target_feature = "avx512f")),
                all(target_feature = "avx512f", not(target_feature = "avx512ifma")),
            ),
        ),
    ))]
    proptest! {
        /// The scalar recombination against direct modular arithmetic over the whole input range.
        #[test]
        fn limb_recombination_matches_direct_modulo(
            s0 in 0..=MAX_LIMB_SUM,
            s1 in 0..=MAX_LIMB_SUM,
            s2 in 0..=MAX_LIMB_SUM,
        ) {
            let direct = (s0 as u128 + ((s1 as u128) << 22) + ((s2 as u128) << 44))
                % GOLDILOCKS_MODULUS as u128;
            prop_assert_eq!(limbs::recombine(s0, s1, s2), direct as u64);
        }
    }

    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    proptest! {
        /// The AVX2 and AVX-512 recombinations against the scalar one on random lanes.
        #[test]
        fn x86_vector_recombinations_match_scalar_recombination(
            sums in proptest::array::uniform3(proptest::array::uniform8(0..=MAX_LIMB_SUM)),
        ) {
            let expected: [u64; 8] = core::array::from_fn(|lane| {
                limbs::recombine(sums[0][lane], sums[1][lane], sums[2][lane])
            });
            if std::is_x86_feature_detected!("avx2") {
                for half in 0..2 {
                    let quarter: [[u64; 4]; 3] = core::array::from_fn(|limb| {
                        core::array::from_fn(|lane| sums[limb][4 * half + lane])
                    });
                    // SAFETY: runtime feature detection above confirmed AVX2 support.
                    let lanes = unsafe { avx2_recombine_lanes(&quarter) };
                    prop_assert_eq!(&lanes[..], &expected[4 * half..4 * half + 4]);
                }
            }
            if std::is_x86_feature_detected!("avx512f") {
                // SAFETY: runtime feature detection above confirmed AVX-512F support.
                let lanes = unsafe { avx512_recombine_lanes(&sums) };
                prop_assert_eq!(lanes, expected);
            }
        }
    }

    /// Limb-sum triples that reach every branch of the vector recombination.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    fn limb_sum_triples() -> std::vec::Vec<[u64; 3]> {
        const MAX_SUM: u64 = MAX_LIMB_SUM;

        let edges = [
            0,
            1,
            (1 << 10) - 1,
            1 << 10,
            (1 << 20) - 1,
            1 << 20,
            1 << 32,
            MAX_SUM - 1,
            MAX_SUM,
        ];
        let mut triples = std::vec::Vec::new();
        for s0 in edges {
            for s1 in edges {
                for s2 in edges {
                    triples.push([s0, s1, s2]);
                }
            }
        }
        for j in 1..64u64 {
            // `h0 = 0` with a large subtracted term forces the borrow.
            triples.push([0, 0, j << 52]);
            triples.push([j, 0, j << 52]);
            // A saturated `h0` with a large added term forces the carry.
            triples.push([u32::MAX as u64, MAX_SUM - j, ((1 << 20) - 1 - j) | (j << 20)]);
        }
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..200_000 {
            triples.push(core::array::from_fn(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state % (MAX_SUM + 1)
            }));
        }
        // Chunks of four and eight lanes must cover every triple.
        while !triples.len().is_multiple_of(8) {
            triples.push([0, 0, 0]);
        }
        triples
    }

    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    #[target_feature(enable = "avx2")]
    unsafe fn avx2_recombine_lanes(sums: &[[u64; 4]; 3]) -> [u64; 4] {
        use core::arch::x86_64::*;

        let mut lanes = [0u64; 4];
        // SAFETY: every load and the store cover one four-word array.
        unsafe {
            let value = x86_64_avx2::recombine(
                _mm256_loadu_si256(sums[0].as_ptr().cast()),
                _mm256_loadu_si256(sums[1].as_ptr().cast()),
                _mm256_loadu_si256(sums[2].as_ptr().cast()),
            );
            _mm256_storeu_si256(lanes.as_mut_ptr().cast(), value);
        }
        lanes
    }

    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    #[target_feature(enable = "avx512f")]
    unsafe fn avx512_recombine_lanes(sums: &[[u64; 8]; 3]) -> [u64; 8] {
        use core::arch::x86_64::*;

        let mut lanes = [0u64; 8];
        // SAFETY: every load and the store cover one eight-word array.
        unsafe {
            let value = x86_64_avx512::recombine(
                _mm512_loadu_si512(sums[0].as_ptr().cast()),
                _mm512_loadu_si512(sums[1].as_ptr().cast()),
                _mm512_loadu_si512(sums[2].as_ptr().cast()),
            );
            _mm512_storeu_si512(lanes.as_mut_ptr().cast(), value);
        }
        lanes
    }

    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    #[test]
    fn x86_avx2_recombination_matches_scalar_recombination() {
        if !std::is_x86_feature_detected!("avx2") {
            std::eprintln!("skipped: the running CPU lacks AVX2");
            return;
        }

        for chunk in limb_sum_triples().chunks_exact(4) {
            let sums = core::array::from_fn(|limb| core::array::from_fn(|lane| chunk[lane][limb]));
            // SAFETY: runtime feature detection above confirmed AVX2 support.
            let lanes = unsafe { avx2_recombine_lanes(&sums) };
            for (lane, &[s0, s1, s2]) in chunk.iter().enumerate() {
                assert_eq!(lanes[lane], limbs::recombine(s0, s1, s2), "{s0} {s1} {s2}");
            }
        }
    }

    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    #[test]
    fn x86_avx512_recombination_matches_scalar_recombination() {
        if !std::is_x86_feature_detected!("avx512f") {
            std::eprintln!("skipped: the running CPU lacks AVX-512F");
            return;
        }

        for chunk in limb_sum_triples().chunks_exact(8) {
            let sums = core::array::from_fn(|limb| core::array::from_fn(|lane| chunk[lane][limb]));
            // SAFETY: runtime feature detection above confirmed AVX-512F support.
            let lanes = unsafe { avx512_recombine_lanes(&sums) };
            for (lane, &[s0, s1, s2]) in chunk.iter().enumerate() {
                assert_eq!(lanes[lane], limbs::recombine(s0, s1, s2), "{s0} {s1} {s2}");
            }
        }
    }

    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    #[test]
    fn wasm_simd_packed_finalizer_matches_scalar_lanes() {
        assert_packed_finalizer_matches(packed_field::finalize);
    }

    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    #[test]
    fn x86_avx2_finalizer_matches_scalar_lanes() {
        if !std::is_x86_feature_detected!("avx2") {
            std::eprintln!("skipped: the running CPU lacks AVX2");
            return;
        }

        assert_packed_finalizer_matches(|input| {
            // SAFETY: runtime feature detection above confirmed AVX2 support.
            unsafe { x86_64_avx2::finalize(input) }
        });
    }

    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    #[test]
    fn x86_avx512_finalizer_matches_scalar_lanes() {
        if !std::is_x86_feature_detected!("avx512f") {
            std::eprintln!("skipped: the running CPU lacks AVX-512F");
            return;
        }

        assert_packed_finalizer_matches(|input| {
            // SAFETY: runtime feature detection above confirmed AVX-512F support.
            unsafe { x86_64_avx512::finalize(input) }
        });
    }

    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    #[target_feature(enable = "avx512f,avx512ifma")]
    unsafe fn avx512ifma_recombine_lanes(a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
        use core::arch::x86_64::*;

        let mut lanes = [0u64; 8];
        // SAFETY: both loads and the store cover one eight-word array.
        unsafe {
            let value = x86_64_avx512ifma::recombine(
                _mm512_loadu_si512(a.as_ptr().cast()),
                _mm512_loadu_si512(b.as_ptr().cast()),
            );
            _mm512_storeu_si512(lanes.as_mut_ptr().cast(), value);
        }
        lanes
    }

    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    #[test]
    fn x86_avx512ifma_recombination_matches_direct_modulo() {
        if !(std::is_x86_feature_detected!("avx512f")
            && std::is_x86_feature_detected!("avx512ifma"))
        {
            std::eprintln!("skipped: the running CPU lacks AVX-512 IFMA");
            return;
        }

        const MODULUS: u128 = GOLDILOCKS_MODULUS as u128;
        // Largest sums of sixteen low and sixteen high-plus-top-limb multiply-add terms.
        const MAX_A: u64 = 16 * ((1 << 52) - 1);
        const MAX_B: u64 = 16 * ((1 << 32) + (1 << 44));

        let mut pairs = std::vec::Vec::new();
        for a in [0, 1, (1 << 32) - 1, 1 << 32, MAX_A - 1, MAX_A] {
            for b in [0, 1, 0xfff, 0x1000, 1 << 44, MAX_B - 1, MAX_B] {
                pairs.push([a, b]);
            }
        }
        for j in 1..32u64 {
            // `h0 = 0` with a large subtracted term forces the borrow.
            pairs.push([0, j << 44]);
            pairs.push([j, j << 44]);
            pairs.push([MAX_A - j, (j << 44) | 0xfff]);
        }
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = |bound: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % (bound + 1)
        };
        for _ in 0..200_000 {
            pairs.push([next(MAX_A), next(MAX_B)]);
        }

        for chunk in pairs.chunks_exact(8) {
            let a = core::array::from_fn(|lane| chunk[lane][0]);
            let b = core::array::from_fn(|lane| chunk[lane][1]);
            // SAFETY: runtime feature detection above confirmed AVX-512F and AVX-512 IFMA support.
            let lanes = unsafe { avx512ifma_recombine_lanes(&a, &b) };
            for (lane, &[a, b]) in chunk.iter().enumerate() {
                let direct = (a as u128 + ((b as u128) << 52)) % MODULUS;
                assert_eq!(lanes[lane], direct as u64, "{a} {b}");
            }
        }
    }

    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    #[test]
    fn x86_avx512ifma_finalizer_matches_scalar_lanes() {
        if !(std::is_x86_feature_detected!("avx512f")
            && std::is_x86_feature_detected!("avx512ifma"))
        {
            std::eprintln!("skipped: the running CPU lacks AVX-512 IFMA");
            return;
        }

        assert_packed_finalizer_matches(|input| {
            // SAFETY: runtime feature detection above confirmed AVX-512F and AVX-512 IFMA support.
            unsafe { x86_64_avx512ifma::finalize(input) }
        });
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn aarch64_neon_finalizer_matches_scalar_lanes() {
        assert_packed_finalizer_matches(aarch64_neon::finalize);
    }
}
