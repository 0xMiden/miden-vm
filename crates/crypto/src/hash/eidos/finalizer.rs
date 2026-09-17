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

/// Computes [`finalize_packed_to_cv`] with the backend selected for the target.
#[inline(always)]
pub(super) fn finalize_packed_native_to_cv(
    input: &[[u32; super::PACKED_LANES]; 16],
) -> [[u32; super::PACKED_LANES]; 8] {
    #[cfg(target_arch = "aarch64")]
    {
        #[cfg(all(target_os = "linux", feature = "std"))]
        if std::arch::is_aarch64_feature_detected!("sve") {
            // SAFETY: runtime feature detection confirmed SVE support.
            return unsafe { aarch64_sve::finalize(input) };
        }
        #[cfg(all(target_os = "linux", not(feature = "std"), target_feature = "sve"))]
        {
            // SAFETY: SVE is enabled crate-wide in this configuration.
            unsafe { aarch64_sve::finalize(input) }
        }
        #[cfg(not(all(target_os = "linux", not(feature = "std"), target_feature = "sve")))]
        {
            packed4::finalize(input)
        }
    }

    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    {
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

    #[cfg(all(target_arch = "x86_64", not(feature = "std"), target_feature = "avx512f"))]
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

#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    any(feature = "std", target_feature = "sve"),
))]
mod aarch64_sve {
    use core::arch::global_asm;

    // This leaf assembly function computes the four finalizer dot products with
    // vector-length-agnostic 64-bit lanes and an exact low/high representation for each 128-bit
    // accumulator. It follows the standard AArch64 procedure-call convention and uses only
    // caller-saved general, predicate, and vector registers.
    global_asm!(
        r#"
        .text
        .arch armv8-a+sve
        .p2align 2
        .hidden miden_eidos_matrix_finalize_sve
        .type miden_eidos_matrix_finalize_sve, %function
    miden_eidos_matrix_finalize_sve:
        .cfi_startproc
        mov     x3, #0
        mov     x4, #16
        mov     x12, #0xffffffff
        mov     x13, #1
        movk    x13, #0xffff, lsl #32
        movk    x13, #0xffff, lsl #48

    .Lfinalizer_lane_batch:
        whilelt p0.d, x3, x4
        add     x5, x0, x3, lsl #2
        mov     x6, x1
        add     x7, x1, #128
        add     x8, x1, #256
        add     x9, x1, #384
        mov     z16.d, #0
        mov     z17.d, #0
        mov     z18.d, #0
        mov     z19.d, #0
        mov     z20.d, #0
        mov     z21.d, #0
        mov     z22.d, #0
        mov     z23.d, #0
        mov     z5.d, #1
        mov     x10, #16

    .Lfinalizer_column:
        ld1w    {{ z0.d }}, p0/z, [x5]
        add     x5, x5, #64

        ldr     x11, [x6], #8
        dup     z1.d, x11
        mov     z2.d, z0.d
        mul     z2.d, p0/m, z2.d, z1.d
        mov     z3.d, z0.d
        umulh   z3.d, p0/m, z3.d, z1.d
        add     z4.d, z16.d, z2.d
        cmplo   p1.d, p0/z, z4.d, z16.d
        mov     z16.d, z4.d
        add     z17.d, z17.d, z3.d
        add     z17.d, p1/m, z17.d, z5.d

        ldr     x11, [x7], #8
        dup     z1.d, x11
        mov     z2.d, z0.d
        mul     z2.d, p0/m, z2.d, z1.d
        mov     z3.d, z0.d
        umulh   z3.d, p0/m, z3.d, z1.d
        add     z4.d, z18.d, z2.d
        cmplo   p1.d, p0/z, z4.d, z18.d
        mov     z18.d, z4.d
        add     z19.d, z19.d, z3.d
        add     z19.d, p1/m, z19.d, z5.d

        ldr     x11, [x8], #8
        dup     z1.d, x11
        mov     z2.d, z0.d
        mul     z2.d, p0/m, z2.d, z1.d
        mov     z3.d, z0.d
        umulh   z3.d, p0/m, z3.d, z1.d
        add     z4.d, z20.d, z2.d
        cmplo   p1.d, p0/z, z4.d, z20.d
        mov     z20.d, z4.d
        add     z21.d, z21.d, z3.d
        add     z21.d, p1/m, z21.d, z5.d

        ldr     x11, [x9], #8
        dup     z1.d, x11
        mov     z2.d, z0.d
        mul     z2.d, p0/m, z2.d, z1.d
        mov     z3.d, z0.d
        umulh   z3.d, p0/m, z3.d, z1.d
        add     z4.d, z22.d, z2.d
        cmplo   p1.d, p0/z, z4.d, z22.d
        mov     z22.d, z4.d
        add     z23.d, z23.d, z3.d
        add     z23.d, p1/m, z23.d, z5.d

        subs    x10, x10, #1
        b.ne    .Lfinalizer_column

        dup     z6.d, x12
        dup     z7.d, x13

        lsr     z0.d, z17.d, #32
        and     z1.d, z17.d, z6.d
        sub     z2.d, z16.d, z0.d
        cmplo   p1.d, p0/z, z16.d, z0.d
        sub     z2.d, p1/m, z2.d, z6.d
        lsl     z3.d, z1.d, #32
        sub     z3.d, z3.d, z1.d
        mov     z4.d, z2.d
        add     z2.d, z2.d, z3.d
        cmplo   p1.d, p0/z, z2.d, z4.d
        add     z2.d, p1/m, z2.d, z6.d
        cmphs   p1.d, p0/z, z2.d, z7.d
        sub     z2.d, p1/m, z2.d, z7.d
        add     x14, x2, x3, lsl #2
        st1w    {{ z2.d }}, p0, [x14]
        lsr     z2.d, z2.d, #32
        add     x14, x14, #64
        st1w    {{ z2.d }}, p0, [x14]

        lsr     z0.d, z19.d, #32
        and     z1.d, z19.d, z6.d
        sub     z2.d, z18.d, z0.d
        cmplo   p1.d, p0/z, z18.d, z0.d
        sub     z2.d, p1/m, z2.d, z6.d
        lsl     z3.d, z1.d, #32
        sub     z3.d, z3.d, z1.d
        mov     z4.d, z2.d
        add     z2.d, z2.d, z3.d
        cmplo   p1.d, p0/z, z2.d, z4.d
        add     z2.d, p1/m, z2.d, z6.d
        cmphs   p1.d, p0/z, z2.d, z7.d
        sub     z2.d, p1/m, z2.d, z7.d
        add     x14, x2, x3, lsl #2
        add     x14, x14, #128
        st1w    {{ z2.d }}, p0, [x14]
        lsr     z2.d, z2.d, #32
        add     x14, x14, #64
        st1w    {{ z2.d }}, p0, [x14]

        lsr     z0.d, z21.d, #32
        and     z1.d, z21.d, z6.d
        sub     z2.d, z20.d, z0.d
        cmplo   p1.d, p0/z, z20.d, z0.d
        sub     z2.d, p1/m, z2.d, z6.d
        lsl     z3.d, z1.d, #32
        sub     z3.d, z3.d, z1.d
        mov     z4.d, z2.d
        add     z2.d, z2.d, z3.d
        cmplo   p1.d, p0/z, z2.d, z4.d
        add     z2.d, p1/m, z2.d, z6.d
        cmphs   p1.d, p0/z, z2.d, z7.d
        sub     z2.d, p1/m, z2.d, z7.d
        add     x14, x2, x3, lsl #2
        add     x14, x14, #256
        st1w    {{ z2.d }}, p0, [x14]
        lsr     z2.d, z2.d, #32
        add     x14, x14, #64
        st1w    {{ z2.d }}, p0, [x14]

        lsr     z0.d, z23.d, #32
        and     z1.d, z23.d, z6.d
        sub     z2.d, z22.d, z0.d
        cmplo   p1.d, p0/z, z22.d, z0.d
        sub     z2.d, p1/m, z2.d, z6.d
        lsl     z3.d, z1.d, #32
        sub     z3.d, z3.d, z1.d
        mov     z4.d, z2.d
        add     z2.d, z2.d, z3.d
        cmplo   p1.d, p0/z, z2.d, z4.d
        add     z2.d, p1/m, z2.d, z6.d
        cmphs   p1.d, p0/z, z2.d, z7.d
        sub     z2.d, p1/m, z2.d, z7.d
        add     x14, x2, x3, lsl #2
        add     x14, x14, #384
        st1w    {{ z2.d }}, p0, [x14]
        lsr     z2.d, z2.d, #32
        add     x14, x14, #64
        st1w    {{ z2.d }}, p0, [x14]

        incd    x3
        cmp     x3, #16
        b.lo    .Lfinalizer_lane_batch
        ret
        .cfi_endproc
        .size miden_eidos_matrix_finalize_sve, .-miden_eidos_matrix_finalize_sve
        "#,
    );

    unsafe extern "C" {
        fn miden_eidos_matrix_finalize_sve(input: *const u32, matrix: *const u64, output: *mut u32);
    }

    #[inline(never)]
    pub(super) unsafe fn finalize(input: &[[u32; 16]; 16]) -> [[u32; 16]; 8] {
        let mut output = [[0u32; 16]; 8];
        unsafe {
            miden_eidos_matrix_finalize_sve(
                input.as_ptr().cast(),
                super::FINALIZER_MATRIX.as_ptr().cast(),
                output.as_mut_ptr().cast(),
            );
        }
        output
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
mod x86_64_avx512 {
    use core::arch::x86_64::*;

    use super::{FINALIZER_MATRIX, GOLDILOCKS_EPSILON, GOLDILOCKS_MODULUS};

    const LANES: usize = 16;
    const SIMD_LANES: usize = 8;

    /// Adds one `u64 * u32` product to an eight-lane exact 128-bit accumulator.
    #[inline(always)]
    unsafe fn accumulate_product(
        accumulator_lo: __m512i,
        accumulator_hi: __m512i,
        words: __m512i,
        coefficient: u64,
    ) -> (__m512i, __m512i) {
        unsafe {
            let coefficient_lo = _mm512_set1_epi64((coefficient as u32) as i64);
            let coefficient_hi = _mm512_set1_epi64((coefficient >> 32) as i64);
            let product_lo32 = _mm512_mul_epu32(words, coefficient_lo);
            let product_hi32 = _mm512_mul_epu32(words, coefficient_hi);

            let shifted_hi32 = _mm512_slli_epi64::<32>(product_hi32);
            let product_lo = _mm512_add_epi64(product_lo32, shifted_hi32);
            let product_carry = _mm512_cmplt_epu64_mask(product_lo, product_lo32);
            let product_hi = _mm512_srli_epi64::<32>(product_hi32);
            let product_hi =
                _mm512_mask_add_epi64(product_hi, product_carry, product_hi, _mm512_set1_epi64(1));

            let sum_lo = _mm512_add_epi64(accumulator_lo, product_lo);
            let accumulator_carry = _mm512_cmplt_epu64_mask(sum_lo, accumulator_lo);
            let sum_hi = _mm512_add_epi64(accumulator_hi, product_hi);
            let sum_hi =
                _mm512_mask_add_epi64(sum_hi, accumulator_carry, sum_hi, _mm512_set1_epi64(1));
            (sum_lo, sum_hi)
        }
    }

    #[inline(always)]
    unsafe fn reduce(accumulator_lo: __m512i, accumulator_hi: __m512i) -> __m512i {
        unsafe {
            let epsilon = _mm512_set1_epi64(GOLDILOCKS_EPSILON as i64);
            let modulus = _mm512_set1_epi64(GOLDILOCKS_MODULUS as i64);

            let hi_hi = _mm512_srli_epi64::<32>(accumulator_hi);
            let hi_lo = _mm512_and_si512(accumulator_hi, epsilon);

            let borrow = _mm512_cmplt_epu64_mask(accumulator_lo, hi_hi);
            let mut reduced = _mm512_sub_epi64(accumulator_lo, hi_hi);
            reduced = _mm512_mask_sub_epi64(reduced, borrow, reduced, epsilon);

            let folded_hi = _mm512_sub_epi64(_mm512_slli_epi64::<32>(hi_lo), hi_lo);
            let before_addition = reduced;
            reduced = _mm512_add_epi64(reduced, folded_hi);
            let carry = _mm512_cmplt_epu64_mask(reduced, before_addition);
            reduced = _mm512_mask_add_epi64(reduced, carry, reduced, epsilon);

            let below_modulus = _mm512_cmplt_epu64_mask(reduced, modulus);
            _mm512_mask_sub_epi64(reduced, !below_modulus, reduced, modulus)
        }
    }

    #[inline(always)]
    unsafe fn finalize_rows<const ROW0: usize, const ROW1: usize>(
        input: &[[u32; LANES]; 16],
        first_lane: usize,
    ) -> (__m512i, __m512i) {
        unsafe {
            let mut lo0 = _mm512_setzero_si512();
            let mut hi0 = _mm512_setzero_si512();
            let mut lo1 = _mm512_setzero_si512();
            let mut hi1 = _mm512_setzero_si512();

            for column in 0..16 {
                let words256 = _mm256_loadu_si256(input[column].as_ptr().add(first_lane).cast());
                let words = _mm512_cvtepu32_epi64(words256);
                (lo0, hi0) = accumulate_product(lo0, hi0, words, FINALIZER_MATRIX[ROW0][column]);
                (lo1, hi1) = accumulate_product(lo1, hi1, words, FINALIZER_MATRIX[ROW1][column]);
            }

            (reduce(lo0, hi0), reduce(lo1, hi1))
        }
    }

    #[inline(never)]
    #[target_feature(enable = "avx512f")]
    pub(super) unsafe fn finalize(input: &[[u32; LANES]; 16]) -> [[u32; LANES]; 8] {
        let mut output = [[0u32; LANES]; 8];
        for first_lane in (0..LANES).step_by(SIMD_LANES) {
            // SAFETY: this function requires AVX-512F, and every eight-lane load/store stays
            // within the sixteen-lane input and output rows.
            let (row0, row1) = unsafe { finalize_rows::<0, 1>(input, first_lane) };
            let (row2, row3) = unsafe { finalize_rows::<2, 3>(input, first_lane) };
            let mut finalized = [[0u64; SIMD_LANES]; 4];
            unsafe {
                _mm512_storeu_si512(finalized[0].as_mut_ptr().cast(), row0);
                _mm512_storeu_si512(finalized[1].as_mut_ptr().cast(), row1);
                _mm512_storeu_si512(finalized[2].as_mut_ptr().cast(), row2);
                _mm512_storeu_si512(finalized[3].as_mut_ptr().cast(), row3);
            }

            for row in 0..4 {
                for lane in 0..SIMD_LANES {
                    let value = finalized[row][lane];
                    output[2 * row][first_lane + lane] = value as u32;
                    output[2 * row + 1][first_lane + lane] = (value >> 32) as u32;
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
    use core::arch::x86_64::*;

    use super::{FINALIZER_MATRIX, GOLDILOCKS_EPSILON, GOLDILOCKS_MODULUS};

    const LANES: usize = 16;
    const SIMD_LANES: usize = 4;

    #[inline(always)]
    unsafe fn shift_for_unsigned_comparison(value: __m256i) -> __m256i {
        unsafe { _mm256_xor_si256(value, _mm256_set1_epi64x(i64::MIN)) }
    }

    /// Returns all ones in lanes where `lhs < rhs` as unsigned integers, and zero otherwise.
    #[inline(always)]
    unsafe fn less_than_unsigned(lhs: __m256i, rhs: __m256i) -> __m256i {
        unsafe {
            _mm256_cmpgt_epi64(
                shift_for_unsigned_comparison(rhs),
                shift_for_unsigned_comparison(lhs),
            )
        }
    }

    /// Adds one `u64 * u32` product to a four-lane exact 128-bit accumulator.
    #[inline(always)]
    unsafe fn accumulate_product(
        accumulator_lo: __m256i,
        accumulator_hi: __m256i,
        words: __m256i,
        coefficient: u64,
    ) -> (__m256i, __m256i) {
        unsafe {
            let coefficient_lo = _mm256_set1_epi64x((coefficient as u32) as i64);
            let coefficient_hi = _mm256_set1_epi64x((coefficient >> 32) as i64);
            let product_lo32 = _mm256_mul_epu32(words, coefficient_lo);
            let product_hi32 = _mm256_mul_epu32(words, coefficient_hi);

            let shifted_hi32 = _mm256_slli_epi64::<32>(product_hi32);
            let product_lo = _mm256_add_epi64(product_lo32, shifted_hi32);
            let product_carry = less_than_unsigned(product_lo, product_lo32);
            let product_hi = _mm256_sub_epi64(_mm256_srli_epi64::<32>(product_hi32), product_carry);

            let sum_lo = _mm256_add_epi64(accumulator_lo, product_lo);
            let accumulator_carry = less_than_unsigned(sum_lo, accumulator_lo);
            let sum_hi =
                _mm256_sub_epi64(_mm256_add_epi64(accumulator_hi, product_hi), accumulator_carry);
            (sum_lo, sum_hi)
        }
    }

    #[inline(always)]
    unsafe fn reduce(accumulator_lo: __m256i, accumulator_hi: __m256i) -> __m256i {
        unsafe {
            let epsilon = _mm256_set1_epi64x(GOLDILOCKS_EPSILON as i64);
            let modulus = _mm256_set1_epi64x(GOLDILOCKS_MODULUS as i64);

            let hi_hi = _mm256_srli_epi64::<32>(accumulator_hi);
            let hi_lo = _mm256_and_si256(accumulator_hi, epsilon);

            let borrow = less_than_unsigned(accumulator_lo, hi_hi);
            let mut reduced = _mm256_sub_epi64(accumulator_lo, hi_hi);
            reduced = _mm256_sub_epi64(reduced, _mm256_and_si256(borrow, epsilon));

            let folded_hi = _mm256_sub_epi64(_mm256_slli_epi64::<32>(hi_lo), hi_lo);
            let before_addition = reduced;
            reduced = _mm256_add_epi64(reduced, folded_hi);
            let carry = less_than_unsigned(reduced, before_addition);
            reduced = _mm256_add_epi64(reduced, _mm256_and_si256(carry, epsilon));

            let below_modulus = less_than_unsigned(reduced, modulus);
            _mm256_sub_epi64(reduced, _mm256_andnot_si256(below_modulus, modulus))
        }
    }

    #[inline(always)]
    unsafe fn finalize_rows<const ROW0: usize, const ROW1: usize>(
        input: &[[u32; LANES]; 16],
        first_lane: usize,
    ) -> (__m256i, __m256i) {
        unsafe {
            let mut lo0 = _mm256_setzero_si256();
            let mut hi0 = _mm256_setzero_si256();
            let mut lo1 = _mm256_setzero_si256();
            let mut hi1 = _mm256_setzero_si256();

            for column in 0..16 {
                let words128 = _mm_loadu_si128(input[column].as_ptr().add(first_lane).cast());
                let words = _mm256_cvtepu32_epi64(words128);
                (lo0, hi0) = accumulate_product(lo0, hi0, words, FINALIZER_MATRIX[ROW0][column]);
                (lo1, hi1) = accumulate_product(lo1, hi1, words, FINALIZER_MATRIX[ROW1][column]);
            }

            (reduce(lo0, hi0), reduce(lo1, hi1))
        }
    }

    #[inline(never)]
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn finalize(input: &[[u32; LANES]; 16]) -> [[u32; LANES]; 8] {
        let mut output = [[0u32; LANES]; 8];
        for first_lane in (0..LANES).step_by(SIMD_LANES) {
            // SAFETY: this function requires AVX2, and every four-lane load/store stays within
            // the sixteen-lane input and output rows.
            let (row0, row1) = unsafe { finalize_rows::<0, 1>(input, first_lane) };
            let (row2, row3) = unsafe { finalize_rows::<2, 3>(input, first_lane) };
            let mut finalized = [[0u64; SIMD_LANES]; 4];
            unsafe {
                _mm256_storeu_si256(finalized[0].as_mut_ptr().cast(), row0);
                _mm256_storeu_si256(finalized[1].as_mut_ptr().cast(), row1);
                _mm256_storeu_si256(finalized[2].as_mut_ptr().cast(), row2);
                _mm256_storeu_si256(finalized[3].as_mut_ptr().cast(), row3);
            }

            for row in 0..4 {
                for lane in 0..SIMD_LANES {
                    let value = finalized[row][lane];
                    output[2 * row][first_lane + lane] = value as u32;
                    output[2 * row + 1][first_lane + lane] = (value >> 32) as u32;
                }
            }
        }
        output
    }
}

#[cfg(all(
    target_arch = "aarch64",
    any(
        test,
        not(all(target_os = "linux", not(feature = "std"), target_feature = "sve")),
    ),
))]
mod packed4 {
    //! aarch64 finalizer built from scalar `u128` arithmetic.
    //!
    //! NEON has no 64-bit widening multiply, so this path does not use vector registers. Each
    //! `finalize_rows_pair` call covers four lanes and two matrix rows, which bounds the live
    //! `u128` accumulators at eight, and unrolls the accumulation over the sixteen input words.
    //! The output equals `finalize_packed_to_cv`, which the tests use as the reference.

    use super::{FINALIZER_MATRIX, reduce_u128};

    fn finalize_rows_pair<const ROW0: usize, const ROW1: usize>(
        input: &[[u32; 4]; 16],
    ) -> ([u32; 4], [u32; 4], [u32; 4], [u32; 4]) {
        let mut acc00 = 0u128;
        let mut acc01 = 0u128;
        let mut acc02 = 0u128;
        let mut acc03 = 0u128;
        let mut acc10 = 0u128;
        let mut acc11 = 0u128;
        let mut acc12 = 0u128;
        let mut acc13 = 0u128;

        macro_rules! absorb {
            ($input:literal) => {{
                let coefficient0 = FINALIZER_MATRIX[ROW0][$input] as u128;
                let coefficient1 = FINALIZER_MATRIX[ROW1][$input] as u128;
                let word = input[$input];
                let x0 = word[0] as u128;
                let x1 = word[1] as u128;
                let x2 = word[2] as u128;
                let x3 = word[3] as u128;

                acc00 += coefficient0 * x0;
                acc01 += coefficient0 * x1;
                acc02 += coefficient0 * x2;
                acc03 += coefficient0 * x3;
                acc10 += coefficient1 * x0;
                acc11 += coefficient1 * x1;
                acc12 += coefficient1 * x2;
                acc13 += coefficient1 * x3;
            }};
        }

        absorb!(0);
        absorb!(1);
        absorb!(2);
        absorb!(3);
        absorb!(4);
        absorb!(5);
        absorb!(6);
        absorb!(7);
        absorb!(8);
        absorb!(9);
        absorb!(10);
        absorb!(11);
        absorb!(12);
        absorb!(13);
        absorb!(14);
        absorb!(15);

        let value00 = reduce_u128(acc00);
        let value01 = reduce_u128(acc01);
        let value02 = reduce_u128(acc02);
        let value03 = reduce_u128(acc03);
        let value10 = reduce_u128(acc10);
        let value11 = reduce_u128(acc11);
        let value12 = reduce_u128(acc12);
        let value13 = reduce_u128(acc13);

        (
            [value00 as u32, value01 as u32, value02 as u32, value03 as u32],
            [
                (value00 >> 32) as u32,
                (value01 >> 32) as u32,
                (value02 >> 32) as u32,
                (value03 >> 32) as u32,
            ],
            [value10 as u32, value11 as u32, value12 as u32, value13 as u32],
            [
                (value10 >> 32) as u32,
                (value11 >> 32) as u32,
                (value12 >> 32) as u32,
                (value13 >> 32) as u32,
            ],
        )
    }

    #[inline(never)]
    fn finalize4(input: &[[u32; 4]; 16]) -> [[u32; 4]; 8] {
        let (out0, out1, out2, out3) = finalize_rows_pair::<0, 1>(input);
        let (out4, out5, out6, out7) = finalize_rows_pair::<2, 3>(input);
        [out0, out1, out2, out3, out4, out5, out6, out7]
    }

    #[inline(never)]
    pub(super) fn finalize(input: &[[u32; 16]; 16]) -> [[u32; 16]; 8] {
        let mut output = [[0u32; 16]; 8];
        for batch in 0..4 {
            let start = 4 * batch;
            let sub_batch =
                core::array::from_fn(|word| core::array::from_fn(|lane| input[word][start + lane]));
            let finalized = finalize4(&sub_batch);
            for word in 0..8 {
                output[word][start..start + 4].copy_from_slice(&finalized[word]);
            }
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use shake::{
        Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };

    use super::*;
    use crate::{Felt, field::Field};

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
            MAX_MATRIX_ACCUMULATOR,
            u128::MAX,
        ] {
            assert_eq!(reduce_u128(value), (value % MODULUS) as u64);
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
            let expected: [u64; 4] = core::array::from_fn(|row| {
                input
                    .iter()
                    .enumerate()
                    .fold(Felt::ZERO, |sum, (column, &word)| {
                        sum + Felt::new_unchecked(FINALIZER_MATRIX[row][column])
                            * Felt::from_u32(word)
                    })
                    .as_canonical_u64()
            });
            let actual = finalize_to_cv(&input);
            let actual: [u64; 4] = core::array::from_fn(|row| {
                actual[2 * row] as u64 + ((actual[2 * row + 1] as u64) << 32)
            });
            assert_eq!(actual, expected);
        }
    }

    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    #[test]
    fn wasm_simd_finalizer_matches_scalar_lanes() {
        assert_packed_finalizer_matches(packed_field::finalize);
    }

    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    #[test]
    fn x86_avx2_finalizer_matches_scalar_lanes() {
        if !std::is_x86_feature_detected!("avx2") {
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
            return;
        }

        assert_packed_finalizer_matches(|input| {
            // SAFETY: runtime feature detection above confirmed AVX-512F support.
            unsafe { x86_64_avx512::finalize(input) }
        });
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn aarch64_packed_finalizer_matches_scalar_lanes() {
        assert_packed_finalizer_matches(packed4::finalize);
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux", feature = "std"))]
    #[test]
    fn aarch64_sve_finalizer_matches_scalar_lanes() {
        if !std::arch::is_aarch64_feature_detected!("sve") {
            return;
        }

        assert_packed_finalizer_matches(|input| {
            // SAFETY: runtime feature detection above confirmed SVE support.
            unsafe { aarch64_sve::finalize(input) }
        });
    }
}
