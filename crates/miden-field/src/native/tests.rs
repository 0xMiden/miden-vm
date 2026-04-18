use alloc::{format, vec::Vec};
use core::hash::{Hash, Hasher};

use p3_challenger::UniformSamplingField;
use p3_field::{
    Field, InjectiveMonomial, PermutationMonomial, PrimeCharacteristicRing, PrimeField,
    PrimeField64, TwoAdicField,
    extension::{BinomiallyExtendable, HasTwoAdicBinomialExtension},
    integers::QuotientMap,
};
use proptest::prelude::*;
use rand::{SeedableRng, distr::Distribution, rngs::SmallRng};

use super::{Felt, Goldilocks};

/// A minimal hasher used to validate that `Felt` hashes identically to `Goldilocks`.
#[derive(Default)]
struct U64Hasher {
    state: u64,
}

impl Hasher for U64Hasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.state
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        // `Felt` and `Goldilocks` only call `write_u64` in their `Hash` impls. If this is
        // called, something about hashing has changed and this test helper should be updated.
        let _ = bytes;
        panic!("unexpected Hasher::write call");
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.state = i;
    }
}

#[inline]
unsafe fn felt_from_raw_u64(raw: u64) -> Felt {
    // SAFETY: Felt is repr(transparent) over Goldilocks, which is repr(transparent) over u64.
    unsafe { core::mem::transmute_copy(&raw) }
}

proptest! {
    /// `Felt::new` matches `Goldilocks::new` for the same input.
    #[test]
    fn felt_new_matches_goldilocks_new(x in any::<u64>()) {
        prop_assert_eq!(Felt::new_unchecked(x), Goldilocks::new(x));
    }

    /// Core arithmetic operations match `Goldilocks`.
    #[test]
    fn felt_arithmetic_matches_goldilocks(a in any::<u64>(), b in any::<u64>()) {
        let fa = Felt::new_unchecked(a);
        let fb = Felt::new_unchecked(b);
        let ga = Goldilocks::new(a);
        let gb = Goldilocks::new(b);

        prop_assert_eq!(fa + fb, ga + gb);
        prop_assert_eq!(fa - fb, ga - gb);
        prop_assert_eq!(fa * fb, ga * gb);
        prop_assert_eq!(-fa, -ga);

        let mut fa2 = fa;
        fa2 += fb;
        prop_assert_eq!(fa2, ga + gb);

        let mut fa2 = fa;
        fa2 -= fb;
        prop_assert_eq!(fa2, ga - gb);

        let mut fa2 = fa;
        fa2 *= fb;
        prop_assert_eq!(fa2, ga * gb);

        if !gb.is_zero() {
            prop_assert_eq!(fa / fb, ga / gb);
            let mut fa2 = fa;
            fa2 /= fb;
            prop_assert_eq!(fa2, ga / gb);
        }
    }

    /// `Field` and `PrimeCharacteristicRing` operations match `Goldilocks`.
    #[test]
    fn felt_field_methods_match_goldilocks(a in any::<u64>(), exp in any::<u64>(), shift in any::<u8>()) {
        let fa = Felt::new_unchecked(a);
        let ga = Goldilocks::new(a);

        prop_assert_eq!(
            Felt::from_bool((a & 1) == 1),
            Goldilocks::from_bool((a & 1) == 1),
        );
        prop_assert_eq!(fa.is_zero(), ga.is_zero());
        prop_assert_eq!(
            fa.try_inverse(),
            ga.try_inverse().map(Felt::from),
        );

        prop_assert_eq!(fa.halve(), ga.halve());
        prop_assert_eq!(fa.mul_2exp_u64(shift as u64), ga.mul_2exp_u64(shift as u64));
        prop_assert_eq!(fa.div_2exp_u64(shift as u64), ga.div_2exp_u64(shift as u64));
        prop_assert_eq!(fa.exp_u64(exp), ga.exp_u64(exp));
    }

    /// Constant-time canonicalization matches `as_canonical_u64()` for all sampled values.
    #[test]
    fn felt_canonical_u64_ct_matches(a in any::<Felt>()) {
        prop_assert_eq!(a.as_canonical_u64_ct(), a.as_canonical_u64());
    }

    /// Constant-time canonicalization matches `as_canonical_u64()` for non-canonical values.
    #[test]
    fn felt_canonical_u64_ct_matches_non_canonical(raw in (Felt::ORDER..=u64::MAX)) {
        let a = unsafe { felt_from_raw_u64(raw) };
        prop_assert_eq!(a.as_canonical_u64_ct(), a.as_canonical_u64());
    }

    /// Formatting, ordering, and hashing match `Goldilocks`.
    #[test]
    fn felt_misc_traits_match_goldilocks(a in any::<u64>(), b in any::<u64>()) {
        let fa = Felt::new_unchecked(a);
        let fb = Felt::new_unchecked(b);
        let ga = Goldilocks::new(a);
        let gb = Goldilocks::new(b);

        prop_assert_eq!(fa.cmp(&fb), ga.cmp(&gb));
        prop_assert_eq!(format!("{fa}"), format!("{ga}"));
        prop_assert_eq!(format!("{fa:?}"), format!("{ga:?}"));

        let mut h1 = U64Hasher::default();
        fa.hash(&mut h1);
        let mut h2 = U64Hasher::default();
        ga.hash(&mut h2);
        prop_assert_eq!(h1.finish(), h2.finish());
    }

    /// Integer conversion and canonical checks match `Goldilocks`.
    #[test]
    fn felt_quotient_map_matches_goldilocks_u64(x in any::<u64>()) {
        let f_checked = <Felt as QuotientMap<u64>>::from_canonical_checked(x);
        let g_checked = <Goldilocks as QuotientMap<u64>>::from_canonical_checked(x).map(Felt::from);
        prop_assert_eq!(f_checked, g_checked);

        prop_assert_eq!(<Felt as QuotientMap<u64>>::from_int(x), <Goldilocks as QuotientMap<u64>>::from_int(x));

        if x < Felt::ORDER_U64 {
            let f_unchecked = unsafe { <Felt as QuotientMap<u64>>::from_canonical_unchecked(x) };
            let g_unchecked = unsafe { <Goldilocks as QuotientMap<u64>>::from_canonical_unchecked(x) };
            prop_assert_eq!(f_unchecked, g_unchecked);
        }
    }

    /// Signed integer conversion and canonical checks match `Goldilocks`.
    #[test]
    fn felt_quotient_map_matches_goldilocks_i64(x in any::<i64>()) {
        let f_checked = <Felt as QuotientMap<i64>>::from_canonical_checked(x);
        let g_checked = <Goldilocks as QuotientMap<i64>>::from_canonical_checked(x).map(Felt::from);
        prop_assert_eq!(f_checked, g_checked);

        prop_assert_eq!(<Felt as QuotientMap<i64>>::from_int(x), <Goldilocks as QuotientMap<i64>>::from_int(x));

        let min = i64::MIN + (1i64 << 31);
        let max = i64::MAX - (1i64 << 31);
        if (min..=max).contains(&x) {
            let f_unchecked = unsafe { <Felt as QuotientMap<i64>>::from_canonical_unchecked(x) };
            let g_unchecked = unsafe { <Goldilocks as QuotientMap<i64>>::from_canonical_unchecked(x) };
            prop_assert_eq!(f_unchecked, g_unchecked);
        }
    }

    /// Iterated operations (`Sum`/`Product`) match `Goldilocks`.
    #[test]
    fn felt_iterators_match_goldilocks(xs in prop::collection::vec(any::<u64>(), 0..64)) {
        let felts: Vec<Felt> = xs.iter().copied().map(Felt::new_unchecked).collect();
        let golds: Vec<Goldilocks> = xs.iter().copied().map(Goldilocks::new).collect();

        let fs = felts.iter().copied().sum::<Felt>();
        let gs = golds.iter().copied().sum::<Goldilocks>();
        prop_assert_eq!(fs, gs);

        let fp = felts.iter().copied().product::<Felt>();
        let gp = golds.iter().copied().product::<Goldilocks>();
        prop_assert_eq!(fp, gp);

        let fs_ref = felts.iter().sum::<Felt>();
        let gs_ref = golds.iter().copied().sum::<Goldilocks>();
        prop_assert_eq!(fs_ref, gs_ref);

        let fp_ref = felts.iter().product::<Felt>();
        let gp_ref = golds.iter().copied().product::<Goldilocks>();
        prop_assert_eq!(fp_ref, gp_ref);
    }

    /// RNG sampling via `StandardUniform` matches `Goldilocks` for the same RNG seed.
    #[test]
    fn felt_distribution_matches_goldilocks(seed in any::<u64>()) {
        let mut rng1 = SmallRng::seed_from_u64(seed);
        let mut rng2 = SmallRng::seed_from_u64(seed);

        let g = <rand::distr::StandardUniform as Distribution<Goldilocks>>::sample(&rand::distr::StandardUniform, &mut rng1);
        let f = <rand::distr::StandardUniform as Distribution<Felt>>::sample(&rand::distr::StandardUniform, &mut rng2);
        prop_assert_eq!(f, g);
    }
}

/// Validates that `Felt` exposes the same field constants as `Goldilocks`.
#[test]
fn felt_constants_match_goldilocks() {
    assert_eq!(Felt::ZERO, Goldilocks::ZERO);
    assert_eq!(Felt::ONE, Goldilocks::ONE);
    assert_eq!(Felt::TWO, Goldilocks::TWO);
    assert_eq!(Felt::NEG_ONE, Goldilocks::NEG_ONE);
    assert_eq!(Felt::GENERATOR, Goldilocks::GENERATOR);

    assert_eq!(Felt::ORDER_U64, Goldilocks::ORDER_U64);
    assert_eq!(Felt::TWO_ADICITY, Goldilocks::TWO_ADICITY);

    assert_eq!(Felt::MAX_SINGLE_SAMPLE_BITS, Goldilocks::MAX_SINGLE_SAMPLE_BITS);
    assert_eq!(Felt::SAMPLING_BITS_M, Goldilocks::SAMPLING_BITS_M);

    assert_eq!(<Felt as Field>::order(), <Goldilocks as Field>::order());
    assert_eq!(
        <Felt as PrimeField>::as_canonical_biguint(&Felt::new_unchecked(u64::MAX)),
        <Goldilocks as PrimeField>::as_canonical_biguint(&Goldilocks::new(u64::MAX)),
    );
    assert_eq!(
        Felt::new_unchecked(u64::MAX).as_canonical_u64(),
        Goldilocks::new(u64::MAX).as_canonical_u64()
    );
}

/// Validates extension-field and two-adic generator delegation.
#[test]
fn felt_extension_and_generators_match_goldilocks() {
    for bits in 0..=Felt::TWO_ADICITY {
        assert_eq!(Felt::two_adic_generator(bits), Goldilocks::two_adic_generator(bits));
    }

    assert_eq!(<Felt as BinomiallyExtendable<2>>::W, <Goldilocks as BinomiallyExtendable<2>>::W);
    assert_eq!(
        <Felt as BinomiallyExtendable<2>>::DTH_ROOT,
        <Goldilocks as BinomiallyExtendable<2>>::DTH_ROOT
    );
    for (f, g) in <Felt as BinomiallyExtendable<2>>::EXT_GENERATOR
        .iter()
        .copied()
        .zip(<Goldilocks as BinomiallyExtendable<2>>::EXT_GENERATOR.iter().copied())
    {
        assert_eq!(f, g);
    }
    for bits in 0..=<Felt as HasTwoAdicBinomialExtension<2>>::EXT_TWO_ADICITY {
        let f = <Felt as HasTwoAdicBinomialExtension<2>>::ext_two_adic_generator(bits);
        let g = <Goldilocks as HasTwoAdicBinomialExtension<2>>::ext_two_adic_generator(bits);
        assert_eq!(f[0], g[0]);
        assert_eq!(f[1], g[1]);
    }

    assert_eq!(<Felt as BinomiallyExtendable<5>>::W, <Goldilocks as BinomiallyExtendable<5>>::W);
    assert_eq!(
        <Felt as BinomiallyExtendable<5>>::DTH_ROOT,
        <Goldilocks as BinomiallyExtendable<5>>::DTH_ROOT
    );
    for (f, g) in <Felt as BinomiallyExtendable<5>>::EXT_GENERATOR
        .iter()
        .copied()
        .zip(<Goldilocks as BinomiallyExtendable<5>>::EXT_GENERATOR.iter().copied())
    {
        assert_eq!(f, g);
    }
    for bits in 0..=<Felt as HasTwoAdicBinomialExtension<5>>::EXT_TWO_ADICITY {
        let f = <Felt as HasTwoAdicBinomialExtension<5>>::ext_two_adic_generator(bits);
        let g = <Goldilocks as HasTwoAdicBinomialExtension<5>>::ext_two_adic_generator(bits);
        for (f_i, g_i) in f.iter().copied().zip(g.iter().copied()) {
            assert_eq!(f_i, g_i);
        }
    }
}

/// Ensures injective/permutation monomial operations match `Goldilocks`.
#[test]
fn felt_injective_monomial_matches_goldilocks() {
    let inputs = [
        Felt::ZERO,
        Felt::ONE,
        Felt::new_unchecked(Felt::ORDER),
        Felt::new_unchecked(u64::MAX),
        Felt::new_unchecked(100),
    ];

    for f in inputs {
        let g: Goldilocks = f.into();
        assert_eq!(
            f.injective_exp_n().injective_exp_root_n(),
            g.injective_exp_n().injective_exp_root_n(),
        );
        assert_eq!(
            <Felt as PermutationMonomial<7>>::injective_exp_root_n(&f),
            <Goldilocks as PermutationMonomial<7>>::injective_exp_root_n(&g),
        );
    }
}

/// Ensures `from_prime_subfield` is a transparent wrapper.
#[test]
fn felt_from_prime_subfield_is_transparent() {
    let g = Goldilocks::new(u64::MAX);
    let f = Felt::from_prime_subfield(g);
    assert_eq!(f, g);
}

/// Ensures TryFrom<u64> fails for inputs at or exceeding the modulus.
#[test]
fn felt_try_from_u64_fails_on_large_inputs() {
    Felt::try_from(u64::MAX).unwrap_err();
    Felt::try_from(Felt::ORDER).unwrap_err();
}
