use alloc::string::ToString;
use core::{fmt, ops::Deref};

use num::Zero;

use super::{
    FalconVariant, LOG_N, MODULUS, N, Nonce, SIG_L2_BOUND, SIG_POLY_BYTE_LEN,
    keys::PublicKey,
    math::{FalconFelt, FastFft, Polynomial},
};
use crate::{
    Word,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// FALCON SIGNATURE
// ================================================================================================

/// A deterministic Falcon512 signature.
///
/// The signature contains a nonce `r`, a signature polynomial `s2`, and the public key polynomial
/// `h`. Verification reconstructs `s1` in `(Z_p[x]/(phi))` where:
/// - p := 12289
/// - phi := x^512 + 1
///
/// The signature verifies against the public key polynomial `h` if and only if:
/// 1. s1 = c - s2 * h
/// 2. |s1|^2 + |s2|^2 <= SIG_L2_BOUND
///
/// where `c = HashToPoint(r || message)`. The variant-specific commitment to `h` is exposed through
/// [`PublicKey::to_commitment`](super::keys::PublicKey::to_commitment).
///
/// This construction uses:
///
/// 1. Hash-to-point uses the variant's hash function and fixed nonce. The nonce is
///    `nonce_version_byte || preversioned_nonce`; only the version byte is serialized.
/// 2. The trapdoor sampler uses `ChaCha20Rng` seeded with `Blake3(log2(512) || sk || message)`.
///
/// The signature is serialized as:
///
/// 1. 1-byte header, set to `10111001` for the Miden Falcon512 variants.
/// 2. 1-byte nonce version.
/// 3. 625 bytes encoding the `s2` polynomial.
///
/// The public key polynomial `h` is serialized after the signature as:
///
/// 1. 1 byte representing `log2(512)`.
/// 2. 896 bytes encoding the public key.
///
/// The total serialized length is 1524 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature<V: FalconVariant> {
    header: SignatureHeader,
    nonce: Nonce<V>,
    s2: SignaturePoly,
    h: PublicKey<V>,
}

impl<V: FalconVariant> Signature<V> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates a new signature from the given nonce, public key polynomial, and signature
    /// polynomial.
    pub fn new(nonce: Nonce<V>, h: PublicKey<V>, s2: SignaturePoly) -> Self {
        Self {
            header: SignatureHeader::default(),
            nonce,
            s2,
            h,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the public key polynomial h.
    pub fn public_key(&self) -> &PublicKey<V> {
        &self.h
    }

    /// Returns the polynomial representation of the signature in Z_p\[x\]/(phi).
    pub fn sig_poly(&self) -> &Polynomial<FalconFelt> {
        &self.s2
    }

    /// Returns the nonce component of the signature.
    pub fn nonce(&self) -> &Nonce<V> {
        &self.nonce
    }

    // SIGNATURE VERIFICATION
    // --------------------------------------------------------------------------------------------

    /// Returns true if this signature is valid for the specified message and public key.
    pub fn verify(&self, message: Word, pub_key: &PublicKey<V>) -> bool {
        if self.h != *pub_key {
            return false;
        }
        let c = V::hash_message_to_point(message, &self.nonce);
        verify_helper(&c, &self.s2, pub_key)
    }
}

impl<V: FalconVariant> Serializable for Signature<V> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(&self.header);
        target.write(&self.nonce);
        target.write(&self.s2);
        target.write(&self.h);
    }
}

impl<V: FalconVariant> Deserializable for Signature<V> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let header = source.read()?;
        let nonce = source.read()?;
        let s2 = source.read()?;
        let h = source.read()?;

        Ok(Self { header, nonce, s2, h })
    }
}

impl<V: FalconVariant> fmt::Display for Signature<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::utils::write_hex(f, &self.to_bytes())
    }
}

// SIGNATURE HEADER
// ================================================================================================

/// The header byte used to encode the signature metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureHeader(u8);

impl Default for SignatureHeader {
    /// Section 3.11.3 of the specification [1] defines the signature header as
    /// `0cc1nnnn` where:
    ///
    /// 1. `cc` selects the encoding method. `01` denotes compressed encoding and `10` denotes
    ///    uncompressed encoding.
    /// 2. `nnnn` encodes `LOG_N`.
    ///
    /// This Falcon512 variant uses compressed encoding with N = 512. Its first bit differs from
    /// the SHAKE256 reference variant, giving the header `10111001`.
    ///
    /// [1]: <https://falcon-sign.info/falcon.pdf>
    fn default() -> Self {
        Self(0b1011_1001)
    }
}

impl Serializable for &SignatureHeader {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.0)
    }
}

impl Deserializable for SignatureHeader {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let header = source.read_u8()?;
        let (encoding, log_n) = (header >> 4, header & 0b00001111);
        if encoding != 0b1011 {
            return Err(DeserializationError::InvalidValue(
                "Failed to decode signature: not supported encoding algorithm".to_string(),
            ));
        }

        if log_n != LOG_N {
            return Err(DeserializationError::InvalidValue(format!(
                "Failed to decode signature: only supported irreducible polynomial degree is 512, 2^{log_n} was provided"
            )));
        }

        Ok(Self(header))
    }
}

// SIGNATURE POLYNOMIAL
// ================================================================================================

/// A polynomial used as the `s2` component of the signature.
///
/// A valid `SignaturePoly` has 512 coefficients in `-2047..=2047` whose Falcon compressed
/// encoding fits the fixed 625-byte representation. All constructors enforce that invariant and
/// the coefficient vector is private, so a caller cannot bypass it. Use [`Deref`] for read access.
#[derive(Debug, Clone, PartialEq, Eq)]
// The shared macro contributes a fixed 100-case arbitrary-value roundtrip when the `arbitrary`
// feature is enabled under test. It does not cover raw coefficient construction or the encoding
// boundary; those properties live in this module's tests.
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serialization_macros::serialization_test
)]
pub struct SignaturePoly(Polynomial<FalconFelt>);

impl Deref for SignaturePoly {
    type Target = Polynomial<FalconFelt>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&[i16; N]> for SignaturePoly {
    type Error = ();

    /// Builds a signature polynomial from balanced coefficients.
    ///
    /// Returns an error when a coefficient is outside `-2047..=2047` or when the compressed
    /// encoding would exceed the fixed 625-byte capacity.
    fn try_from(coefficients: &[i16; N]) -> Result<Self, Self::Error> {
        if are_coefficients_valid(coefficients, |&coefficient| coefficient) {
            Ok(Self(coefficients.to_vec().into()))
        } else {
            Err(())
        }
    }
}

impl TryFrom<Polynomial<FalconFelt>> for SignaturePoly {
    type Error = ();

    /// Builds a signature polynomial from field elements after converting them to their balanced
    /// representatives and validating the compressed encoding size.
    fn try_from(polynomial: Polynomial<FalconFelt>) -> Result<Self, Self::Error> {
        if are_coefficients_valid(&polynomial.coefficients, |coefficient| {
            coefficient.balanced_value()
        }) {
            Ok(Self(polynomial))
        } else {
            Err(())
        }
    }
}

/// Generates coefficients that always fit the fixed encoding by spending at most the 392 bits
/// available above the 512 * 9-bit baseline. The strategy is shared by the `Arbitrary`
/// implementation and the accepted-value property test.
#[cfg(any(test, feature = "arbitrary"))]
fn accepted_coefficient_strategy() -> proptest::strategy::BoxedStrategy<[i16; N]> {
    use proptest::prelude::*;

    (
        proptest::collection::vec(0u8..=15, N),
        proptest::collection::vec(0i16..=127, N),
        proptest::collection::vec(any::<bool>(), N),
    )
        .prop_map(|(extras, lows, negative)| {
            let mut remaining = SIG_POLY_BYTE_LEN * 8 - N * 9;
            let mut coefficients = [0i16; N];
            for index in 0..N {
                let extra = (extras[index] as usize).min(remaining);
                remaining -= extra;
                let magnitude = ((extra as i16) << 7) + lows[index];
                coefficients[index] = if negative[index] { -magnitude } else { magnitude };
            }
            coefficients
        })
        .boxed()
}

#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for SignaturePoly {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        accepted_coefficient_strategy()
            .prop_map(|coefficients| {
                SignaturePoly::try_from(&coefficients)
                    .expect("budget-aware Arbitrary strategy must produce valid coefficients")
            })
            .boxed()
    }
}

impl Serializable for SignaturePoly {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let sig_coeff = self.0.to_balanced_values();
        let mut sk_bytes = vec![0_u8; SIG_POLY_BYTE_LEN];

        let mut acc = 0;
        let mut acc_len = 0;
        let mut v = 0;
        let mut t;
        let mut w;

        // Constructor validation guarantees that the encoded length fits SIG_POLY_BYTE_LEN bytes,
        // so the fixed-size buffer is never overrun.

        // For each coefficient of x:
        // - the sign is encoded on 1 bit
        // - the 7 lower bits are encoded naively (binary)
        // - the high bits are encoded in unary encoding
        //
        // Algorithm 17 p. 47 of the specification [1].
        //
        // [1]: https://falcon-sign.info/falcon.pdf
        for &c in sig_coeff.iter() {
            acc <<= 1;
            t = c;

            if t < 0 {
                t = -t;
                acc |= 1;
            }
            w = t as u16;

            acc <<= 7;
            let mask = 127_u32;
            acc |= (w as u32) & mask;
            w >>= 7;

            acc_len += 8;

            acc <<= w + 1;
            acc |= 1;
            acc_len += w + 1;

            while acc_len >= 8 {
                acc_len -= 8;

                sk_bytes[v] = (acc >> acc_len) as u8;
                v += 1;
            }
        }

        if acc_len > 0 {
            sk_bytes[v] = (acc << (8 - acc_len)) as u8;
        }
        target.write_bytes(&sk_bytes);
    }
}

impl Deserializable for SignaturePoly {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let input = source.read_array::<SIG_POLY_BYTE_LEN>()?;

        let mut input_idx = 0;
        let mut acc = 0u32;
        let mut acc_len = 0;
        let mut coefficients = [FalconFelt::zero(); N];

        // Algorithm 18 p. 48 of the specification [1].
        //
        // [1]: https://falcon-sign.info/falcon.pdf
        for c in coefficients.iter_mut() {
            acc = (acc << 8) | (next_sig_poly_byte(&input, &mut input_idx)? as u32);
            let b = acc >> acc_len;
            let s = b & 128;
            let mut m = b & 127;

            loop {
                if acc_len == 0 {
                    acc = (acc << 8) | (next_sig_poly_byte(&input, &mut input_idx)? as u32);
                    acc_len = 8;
                }
                acc_len -= 1;
                if ((acc >> acc_len) & 1) != 0 {
                    break;
                }
                m += 128;
                if m >= 2048 {
                    return Err(DeserializationError::InvalidValue(format!(
                        "Failed to decode signature: high bits {m} exceed 2048",
                    )));
                }
            }
            if s != 0 && m == 0 {
                return Err(DeserializationError::InvalidValue(
                    "Failed to decode signature: -0 is forbidden".to_string(),
                ));
            }

            let felt = if s != 0 { (MODULUS as u32 - m) as u16 } else { m as u16 };
            *c = FalconFelt::new(felt as i16);
        }

        if (acc & ((1 << acc_len) - 1)) != 0 {
            return Err(DeserializationError::InvalidValue(
                "Failed to decode signature: Non-zero unused bits in the last byte".to_string(),
            ));
        }
        if input[input_idx..].iter().any(|&byte| byte != 0) {
            return Err(DeserializationError::InvalidValue(
                "Failed to decode signature: Non-zero trailing bytes".to_string(),
            ));
        }
        Ok(Self(Polynomial::new(coefficients.to_vec())))
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn next_sig_poly_byte(
    input: &[u8; SIG_POLY_BYTE_LEN],
    input_idx: &mut usize,
) -> Result<u8, DeserializationError> {
    let byte = input.get(*input_idx).copied().ok_or_else(|| {
        DeserializationError::InvalidValue(
            "Failed to decode signature: compressed polynomial ended early".to_string(),
        )
    })?;
    *input_idx += 1;
    Ok(byte)
}

/// Returns `true` when the hash-to-point polynomial `c`, signature polynomial `s2`, and public key
/// polynomial `h` form a valid signature.
fn verify_helper<V: FalconVariant>(
    c: &Polynomial<FalconFelt>,
    s2: &SignaturePoly,
    h: &PublicKey<V>,
) -> bool {
    let h_fft = h.fft();
    let s2_fft = s2.fft();
    let c_fft = c.fft();

    // Compute the signature polynomial s1 using s1 = c - s2 * h.
    let s1_fft = c_fft - s2_fft.hadamard_mul(&h_fft);
    let s1 = s1_fft.ifft();

    // Compute the squared norm of (s1, s2).
    let length_squared_s1 = s1.norm_squared();
    let length_squared_s2 = s2.norm_squared();
    let length_squared = length_squared_s1 + length_squared_s2;

    length_squared < SIG_L2_BOUND
}

/// Checks whether a set of coefficients is valid for a signature polynomial.
///
/// The check mirrors the encoder exactly. Each coefficient occupies `9 + (abs(c) >> 7)` bits, and
/// the fixed compressed representation holds `SIG_POLY_BYTE_LEN * 8` bits. A coefficient range
/// check alone is insufficient: for example, 512 coefficients of magnitude 128 have a squared norm
/// below `SIG_L2_BOUND` but need 640 encoded bytes.
fn are_coefficients_valid<T>(coefficients: &[T], balanced_value: impl Fn(&T) -> i16) -> bool {
    if coefficients.len() != N {
        return false;
    }

    let capacity_bits = SIG_POLY_BYTE_LEN * 8;
    let mut encoded_bits = 0;
    for coefficient in coefficients {
        let c = balanced_value(coefficient);
        if !(-2047..=2047).contains(&c) {
            return false;
        }

        encoded_bits += 9 + (c.unsigned_abs() as usize >> 7);
        if encoded_bits > capacity_bits {
            return false;
        }
    }

    true
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use proptest::{collection::vec, prelude::*};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::{
        super::{SIG_SERIALIZED_LEN, SecretKey, TestVariant},
        *,
    };

    type TestSecretKey = SecretKey<TestVariant>;
    type TestSignature = Signature<TestVariant>;

    #[test]
    fn test_serialization_round_trip() {
        let seed = [0_u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);

        let sk = TestSecretKey::with_rng(&mut rng);
        let signature = sk.sign_with_rng(Word::default(), &mut rng);
        let serialized = signature.to_bytes();
        assert_eq!(serialized.len(), SIG_SERIALIZED_LEN);
        let deserialized = TestSignature::read_from_bytes(&serialized).unwrap();
        assert_eq!(signature.sig_poly(), deserialized.sig_poly());
    }

    #[test]
    fn signature_poly_rejects_unterminated_compressed_payload() {
        let encoded = [1u8; SIG_POLY_BYTE_LEN];
        let err = SignaturePoly::read_from_bytes(&encoded).unwrap_err();

        assert!(matches!(err, DeserializationError::InvalidValue(_)));
    }

    #[test]
    fn signature_poly_rejects_nonzero_trailing_bytes() {
        let coefficients = [0i16; N];
        let poly = SignaturePoly::try_from(&coefficients).unwrap();
        let mut encoded = poly.to_bytes();
        assert!(SignaturePoly::read_from_bytes(&encoded).is_ok());

        *encoded.last_mut().unwrap() = 1;
        let err = SignaturePoly::read_from_bytes(&encoded).unwrap_err();

        assert!(matches!(err, DeserializationError::InvalidValue(_)));
    }

    // CONSTRUCTOR AND ENCODING PROPERTIES
    // --------------------------------------------------------------------------------------------

    /// The fixed compressed signature-polynomial capacity in bits.
    const SIG_POLY_BITS: usize = SIG_POLY_BYTE_LEN * 8;

    /// Independently computes the compressed bit length used by the encoder:
    /// one sign bit, seven low bits, and one unary terminator plus `abs(c) >> 7` high bits.
    fn encoded_bit_len(coefficients: &[i16; N]) -> usize {
        coefficients.iter().map(|c| 9 + (c.unsigned_abs() as usize >> 7)).sum()
    }

    /// Builds vectors by whole-vector family so the encoded budget is the deciding property.
    ///
    /// `accepted_coefficient_strategy` always fits. The boundary family sets between 0 and 512
    /// coefficients to magnitude 128, so counts at or below 392 are accepted and counts above are
    /// rejected. The high family always exceeds the budget, and the sparse family accepts one
    /// coefficient of any allowed magnitude. This exercises both constructor outcomes and varied
    /// under-budget, boundary, and extreme values.
    fn boundary_coefficient_strategy() -> impl Strategy<Value = [i16; N]> {
        (0usize..=N, vec(any::<bool>(), N)).prop_map(|(count, negative)| {
            let mut coefficients = [0i16; N];
            for (index, coefficient) in coefficients.iter_mut().enumerate() {
                if index < count {
                    *coefficient = if negative[index] { -128 } else { 128 };
                }
            }
            coefficients
        })
    }

    fn high_coefficient_strategy() -> impl Strategy<Value = [i16; N]> {
        (vec(128i16..=2047, N), vec(any::<bool>(), N)).prop_map(|(magnitudes, negative)| {
            let mut coefficients = [0i16; N];
            for (index, (&magnitude, &negative)) in
                magnitudes.iter().zip(negative.iter()).enumerate()
            {
                coefficients[index] = if negative { -magnitude } else { magnitude };
            }
            coefficients
        })
    }

    fn sparse_extreme_strategy() -> impl Strategy<Value = [i16; N]> {
        (0usize..N, 0i16..=2047, any::<bool>()).prop_map(|(index, magnitude, negative)| {
            let mut coefficients = [0i16; N];
            coefficients[index] = if negative { -magnitude } else { magnitude };
            coefficients
        })
    }

    fn coefficient_strategy() -> BoxedStrategy<[i16; N]> {
        prop_oneof![
            2 => accepted_coefficient_strategy(),
            1 => boundary_coefficient_strategy().boxed(),
            1 => high_coefficient_strategy().boxed(),
            1 => sparse_extreme_strategy().boxed(),
        ]
        .boxed()
    }

    fn magnitude_coefficients(count: usize, magnitude: i16) -> [i16; N] {
        let mut coefficients = [0i16; N];
        for coefficient in coefficients.iter_mut().take(count) {
            *coefficient = magnitude;
        }
        coefficients
    }

    #[test]
    fn coefficient_strategy_exercises_both_constructor_outcomes() {
        use proptest::{strategy::ValueTree, test_runner::TestRunner};

        let mut runner = TestRunner::deterministic();
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        for _ in 0..256 {
            let coefficients = coefficient_strategy().new_tree(&mut runner).unwrap().current();
            if SignaturePoly::try_from(&coefficients).is_ok() {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }

        assert!(accepted > 0, "strategy never produced an accepted polynomial");
        assert!(rejected > 0, "strategy never produced a rejected polynomial");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn signature_poly_constructor_matches_encoded_budget(
            coefficients in coefficient_strategy()
        ) {
            let bits = encoded_bit_len(&coefficients);
            match SignaturePoly::try_from(&coefficients) {
                Ok(poly) => {
                    prop_assert!(bits <= SIG_POLY_BITS);
                    let bytes = poly.to_bytes();
                    prop_assert_eq!(bytes.len(), SIG_POLY_BYTE_LEN);
                    let decoded = SignaturePoly::read_from_bytes(&bytes).unwrap();
                    prop_assert_eq!(decoded, poly);
                },
                Err(()) => prop_assert!(bits > SIG_POLY_BITS),
            }
        }

        #[test]
        fn signature_poly_polynomial_constructor_matches_raw_constructor(
            coefficients in coefficient_strategy()
        ) {
            let polynomial =
                Polynomial::new(coefficients.iter().map(|&c| FalconFelt::new(c)).collect());
            let from_polynomial = SignaturePoly::try_from(polynomial);
            let from_raw = SignaturePoly::try_from(&coefficients);

            prop_assert_eq!(from_polynomial.is_ok(), from_raw.is_ok());
            if let Ok(poly) = from_polynomial {
                let bytes = poly.to_bytes();
                prop_assert_eq!(bytes.len(), SIG_POLY_BYTE_LEN);
                prop_assert_eq!(SignaturePoly::read_from_bytes(&bytes).unwrap(), poly);
            }
        }
    }

    #[test]
    fn signature_poly_polynomial_constructor_rejects_invalid_shapes() {
        let wrong_length = Polynomial::new(vec![FalconFelt::new(0); N - 1]);
        assert!(SignaturePoly::try_from(wrong_length).is_err());

        let out_of_range = Polynomial::new(vec![FalconFelt::new(2048); N]);
        assert!(SignaturePoly::try_from(out_of_range).is_err());

        let over_budget = Polynomial::new(vec![FalconFelt::new(2047); N]);
        assert!(SignaturePoly::try_from(over_budget).is_err());
    }

    #[test]
    fn signature_poly_polynomial_constructor_uses_balanced_values() {
        // 12288 is the canonical representative of -1 in the Falcon field. The constructor must
        // validate the balanced value and the decoder must recover the same canonical element.
        let polynomial = Polynomial::new(vec![FalconFelt::new(12288); N]);
        let poly = SignaturePoly::try_from(polynomial).unwrap();
        let bytes = poly.to_bytes();
        assert_eq!(bytes.len(), SIG_POLY_BYTE_LEN);
        let decoded = SignaturePoly::read_from_bytes(&bytes).unwrap();
        assert_eq!(decoded, poly);
    }

    #[test]
    fn signature_poly_rejects_coefficients_that_exceed_encoded_capacity() {
        let mut single_2047 = [0i16; N];
        single_2047[0] = 2047;
        let mut mixed_signs = magnitude_coefficients(392, 128);
        for coefficient in mixed_signs.iter_mut().take(392).skip(1).step_by(2) {
            *coefficient = -128;
        }

        let cases = [
            ([2047i16; N], false),
            ([-2047i16; N], false),
            ([128i16; N], false),
            (magnitude_coefficients(392, 128), true),
            (magnitude_coefficients(393, 128), false),
            (single_2047, true),
            (mixed_signs, true),
            ([0i16; N], true),
        ];

        for (coefficients, expected_ok) in cases {
            match SignaturePoly::try_from(&coefficients) {
                Ok(poly) => {
                    let bytes = poly.to_bytes();
                    assert_eq!(bytes.len(), SIG_POLY_BYTE_LEN);
                    let decoded = SignaturePoly::read_from_bytes(&bytes).unwrap();
                    assert_eq!(decoded, poly);
                    assert!(expected_ok, "constructor accepted an over-budget polynomial");
                },
                Err(()) => assert!(!expected_ok, "constructor rejected a representable polynomial"),
            }
        }
    }

    #[test]
    fn encoded_budget_boundary_is_exact() {
        let exact = magnitude_coefficients(392, 128);
        assert_eq!(encoded_bit_len(&exact), SIG_POLY_BITS);
        assert_eq!(encoded_bit_len(&exact).div_ceil(8), SIG_POLY_BYTE_LEN);
        assert!(SignaturePoly::try_from(&exact).is_ok());

        let over = magnitude_coefficients(393, 128);
        assert_eq!(encoded_bit_len(&over), SIG_POLY_BITS + 1);
        assert!(SignaturePoly::try_from(&over).is_err());
    }

    #[test]
    fn norm_bound_does_not_guarantee_encoded_size() {
        let coefficients = [128i16; N];
        let polynomial =
            Polynomial::new(coefficients.iter().map(|&c| FalconFelt::new(c)).collect());

        assert!(polynomial.norm_squared() < SIG_L2_BOUND);
        assert_eq!(encoded_bit_len(&coefficients), 5120);
        assert_eq!(encoded_bit_len(&coefficients).div_ceil(8), 640);
    }
}
