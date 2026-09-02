use alloc::string::ToString;
use core::{fmt, ops::Deref};

use num::Zero;

use super::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, LOG_N, MODULUS, N, Nonce,
    SIG_L2_BOUND, SIG_POLY_BYTE_LEN, Serializable,
    hash_to_point::hash_to_point_eidos,
    keys::PublicKey,
    math::{FalconFelt, FastFft, Polynomial},
};
use crate::Word;

// FALCON SIGNATURE
// ================================================================================================

/// A deterministic Falcon512-Eidos signature.
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
/// where `c = HashToPoint(r || message)`. The Eidos commitment to `h` is exposed through
/// [`PublicKey::to_commitment`](super::keys::PublicKey::to_commitment).
///
/// Main differences from the Falcon reference implementation:
///
/// 1. Hash-to-point uses Eidos and a fixed nonce. The nonce is `nonce_version_byte ||
///    preversioned_nonce`, where `preversioned_nonce` is `log2(512) || "FALCON-BLAKEG-DET" || zero
///    padding` and is not serialized. The byte string is part of the deterministic-signature
///    protocol and contributes to signature outputs.
/// 2. The trapdoor sampler uses `ChaCha20Rng` seeded with `Blake3(log2(512) || sk || message)`.
///
/// The signature is serialized as:
///
/// 1. 1-byte header, set to `10111001` for Falcon512-Eidos.
/// 2. 1-byte nonce version.
/// 3. 625 bytes encoding the `s2` polynomial.
///
/// The public key polynomial `h` is serialized after the signature as:
///
/// 1. 1 byte representing `log2(512)`.
/// 2. 896 bytes encoding the public key.
///
/// The total serialized length is 1524 bytes.
///
/// [1]: <https://github.com/algorand/falcon/blob/main/falcon-det.pdf>
/// [2]: <https://datatracker.ietf.org/doc/html/rfc6979#section-3.5>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    header: SignatureHeader,
    nonce: Nonce,
    s2: SignaturePoly,
    h: PublicKey,
}

impl Signature {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates a new signature from the given nonce, public key polynomial, and signature
    /// polynomial.
    pub fn new(nonce: Nonce, h: PublicKey, s2: SignaturePoly) -> Signature {
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
    pub fn public_key(&self) -> &PublicKey {
        &self.h
    }

    /// Returns the polynomial representation of the signature in Z_p\[x\]/(phi).
    pub fn sig_poly(&self) -> &Polynomial<FalconFelt> {
        &self.s2
    }

    /// Returns the nonce component of the signature.
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    // SIGNATURE VERIFICATION
    // --------------------------------------------------------------------------------------------

    /// Returns true if this signature is valid for the specified message and public key.
    pub fn verify(&self, message: Word, pub_key: &PublicKey) -> bool {
        if self.h != *pub_key {
            return false;
        }
        let c = hash_to_point_eidos(message, &self.nonce);
        verify_helper(&c, &self.s2, pub_key)
    }
}

impl Serializable for Signature {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(&self.header);
        target.write(&self.nonce);
        target.write(&self.s2);
        target.write(&self.h);
    }
}

impl Deserializable for Signature {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let header = source.read()?;
        let nonce = source.read()?;
        let s2 = source.read()?;
        let h = source.read()?;

        Ok(Self { header, nonce, s2, h })
    }
}

impl fmt::Display for Signature {
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignaturePoly(pub Polynomial<FalconFelt>);

impl Deref for SignaturePoly {
    type Target = Polynomial<FalconFelt>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Polynomial<FalconFelt>> for SignaturePoly {
    fn from(pk_poly: Polynomial<FalconFelt>) -> Self {
        Self(pk_poly)
    }
}

impl TryFrom<&[i16; N]> for SignaturePoly {
    type Error = ();

    fn try_from(coefficients: &[i16; N]) -> Result<Self, Self::Error> {
        if are_coefficients_valid(coefficients) {
            Ok(Self(coefficients.to_vec().into()))
        } else {
            Err(())
        }
    }
}

impl Serializable for &SignaturePoly {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let sig_coeff = self.0.to_balanced_values();
        let mut sk_bytes = vec![0_u8; SIG_POLY_BYTE_LEN];

        let mut acc = 0;
        let mut acc_len = 0;
        let mut v = 0;
        let mut t;
        let mut w;

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
        Ok(Polynomial::new(coefficients.to_vec()).into())
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
fn verify_helper(c: &Polynomial<FalconFelt>, s2: &SignaturePoly, h: &PublicKey) -> bool {
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

/// Checks whether a set of coefficients is a valid one for a signature polynomial.
fn are_coefficients_valid(x: &[i16]) -> bool {
    if x.len() != N {
        return false;
    }

    for &c in x {
        if !(-2047..=2047).contains(&c) {
            return false;
        }
    }

    true
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::{
        super::{SIG_SERIALIZED_LEN, SecretKey},
        *,
    };

    #[test]
    fn test_serialization_round_trip() {
        let seed = [0_u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);

        let sk = SecretKey::with_rng(&mut rng);
        let signature = sk.sign_with_rng(Word::default(), &mut rng);
        let serialized = signature.to_bytes();
        assert_eq!(serialized.len(), SIG_SERIALIZED_LEN);
        let deserialized = Signature::read_from_bytes(&serialized).unwrap();
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
        let mut encoded = (&poly).to_bytes();
        assert!(SignaturePoly::read_from_bytes(&encoded).is_ok());

        *encoded.last_mut().unwrap() = 1;
        let err = SignaturePoly::read_from_bytes(&encoded).unwrap_err();

        assert!(matches!(err, DeserializationError::InvalidValue(_)));
    }
}
