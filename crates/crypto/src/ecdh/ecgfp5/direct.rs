use num::{BigInt, Signed, Zero, bigint::Sign};
use once_cell::sync::Lazy;

use super::{
    PreparedPublicKey, PublicKey, SecretKey,
    advice::{A_OVER_THREE, Affine, AgreementAdvice},
    native::field::GFp,
};
use crate::utils::zeroize::Zeroize;

const SHORT_LIMBS: usize = 10;
const RADIX: i64 = 1 << 16;
const CARRY_OFFSET: i64 = 1 << 20;
const ORDER: [u64; 5] = [
    0xe80fd996948bffe1,
    0xe8885c39d724a09c,
    0x7fffffe6cfb80639,
    0x7ffffff100000016,
    0x7ffffffd80000007,
];

// Generator table matching GENERATOR_COMMITMENT in the MASM implementation.
static GENERATOR: Lazy<PreparedPublicKey> = Lazy::new(|| {
    let mut bytes = [0; 40];
    bytes[0] = 4;
    PreparedPublicKey::new(PublicKey::from_bytes(bytes).expect("canonical generator"))
});

impl PublicKey {
    /// Prepares private advice for `crypto::ecdh::ecgfp5::agree`.
    ///
    /// First use builds a roughly 4.1 MiB generator cache, retained for the process lifetime.
    /// See the [module-level guidance](super) on handling private advice.
    pub fn advise(&self, ephemeral_secret: &SecretKey) -> AgreementAdvice {
        // Let G be the generator, Q this public key, r the private scalar, and n the subgroup
        // order. The generator table supplies the openings for R = rG. For S = rQ, the VM
        // checks short integers a,b with b*r = a (mod n), then verifies b*S = a*Q.
        let (mut advice, ephemeral) = GENERATOR.generator_advice(ephemeral_secret);
        advice.elements.splice(..0, self.to_elements().map(|x| x.as_canonical_u64()));
        let fraction = Fraction::new(ephemeral_secret);
        fraction.append_to(&mut advice);
        let recipient_point = self.point();
        let recipient = Affine::from_point(recipient_point);
        append_decoding(&mut advice, recipient);
        let first = if fraction.negative {
            negate(recipient)
        } else {
            recipient
        };

        // T[i + 4*j] = i*sign(a)*Q - j*S, for i,j in 0..4. None represents the identity.
        let mut table = [None; 16];
        table[1] = Some(first);
        for i in 2..4 {
            table[i] = add(&mut advice, table[i - 1], table[1]);
        }
        let shared = Affine::from_point(recipient_point * *ephemeral_secret.0);
        advice.elements.extend(shared.encode().0.map(GFp::to_u64));
        append_decoding(&mut advice, shared);
        table[4] = Some(negate(shared));
        for j in 1..4 {
            if j > 1 {
                table[4 * j] = add(&mut advice, table[4 * (j - 1)], table[4]);
            }
            for i in 1..4 {
                table[4 * j + i] = add(&mut advice, table[4 * j + i - 1], table[1]);
            }
        }
        let mut sum = None;
        for window in (0..80).rev() {
            sum = add(&mut advice, sum, sum);
            sum = add(&mut advice, sum, sum);
            let digit = |limbs: &[u64; SHORT_LIMBS]| (limbs[window / 8] >> (2 * (window % 8))) & 3;
            let index = (digit(&fraction.numerator) + 4 * digit(&fraction.denominator)) as usize;
            if index != 0 {
                sum = add(&mut advice, sum, table[index]);
            }
        }
        assert!(sum.is_none(), "the short-scalar relation must cancel");
        advice.elements.extend(ephemeral.encode().0.map(GFp::to_u64));
        advice.elements.extend(shared.encode().0.map(GFp::to_u64));
        advice
    }
}

fn append_decoding(advice: &mut AgreementAdvice, point: Affine) {
    let (root, valid) = (point.x - A_OVER_THREE).sqrt();
    assert_ne!(valid, 0, "a subgroup point has square unshifted x");
    advice.elements.extend(root.0.map(GFp::to_u64));
}

fn negate(point: Affine) -> Affine {
    Affine { x: point.x, y: -point.y }
}

// Emit a slope only for finite addition or doubling, matching the VM's complete-addition branches.
fn add(
    advice: &mut AgreementAdvice,
    left: Option<Affine>,
    right: Option<Affine>,
) -> Option<Affine> {
    let (Some(left), Some(right)) = (left, right) else {
        return left.or(right);
    };
    let (sum, slope) = if (left.x - right.x).iszero() != 0 {
        if (left.y - right.y).iszero() == 0 {
            return None;
        }
        left.double()
    } else {
        left.add_finite(right)
    };
    advice.elements.extend(slope.0.map(GFp::to_u64));
    Some(sum)
}

// b*r - k*n = a. All magnitudes use ten u16 limbs; the numerator alone may be negative.
struct Fraction {
    numerator: [u64; SHORT_LIMBS],
    denominator: [u64; SHORT_LIMBS],
    quotient: [u64; SHORT_LIMBS],
    negative: bool,
    carries: [u64; 30],
}

impl Drop for Fraction {
    fn drop(&mut self) {
        self.numerator.zeroize();
        self.denominator.zeroize();
        self.quotient.zeroize();
        self.negative.zeroize();
        self.carries.zeroize();
    }
}

impl Fraction {
    fn new(secret: &SecretKey) -> Self {
        let order_bytes: [u8; 40] = core::array::from_fn(|i| ORDER[i / 8].to_le_bytes()[i % 8]);
        let n = BigInt::from_bytes_le(Sign::Plus, &order_bytes);
        let bytes = secret.to_bytes();
        let r = BigInt::from_bytes_le(Sign::Plus, &bytes[..]);
        let (mut high, mut low) = (n.clone(), r.clone());
        let (mut high_coeff, mut low_coeff) = (BigInt::zero(), BigInt::from(1));
        // At the first remainder below 2^160, Euclid gives |a| < 2^160 and 0 < b < 2^159.
        // Adjacent remainders h,l satisfy n = h*|d| + l*|c|, so |d| <= n/h < 2^159.
        while low.bits() > 160 {
            let q = &high / &low;
            (high, low) = (low.clone(), high - &q * &low);
            (high_coeff, low_coeff) = (low_coeff.clone(), high_coeff - q * &low_coeff);
        }
        let negative = low_coeff.is_negative();
        let a = if negative { -low } else { low };
        let b = low_coeff.abs();
        let k = (&b * &r - &a) / &n;
        let mut result = Self {
            numerator: limbs(&a),
            denominator: limbs(&b),
            quotient: limbs(&k),
            negative,
            carries: [0; 30],
        };
        let rd: [u64; 20] =
            core::array::from_fn(|i| u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]) as u64);
        let nd: [u64; 20] = core::array::from_fn(|i| (ORDER[i / 4] >> (16 * (i % 4))) & 65535);
        let mut carry = 0i64;
        for i in 0usize..30 {
            for j in 0..SHORT_LIMBS {
                if let Some(t) = i.checked_sub(j).filter(|&t| t < 20) {
                    carry += (result.denominator[j] * rd[t]) as i64
                        - (result.quotient[j] * nd[t]) as i64;
                }
            }
            if i < SHORT_LIMBS {
                carry -= if negative { -1 } else { 1 } * result.numerator[i] as i64;
            }
            assert_eq!(carry % RADIX, 0);
            carry /= RADIX;
            assert!((-CARRY_OFFSET..CARRY_OFFSET).contains(&carry));
            result.carries[i] = (carry + CARRY_OFFSET) as u64;
        }
        assert_eq!(carry, 0);
        result
    }

    fn append_to(&self, advice: &mut AgreementAdvice) {
        advice.elements.extend(self.denominator);
        advice.elements.extend(self.numerator);
        advice.elements.extend(self.quotient);
        advice.elements.push(u64::from(self.negative));
        advice.elements.extend(self.carries);
    }
}

fn limbs(value: &BigInt) -> [u64; SHORT_LIMBS] {
    assert!(value.bits() <= 160);
    let (_, bytes) = value.to_bytes_le();
    core::array::from_fn(|i| {
        u16::from_le_bytes([
            bytes.get(2 * i).copied().unwrap_or(0),
            bytes.get(2 * i + 1).copied().unwrap_or(0),
        ]) as u64
    })
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::ecdh::ecgfp5::native::scalar::Scalar;

    #[test]
    fn short_fractions_match_native_scalar_arithmetic() {
        let mut rng = ChaCha20Rng::from_seed([93; 32]);
        let mut signs = [false; 2];
        for _ in 0..128 {
            let secret = SecretKey::with_rng(&mut rng);
            let fraction = Fraction::new(&secret);
            let as_scalar = |limbs: [u64; SHORT_LIMBS]| {
                let bytes: [u8; 20] =
                    core::array::from_fn(|i| (limbs[i / 2] >> (8 * (i % 2))) as u8);
                Scalar::decode_reduce(&bytes)
            };
            let numerator = as_scalar(fraction.numerator);
            let denominator = as_scalar(fraction.denominator);
            let numerator = if fraction.negative { -numerator } else { numerator };
            assert_eq!(denominator.iszero(), 0);
            assert_ne!((denominator * *secret.0).equals(numerator), 0);
            signs[usize::from(fraction.negative)] = true;
        }
        assert_eq!(signs, [true, true]);
    }
}
