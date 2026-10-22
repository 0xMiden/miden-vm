use alloc::vec::Vec;

use rand::CryptoRng;

use super::{Ciphertext, PublicKey, SharedSecret, framing::felt, lift};
use crate::{Felt, utils::zeroize::Zeroizing};

/// The public polynomial and private witnesses needed for MASM encapsulation.
///
/// The witnesses contain the sampled polynomials r and m and the integer product h * lift(r).
/// Here h is the public polynomial, and the lift maps trits 0, 1, 2 to 0, 1, 2047. The buffer also
/// includes the capsule for copying to caller memory. Its owned storage is erased on drop.
pub struct EncapsulationAdvice(Zeroizing<Vec<u64>>);

impl EncapsulationAdvice {
    /// Returns the elements from the top of the advice stack down.
    pub fn elements(&self) -> impl ExactSizeIterator<Item = Felt> + '_ {
        self.0.iter().copied().map(felt)
    }
}

impl PublicKey {
    /// Produces a capsule, shared secret, and the private witness checked by MASM.
    ///
    /// Pass `self.to_commitment()` as the procedure's public-key input.
    pub fn encapsulate_with_advice(
        &self,
        rng: &mut impl CryptoRng,
    ) -> (Ciphertext, SharedSecret, EncapsulationAdvice) {
        let sample = self.sample(rng);
        let h = self.polynomial();
        let mut product = Zeroizing::new([0u64; 1024]);
        for (i, &a) in h[..509].iter().enumerate() {
            for (j, &r) in sample.r.iter().enumerate() {
                product[i + j] += u64::from(a) * lift(r);
            }
        }
        // Advice order: h(512), packed r(26), packed m(26), product(1024), ciphertext(175).
        // Reserve the complete buffer before adding private values to avoid reallocating them.
        let mut advice = Zeroizing::new(Vec::with_capacity(512 + 52 + 1024 + 175));
        advice.extend(h.into_iter().map(u64::from));
        // Pack 20 trits per Felt in base 3, lowest coefficient first. The final group has 8 trits;
        // coefficient 508 is always zero and is omitted.
        for polynomial in [&sample.r, &sample.m] {
            advice.extend(polynomial[..508].chunks(20).map(|trits| {
                trits.iter().rev().fold(0, |packed, &trit| packed * 3 + u64::from(trit))
            }));
        }
        advice.extend_from_slice(product.as_ref());
        advice.extend(
            super::framing::packed_bytes(sample.ciphertext.as_bytes())
                .map(|x| x.as_canonical_u64()),
        );
        (sample.ciphertext, sample.secret, EncapsulationAdvice(advice))
    }
}
