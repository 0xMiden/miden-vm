use chacha20poly1305::aead::rand_core::{
    CryptoRng as CryptoRng06, Error as RandError06, RngCore as RngCore06,
};
use rand::{CryptoRng, Rng};

/// Adapts rand 0.10 RNGs for stable crypto crates that still use rand_core 0.6.
pub(crate) struct RandCore06<'a, R: ?Sized>(&'a mut R);

impl<'a, R: ?Sized> RandCore06<'a, R> {
    pub(crate) fn new(rng: &'a mut R) -> Self {
        Self(rng)
    }
}

impl<R: Rng + ?Sized> RngCore06 for RandCore06<'_, R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError06> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl<R: CryptoRng + ?Sized> CryptoRng06 for RandCore06<'_, R> {}
