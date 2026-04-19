use alloc::vec::Vec;

use rand::{Rng, RngCore};
use rand_core::impls;
use sha3::{
    Shake256, Shake256ReaderCore,
    digest::{ExtendableOutput, Update, XofReader, core_api::XofReaderCoreWrapper},
};

use super::data::SYNC_DATA;
use crate::dsa::falcon512_poseidon2::SIG_NONCE_LEN;

/// Length of the seed for the ChaCha20-based PRNG.
pub(crate) const CHACHA_SEED_LEN: usize = 56;

// SHAKE256
// ================================================================================================

/// A PRNG based on SHAKE256 used for testing.
pub struct Shake256Testing(XofReaderCoreWrapper<Shake256ReaderCore>);

impl Shake256Testing {
    pub fn new(data: Vec<u8>) -> Self {
        let mut hasher = Shake256::default();
        hasher.update(&data);
        let result = hasher.finalize_xof();

        Self(result)
    }

    fn fill_bytes(&mut self, des: &mut [u8]) {
        self.0.read(des)
    }

    /// A function to help with "syncing" the SHAKE256 PRNG so that it can be used with the test
    /// vectors for Falcon512.
    pub(crate) fn sync_rng(&mut self) {
        for (bytes, num_seed_sampled) in SYNC_DATA.iter() {
            let mut dummy = vec![0_u8; bytes * 8];
            self.fill_bytes(&mut dummy);
            let mut nonce_bytes = [0u8; SIG_NONCE_LEN];
            self.fill_bytes(&mut nonce_bytes);

            for _ in 0..*num_seed_sampled {
                let mut chacha_seed = [0_u8; CHACHA_SEED_LEN];
                self.fill_bytes(&mut chacha_seed);
            }
        }
    }
}

impl RngCore for Shake256Testing {
    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_u32(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.fill_bytes(dest)
    }
}

// ChaCha20
// ================================================================================================

/// A PRNG based on ChaCha20 used for testing.
#[derive(Clone, PartialEq, Eq)]
pub struct ChaCha {
    state: Vec<u32>,
    s: Vec<u32>,
    ctr: u64,
    buffer: Vec<u8>,
}

impl ChaCha {
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let mut chacha_seed = [0_u8; CHACHA_SEED_LEN];
        rng.fill_bytes(&mut chacha_seed);
        ChaCha::with_seed(chacha_seed.to_vec())
    }

    pub fn with_seed(src: Vec<u8>) -> Self {
        let mut s = vec![0_u32; 14];
        for i in 0..14 {
            let bytes = &src[(4 * i)..(4 * (i + 1))];
            let value = u32::from_le_bytes(bytes.try_into().unwrap());
            s[i] = value;
        }
        Self {
            state: vec![0_u32; 16],
            ctr: s[12] as u64 + ((s[13] as u64) << 32),
            s,
            buffer: vec![0_u8; 0],
        }
    }

    #[inline(always)]
    fn qround(&mut self, a: usize, b: usize, c: usize, d: usize) {
        self.state[a] = self.state[a].wrapping_add(self.state[b]);
        self.state[d] = Self::roll(self.state[d] ^ self.state[a], 16);
        self.state[c] = self.state[c].wrapping_add(self.state[d]);
        self.state[b] = Self::roll(self.state[b] ^ self.state[c], 12);
        self.state[a] = self.state[a].wrapping_add(self.state[b]);
        self.state[d] = Self::roll(self.state[d] ^ self.state[a], 8);
        self.state[c] = self.state[c].wrapping_add(self.state[d]);
        self.state[b] = Self::roll(self.state[b] ^ self.state[c], 7);
    }

    fn update(&mut self) -> Vec<u32> {
        const CW: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

        self.state = vec![0_u32; 16];
        self.state[0] = CW[0];
        self.state[1] = CW[1];
        self.state[2] = CW[2];
        self.state[3] = CW[3];

        for i in 0..10 {
            self.state[i + 4] = self.s[i]
        }

        self.state[14] = self.s[10] ^ ((self.ctr & 0xffffffff) as u32);
        self.state[15] = self.s[11] ^ ((self.ctr >> 32) as u32);

        let state = self.state.clone();

        for _ in 0..10 {
            self.qround(0, 4, 8, 12);
            self.qround(1, 5, 9, 13);
            self.qround(2, 6, 10, 14);
            self.qround(3, 7, 11, 15);
            self.qround(0, 5, 10, 15);
            self.qround(1, 6, 11, 12);
            self.qround(2, 7, 8, 13);
            self.qround(3, 4, 9, 14);
        }

        for (i, s) in self.state.iter_mut().enumerate().take(16) {
            *s = (*s).wrapping_add(state[i]);
        }

        self.ctr += 1;
        self.state.clone()
    }

    fn block_update(&mut self) -> Vec<u32> {
        let mut block = vec![0_u32; 16 * 8];
        for i in 0..8 {
            let updated = self.update();
            block
                .iter_mut()
                .skip(i)
                .step_by(8)
                .zip(updated.iter())
                .for_each(|(b, &u)| *b = u);
        }
        block
    }

    fn random_bytes(&mut self, k: usize) -> Vec<u8> {
        if k > self.buffer.len() {
            let block = self.block_update();
            self.buffer = block.iter().flat_map(|&e| e.to_le_bytes().to_vec()).collect();
        }
        let out = (self.buffer[..k]).to_vec();
        self.buffer = self.buffer[k..].to_vec();

        out
    }

    fn roll(x: u32, n: usize) -> u32 {
        (x << n) ^ (x >> (32 - n))
    }
}

impl RngCore for ChaCha {
    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_u32(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let len = dest.len();
        let buffer = self.random_bytes(len);
        dest.iter_mut().enumerate().for_each(|(i, d)| *d = buffer[i])
    }
}
