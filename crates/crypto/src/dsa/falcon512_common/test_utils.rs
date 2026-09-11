//! Helpers for checking both Miden Falcon512 variants against the reference implementation.

use alloc::vec::Vec;

use rand::{
    Rng,
    rand_core::{Infallible, TryRng, utils},
};
use shake::{
    Shake256, Shake256Reader,
    digest::{ExtendableOutput, Update, XofReader},
};

use super::{FalconVariant, MODULUS, N, Nonce, Polynomial, SIG_NONCE_LEN, math::FalconFelt};

const CHACHA_SEED_LEN: usize = 56;

/// Hashes a message and nonce to a Falcon polynomial using the reference SHAKE256 construction.
pub(super) fn hash_to_point_shake256<V: FalconVariant>(
    message: &[u8],
    nonce: &Nonce<V>,
) -> Polynomial<FalconFelt> {
    let mut data = Vec::with_capacity(SIG_NONCE_LEN + message.len());
    data.extend_from_slice(&nonce.as_bytes());
    data.extend_from_slice(message);

    let mut hasher = Shake256::default();
    hasher.update(&data);
    let mut reader = hasher.finalize_xof();

    const K: u32 = (1u32 << 16) / MODULUS as u32;
    let mut coefficients = Vec::with_capacity(N);
    while coefficients.len() != N {
        let mut randomness = [0u8; 2];
        reader.read(&mut randomness);
        let sample = u16::from_be_bytes(randomness) as u32;
        if sample < K * MODULUS as u32 {
            coefficients.push(FalconFelt::new((sample % MODULUS as u32) as i16));
        }
    }

    Polynomial::new(coefficients)
}

/// SHAKE256-based RNG used to replay the reference Falcon test vectors.
pub(in crate::dsa) struct Shake256Testing(Shake256Reader);

impl Shake256Testing {
    pub(in crate::dsa) fn new(data: &[u8]) -> Self {
        let mut hasher = Shake256::default();
        hasher.update(data);
        Self(hasher.finalize_xof())
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        self.0.read(destination)
    }

    /// Advances the RNG to the state recorded for a reference test vector.
    pub(in crate::dsa) fn sync_rng(&mut self, sync_data: &[(usize, usize)]) {
        for &(num_bytes, num_seeds) in sync_data {
            let mut discarded = vec![0_u8; num_bytes * 8];
            self.fill_bytes(&mut discarded);

            let mut nonce = [0u8; SIG_NONCE_LEN];
            self.fill_bytes(&mut nonce);

            for _ in 0..num_seeds {
                let mut seed = [0_u8; CHACHA_SEED_LEN];
                self.fill_bytes(&mut seed);
            }
        }
    }
}

impl TryRng for Shake256Testing {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        utils::next_word_via_fill::<u32, _>(self)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        utils::next_u64_via_u32(self)
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.fill_bytes(destination);
        Ok(())
    }
}

/// ChaCha20 RNG used by the Falcon reference test harness.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct ChaCha {
    state: Vec<u32>,
    seed_words: Vec<u32>,
    counter: u64,
    buffer: Vec<u8>,
}

impl ChaCha {
    pub(super) fn new<R: Rng>(rng: &mut R) -> Self {
        let mut seed = [0_u8; CHACHA_SEED_LEN];
        rng.fill_bytes(&mut seed);
        Self::with_seed(&seed)
    }

    fn with_seed(seed: &[u8]) -> Self {
        let mut seed_words = vec![0_u32; 14];
        for (word, bytes) in seed_words.iter_mut().zip(seed.chunks_exact(4)) {
            *word = u32::from_le_bytes(bytes.try_into().unwrap());
        }

        Self {
            state: vec![0_u32; 16],
            counter: seed_words[12] as u64 + ((seed_words[13] as u64) << 32),
            seed_words,
            buffer: Vec::new(),
        }
    }

    #[inline(always)]
    fn quarter_round(&mut self, a: usize, b: usize, c: usize, d: usize) {
        self.state[a] = self.state[a].wrapping_add(self.state[b]);
        self.state[d] = (self.state[d] ^ self.state[a]).rotate_left(16);
        self.state[c] = self.state[c].wrapping_add(self.state[d]);
        self.state[b] = (self.state[b] ^ self.state[c]).rotate_left(12);
        self.state[a] = self.state[a].wrapping_add(self.state[b]);
        self.state[d] = (self.state[d] ^ self.state[a]).rotate_left(8);
        self.state[c] = self.state[c].wrapping_add(self.state[d]);
        self.state[b] = (self.state[b] ^ self.state[c]).rotate_left(7);
    }

    fn update(&mut self) -> Vec<u32> {
        const CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

        self.state = vec![0_u32; 16];
        self.state[..4].copy_from_slice(&CONSTANTS);
        self.state[4..14].copy_from_slice(&self.seed_words[..10]);
        self.state[14] = self.seed_words[10] ^ self.counter as u32;
        self.state[15] = self.seed_words[11] ^ (self.counter >> 32) as u32;

        let initial_state = self.state.clone();
        for _ in 0..10 {
            self.quarter_round(0, 4, 8, 12);
            self.quarter_round(1, 5, 9, 13);
            self.quarter_round(2, 6, 10, 14);
            self.quarter_round(3, 7, 11, 15);
            self.quarter_round(0, 5, 10, 15);
            self.quarter_round(1, 6, 11, 12);
            self.quarter_round(2, 7, 8, 13);
            self.quarter_round(3, 4, 9, 14);
        }

        for (word, initial) in self.state.iter_mut().zip(initial_state) {
            *word = word.wrapping_add(initial);
        }

        self.counter += 1;
        self.state.clone()
    }

    fn refill(&mut self) {
        let mut block = vec![0_u32; 16 * 8];
        for index in 0..8 {
            let state = self.update();
            block
                .iter_mut()
                .skip(index)
                .step_by(8)
                .zip(state)
                .for_each(|(destination, value)| *destination = value);
        }
        self.buffer = block.into_iter().flat_map(u32::to_le_bytes).collect();
    }
}

impl TryRng for ChaCha {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        utils::next_word_via_fill::<u32, _>(self)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        utils::next_u64_via_u32(self)
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        if destination.len() > self.buffer.len() {
            self.refill();
        }
        destination.copy_from_slice(&self.buffer[..destination.len()]);
        self.buffer.drain(..destination.len());
        Ok(())
    }
}
