//! Rust-side transcript that exactly matches the MASM signature verifier's
//! Poseidon2 sponge operations.
//!
//! The MASM verifier uses `reseed_direct` (overwrite R1, keep R2+C, permute) and
//! full-rate absorption (overwrite R1+R2, keep C, permute). This custom transcript
//! replicates those operations exactly using `Poseidon2Permutation256::apply_permutation`.
//!
//! Sponge state: [R1(4), R2(4), C(4)] -- width 12, rate 8, capacity 4.

use miden_core::Felt;
use miden_crypto::hash::poseidon2::Poseidon2Permutation256;

const STATE_WIDTH: usize = 12;
const RATE: usize = 8;

/// Poseidon2 sponge transcript matching the MASM signature verifier exactly.
#[derive(Clone)]
pub struct SigTranscript {
    pub state: [Felt; STATE_WIDTH],
    /// How many rate elements are available for sampling (counts down from 8).
    output_len: usize,
}

impl SigTranscript {
    /// Initialize: hperm(R1=msg, R2=pk, C=instance_seed), then zero rate.
    ///
    /// After this, capacity holds PROOF_SEED and the sponge is ready to absorb.
    pub fn new(instance_seed: [Felt; 4], pk: [Felt; 4], msg: [Felt; 4]) -> Self {
        let mut state = [Felt::ZERO; STATE_WIDTH];
        // R1 = msg (state[0..4])
        state[0..4].copy_from_slice(&msg);
        // R2 = pk (state[4..8])
        state[4..8].copy_from_slice(&pk);
        // C = instance_seed (state[8..12])
        state[8..12].copy_from_slice(&instance_seed);

        Poseidon2Permutation256::apply_permutation(&mut state);

        // Keep full state (R1', R2', PROOF_SEED). No rate zeroing —
        // R2' carries entropy and is preserved by the next reseed_direct.
        Self { state, output_len: RATE }
    }

    /// Absorb 4 felts into R1, keep R2 and C, permute.
    /// Matches MASM `reseed_direct`.
    pub fn reseed_direct(&mut self, word: [Felt; 4]) {
        self.state[0..4].copy_from_slice(&word);
        Poseidon2Permutation256::apply_permutation(&mut self.state);
        self.output_len = RATE;
    }

    /// Absorb 8 felts (full rate), permute.
    /// Matches MASM OOD absorption: write R1 + R2, permute.
    pub fn absorb_full_rate(&mut self, r1: [Felt; 4], r2: [Felt; 4]) {
        self.state[0..4].copy_from_slice(&r1);
        self.state[4..8].copy_from_slice(&r2);
        Poseidon2Permutation256::apply_permutation(&mut self.state);
        self.output_len = RATE;
    }

    /// Sample one base field element.
    /// Matches MASM `sample_felt`: reads rate[output_len - 1].
    /// Auto-permutes when rate is exhausted (matches MASM `generate_list_indices`).
    pub fn sample_felt(&mut self) -> Felt {
        if self.output_len == 0 {
            Poseidon2Permutation256::apply_permutation(&mut self.state);
            self.output_len = RATE;
        }
        self.output_len -= 1;
        self.state[self.output_len]
    }

    /// Sample a quadratic extension field element (2 felts).
    /// Matches MASM `sample_ext`: sample_felt, sample_felt, swap.
    pub fn sample_ext(&mut self) -> [Felt; 2] {
        let a = self.sample_felt();
        let b = self.sample_felt();
        [a, b]
    }

    /// Sample low `bits` bits from a felt.
    pub fn sample_bits(&mut self, bits: usize) -> u64 {
        let felt = self.sample_felt();
        let lo = felt.as_canonical_u64() as u32;
        let mask = if bits >= 32 { u32::MAX } else { (1u32 << bits) - 1 };
        (lo & mask) as u64
    }

    /// Grinding check: write nonce to R1[0], permute, sample bits, check == 0.
    /// Matches MASM nonzero grinding checks (`check_sig_grind_prox_nonzero`,
    /// `check_sig_grind_query_nonzero`).
    pub fn check_grind(&mut self, nonce: u64, bits: usize) -> bool {
        if bits == 0 {
            return nonce == 0;
        }
        self.state[0] = Felt::new(nonce);
        Poseidon2Permutation256::apply_permutation(&mut self.state);
        self.output_len = RATE;
        self.sample_bits(bits) == 0
    }

    /// Find a grinding nonce.
    #[allow(dead_code)]
    pub fn grind(&mut self, bits: usize) -> u64 {
        if bits == 0 {
            return 0;
        }
        let snapshot = self.clone();
        for nonce in 0u64.. {
            *self = snapshot.clone();
            if self.check_grind(nonce, bits) {
                return nonce;
            }
        }
        unreachable!()
    }

    /// Sample a query index in [0, 2^bits).
    /// For power-of-2 code_size, no rejection needed.
    pub fn sample_index(&mut self, log_size: usize) -> usize {
        self.sample_bits(log_size) as usize
    }

    /// Sample `count` indices in [0, 2^log_size) with replacement.
    pub fn sample_indices(&mut self, log_size: usize, count: usize) -> Vec<usize> {
        // Match MASM `sample_sig_query_indices` packed extraction:
        // 4 indices from one felt via u16 lanes, then mask to `log_size` bits.
        if log_size <= 16 {
            let mask = (1u64 << log_size) - 1;
            let mut indices = Vec::with_capacity(count);

            let groups = count / 4;
            for _ in 0..groups {
                let word = self.sample_felt().as_canonical_u64();
                indices.push((((word) as u16 as u64) & mask) as usize);
                indices.push((((word >> 16) as u16 as u64) & mask) as usize);
                indices.push((((word >> 32) as u16 as u64) & mask) as usize);
                indices.push((((word >> 48) as u16 as u64) & mask) as usize);
            }

            let rem = count % 4;
            if rem != 0 {
                let word = self.sample_felt().as_canonical_u64();
                if rem >= 1 {
                    indices.push((((word) as u16 as u64) & mask) as usize);
                }
                if rem >= 2 {
                    indices.push((((word >> 16) as u16 as u64) & mask) as usize);
                }
                if rem >= 3 {
                    indices.push((((word >> 32) as u16 as u64) & mask) as usize);
                }
            }

            return indices;
        }

        let mut indices = Vec::with_capacity(count);
        for _ in 0..count {
            indices.push(self.sample_index(log_size));
        }
        indices
    }

    /// Get the current capacity (for debugging / INSTANCE_SEED computation).
    #[allow(dead_code)]
    pub fn capacity(&self) -> [Felt; 4] {
        [self.state[8], self.state[9], self.state[10], self.state[11]]
    }
}

/// Compute INSTANCE_SEED for e2_105 from protocol parameters.
///
/// INSTANCE_SEED = capacity after:
///   hperm(R1=[code_size, num_queries, grind_prox, grind_query],
///         R2=[log_trace_height, num_constraints, 0, 0],
///         C=RELATION_DIGEST)
///
/// RELATION_DIGEST is currently zeroed in tests.
/// Once finalized, it should be derived from protocol metadata and circuit commitment.
pub fn compute_instance_seed() -> [Felt; 4] {
    let config = miden_signature::internal::signer::Config::e2_105bit();
    let seed = miden_signature::internal::proof::instance_seed_for_config::<
        miden_signature::internal::air8::Rpo8,
    >(&config.stark);
    core::array::from_fn(|i| seed[i].into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_masm_const(contents: &str, name: &str) -> Option<u64> {
        for line in contents.lines() {
            let line = line.trim();
            if !line.starts_with("const") {
                continue;
            }
            if !line.contains(name) {
                continue;
            }
            let (_lhs, rhs) = line.split_once('=')?;

            let val_str = rhs.split('#').next()?.trim();
            return val_str.parse().ok();
        }
        None
    }

    #[test]
    fn transcript_basic_operations() {
        let seed = compute_instance_seed();
        let pk = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)];
        let msg = [Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)];

        let mut t = SigTranscript::new(seed, pk, msg);

        // After init, output_len starts at RATE from the initial permutation.
        // Absorb a commitment
        let com = [Felt::new(10), Felt::new(11), Felt::new(12), Felt::new(13)];
        t.reseed_direct(com);

        // Should be able to sample now
        let ext = t.sample_ext();
        assert!(ext[0] != Felt::ZERO || ext[1] != Felt::ZERO, "sampled non-trivial value");
    }

    #[test]
    fn poseidon2_matches_miden_signature() {
        // Verify that miden-crypto's Poseidon2Permutation256 matches
        // miden-signature's Poseidon2Perm on the same input.
        use miden_signature::{Goldilocks, internal::poseidon2::Poseidon2Perm};

        let mut state_mc = [Felt::ZERO; 12];
        state_mc[0] = Felt::ONE;
        Poseidon2Permutation256::apply_permutation(&mut state_mc);

        let mut state_sig: [Goldilocks; 12] = unsafe { core::mem::zeroed() };
        state_sig[0] = Goldilocks::new(1);
        Poseidon2Perm::permute(&mut state_sig);

        for i in 0..12 {
            let mc = state_mc[i].as_canonical_u64();
            let sig: u64 = Felt::from(state_sig[i]).as_canonical_u64();
            assert_eq!(mc, sig, "Poseidon2 mismatch at {}: mc={}, sig={}", i, mc, sig);
        }
    }

    #[test]
    fn print_instance_seed() {
        let seed = compute_instance_seed();
        for (i, f) in seed.iter().enumerate() {
            eprintln!("SIG_INSTANCE_SEED_{} = {}", i, f.as_canonical_u64());
        }
        // Verify it's non-trivial
        assert!(seed.iter().any(|f| *f != Felt::ZERO), "seed should be non-zero");
    }

    #[test]
    fn instance_seed_matches_masm_constants() {
        let seed = compute_instance_seed();
        let seed_vals = [
            seed[0].as_canonical_u64(),
            seed[1].as_canonical_u64(),
            seed[2].as_canonical_u64(),
            seed[3].as_canonical_u64(),
        ];

        let constants = include_str!("../../asm/sig/constants.masm");
        let mod_masm = include_str!("../../asm/sig/mod.masm");

        for (i, &seed_val) in seed_vals.iter().enumerate() {
            let name = format!("SIG_INSTANCE_SEED_{}", i);
            let from_constants = parse_masm_const(constants, &name)
                .unwrap_or_else(|| panic!("missing {name} in sig/constants.masm"));
            let from_mod = parse_masm_const(mod_masm, &name)
                .unwrap_or_else(|| panic!("missing {name} in sig/mod.masm"));

            assert_eq!(
                from_constants, from_mod,
                "{name} mismatch between sig/constants.masm and sig/mod.masm"
            );
            assert_eq!(
                from_constants, seed_val,
                "{name} mismatch between MASM constants and instance seed"
            );
        }
    }

    #[test]
    fn transcript_deterministic() {
        let seed = compute_instance_seed();
        let pk = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)];
        let msg = [Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)];

        let mut t1 = SigTranscript::new(seed, pk, msg);
        let mut t2 = SigTranscript::new(seed, pk, msg);

        let com = [Felt::new(10), Felt::new(11), Felt::new(12), Felt::new(13)];
        t1.reseed_direct(com);
        t2.reseed_direct(com);

        assert_eq!(t1.sample_ext(), t2.sample_ext());
        assert_eq!(t1.sample_felt(), t2.sample_felt());
    }
}
