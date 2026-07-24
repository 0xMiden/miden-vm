use miden_core::{
    Felt, Word,
    advice::{AdviceInputs, AdviceStack},
};
use miden_core_lib::dsa::ecdsa_k256_keccak;
use miden_crypto::dsa::ecdsa_k256_keccak::SigningKey;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

pub const DEFAULT_KECCAKS: usize = 100;
pub const DEFAULT_ECDSAS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrecompileWorkload {
    pub keccaks: usize,
    pub ecdsas: usize,
}

impl Default for PrecompileWorkload {
    fn default() -> Self {
        Self {
            keccaks: DEFAULT_KECCAKS,
            ecdsas: DEFAULT_ECDSAS,
        }
    }
}

pub(crate) fn generate_advice_inputs(workload: PrecompileWorkload) -> AdviceInputs {
    let mut advice_stack = AdviceStack::new();
    let mut rng = ChaCha20Rng::from_seed([0xd3; 32]);

    for i in 0..workload.ecdsas {
        let sk = SigningKey::with_rng(&mut rng);
        let pk = sk.public_key();
        let message = ecdsa_message(i as u64);
        let signature = sk.sign(message);
        assert!(
            pk.verify(message, &signature),
            "generated ECDSA fixture must verify before passing it to MASM",
        );

        advice_stack.push_word(message);
        advice_stack.push_word(ecdsa_k256_keccak::public_key_commitment(&pk));
        advice_stack.push_for_adv_pipe(&ecdsa_k256_keccak::encode_signature(&pk, &signature));
    }

    assert_eq!(advice_stack.len(), workload.ecdsas * 40, "unexpected ECDSA advice length");
    AdviceInputs::default().with_advice_stack(advice_stack)
}

fn ecdsa_message(index: u64) -> Word {
    Word::new([
        Felt::new_unchecked(0x0001_0203_0405_0607 + index),
        Felt::new_unchecked(0x0809_0a0b_0c0d_0e0f + index * 3),
        Felt::new_unchecked(0x1011_1213_1415_1617 + index * 5),
        Felt::new_unchecked(0x1819_1a1b_1c1d_1e1f + index * 7),
    ])
}
