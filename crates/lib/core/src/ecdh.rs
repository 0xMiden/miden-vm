//! Advice builders for native MASM key agreement.

/// EcGFp5 Diffie-Hellman key agreement.
pub mod ecgfp5 {
    use miden_core::advice::AdviceInputs;
    use miden_crypto::ecdh::ecgfp5::{AgreementAdvice, PreparedPublicKey, PublicKey, SecretKey};

    /// Builds private inputs for `crypto::ecdh::ecgfp5::agree`.
    /// Pass `key.to_commitment()` on the operand stack; see [`PublicKey::advise`].
    pub fn advice_inputs(key: &PublicKey, ephemeral_secret: &SecretKey) -> AdviceInputs {
        from_advice(key.advise(ephemeral_secret))
    }

    /// Builds private inputs for `crypto::ecdh::ecgfp5::agree_preprocessed`.
    ///
    /// Pass `key.to_commitment()` on the operand stack; see [`PreparedPublicKey::advise`].
    pub fn preprocessed_advice_inputs(
        key: &PreparedPublicKey,
        ephemeral_secret: &SecretKey,
    ) -> AdviceInputs {
        from_advice(key.advise(ephemeral_secret))
    }

    fn from_advice(advice: AgreementAdvice) -> AdviceInputs {
        AdviceInputs::default()
            .with_stack(advice.elements().collect())
            .with_merkle_store(advice.merkle_nodes().iter().cloned().collect())
    }
}
