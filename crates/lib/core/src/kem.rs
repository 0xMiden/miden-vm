//! Advice builders for MASM key encapsulation.

/// NTRU-HPS509 encapsulation.
pub mod ntru_hps509 {
    use miden_core::advice::AdviceInputs;
    use miden_crypto::kem::ntru_hps509::EncapsulationAdvice;

    /// Converts private encapsulation advice into the VM's advice-stack representation.
    ///
    /// Used by `crypto::kem::ntru_hps509::encapsulate` and `crypto::ies::ntru_eidos::seal`.
    pub fn advice_inputs(advice: &EncapsulationAdvice) -> AdviceInputs {
        AdviceInputs::default().with_stack(advice.elements().collect())
    }
}
