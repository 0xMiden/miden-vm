//! Complete/deferred execution proof composition over independent VM and PVM products.
#[cfg(feature = "prover")]
mod prover;
#[cfg(feature = "prover")]
pub use prover::{Prover, ProverError, prove_sync};
mod verifier;
pub use miden_air::security::{
    AirShape, InstanceShape, LookupShape, ProofSecurityParameters, ProtocolParams, SecurityReport,
    SecurityTerm,
};
pub use miden_precompile_stark as precompile;
pub use miden_vm_stark as vm;
pub use verifier::{StarkVerificationError, VerificationError, VerificationOutcome, Verifier};
