use core::fmt;
use winter_utils::string::String;

// VERIFIER ERROR
// ================================================================================================
/// Represents an error returned by the verifier during an execution of the protocol.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifierError {
    /// This error occurs when base field read by a verifier from a proof does not match the
    /// base field of AIR with which the verifier was instantiated.
    InconsistentBaseField,
    /// This error occurs when a verifier cannot deserialize the specified proof.
    ProofDeserializationError(String),
    /// This error occurs when a verifier fails to draw a random value from a random coin
    /// within a specified number of tries.
    RandomCoinError,
    /// This error occurs when constraints evaluated over out-of-domain trace rows do not match
    /// evaluations of the constraint composition polynomial at the out-of-domain point.
    InconsistentOodConstraintEvaluations,
    /// This error occurs when the proof-of-work nonce hashed with the current state of the public
    /// coin resolves to a value which does not meet the proof-of-work threshold specified by the
    // proof options.
    QuerySeedProofOfWorkVerificationFailed,
    /// This error occurs when the DEEP composition polynomial evaluations derived from trace and
    /// constraint evaluation queries do not represent a polynomial of the degree expected by the
    /// verifier.
    FriVerificationFailed(winter_fri::VerifierError),
}

impl fmt::Display for VerifierError {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InconsistentBaseField =>  {
                write!(f, "base field of the proof does not match base field of the specified AIR")
            }
            Self::ProofDeserializationError(msg) => {
                write!(f, "proof deserialization failed: {msg}")
            }
            Self::RandomCoinError => {
                write!(f, "failed to draw a random value from a random coin")
            }
            Self::InconsistentOodConstraintEvaluations => {
                write!(f, "constraint evaluations over the out-of-domain frame are inconsistent")
            }
            Self::QuerySeedProofOfWorkVerificationFailed => {
                write!(f, "query seed proof-of-work verification failed")
            }
            Self::FriVerificationFailed(err) => {
                write!(f, "verification of low-degree proof failed: {err}")
            }
        }
    }
}
