//! Production PVM configuration view with deliberately accepted relation digest.
pub use miden_air_source::precompile::stark_config::*;
use miden_core::Felt;
/// Relation digest binding the canonical PVM ACE circuit into the Fiat-Shamir transcript.
///
/// The generated raw limbs live with the canonical ACE constants; this public field-valued view
/// is the value passed to every production PVM configuration.
pub const PRECOMPILE_RELATION_DIGEST: RelationDigest = {
    let [d0, d1, d2, d3] = super::protocol::PVM_RELATION_DIGEST;
    [
        Felt::new_unchecked(d0),
        Felt::new_unchecked(d1),
        Felt::new_unchecked(d2),
        Felt::new_unchecked(d3),
    ]
};

/// Compatibility test preset bound to the accepted production relation, as before extraction.
pub fn test_config() -> TestConfig {
    eidos_config(test_pcs_params(), PRECOMPILE_RELATION_DIGEST)
}
/// Challenger for the compatibility test preset.
pub fn test_challenger() -> miden_crypto::hash::eidos::MidenEidosChallenger {
    use miden_stark::StarkConfig;
    test_config().challenger()
}
