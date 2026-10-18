//! Canonical production ACE generated ahead of use from authored equations.
use miden_ace::{AceError, EncodedCircuit, RecursiveAceCircuit};
pub const ENCODED_ACE: &[u8] = include_bytes!("../../artifacts/precompile.ace");
pub fn recursive_circuit() -> Result<RecursiveAceCircuit, AceError> {
    recursive_circuit_for(super::PvmAirVariant::ALL)
}
#[cfg(feature = "std")]
pub fn shared_recursive_circuit() -> &'static RecursiveAceCircuit {
    shared_recursive_circuit_for(super::PvmAirVariant::ALL)
}

pub use super::ace_constants::PVM_ACE_CIRCUIT_DIGEST as ACE_CIRCUIT_DIGEST;

/// The selected, precompiled canonical stream. ALL preserves the legacy artifact bytes.
pub fn encoded_ace_for(variant: super::PvmAirVariant) -> &'static [u8] {
    match variant.as_u8() {
        0 => include_bytes!("../../artifacts/precompile-0.ace"),
        1 => include_bytes!("../../artifacts/precompile-1.ace"),
        2 => include_bytes!("../../artifacts/precompile-2.ace"),
        3 => include_bytes!("../../artifacts/precompile-3.ace"),
        4 => include_bytes!("../../artifacts/precompile-4.ace"),
        5 => include_bytes!("../../artifacts/precompile-5.ace"),
        6 => include_bytes!("../../artifacts/precompile-6.ace"),
        7 => ENCODED_ACE,
        _ => unreachable!("validated variant"),
    }
}

pub fn recursive_circuit_for(
    variant: super::PvmAirVariant,
) -> Result<RecursiveAceCircuit, AceError> {
    let circuit: RecursiveAceCircuit =
        EncodedCircuit::from_canonical_bytes(encoded_ace_for(variant))?.into();
    let expected = super::protocol::PVM_VARIANT_CIRCUIT_DIGESTS[variant.as_u8() as usize];
    if circuit.commitment != miden_core::Word::new(expected.map(miden_core::Felt::new_unchecked)) {
        return Err(AceError::InvalidInputLayout {
            message: "selected PVM artifact differs from accepted identity".into(),
        });
    }
    Ok(circuit)
}

#[cfg(feature = "std")]
pub fn shared_recursive_circuit_for(variant: super::PvmAirVariant) -> &'static RecursiveAceCircuit {
    static CIRCUITS: [std::sync::OnceLock<RecursiveAceCircuit>; 8] =
        [const { std::sync::OnceLock::new() }; 8];
    CIRCUITS[variant.as_u8() as usize]
        .get_or_init(|| recursive_circuit_for(variant).expect("packaged selected ACE must decode"))
}
