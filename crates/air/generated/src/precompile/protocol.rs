/// Relation digest binding the canonical PVM ACE circuit into the Fiat-Shamir transcript.
///
/// Checked by `air-codegen`; must match `PVM_RELATION_DIGEST` in
/// `miden-air::precompile::ace_constants`.
#[rustfmt::skip]
pub const PVM_RELATION_DIGEST: [u64; 4] = [
    5618632176883261929,
    5091169848121332946,
    9110857118546866548,
    100418585322354598,
];

include!("../../artifacts/precompile-variants.rs");

/// Returns the identity of the exact selected canonical relation.
pub fn relation_digest(variant: super::PvmAirVariant) -> super::stark_config::RelationDigest {
    PVM_VARIANT_RELATION_DIGESTS[variant.as_u8() as usize].map(miden_core::Felt::new_unchecked)
}
