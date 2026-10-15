//! Variant framing of serialized PVM STARK proofs.

use alloc::vec::Vec;

use crate::PvmAirVariant;

// A legacy full proof starts with a wincode Vec length of twelve (its AIR log heights),
// so this header cannot collide with a valid legacy proof. The full variant retains its
// original encoding for the existing recursive verifier and pinned proof fixtures.
const HEADER: &[u8; 8] = b"MIDENPVM";
const VERSION: u8 = 1;

/// Frames a reduced-variant proof, preserving the full variant's original encoding.
pub fn encode_proof(variant: PvmAirVariant, proof: Vec<u8>) -> Vec<u8> {
    if variant == PvmAirVariant::ALL {
        return proof;
    }
    let mut encoded = Vec::with_capacity(HEADER.len() + 2 + proof.len());
    encoded.extend_from_slice(HEADER);
    encoded.push(VERSION);
    encoded.push(variant.as_u8());
    encoded.extend_from_slice(&proof);
    encoded
}

/// Selects one of the eight supported relations and returns its serialized STARK payload.
///
/// A recognized header must be valid; it never falls back to legacy decoding on an error.
/// The selected relation's digest must be bound into the verifier's Fiat–Shamir transcript.
pub fn decode_proof(proof: &[u8]) -> Result<(PvmAirVariant, &[u8]), &'static str> {
    if !proof.starts_with(HEADER) {
        return Ok((PvmAirVariant::ALL, proof));
    }
    let [version, variant, payload @ ..] = &proof[HEADER.len()..] else {
        return Err("truncated PVM variant header");
    };
    if *version != VERSION {
        return Err("unsupported PVM variant encoding version");
    }
    let variant = PvmAirVariant::from_u8(*variant).ok_or("unsupported PVM AIR variant")?;
    if variant == PvmAirVariant::ALL {
        return Err("the full PVM variant must use its original encoding");
    }
    Ok((variant, payload))
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn full_proofs_preserve_the_existing_encoding() {
        // StarkProofData begins with the encoded length of its twelve log heights.
        let payload = vec![12, 0, 0, 0, 0, 0, 0, 0, 7, 16];
        assert_eq!(encode_proof(PvmAirVariant::ALL, payload.clone()), payload);
        assert_eq!(decode_proof(&payload), Ok((PvmAirVariant::ALL, payload.as_slice())));
    }

    #[test]
    fn reduced_proofs_round_trip_the_exact_variant_and_payload() {
        for variant in PvmAirVariant::ALL_VARIANTS {
            let encoded = encode_proof(variant, vec![42, 19]);
            assert_eq!(decode_proof(&encoded), Ok((variant, &[42, 19][..])));
        }
    }

    #[test]
    fn recognized_headers_reject_unknown_versions_variants_and_truncation() {
        let encoded = encode_proof(PvmAirVariant::NONE, vec![42]);
        for len in 8..10 {
            assert!(decode_proof(&encoded[..len]).is_err());
        }
        let mut invalid = encoded.clone();
        invalid[8] = 2;
        assert!(decode_proof(&invalid).is_err());
        for mask in [7, 8, 255] {
            let mut invalid = encoded.clone();
            invalid[9] = mask;
            assert!(decode_proof(&invalid).is_err());
        }
    }
}
