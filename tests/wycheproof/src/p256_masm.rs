use std::sync::Arc;

use der::{Decode, DecodeValue, Header, Reader, Sequence, asn1::UintRef};
use miden_assembly::{Assembler, Linkage};
use miden_core::{
    Felt,
    advice::{AdviceInputs, AdviceStack},
    utils::bytes_to_packed_u32_elements,
};
use miden_core_lib::{CoreLibrary, dsa::ecdsa_p256_sha256};
use miden_crypto::hash::sha2::Sha256;
use miden_processor::{DefaultHost, ExecutionOptions, FastProcessor, StackInputs};
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use wycheproof_ng_core::TestResult;

/// Run arbitrary-byte vectors through the public MASM ABI. Rust rejects only undecodable public
/// keys and signatures that are not strict DER or whose integers exceed 256 bits; every other r and
/// s reaches MASM as raw little-endian u32 limbs, so zero and out-of-range scalars are rejected by
/// the MASM canonical scalar loaders and nonzero checks. Evaluating each successful run's
/// precompile witness also checks the native precompile relation.
#[test]
fn p256_wycheproof_vectors_verify_in_masm() {
    let vectors =
        wycheproof_ng_ecdsa::TestSet::load(wycheproof_ng_ecdsa::TestName::EcdsaSecp256r1Sha256)
            .expect("P-256/SHA-256 Wycheproof vectors should load");
    let library = CoreLibrary::default();
    let program = Assembler::default()
        .with_package(library.package(), Linkage::Dynamic)
        .unwrap()
        .assemble_program(
            "p256_wycheproof",
            r#"
proc load_message
    push.128 adv_push
    dup neq.0
    while.true
        swap padw padw padw adv_pipe dropw dropw dropw
        swap sub.1 dup neq.0
    end
    drop drop
end
begin
    exec.load_message
    adv_push push.128 padw adv_loadw
    exec.::miden::core::crypto::dsa::ecdsa_p256_sha256::verify_bytes
end
"#,
        )
        .unwrap()
        .unwrap_program();
    let registry = Arc::new(miden_precompiles::registry());
    let mut valid = 0;
    let mut invalid = 0;
    let mut acceptable = 0;
    let mut invalid_in_masm = 0;

    for group in vectors.test_groups {
        let public_key = match VerifyingKey::from_sec1_bytes(group.key.key.as_ref()) {
            Ok(public_key) => public_key,
            Err(_) => {
                for test in group.tests {
                    assert!(
                        !matches!(test.result, TestResult::Valid),
                        "tcId {}: invalid public key",
                        test.tc_id
                    );
                    invalid += 1;
                }
                continue;
            },
        };
        let public_key_commitment = ecdsa_p256_sha256::public_key_commitment(&public_key);
        let point = public_key.to_sec1_point(false);
        let public_key_limbs = [point.x(), point.y()]
            .map(|coordinate| be_to_le_limbs(&(*coordinate.expect("uncompressed point")).into()));

        for test in group.tests {
            let id = test.tc_id;
            let Some((r, s)) = der_scalars(test.sig.as_ref()) else {
                assert!(
                    !matches!(test.result, TestResult::Valid),
                    "tcId {id}: DER decoding failed for a valid vector"
                );
                invalid += 1;
                continue;
            };

            let mut message = bytes_to_packed_u32_elements(test.msg.as_ref());
            message.resize(message.len().max(8).next_multiple_of(8), Felt::ZERO);
            let mut advice = AdviceStack::new();
            advice.append_elements([Felt::from_u32((message.len() / 8) as u32)]);
            advice.append_for_adv_pipe(&message);
            advice.append_elements([Felt::from_u32(test.msg.len() as u32)]);
            advice.append_word(public_key_commitment);
            advice.append_elements(public_key_limbs.into_iter().flatten());
            advice.append_elements(be_to_le_limbs(&r));
            advice.append_elements(be_to_le_limbs(&s));
            let mut host = DefaultHost::default().with_library(&library).unwrap();
            let result = FastProcessor::new_with_options(
                StackInputs::default(),
                AdviceInputs::default().with_stack(advice),
                ExecutionOptions::default(),
            )
            .unwrap()
            .execute_sync(&program, &mut host);

            match test.result {
                TestResult::Valid => {
                    valid += 1;
                    assert!(result.is_ok(), "tcId {id}: valid signature rejected: {result:?}");
                },
                TestResult::Invalid => {
                    invalid += 1;
                    invalid_in_masm += 1;
                    assert!(result.is_err(), "tcId {id}: invalid signature accepted");
                },
                TestResult::Acceptable => {
                    acceptable += 1;
                    // The MASM contract follows FIPS 186-5/EIP-7951: r and s only need to lie in
                    // [1, n), and high-s witnesses are accepted, matching a range-checked
                    // signature and a plain prehash-verify policy call against the parsed key.
                    let digest: [u8; 32] = Sha256::hash(test.msg.as_ref()).into();
                    let policy_accepts = Signature::from_scalars(r, s).is_ok_and(|signature| {
                        public_key.verify_prehash(&digest, &signature).is_ok()
                    });
                    assert_eq!(
                        result.is_ok(),
                        policy_accepts,
                        "tcId {id}: acceptable vector disagrees with the documented policy"
                    );
                },
            }
            if let Ok(output) = result {
                assert!(output.advice.stack().is_empty(), "tcId {id}: leftover witness");
                let witness = output
                    .precompile_witness
                    .as_ref()
                    .unwrap_or_else(|| panic!("tcId {id}: missing deferred work"));
                let root = witness
                    .compute_root(Arc::clone(&registry))
                    .unwrap_or_else(|err| panic!("tcId {id}: invalid deferred relation: {err}"));
                assert_eq!(root, output.precompile_root(), "tcId {id}: root changed");
            }
        }
    }
    assert!(valid > 0 && invalid > 0);
    // Zero and out-of-range scalars, such as r = n or r = 5 + n with x(R) = 5, reach MASM.
    assert_eq!(invalid_in_masm, INVALID_VECTORS_IN_MASM, "invalid vectors checked by MASM");
    eprintln!(
        "P-256/SHA-256 MASM Wycheproof: {valid} valid, {invalid} invalid ({invalid_in_masm} \
         rejected by MASM), {acceptable} acceptable"
    );
}

/// Invalid vectors whose signature is strict DER with integers of at most 256 bits.
const INVALID_VECTORS_IN_MASM: usize = 75;

/// `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` with non-negative integers.
struct DerScalars<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}

impl<'a> DecodeValue<'a> for DerScalars<'a> {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        Ok(Self {
            r: UintRef::decode(reader)?,
            s: UintRef::decode(reader)?,
        })
    }
}

impl<'a> Sequence<'a> for DerScalars<'a> {}

/// Returns the big-endian r and s of a strict-DER ECDSA signature without range-checking them
/// against the group order, or `None` if the encoding is not strict DER or either integer is wider
/// than 256 bits.
fn der_scalars(signature: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let DerScalars { r, s } = DerScalars::from_der(signature).ok()?;
    Some((left_pad_32(r.as_bytes())?, left_pad_32(s.as_bytes())?))
}

fn left_pad_32(bytes: &[u8]) -> Option<[u8; 32]> {
    let mut padded = [0; 32];
    padded[32_usize.checked_sub(bytes.len())?..].copy_from_slice(bytes);
    Some(padded)
}

/// Converts a 32-byte big-endian integer into eight little-endian u32 limbs.
fn be_to_le_limbs(bytes: &[u8; 32]) -> [Felt; 8] {
    core::array::from_fn(|i| {
        let offset = 28 - 4 * i;
        Felt::from_u32(u32::from_be_bytes(bytes[offset..offset + 4].try_into().expect("u32 limb")))
    })
}
