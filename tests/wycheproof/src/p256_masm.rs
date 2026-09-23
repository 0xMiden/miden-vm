use std::sync::Arc;

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

/// Run arbitrary-byte vectors through the public MASM ABI without prevalidating their scalars in
/// Rust. Evaluating each successful run's precompile witness also checks the native precompile
/// relation.
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

        for test in group.tests {
            let id = test.tc_id;
            let signature = match Signature::from_der(test.sig.as_ref()) {
                Ok(signature) => signature,
                Err(_) => {
                    assert!(
                        !matches!(test.result, TestResult::Valid),
                        "tcId {id}: DER decoding failed for a valid vector"
                    );
                    invalid += 1;
                    continue;
                },
            };

            let mut message = bytes_to_packed_u32_elements(test.msg.as_ref());
            message.resize(message.len().max(8).next_multiple_of(8), Felt::ZERO);
            let mut advice = AdviceStack::new();
            advice.append_elements([Felt::from_u32((message.len() / 8) as u32)]);
            advice.append_for_adv_pipe(&message);
            advice.append_elements([Felt::from_u32(test.msg.len() as u32)]);
            advice.append_word(public_key_commitment);
            advice.append_elements(ecdsa_p256_sha256::encode_signature(&public_key, &signature));
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
                    assert!(result.is_err(), "tcId {id}: invalid signature accepted");
                },
                TestResult::Acceptable => {
                    acceptable += 1;
                    // The MASM contract follows FIPS 186-5/EIP-7951: r and s only need to lie in
                    // [1, n), and high-s witnesses are accepted, matching a plain prehash-verify
                    // policy call against the parsed key and DER-decoded signature.
                    let digest: [u8; 32] = Sha256::hash(test.msg.as_ref()).into();
                    let policy_accepts = public_key.verify_prehash(&digest, &signature).is_ok();
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
    eprintln!(
        "P-256/SHA-256 MASM Wycheproof: {valid} valid, {invalid} invalid, {acceptable} acceptable"
    );
}
