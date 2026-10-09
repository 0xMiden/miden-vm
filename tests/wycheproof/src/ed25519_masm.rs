use std::sync::Arc;

use miden_assembly::{Assembler, Linkage};
use miden_core::{
    Felt,
    advice::{AdviceInputs, AdviceStack},
    utils::bytes_to_packed_u32_elements,
};
use miden_core_lib::CoreLibrary;
use miden_crypto::hash::eidos::Eidos;
use miden_processor::{DefaultHost, ExecutionOptions, FastProcessor, StackInputs};
use wycheproof_ng_core::TestResult;

/// Run arbitrary-byte vectors through the public MASM ABI without prevalidating their points or
/// scalars in Rust. Evaluating each successful run's precompile witness also checks the native
/// precompile relation.
#[test]
fn ed25519_wycheproof_vectors_verify_in_masm() {
    let vectors = wycheproof_ng_eddsa::TestSet::load(wycheproof_ng_eddsa::TestName::Ed25519)
        .expect("Ed25519 Wycheproof vectors should load");
    let library = CoreLibrary::default();
    let program = Assembler::default()
        .with_package(library.package(), Linkage::Dynamic)
        .unwrap()
        .assemble_program(
            "ed25519_wycheproof",
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
    push.1048576 adv_push push.128 padw adv_loadw
    exec.::miden::core::crypto::dsa::eddsa_25519_sha512::verify_bytes
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
        for test in group.tests {
            let id = test.tc_id;
            // The ABI consumes exactly 32 key bytes and 64 signature bytes. Other lengths cannot
            // be represented by this witness format and must be rejected at the encoding boundary.
            if group.key.pk.len() != 32 || test.sig.len() != 64 {
                assert!(
                    !matches!(test.result, TestResult::Valid),
                    "tcId {id}: wrong encoding length"
                );
                invalid += 1;
                continue;
            }
            let mut message = bytes_to_packed_u32_elements(test.msg.as_ref());
            message.resize(message.len().max(8).next_multiple_of(8), Felt::ZERO);
            assert!(128 + message.len() < 1048576, "test message overlaps scratch");
            let key = bytes_to_packed_u32_elements(group.key.pk.as_ref());
            let mut advice = AdviceStack::new();
            advice.append_elements([Felt::from_u32((message.len() / 8) as u32)]);
            advice.append_for_adv_pipe(&message);
            advice.append_elements([Felt::from_u32(test.msg.len() as u32)]);
            advice.append_word(Eidos::hash_elements(&key));
            advice.append_elements(key);
            advice.append_elements(bytes_to_packed_u32_elements(test.sig.as_ref()));
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
                    // Wycheproof permits either outcome for policy-sensitive vectors. The MASM
                    // contract follows dalek's strict policy: canonical encodings and no
                    // small-order A/R are required, so only strict verification may succeed.
                    let pk_bytes: [u8; 32] =
                        group.key.pk.as_ref().try_into().expect("checked key length");
                    let sig_bytes: [u8; 64] =
                        test.sig.as_ref().try_into().expect("checked signature length");
                    let r_bytes: [u8; 32] =
                        sig_bytes[..32].try_into().expect("checked R encoding length");
                    let public_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes);
                    // Dalek's key constructor preserves the compressed bytes, so comparing
                    // `VerifyingKey::to_bytes()` would not test canonicality. The precompile's
                    // decompressor is the policy oracle for both compressed point encodings.
                    let canonical_encodings = miden_precompiles::ed25519_decompress_x(pk_bytes)
                        .is_ok()
                        && miden_precompiles::ed25519_decompress_x(r_bytes).is_ok();
                    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
                    let strict_accepts = canonical_encodings
                        && public_key
                            .map(|public_key| {
                                public_key.verify_strict(test.msg.as_ref(), &signature).is_ok()
                            })
                            .unwrap_or(false);
                    assert_eq!(
                        result.is_ok(),
                        strict_accepts,
                        "tcId {id}: acceptable vector disagrees with canonical/small-order policy"
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
    eprintln!("Ed25519 MASM Wycheproof: {valid} valid, {invalid} invalid, {acceptable} acceptable");
}
