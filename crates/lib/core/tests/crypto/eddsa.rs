use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION},
    scalar::Scalar,
    traits::IsIdentity,
};
use miden_assembly::{Assembler, Linkage};
use miden_core::{
    Felt, Word,
    serde::{Deserializable, Serializable},
    utils::bytes_to_packed_u32_elements,
};
use miden_core_lib::{
    CoreLibrary,
    dsa::eddsa_25519_sha512,
    handlers::precompiles::ed25519::{ED25519_DECOMPRESS_EVENT_NAME, handle_ed25519_decompress},
};
use miden_crypto::{
    dsa::eddsa_25519_sha512::SigningKey,
    hash::{eidos::Eidos, sha2::Sha512},
};
use miden_precompiles::{Ed25519Base, UintSpec, ed25519_decompress_x};
use miden_processor::{
    DefaultHost, ExecutionError, ExecutionOptions, ExecutionOutput, FastProcessor, StackInputs,
    advice::{AdviceInputs, AdviceMutation, AdviceStack},
    event::EventHandler,
    operation::OperationError,
};

use crate::{
    helpers::{masm_push_word, masm_store_felts},
    precompiles::helpers::assert_precompile_witness_round_trips,
};

#[test]
fn ed25519_verify_word_binds_message_and_public_key_commitment() {
    let key = SigningKey::read_from_bytes(&[42; 32]).unwrap();
    let message = Word::new([1, 2, 3, 4].map(Felt::from_u32));
    let pk: [u8; 32] = key.public_key().to_bytes().try_into().unwrap();
    let sig: [u8; 64] = key.sign(message).to_bytes().try_into().unwrap();
    let commitment = key.public_key().to_commitment();
    let encoded = eddsa_25519_sha512::encode_signature(&key.public_key(), &key.sign(message));
    assert_eq!(encoded, bytes_to_packed_u32_elements(&[&pk[..], &sig[..]].concat()));
    assert_eq!(eddsa_25519_sha512::sign(&key, message), encoded);
    assert_eq!(eddsa_25519_sha512::public_key_commitment(&key.public_key()), commitment);
    let output = run_word(message, commitment, &pk, &sig).expect("valid Ed25519 Word signature");
    assert_precompile_witness_round_trips(&output);

    let wrong_message = Word::new([1, 2, 3, 5].map(Felt::from_u32));
    assert!(run_word(wrong_message, commitment, &pk, &sig).is_err());
    assert!(run_word(message, Word::default(), &pk, &sig).is_err());
}

#[test]
fn ed25519_verify_bytes_accepts_rfc8032_empty_message() {
    let pk = hex_bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let sig = hex_bytes(concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ));
    let output = run_bytes(&[], &pk, &sig).expect("RFC 8032 empty-message signature");
    assert_precompile_witness_round_trips(&output);
    assert!(run_bytes(&[0], &pk, &sig).is_err());
}

#[test]
fn ed25519_rejects_noncanonical_signature_scalar_even_when_equation_is_unchanged() {
    let key = SigningKey::read_from_bytes(&[42; 32]).unwrap();
    let message = Word::new([1, 2, 3, 4].map(Felt::from_u32));
    let pk: [u8; 32] = key.public_key().to_bytes().try_into().unwrap();
    let mut sig: [u8; 64] = key.sign(message).to_bytes().try_into().unwrap();
    let order: [u8; 32] =
        hex_bytes("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    let mut carry = 0u16;
    for (byte, order_byte) in sig[32..].iter_mut().zip(order) {
        let sum = u16::from(*byte) + u16::from(order_byte) + carry;
        *byte = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    // [s+l]B = [s]B: this catches a missing s<l check, not just a broken signature equation.
    assert!(run_word(message, key.public_key().to_commitment(), &pk, &sig).is_err());
}

#[test]
fn ed25519_rejects_all_small_order_keys_despite_satisfiable_equations() {
    for point in EIGHT_TORSION {
        let pk = point.compress().to_bytes();
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&ED25519_BASEPOINT_POINT.compress().to_bytes());
        sig[32] = 1;
        let message = (0u32..256)
            .map(u32::to_le_bytes)
            .find(|message| (challenge(&pk, &sig, message) * point).is_identity())
            .expect("a challenge annihilating the small-order public key");
        // R=B and s=1 make [s]B = R+[k]A when [k]A=0. Only input validation rejects this.
        assert!(run_bytes(&message, &pk, &sig).is_err());
    }
}

#[test]
fn ed25519_rejects_all_small_order_signature_points_despite_satisfiable_equations() {
    let a = ED25519_BASEPOINT_POINT + EIGHT_TORSION[1];
    let pk = a.compress().to_bytes();
    for r in EIGHT_TORSION {
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r.compress().to_bytes());
        let message = (0u32..256)
            .map(u32::to_le_bytes)
            .find(|message| {
                let k = challenge(&pk, &sig, message);
                k * ED25519_BASEPOINT_POINT == r + k * a
            })
            .expect("a challenge cancelling the signature's torsion point");
        let scalar = challenge(&pk, &sig, &message);
        sig[32..].copy_from_slice(&scalar.to_bytes());
        // s=k, A=B+T, and R=-[k]T satisfy the exact equation; R must still be rejected.
        assert!(run_bytes(&message, &pk, &sig).is_err());
    }
}

#[test]
fn ed25519_rejects_advice_that_negates_both_encoded_points() {
    let key = SigningKey::read_from_bytes(&[42; 32]).unwrap();
    let message = Word::new([1, 2, 3, 4].map(Felt::from_u32));
    let pk: [u8; 32] = key.public_key().to_bytes().try_into().unwrap();
    let mut sig: [u8; 64] = key.sign(message).to_bytes().try_into().unwrap();
    let scalar = Scalar::from_canonical_bytes(sig[32..].try_into().unwrap()).unwrap();
    sig[32..].copy_from_slice(&(-scalar).to_bytes());
    let source = format!(
        "begin {} {} exec.::miden::core::crypto::dsa::eddsa_25519_sha512::verify end",
        masm_push_word(&message),
        masm_push_word(&key.public_key().to_commitment()),
    );
    let handler: Arc<dyn EventHandler> =
        Arc::new(|process: &miden_processor::ProcessorState<'_>| {
            let mut mutations = handle_ed25519_decompress(process)?;
            let AdviceMutation::ExtendStack { stack } = mutations.pop().unwrap() else {
                panic!("coordinate witness must be advice-stack data")
            };
            let mut limbs: [Felt; 8] = stack.into_elements().try_into().unwrap();
            // Restore operand-stack limb order from the scalar advice-pop order.
            limbs.reverse();
            let opposite_x = Ed25519Base::sub([0; 8], limbs.map(|v| v.as_canonical_u64() as u32));
            Ok(vec![decompression_advice(opposite_x)])
        });
    // [-s]B = (-R)+[k](-A). Both advised points are valid curve points, but their signs disagree
    // with the committed encodings. Removing the parity check would accept this witness.
    let err = run_program_with_handler(&source, &pk, &sig, Some(handler)).unwrap_err();
    assert!(
        matches!(
            &err,
            ExecutionError::OperationError {
                err: OperationError::FailedAssertion { err_code, .. }, ..
            } if *err_code == miden_core::mast::error_code_from_msg(
                "invalid compressed point parity"
            )
        ),
        "{err}",
    );
}

#[test]
fn ed25519_rejects_noncanonical_x_witness_even_when_parity_matches() {
    let message = Word::new([1, 2, 3, 4].map(Felt::from_u32));
    let scalar_a = Scalar::from(5u64);
    let point_a = scalar_a * ED25519_BASEPOINT_POINT;
    let canonical_pk = point_a.compress().to_bytes();
    let canonical_x = ed25519_decompress_x(canonical_pk).unwrap();
    let scalar_r = Scalar::from(7u64);
    let r = scalar_r * ED25519_BASEPOINT_POINT;
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r.compress().to_bytes());

    // Flip the encoded sign bit but keep the positive canonical x in the witness. Adding the
    // odd modulus preserves that flipped parity, so this reaches the base-field canonicality
    // check. The signature is otherwise valid for the challenged positive point: s = r + k*a.
    let mut pk = canonical_pk;
    pk[31] ^= 0x80;
    let message_bytes: [u8; 32] = message.into();
    let challenge = challenge(&pk, &sig, &message_bytes);
    sig[32..].copy_from_slice(&(scalar_r + challenge * scalar_a).to_bytes());
    let commitment = Eidos::hash_elements(&bytes_to_packed_u32_elements(&pk));
    let source = format!(
        "begin {} {} exec.::miden::core::crypto::dsa::eddsa_25519_sha512::verify end",
        masm_push_word(&message),
        masm_push_word(&commitment),
    );
    let noncanonical = add_ed25519_base_modulus(canonical_x);
    assert_eq!(noncanonical[0] & 1, u32::from(pk[31] >> 7));
    let decompressions = Arc::new(AtomicUsize::new(0));
    let handler_decompressions = Arc::clone(&decompressions);
    let handler: Arc<dyn EventHandler> =
        Arc::new(move |process: &miden_processor::ProcessorState<'_>| {
            if handler_decompressions.fetch_add(1, Ordering::Relaxed) == 0 {
                Ok(vec![decompression_advice(noncanonical)])
            } else {
                // Keep the R witness canonical if execution reaches the second point. The
                // failure should therefore come from A's noncanonical x witness alone.
                handle_ed25519_decompress(process)
            }
        });
    assert!(run_program_with_handler(&source, &pk, &sig, Some(handler)).is_err());
    assert_eq!(decompressions.load(Ordering::Relaxed), 1);
}

#[test]
fn ed25519_rejects_noncanonical_y_encoding() {
    let key = SigningKey::read_from_bytes(&[42; 32]).unwrap();
    let message = Word::new([1, 2, 3, 4].map(Felt::from_u32));
    let sig: [u8; 64] = key.sign(message).to_bytes().try_into().unwrap();
    // y = p + 3 has the same field value as the valid, non-small-order y = 3 point. Supplying
    // that point's canonical x witness isolates the y canonicality check from x decoding or
    // small-order rejection; the later R witness is canonical if execution reaches it.
    let canonical_y = {
        let mut y = [0u8; 32];
        y[0] = 3;
        y
    };
    let canonical_x = ed25519_decompress_x(canonical_y).unwrap();
    let mut pk = [0u8; 32];
    let modulus_bytes: [u8; 32] =
        core::array::from_fn(|index| Ed25519Base::MODULUS[index / 4].to_le_bytes()[index % 4]);
    let mut carry = 3u16;
    for (byte, modulus_byte) in pk.iter_mut().zip(modulus_bytes) {
        let sum = u16::from(modulus_byte) + carry;
        *byte = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    let commitment = Eidos::hash_elements(&bytes_to_packed_u32_elements(&pk));
    let source = format!(
        "begin {} {} exec.::miden::core::crypto::dsa::eddsa_25519_sha512::verify end",
        masm_push_word(&message),
        masm_push_word(&commitment),
    );
    let decompressions = Arc::new(AtomicUsize::new(0));
    let handler_decompressions = Arc::clone(&decompressions);
    let handler: Arc<dyn EventHandler> =
        Arc::new(move |process: &miden_processor::ProcessorState<'_>| {
            if handler_decompressions.fetch_add(1, Ordering::Relaxed) == 0 {
                Ok(vec![decompression_advice(canonical_x)])
            } else {
                handle_ed25519_decompress(process)
            }
        });
    assert!(run_program_with_handler(&source, &pk, &sig, Some(handler)).is_err());
    assert_eq!(decompressions.load(Ordering::Relaxed), 1);
}

#[test]
fn ed25519_rejects_buffers_that_alias_verifier_local_frames() {
    let key = SigningKey::read_from_bytes(&[42; 32]).unwrap();
    let message = Word::new([1, 2, 3, 4].map(Felt::from_u32));
    let message_bytes: [u8; 32] = message.into();
    let pk = key.public_key().to_bytes().try_into().unwrap();
    let sig = key.sign(message).to_bytes().try_into().unwrap();
    let frame = miden_core::FMP_INIT_VALUE.as_canonical_u64() as u32;

    for (message_ptr, scratch_ptr) in [
        (frame, 1024),
        (frame - 4, 1024),
        (128, frame),
        (128, frame - 16),
        (128, frame + 48),
    ] {
        // Both saved arguments and nested decompression witnesses must remain isolated from the
        // message/scratch buffers. Require the deliberate entry check, not an incidental later
        // trap.
        let err = run_bytes_at(&message_bytes, &pk, &sig, message_ptr, scratch_ptr).unwrap_err();
        assert!(
            matches!(
                &err,
                ExecutionError::OperationError {
                    err: OperationError::FailedAssertion { err_code, .. }, ..
                } if *err_code == miden_core::mast::error_code_from_msg(
                    "Ed25519 buffers must precede verifier locals"
                )
            ),
            "message={message_ptr}, scratch={scratch_ptr}: {err}",
        );
    }
}

fn challenge(pk: &[u8; 32], sig: &[u8; 64], message: &[u8]) -> Scalar {
    let preimage = [&sig[..32], &pk[..], message].concat();
    Scalar::from_bytes_mod_order_wide(Sha512::hash(&preimage).as_bytes())
}

fn run_word(
    message: Word,
    commitment: Word,
    pk: &[u8; 32],
    sig: &[u8; 64],
) -> Result<ExecutionOutput, ExecutionError> {
    let source = format!(
        "begin {} {} exec.::miden::core::crypto::dsa::eddsa_25519_sha512::verify end",
        masm_push_word(&message),
        masm_push_word(&commitment),
    );
    run_program(&source, pk, sig)
}

fn run_bytes(
    message: &[u8],
    pk: &[u8; 32],
    sig: &[u8; 64],
) -> Result<ExecutionOutput, ExecutionError> {
    run_bytes_at(message, pk, sig, 128, 1024)
}

fn run_bytes_at(
    message: &[u8],
    pk: &[u8; 32],
    sig: &[u8; 64],
    message_ptr: u32,
    scratch_ptr: u32,
) -> Result<ExecutionOutput, ExecutionError> {
    let commitment = Eidos::hash_elements(&bytes_to_packed_u32_elements(pk));
    let stores = masm_store_felts(&bytes_to_packed_u32_elements(message), message_ptr);
    let source = format!(
        "begin {stores} push.{scratch_ptr} push.{} push.{message_ptr} {} \
         exec.::miden::core::crypto::dsa::eddsa_25519_sha512::verify_bytes end",
        message.len(),
        masm_push_word(&commitment),
    );
    run_program(&source, pk, sig)
}

fn run_program(
    source: &str,
    pk: &[u8; 32],
    sig: &[u8; 64],
) -> Result<ExecutionOutput, ExecutionError> {
    run_program_with_handler(source, pk, sig, None)
}

fn run_program_with_handler(
    source: &str,
    pk: &[u8; 32],
    sig: &[u8; 64],
    handler: Option<Arc<dyn EventHandler>>,
) -> Result<ExecutionOutput, ExecutionError> {
    let library = CoreLibrary::default();
    let program = Assembler::default()
        .with_package(library.package(), Linkage::Dynamic)
        .unwrap()
        .assemble_program("ed25519_test", source)
        .expect("Ed25519 verification interface must assemble")
        .unwrap_program();
    let mut host = DefaultHost::default().with_library(&library).unwrap();
    if let Some(handler) = handler {
        assert!(host.replace_handler(ED25519_DECOMPRESS_EVENT_NAME, handler));
    }
    let mut advice = AdviceStack::new();
    advice.append_elements(bytes_to_packed_u32_elements(pk));
    advice.append_elements(bytes_to_packed_u32_elements(sig));
    let output = FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default().with_stack(advice),
        ExecutionOptions::default(),
    )
    .unwrap()
    .execute_sync(&program, &mut host);
    if let Ok(output) = &output {
        assert!(output.advice.stack().is_empty(), "signature witness must be consumed");
    }
    output
}

/// Encodes a coordinate witness for the decompression loader's eight scalar advice pushes.
fn decompression_advice(x: [u32; 8]) -> AdviceMutation {
    let mut advice = AdviceStack::new();
    advice.append_for_adv_push(&x.map(Felt::from_u32));
    AdviceMutation::extend_advice_stack(advice)
}

fn hex_bytes<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), 2 * N);
    core::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
}

fn add_ed25519_base_modulus(value: [u32; 8]) -> [u32; 8] {
    let mut carry = 0u64;
    core::array::from_fn(|index| {
        let sum = u64::from(value[index]) + u64::from(Ed25519Base::MODULUS[index]) + carry;
        carry = sum >> 32;
        sum as u32
    })
}
