#[cfg(test)]
mod tests {
    use ed25519_dalek::Verifier;
    use k256::{elliptic_curve::sec1::ToSec1Point, pkcs8::DecodePublicKey};
    use miden_crypto::{
        Word,
        dsa::{ecdsa_k256_keccak, eddsa_25519_sha512},
        ecdh::{k256 as miden_k256, x25519 as miden_x25519},
        ies::{IesError, IesScheme, SealedMessage, UnsealingKey},
        utils::{Deserializable, Serializable},
    };
    use wycheproof_ng_core::TestResult;

    #[test]
    fn secp256k1_ecdh_vectors() {
        let test_set =
            wycheproof_ng_dh::ecdh::TestSet::load(wycheproof_ng_dh::ecdh::TestName::EcdhSecp256k1)
                .expect("secp256k1 ECDH Wycheproof vectors should load");

        for group in test_set.test_groups {
            for test in group.tests {
                let id = test.tc_id;
                let Some(private_key) = test
                    .private_key
                    .as_str()
                    .and_then(|value| hex::decode(value).ok())
                    .and_then(secp256k1_scalar)
                else {
                    assert!(!is_valid(test.result), "tcId {id}: invalid private key");
                    continue;
                };
                let Some(public_key_bytes) =
                    test.public_key.as_str().and_then(|value| hex::decode(value).ok())
                else {
                    assert!(!is_valid(test.result), "tcId {id}: invalid public key encoding");
                    continue;
                };

                let public_key = match k256::PublicKey::from_public_key_der(&public_key_bytes)
                    .or_else(|_| k256::PublicKey::from_sec1_bytes(&public_key_bytes))
                {
                    Ok(public_key) => public_key,
                    Err(_) => {
                        assert!(!is_valid(test.result), "tcId {id}: invalid public key");
                        continue;
                    },
                };
                let encoded_public_key = public_key.to_sec1_point(true);
                let ephemeral_pk = match miden_k256::EphemeralPublicKey::read_from_bytes(
                    encoded_public_key.as_bytes(),
                ) {
                    Ok(ephemeral_pk) => ephemeral_pk,
                    Err(_) => {
                        assert!(!is_valid(test.result), "tcId {id}: invalid public key");
                        continue;
                    },
                };
                let static_sk =
                    match ecdsa_k256_keccak::KeyExchangeKey::read_from_bytes(&private_key) {
                        Ok(static_sk) => static_sk,
                        Err(_) => {
                            assert!(!is_valid(test.result), "tcId {id}: invalid private key");
                            continue;
                        },
                    };
                let shared_secret = static_sk.get_shared_secret(ephemeral_pk);

                if is_invalid(test.result) {
                    assert_ne!(
                        shared_secret.as_ref(),
                        test.shared_secret.as_ref(),
                        "tcId {id}: invalid vector produced expected shared secret"
                    );
                } else {
                    assert_eq!(
                        shared_secret.as_ref(),
                        test.shared_secret.as_ref(),
                        "tcId {id}: shared secret for {:?}",
                        group.encoding
                    );
                }
            }
        }
    }

    #[test]
    fn x25519_vectors_and_miden_rejection_path() {
        let test_set =
            wycheproof_ng_dh::xdh::TestSet::load(wycheproof_ng_dh::xdh::TestName::X25519)
                .expect("X25519 Wycheproof vectors should load");

        for group in test_set.test_groups {
            for test in group.tests {
                let id = test.tc_id;
                let Some(private_key) = test
                    .private_key
                    .as_str()
                    .and_then(|value| hex::decode(value).ok())
                    .and_then(|bytes| fixed_array::<32>(&bytes))
                else {
                    assert!(!is_valid(test.result), "tcId {id}: invalid private key");
                    continue;
                };
                let Some(public_key) = test
                    .public_key
                    .as_str()
                    .and_then(|value| hex::decode(value).ok())
                    .and_then(|bytes| fixed_array::<32>(&bytes))
                else {
                    assert!(!is_valid(test.result), "tcId {id}: invalid public key");
                    continue;
                };

                if is_invalid(test.result) {
                    assert_x25519_invalid_vector_rejected(id, &public_key);
                    continue;
                }

                // Miden converts an Ed25519 exchange key into X25519 internally, so Wycheproof's
                // raw X25519 private scalars do not map to its public key type. The valid vectors
                // still pin the X25519 primitive used underneath the wrapper.
                let shared_secret = x25519_dalek::StaticSecret::from(private_key)
                    .diffie_hellman(&x25519_dalek::PublicKey::from(public_key));
                assert_eq!(
                    shared_secret.as_bytes(),
                    test.shared_secret.as_ref(),
                    "tcId {id}: shared secret"
                );
            }
        }
    }

    #[test]
    fn ed25519_vectors_and_word_sized_wrapper_contract() {
        let test_set = wycheproof_ng_eddsa::TestSet::load(wycheproof_ng_eddsa::TestName::Ed25519)
            .expect("Ed25519 Wycheproof vectors should load");

        for group in test_set.test_groups {
            let Some(public_key_bytes) = fixed_array::<32>(group.key.pk.as_ref()) else {
                panic!("Wycheproof Ed25519 public key should be 32 bytes");
            };
            let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes) {
                Ok(verifying_key) => verifying_key,
                Err(_) => {
                    for test in group.tests {
                        assert!(!is_valid(test.result), "tcId {}: invalid public key", test.tc_id);
                    }
                    continue;
                },
            };
            let public_key = eddsa_25519_sha512::PublicKey::read_from_bytes(&public_key_bytes)
                .expect("valid Ed25519 public key should parse");

            for test in group.tests {
                let id = test.tc_id;
                let Some(signature_bytes) = fixed_array::<64>(test.sig.as_ref()) else {
                    assert!(!is_valid(test.result), "tcId {id}: invalid signature length");
                    continue;
                };
                let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
                let verified = verifying_key.verify(test.msg.as_ref(), &signature).is_ok();

                if is_invalid(test.result) {
                    assert!(!verified, "tcId {id}: invalid signature verified");
                } else if is_valid(test.result) {
                    assert!(verified, "tcId {id}: valid signature did not verify");
                }

                // Miden's Ed25519 wrapper verifies a Word, so arbitrary Wycheproof messages can
                // only reach the dependency primitive above. For 32-byte messages, also check the
                // exact wrapper path.
                if let Some(message) = fixed_array::<32>(test.msg.as_ref()) {
                    let Ok(message) = Word::try_from(message) else {
                        continue;
                    };
                    let signature = eddsa_25519_sha512::Signature::from_der(&signature_bytes)
                        .expect("raw Ed25519 signature should parse");
                    let wrapper_verified = public_key.verify(message, &signature);
                    assert_eq!(wrapper_verified, verified, "tcId {id}: wrapper verification");
                }
            }
        }
    }

    fn assert_x25519_invalid_vector_rejected(id: usize, public_key: &[u8; 32]) {
        let mut encoded_key = Vec::new();
        encoded_key.push(IesScheme::X25519XChaCha20Poly1305 as u8);
        public_key.to_vec().write_into(&mut encoded_key);
        Vec::<u8>::new().write_into(&mut encoded_key);

        let Ok(sealed_message) = SealedMessage::read_from_bytes(&encoded_key) else {
            return;
        };

        let static_sk = eddsa_25519_sha512::KeyExchangeKey::read_from_bytes(&[id as u8; 32])
            .expect("fixed-size Ed25519 exchange key should parse");
        let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(static_sk);
        let local_ephemeral_pk = miden_x25519::EphemeralPublicKey::read_from_bytes(public_key);
        let has_zero_shared_secret = x25519_dalek_reaches_zero_shared_secret(public_key);
        let unseal_result = unsealing_key.unseal_bytes(sealed_message);

        if local_ephemeral_pk.is_ok() && has_zero_shared_secret {
            assert!(
                matches!(unseal_result, Err(IesError::KeyAgreementFailed)),
                "tcId {id}: low-order public key reached decryption"
            );
        } else {
            assert!(
                matches!(
                    unseal_result,
                    Err(IesError::KeyAgreementFailed | IesError::DecryptionFailed)
                ),
                "tcId {id}: invalid public key was accepted"
            );
        }

        assert!(
            local_ephemeral_pk.is_err() || has_zero_shared_secret,
            "tcId {id}: invalid public key parsed without low-order rejection"
        );
    }

    fn x25519_dalek_reaches_zero_shared_secret(public_key: &[u8; 32]) -> bool {
        let shared_secret = x25519_dalek::StaticSecret::from([1u8; 32])
            .diffie_hellman(&x25519_dalek::PublicKey::from(*public_key));
        shared_secret.as_bytes().iter().all(|byte| *byte == 0)
    }

    fn secp256k1_scalar(mut bytes: Vec<u8>) -> Option<[u8; 32]> {
        while bytes.len() > 32 && bytes.first().copied() == Some(0) {
            bytes.remove(0);
        }
        if bytes.len() > 32 {
            return None;
        }
        let mut scalar = [0u8; 32];
        scalar[32 - bytes.len()..].copy_from_slice(&bytes);
        Some(scalar)
    }

    fn fixed_array<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
        bytes.try_into().ok()
    }

    fn is_valid(result: TestResult) -> bool {
        matches!(result, TestResult::Valid)
    }

    fn is_invalid(result: TestResult) -> bool {
        matches!(result, TestResult::Invalid)
    }
}
