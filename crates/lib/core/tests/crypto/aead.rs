use miden_air::Felt;
use miden_crypto::aead::aead_rpo::{Nonce, SecretKey};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn test_encrypt_zero_blocks_roundtrip() {
    // Verifies that aead::encrypt handles num_blocks = 0 by encrypting only the padding block
    // and producing a tag, and that aead::decrypt accepts it and succeeds.
    let source = r#"
    use miden::core::crypto::aead

    begin
        # No plaintext needed; num_blocks = 0
        push.0              # num_blocks
        push.2000           # dst_ptr
        push.1000           # src_ptr
        push.[1,2,3,4]        # nonce
        push.[5,6,7,8]        # key

        # Encrypt: writes encrypted padding at dst_ptr, returns tag(4) on stack
        exec.aead::encrypt

        # Store tag to memory at dst_ptr + 8 (immediately after encrypted padding)
        push.2008 mem_storew_le dropw

        # Decrypt back with num_blocks=0; should succeed (empty plaintext)
        push.0              # num_blocks
        push.3000           # dst_ptr (plaintext output)
        push.2000           # src_ptr (ciphertext location)
        push.[1,2,3,4]        # nonce
        push.[5,6,7,8]        # key
        exec.aead::decrypt
    end
    "#;

    let test = build_test!(source, &[]);
    test.execute().expect("AEAD zero-block roundtrip failed");
}

#[test]
fn test_encrypt_with_known_values() {
    let seed = [2_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let key = SecretKey::with_rng(&mut rng);
    let nonce = Nonce::with_rng(&mut rng);

    let plaintext = vec![
        Felt::new(10),
        Felt::new(11),
        Felt::new(12),
        Felt::new(13),
        Felt::new(14),
        Felt::new(15),
        Felt::new(16),
        Felt::new(17),
    ];

    let encrypted = key
        .encrypt_elements_with_nonce(&plaintext, &[], nonce)
        .expect("Encryption failed");

    // Extract values from the reference implementation
    let expected_tag = encrypted.auth_tag().to_elements();
    let key_elements = key.to_elements();
    let nonce_elements: [Felt; 4] = encrypted.nonce().clone().into();
    let ciphertext = encrypted.ciphertext();

    // Build MASM test dynamically with extracted values
    let source = format!(
        "
    use miden::core::crypto::aead

    begin
        # Store plaintext [10,11,12,13,14,15,16,17] at address 1000
        push.[10,11,12,13] push.1000 mem_storew_le dropw
        push.[14,15,16,17] push.1004 mem_storew_le dropw

        # Encrypt 1 block with key and nonce from reference
        push.1           # num_blocks = 1
        push.2000        # dst_ptr
        push.1000        # src_ptr
        push.{nonce_elements:?}     # nonce
  
        push.{key_elements:?}     # key

        exec.aead::encrypt

        # Result: [tag(4), ...]
        # Verify tag
        push.{expected_tag:?}
        eqw assert
        dropw dropw

        # Verify all 4 ciphertext words
        push.2000 mem_loadw_le
        push.{ciphertext_0:?}
        eqw assert dropw dropw


        push.2004 mem_loadw_le
        push.{ciphertext_1:?}
        eqw assert dropw dropw

        push.2008 mem_loadw_le
        push.{ciphertext_2:?}
        eqw assert dropw dropw

        push.2012 mem_loadw_le
        push.{ciphertext_3:?}
        eqw assert dropw dropw
    end
    ",
        ciphertext_0 = &ciphertext[0..4],
        ciphertext_1 = &ciphertext[4..8],
        ciphertext_2 = &ciphertext[8..12],
        ciphertext_3 = &ciphertext[12..16],
    );

    let test = build_test!(source.as_str(), &[]);
    test.execute().expect("Execution failed");
}

#[test]
fn test_decrypt_with_known_values() {
    let seed = [3_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let key = SecretKey::with_rng(&mut rng);
    let nonce = Nonce::with_rng(&mut rng);

    let plaintext = vec![
        Felt::new(10),
        Felt::new(11),
        Felt::new(12),
        Felt::new(13),
        Felt::new(14),
        Felt::new(15),
        Felt::new(16),
        Felt::new(17),
    ];

    // Encrypt to get ciphertext and tag
    let encrypted = key
        .encrypt_elements_with_nonce(&plaintext, &[], nonce)
        .expect("Encryption failed");

    let expected_tag = encrypted.auth_tag().to_elements();
    let key_elements = key.to_elements();
    let nonce_elements: [Felt; 4] = encrypted.nonce().clone().into();
    let ciphertext = encrypted.ciphertext();

    // Build MASM test for decryption
    let source = format!(
        "
    use miden::core::crypto::aead

    begin
        # Store ciphertext at address 1000 (data + padding + tag)
        # Note: push.[...] puts first element on top (LE), mem_storew_le stores top to lowest addr
        push.{ciphertext_0:?} push.1000 mem_storew_le dropw
        push.{ciphertext_1:?} push.1004 mem_storew_le dropw
        push.{ciphertext_2:?} push.1008 mem_storew_le dropw
        push.{ciphertext_3:?} push.1012 mem_storew_le dropw

        # Store the tag at address 1016
        push.{expected_tag:?} push.1016 mem_storew_le dropw

        # Decrypt: [key(4), nonce(4), src_ptr, dst_ptr, num_blocks]
        push.1           # num_blocks = 1 (data blocks only, padding is automatic)
        push.2000        # dst_ptr (where plaintext will be written)
        push.1000        # src_ptr (ciphertext location)
        push.{nonce_elements:?}     # nonce (push.[...] is already LE)
        push.{key_elements:?}       # key

        exec.aead::decrypt
        # => [tag(4), ...]

        # Verify decrypted plaintext matches original
        padw push.2000 mem_loadw_le
        push.[10,11,12,13] eqw assert dropw dropw

        padw push.2004 mem_loadw_le
        push.[14,15,16,17] eqw assert dropw dropw

        # Verify padding block [1,0,0,0,0,0,0,0]
        padw push.2008 mem_loadw_le
        push.[1,0,0,0] eqw assert dropw dropw

        padw push.2012 mem_loadw_le
        padw eqw assert dropw dropw
    end
    ",
        ciphertext_0 = &ciphertext[0..4],
        ciphertext_1 = &ciphertext[4..8],
        ciphertext_2 = &ciphertext[8..12],
        ciphertext_3 = &ciphertext[12..16],
    );

    let test = build_test!(source.as_str(), &[]);
    test.execute().expect("Decryption test failed");
}

#[test]
fn test_decrypt_with_wrong_key() {
    let seed = [4_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let key = SecretKey::with_rng(&mut rng);
    let wrong_key = SecretKey::with_rng(&mut rng); // Different key
    let nonce = Nonce::with_rng(&mut rng);

    let plaintext = vec![
        Felt::new(10),
        Felt::new(11),
        Felt::new(12),
        Felt::new(13),
        Felt::new(14),
        Felt::new(15),
        Felt::new(16),
        Felt::new(17),
    ];

    // Encrypt with correct key
    let encrypted = key
        .encrypt_elements_with_nonce(&plaintext, &[], nonce)
        .expect("Encryption failed");

    let expected_tag = encrypted.auth_tag().to_elements();
    let wrong_key_elements = wrong_key.to_elements(); // Use wrong key
    let nonce_elements: [Felt; 4] = encrypted.nonce().clone().into();
    let ciphertext = encrypted.ciphertext();

    // Build MASM test that uses wrong key for decryption
    let source = format!(
        "
    use miden::core::crypto::aead

    begin
        # Store ciphertext at address 1000
        push.{ciphertext_0:?} reversew push.1000 mem_storew_le dropw
        push.{ciphertext_1:?} reversew push.1004 mem_storew_le dropw
        push.{ciphertext_2:?} reversew push.1008 mem_storew_le dropw
        push.{ciphertext_3:?} reversew push.1012 mem_storew_le dropw

        # Store the tag
        push.{expected_tag:?} push.1016 mem_storew_le dropw

        # Decrypt with WRONG KEY - should fail assertion
        push.2           # num_blocks = 2
        push.2000        # dst_ptr (where plaintext will be written)
        push.1000        # src_ptr (ciphertext location)
        push.{nonce_elements:?} reversew    # nonce
        push.{wrong_key_elements:?} reversew    # WRONG KEY!

        exec.aead::decrypt
        # Should fail with assertion error before reaching here
    end
    ",
        ciphertext_0 = &ciphertext[0..4],
        ciphertext_1 = &ciphertext[4..8],
        ciphertext_2 = &ciphertext[8..12],
        ciphertext_3 = &ciphertext[12..16],
    );

    let test = build_test!(source.as_str(), &[]);
    // Should fail with assertion error
    assert!(test.execute().is_err(), "Wrong key should cause assertion failure");
}
