use miden_air::Felt;
use miden_crypto::aead::aead_rpo::{Nonce, SecretKey};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn test_encrypt_with_known_values() {
    let seed = [2_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let key = SecretKey::with_rng(&mut rng);
    let nonce = Nonce::with_rng(&mut rng);

    let plaintext = vec![
        Felt::new(10), Felt::new(11), Felt::new(12), Felt::new(13),
        Felt::new(14), Felt::new(15), Felt::new(16), Felt::new(17),
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
    let source = format!("
    use.std::crypto::aead

    begin
        # Store plaintext [10,11,12,13,14,15,16,17] + padding [1,0,0,0,0,0,0,0] at address 1000
        push.10.11.12.13 push.1000 mem_storew_be dropw
        push.14.15.16.17 push.1004 mem_storew_be dropw
        push.1.0.0.0     push.1008 mem_storew_be dropw
        push.0.0.0.0     push.1012 mem_storew_be dropw

        # Encrypt 2 blocks (plaintext + padding) with key and nonce from reference
        push.2           # num_blocks = 2
        push.2000        # dst_ptr
        push.1000        # src_ptr
        push.{}.{}.{}.{}     # key
        push.{}.{}.{}.{}     # nonce

        exec.aead::encrypt

        # Result: [tag(4), ...]
        # Verify tag
        push.{}.{}.{}.{}
        eqw assert
        dropw dropw

        # Verify all 4 ciphertext words
        push.2000 mem_loadw_be
        push.{}.{}.{}.{} eqw assert dropw dropw

        push.2004 mem_loadw_be
        push.{}.{}.{}.{} eqw assert dropw dropw

        push.2008 mem_loadw_be
        push.{}.{}.{}.{} eqw assert dropw dropw

        push.2012 mem_loadw_be
        push.{}.{}.{}.{} eqw assert dropw dropw
    end
    ",
        key_elements[0].as_int(), key_elements[1].as_int(),
        key_elements[2].as_int(), key_elements[3].as_int(),
        nonce_elements[0].as_int(), nonce_elements[1].as_int(),
        nonce_elements[2].as_int(), nonce_elements[3].as_int(),
        expected_tag[0].as_int(), expected_tag[1].as_int(),
        expected_tag[2].as_int(), expected_tag[3].as_int(),
        // Ciphertext word 0 - push in original order
        ciphertext[0].as_int(), ciphertext[1].as_int(),
        ciphertext[2].as_int(), ciphertext[3].as_int(),
        // Ciphertext word 1
        ciphertext[4].as_int(), ciphertext[5].as_int(),
        ciphertext[6].as_int(), ciphertext[7].as_int(),
        // Ciphertext word 2
        ciphertext[8].as_int(), ciphertext[9].as_int(),
        ciphertext[10].as_int(), ciphertext[11].as_int(),
        // Ciphertext word 3
        ciphertext[12].as_int(), ciphertext[13].as_int(),
        ciphertext[14].as_int(), ciphertext[15].as_int(),
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
        Felt::new(10), Felt::new(11), Felt::new(12), Felt::new(13),
        Felt::new(14), Felt::new(15), Felt::new(16), Felt::new(17),
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
    let source = format!("
    use.std::crypto::aead

    begin
        # Store ciphertext at address 1000
        push.{}.{}.{}.{} push.1000 mem_storew_be dropw
        push.{}.{}.{}.{} push.1004 mem_storew_be dropw
        push.{}.{}.{}.{} push.1008 mem_storew_be dropw
        push.{}.{}.{}.{} push.1012 mem_storew_be dropw

        # Store the tag
        push.{}.{}.{}.{} push.1016 mem_storew_be dropw

        # Decrypt: [nonce(4), key(4), src_ptr, dst_ptr, num_blocks]
        push.2           # num_blocks = 2
        push.2000        # dst_ptr (where plaintext will be written)
        push.1000        # src_ptr (ciphertext location)
        push.{}.{}.{}.{}     # key
        push.{}.{}.{}.{}     # nonce

        exec.aead::decrypt
        # => [tag(4), ...]

        # Verify decrypted plaintext matches original
        padw push.2000 mem_loadw_be
        push.10.11.12.13 eqw assert dropw dropw

        padw push.2004 mem_loadw_be
        push.14.15.16.17 eqw assert dropw dropw

        # Verify padding block [1,0,0,0,0,0,0,0]
        padw push.2008 mem_loadw_be
        push.1.0.0.0 eqw assert dropw dropw

        padw push.2012 mem_loadw_be
        push.0.0.0.0 eqw assert dropw dropw
    end
    ",
        // Ciphertext word 0
        ciphertext[0].as_int(), ciphertext[1].as_int(),
        ciphertext[2].as_int(), ciphertext[3].as_int(),
        // Ciphertext word 1
        ciphertext[4].as_int(), ciphertext[5].as_int(),
        ciphertext[6].as_int(), ciphertext[7].as_int(),
        // Ciphertext word 2
        ciphertext[8].as_int(), ciphertext[9].as_int(),
        ciphertext[10].as_int(), ciphertext[11].as_int(),
        // Ciphertext word 3
        ciphertext[12].as_int(), ciphertext[13].as_int(),
        ciphertext[14].as_int(), ciphertext[15].as_int(),
        // Ciphertext tag 
        expected_tag[0].as_int(), expected_tag[1].as_int(),
        expected_tag[2].as_int(), expected_tag[3].as_int(),
        // Key
        key_elements[0].as_int(), key_elements[1].as_int(),
        key_elements[2].as_int(), key_elements[3].as_int(),
        // Nonce
        nonce_elements[0].as_int(), nonce_elements[1].as_int(),
        nonce_elements[2].as_int(), nonce_elements[3].as_int(),
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
        Felt::new(10), Felt::new(11), Felt::new(12), Felt::new(13),
        Felt::new(14), Felt::new(15), Felt::new(16), Felt::new(17),
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
    let source = format!("
    use.std::crypto::aead

    begin
        # Store ciphertext at address 1000
        push.{}.{}.{}.{} push.1000 mem_storew_be dropw
        push.{}.{}.{}.{} push.1004 mem_storew_be dropw
        push.{}.{}.{}.{} push.1008 mem_storew_be dropw
        push.{}.{}.{}.{} push.1012 mem_storew_be dropw

        # Store the tag
        push.{}.{}.{}.{} push.1016 mem_storew_be dropw

        # Decrypt with WRONG KEY - should fail assertion
        push.2           # num_blocks = 2
        push.2000        # dst_ptr (where plaintext will be written)
        push.1000        # src_ptr (ciphertext location)
        push.{}.{}.{}.{}     # WRONG KEY!
        push.{}.{}.{}.{}     # nonce

        exec.aead::decrypt
        # Should fail with assertion error before reaching here
    end
    ",
        // Ciphertext word 0
        ciphertext[0].as_int(), ciphertext[1].as_int(),
        ciphertext[2].as_int(), ciphertext[3].as_int(),
        // Ciphertext word 1
        ciphertext[4].as_int(), ciphertext[5].as_int(),
        ciphertext[6].as_int(), ciphertext[7].as_int(),
        // Ciphertext word 2
        ciphertext[8].as_int(), ciphertext[9].as_int(),
        ciphertext[10].as_int(), ciphertext[11].as_int(),
        // Ciphertext word 3
        ciphertext[12].as_int(), ciphertext[13].as_int(),
        ciphertext[14].as_int(), ciphertext[15].as_int(),
        // Tag
        expected_tag[0].as_int(), expected_tag[1].as_int(),
        expected_tag[2].as_int(), expected_tag[3].as_int(),
        // WRONG Key
        wrong_key_elements[0].as_int(), wrong_key_elements[1].as_int(),
        wrong_key_elements[2].as_int(), wrong_key_elements[3].as_int(),
        // Nonce
        nonce_elements[0].as_int(), nonce_elements[1].as_int(),
        nonce_elements[2].as_int(), nonce_elements[3].as_int(),
    );

    let test = build_test!(source.as_str(), &[]);
    // Should fail with assertion error
    assert!(test.execute().is_err(), "Wrong key should cause assertion failure");
}
