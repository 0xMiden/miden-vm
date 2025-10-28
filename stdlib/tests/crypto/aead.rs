use miden_air::Felt;
use miden_crypto::aead::aead_rpo::{Nonce, SecretKey};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn test_encrypt_with_known_values() {

     let seed = [1_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let key = SecretKey::with_rng(&mut rng);
    let nonce = Nonce::with_rng(&mut rng);

    let plaintext = vec![
        Felt::new(10), Felt::new(11), Felt::new(12), Felt::new(13),
        Felt::new(14), Felt::new(15), Felt::new(16), Felt::new(17),
    ];

    let _encrypted = key.encrypt_elements_with_nonce(&plaintext, &[], nonce)
        .expect("Encryption failed");

    println!("encrypted {:?}", _encrypted);
    // TODO: add From<Word> to Nonce and SecretKey

    // Test vectors generated from reference implementation (seed [1; 32])

    let source = "
    use.std::crypto::aead

    begin
        # Store plaintext [10,11,12,13,14,15,16,17] + padding [1,0,0,0,0,0,0,0] at address 1000
        push.10.11.12.13 push.1000 mem_storew_be dropw
        push.14.15.16.17 push.1004 mem_storew_be dropw
        push.1.0.0.0     push.1008 mem_storew_be dropw
        push.0.0.0.0     push.1012 mem_storew_be dropw

        # Encrypt 2 blocks (plaintext + padding) with known key and nonce
        # Build stack bottom-up for: [nonce(4), key(4), src, dst, num_blocks]
        push.2           # num_blocks = 2 (one for plaintext, one for padding)
        push.2000        # dst_ptr
        push.1000        # src_ptr
        push.14156542307456850632.12122666295810984288.13249238539525561139.4050451889537540096     # key
        push.13322508296688745832.13895135492789763118.11360277986885815498.937678706176150946       # nonce

        exec.aead::encrypt

        # Result: [tag(4), ...]
        # Push expected tag and compare
        push.9098967459671825806.12781258358417089247.381767408146379879.2129799113505984489

        # Stack is now: [expected_tag(4), actual_tag(4), ...]
        # Compare the two words
        eqw assert
        dropw dropw
    end
    ";

    let test = build_test!(source, &[]);
    test.execute().expect("Execution failed");
}
