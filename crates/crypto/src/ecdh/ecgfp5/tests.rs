use alloc::{vec, vec::Vec};

use rand::{
    SeedableRng,
    rand_core::{Infallible, TryCryptoRng, TryRng, utils},
};
use rand_chacha::ChaCha20Rng;

use super::{native::field::GFp, *};

const ORDER: [u64; 5] = [
    0xe80fd996948bffe1,
    0xe8885c39d724a09c,
    0x7fffffe6cfb80639,
    0x7ffffff100000016,
    0x7ffffffd80000007,
];

#[test]
fn rejects_noncanonical_and_zero_scalars() {
    assert!(SecretKey::from_bytes(&[0; 40]).is_err());
    assert!(SecretKey::from_bytes(&[255; 40]).is_err());
    let mut order = [0; 40];
    for (chunk, limb) in order.chunks_exact_mut(8).zip(ORDER) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    assert!(SecretKey::from_bytes(&order).is_err());
    order[0] -= 1;
    let key = SecretKey::from_bytes(&order).unwrap();
    assert_eq!(*key.to_bytes(), order);
    let mut minus_generator = [0; 40];
    minus_generator[..8].copy_from_slice(&(Felt::ORDER - 4).to_le_bytes());
    assert_eq!(key.public_key().to_bytes(), minus_generator);
}

#[test]
fn scalar_sampling_retries_zero_and_out_of_range_values() {
    let mut candidates = [[0; 40]; 4];
    for (chunk, limb) in candidates[1].chunks_exact_mut(8).zip(ORDER) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    candidates[2] = candidates[1];
    // n + 1 must be rejected rather than reduced to 1.
    candidates[2][0] += 1;
    candidates[3] = candidates[1];
    candidates[3][0] -= 1;

    let mut rng = ScriptedRng {
        remaining: candidates.as_flattened(),
        draws: 0,
    };
    assert_eq!(*SecretKey::with_rng(&mut rng).to_bytes(), candidates[3]);
    assert_eq!(rng.draws, 4);
}

#[test]
fn scalar_sampling_masks_only_the_high_bit() {
    let mut expected = [0xff; 40];
    expected[39] = 0x7e;
    let mut candidate = expected;
    candidate[39] |= 0x80;

    let mut rng = ScriptedRng { remaining: &candidate, draws: 0 };
    assert_eq!(*SecretKey::with_rng(&mut rng).to_bytes(), expected);
    assert_eq!(rng.draws, 1);
}

#[test]
fn validates_point_encoding_and_serialization() {
    let mut one = [0; 40];
    one[0] = 1;
    let generator = SecretKey::from_bytes(&one).unwrap().public_key();
    assert_eq!(
        generator.to_elements(),
        [Felt::from_u32(4), Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO]
    );
    assert_eq!(PublicKey::read_from_bytes(&generator.to_bytes()).unwrap(), generator);
    assert_eq!(PublicKey::from_elements(generator.to_elements()).unwrap(), generator);
    assert!(PublicKey::from_bytes([0; 40]).is_err());
    assert!(PublicKey::from_bytes([255; 40]).is_err());
    for i in 0..5 {
        let mut bytes = generator.to_bytes();
        bytes[8 * i..8 * i + 8].copy_from_slice(&Felt::ORDER.to_le_bytes());
        assert!(PublicKey::from_bytes(bytes).is_err());
    }
    // This field element has no corresponding point, despite its canonical coefficients.
    let invalid = [
        13557832913345268708,
        15669280705791538619,
        8534654657267986396,
        12533218303838131749,
        5058070698878426028,
    ]
    .map(Felt::new_unchecked);
    assert!(PublicKey::from_elements(invalid).is_err());
}

#[test]
fn agrees_in_both_directions() {
    let mut rng = ChaCha20Rng::from_seed([21; 32]);
    for _ in 0..32 {
        let alice = SecretKey::with_rng(&mut rng);
        let bob = SecretKey::with_rng(&mut rng);
        let ab = alice.diffie_hellman(&bob.public_key());
        let ba = bob.diffie_hellman(&alice.public_key());
        assert_eq!(ab.as_ref(), ba.as_ref());
        assert_eq!(ab.to_elements(), ba.to_elements());
        assert!(PublicKey::from_elements(ab.to_elements()).is_ok());
    }
}

#[test]
fn scalar_encoding_and_agreement_match_native_operations() {
    let mut rng = ChaCha20Rng::from_seed([91; 32]);
    let mut scalars = vec![[0; 40], [255; 40], Scalar::ONE.encode()];
    let mut order = (-Scalar::ONE).encode();
    scalars.push(order); // n - 1
    order[0] += 1;
    scalars.push(order); // n
    order[0] += 1;
    scalars.push(order); // n + 1
    // Place a nonzero digit in each 16-bit window, including the highest one.
    for window in 0..20 {
        let mut bytes = [0; 40];
        bytes[2 * window] = 1;
        scalars.push(bytes);
    }
    scalars.extend((0..256).map(|_| random_bytes(&mut rng)));

    for bytes in scalars {
        let (scalar, canonical) = Scalar::decode(&bytes);
        let key = SecretKey::from_bytes(&bytes);
        assert_eq!(key.is_ok(), canonical != 0 && scalar.iszero() == 0);
        let Ok(key) = key else { continue };
        assert_eq!(*key.to_bytes(), scalar.encode());
        assert_eq!(key.public_key().to_bytes(), Point::mulgen(scalar).encode().encode());

        let recipient = SecretKey::with_rng(&mut rng);
        let (recipient_scalar, _) = Scalar::decode(recipient.to_bytes().as_ref());
        let recipient_point = Point::mulgen(recipient_scalar);
        let public_key = PublicKey::from_bytes(recipient_point.encode().encode()).unwrap();
        assert_eq!(public_key, recipient.public_key());
        assert_eq!(
            key.diffie_hellman(&public_key).as_ref(),
            (recipient_point * scalar).encode().encode()
        );
    }
}

#[test]
fn public_key_validation_matches_native_decoding() {
    let mut rng = ChaCha20Rng::from_seed([92; 32]);
    let mut encodings = vec![[0; 40], [255; 40], Point::GENERATOR.encode().encode()];
    for lane in 0..5 {
        for value in [1, 4, 0xffff_ffff_0000_0000, 0xffff_ffff_0000_0001] {
            let mut bytes = [0; 40];
            bytes[8 * lane..8 * lane + 8].copy_from_slice(&u64::to_le_bytes(value));
            encodings.push(bytes);
        }
    }
    encodings.extend((0..256).map(|_| random_bytes(&mut rng)));
    for bytes in encodings {
        let (encoding, canonical) = GFp5::decode(&bytes);
        let (point, valid) = Point::decode(encoding);
        let key = PublicKey::from_bytes(bytes);
        assert_eq!(key.is_ok(), canonical != 0 && valid != 0 && point.isneutral() == 0);
        if let Ok(key) = key {
            assert_eq!(key.to_bytes(), point.encode().encode());
            assert_eq!(PublicKey::from_elements(key.to_elements()).unwrap(), key);
        }
    }
}

#[test]
fn agreement_matches_reference_vectors() {
    // Generated with the reference implementation at ce059c6d1e1662db437aecbf3db6bb67fe63c716.
    // Each row is (scalar, public key, shared secret) for the recipient below.
    // Scalars: 1, n - 1, 2^304, and two dense bit patterns.
    let decode = |encoded: &str| {
        let mut bytes = [0; 40];
        hex::decode_to_slice(encoded, &mut bytes).unwrap();
        bytes
    };
    let recipient = PublicKey::from_bytes(decode(
        "1546b7c05ef4da10f1f3d9b0d5cf99096ca949452dc08703e56ced3bc20295b41196545498db62b2",
    ))
    .unwrap();
    let vectors = [
        (
            "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "04000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "1546b7c05ef4da10f1f3d9b0d5cf99096ca949452dc08703e56ced3bc20295b41196545498db62b2",
        ),
        (
            "e0ff8b9496d90fe89ca024d7395c88e83906b8cfe6ffff7f16000000f1ffff7f07000080fdffff7f",
            "fdfffffffeffffff0000000000000000000000000000000000000000000000000000000000000000",
            "ecb9483fa00b25ef100c264f293066f69556b6bad13f78fc1c9312c43cfd6a4bf069abab66249d4d",
        ),
        (
            "00000000000000000000000000000000000000000000000000000000000000000000000000000100",
            "87be7ef287ac73ff58a09aaf2a17555dc53da4bfc695edf44d7dda57f63e6d027eb283316cc7be2b",
            "07177eb8b0e57c2512feb0a7a06ad3e328445fe7048b0f6a9c059dc5d21bf69838e3d674fcef4d57",
        ),
        (
            "55555555555555555555555555555555555555555555555555555555555555555555555555555555",
            "b00bf1b6265db093d398552bc8b391425652357c21eba12baa7d74af812c2622811fd93f8d195045",
            "c4efa7e47e2e74dd47bf7587b33f764413e0c6ea6ad989d13f10e82b1ced8245b66e6ace6528fdbf",
        ),
        (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a",
            "4ee70097d95f5e43927b97b2e5bee085ff8f075f4582a7c6dc24642918f576cc3f5576dadda53fa3",
            "32dbfbbcc263e36b8fe089ef4e76cd450072c37d85733fb3d83aafdc86133e1c183380160bf816f6",
        ),
    ];
    for (scalar, public_key, shared_secret) in vectors {
        let scalar = decode(scalar);
        let key = SecretKey::from_bytes(&scalar).unwrap();
        assert_eq!(*key.to_bytes(), scalar);
        assert_eq!(key.public_key().to_bytes(), decode(public_key));
        assert_eq!(key.diffie_hellman(&recipient).as_ref(), decode(shared_secret));
    }
}

#[test]
fn direct_advice_matches_native_outputs() {
    let mut rng = ChaCha20Rng::from_seed([86; 32]);
    for _ in 0..8 {
        let public_key = SecretKey::with_rng(&mut rng).public_key();
        let ephemeral = SecretKey::with_rng(&mut rng);
        let advice = public_key.advise(&ephemeral);
        assert!(!advice.merkle_nodes().is_empty());
        let elements: Vec<_> = advice.elements().collect();
        assert_eq!(&elements[..5], public_key.to_elements());
        let expected: Vec<_> = ephemeral
            .public_key()
            .to_elements()
            .into_iter()
            .chain(ephemeral.diffie_hellman(&public_key).to_elements())
            .collect();
        assert_eq!(&elements[elements.len() - 10..], expected);
    }
}

#[test]
fn generator_maps_to_the_reference_weierstrass_coordinates() {
    let (x, y) = Point::GENERATOR.to_weierstrass();
    // Coordinates from the Python reference implementation, which uses the subgroup model directly.
    assert_eq!(
        x.0.map(GFp::to_u64),
        [
            11712523173042564207,
            14090224426659529053,
            13197813503519687414,
            16280770174934269299,
            15998333998318935536,
        ]
    );
    assert_eq!(
        y.0.map(GFp::to_u64),
        [
            14639054205878357578,
            17426078571020221072,
            2548978194165003307,
            8663895577921260088,
            9793640284382595140,
        ]
    );
}

#[test]
fn prepared_key_matches_independent_reference_roots() {
    // The Python reference hashes the twenty full-table roots as a generic Felt sequence.
    let recipient = SecretKey::from_bytes(&[
        117, 171, 10, 165, 110, 135, 33, 237, 241, 30, 7, 71, 125, 62, 129, 31, 203, 158, 70, 250,
        55, 247, 66, 192, 60, 188, 229, 137, 36, 231, 205, 93, 195, 241, 212, 208, 95, 159, 181,
        67,
    ])
    .unwrap();
    let prepared = PreparedPublicKey::new(recipient.public_key());
    assert_eq!(prepared.public_key(), recipient.public_key());
    assert_eq!(
        Eidos::hash_elements(&prepared.to_elements())
            .into_elements()
            .map(|v| v.as_canonical_u64()),
        [
            2915416104584218818,
            4033057376162662068,
            8636948789060949707,
            8258287324667723123,
        ]
    );
    assert_eq!(
        prepared.to_commitment(),
        Eidos::hash_elements_in_domain(
            &prepared.to_elements(),
            crate::hash::eidos::domains::ECGFP5_PREPROCESSED_PUBLIC_KEY,
        ),
    );
    assert_eq!(prepared.to_commitment(), SequentialCommit::to_commitment(&prepared));
    let mut rng = ChaCha20Rng::from_seed([41; 32]);
    for _ in 0..8 {
        let ephemeral = SecretKey::with_rng(&mut rng);
        let advice = prepared.advise(&ephemeral);
        let elements: Vec<_> = advice.elements().collect();
        let expected: Vec<_> = ephemeral
            .public_key()
            .to_elements()
            .into_iter()
            .chain(ephemeral.diffie_hellman(&recipient.public_key()).to_elements())
            .collect();
        assert_eq!(&elements[elements.len() - 39..elements.len() - 29], expected);
        assert_eq!(&elements[elements.len() - 5..], recipient.public_key().to_elements());
        assert!(!advice.merkle_nodes().is_empty());
    }
}

#[test]
fn public_key_commitment_matches_its_encoding_and_domain() {
    let mut rng = ChaCha20Rng::from_seed([86; 32]);
    let key = SecretKey::with_rng(&mut rng).public_key();
    let elements = key.to_elements();
    let commitment = key.to_commitment();
    assert_eq!(commitment, Eidos::hash_elements_in_domain(&elements, ECGFP5_PUBLIC_KEY));
    assert_eq!(commitment, SequentialCommit::to_commitment(&key));
    assert_eq!(SequentialCommit::to_elements(&key), elements);
    assert_eq!(commitment, PublicKey::from_bytes(key.to_bytes()).unwrap().to_commitment());
    assert_ne!(commitment, Eidos::hash_elements(&elements));
}

fn random_bytes(rng: &mut ChaCha20Rng) -> [u8; 40] {
    let mut bytes = [0; 40];
    rng.try_fill_bytes(&mut bytes).unwrap();
    bytes
}

struct ScriptedRng<'a> {
    remaining: &'a [u8],
    draws: usize,
}

impl TryRng for ScriptedRng<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        utils::next_word_via_fill::<u32, _>(self)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        utils::next_word_via_fill::<u64, _>(self)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let (bytes, remaining) =
            self.remaining.split_at_checked(dst.len()).expect("scripted RNG exhausted");
        dst.copy_from_slice(bytes);
        self.remaining = remaining;
        self.draws += 1;
        Ok(())
    }
}

// This test-only source supplies fixed bytes, not cryptographic randomness.
impl TryCryptoRng for ScriptedRng<'_> {}
