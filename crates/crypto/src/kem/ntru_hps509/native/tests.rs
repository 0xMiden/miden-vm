use shake::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use super::*;

mod vectors;

#[test]
fn reference_vectors() {
    for vector in &vectors::VECTORS {
        let case = vector.case;
        let mut public = [0; POLY_BYTES];
        let mut secret = Zeroizing::new([0; SECRET_BYTES]);
        keypair(&draw(&format!("ntru-rust/key/{case}")), &mut public, &mut secret);
        assert_eq!(public, decode(vector.public_key), "key {case}");
        assert_eq!(*secret, decode(vector.secret_key), "secret {case}");
        assert_eq!(restore_public_key(&secret), Some(public), "restore {case}");

        let sample = encapsulate(&public, &draw(&format!("ntru-rust/enc/{case}")));
        let pair = decode::<PAIR_BYTES>(vector.pair);
        assert_eq!(sample.ciphertext, decode(vector.ciphertext), "ciphertext {case}");
        assert_eq!(*sample.encoded_pair, pair, "pair {case}");
        assert_eq!(*sample.r, trits(&pair[..TRINARY_BYTES]), "r {case}");
        assert_eq!(*sample.m, trits(&pair[TRINARY_BYTES..]), "m {case}");
        let (recovered, failed) = recover(&sample.ciphertext, &secret);
        assert_eq!(failed, 0, "recovery {case}");
        assert_eq!(recovered, sample.encoded_pair, "recovery {case}");
    }
}

#[test]
fn sampling_boundaries_match_reference() {
    let public = decode(vectors::VECTORS[0].public_key);
    let secret = decode(vectors::VECTORS[0].secret_key);
    for (byte, expected) in vectors::SAMPLES {
        let pair = decode::<PAIR_BYTES>(expected);
        let sample = encapsulate(&public, &[byte; COIN_BYTES]);
        assert_eq!(*sample.r, trits(&pair[..TRINARY_BYTES]), "r, byte {byte:02x}");
        assert_eq!(*sample.m, trits(&pair[TRINARY_BYTES..]), "m, byte {byte:02x}");
        assert_eq!(*sample.encoded_pair, pair, "pair, byte {byte:02x}");
        let (recovered, failed) = recover(&sample.ciphertext, &secret);
        assert_eq!(failed, 0, "recovery, byte {byte:02x}");
        assert_eq!(*recovered, pair, "recovery, byte {byte:02x}");
    }
}

#[test]
fn recovery_rejections_match_reference() {
    let vector = &vectors::VECTORS[0];
    let secret = decode(vector.secret_key);
    let ciphertext = decode::<POLY_BYTES>(vector.ciphertext);
    let mut padded = ciphertext;
    padded[POLY_BYTES - 1] |= 0x40;
    let mut random = draw::<POLY_BYTES>(&format!("ntru-rust/ciphertext/{}", vector.case));
    random[POLY_BYTES - 1] &= 0x0f;
    let mut flipped = ciphertext;
    flipped[318] ^= 0x40;
    let cases = [
        ("nonzero padding", padded),
        ("zeros", [0; POLY_BYTES]),
        ("ones", [255; POLY_BYTES]),
        ("random canonical bytes", random),
        ("flipped payload bit", flipped),
        ("invalid randomness", decode(vectors::INVALID_R_CIPHERTEXT)),
        ("wrong-weight message", decode(vectors::WRONG_WEIGHT_CIPHERTEXT)),
    ];
    for ((name, ciphertext), expected) in cases.into_iter().zip(vectors::REJECTED_PAIRS) {
        let (candidate, failed) = recover(&ciphertext, &secret);
        assert_eq!(failed, 1, "{name}");
        assert_eq!(*candidate, decode(expected), "{name}");
    }
}

#[test]
fn arithmetic_and_encoding_boundaries() {
    for byte in 0..=u8::MAX {
        let input = [byte; TRINARY_BYTES];
        let decoded = Poly::decode_s3(&input);
        let repacked = decoded.encode_s3();
        assert!(repacked[..TRINARY_BYTES - 1].iter().all(|&b| b == byte % 243));
        assert_eq!(repacked[TRINARY_BYTES - 1], byte % 27);
        assert!(decoded.0.iter().all(|&c| c < 3));
    }
    for value in 0..Q {
        let mut a = Poly([value; N]);
        a.0[N - 1] = 0;
        assert_eq!(Poly::decode_sq(&a.encode_q()).0, a.0);
        let mut trinary = Poly([value % 3; N]);
        trinary.0[N - 1] = 0;
        assert_eq!(Poly::decode_s3(&trinary.encode_s3()).0, trinary.0);
        let expected = u16::from(![0, 1, Q - 1].contains(&value));
        assert_eq!(u16::from(a.trinary_failure() != 0), expected);
    }
    // Multiplication wraps x^N to 1; reduction modulo Phi makes the last coefficient zero.
    let mut x = Poly::zero();
    x.0[1] = 1;
    let mut last = Poly::zero();
    last.0[N - 1] = 1;
    let product = x.mul_rq(&last);
    assert_eq!(product.0[0], 1);
    assert!(product.0[1..].iter().all(|&x| x == 0));
    let inverse = x.invert_sq();
    assert_eq!(x.mul_sq(&inverse).0, product.0);
    assert_eq!(x.mul_s3(&x.invert_s3()).0, product.0);
}

#[test]
fn secret_key_import_checks_recovered_g() {
    // With f = f^-1 = 1, h = 3g. Each case has an invertible h and zero coefficient sum,
    // so rejection must come from g's trits, weight, or final coefficient.
    let mut one = Poly::zero();
    one.0[0] = 1;
    let mut secret = Zeroizing::new([0; SECRET_BYTES]);
    secret[..TRINARY_BYTES].copy_from_slice(&*one.encode_s3());
    secret[TRINARY_BYTES..PAIR_BYTES].copy_from_slice(&*one.encode_s3());

    let half_weight = usize::from(WEIGHT / 2);
    let mut valid = Poly::zero();
    valid.0[..half_weight].fill(1);
    valid.0[half_weight..2 * half_weight].fill(Q - 1);
    let mut light = Poly::zero();
    light.0[..2].copy_from_slice(&[1, Q - 1]);
    let mut nontrinary = Poly(valid.0);
    nontrinary.0[0] = 5;
    nontrinary.0[half_weight] = Q - 5;
    let mut nonzero_last = Poly::zero();
    nonzero_last.0[..half_weight].fill(1);
    nonzero_last.0[N - half_weight..].fill(Q - 1);

    for (name, g, accepted) in [
        ("valid", valid, true),
        ("weight", light, false),
        ("trits", nontrinary, false),
        ("last coefficient", nonzero_last, false),
    ] {
        let h = Poly(g.0.map(|c| 3 * c % Q));
        assert_eq!(h.0.iter().copied().map(u32::from).sum::<u32>() % u32::from(Q), 0);
        let inverse_h = h.invert_sq().mul_sq(&one);
        assert!(h.mul_sq(&inverse_h).is_one(), "{name}: inverse");
        assert_eq!(Poly::decode_sq(&inverse_h.encode_q()).0, inverse_h.0);
        secret[PAIR_BYTES..].copy_from_slice(&*inverse_h.encode_q());
        let expected = if accepted { Some(*h.encode_q()) } else { None };
        assert_eq!(restore_public_key(&secret), expected, "{name}");
    }
    secret[PAIR_BYTES..].fill(0);
    assert!(restore_public_key(&secret).is_none(), "noninvertible h");
}

fn decode<const LEN: usize>(encoded: &str) -> [u8; LEN] {
    let mut bytes = [0; LEN];
    hex::decode_to_slice(encoded, &mut bytes).unwrap();
    bytes
}

fn draw<const LEN: usize>(label: &str) -> [u8; LEN] {
    let mut bytes = [0; LEN];
    let mut hasher = Shake256::default();
    hasher.update(label.as_bytes());
    hasher.finalize_xof().read(&mut bytes);
    bytes
}

fn trits(encoded: &[u8]) -> [u16; N] {
    // S3 packs five base-3 digits per byte; the final byte's unused digits are zero.
    core::array::from_fn(|i| (u16::from(encoded[i / 5]) / 3u16.pow((i % 5) as u32)) % 3)
}
