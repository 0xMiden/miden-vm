//! Fixed compatibility vectors for the public API restored from PR #4032's parent
//! (`8ac2627a6`). Inputs straddle the byte-encoding and sponge-rate boundaries.

use miden_crypto::{Felt, Word, hash::poseidon2::Poseidon2};

fn assert_digest(actual: Word, expected: [u64; 4]) {
    assert_eq!(actual, Word::new(expected.map(Felt::new_unchecked)));
}

#[test]
fn poseidon2_byte_hash_compatibility() {
    // Input bytes are 0, 1, ..., len - 1.
    let vectors = [
        (
            0,
            [0x608636e7585eff7d, 0x9a370961a04af44b, 0xdd689f374dc7fc91, 0xf248e6a82088ea38],
        ),
        (
            1,
            [0xa9fccbf70cd5952b, 0x9f081596e922d7ec, 0xe415c3ba0c4b5e0d, 0x1d519c9b545a1b3b],
        ),
        (
            6,
            [0x40601b283de8a0ed, 0x85e6e96ac8171fd2, 0x4cfdbc9d65515757, 0x0eea7d93b6926933],
        ),
        (
            7,
            [0xc4af48c4ba7c0573, 0x229ab9fe499cc675, 0x6d93f74915e3d581, 0x7eaa4152b9e3ea7d],
        ),
        (
            8,
            [0xba5a03557bb82a4f, 0x0d9e243adccbeff0, 0x308678c4d39932ac, 0xa54013b958c3a802],
        ),
        (
            55,
            [0x7b2fdb0865c0dffe, 0xd718dbef46e0a888, 0xc3f09791badc48c6, 0x00d5f4a0d04577f8],
        ),
        (
            56,
            [0x9840d2265de616b1, 0xeed02ff5e2bce4ca, 0xb497b56f39e74527, 0x7b3293b09d40b335],
        ),
        (
            57,
            [0x7462e96fc0a9b810, 0x4a4e5d5fe17b452e, 0xd9361ae183b1c0c8, 0x1a775b327f6a0391],
        ),
        (
            113,
            [0xd686db43a8314bdc, 0x8580a41cb3acfde6, 0xa0485bd945195327, 0x1449721de9c136d3],
        ),
    ];
    for (len, expected) in vectors {
        let input: Vec<u8> = (0..len).map(|i| i as u8).collect();
        assert_digest(Poseidon2::hash(&input), expected);
    }
}

#[test]
fn poseidon2_element_hash_compatibility() {
    // Input field elements are 0, 1, ..., len - 1.
    let vectors = [
        (
            0,
            [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
        ),
        (
            1,
            [0x0b58912bb91aa0d8, 0xabfe5c40247be2b8, 0x6edf1a7c0d5fc5e6, 0xb90241752cc63f47],
        ),
        (
            7,
            [0x8b2c3a8590ac98d8, 0xa55b5d71b9a0ce9f, 0xea8cec51629faa74, 0x98d1b69faa274ca4],
        ),
        (
            8,
            [0xc7b751582cf5851f, 0xed8b220f07f92cd1, 0xe214a022092ba3d3, 0xf2f5725739a89256],
        ),
        (
            9,
            [0xbe7ecf3b373c28ce, 0x0c5c990caf9c8f32, 0x2a74108a54ff0f8c, 0x783fdc2f7a3d993c],
        ),
        (
            16,
            [0x116955ad55d9f25f, 0x3ab166587a4352ea, 0x3dfe5b1eddc405a9, 0xc2b7292b3a67bbb3],
        ),
        (
            17,
            [0xd78f02a220ed5dea, 0x6e55f5c87fabe7c0, 0x51e40ec0b6655cab, 0x93439cf9ebbb13e2],
        ),
    ];
    for (len, expected) in vectors {
        let input: Vec<Felt> = (0..len).map(|i| Felt::new_unchecked(i as u64)).collect();
        assert_digest(Poseidon2::hash_elements(&input), expected);
        assert_digest(Poseidon2::hash_elements_in_domain(&input, Felt::ZERO), expected);
    }
}

#[test]
fn poseidon2_domain_hash_compatibility() {
    let domain = Felt::new_unchecked(7);
    let vectors = [
        (
            0,
            [0x2c4f591ff28bc088, 0x6821793a59f29754, 0x35bff5ad9ce512ba, 0x687cc508b7d58cf2],
        ),
        (
            1,
            [0xf94af1204c99d6ff, 0x75fcd0237c6a4662, 0xe61d36da34d4c892, 0x9412d4c4ac23fc79],
        ),
        (
            8,
            [0x5a1a79a8b1373c53, 0xaf28ae08930f7107, 0x3ea5aec55374c515, 0xa742ee23b84ba24f],
        ),
        (
            9,
            [0x6800c68541e0b768, 0xff92d855b14e2f3f, 0xf4d79d00449f0bed, 0x807782b6ecda5bb9],
        ),
    ];
    for (len, expected) in vectors {
        let input: Vec<Felt> = (0..len).map(|i| Felt::new_unchecked(i as u64)).collect();
        assert_digest(Poseidon2::hash_elements_in_domain(&input, domain), expected);
    }
}

#[test]
fn poseidon2_merge_compatibility() {
    let words: [Word; 4] = core::array::from_fn(|i| {
        Word::new(core::array::from_fn(|j| Felt::new_unchecked((4 * i + j) as u64)))
    });
    let pair = [words[0], words[1]];
    let pair_digest =
        [0xc7b751582cf5851f, 0xed8b220f07f92cd1, 0xe214a022092ba3d3, 0xf2f5725739a89256];
    let domain_digest =
        [0x5a1a79a8b1373c53, 0xaf28ae08930f7107, 0x3ea5aec55374c515, 0xa742ee23b84ba24f];
    let four_word_digest =
        [0x116955ad55d9f25f, 0x3ab166587a4352ea, 0x3dfe5b1eddc405a9, 0xc2b7292b3a67bbb3];

    assert_digest(Poseidon2::merge(&pair), pair_digest);
    assert_digest(Poseidon2::merge_in_domain(&pair, Felt::ZERO), pair_digest);
    assert_digest(Poseidon2::merge_in_domain(&pair, Felt::new_unchecked(7)), domain_digest);
    assert_digest(Poseidon2::merge_many(&words), four_word_digest);
}
