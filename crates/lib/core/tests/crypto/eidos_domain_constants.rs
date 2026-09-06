use miden_core::{
    Felt, Word,
    program::domain::{
        DEFERRED_CHUNKS, EXECUTION_CLAIM, FALCON_PRODUCT_CHECK, FALCON_PRODUCT_CHECK_PAYLOAD_LEN,
        KERNEL_COMMITMENT, PROOF_REQUEST, STARK_TRANSCRIPT, domain_tag,
    },
};
use miden_crypto::hash::eidos::{
    Eidos,
    domains::{
        AEAD_CTR_KEY, AEAD_MAC_KEY, FALCON_HASH_TO_POINT, FALCON_PUBLIC_KEY, GENERIC_FELT_SEQUENCE,
        LMCS_LEAF, MMR_PEAKS, SMT_BUCKET_LEAF,
    },
};
use miden_precompiles::Keccak256Precompile;

const EIDOS: &str = include_str!("../../asm/crypto/hashes/eidos.masm");
const SMT: &str = include_str!("../../asm/collections/smt.masm");
const MMR: &str = include_str!("../../asm/collections/mmr.masm");
const FALCON: &str = include_str!("../../asm/crypto/dsa/falcon512_eidos.masm");
const ECDSA_K256_KECCAK: &str = include_str!("../../asm/crypto/dsa/ecdsa_k256_keccak.masm");
const AEAD: &str = include_str!("../../asm/crypto/aead_eidos.masm");
const PRECOMPILES: &str = include_str!("../../asm/precompiles/mod.masm");
const KECCAK: &str = include_str!("../../asm/precompiles/hashes/keccak256.masm");
const RANDOM_COIN: &str = include_str!("../../asm/stark/random_coin.masm");
const SYS: &str = include_str!("../../asm/sys/mod.masm");
const VM: &str = include_str!("../../asm/sys/vm/mod.masm");
const CLAIM: &str = include_str!("../../asm/sys/vm/claim.masm");
const FRI: &str = include_str!("../../asm/pcs/fri/frie2f4.masm");
const VM_DEEP_QUERIES: &str = include_str!("../../asm/sys/vm/deep_queries.masm");
const PVM_DEEP_QUERIES: &str = include_str!("../../asm/sys/pvm/deep_queries.masm");

fn parse_u64(value: &str) -> u64 {
    let value = value.trim().trim_end_matches(',');
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).expect("valid hexadecimal MASM constant")
    } else {
        value.parse().expect("valid decimal MASM constant")
    }
}

fn masm_scalar(source: &str, name: &str) -> u64 {
    let prefix = format!("const {name} = ");
    source
        .lines()
        .find_map(|line| line.trim().strip_prefix(&prefix))
        .map(|value| parse_u64(value.split('#').next().expect("constant value")))
        .unwrap_or_else(|| panic!("missing MASM constant {name}"))
}

fn masm_word(source: &str, name: &str) -> Word {
    let prefix = format!("const {name} = ");
    let start = source.find(&prefix).unwrap_or_else(|| panic!("missing MASM constant {name}"));
    let value = &source[start + prefix.len()..];
    let open = value.find('[').unwrap_or_else(|| panic!("MASM constant {name} is not a word"));
    let close = value[open..]
        .find(']')
        .map(|offset| open + offset)
        .unwrap_or_else(|| panic!("unterminated MASM word constant {name}"));
    let values = value[open + 1..close]
        .split(',')
        .filter(|value| !value.trim().is_empty())
        .map(parse_u64)
        .collect::<Vec<_>>();
    let values: [u64; 4] = values.try_into().unwrap_or_else(|values: Vec<u64>| {
        panic!("MASM constant {name} has {} elements", values.len())
    });
    Word::new(values.map(Felt::new_unchecked))
}

fn masm_indexed_word(source: &str, prefix: &str) -> Word {
    Word::new(core::array::from_fn(|index| {
        Felt::new_unchecked(masm_scalar(source, &format!("{prefix}_{index}")))
    }))
}

fn masm_base_word(source: &str, prefix: &str) -> Word {
    Word::new(core::array::from_fn(|index| {
        Felt::new_unchecked(masm_scalar(source, &format!("{prefix}_{index}_BASE")))
    }))
}

fn assert_word(source: &str, name: &str, expected: Word) {
    assert_eq!(masm_word(source, name), expected, "MASM constant {name} drifted");
}

fn assert_indexed_word(source: &str, prefix: &str, expected: Word) {
    assert_eq!(
        masm_indexed_word(source, prefix),
        expected,
        "MASM constants {prefix}_0..3 drifted",
    );
}

#[test]
fn masm_domain_tags_match_rust_registries() {
    assert_eq!(
        masm_scalar(EIDOS, "GENERIC_FELT_SEQUENCE_DOMAIN_TAG"),
        domain_tag(GENERIC_FELT_SEQUENCE).as_canonical_u64(),
    );
    assert_eq!(
        masm_scalar(PRECOMPILES, "DEFERRED_CHUNKS_DOMAIN"),
        domain_tag(DEFERRED_CHUNKS).as_canonical_u64(),
    );
    assert_eq!(
        masm_scalar(VM, "KERNEL_DOMAIN_TAG"),
        domain_tag(KERNEL_COMMITMENT).as_canonical_u64(),
    );
    assert_eq!(
        masm_scalar(KECCAK, "DOMAIN_TAG"),
        u64::from(Keccak256Precompile::domain().as_u32()),
    );
    assert_eq!(
        masm_scalar(KECCAK, "ASSERT_OP_ID"),
        u64::from(Keccak256Precompile::ASSERT_OP_ID),
    );
}

#[test]
fn masm_initial_chaining_words_match_rust() {
    let merkle_cv = Eidos::merkle_node_init_chaining_word();
    assert_eq!(masm_base_word(EIDOS, "EIDOS_INIT_CV"), merkle_cv);
    assert_eq!(masm_base_word(PRECOMPILES, "EIDOS_INIT_CV"), merkle_cv);
    assert_eq!(
        masm_scalar(PRECOMPILES, "DEFERRED_CHUNKS_INIT_CV_0"),
        Eidos::init_chaining_word(DEFERRED_CHUNKS, 8).as_elements()[0].as_canonical_u64(),
    );
    assert_indexed_word(
        EIDOS,
        "EIDOS_EMPTY_FELT_SEQUENCE_DIGEST",
        Eidos::hash_elements::<Felt>(&[]),
    );

    assert_eq!(
        Word::new([
            Felt::new_unchecked(masm_scalar(SMT, "LEAF_INIT_CV_0")),
            Felt::new_unchecked(masm_scalar(SMT, "LEAF_INIT_CV_1_BASE")),
            Felt::new_unchecked(masm_scalar(SMT, "LEAF_INIT_CV_2")),
            Felt::new_unchecked(masm_scalar(SMT, "LEAF_INIT_CV_3")),
        ]),
        Eidos::init_chaining_word(SMT_BUCKET_LEAF, 0),
    );
    assert_word(SMT, "LEAF_MERGE_INIT_CV", Eidos::init_chaining_word(SMT_BUCKET_LEAF, 1));
    assert_eq!(
        Word::new([
            Felt::new_unchecked(masm_scalar(MMR, "MMR_PEAKS_INIT_CV_0")),
            Felt::new_unchecked(masm_scalar(MMR, "MMR_PEAKS_INIT_CV_1_BASE")),
            Felt::new_unchecked(masm_scalar(MMR, "MMR_PEAKS_INIT_CV_2")),
            Felt::new_unchecked(masm_scalar(MMR, "MMR_PEAKS_INIT_CV_3")),
        ]),
        Eidos::init_chaining_word(MMR_PEAKS, 0),
    );

    assert_word(FALCON, "FALCON_H2P_INIT_CV", Eidos::init_chaining_word(FALCON_HASH_TO_POINT, 0));
    assert_word(
        FALCON,
        "FALCON_PUBLIC_KEY_INIT_CV",
        Eidos::init_chaining_word(FALCON_PUBLIC_KEY, 512),
    );
    assert_word(
        FALCON,
        "FALCON_PRODUCT_INIT_CV",
        Eidos::init_chaining_word(FALCON_PRODUCT_CHECK, FALCON_PRODUCT_CHECK_PAYLOAD_LEN),
    );
    assert_word(
        ECDSA_K256_KECCAK,
        "PUBLIC_KEY_INIT_CV",
        Eidos::init_chaining_word(GENERIC_FELT_SEQUENCE, (4 * Word::NUM_ELEMENTS) as u32),
    );
    assert_indexed_word(AEAD, "AEAD_CTR_INIT_CV", Eidos::init_chaining_word(AEAD_CTR_KEY, 0));
    assert_indexed_word(AEAD, "AEAD_MAC_INIT_CV", Eidos::init_chaining_word(AEAD_MAC_KEY, 0));

    for (name, len) in [
        ("DEFERRED_CHUNKS_INIT_CV_1", 8),
        ("DEFERRED_CHUNKS_INIT_CV_2", 16),
        ("DEFERRED_CHUNKS_INIT_CV_3", 24),
    ] {
        assert_word(PRECOMPILES, name, Eidos::init_chaining_word(DEFERRED_CHUNKS, len));
    }
    assert_eq!(
        Word::new([
            Felt::new_unchecked(masm_scalar(KECCAK, "ASSERT_INIT_CV_0")),
            Felt::new_unchecked(masm_scalar(KECCAK, "ASSERT_INIT_CV_1")),
            Felt::new_unchecked(masm_scalar(KECCAK, "ASSERT_INIT_CV_2_BASE")),
            Felt::new_unchecked(masm_scalar(KECCAK, "ASSERT_INIT_CV_3")),
        ]),
        Keccak256Precompile::assert_frame(0).initial_chaining_word(),
    );
    assert_indexed_word(
        RANDOM_COIN,
        "EIDOS_TRANSCRIPT_INIT_CV",
        Eidos::transcript_init_cv(STARK_TRANSCRIPT),
    );
    assert_word(
        SYS,
        "PROOF_REQUEST_INIT_CV",
        Eidos::init_chaining_word(PROOF_REQUEST, (2 * Word::NUM_ELEMENTS) as u32),
    );
    assert_word(CLAIM, "CLAIM_INIT_CV", Eidos::init_chaining_word(EXECUTION_CLAIM, 40));

    assert_word(FRI, "FRI_ROW_HASH_INIT_CV", Eidos::init_chaining_word(LMCS_LEAF, 8));
    for (name, len) in [
        ("EIDOS_LMCS_INIT_CV_16", 16),
        ("EIDOS_LMCS_INIT_CV_80", 80),
        ("EIDOS_LMCS_INIT_CV_208", 208),
    ] {
        assert_word(VM_DEEP_QUERIES, name, Eidos::init_chaining_word(LMCS_LEAF, len));
    }
    for (name, len) in [
        ("EIDOS_LMCS_INIT_CV_8", 8),
        ("EIDOS_LMCS_INIT_CV_16", 16),
        ("EIDOS_LMCS_INIT_CV_368", 368),
        ("EIDOS_LMCS_INIT_CV_528", 528),
    ] {
        assert_word(PVM_DEEP_QUERIES, name, Eidos::init_chaining_word(LMCS_LEAF, len));
    }
}
