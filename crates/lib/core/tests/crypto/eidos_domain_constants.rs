use miden_ace_codegen::EXT_DEGREE;
use miden_air::precompiles::{ChipletAir, PvmAirVariant, security};
use miden_core::{
    Felt, Word,
    field::QuadFelt,
    program::domain::{
        DEFERRED_CHUNKS, EXECUTION_CLAIM, FALCON_PRODUCT_CHECK, FALCON_PRODUCT_CHECK_PAYLOAD_LEN,
        KERNEL_COMMITMENT, PROOF_REQUEST, STARK_TRANSCRIPT, domain_tag,
    },
};
use miden_crypto::hash::eidos::{
    BLOCK_LEN as EIDOS_BLOCK_WIDTH, Eidos,
    domains::{
        AEAD_CTR_KEY, AEAD_MAC_KEY, ECGFP5_PREPROCESSED_PUBLIC_KEY, ECGFP5_PUBLIC_KEY,
        ECGFP5_SEAL_CONTEXT, ECGFP5_SEAL_EXTRACT, ECGFP5_SEAL_KEY, ECGFP5_SEAL_NONCE,
        FALCON_HASH_TO_POINT, FALCON_PUBLIC_KEY, GENERIC_FELT_SEQUENCE, LMCS_LEAF, MMR_PEAKS,
        SMT_BUCKET_LEAF,
    },
};
use miden_lifted_stark::air::{BaseAir, LiftedAir};
use miden_precompiles::{Keccak256Precompile, Sha256Precompile, Sha512Precompile};

use crate::helpers::read_memory_felt;

const EIDOS: &str = include_str!("../../asm/crypto/hashes/eidos.masm");
const SMT: &str = include_str!("../../asm/collections/smt.masm");
const MMR: &str = include_str!("../../asm/collections/mmr.masm");
const FALCON: &str = include_str!("../../asm/crypto/dsa/falcon512_eidos.masm");
const ECDSA_K256_KECCAK: &str = include_str!("../../asm/crypto/dsa/ecdsa_k256_keccak.masm");
const ECDSA_P256_SHA256: &str = include_str!("../../asm/crypto/dsa/ecdsa_p256_sha256.masm");
const EDDSA_25519_SHA512: &str = include_str!("../../asm/crypto/dsa/eddsa_25519_sha512.masm");
const AEAD: &str = include_str!("../../asm/crypto/aead_eidos/primitives.masm");
const ECGFP5_IES: &str = include_str!("../../asm/crypto/ies/ecgfp5_eidos.masm");
const ECGFP5_TABLES: &str = include_str!("../../asm/crypto/ecdh/ecgfp5/tables.masm");
const ECGFP5_DIRECT: &str = include_str!("../../asm/crypto/ecdh/ecgfp5/direct.masm");
const PRECOMPILES: &str = include_str!("../../asm/precompiles/mod.masm");
const KECCAK: &str = include_str!("../../asm/precompiles/hashes/keccak256.masm");
const SHA256: &str = include_str!("../../asm/precompiles/hashes/sha256.masm");
const SHA512: &str = include_str!("../../asm/precompiles/hashes/sha512.masm");
const RANDOM_COIN: &str = include_str!("../../asm/stark/random_coin.masm");
const SYS: &str = include_str!("../../asm/sys/mod.masm");
const VM: &str = include_str!("../../asm/sys/vm/mod.masm");
const CLAIM: &str = include_str!("../../asm/sys/vm/claim.masm");
const FRI: &str = include_str!("../../asm/pcs/fri/frie2f4.masm");
const VM_PARAMETERS: &str = include_str!("../../asm/sys/vm/parameters.masm");
const PVM_PARAMETERS: &str = include_str!("../../asm/sys/pvm/parameters.masm");

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
    let metadata_prefix = format!("# {name} = ");
    source
        .lines()
        .find_map(|line| {
            let line = line.trim();
            let line = line.strip_prefix("pub ").unwrap_or(line);
            line.strip_prefix(&prefix).or_else(|| line.strip_prefix(&metadata_prefix))
        })
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
        masm_scalar(ECGFP5_IES, "ECGFP5_SEAL_CONTEXT"),
        domain_tag(ECGFP5_SEAL_CONTEXT).as_canonical_u64(),
    );
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
    assert_eq!(
        masm_scalar(SHA512, "DOMAIN_TAG"),
        u64::from(Sha512Precompile::domain().as_u32())
    );
    assert_eq!(masm_scalar(SHA512, "ASSERT_OP_ID"), u64::from(Sha512Precompile::ASSERT_OP_ID));
    assert_eq!(
        masm_scalar(SHA256, "DOMAIN_TAG"),
        u64::from(Sha256Precompile::domain().as_u32())
    );
    assert_eq!(masm_scalar(SHA256, "ASSERT_OP_ID"), u64::from(Sha256Precompile::ASSERT_OP_ID));
}

#[test]
fn ecgfp5_generator_commitment_matches_rust() {
    use miden_crypto::ecdh::ecgfp5::SecretKey;

    let mut bytes = [0; 40];
    bytes[0] = 1;
    let secret = SecretKey::from_bytes(&bytes).unwrap();
    let advice = secret.public_key().advise(&secret);
    // The direct advice starts with Q(5) and the scalar's ten u32 limbs, then the twenty roots.
    let roots: Vec<_> = advice.elements().skip(5 + 10).take(80).collect();
    assert_word(
        ECGFP5_DIRECT,
        "GENERATOR_COMMITMENT",
        Eidos::hash_elements_in_domain(&roots, ECGFP5_PREPROCESSED_PUBLIC_KEY),
    );
}

#[test]
fn masm_initial_chaining_words_match_rust() {
    assert_word(
        ECGFP5_DIRECT,
        "PUBLIC_KEY_INIT_CV",
        Eidos::init_chaining_word(ECGFP5_PUBLIC_KEY, 5),
    );
    assert_word(
        ECGFP5_TABLES,
        "ROOTS_INIT_CV",
        Eidos::init_chaining_word(ECGFP5_PREPROCESSED_PUBLIC_KEY, 80),
    );
    assert_word(
        ECGFP5_TABLES,
        "LEAF_INIT_CV",
        Eidos::init_chaining_word(GENERIC_FELT_SEQUENCE, 24),
    );
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
    assert_word(
        ECDSA_P256_SHA256,
        "PUBLIC_KEY_INIT_CV",
        Eidos::init_chaining_word(GENERIC_FELT_SEQUENCE, (4 * Word::NUM_ELEMENTS) as u32),
    );
    assert_word(
        EDDSA_25519_SHA512,
        "PUBLIC_KEY_INIT_CV",
        Eidos::init_chaining_word(GENERIC_FELT_SEQUENCE, (2 * Word::NUM_ELEMENTS) as u32),
    );
    assert_indexed_word(AEAD, "AEAD_CTR_INIT_CV", Eidos::init_chaining_word(AEAD_CTR_KEY, 0));
    assert_indexed_word(AEAD, "AEAD_MAC_INIT_CV", Eidos::init_chaining_word(AEAD_MAC_KEY, 0));
    assert_word(
        ECGFP5_IES,
        "EXTRACT_INIT_CV",
        Eidos::init_chaining_word(ECGFP5_SEAL_EXTRACT, 24),
    );
    assert_word(ECGFP5_IES, "KEY_INIT_CV", Eidos::init_chaining_word(ECGFP5_SEAL_KEY, 8));
    assert_word(ECGFP5_IES, "NONCE_INIT_CV", Eidos::init_chaining_word(ECGFP5_SEAL_NONCE, 8));

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
    assert_eq!(
        Word::new([
            Felt::new_unchecked(masm_scalar(SHA512, "ASSERT_INIT_CV_0")),
            Felt::new_unchecked(masm_scalar(SHA512, "ASSERT_INIT_CV_1")),
            Felt::new_unchecked(masm_scalar(SHA512, "ASSERT_INIT_CV_2_BASE")),
            Felt::new_unchecked(masm_scalar(SHA512, "ASSERT_INIT_CV_3")),
        ]),
        Sha512Precompile::assert_frame(0).initial_chaining_word(),
    );
    assert_eq!(
        Word::new([
            Felt::new_unchecked(masm_scalar(SHA256, "ASSERT_INIT_CV_0")),
            Felt::new_unchecked(masm_scalar(SHA256, "ASSERT_INIT_CV_1")),
            Felt::new_unchecked(masm_scalar(SHA256, "ASSERT_INIT_CV_2_BASE")),
            Felt::new_unchecked(masm_scalar(SHA256, "ASSERT_INIT_CV_3")),
        ]),
        Sha256Precompile::assert_frame(0).initial_chaining_word(),
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
    for (cv_name, blocks_name) in [
        ("PREPROCESSED_LMCS_INIT_CV", "PREPROCESSED_ROW_DOUBLE_WORDS"),
        ("MAIN_LMCS_INIT_CV", "MAIN_ROW_DOUBLE_WORDS"),
        ("AUX_LMCS_INIT_CV", "AUX_ROW_DOUBLE_WORDS"),
        ("QUOTIENT_LMCS_INIT_CV", "QUOTIENT_ROW_DOUBLE_WORDS"),
    ] {
        let blocks = u32::try_from(masm_scalar(VM_PARAMETERS, blocks_name))
            .expect("LMCS block count exceeds u32");
        let encoded_len = blocks
            .checked_mul(EIDOS_BLOCK_WIDTH as u32)
            .expect("LMCS encoded length exceeds u32");
        assert_word(VM_PARAMETERS, cv_name, Eidos::init_chaining_word(LMCS_LEAF, encoded_len));
    }
    let blocks = u32::try_from(masm_scalar(PVM_PARAMETERS, "PREPROCESSED_ROW_DOUBLE_WORDS"))
        .expect("PVM LMCS block count exceeds u32");
    let encoded_len = blocks
        .checked_mul(EIDOS_BLOCK_WIDTH as u32)
        .expect("PVM LMCS encoded length exceeds u32");
    assert_word(
        PVM_PARAMETERS,
        "PREPROCESSED_LMCS_INIT_CV",
        Eidos::init_chaining_word(LMCS_LEAF, encoded_len),
    );
}

#[test]
fn pvm_variant_initial_chaining_words_match_rust() {
    let source = "use miden::core::sys::pvm::variants
use miden::core::sys::pvm::layout

begin
    exec.variants::load
    exec.layout::main_lmcs_init_cv mem_storew_le.1000 dropw
    exec.layout::aux_lmcs_init_cv mem_storew_le.1004 dropw
    exec.layout::quotient_lmcs_init_cv mem_storew_le.1008 dropw
end";
    for variant in PvmAirVariant::ALL_VARIANTS {
        let airs: Vec<_> =
            ChipletAir::all().into_iter().filter(|air| air.is_in_variant(variant)).collect();
        // LMCS pads each AIR's row separately before concatenating the commitment group.
        let widths = [
            airs.iter()
                .map(|air| BaseAir::<Felt>::width(air).next_multiple_of(EIDOS_BLOCK_WIDTH))
                .sum::<usize>(),
            airs.iter()
                .map(|air| {
                    (LiftedAir::<Felt, QuadFelt>::aux_width(air) * EXT_DEGREE)
                        .next_multiple_of(EIDOS_BLOCK_WIDTH)
                })
                .sum(),
            (security::derive_air_shape_for(variant).num_quotient_chunks as usize * EXT_DEGREE)
                .next_multiple_of(EIDOS_BLOCK_WIDTH),
        ];
        let test = build_test!(source, &[], &[u64::from(variant.as_u8())]);
        let (output, _) = test.execute_for_output().expect("PVM variant metadata must load");
        for (group, width) in widths.into_iter().enumerate() {
            let cv = Word::new(core::array::from_fn(|lane| {
                read_memory_felt(&output, 1000 + (group * Word::NUM_ELEMENTS + lane) as u32)
            }));
            let encoded_len = u32::try_from(width).expect("PVM LMCS encoded length exceeds u32");
            assert_eq!(
                cv,
                Eidos::init_chaining_word(LMCS_LEAF, encoded_len),
                "PVM variant {} commitment group {group} initial CV drifted",
                variant.as_u8(),
            );
        }
    }
}
