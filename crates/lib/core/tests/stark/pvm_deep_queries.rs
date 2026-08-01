//! Behavioral oracle for the PVM DEEP-query hook.

use miden_core::{
    Felt, Word,
    crypto::{
        hash::Poseidon2,
        merkle::{MerklePath, MerkleStore},
    },
    field::{BasedVectorSpace, Field, PrimeCharacteristicRing, QuadFelt},
};

use crate::helpers::{masm_push_word, read_memory_felt};

const FULL_DEPTH: u8 = 20;
const PREPROCESSED_DEPTH: u8 = 19;
const FULL_INDEX: u32 = (1 << PREPROCESSED_DEPTH) + 7;
const FOLDED_INDEX: u32 = FULL_INDEX & ((1 << PREPROCESSED_DEPTH) - 1);

const QUERY_PTR: u32 = 1_000;
const QUERY_END_PTR: u32 = QUERY_PTR + 4;
const ALPHA_PTR: u32 = 2_000;
const RESULT_ROW_PTR: u32 = 3_225_443_408;
const PREPROCESSED_COM_PTR: u32 = 3_225_444_176;

const MAIN_COM_PTR: u32 = 3_223_322_640;
const AUX_COM_PTR: u32 = 3_223_322_644;
const QUOTIENT_COM_PTR: u32 = 3_223_322_648;

const PREPROCESSED_WIDTH: usize = 8;
const MAIN_WIDTH: usize = 440;
const AUX_WIDTH: usize = 312;
const QUOTIENT_WIDTH: usize = 8;
const QUERY_ROW_WIDTH: usize = PREPROCESSED_WIDTH + MAIN_WIDTH + AUX_WIDTH + QUOTIENT_WIDTH;

const ALPHA: [u64; 2] = [3, 5];
const DOMAIN_GENERATOR: u64 = 7;

fn row(width: usize, offset: u32) -> Vec<Felt> {
    (0..width)
        .map(|i| Felt::from_u32(((i as u32 + 1) * 17 + offset) % 65_521))
        .collect()
}

fn add_path(
    store: &mut MerkleStore,
    row: &[Felt],
    index: u32,
    depth: u8,
    sibling_seed: u32,
) -> Word {
    let leaf = Poseidon2::hash_elements(row);
    let siblings = (0..depth)
        .map(|level| {
            Word::new(core::array::from_fn(|limb| {
                Felt::from_u32(sibling_seed + 16 * u32::from(level) + limb as u32)
            }))
        })
        .collect();
    store
        .add_merkle_path(u64::from(index), leaf, MerklePath::new(siblings))
        .expect("valid synthetic Merkle path")
}

fn source(preprocessed_root: Word, main_root: Word, aux_root: Word, quotient_root: Word) -> String {
    format!(
        r#"
        use miden::core::stark::constants
        use miden::core::sys::pvm::deep_queries

        begin
            # Query word: [natural index, full tree depth, natural index, 0].
            push.0.{index}.{depth}.{index} push.{query_ptr} mem_storew_le dropw

            # Horner alpha and generic scratch word [row_ptr, alpha_ptr, 0, 0].
            push.0.0.{alpha1}.{alpha0} push.{alpha_ptr} mem_storew_le dropw
            push.0.0.{alpha_ptr}.{result_row_ptr} exec.constants::tmp2 mem_storew_le dropw

            # Domain data used by the generic final DEEP computation.
            push.0.{domain_generator}.{depth}.{lde_size}
            exec.constants::set_lde_domain_info_word
            dropw
            push.1 exec.constants::set_domain_offset

            # Commitment roots for all four groups.
            {preprocessed_root}
            push.{preprocessed_com_ptr} mem_storew_le dropw
            {main_root}
            push.{main_com_ptr} mem_storew_le dropw
            {aux_root}
            push.{aux_com_ptr} mem_storew_le dropw
            {quotient_root}
            push.{quotient_com_ptr} mem_storew_le dropw

            # [Y, query_ptr, query_end_ptr, W = 0, query_ptr]. One query only.
            push.{query_ptr}
            padw
            push.{query_end_ptr}.{query_ptr}
            padw
            exec.deep_queries::compute_deep_composition_polynomial_queries
        end
        "#,
        index = FULL_INDEX,
        depth = FULL_DEPTH,
        query_ptr = QUERY_PTR,
        query_end_ptr = QUERY_END_PTR,
        alpha0 = ALPHA[0],
        alpha1 = ALPHA[1],
        alpha_ptr = ALPHA_PTR,
        result_row_ptr = RESULT_ROW_PTR,
        domain_generator = DOMAIN_GENERATOR,
        lde_size = 1u32 << FULL_DEPTH,
        preprocessed_root = masm_push_word(&preprocessed_root),
        preprocessed_com_ptr = PREPROCESSED_COM_PTR,
        main_root = masm_push_word(&main_root),
        main_com_ptr = MAIN_COM_PTR,
        aux_root = masm_push_word(&aux_root),
        aux_com_ptr = AUX_COM_PTR,
        quotient_root = masm_push_word(&quotient_root),
        quotient_com_ptr = QUOTIENT_COM_PTR,
    )
}

#[test]
fn pvm_deep_query_hook_authenticates_folded_setup_index_and_reduces_every_group() {
    let preprocessed = row(PREPROCESSED_WIDTH, 100);
    let main = row(MAIN_WIDTH, 200);
    let aux = row(AUX_WIDTH, 300);
    let quotient = row(QUOTIENT_WIDTH, 400);

    let mut store = MerkleStore::new();
    let preprocessed_root =
        add_path(&mut store, &preprocessed, FOLDED_INDEX, PREPROCESSED_DEPTH, 1_000);
    let main_root = add_path(&mut store, &main, FULL_INDEX, FULL_DEPTH, 2_000);
    let aux_root = add_path(&mut store, &aux, FULL_INDEX, FULL_DEPTH, 3_000);
    let quotient_root = add_path(&mut store, &quotient, FULL_INDEX, FULL_DEPTH, 4_000);

    let advice_map = [
        (Poseidon2::hash_elements(&preprocessed), preprocessed.clone()),
        (Poseidon2::hash_elements(&main), main.clone()),
        (Poseidon2::hash_elements(&aux), aux.clone()),
        (Poseidon2::hash_elements(&quotient), quotient.clone()),
    ];

    let program = source(preprocessed_root, main_root, aux_root, quotient_root);
    let (output, _) = build_test!(&program, &[], &[], store, advice_map)
        .execute_for_output()
        .expect("PVM DEEP-query hook must execute");

    let opened_row: Vec<Felt> =
        preprocessed.into_iter().chain(main).chain(aux).chain(quotient).collect();
    assert_eq!(opened_row.len(), QUERY_ROW_WIDTH);
    for (i, expected) in opened_row.iter().enumerate() {
        assert_eq!(
            read_memory_felt(&output, RESULT_ROW_PTR + i as u32),
            *expected,
            "opened query-row felt {i} is out of commitment-group order"
        );
    }

    let alpha = QuadFelt::new(ALPHA.map(Felt::new_unchecked));
    let reduced_row = opened_row
        .iter()
        .copied()
        .fold(QuadFelt::ZERO, |acc, value| QuadFelt::from(value) + alpha * acc);
    let poe = Felt::new_unchecked(DOMAIN_GENERATOR).exp_u64(u64::from(FULL_INDEX));
    let expected_eval = reduced_row * QuadFelt::from(poe).inverse();
    let expected_eval: &[Felt] = expected_eval.as_basis_coefficients_slice();

    assert_eq!(read_memory_felt(&output, QUERY_PTR), poe);
    assert_eq!(read_memory_felt(&output, QUERY_PTR + 1), Felt::from_u32(FULL_INDEX));
    assert_eq!(read_memory_felt(&output, QUERY_PTR + 2), expected_eval[0]);
    assert_eq!(read_memory_felt(&output, QUERY_PTR + 3), expected_eval[1]);
}
