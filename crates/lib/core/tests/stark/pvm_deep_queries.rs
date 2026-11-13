//! Behavioral oracle for the PVM DEEP-query hook.

use miden_ace::EXT_DEGREE;
use miden_core::{
    Felt, Word,
    crypto::{
        hash::Eidos,
        merkle::{MerklePath, MerkleStore},
    },
    field::{BasedVectorSpace, Field, PrimeCharacteristicRing, QuadFelt},
};
use miden_crypto::hash::eidos::{BLOCK_LEN as EIDOS_RATE, domains::LMCS_LEAF};

use super::pvm_layout_const;
use crate::helpers::{masm_push_word, read_memory_felt, stark_constant};

const FULL_DEPTH: u8 = 20;
const PREPROCESSED_DEPTH: u8 = 19;
const FULL_INDEX: u32 = (1 << PREPROCESSED_DEPTH) + 7;
const FOLDED_INDEX: u32 = FULL_INDEX & ((1 << PREPROCESSED_DEPTH) - 1);

const QUERY_PTR: u32 = 1_000;
const QUERY_END_PTR: u32 = QUERY_PTR + 4;
const ALPHA_PTR: u32 = 2_000;
const ROW_SENTINEL: u32 = 123_456;

const ALPHA: [u64; 2] = [3, 5];
const DOMAIN_GENERATOR: u64 = 7;

fn commitment_width(current_ptr: &str, next_ptr: &str) -> usize {
    let current_ptr = pvm_layout_const(current_ptr);
    let next_ptr = pvm_layout_const(next_ptr);
    let ood_felts = next_ptr.checked_sub(current_ptr).expect("PVM OOD regions are ordered");
    let ood_felts = usize::try_from(ood_felts).expect("PVM OOD extent fits in usize");
    assert_eq!(
        ood_felts % EXT_DEGREE,
        0,
        "PVM OOD region must contain whole extension-field evaluations"
    );
    ood_felts / EXT_DEGREE
}

fn row(width: usize, offset: u32) -> Vec<Felt> {
    (0..width)
        .map(|i| Felt::from_u32(((i as u32 + 1) * 17 + offset) % 65_521))
        .collect()
}

fn query_rows() -> [Vec<Felt>; 4] {
    [
        ("PREPROCESSED_CURRENT_PTR", "MAIN_CURRENT_PTR", 100),
        ("MAIN_CURRENT_PTR", "AUX_CURRENT_PTR", 200),
        ("AUX_CURRENT_PTR", "QUOTIENT_CURRENT_PTR", 300),
        ("QUOTIENT_CURRENT_PTR", "PREPROCESSED_NEXT_PTR", 400),
    ]
    .map(|(start, end, offset)| row(commitment_width(start, end), offset))
}

fn query_fixture(rows: &[Vec<Felt>; 4]) -> (String, MerkleStore) {
    let mut store = MerkleStore::new();
    let preprocessed_root = add_path(&mut store, &rows[0], FOLDED_INDEX, PREPROCESSED_DEPTH, 1_000);
    let main_root = add_path(&mut store, &rows[1], FULL_INDEX, FULL_DEPTH, 2_000);
    let aux_root = add_path(&mut store, &rows[2], FULL_INDEX, FULL_DEPTH, 3_000);
    let quotient_root = add_path(&mut store, &rows[3], FULL_INDEX, FULL_DEPTH, 4_000);
    (source(preprocessed_root, main_root, aux_root, quotient_root), store)
}

fn add_path(
    store: &mut MerkleStore,
    row: &[Felt],
    index: u32,
    depth: u8,
    sibling_seed: u32,
) -> Word {
    let leaf = lmcs_leaf(row);
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

/// Mirrors the Eidos LMCS leaf hasher. All four PVM commitment-group widths are LMCS-aligned.
fn lmcs_leaf(row: &[Felt]) -> Word {
    assert_eq!(row.len() % EIDOS_RATE, 0, "synthetic LMCS row must be block-aligned");
    row.as_chunks::<EIDOS_RATE>()
        .0
        .iter()
        .fold(Eidos::init_chaining_word(LMCS_LEAF, row.len() as u32), |cv, block| {
            Eidos::compress(cv, *block)
        })
}

fn source(preprocessed_root: Word, main_root: Word, aux_root: Word, quotient_root: Word) -> String {
    let result_row_ptr = stark_constant("CURRENT_TRACE_ROW_PTR");
    let row_width =
        u32::try_from(commitment_width("PREPROCESSED_CURRENT_PTR", "PREPROCESSED_NEXT_PTR"))
            .unwrap();
    let preprocessed_com_ptr = stark_constant("PREPROCESSED_TRACE_COM_PTR");
    format!(
        r#"
        use {{
            DOMAIN_OFFSET_PTR, LDE_DOMAIN_INFO_PTR, TMP2_PTR
        }} from miden::core::stark::constants
        use miden::core::sys::pvm::deep_queries

        begin
            # Detect writes outside the query-row buffer.
            push.{ROW_SENTINEL} mem_store.{row_before}
            push.{ROW_SENTINEL} mem_store.{row_after}

            # Query word: [natural index, full tree depth, natural index, 0].
            push.0.{index}.{depth}.{index} push.{query_ptr} mem_storew_le dropw

            # Horner alpha and generic scratch word [row_ptr, alpha_ptr, 0, 0].
            push.0.0.{alpha1}.{alpha0} push.{alpha_ptr} mem_storew_le dropw
            push.0.0.{alpha_ptr}.{result_row_ptr} mem_storew_le.TMP2_PTR dropw

            # Domain data used by the generic final DEEP computation.
            push.0.{domain_generator}.{depth}.{lde_size}
            mem_storew_le.LDE_DOMAIN_INFO_PTR
            dropw
            push.1 mem_store.DOMAIN_OFFSET_PTR

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
        result_row_ptr = result_row_ptr,
        row_before = result_row_ptr - 1,
        row_after = result_row_ptr + row_width,
        domain_generator = DOMAIN_GENERATOR,
        lde_size = 1u32 << FULL_DEPTH,
        preprocessed_root = masm_push_word(&preprocessed_root),
        preprocessed_com_ptr = preprocessed_com_ptr,
        main_root = masm_push_word(&main_root),
        main_com_ptr = stark_constant("MAIN_TRACE_COM_PTR"),
        aux_root = masm_push_word(&aux_root),
        aux_com_ptr = stark_constant("AUX_TRACE_COM_PTR"),
        quotient_root = masm_push_word(&quotient_root),
        quotient_com_ptr = stark_constant("COMPOSITION_POLY_COM_PTR"),
    )
}

#[test]
fn pvm_deep_query_hook_authenticates_folded_setup_index_and_reduces_every_group() {
    let result_row_ptr = stark_constant("CURRENT_TRACE_ROW_PTR");
    let rows = query_rows();
    let widths = rows.each_ref().map(Vec::len);
    let next_widths = [
        commitment_width("PREPROCESSED_NEXT_PTR", "MAIN_NEXT_PTR"),
        commitment_width("MAIN_NEXT_PTR", "AUX_NEXT_PTR"),
        commitment_width("AUX_NEXT_PTR", "QUOTIENT_NEXT_PTR"),
        commitment_width("QUOTIENT_NEXT_PTR", "AUX_BUS_BOUNDARY_PTR"),
    ];
    assert_eq!(widths, next_widths, "current and next PVM OOD rows must have equal geometry");

    let (program, store) = query_fixture(&rows);
    let advice_map = rows.each_ref().map(|row| (lmcs_leaf(row), row.clone()));
    let (output, _) = build_test!(&program, &[], &[], store, advice_map)
        .execute_for_output()
        .expect("PVM DEEP-query hook must execute");

    let opened_row: Vec<Felt> = rows.into_iter().flatten().collect();
    let row_end = result_row_ptr + u32::try_from(opened_row.len()).unwrap();
    for address in [result_row_ptr - 1, row_end] {
        assert_eq!(
            read_memory_felt(&output, address),
            Felt::from_u32(ROW_SENTINEL),
            "query-row boundary at {address} was overwritten"
        );
    }
    for (i, expected) in opened_row.iter().enumerate() {
        assert_eq!(
            read_memory_felt(&output, result_row_ptr + i as u32),
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

#[test]
fn pvm_deep_query_hook_rejects_tampered_rows() {
    let rows = query_rows();
    let (program, store) = query_fixture(&rows);
    for (group, message) in [
        "preprocessed query leaf hash mismatch",
        "main query leaf hash mismatch",
        "aux query leaf hash mismatch",
        "quotient query leaf hash mismatch",
    ]
    .into_iter()
    .enumerate()
    {
        // Keep the authenticated leaf digest as the key; forge only the advised row.
        let mut advice_map = rows.each_ref().map(|row| (lmcs_leaf(row), row.clone()));
        advice_map[group].1[0] += Felt::ONE;
        let test = build_test!(&program, &[], &[], store.clone(), advice_map);
        expect_assert_error_code_from_msg!(test, message);
    }
}
