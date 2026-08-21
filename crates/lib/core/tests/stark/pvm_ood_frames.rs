//! Behavioral oracle for the PVM out-of-domain row hook.

use miden_core::{
    Felt,
    advice::AdviceStack,
    field::{BasedVectorSpace, QuadFelt},
};
use miden_crypto::{
    hash::poseidon2::Poseidon2Permutation256,
    stark::challenger::{CanObserve, DuplexChallenger},
};

use crate::helpers::read_memory_felt;

const OOD_ROW_FELTS: usize = 1_536;
const OOD_PTR: u32 = 3_225_426_432;
const ALPHA_PTR: u32 = 1_000;
const RESULT_PTR: u32 = 2_000;

const INITIAL_SPONGE: [u64; 12] = [11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22];
const ALPHA: [u64; 2] = [3, 5];
const INITIAL_ACC: [u64; 2] = [7, 9];

fn source() -> String {
    let s = INITIAL_SPONGE;
    format!(
        r#"
        use miden::core::sys::pvm::ood_frames

        begin
            push.0.0.{alpha1}.{alpha0} push.{alpha_ptr} mem_storew_le dropw

            push.{acc1}.{acc0}.{alpha_ptr}.{ood_ptr}
            push.{c3}.{c2}.{c1}.{c0}
            push.{r1_3}.{r1_2}.{r1_1}.{r1_0}
            push.{r0_3}.{r0_2}.{r0_1}.{r0_0}
            exec.ood_frames::process_row_ood_evaluations

            push.{result_ptr} mem_storew_le dropw
            push.{result_ptr_plus_4} mem_storew_le dropw
            push.{result_ptr_plus_8} mem_storew_le dropw
            push.{result_ptr_plus_12} mem_store
            push.{result_ptr_plus_13} mem_store
            push.{result_ptr_plus_14} mem_store
            push.{result_ptr_plus_15} mem_store
        end
        "#,
        alpha0 = ALPHA[0],
        alpha1 = ALPHA[1],
        alpha_ptr = ALPHA_PTR,
        result_ptr = RESULT_PTR,
        result_ptr_plus_4 = RESULT_PTR + 4,
        result_ptr_plus_8 = RESULT_PTR + 8,
        result_ptr_plus_12 = RESULT_PTR + 12,
        result_ptr_plus_13 = RESULT_PTR + 13,
        result_ptr_plus_14 = RESULT_PTR + 14,
        result_ptr_plus_15 = RESULT_PTR + 15,
        acc0 = INITIAL_ACC[0],
        acc1 = INITIAL_ACC[1],
        ood_ptr = OOD_PTR,
        r0_0 = s[0],
        r0_1 = s[1],
        r0_2 = s[2],
        r0_3 = s[3],
        r1_0 = s[4],
        r1_1 = s[5],
        r1_2 = s[6],
        r1_3 = s[7],
        c0 = s[8],
        c1 = s[9],
        c2 = s[10],
        c3 = s[11],
    )
}

fn row() -> Vec<Felt> {
    (0..OOD_ROW_FELTS)
        .map(|i| Felt::from_u32((17 * i as u32 + 23) % 65_521))
        .collect()
}

#[test]
fn pvm_ood_hook_matches_memory_horner_and_transcript_oracles() {
    let row = row();
    let mut advice = AdviceStack::new();
    advice.append_for_adv_pipe(&row);

    let (output, _) = build_test!(&source(), &[], &advice)
        .execute_for_output()
        .expect("PVM OOD row hook must execute");

    for (i, expected) in row.iter().enumerate() {
        assert_eq!(
            read_memory_felt(&output, OOD_PTR + i as u32),
            *expected,
            "OOD felt {i} was not stored in wire order"
        );
    }
    assert_eq!(
        read_memory_felt(&output, RESULT_PTR + 12),
        Felt::from_u32(OOD_PTR + OOD_ROW_FELTS as u32),
        "OOD pointer did not advance by exactly one row"
    );

    let alpha = QuadFelt::new(ALPHA.map(Felt::new_unchecked));
    let expected_acc = row
        .as_chunks::<2>()
        .0
        .iter()
        .map(|coords| QuadFelt::new([coords[0], coords[1]]))
        .fold(QuadFelt::new(INITIAL_ACC.map(Felt::new_unchecked)), |acc, coefficient| {
            coefficient + alpha * acc
        });
    let expected_acc: &[Felt] = expected_acc.as_basis_coefficients_slice();
    assert_eq!(read_memory_felt(&output, RESULT_PTR + 14), expected_acc[0]);
    assert_eq!(read_memory_felt(&output, RESULT_PTR + 15), expected_acc[1]);

    let mut challenger =
        DuplexChallenger::<Felt, Poseidon2Permutation256, 12, 8>::new(Poseidon2Permutation256);
    challenger.sponge_state = INITIAL_SPONGE.map(Felt::new_unchecked);
    for block in row.as_chunks::<8>().0 {
        challenger.observe_slice(block);
    }
    for (i, expected) in challenger.sponge_state.iter().enumerate() {
        assert_eq!(
            read_memory_felt(&output, RESULT_PTR + i as u32),
            *expected,
            "transcript state differs at index {i}"
        );
    }
}
