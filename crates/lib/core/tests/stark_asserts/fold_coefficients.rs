use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
};
use miden_processor::ExecutionOutput;

use super::read_memory;
use crate::helpers::read_memory_felt;

/// Base offset, in felts from the relation's stark-vars base, of AIR 0's selector triple.
const FIRST_SELECTOR_OFFSET: u32 = 20;
/// Felts per AIR in the selector block (three EF-valued selectors).
const SELECTOR_STRIDE: u32 = 6;

/// Written either side of the coefficient block; staging must leave both intact.
const FOLD_SENTINEL: u64 = 0xdead_beef;
/// Values parked under the fold walk so its operand-stack neutrality is observable directly.
const FOLD_STACK_SENTINELS: [u64; 4] = [8_001, 8_002, 8_003, 8_004];
const FOLD_STACK_SENTINEL_PTR: u32 = 1_100;

/// Exposes the generated evaluator's private staging procedure in a test module.
/// Its body is unchanged, and its layout accessors resolve to the production relation.
fn production_fold_staging_module(relation: &str, evaluator_source: &str) -> String {
    const HEADER: &str = "proc stage_air_fold_coefficients";
    let start = evaluator_source
        .find(HEADER)
        .unwrap_or_else(|| panic!("{relation}: the evaluator declares no fold staging"));
    let body = &evaluator_source[start + HEADER.len()..];
    let end = body.find("\nend").expect("the fold staging procedure ends") + "\nend".len();
    format!(
        "use {{
            CONSTRAINT_COMPOSITION_COEFS_PTR, LOG_AIR_TRACE_LENGTHS_PTR
        }} from miden::core::stark::constants\nuse miden::core::sys::{relation}::layout\n\n\
         pub {HEADER}{}\n",
        &body[..end]
    )
}

/// One relation's fold-coefficient staging under test.
struct FoldRelation {
    /// Layout, evaluator, and proof-order modules below `miden::core::sys`.
    relation: &'static str,
    num_airs: usize,
    stark_vars_ptr: u32,
    /// The checked-in generated evaluator, whose private staging procedure is under test.
    evaluator: &'static str,
}

impl FoldRelation {
    fn vm() -> Self {
        Self {
            relation: "vm",
            num_airs: miden_air::vm::MIDEN_AIR_COUNT,
            stark_vars_ptr: crate::stark::vm_layout_const("AUXILIARY_ACE_INPUTS_PTR"),
            evaluator: include_str!("../../asm/sys/vm/constraints_eval.masm"),
        }
    }

    fn pvm() -> Self {
        Self {
            relation: "pvm",
            num_airs: miden_air::precompiles::NUM_CHIPLETS,
            stark_vars_ptr: crate::stark::pvm_layout_const("AUXILIARY_ACE_INPUTS_PTR"),
            evaluator: include_str!("../../asm/sys/pvm/constraints_eval.masm"),
        }
    }

    /// The test program with the production staging attached as `test::fold`.
    fn test(&self, heights: &[u64], beta: (u64, u64)) -> miden_utils_testing::Test {
        let source = self.source(heights, beta);
        let mut test = build_test!(source.as_str(), &[]);
        test.add_module(
            "test::fold",
            production_fold_staging_module(self.relation, self.evaluator),
        );
        test
    }

    fn block_start(&self) -> u32 {
        self.stark_vars_ptr + FIRST_SELECTOR_OFFSET + SELECTOR_STRIDE * self.num_airs as u32
    }

    /// Program: store `heights`, seed `beta`, stage the proof-order maps, guard the coefficient
    /// block with sentinels, then run the generated walk.
    fn source(&self, heights: &[u64], beta: (u64, u64)) -> String {
        let relation = self.relation;
        let num_airs = self.num_airs;
        let (beta0, beta1) = beta;
        let mut source = format!(
            "use {{
                CONSTRAINT_COMPOSITION_COEFS_PTR, LOG_AIR_TRACE_LENGTHS_PTR
            }} from miden::core::stark::constants
             use miden::core::sys::{relation}::ood_frames
             use test::fold
             begin\n"
        );
        for (i, height) in heights.iter().enumerate() {
            let offset = if i == 0 { String::new() } else { format!(" add.{i}") };
            source +=
                &format!("    push.{height} push.LOG_AIR_TRACE_LENGTHS_PTR{offset} mem_store\n");
        }
        source += &format!(
            "    push.{beta0} push.CONSTRAINT_COMPOSITION_COEFS_PTR add.2 mem_store\n    \
             push.{beta1} push.CONSTRAINT_COMPOSITION_COEFS_PTR add.3 mem_store\n"
        );
        let start = self.block_start();
        for addr in [start - 1, start + 2 * num_airs as u32] {
            source += &format!("    push.{FOLD_SENTINEL} push.{addr} mem_store\n");
        }
        let stack = FOLD_STACK_SENTINELS;
        source += &format!(
            "    exec.ood_frames::stage_proof_order_maps\n    \
             push.{s3}.{s2}.{s1}.{s0}\n    \
             exec.fold::stage_air_fold_coefficients\n    \
             push.{FOLD_STACK_SENTINEL_PTR} mem_storew_le dropw\n\
             end",
            s0 = stack[0],
            s1 = stack[1],
            s2 = stack[2],
            s3 = stack[3],
        );
        source
    }
}

/// AIR `k`'s rank in the stable height-sorted proof order.
fn proof_order_positions(heights: &[u64]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..heights.len()).collect();
    order.sort_by_key(|&i| (heights[i], i));
    let mut positions = vec![0; heights.len()];
    for (rank, &air) in order.iter().enumerate() {
        positions[air] = rank;
    }
    positions
}

fn quad_felt(c0: u64, c1: u64) -> QuadFelt {
    QuadFelt::new([
        Felt::new(c0).expect("coefficient is a valid field element"),
        Felt::new(c1).expect("coefficient is a valid field element"),
    ])
}

fn read_quad(output: &ExecutionOutput, addr: u32) -> QuadFelt {
    QuadFelt::new([read_memory_felt(output, addr), read_memory_felt(output, addr + 1)])
}

fn fold_height_cases(num_airs: usize) -> Vec<Vec<u64>> {
    let mut cases = vec![
        (10..10 + num_airs as u64).collect::<Vec<_>>(), // identity order
        (10..10 + num_airs as u64).rev().collect::<Vec<_>>(), // reversed
        vec![12; num_airs],                             // all tied
    ];
    // Every adjacent transposition of the ascending order.
    for i in 0..num_airs - 1 {
        let mut heights: Vec<u64> = (10..10 + num_airs as u64).collect();
        heights.swap(i, i + 1);
        cases.push(heights);
    }
    // Block ties and a scramble, cut to the relation's size.
    for template in [
        [12u64, 12, 11, 11, 13, 13, 12, 11, 13, 12, 11, 13],
        [9u64, 14, 9, 22, 7, 14, 25, 6, 14, 9, 22, 7],
        [20u64, 6, 19, 7, 18, 8, 17, 9, 16, 10, 15, 11],
    ] {
        cases.push(template[..num_airs].to_vec());
    }
    if num_airs == 4 {
        // All 24 orders of the four VM AIRs.
        let mut order: Vec<usize> = (0..4).collect();
        loop {
            let mut heights = vec![0u64; 4];
            for (position, &air) in order.iter().enumerate() {
                heights[air] = 10 + position as u64;
            }
            cases.push(heights);
            let Some(pivot) = (0..3).rev().find(|&i| order[i] < order[i + 1]) else {
                break;
            };
            let successor = (pivot + 1..4).rev().find(|&j| order[j] > order[pivot]).unwrap();
            order.swap(pivot, successor);
            order[pivot + 1..].reverse();
        }
    }
    cases.sort();
    cases.dedup();
    cases
}

fn assert_fold_staging_case(relation: &FoldRelation, heights: &[u64], beta_value: (u64, u64)) {
    assert_eq!(heights.len(), relation.num_airs, "every AIR must have a fixture height");
    let beta = quad_felt(beta_value.0, beta_value.1);
    let (output, _) = relation
        .test(heights, beta_value)
        .execute_for_output()
        .unwrap_or_else(|err| panic!("{}: staging must execute: {err}", relation.relation));

    let staged = relation.block_start();
    for (k, position) in proof_order_positions(heights).into_iter().enumerate() {
        let mut expected = QuadFelt::ONE;
        for _ in 0..(heights.len() - 1 - position) {
            expected *= beta;
        }
        let addr = staged + 2 * k as u32;
        assert_eq!(
            read_quad(&output, addr),
            expected,
            "{}: AIR {k} of {heights:?} sits at proof position {position}",
            relation.relation
        );
    }

    for addr in [staged - 1, staged + 2 * relation.num_airs as u32] {
        assert_eq!(
            read_memory(&output, addr),
            FOLD_SENTINEL,
            "{}: staging wrote outside the coefficient block of {heights:?}",
            relation.relation
        );
    }
    for (offset, expected) in FOLD_STACK_SENTINELS.into_iter().enumerate() {
        assert_eq!(
            read_memory(&output, FOLD_STACK_SENTINEL_PTR + offset as u32),
            expected,
            "{}: staging disturbed operand-stack slot {offset} for {heights:?}",
            relation.relation
        );
    }
}

/// AIR k receives beta^(num_airs - 1 - pos_k), where pos_k is its height-sorted proof position.
/// Memory guards and caller values must survive staging.
#[test]
fn stage_air_fold_coefficients_places_beta_powers_by_proof_order_position() {
    const BETA: (u64, u64) = (7, 3);

    for relation in [FoldRelation::vm(), FoldRelation::pvm()] {
        for heights in fold_height_cases(relation.num_airs) {
            assert_fold_staging_case(&relation, &heights, BETA);
        }
    }
}

/// A zero challenge gives the last AIR coefficient one (0^0) and all earlier coefficients zero.
/// A tied, non-identity order checks that this follows proof position in both relations.
#[test]
fn stage_air_fold_coefficients_handles_zero_beta() {
    for relation in [FoldRelation::vm(), FoldRelation::pvm()] {
        let heights: Vec<_> = (0..relation.num_airs).map(|air| 12 - (air % 3) as u64).collect();
        let positions = proof_order_positions(&heights);
        assert_ne!(
            positions,
            (0..relation.num_airs).collect::<Vec<_>>(),
            "{}: the zero-beta fixture must have a non-identity order",
            relation.relation
        );
        let mut distinct = heights.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert!(
            distinct.len() < heights.len(),
            "{}: the zero-beta fixture must exercise the stable tie break",
            relation.relation
        );

        assert_fold_staging_case(&relation, &heights, (0, 0));
    }
}

/// The staging offsets must agree with the canonical Rust ACE layout for every supported AIR count.
#[test]
fn stage_air_fold_coefficients_offset_matches_the_canonical_ace_layout() {
    use miden_ace::{EXT_DEGREE, InputCounts, InputKey, InputLayout};

    let counts = InputCounts {
        preprocessed_width: 0,
        width: 1,
        aux_width: 1,
        num_aux_boundary: 3,
        num_public: 8,
        num_randomness: 2,
        num_quotient_chunks: 1,
    };

    for num_airs in 2..=miden_ace::MAX_ORDER_AIRS {
        let layout = InputLayout::new_masm_multi_air(counts, num_airs);
        let stark_base = layout.index(InputKey::Alpha).expect("alpha starts the stark-vars block");
        for k in 0..num_airs {
            let coeff = layout
                .index(InputKey::MultiAirFoldCoeff(k))
                .expect("canonical layout has per-AIR fold coefficients");
            let layout_offset = (coeff - stark_base) * EXT_DEGREE;
            let masm_offset = FIRST_SELECTOR_OFFSET as usize
                + SELECTOR_STRIDE as usize * num_airs
                + EXT_DEGREE * k;
            assert_eq!(
                layout_offset, masm_offset,
                "canonical fold coefficient {k} of {num_airs} AIRs is staged off-slot"
            );
        }
    }
}
