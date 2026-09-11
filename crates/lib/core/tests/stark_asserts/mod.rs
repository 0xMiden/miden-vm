// ---- AIR context and validate_inputs tests ----
//
// The VM wrapper validates AIR shape before calling the generic verifier. The generic
// validate_inputs procedure only checks memory-resident security parameters.

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
};
use miden_processor::ExecutionOutput;

use crate::{
    helpers::read_memory_felt,
    support::security::{
        LOG_HEIGHT_MAX, MVM_LOG_HEIGHT_MIN, NUM_QUERIES_MAX, NUM_QUERIES_MIN, POW_BITS_MAX,
    },
};

const TRACE_LENGTH_LOG_PTR: u32 = 3223322634;
const AIR_TRACE_LENGTH_LOGS_PTR: u32 = 3223322744;
const OOD_EVALUATIONS_ADDRESS_PTR: u32 = 3223322770;
const CURRENT_TRACE_ROW_ADDRESS_PTR: u32 = 3223322771;

const VM_OOD_EVALUATIONS_PTR: u32 = 3225419784;
const VM_CURRENT_TRACE_ROW_PTR: u32 = 3238002688;

fn load_air_context_source() -> &'static str {
    "use miden::core::sys::vm
     begin
         exec.vm::load_air_context
     end"
}

fn read_memory(output: &ExecutionOutput, addr: u32) -> u64 {
    read_memory_felt(output, addr).as_canonical_u64()
}

fn execute_load_air_context(
    core_log_height: u64,
    chiplets_log_height: u64,
    eidos_compression_log_height: u64,
) -> ExecutionOutput {
    let (output, _) = build_test!(
        load_air_context_source(),
        &[],
        &[core_log_height, chiplets_log_height, eidos_compression_log_height],
    )
    .execute_for_output()
    .expect("load_air_context should execute");
    assert_eq!(output.stack.get_num_elements(16), &[Felt::ZERO; 16]);
    output
}

fn validate_inputs_source(
    num_queries: u64,
    query_pow_bits: u64,
    deep_pow_bits: u64,
    folding_pow_bits: u64,
) -> String {
    format!(
        "use miden::core::stark::utils
         use miden::core::stark::constants
         begin
             push.{num_queries} exec.constants::set_number_queries
             push.{query_pow_bits} exec.constants::set_query_pow_bits
             push.{deep_pow_bits} exec.constants::set_deep_pow_bits
             push.{folding_pow_bits} exec.constants::set_folding_pow_bits
             exec.utils::validate_inputs
         end"
    )
}

#[test]
fn load_air_context_core_trace_length_upper_bound() {
    let test = build_test!(load_air_context_source(), &[], &[LOG_HEIGHT_MAX + 1, 10, 10],);
    expect_assert_error_message!(test);
}

#[test]
fn load_air_context_core_trace_length_lower_bound() {
    let test = build_test!(load_air_context_source(), &[], &[MVM_LOG_HEIGHT_MIN - 1, 10, 10],);
    expect_assert_error_message!(test);
}

#[test]
fn load_air_context_chiplets_trace_length_upper_bound() {
    let test = build_test!(load_air_context_source(), &[], &[10, LOG_HEIGHT_MAX + 1, 10],);
    expect_assert_error_message!(test);
}

#[test]
fn load_air_context_chiplets_trace_length_lower_bound() {
    let test = build_test!(load_air_context_source(), &[], &[10, MVM_LOG_HEIGHT_MIN - 1, 10],);
    expect_assert_error_message!(test);
}

#[test]
fn load_air_context_eidos_compression_trace_length_upper_bound() {
    let test = build_test!(load_air_context_source(), &[], &[10, 10, LOG_HEIGHT_MAX + 1],);
    expect_assert_error_message!(test);
}

#[test]
fn load_air_context_eidos_compression_trace_length_lower_bound() {
    let test = build_test!(load_air_context_source(), &[], &[10, 10, MVM_LOG_HEIGHT_MIN - 1],);
    expect_assert_error_message!(test);
}

#[test]
fn load_air_context_accepts_trace_length_boundaries() {
    execute_load_air_context(MVM_LOG_HEIGHT_MIN, MVM_LOG_HEIGHT_MIN, MVM_LOG_HEIGHT_MIN);
    execute_load_air_context(LOG_HEIGHT_MAX, LOG_HEIGHT_MAX, LOG_HEIGHT_MAX);
}

#[test]
fn load_air_context_rejects_a_non_u32_trace_length() {
    let non_u32 = u64::from(u32::MAX) + 1;
    let test = build_test!(load_air_context_source(), &[], &[non_u32, 10, 10]);
    assert!(test.execute().is_err(), "a non-u32 AIR height must be rejected");
}

#[test]
fn load_air_context_stores_shape_and_max_height() {
    let output = execute_load_air_context(8, 10, 9);
    assert_eq!(read_memory(&output, AIR_TRACE_LENGTH_LOGS_PTR), 8);
    assert_eq!(read_memory(&output, AIR_TRACE_LENGTH_LOGS_PTR + 1), 10);
    assert_eq!(read_memory(&output, AIR_TRACE_LENGTH_LOGS_PTR + 2), 9);
    assert_eq!(read_memory(&output, AIR_TRACE_LENGTH_LOGS_PTR + 3), 16);
    assert_eq!(read_memory(&output, TRACE_LENGTH_LOG_PTR), 16);
    assert_eq!(read_memory(&output, OOD_EVALUATIONS_ADDRESS_PTR), VM_OOD_EVALUATIONS_PTR as u64);
    assert_eq!(
        read_memory(&output, CURRENT_TRACE_ROW_ADDRESS_PTR),
        VM_CURRENT_TRACE_ROW_PTR as u64
    );
}

#[test]
fn validate_inputs_accepts_num_query_boundaries() {
    for num_queries in [NUM_QUERIES_MIN, NUM_QUERIES_MAX] {
        let source = validate_inputs_source(num_queries, 0, 0, 16);
        build_test!(&source, &[])
            .execute()
            .unwrap_or_else(|err| panic!("num_queries={num_queries} must be accepted: {err}"));
    }
}

#[test]
fn validate_inputs_rejects_num_queries_outside_boundaries() {
    for (num_queries, message) in [
        (NUM_QUERIES_MIN - 1, "num_queries must be at least 7"),
        (NUM_QUERIES_MAX + 1, "num_queries must be at most 150"),
    ] {
        let source = validate_inputs_source(num_queries, 0, 0, 16);
        let test = build_test!(&source, &[]);
        expect_assert_error_code_from_msg!(test, message);
    }
}

#[test]
fn validate_inputs_pow_bit_bounds() {
    for (name, valid, invalid, message) in [
        (
            "query_pow_bits",
            [POW_BITS_MAX, 0, 0],
            [POW_BITS_MAX + 1, 0, 0],
            "query_pow_bits must be less than 32",
        ),
        (
            "deep_pow_bits",
            [0, POW_BITS_MAX, 0],
            [0, POW_BITS_MAX + 1, 0],
            "deep_pow_bits must be less than 32",
        ),
        (
            "folding_pow_bits",
            [0, 0, POW_BITS_MAX],
            [0, 0, POW_BITS_MAX + 1],
            "folding_pow_bits must be less than 32",
        ),
    ] {
        let [query, deep, folding] = valid;
        let source = validate_inputs_source(27, query, deep, folding);
        build_test!(&source, &[])
            .execute()
            .unwrap_or_else(|err| panic!("{name}={POW_BITS_MAX} must be accepted: {err}"));

        let [query, deep, folding] = invalid;
        let source = validate_inputs_source(27, query, deep, folding);
        let test = build_test!(&source, &[]);
        expect_assert_error_code_from_msg!(test, message);
    }
}

#[test]
fn validate_inputs_rejects_non_u32_security_parameters() {
    let non_u32 = u64::from(u32::MAX) + 1;
    for [num_queries, query, deep, folding] in [
        [non_u32, 0, 0, 0],
        [27, non_u32, 0, 0],
        [27, 0, non_u32, 0],
        [27, 0, 0, non_u32],
    ] {
        let source = validate_inputs_source(num_queries, query, deep, folding);
        let test = build_test!(&source, &[]);
        assert!(test.execute().is_err(), "a non-u32 security parameter must be rejected");
    }
}

// ---- init_seed tests ----
//
// init_seed expects:
//   Memory: num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits, relation digest,
//           and trace-height metadata.

#[test]
fn init_seed_trace_length_too_large_has_message() {
    // log(trace_length) = 32 overflows u32 in init_seed's `pow2` step.
    let source = "
        use miden::core::stark::constants
        use miden::core::stark::random_coin
        begin
            push.32 exec.constants::set_trace_length_log
            push.0.0.0.0 exec.constants::relation_digest_ptr mem_storew_le dropw
            exec.random_coin::init_seed
        end
    ";
    let test = build_test!(source, &[]);
    expect_assert_error_message!(test);
}

#[test]
fn check_pow_invalid_has_message() {
    // Store query_pow_bits = 16 so check_pow actually exercises the PoW path.
    // Use a valid trace height so init_seed succeeds.
    // The advice nonce (0) will fail the PoW check.
    let source = "
        use miden::core::stark::random_coin
        use miden::core::stark::constants
        begin
            push.27 exec.constants::set_number_queries
            push.16 exec.constants::set_query_pow_bits
            push.0  exec.constants::set_deep_pow_bits
            push.16 exec.constants::set_folding_pow_bits
            push.10 exec.constants::set_trace_length_log
            push.0.0.0.0 exec.constants::relation_digest_ptr mem_storew_le dropw
            exec.random_coin::init_seed
            exec.random_coin::check_query_pow
        end
    ";
    let advice_stack = &[0_u64];
    let test = build_test!(source, &[], advice_stack);
    expect_assert_error_message!(test);
}

// ---- canonical fold-coefficient staging ----
//
// The multi-AIR fold is a Horner accumulation over the height-sorted proof order, so the
// coefficient staged for AIR k is beta^(num_airs - 1 - pos_k) with `pos_k` that AIR's *proof
// position*, not its instance index. Each relation's generated evaluator stages the block by
// walking the `id_by_pos` map from the last proof position to the first; the tests here pin that
// walk against the Rust power oracle.

/// Base offset, in felts from the relation's stark-vars base, of AIR 0's selector triple.
const FIRST_SELECTOR_OFFSET: u32 = 22;
/// Felts per AIR in the selector block (three EF-valued selectors).
const SELECTOR_STRIDE: u32 = 6;

/// Written either side of the coefficient block; staging must leave both intact.
const FOLD_SENTINEL: u64 = 0xdead_beef;
/// Values parked under the fold walk so its operand-stack neutrality is observable directly.
const FOLD_STACK_SENTINELS: [u64; 4] = [8_001, 8_002, 8_003, 8_004];
const FOLD_STACK_SENTINEL_PTR: u32 = 1_100;

/// Wraps a relation's generated, evaluator-private `stage_air_fold_coefficients` as a public
/// procedure of a test module, so tests execute the exact production text without widening the
/// production module's surface.
///
/// `evaluator_source` is the checked-in `sys/<relation>/constraints_eval.masm`; `relation` is
/// the `sys` submodule the procedure's `layout` accessors resolve against.
fn production_fold_staging_module(relation: &str, evaluator_source: &str) -> String {
    const HEADER: &str = "proc stage_air_fold_coefficients";
    let start = evaluator_source
        .find(HEADER)
        .unwrap_or_else(|| panic!("{relation}: the evaluator declares no fold staging"));
    let body = &evaluator_source[start + HEADER.len()..];
    let end = body.find("\nend").expect("the fold staging procedure ends") + "\nend".len();
    format!(
        "use miden::core::stark::constants\nuse miden::core::sys::{relation}::layout\n\n\
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
            num_airs: miden_air::MIDEN_AIR_COUNT,
            stark_vars_ptr: crate::stark::vm_layout_const("AUXILIARY_ACE_INPUTS_PTR"),
            evaluator: include_str!("../../asm/sys/vm/constraints_eval.masm"),
        }
    }

    fn pvm() -> Self {
        Self {
            relation: "pvm",
            num_airs: 10,
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

    fn block_start(&self, base: u32) -> u32 {
        base + FIRST_SELECTOR_OFFSET + SELECTOR_STRIDE * self.num_airs as u32
    }

    /// Program: store `heights`, seed `beta`, stage the proof-order maps, guard the coefficient
    /// block with sentinels, then run the generated walk.
    fn source(&self, heights: &[u64], beta: (u64, u64)) -> String {
        let relation = self.relation;
        let num_airs = self.num_airs;
        let (beta0, beta1) = beta;
        let mut source = format!(
            "use miden::core::stark::constants
             use miden::core::sys::{relation}::ood_frames
             use test::fold
             begin\n"
        );
        for (i, height) in heights.iter().enumerate() {
            let offset = if i == 0 { String::new() } else { format!(" add.{i}") };
            source += &format!(
                "    push.{height} exec.constants::air_trace_length_logs_ptr{offset} mem_store\n"
            );
        }
        source += &format!(
            "    push.{beta0} exec.constants::composition_coef_ptr add.2 mem_store\n    \
             push.{beta1} exec.constants::composition_coef_ptr add.3 mem_store\n"
        );
        let start = self.block_start(self.stark_vars_ptr);
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
        vec![12u64, 12, 11, 11, 13, 13, 12, 11, 13, 12],
        vec![9u64, 14, 9, 22, 7, 14, 25, 6, 14, 9],
        vec![20u64, 6, 19, 7, 18, 8, 17, 9, 16, 10],
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
    let beta = quad_felt(beta_value.0, beta_value.1);
    let (output, _) = relation
        .test(heights, beta_value)
        .execute_for_output()
        .unwrap_or_else(|err| panic!("{}: staging must execute: {err}", relation.relation));

    let staged = relation.block_start(relation.stark_vars_ptr);
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

/// The generated walk must place `beta^(num_airs - 1 - pos_k)` at AIR k's slot, keyed by proof
/// position rather than instance index, and write nothing outside the block. The production text
/// is executed verbatim through a test-module wrapper, since the procedure is private to its
/// evaluator.
#[test]
fn stage_air_fold_coefficients_places_beta_powers_by_proof_order_position() {
    const BETA: (u64, u64) = (7, 3);

    for relation in [FoldRelation::vm(), FoldRelation::pvm()] {
        for heights in fold_height_cases(relation.num_airs) {
            assert_fold_staging_case(&relation, &heights, BETA);
        }
    }
}

/// Zero is a valid extension-field challenge value even though it occurs only with negligible
/// probability. The reverse walk must still assign `0^0 = 1` to the AIR opened last and zero to
/// every earlier AIR. Exercise one tied, non-identity order per relation without repeating the
/// full nonzero-beta matrix above.
#[test]
fn stage_air_fold_coefficients_handles_zero_beta() {
    for (relation, heights) in [
        (FoldRelation::vm(), vec![12, 10, 12, 11]),
        (FoldRelation::pvm(), vec![12, 12, 11, 11, 13, 13, 12, 11, 13, 12]),
    ] {
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

/// The MASM staging address must land on the canonical layout's `MultiAirFoldCoeff` slot.
///
/// The generated evaluator addresses the block at `FIRST_SELECTOR_OFFSET + SELECTOR_STRIDE *
/// num_airs` and the Rust side allocates it right after the selector block; nothing else forces
/// the two to agree, so a change to either side's slot arithmetic would otherwise be caught only
/// by a full recursive proof.
#[test]
fn stage_air_fold_coefficients_offset_matches_the_canonical_ace_layout() {
    use miden_ace_codegen::{EXT_DEGREE, InputCounts, InputKey, InputLayout};

    let counts = InputCounts {
        preprocessed_width: 0,
        width: 1,
        aux_width: 1,
        num_aux_boundary: 3,
        num_public: 8,
        num_randomness: 2,
        num_quotient_chunks: 1,
    };

    for num_airs in 2..=miden_ace_codegen::MAX_ORDER_AIRS {
        let layout = InputLayout::new_masm_canonical_multi_air(counts, num_airs);
        let first_selector = layout
            .index(InputKey::IsFirstAir(0))
            .expect("canonical layout has per-AIR selectors");
        for k in 0..num_airs {
            let coeff = layout
                .index(InputKey::MultiAirFoldCoeff(k))
                .expect("canonical layout has per-AIR fold coefficients");
            let layout_offset =
                FIRST_SELECTOR_OFFSET as usize + (coeff - first_selector) * EXT_DEGREE;
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

/// Every fixed verifier-memory region must be declared, disjoint, and correctly sized.
///
/// The memory map is split across the generic module and per-relation layouts, so no
/// single file shows every address claim: a generic constant added at an address a
/// relation already uses would assemble cleanly and corrupt that relation's state at run
/// time. Both sides therefore share this semantic manifest.
///
/// Comparing start addresses is not enough — a constant landing *inside* a multi-felt
/// region collides just as badly — so every fixed address declaration has an explicit,
/// fail-closed extent below. Both sides are expanded to intervals before comparison.
#[test]
fn verifier_memory_layout_is_complete_dense_and_disjoint() {
    use std::{
        collections::BTreeMap,
        path::{Path, PathBuf},
        sync::Arc,
    };

    use miden_assembly::{
        ModuleParser, Path as MasmPath, PathBuf as MasmPathBuf,
        ast::{
            ConstantExpr, Ident,
            constants::{
                ConstEnvironment, ConstEvalError,
                eval::{self, CachedConstantValue},
            },
        },
        debuginfo::{DefaultSourceManager, SourceFile, SourceSpan, Span},
    };

    const FRI_QUERY_REGION_SIZE: u64 = NUM_QUERIES_MAX * 4;
    const FRI_FORWARD_REGION_SIZE: u64 = 512;

    /// `(name, offset from the declared address, extent in felts)`.
    ///
    /// Every address declaration must occur exactly once. There is deliberately no
    /// one-felt default: forgetting an entry is a test failure, not an under-claim.
    const GENERIC_REGIONS: &[(&str, i64, u64)] = &[
        ("DOMAIN_OFFSET_PTR", 0, 1),
        ("DOMAIN_OFFSET_INV_PTR", 0, 1),
        ("LDE_DOMAIN_INFO_PTR", 0, 4),
        ("LDE_DOMAIN_SIZE_PTR", 0, 1),
        ("LDE_DOMAIN_LOG_SIZE_PTR", 0, 1),
        ("LDE_DOMAIN_GEN_PTR", 0, 1),
        ("NUM_QUERIES_PTR", 0, 1),
        ("REMAINDER_POLY_SIZE_PTR", 0, 1),
        ("NUM_FRI_LAYERS_PTR", 0, 1),
        ("REMAINDER_POLY_ADDRESS_PTR", 0, 1),
        ("TRACE_LENGTH_PTR", 0, 1),
        ("FRI_QUERIES_ADDRESS_PTR", 0, 1),
        ("TRACE_LENGTH_LOG_PTR", 0, 1),
        ("MAIN_TRACE_COM_PTR", 0, 4),
        ("AUX_TRACE_COM_PTR", 0, 4),
        ("COMPOSITION_POLY_COM_PTR", 0, 4),
        ("Z_PTR", 0, 4),
        ("ZERO_WORD_PTR", 0, 4),
        ("ALPHA_DEEP_ND_PTR", 0, 4),
        ("OOD_FIXED_TERM_HORNER_EVALS_PTR", 0, 4),
        ("RANDOM_COIN_CV_PTR", 0, 4),
        ("RANDOM_COIN_OUTPUT_WORD_PTR", 0, 4),
        ("RANDOM_COIN_INPUT_BUF_PTR", 0, 8),
        ("TRACE_DOMAIN_GENERATOR_PTR", 0, 1),
        ("PUBLIC_INPUTS_ADDRESS_PTR", 0, 1),
        ("FRI_VERIFY_STATE_PTR", 0, 4),
        ("TMP1", 0, 4),
        ("TMP2", 0, 4),
        ("TMP3", 0, 4),
        ("TMP4", 0, 4),
        ("COMPOSITION_COEF_PTR", 0, 4),
        ("DEEP_RAND_CC_PTR", 0, 4),
        ("NUM_FIXED_LEN_PUBLIC_INPUTS_PTR", 0, 1),
        ("NUM_ACE_INPUTS_PTR", 0, 1),
        ("NUM_ACE_GATES_PTR", 0, 1),
        ("MAX_CYCLE_LEN_LOG_PTR", 0, 1),
        ("QUERY_POW_BITS_PTR", 0, 1),
        ("DEEP_POW_BITS_PTR", 0, 1),
        ("FOLDING_POW_BITS_PTR", 0, 1),
        ("DYNAMIC_PROCEDURE_0_PTR", 0, 4),
        ("DYNAMIC_PROCEDURE_1_PTR", 0, 4),
        ("DYNAMIC_PROCEDURE_2_PTR", 0, 4),
        ("DYNAMIC_PROCEDURE_3_PTR", 0, 4),
        ("DYNAMIC_PROCEDURE_4_PTR", 0, 4),
        ("RANDOM_COIN_INPUT_LEN_PTR", 0, 1),
        ("RANDOM_COIN_OUTPUT_LEN_PTR", 0, 1),
        ("OOD_EVALUATIONS_ADDRESS_PTR", 0, 1),
        ("CURRENT_TRACE_ROW_ADDRESS_PTR", 0, 1),
        ("GENERIC_RESERVED_CELL_PTR", 0, 1),
        ("AIR_TRACE_LENGTH_LOGS_PTR", 0, 16),
        ("RELATION_DIGEST_PTR", 0, 4),
        ("GENERIC_RESERVED_WORD_PTR", 0, 4),
        ("PREPROCESSED_TRACE_COM_PTR", 0, 4),
        ("RANDOM_COIN_COUNTER_PTR", 0, 1),
        ("AUXILIARY_ACE_INPUTS_ADDRESS_PTR", 0, 1),
        ("AUX_RAND_ELEM_ADDRESS_PTR", 0, 1),
        ("GENERIC_ALIGNMENT_PADDING_PTR", 0, 2),
        // One word per accepted query grows backward; FRI layers and the remainder grow forward.
        (
            "FRI_COM_PTR",
            -(FRI_QUERY_REGION_SIZE as i64),
            FRI_QUERY_REGION_SIZE + FRI_FORWARD_REGION_SIZE,
        ),
    ];

    // These declarations name fields inside LDE_DOMAIN_INFO_PTR rather than distinct storage.
    const GENERIC_ALIASES: &[&str] =
        &["LDE_DOMAIN_SIZE_PTR", "LDE_DOMAIN_LOG_SIZE_PTR", "LDE_DOMAIN_GEN_PTR"];

    const GENERIC_FRAME_START: u64 = 3_223_322_624;
    const GENERIC_FRAME_END: u64 = 3_223_322_776;
    const VM_FRAME_END: u64 = 3_223_323_864;
    const VM_ACE_READ_START: u64 = 3_225_419_776;
    const PVM_FRAME_START: u64 = 3_225_432_064;

    #[derive(Clone, Copy, Debug)]
    enum RegionExtent {
        Fixed(u64),
        Until(&'static str),
        UntilAddress(u64),
        FractionOf {
            start: &'static str,
            end: &'static str,
            divisor: u64,
        },
    }
    use RegionExtent::{Fixed, FractionOf, Until, UntilAddress};

    /// `(path below asm/sys, name, offset from the declared address, extent)`.
    ///
    /// Pointer-delimited extents keep the manifest tied to generated AIR geometry. New
    /// relation-owned addresses must still be listed explicitly, including one-felt cells.
    const RELATION_REGIONS: &[(&str, &str, i64, RegionExtent)] = &[
        ("pvm/layout.masm", "PUBLIC_INPUTS_PTR", 0, Until("AUX_RAND_ELEM_PTR")),
        ("pvm/layout.masm", "AUX_RAND_ELEM_PTR", 0, Until("PREPROCESSED_CURRENT_PTR")),
        ("pvm/layout.masm", "PREPROCESSED_CURRENT_PTR", 0, Until("MAIN_CURRENT_PTR")),
        ("pvm/layout.masm", "MAIN_CURRENT_PTR", 0, Until("AUX_CURRENT_PTR")),
        ("pvm/layout.masm", "AUX_CURRENT_PTR", 0, Until("QUOTIENT_CURRENT_PTR")),
        ("pvm/layout.masm", "QUOTIENT_CURRENT_PTR", 0, Until("PREPROCESSED_NEXT_PTR")),
        ("pvm/layout.masm", "PREPROCESSED_NEXT_PTR", 0, Until("MAIN_NEXT_PTR")),
        ("pvm/layout.masm", "MAIN_NEXT_PTR", 0, Until("AUX_NEXT_PTR")),
        ("pvm/layout.masm", "AUX_NEXT_PTR", 0, Until("QUOTIENT_NEXT_PTR")),
        ("pvm/layout.masm", "QUOTIENT_NEXT_PTR", 0, Until("AUX_BUS_BOUNDARY_PTR")),
        ("pvm/layout.masm", "AUX_BUS_BOUNDARY_PTR", 0, Until("AUXILIARY_ACE_INPUTS_PTR")),
        (
            "pvm/layout.masm",
            "AUXILIARY_ACE_INPUTS_PTR",
            0,
            Until("ACE_CIRCUIT_STREAM_PTR"),
        ),
        ("pvm/layout.masm", "ACE_CIRCUIT_STREAM_PTR", 0, Until("BUS_GAMMA_PTR")),
        ("pvm/layout.masm", "BUS_GAMMA_PTR", 0, Until("C_TOTAL_PTR")),
        ("pvm/layout.masm", "C_TOTAL_PTR", 0, Until("CURRENT_TRACE_ROW_PTR")),
        ("pvm/layout.masm", "CURRENT_TRACE_ROW_PTR", 0, Until("PREPROCESSED_COM_PTR")),
        ("pvm/layout.masm", "PREPROCESSED_COM_PTR", 0, Fixed(4)),
        (
            "pvm/layout.masm",
            "OOD_SCATTER_TABLE_PTR",
            0,
            Until("PROOF_ORDER_POSITIONS_PTR"),
        ),
        // Ten live position cells plus two alignment cells, followed by one ID per proof position.
        ("pvm/layout.masm", "PROOF_ORDER_POSITIONS_PTR", 0, Until("PROOF_ORDER_IDS_PTR")),
        ("pvm/layout.masm", "PROOF_ORDER_IDS_PTR", 0, Fixed(10)),
        ("vm/layout.masm", "NUM_KERNEL_PROCEDURES_PTR", 0, Fixed(1)),
        ("vm/layout.masm", "CONTROL_ALIGNMENT_PADDING_PTR", 0, Fixed(3)),
        ("vm/layout.masm", "BUS_GAMMA_PTR", 0, Fixed(4)),
        ("vm/layout.masm", "C_TOTAL_PTR", 0, Fixed(4)),
        ("vm/layout.masm", "CLAIM_COMMITMENT_PTR", 0, Fixed(4)),
        ("vm/layout.masm", "CLAIM_PTR", 0, Fixed(40)),
        ("vm/layout.masm", "BOUNDARY_ANCHOR_PADDING_PTR", 0, Fixed(4)),
        ("vm/layout.masm", "BOUNDARY_INPUTS_PTR", 0, Fixed(8)),
        ("vm/layout.masm", "KERNEL_WITNESS_PTR", 0, Fixed(1020)),
        // Out-of-domain scatter table: row base, per-position dispatch pairs, and the `pipe_k`
        // digests, followed by the two proof-order maps inside the same 64-felt reserve. Sits
        // immediately after the VM control frame, so it is outside the tiling above.
        ("vm/layout.masm", "OOD_SCATTER_TABLE_PTR", 0, Until("PROOF_ORDER_POSITIONS_PTR")),
        ("vm/layout.masm", "PROOF_ORDER_POSITIONS_PTR", 0, Until("PROOF_ORDER_IDS_PTR")),
        ("vm/layout.masm", "PROOF_ORDER_IDS_PTR", 0, Fixed(4)),
        // Includes the alignment word before OOD_EVALUATIONS_PTR.
        ("vm/layout.masm", "AUX_RAND_ELEM_PTR", 0, Fixed(8)),
        ("vm/layout.masm", "OOD_EVALUATIONS_PTR", 0, Until("AUX_BUS_BOUNDARY_PTR")),
        ("vm/layout.masm", "AUX_BUS_BOUNDARY_PTR", 0, Fixed(8)),
        ("vm/layout.masm", "AUXILIARY_ACE_INPUTS_PTR", 0, Fixed(56)),
        // Fixed VM stream reservation ending at the PVM allocation.
        ("vm/layout.masm", "ACE_CIRCUIT_STREAM_PTR", 0, UntilAddress(PVM_FRAME_START)),
        (
            "vm/layout.masm",
            "CURRENT_TRACE_ROW_PTR",
            0,
            FractionOf {
                start: "OOD_EVALUATIONS_PTR",
                end: "AUX_BUS_BOUNDARY_PTR",
                // The OOD allocation contains current and next rows, with every scalar
                // evaluation represented by EXT_DEGREE base-field coordinates.
                divisor: 2 * miden_ace_codegen::EXT_DEGREE as u64,
            },
        ),
    ];

    #[derive(Debug)]
    struct Region {
        source: String,
        name: String,
        lo: u64,
        hi: u64,
    }

    struct LocalConstantEnv<'a> {
        constants: BTreeMap<String, &'a ConstantExpr>,
    }

    impl ConstEnvironment for LocalConstantEnv<'_> {
        type Error = ConstEvalError;

        fn get_source_file_for(&self, _span: SourceSpan) -> Option<Arc<SourceFile>> {
            None
        }

        fn get(&mut self, name: &Ident) -> Result<Option<CachedConstantValue<'_>>, Self::Error> {
            Ok(self.constants.get(name.as_str()).copied().map(CachedConstantValue::Miss))
        }

        fn get_by_path(
            &mut self,
            path: Span<&MasmPath>,
        ) -> Result<Option<CachedConstantValue<'_>>, Self::Error> {
            match path.as_ident() {
                Some(name) => self.get(&name),
                None => Ok(None),
            }
        }
    }

    /// Semantically evaluated fixed-memory declarations in a MASM module.
    ///
    /// MASM constants may be expressions (`const NEW_PTR = OLD_PTR + 1`), so this uses
    /// the semantic constant evaluator rather than text parsing. Anything numeric that remains
    /// unresolved fails closed instead of escaping the manifest.
    /// Relation layout modules are address-only, so every numeric constant in them is included.
    /// Elsewhere, pointer-named constants are included at any address; other numeric constants
    /// are treated as addresses only in the verifier's high 32-bit address band.
    fn declarations(path: &Path) -> Vec<(String, u64)> {
        let address_only_module = path.file_name().is_some_and(|name| name == "layout.masm");
        let module_path: MasmPathBuf =
            "audit::layout".parse().expect("valid synthetic module path");
        let mut parser = ModuleParser::default();
        let module = parser
            .parse_file(Some(&module_path), path, Arc::new(DefaultSourceManager::default()))
            .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

        let mut env = LocalConstantEnv {
            constants: module
                .constants()
                .map(|constant| (constant.name().as_str().to_string(), &constant.value))
                .collect(),
        };
        module
            .constants()
            .filter_map(|constant| {
                let value = eval::expr(&constant.value, &mut env).unwrap_or_else(|err| {
                    panic!("failed to evaluate {}:{}: {err}", path.display(), constant.name())
                });
                match value {
                    ConstantExpr::Int(value) => {
                        let value = value.inner().as_int();
                        let name = constant.name().as_str();
                        let pointer_name = name.ends_with("_PTR")
                            || matches!(name, "TMP1" | "TMP2" | "TMP3" | "TMP4");
                        (address_only_module
                            || pointer_name
                            || ((1 << 31)..=u32::MAX as u64).contains(&value))
                        .then(|| (name.to_string(), value))
                    },
                    ConstantExpr::String(_) | ConstantExpr::Word(_) | ConstantExpr::Hash(..) => {
                        None
                    },
                    ConstantExpr::Var(_) | ConstantExpr::BinaryOp { .. } => panic!(
                        "{}:{} has an unevaluated numeric constant expression",
                        path.display(),
                        constant.name()
                    ),
                }
            })
            .collect()
    }

    fn region(source: &str, name: String, address: u64, offset: i64, felts: u64) -> Region {
        assert!(felts > 0, "{source}:{name} has an empty region");
        let lo = if offset < 0 {
            address.checked_sub(offset.unsigned_abs())
        } else {
            address.checked_add(offset as u64)
        }
        .unwrap_or_else(|| panic!("{source}:{name} region start overflows"));
        let hi = lo
            .checked_add(felts - 1)
            .unwrap_or_else(|| panic!("{source}:{name} region end overflows"));
        Region { source: source.to_string(), name, lo, hi }
    }

    fn collect_masm_files(dir: &Path, files: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("MASM directory is readable") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                collect_masm_files(&path, files);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("masm") {
                files.push(path);
            }
        }
    }

    fn overlaps(a: &Region, b: &Region) -> bool {
        a.lo <= b.hi && b.lo <= a.hi
    }

    fn assert_disjoint(regions: &[&Region], label: &str) {
        for (index, region) in regions.iter().enumerate() {
            if let Some(other) = regions[index + 1..].iter().find(|other| overlaps(region, other)) {
                panic!(
                    "{label} region {}:{} ({}..={}) overlaps {}:{} ({}..={})",
                    region.source,
                    region.name,
                    region.lo,
                    region.hi,
                    other.source,
                    other.name,
                    other.lo,
                    other.hi
                );
            }
        }
    }

    fn assert_tiled_frame(regions: &[&Region], source: &str, frame_start: u64, frame_end: u64) {
        let mut frame_regions = Vec::new();
        for region in regions.iter().filter(|region| region.source == source) {
            if region.lo < frame_end && frame_start <= region.hi {
                assert!(
                    frame_start <= region.lo && region.hi < frame_end,
                    "{}:{} crosses the {} frame boundary",
                    region.source,
                    region.name,
                    source
                );
                frame_regions.push(*region);
            }
        }
        frame_regions.sort_unstable_by_key(|region| region.lo);

        let mut next = frame_start;
        for region in frame_regions {
            assert_eq!(
                region.lo, next,
                "gap before {}:{} in the {} frame",
                region.source, region.name, source
            );
            next = region.hi.checked_add(1).expect("frame address overflows");
        }
        assert_eq!(next, frame_end, "{source} frame does not end at its declared boundary");
    }

    let base = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/asm"));
    let generic_path = base.join("stark/constants.masm");
    let generic_declarations = declarations(&generic_path);
    assert!(!generic_declarations.is_empty(), "the generic layer must declare addresses");

    let mut generic_manifest: BTreeMap<&str, (i64, u64)> = BTreeMap::new();
    for &(name, offset, felts) in GENERIC_REGIONS {
        assert!(
            generic_manifest.insert(name, (offset, felts)).is_none(),
            "duplicate generic region manifest entry: {name}"
        );
    }
    let mut generic_regions = Vec::new();
    for (name, address) in generic_declarations {
        let (offset, felts) = generic_manifest
            .remove(name.as_str())
            .unwrap_or_else(|| panic!("unmanifested generic address: {name}"));
        generic_regions.push(region("stark/constants.masm", name, address, offset, felts));
    }
    assert!(
        generic_manifest.is_empty(),
        "generic region manifest entries have no declaration: {:?}",
        generic_manifest.keys().collect::<Vec<_>>()
    );

    let sys = base.join("sys");
    let mut relation_files = Vec::new();
    collect_masm_files(&sys, &mut relation_files);
    relation_files.sort();

    let mut relation_manifest: BTreeMap<(String, String), (i64, RegionExtent)> = BTreeMap::new();
    for &(source, name, offset, extent) in RELATION_REGIONS {
        assert!(
            relation_manifest
                .insert((source.to_string(), name.to_string()), (offset, extent))
                .is_none(),
            "duplicate relation region manifest entry: {source}:{name}"
        );
    }

    let mut relation_declarations = BTreeMap::new();
    for path in relation_files {
        let source = path
            .strip_prefix(&sys)
            .expect("relation module is below asm/sys")
            .to_string_lossy()
            .replace('\\', "/");
        let mut source_declarations = BTreeMap::new();
        for (name, address) in declarations(&path) {
            assert!(
                source_declarations.insert(name.clone(), address).is_none(),
                "duplicate relation address declaration: {source}:{name}"
            );
        }
        if !source_declarations.is_empty() {
            assert!(
                relation_declarations.insert(source.clone(), source_declarations).is_none(),
                "relation source visited twice: {source}"
            );
        }
    }

    let extent_between =
        |source: &str, declarations: &BTreeMap<String, u64>, start: &str, end: &str| {
            let start_address = declarations
                .get(start)
                .unwrap_or_else(|| panic!("{source} is missing extent boundary {start}"));
            let end_address = declarations
                .get(end)
                .unwrap_or_else(|| panic!("{source} is missing extent boundary {end}"));
            end_address
                .checked_sub(*start_address)
                .unwrap_or_else(|| panic!("{source}:{end} precedes {start}"))
        };

    let mut relation_regions = Vec::new();
    for (source, declarations) in &relation_declarations {
        for (name, &address) in declarations {
            let (offset, extent) = relation_manifest
                .remove(&(source.clone(), name.clone()))
                .unwrap_or_else(|| panic!("unmanifested relation address: {source}:{name}"));
            let felts = match extent {
                Fixed(felts) => felts,
                Until(end) => extent_between(source, declarations, name, end),
                UntilAddress(end) => end
                    .checked_sub(address)
                    .unwrap_or_else(|| panic!("{source}:{name} begins after its frame boundary")),
                FractionOf { start, end, divisor } => {
                    assert_ne!(divisor, 0, "{source}:{name} has a zero extent divisor");
                    let span = extent_between(source, declarations, start, end);
                    assert_eq!(
                        span % divisor,
                        0,
                        "{source}:{name} source span is not divisible by {divisor}"
                    );
                    span / divisor
                },
            };
            relation_regions.push(region(source, name.clone(), address, offset, felts));
        }
    }
    assert!(
        relation_manifest.is_empty(),
        "relation region manifest entries have no declaration: {:?}",
        relation_manifest.keys().collect::<Vec<_>>()
    );

    for relation in &relation_regions {
        if let Some(generic) = generic_regions.iter().find(|generic| overlaps(relation, generic)) {
            panic!(
                "relation region {}:{} ({}..={}) overlaps generic region {}:{} ({}..={})",
                relation.source,
                relation.name,
                relation.lo,
                relation.hi,
                generic.source,
                generic.name,
                generic.lo,
                generic.hi
            );
        }
    }

    let canonical_generic_regions: Vec<_> = generic_regions
        .iter()
        .filter(|region| !GENERIC_ALIASES.contains(&region.name.as_str()))
        .collect();
    let relation_region_refs: Vec<_> = relation_regions.iter().collect();
    let pvm_frame_end = relation_regions
        .iter()
        .find(|region| region.source == "pvm/layout.masm" && region.name == "PROOF_ORDER_IDS_PTR")
        .and_then(|region| region.hi.checked_add(1))
        .expect("the terminal PVM proof-order-IDs region must define the frame end");

    assert_disjoint(&canonical_generic_regions, "generic");
    assert_disjoint(&relation_region_refs, "relation");

    let lde_info = generic_regions
        .iter()
        .find(|region| region.name == "LDE_DOMAIN_INFO_PTR")
        .expect("LDE domain info region is declared");
    for alias in GENERIC_ALIASES {
        let region = generic_regions
            .iter()
            .find(|region| region.name == *alias)
            .unwrap_or_else(|| panic!("missing generic alias: {alias}"));
        assert!(
            lde_info.lo <= region.lo && region.hi <= lde_info.hi,
            "{alias} must remain inside LDE_DOMAIN_INFO_PTR"
        );
    }

    assert_tiled_frame(
        &canonical_generic_regions,
        "stark/constants.masm",
        GENERIC_FRAME_START,
        GENERIC_FRAME_END,
    );
    assert_tiled_frame(&relation_region_refs, "vm/layout.masm", GENERIC_FRAME_END, VM_FRAME_END);
    assert_tiled_frame(&relation_region_refs, "vm/layout.masm", VM_ACE_READ_START, PVM_FRAME_START);
    assert_tiled_frame(&relation_region_refs, "pvm/layout.masm", PVM_FRAME_START, pvm_frame_end);

    let kernel_witness = relation_regions
        .iter()
        .find(|region| region.source == "vm/layout.masm" && region.name == "KERNEL_WITNESS_PTR")
        .expect("VM kernel witness region is declared");
    assert_eq!(
        kernel_witness.hi - kernel_witness.lo + 1,
        (miden_core::program::KernelDescriptor::MAX_NUM_PROCEDURES * 4) as u64,
        "the VM kernel witness must hold the maximum number of procedure digests"
    );
}

/// The relation's named height setters must write consecutive cells of the generic
/// per-AIR array, in canonical instance order.
///
/// `stage_proof_order_maps` and `set_up_auxiliary_inputs_ace` both index that array as
/// `base + k`, so a gap or a reordered offset would silently feed one AIR's height in
/// another's place.
#[test]
fn relation_height_setters_write_the_generic_array_in_order() {
    let source = "use miden::core::sys::vm::layout
     begin
         push.11 exec.layout::set_core_trace_length_log
         push.22 exec.layout::set_chiplets_trace_length_log
         push.33 exec.layout::set_eidos_compression_trace_length_log
         push.44 exec.layout::set_and8_lookup_trace_length_log
     end";
    let (output, _) =
        build_test!(source, &[]).execute_for_output().expect("setters should execute");
    assert_eq!(read_memory(&output, AIR_TRACE_LENGTH_LOGS_PTR), 11, "core at offset 0");
    assert_eq!(read_memory(&output, AIR_TRACE_LENGTH_LOGS_PTR + 1), 22, "chiplets at offset 1");
    assert_eq!(
        read_memory(&output, AIR_TRACE_LENGTH_LOGS_PTR + 2),
        33,
        "Eidos compression at offset 2"
    );
    assert_eq!(
        read_memory(&output, AIR_TRACE_LENGTH_LOGS_PTR + 3),
        44,
        "And8 lookup at offset 3"
    );
}

/// The map must reserve at least as many height cells as the largest supported relation, so a
/// relation is never silently truncated by the memory map.
#[test]
fn height_array_capacity_covers_the_supported_air_count() {
    // 13! exceeds the u32 tag space, so a relation is capped at 12 AIRs. The reserved extent is
    // pinned against the declaration itself by
    // `verifier_memory_layout_is_complete_dense_and_disjoint`.
    const RESERVED_HEIGHT_CELLS: usize = 16;
    const { assert!(miden_ace_codegen::MAX_ORDER_AIRS <= RESERVED_HEIGHT_CELLS) };
}

/// `load_air_context` documents no stack effect. Compare against a no-op program run with the
/// same operands: values the caller keeps below the wrapper's advice-driven inputs must
/// survive, which pins the store helpers' drop accounting.
#[test]
fn vm_wrapper_preserves_the_caller_stack() {
    const SENTINELS: [u64; 8] = [16_201, 16_202, 16_203, 16_204, 16_205, 16_206, 16_207, 16_208];
    let source = "use miden::core::sys::vm
        begin
            exec.vm::load_air_context
        end";

    let (control, _) = build_test!("begin push.0 drop end", &SENTINELS)
        .execute_for_output()
        .expect("control program must run");
    let (subject, _) = build_test!(source, &SENTINELS, &[16, 16, 16])
        .execute_for_output()
        .expect("VM AIR context must load");

    assert_eq!(
        subject.stack.get_num_elements(16),
        control.stack.get_num_elements(16),
        "load_air_context must leave the caller stack unchanged"
    );
}
