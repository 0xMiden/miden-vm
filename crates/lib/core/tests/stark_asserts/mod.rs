// ---- AIR context and validate_inputs tests ----
//
// The VM wrapper validates AIR shape before calling the generic verifier. The generic
// validate_inputs procedure only checks memory-resident security parameters.

use miden_core::Felt;
use miden_processor::ExecutionOutput;
#[cfg(feature = "arbitrary")]
use miden_utils_testing::proptest::prelude::*;

use crate::helpers::read_memory_felt;

const TRACE_LENGTH_LOG_PTR: u32 = 3223322634;
const ORDER_TAG_PTR: u32 = 3223322639;
const AIR_TRACE_LENGTH_LOGS_PTR: u32 = 3223322736;
const OOD_EVALUATIONS_ADDRESS_PTR: u32 = 3223322761;
const CURRENT_TRACE_ROW_ADDRESS_PTR: u32 = 3223322762;

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
    poseidon2_log_height: u64,
) -> ExecutionOutput {
    let (output, _) = build_test!(
        load_air_context_source(),
        &[],
        &[core_log_height, chiplets_log_height, poseidon2_log_height],
    )
    .execute_for_output()
    .expect("load_air_context should execute");
    assert_eq!(output.stack.get_num_elements(16), &[Felt::ZERO; 16]);
    output
}

fn validate_inputs_source(
    num_queries: u32,
    query_pow_bits: u32,
    deep_pow_bits: u32,
    folding_pow_bits: u32,
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
    let test = build_test!(load_air_context_source(), &[], &[30, 10, 10]);
    expect_assert_error_message!(test);
}

#[test]
fn load_air_context_core_trace_length_lower_bound() {
    let test = build_test!(load_air_context_source(), &[], &[5, 10, 10]);
    expect_assert_error_message!(test);
}

#[test]
fn load_air_context_chiplets_trace_length_upper_bound() {
    let test = build_test!(load_air_context_source(), &[], &[10, 30, 10]);
    expect_assert_error_message!(test);
}

#[test]
fn load_air_context_chiplets_trace_length_lower_bound() {
    let test = build_test!(load_air_context_source(), &[], &[10, 5, 10]);
    expect_assert_error_message!(test);
}

#[test]
fn load_air_context_poseidon2_trace_length_upper_bound() {
    let test = build_test!(load_air_context_source(), &[], &[10, 10, 30]);
    expect_assert_error_message!(test);
}

#[test]
fn load_air_context_poseidon2_trace_length_lower_bound() {
    let test = build_test!(load_air_context_source(), &[], &[10, 10, 5]);
    expect_assert_error_message!(test);
}

#[test]
fn load_air_context_stores_shape_and_max_height() {
    let output = execute_load_air_context(8, 10, 9);
    assert_eq!(read_memory(&output, AIR_TRACE_LENGTH_LOGS_PTR), 8);
    assert_eq!(read_memory(&output, AIR_TRACE_LENGTH_LOGS_PTR + 1), 10);
    assert_eq!(read_memory(&output, AIR_TRACE_LENGTH_LOGS_PTR + 2), 9);
    assert_eq!(read_memory(&output, TRACE_LENGTH_LOG_PTR), 10);
    assert_eq!(read_memory(&output, OOD_EVALUATIONS_ADDRESS_PTR), VM_OOD_EVALUATIONS_PTR as u64);
    assert_eq!(
        read_memory(&output, CURRENT_TRACE_ROW_ADDRESS_PTR),
        VM_CURRENT_TRACE_ROW_PTR as u64
    );
}

#[test]
fn load_air_context_derives_proof_order_tags() {
    let cases = [
        ((8, 9, 10), 0), // Core, Chiplets, Poseidon2Permutation
        ((8, 10, 9), 1), // Core, Poseidon2Permutation, Chiplets
        ((9, 8, 10), 2), // Chiplets, Core, Poseidon2Permutation
        ((10, 8, 9), 3), // Chiplets, Poseidon2Permutation, Core
        ((9, 10, 8), 4), // Poseidon2Permutation, Core, Chiplets
        ((10, 9, 8), 5), // Poseidon2Permutation, Chiplets, Core
        ((8, 8, 8), 0),  // ties use instance order
        ((8, 8, 9), 0),  // partial tie: Core before Chiplets
        ((8, 9, 8), 1),  // partial tie: Core before Poseidon2Permutation
        ((9, 8, 8), 3),  // partial tie: Chiplets before Poseidon2Permutation
        ((9, 9, 8), 4),  // partial tie: Core before Chiplets after Poseidon2Permutation
        ((9, 8, 9), 2),  // partial tie: Core before Poseidon2Permutation after Chiplets
        ((8, 9, 9), 0),  // partial tie: Chiplets before Poseidon2Permutation
    ];

    for ((core, chiplets, poseidon2), expected_tag) in cases {
        let output = execute_load_air_context(core, chiplets, poseidon2);
        assert_eq!(read_memory(&output, ORDER_TAG_PTR), expected_tag);
    }
}

#[test]
fn validate_inputs_num_queries_upper_bound() {
    // num_queries = 151 must be rejected (must be < 151).
    let source = validate_inputs_source(151, 0, 0, 16);
    let test = build_test!(&source, &[]);
    expect_assert_error_message!(test);
}

#[test]
fn validate_inputs_num_queries_lower_bound() {
    // num_queries = 6 must be rejected (must be > 6).
    let source = validate_inputs_source(6, 0, 0, 16);
    let test = build_test!(&source, &[]);
    expect_assert_error_message!(test);
}

#[test]
fn validate_inputs_pow_bit_bounds() {
    for (name, valid, invalid, message) in [
        ("query_pow_bits", [31, 0, 0], [32, 0, 0], "query_pow_bits must be less than 32"),
        ("deep_pow_bits", [0, 31, 0], [0, 32, 0], "deep_pow_bits must be less than 32"),
        (
            "folding_pow_bits",
            [0, 0, 31],
            [0, 0, 32],
            "folding_pow_bits must be less than 32",
        ),
    ] {
        let [query, deep, folding] = valid;
        let source = validate_inputs_source(27, query, deep, folding);
        build_test!(&source, &[])
            .execute()
            .unwrap_or_else(|err| panic!("{name}=31 must be accepted: {err}"));

        let [query, deep, folding] = invalid;
        let source = validate_inputs_source(27, query, deep, folding);
        let test = build_test!(&source, &[]);
        expect_assert_error_code_from_msg!(test, message);
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

/// Program: store `n` advice heights at `ptr..ptr+n`, then derive the order tag with
/// the shared N-generic procedure.
fn derive_order_tag_source() -> &'static str {
    "use miden::core::stark::utils
     begin
         # => [ptr, n]; advice: [h_0, ..., h_{n-1}] in instance order
         push.0
         # => [i, ptr, n]
         dup.2 dup.1 u32gt
         while.true
             adv_push
             # => [h_i, i, ptr, n]
             dup.2 dup.2 add
             # => [ptr + i, h_i, i, ptr, n]
             mem_store
             add.1
             dup.2 dup.1 u32gt
         end
         drop swap
         # => [n, ptr]
         exec.utils::derive_order_tag_from_heights
         # => [tag]
     end"
}

fn expected_order_tag(heights: &[u64]) -> u64 {
    let mut order: Vec<usize> = (0..heights.len()).collect();
    order.sort_by_key(|&i| (heights[i], i));
    u64::from(miden_ace_codegen::order_tag(&order))
}

/// The generic MASM tag derivation must agree with the shared Rust Lehmer ranking
/// (`miden_ace_codegen::order_tag` over the stable height sort). Covers every supported AIR count,
/// structured N=10 orders and tie patterns, and the full N=3 case table also used to pin the VM's
/// fixed-count specialization.
#[test]
fn derive_order_tag_from_heights_matches_the_rust_ranking() {
    const PTR: u64 = 1000;

    let mut cases: Vec<Vec<u64>> = vec![
        vec![12, 12, 11, 11, 13, 13, 12, 11, 13, 12], // block ties
        vec![9, 14, 9, 22, 7, 14, 25, 6, 14, 9],      // mixed with repeated heights
        vec![20, 6, 19, 7, 18, 8, 17, 9, 16, 10],     // interleaved extremes
        vec![0, u32::MAX as u64, 1 << 31, 1, (1 << 31) - 1], // valid u32 boundaries
    ];
    // Descending and all-tie shapes exercise every supported AIR count. N=12 reversal exercises
    // factorial(11) and the maximum supported tag, 12! - 1.
    for num_airs in 2..=12u64 {
        cases.push((0..num_airs).rev().collect());
        cases.push(vec![12; num_airs as usize]);
    }
    // Every adjacent transposition of the ascending order.
    for i in 0..9u64 {
        let mut heights: Vec<u64> = (10..20).collect();
        heights.swap(i as usize, i as usize + 1);
        cases.push(heights);
    }
    // The N=3 table the VM-local `derive_order_tag` is pinned against.
    for (a, b, c) in [
        (8, 9, 10),
        (8, 10, 9),
        (9, 8, 10),
        (10, 8, 9),
        (9, 10, 8),
        (10, 9, 8),
        (8, 8, 8),
        (8, 8, 9),
        (8, 9, 8),
        (9, 8, 8),
        (9, 9, 8),
        (9, 8, 9),
        (8, 9, 9),
    ] {
        cases.push(vec![a, b, c]);
    }

    for heights in cases {
        let expected = expected_order_tag(&heights);
        let n = heights.len() as u64;
        let test = build_test!(derive_order_tag_source(), &[PTR, n], &heights);
        test.expect_stack(&[expected]);
    }

    // Sanity anchors, independent of the Rust reference.
    assert_eq!(expected_order_tag(&(10..20).collect::<Vec<_>>()), 0);
    assert_eq!(expected_order_tag(&(10..20).rev().collect::<Vec<_>>()), 3_628_799);
    assert_eq!(expected_order_tag(&(0..12).rev().collect::<Vec<_>>()), 479_001_599);
}

#[cfg(feature = "arbitrary")]
proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Sample duplicate-heavy and full-width u32 heights across the supported AIR-count range.
    #[test]
    fn derive_order_tag_from_heights_matches_random_stable_orders(
        heights in prop::collection::vec(
            prop_oneof![
                4 => 0_u64..8,
                1 => any::<u32>().prop_map(u64::from),
            ],
            2..13,
        ),
    ) {
        const PTR: u64 = 1000;
        let expected = expected_order_tag(&heights);
        let n = heights.len() as u64;
        build_test!(derive_order_tag_source(), &[PTR, n], &heights)
            .prop_expect_stack(&[expected])?;
    }
}

/// The shared derivation's u32 comparisons must reject an out-of-range height. A
/// caller that forgets its own shape assertion must trap here, not silently
/// mis-rank.
#[test]
fn derive_order_tag_from_heights_rejects_out_of_range_heights() {
    const PTR: u64 = 1000;
    for invalid_index in 0..2 {
        let mut heights = vec![7, 8];
        heights[invalid_index] = 1 << 32;
        let test = build_test!(derive_order_tag_source(), &[PTR, 2], &heights);
        let err = test.execute().expect_err("out-of-range height must trap");
        assert!(
            format!("{err:?}").contains("NotU32Values"),
            "expected a non-u32 operand failure, got: {err:?}"
        );
    }
}

/// The MASM order-tag limit must match the generic registry's supported AIR count.
#[test]
fn derive_order_tag_from_heights_matches_the_registry_air_limit() {
    const PTR: u64 = 1000;
    let max_airs = miden_ace_codegen::MAX_REGISTRY_AIRS;

    let heights: Vec<u64> = (0..max_airs as u64).collect();
    build_test!(derive_order_tag_source(), &[PTR, max_airs as u64], &heights)
        .execute()
        .expect("the registry's maximum AIR count must be supported");

    let oversized = max_airs + 1;
    let heights: Vec<u64> = (0..oversized as u64).collect();
    let test = build_test!(derive_order_tag_source(), &[PTR, oversized as u64], &heights);
    expect_assert_error_code_from_msg!(test, "num_airs exceeds supported order-tag range");
}

/// Relation evaluators must reject padding slots before opening their registry tree.
#[test]
fn relation_constraint_evaluators_reject_padding_order_tags() {
    for (relation, order_count) in [("vm", 6), ("pvm", 3_628_800)] {
        let source = format!(
            "use miden::core::stark::constants
             use miden::core::sys::{relation}::constraints_eval
             begin
                 push.{order_count} exec.constants::set_order_tag
                 push.8 exec.constants::set_trace_length_log
                 exec.constraints_eval::execute_constraint_evaluation_check
             end"
        );
        let test = build_test!(source, &[]);
        expect_assert_error_code_from_msg!(test, "invalid order tag");
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
        ("TRACE_DOMAIN_GENERATOR_PTR", 0, 1),
        ("PUBLIC_INPUTS_ADDRESS_PTR", 0, 1),
        ("FRI_VERIFY_STATE_PTR", 0, 4),
        ("C_PTR", 0, 4),
        ("R1_PTR", 0, 4),
        ("R2_PTR", 0, 4),
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
        ("ORDER_TAG_PTR", 0, 1),
        ("AIR_TRACE_LENGTH_LOGS_PTR", 0, 16),
        ("RELATION_DIGEST_PTR", 0, 4),
        ("ACE_REGISTRY_ROOT_PTR", 0, 4),
        ("GENERIC_ALIGNMENT_PADDING_PTR", 0, 1),
        // Query words grow backward; FRI layers and the remainder grow forward.
        ("FRI_COM_PTR", -600, 1112),
    ];

    // These declarations name fields inside LDE_DOMAIN_INFO_PTR rather than distinct storage.
    const GENERIC_ALIASES: &[&str] =
        &["LDE_DOMAIN_SIZE_PTR", "LDE_DOMAIN_LOG_SIZE_PTR", "LDE_DOMAIN_GEN_PTR"];

    const GENERIC_FRAME_START: u64 = 3_223_322_624;
    const GENERIC_FRAME_END: u64 = 3_223_322_764;
    const VM_FRAME_END: u64 = 3_223_323_864;
    const PVM_FRAME_START: u64 = 3_225_426_416;
    const PVM_FRAME_END: u64 = 3_225_444_180;

    /// `(path below asm/sys, name, offset from the declared address, extent in felts)`.
    /// New relation-owned addresses must be added here, including one-felt cells.
    const RELATION_REGIONS: &[(&str, &str, i64, u64)] = &[
        ("pvm/layout.masm", "PUBLIC_INPUTS_PTR", 0, 8),
        ("pvm/layout.masm", "AUX_RAND_ELEM_PTR", 0, 8),
        ("pvm/layout.masm", "PREPROCESSED_CURRENT_PTR", 0, 16),
        ("pvm/layout.masm", "MAIN_CURRENT_PTR", 0, 880),
        ("pvm/layout.masm", "AUX_CURRENT_PTR", 0, 624),
        ("pvm/layout.masm", "QUOTIENT_CURRENT_PTR", 0, 16),
        ("pvm/layout.masm", "PREPROCESSED_NEXT_PTR", 0, 16),
        ("pvm/layout.masm", "MAIN_NEXT_PTR", 0, 880),
        ("pvm/layout.masm", "AUX_NEXT_PTR", 0, 624),
        ("pvm/layout.masm", "QUOTIENT_NEXT_PTR", 0, 16),
        ("pvm/layout.masm", "AUX_BUS_BOUNDARY_PTR", 0, 20),
        ("pvm/layout.masm", "AUXILIARY_ACE_INPUTS_PTR", 0, 84),
        ("pvm/layout.masm", "ACE_CIRCUIT_STREAM_PTR", 0, 13792),
        ("pvm/layout.masm", "BUS_GAMMA_PTR", 0, 4),
        ("pvm/layout.masm", "C_TOTAL_PTR", 0, 4),
        ("pvm/layout.masm", "CURRENT_TRACE_ROW_PTR", 0, 768),
        ("pvm/layout.masm", "PREPROCESSED_COM_PTR", 0, 4),
        ("vm/layout.masm", "NUM_KERNEL_PROCEDURES_PTR", 0, 1),
        ("vm/layout.masm", "CONTROL_ALIGNMENT_PADDING_PTR", 0, 3),
        ("vm/layout.masm", "BUS_GAMMA_PTR", 0, 4),
        ("vm/layout.masm", "C_TOTAL_PTR", 0, 4),
        ("vm/layout.masm", "CLAIM_COMMITMENT_PTR", 0, 4),
        ("vm/layout.masm", "CLAIM_PTR", 0, 40),
        ("vm/layout.masm", "BOUNDARY_ANCHOR_PADDING_PTR", 0, 16),
        ("vm/layout.masm", "BOUNDARY_INPUTS_PTR", 0, 8),
        ("vm/layout.masm", "KERNEL_WITNESS_PTR", 0, 1020),
        // Includes the alignment word before OOD_EVALUATIONS_PTR.
        ("vm/layout.masm", "AUX_RAND_ELEM_PTR", 0, 8),
        ("vm/layout.masm", "OOD_EVALUATIONS_PTR", 0, 544),
        ("vm/layout.masm", "AUX_BUS_BOUNDARY_PTR", 0, 8),
        ("vm/layout.masm", "AUXILIARY_ACE_INPUTS_PTR", 0, 40),
        // Fixed VM stream reservation ending at the PVM allocation.
        ("vm/layout.masm", "ACE_CIRCUIT_STREAM_PTR", 0, 6040),
        ("vm/layout.masm", "CURRENT_TRACE_ROW_PTR", 0, 136),
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

    let mut relation_manifest: BTreeMap<(String, String), (i64, u64)> = BTreeMap::new();
    for &(source, name, offset, felts) in RELATION_REGIONS {
        assert!(
            relation_manifest
                .insert((source.to_string(), name.to_string()), (offset, felts))
                .is_none(),
            "duplicate relation region manifest entry: {source}:{name}"
        );
    }
    let mut relation_regions = Vec::new();
    for path in relation_files {
        let source = path
            .strip_prefix(&sys)
            .expect("relation module is below asm/sys")
            .to_string_lossy()
            .replace('\\', "/");
        for (name, address) in declarations(&path) {
            let (offset, felts) = relation_manifest
                .remove(&(source.clone(), name.clone()))
                .unwrap_or_else(|| panic!("unmanifested relation address: {source}:{name}"));
            relation_regions.push(region(&source, name, address, offset, felts));
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
    assert_tiled_frame(&relation_region_refs, "pvm/layout.masm", PVM_FRAME_START, PVM_FRAME_END);

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
/// `derive_order_tag_from_heights` and `set_up_auxiliary_inputs_ace` both index that
/// array as `base + k`, so a gap or a reordered offset would silently feed one AIR's
/// height in another's place.
#[test]
fn relation_height_setters_write_the_generic_array_in_order() {
    let source = "use miden::core::sys::vm::layout
     begin
         push.11 exec.layout::set_core_trace_length_log
         push.22 exec.layout::set_chiplets_trace_length_log
         push.33 exec.layout::set_poseidon2_permutation_trace_length_log
     end";
    let (output, _) =
        build_test!(source, &[]).execute_for_output().expect("setters should execute");
    assert_eq!(read_memory(&output, AIR_TRACE_LENGTH_LOGS_PTR), 11, "core at offset 0");
    assert_eq!(read_memory(&output, AIR_TRACE_LENGTH_LOGS_PTR + 1), 22, "chiplets at offset 1");
    assert_eq!(
        read_memory(&output, AIR_TRACE_LENGTH_LOGS_PTR + 2),
        33,
        "poseidon2_permutation at offset 2"
    );
}

/// The map must reserve at least as many height cells as a registry-backed relation can
/// use, so a relation is never silently truncated by the memory map.
#[test]
fn height_array_capacity_covers_the_supported_air_count() {
    // 13! exceeds the u32 tag space, so `RegistryLayout::new` caps a registry-backed
    // relation at 12 AIRs; the map reserves 16 cells.
    assert!(miden_ace_codegen::RegistryLayout::new(12, 1).is_some(), "12 AIRs supported");
    assert!(
        miden_ace_codegen::RegistryLayout::new(13, 1).is_none(),
        "13! overflows u32 tags"
    );
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
