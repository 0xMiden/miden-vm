use alloc::collections::BTreeMap;

use miden_core::{WORD_SIZE, Word};
use miden_stark::testing::fri_vectors::{EXTENSION_DEGREE, FOLD_ARITY, LOG_FOLD_ARITY};
use miden_utils_testing::{Felt, crypto::MerkleStore};

mod verifier_fri_e2f4;
use verifier_fri_e2f4::{FriResult, fri_prove_verify_fold4_ext2};

const ADVICE_LENGTH_PREFIXES: usize = 3; // queries, layers, and remainder

/// Elements per layer record: the commitment word followed by `[d_size, t_depth, a0, a1]`.
const LAYER_RECORD_WIDTH: usize = 2 * WORD_SIZE;

#[test]
fn fri_schedule_matches_rust_for_remainder_bounds_and_blowups() {
    use miden_core::field::TwoAdicField;
    use miden_stark::{
        pcs::PcsParams,
        testing::{canonical_domain, fri_final_poly_degree, fri_num_rounds},
    };

    use crate::helpers::{read_memory_felt, stark_constant};

    let helper = include_str!("../../../asm/pcs/fri/helper.masm")
        .replace("miden::core::pcs::fri::parameters", "test::parameters");
    let caller: Vec<u64> = (101..117).collect();
    let expected_stack: Vec<_> = caller.iter().copied().map(Felt::new_unchecked).collect();
    for log_final_degree in [3, 6, 7] {
        let max_coefficients = 1u32 << log_final_degree;
        let parameters = format!(
            "pub const LOG_FINAL_DEGREE = {log_final_degree}\n\
             pub const REMAINDER_MAX_COEFFICIENTS = {max_coefficients}"
        );
        for log_blowup in [3, 4, 5] {
            let params = PcsParams::new(log_blowup, 2, log_final_degree, 0, 0, 1, 0).unwrap();
            for log_height in log_final_degree - 1..=Felt::TWO_ADICITY as u8 - log_blowup {
                // Leave LDE metadata uninitialized: only the polynomial bound determines the
                // schedule.
                let source = format!(
                    "use test::helper
                     use {{LOG_TRACE_LENGTH_PTR}} from miden::core::stark::constants
                     begin
                         push.{log_height} mem_store.LOG_TRACE_LENGTH_PTR
                         exec.helper::generate_fri_parameters
                     end"
                );
                let (output, _) = build_test!(&source, &caller)
                    .with_module("test::parameters", parameters.clone())
                    .with_module("test::helper", helper.clone())
                    .execute_for_output()
                    .unwrap();
                assert_eq!(output.stack.get_num_elements(16), expected_stack);
                let domain = canonical_domain::<Felt>(log_height, log_blowup);
                for (name, expected) in [
                    ("NUM_FRI_LAYERS_PTR", fri_num_rounds(&params, &domain)),
                    ("REMAINDER_POLY_SIZE_PTR", fri_final_poly_degree(&params, &domain)),
                ] {
                    assert_eq!(
                        read_memory_felt(&output, stark_constant(name)).as_canonical_u64(),
                        expected as u64,
                        "{name}: log_height={log_height}, log_final_degree={log_final_degree}, log_blowup={log_blowup}"
                    );
                }
            }
        }
    }
}

/// The precomputed leaf frame must follow the native hash domain and FRI row encoding.
#[test]
fn fri_row_hash_frame_matches_native() {
    use std::sync::Arc;

    use miden_assembly::{ModuleParser, Path, ast::ConstantExpr, debuginfo::DefaultSourceManager};
    use miden_crypto::hash::eidos::{Eidos, domains::LMCS_LEAF};

    let module = ModuleParser::default()
        .parse_str(
            Some(Path::new("miden::core::pcs::fri::frie2f4")),
            include_str!("../../../asm/pcs/fri/frie2f4.masm"),
            Arc::new(DefaultSourceManager::default()),
        )
        .expect("FRI module parses");
    let constant = module
        .constants()
        .find(|c| c.name().as_str() == "FRI_ROW_HASH_INIT_CV")
        .expect("FRI row frame is declared");
    let ConstantExpr::Word(word) = &constant.value else {
        panic!("FRI row frame must be a word");
    };
    let encoded_len = u32::try_from(FOLD_ARITY * EXTENSION_DEGREE).unwrap();
    assert_eq!(Word::new(word.inner().0), Eidos::init_chaining_word(LMCS_LEAF, encoded_len));
}

const FRI_PREPROCESS_SOURCE: &str = "
    use {FRI_COM_PTR, FRI_QUERIES_ADDRESS_PTR} from miden::core::stark::constants
    use {LDE_DOMAIN_GENERATOR_PTR, REMAINDER_POLY_ADDRESS_PTR} from miden::core::stark::constants
    use {REMAINDER_POLY_SIZE_PTR} from miden::core::stark::constants
    use {REMAINDER_MAX_COEFFICIENTS} from miden::core::pcs::fri::parameters

    const MAX_FRI_QUERIES = 150
    const MAX_FRI_LAYERS = 32
    const MAX_FRI_REMAINDER_WORDS = REMAINDER_MAX_COEFFICIENTS // 2

    #! Copies a non-empty sequence of words from the advice stack into memory.
    #!
    #! Input:  [X, num_words - 1, write_ptr, ...]
    #! Output: [X, x, write_ptr + 4 * num_words, ...]
    proc store_advice_words
        push.1
        while.true
            adv_loadw
            dup.5
            u32wrapping_add.4
            swap.6
            mem_storew_le
            dup.4
            sub.1
            swap.5
            neq.0
        end
    end

    proc preprocess
        dup mem_store.LDE_DOMAIN_GENERATOR_PTR
        adv_push
        # => [num_queries, g, ...]
        dup u32gt.0 assert.err=\"number of FRI queries must be nonzero\"
        dup u32lte.MAX_FRI_QUERIES assert.err=\"number of FRI queries exceeds FRI workspace\"

        push.FRI_COM_PTR
        # => [layer_ptr, num_queries, g, ...]
        dup.1 mul.4 sub
        # => [query_ptr, num_queries, g, ...]
        dup mem_store.FRI_QUERIES_ADDRESS_PTR
        swap
        sub.1
        padw
        # => [X, num_query_words - 1, query_ptr, layer_ptr, g]
        exec.store_advice_words
        #=> [X, x, layer_ptr, g]

        drop
        #=> [X, layer_ptr, g]

        dup.4
        movdn.5
        #=> [X, layer_ptr, layer_ptr, g]

        adv_push
        dup u32lte.MAX_FRI_LAYERS assert.err=\"number of FRI layers exceeds FRI workspace\"

        dup push.0 neq
        if.true
            mul.2
            sub.1
            movdn.4
            #=> [X, num_layer_words - 1, layer_ptr, layer_ptr, g]

            exec.store_advice_words
            #=> [X, x, remainder_poly_ptr, layer_ptr, g]

            drop
        else
            drop
        end
        #=> [X, remainder_poly_ptr, layer_ptr, g]

        dup.4
        movdn.5
        #=> [X, remainder_poly_ptr, remainder_poly_ptr, layer_ptr, g]

        adv_push
        dup u32gt.0 assert.err=\"FRI remainder polynomial must be nonzero\"
        dup u32lte.MAX_FRI_REMAINDER_WORDS assert.err=\"FRI remainder polynomial exceeds FRI workspace\"

        dup mul.2 mem_store.REMAINDER_POLY_SIZE_PTR

        sub.1
        movdn.4
        #=> [X, num_remainder_words - 1, remainder_poly_ptr, remainder_poly_ptr, layer_ptr, g]

        exec.store_advice_words
        #=> [X, x, x, remainder_poly_ptr, layer_ptr, g]
        dropw drop drop
        #=> [remainder_poly_ptr, layer_ptr, g]

        mem_store.REMAINDER_POLY_ADDRESS_PTR
        drop drop
    end
";

#[test]
fn fri_verify_rejects_empty_query_region() {
    let source = "
        use miden::core::pcs::fri::frie2f4
        use {FRI_COM_PTR, FRI_QUERIES_ADDRESS_PTR} from miden::core::stark::constants
        use {LDE_DOMAIN_GENERATOR_PTR} from miden::core::stark::constants
        use {REMAINDER_POLY_ADDRESS_PTR} from miden::core::stark::constants
        use {REMAINDER_POLY_SIZE_PTR} from miden::core::stark::constants
        use {REMAINDER_HALF_COEFFICIENTS} from miden::core::pcs::fri::helper

        begin
            push.1 mem_store.LDE_DOMAIN_GENERATOR_PTR
            push.REMAINDER_HALF_COEFFICIENTS mem_store.REMAINDER_POLY_SIZE_PTR
            push.FRI_COM_PTR
            dup mem_store.REMAINDER_POLY_ADDRESS_PTR
            mem_store.FRI_QUERIES_ADDRESS_PTR
            exec.frie2f4::verify
        end
        ";

    let test = build_test!(source, &[]);
    expect_assert_error_code_from_msg!(test, "fri query region must be non-empty");
}

/// Everything needed to run `frie2f4::verify` on a freshly generated FRI proof.
struct FriTestData {
    source: String,
    domain_generator: u64,
    advice_stack: Vec<u64>,
    store: MerkleStore,
    advice_map: BTreeMap<Word, Vec<Felt>>,
    final_queries: Vec<[Felt; WORD_SIZE]>,
}

/// Generates a fold-4 FRI proof over a random polynomial of degree less than
/// `2^log_poly_degree` and packages it as the preprocess + verify program with its inputs.
fn build_fri_test(log_poly_degree: u8, log_blowup: u8) -> FriTestData {
    let source = format!(
        "{FRI_PREPROCESS_SOURCE}
        use miden::core::pcs::fri::frie2f4
        use miden::core::pcs::fri::helper
        use {{LOG_TRACE_LENGTH_PTR}} from miden::core::stark::constants

        begin
            exec.preprocess
            push.{log_poly_degree} mem_store.LOG_TRACE_LENGTH_PTR
            exec.helper::generate_fri_parameters
            exec.frie2f4::verify
        end
        "
    );

    let fri = fri_prove_verify_fold4_ext2(log_poly_degree, log_blowup);
    let depth = log_poly_degree
        .checked_add(log_blowup)
        .expect("FRI domain depth must fit in u8") as usize;
    let advice_stack = prepare_advice_stack(depth, log_blowup, &fri);

    let mut store = MerkleStore::new();
    for partial_tree in &fri.partial_trees {
        store.extend(partial_tree.inner_nodes());
    }

    FriTestData {
        source,
        domain_generator: fri.domain_generator,
        advice_stack,
        store,
        advice_map: BTreeMap::from_iter(fri.advice_maps),
        final_queries: fri.final_queries,
    }
}

#[rstest::rstest]
#[case::half(7)]
#[case::max(6)]
#[case::half_zero_layers(-1)]
#[case::max_zero_layers(0)]
fn fri_verifier_matches_rust(#[case] height_offset: i8, #[values(3, 4, 5)] log_blowup: u8) {
    use std::sync::{Arc, Mutex};

    use miden_core::events::EventName;
    use miden_processor::ProcessorState;

    let log_poly_degree = miden_air::vm::config::pcs_params()
        .log_final_degree()
        .checked_add_signed(height_offset)
        .unwrap();
    let mut t = build_fri_test(log_poly_degree, log_blowup);
    let caller: Vec<u64> = (101..116).collect();
    let stack: Vec<_> =
        core::iter::once(t.domain_generator).chain(caller.iter().copied()).collect();
    let advice_sentinel = 12345;
    t.advice_stack.push(advice_sentinel);
    let test =
        build_test!(&t.source, &stack, &t.advice_stack, t.store.clone(), t.advice_map.clone());
    let (output, _) = test.execute_for_output().expect("FRI proof must verify");

    // The caller values pass through overflow and become observable when verification returns.
    let mut expected: Vec<_> = caller.into_iter().map(Felt::new_unchecked).collect();
    expected.push(Felt::ZERO);
    assert_eq!(output.stack.get_num_elements(16), expected);
    assert_eq!(output.advice.stack(), [Felt::new_unchecked(advice_sentinel)]);
    test.check_constraints();

    let source = t.source.replace("use miden::core::pcs::fri::frie2f4", "use test::frie2f4");
    let module = include_str!("../../../asm/pcs/fri/frie2f4.masm");
    // Observe [poe_final, index_final, e0, e1] before either remainder check consumes it.
    let marker = "    sub\n    movup.2 drop";
    assert_eq!(module.matches(marker).count(), 2, "both remainder paths must be observed");
    let observed_module =
        module.replace(marker, &format!("    trace.event(\"test::fri_final_query\")\n{marker}"));
    for repeat_first in [false, true] {
        let module = if repeat_first {
            // Keep advancing the loop cursor, but verify the first query on every iteration.
            let load = "        movup.4\n        mem_loadw_le";
            assert_eq!(observed_module.matches(load).count(), 2);
            observed_module.replace(load,
                "        movup.4 drop\n        mem_load.FRI_QUERIES_ADDRESS_PTR\n        mem_loadw_le")
        } else {
            observed_module.clone()
        };
        let actual = Arc::new(Mutex::new(Vec::<[Felt; WORD_SIZE]>::new()));
        let captured = actual.clone();
        let test =
            build_test!(&source, &stack, &t.advice_stack, t.store.clone(), t.advice_map.clone())
                .with_module("test::frie2f4", module)
                .with_trace_handler(
                    EventName::new("test::fri_final_query"),
                    move |state: &ProcessorState| {
                        // Two trace-event IDs and two remainder pointers precede the query word.
                        captured.lock().unwrap().push(state.get_stack_word(4).into());
                        Ok(())
                    },
                );
        test.execute_for_output().expect("each selected query is valid");
        let actual = actual.lock().unwrap();
        assert_eq!(
            actual.len(),
            t.final_queries.len(),
            "every query must reach the remainder check"
        );
        if repeat_first {
            assert!(actual.iter().all(|query| *query == t.final_queries[0]));
            assert_ne!(
                *actual, t.final_queries,
                "the Rust comparison must detect a repeated query"
            );
        } else {
            assert_eq!(*actual, t.final_queries, "final FRI queries differ from Rust");
        }
    }
}

#[rstest::rstest]
#[case::half_zero(true, 0, [11, 13])]
#[case::half_non_u32(true, Felt::ORDER - 1, [8, 8])]
#[case::max_zero(false, 0, [11, 13])]
#[case::max_non_u32(false, Felt::ORDER - 1, [8, 8])]
fn fri_query_evaluates_remainder_without_query_layers(
    #[case] half: bool,
    #[case] point: u64,
    #[case] expected: [u64; 2],
) {
    use crate::helpers::{read_memory_felt, stark_constant};

    const REMAINDER_PTR: u32 = 100_000;
    let max = 1u32 << miden_air::vm::config::pcs_params().log_final_degree();
    let remainder_size = if half { max / 2 } else { max };
    // Coefficients are in descending degree order. The last two are (3, 5) and (11, 13),
    // so evaluation at a base-field point x gives (3x + 11, 5x + 13).
    let linear_ptr = REMAINDER_PTR + (remainder_size - 2) * EXTENSION_DEGREE as u32;
    let [e0, e1] = expected;
    let variant = if half { "half" } else { "max" };
    let source = format!(
        "use {{TMP1_PTR, TMP2_PTR}} from miden::core::stark::constants
        use miden::core::pcs::fri::frie2f4

        begin
            push.13.11.5.3 mem_storew_le.{linear_ptr} dropw

            push.94.93.92.91 mem_storew_le.TMP2_PTR dropw
            push.0.0.TMP2_PTR.{REMAINDER_PTR} mem_storew_le.TMP1_PTR dropw
            push.{REMAINDER_PTR}.{REMAINDER_PTR}.{e1}.{e0}.0.{point}
            exec.frie2f4::verify_query_{variant}
            dropw dropw dropw
        end"
    );
    let caller: Vec<u64> = (101..117).collect();
    let advice = [12345];
    let test = build_test!(&source, &caller, &advice);
    let (output, _) = test.execute_for_output().expect("remainder query must verify");
    assert_eq!(
        output.stack.get_num_elements(16),
        caller.into_iter().map(Felt::new_unchecked).collect::<Vec<_>>()
    );
    assert_eq!(output.advice.stack(), advice.map(Felt::new_unchecked));
    let point_ptr = stark_constant("TMP2_PTR");
    for (lane, value) in [point, 0, 0, 0].into_iter().enumerate() {
        assert_eq!(read_memory_felt(&output, point_ptr + lane as u32), Felt::new_unchecked(value));
    }
    test.check_constraints();
}

/// A tampered remainder coefficient must make verification fail: the Horner evaluation of the
/// remainder polynomial no longer matches the folded query values.
#[rstest::rstest]
#[case::half(7)]
#[case::max(6)]
fn fri_fold4_ext2_rejects_tampered_remainder(
    #[case] height_offset: u8,
    #[values(3, 4, 5)] log_blowup: u8,
) {
    let log_poly_degree = miden_air::vm::config::pcs_params().log_final_degree() + height_offset;
    let t = build_fri_test(log_poly_degree, log_blowup);
    // Changing the constant coefficient isolates each final equality check.
    for lane in 0..EXTENSION_DEGREE {
        let mut advice_stack = t.advice_stack.clone();
        let index = advice_stack.len() - EXTENSION_DEGREE + lane;
        advice_stack[index] += 1;
        let test = build_test!(
            &t.source,
            &[t.domain_generator],
            &advice_stack,
            t.store.clone(),
            t.advice_map.clone()
        );
        assert!(test.execute().is_err(), "tampered remainder coordinate {lane} was accepted");
    }
}

/// A tampered opened row must make verification fail: the row no longer hashes to the
/// authenticated Merkle leaf.
#[rstest::rstest]
fn fri_fold4_ext2_rejects_tampered_leaf(#[values(3, 4, 5)] log_blowup: u8) {
    let log_poly_degree = miden_air::vm::config::pcs_params().log_final_degree() + 7;
    let t = build_fri_test(log_poly_degree, log_blowup);
    for lane in 0..FOLD_ARITY * EXTENSION_DEGREE {
        let mut advice_map = t.advice_map.clone();
        advice_map.first_entry().unwrap().get_mut()[lane] += Felt::ONE;
        let test = build_test!(
            &t.source,
            &[t.domain_generator],
            &t.advice_stack,
            t.store.clone(),
            advice_map
        );
        expect_assert_error_code_from_msg!(test, "FRI layer leaf hash mismatch");
    }
}

fn prepare_advice_stack(depth: usize, log_blowup: u8, fri: &FriResult) -> Vec<u64> {
    assert!(fri.remainder.len().is_multiple_of(WORD_SIZE), "remainder must be word-aligned");
    assert_eq!(
        fri.alphas.len(),
        fri.commitments.len(),
        "each layer must have one folding challenge"
    );

    let domain_size = 1u64
        .checked_shl(u32::try_from(depth).expect("domain depth must fit in u32"))
        .expect("domain depth must fit in u64");
    let advice_length = ADVICE_LENGTH_PREFIXES
        + fri.queries.len() * WORD_SIZE
        + fri.commitments.len() * LAYER_RECORD_WIDTH
        + fri.remainder.len();
    let mut stack = Vec::with_capacity(advice_length);

    stack.push(fri.queries.len() as u64);

    for query in &fri.queries {
        let [e0, e1] = query.evaluation;
        // The VM represents each query as the word [g^p, p, e0, e1].
        let query_word: [u64; WORD_SIZE] = [query.domain_generator_power, query.position, e0, e1];
        stack.extend_from_slice(&query_word);
    }

    stack.push(fri.commitments.len() as u64);

    let mut current_domain_size = domain_size;
    let mut current_depth = depth as u64;

    for (commitment, alpha) in fri.commitments.iter().zip(&fri.alphas) {
        current_domain_size /= FOLD_ARITY as u64;
        current_depth = current_depth
            .checked_sub(LOG_FOLD_ARITY.into())
            .expect("too many FRI layers for the domain");

        stack.extend_from_slice(commitment);
        // The VM loads this metadata as the word [d_size, t_depth, a0, a1].
        stack.extend_from_slice(&[current_domain_size, current_depth]);
        stack.extend_from_slice(alpha);
    }

    let remainder_coefficients = fri.remainder.len() / EXTENSION_DEGREE;
    assert_eq!(
        current_domain_size,
        (remainder_coefficients as u64) << log_blowup,
        "folded domain size must match the remainder degree and blowup"
    );

    stack.push((fri.remainder.len() / WORD_SIZE) as u64);
    for word in fri.remainder.as_chunks::<WORD_SIZE>().0 {
        stack.extend_from_slice(word);
    }

    assert_eq!(stack.len(), advice_length, "advice stack must match the computed layout");

    stack
}
