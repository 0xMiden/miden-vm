//! Rust oracles for the MASM random coin and verifier parameters.

use miden_air::vm::config;
use miden_air_definitions::vm::trace::MIN_TRACE_LEN;
use miden_core::{
    Felt, Word,
    field::{
        BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64, QuadFelt, TwoAdicField,
    },
};
use miden_crypto::hash::eidos::EidosChallenger;
use miden_processor::ExecutionOutput;
use miden_stark::{
    StarkConfig,
    testing::{
        Coset, canonical_domain, fri_final_poly_degree, fri_num_rounds, sample_ood_point_and_next,
    },
    transcript::Channel,
};
use miden_vm_stark::setup::config::eidos_config;
use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

use crate::helpers::{
    masm_push_word, masm_store_felts, read_memory_felt, read_memory_word, stark_constant,
};

type Challenger = EidosChallenger;

const SAMPLES_PTR: u32 = 100_000;

/// Trace heights the recursive verifier supports, from the minimum trace length up to the largest
/// height whose LDE domain still has a two-adic generator.
fn supported_log_heights() -> core::ops::RangeInclusive<u8> {
    let log_blowup = config::pcs_params().log_blowup();
    let max = u8::try_from(Felt::TWO_ADICITY).expect("two-adicity fits in u8") - log_blowup;
    MIN_TRACE_LEN.ilog2() as u8..=max
}

fn random_felt(rng: &mut ChaCha20Rng) -> Felt {
    Felt::new_unchecked(rng.random_range(0..Felt::ORDER_U64))
}

fn random_word(rng: &mut ChaCha20Rng) -> [Felt; 4] {
    core::array::from_fn(|_| random_felt(rng))
}

/// Initializes the challenger and consumes a prefix of its first output word.
fn challenger_with(state: [Felt; 4], consumed: usize) -> Challenger {
    let mut challenger = Challenger::new(Word::from(state));
    for _ in 0..consumed {
        challenger.sample_felt();
    }
    challenger
}

/// Initializes the MASM challenger and consumes the same output prefix as `challenger_with`.
fn store_random_coin(state: &[Felt; 4], consumed: usize) -> String {
    format!(
        "
        {cv} mem_storew_le.RANDOM_COIN_CV_PTR dropw
        exec.random_coin::eidos_clear_buffer
        push.0 mem_store.RANDOM_COIN_COUNTER_PTR
        push.0 mem_store.RANDOM_COIN_OUTPUT_LENGTH_PTR
        {draws}
        ",
        cv = masm_push_word(&Word::from(*state)),
        draws = "exec.random_coin::sample_felt drop\n".repeat(consumed),
    )
}

const RANDOM_COIN_IMPORTS: &str = "
    use miden::core::stark::random_coin
    use {
        RANDOM_COIN_CV_PTR, RANDOM_COIN_COUNTER_PTR, RANDOM_COIN_OUTPUT_LENGTH_PTR
    } from miden::core::stark::constants
";

fn assert_random_coin_state(output: &ExecutionOutput, challenger: &Challenger, context: &str) {
    assert_eq!(
        read_memory_word(output, stark_constant("RANDOM_COIN_CV_PTR")),
        challenger.cv(),
        "{context}: chaining value"
    );
}

/// All persistent challenger cells, using the compiled verifier's memory layout.
pub(super) fn read_state(output: &ExecutionOutput) -> Vec<Felt> {
    [
        ("RANDOM_COIN_CV_PTR", 4),
        ("RANDOM_COIN_OUTPUT_WORD_PTR", 4),
        ("RANDOM_COIN_INPUT_BUF_PTR", 8),
        ("RANDOM_COIN_INPUT_LENGTH_PTR", 1),
        ("RANDOM_COIN_OUTPUT_LENGTH_PTR", 1),
        ("RANDOM_COIN_COUNTER_PTR", 1),
    ]
    .into_iter()
    .flat_map(|(name, width)| {
        let base = stark_constant(name);
        (0..width).map(move |offset| read_memory_felt(output, base + offset))
    })
    .collect()
}

/// `miden_crypto` does not re-export `CanSampleBits`, so it is reached through its
/// `FieldChallenger` supertrait.
fn sample_bits<C: FieldChallenger<Felt>>(challenger: &mut C, bits: usize) -> usize {
    challenger.sample_bits(bits)
}

// TRANSCRIPT SEQUENCES
// ================================================================================================

#[derive(Debug, Clone, Copy)]
enum Step {
    ObserveFelt(Felt),
    ObserveWord([Felt; 4]),
    ObserveWordAndFlush([Felt; 4]),
    ReseedDirect([Felt; 4]),
    FoldingPow {
        commitment: [Felt; 4],
        witness: Felt,
        bits: u8,
    },
    Flush,
    SampleFelt,
    SampleExt,
    SampleBits(u8),
}

/// MASM flushes pending input eagerly; Rust flushes on the next sample. Each buffered sequence
/// ends with a sample, so both sides have incorporated its input before the next observation.
fn boundary_steps(rng: &mut ChaCha20Rng, state: [Felt; 4]) -> Vec<Step> {
    let mut steps = Vec::new();

    // Exercise each pending-input length, including a word that crosses a full rate.
    for prefix_len in 0..8 {
        steps.extend((0..prefix_len).map(|_| Step::ObserveFelt(random_felt(rng))));
        steps.push(Step::ObserveWordAndFlush(random_word(rng)));
        steps.push(Step::SampleFelt);
    }

    steps.push(Step::ObserveWord(random_word(rng)));
    steps.extend((0..2).map(|_| Step::ObserveFelt(random_felt(rng))));
    steps.push(Step::ObserveFelt(random_felt(rng)));
    steps.push(Step::Flush);
    steps.push(Step::Flush); // Flushing an empty input buffer leaves the output untouched.
    steps.extend([
        Step::SampleExt,
        Step::SampleBits(1),
        Step::SampleBits(31),
        Step::SampleExt,
        Step::SampleExt, // Cross an output-word boundary.
    ]);

    steps.push(Step::ReseedDirect(random_word(rng)));
    steps.push(Step::SampleFelt);
    for bits in [0, 4] {
        let commitment = random_word(rng);
        // Generate a witness for the transcript prefix that both implementations will replay.
        let mut challenger = challenger_with(state, 0);
        replay_steps(&mut challenger, &steps);
        commitment.into_iter().for_each(|x| challenger.observe(x));
        let witness = challenger.grind(bits as usize);
        steps.push(Step::FoldingPow { commitment, witness, bits });
        steps.push(Step::SampleFelt);
    }

    // Eight scalar observations compress one full input block without an explicit flush.
    steps.extend((0..8).map(|_| Step::ObserveFelt(random_felt(rng))));
    steps.push(Step::SampleFelt);
    steps
}

fn steps_source(state: &[Felt; 4], steps: &[Step], combined_helpers: bool) -> String {
    let mut body = store_random_coin(state, 0);
    let mut addr = SAMPLES_PTR;
    for step in steps {
        let line = match step {
            Step::ObserveFelt(x) => format!("push.{x} exec.random_coin::observe_felt"),
            Step::ObserveWord(w) | Step::ObserveWordAndFlush(w) if !combined_helpers => {
                let mut observe = w
                    .iter()
                    .map(|x| format!("push.{x} exec.random_coin::observe_felt\n"))
                    .collect::<String>();
                if matches!(step, Step::ObserveWordAndFlush(_)) {
                    observe.push_str("exec.random_coin::flush_buffer");
                }
                observe
            },
            Step::ObserveWord(w) => {
                format!("{} exec.random_coin::observe_word", masm_push_word(&Word::from(*w)))
            },
            Step::ObserveWordAndFlush(w) => {
                format!(
                    "{} exec.random_coin::observe_word_and_flush_buffer",
                    masm_push_word(&Word::from(*w))
                )
            },
            Step::ReseedDirect(w) => {
                format!("{} exec.random_coin::reseed_direct", masm_push_word(&Word::from(*w)))
            },
            Step::FoldingPow { commitment, witness, bits } => {
                let sample = if combined_helpers {
                    "exec.random_coin::reseed_check_folding_pow_and_sample_alpha"
                } else {
                    "exec.random_coin::reseed_with_felt exec.random_coin::sample_folding_pow_and_ext"
                };
                addr += 2;
                format!(
                    "push.{bits} mem_store.FOLDING_POW_BITS_PTR
                    {} push.{witness} {sample} mem_store.{} mem_store.{}",
                    masm_push_word(&Word::from(*commitment)),
                    addr - 2,
                    addr - 1,
                )
            },
            Step::Flush => "exec.random_coin::flush_buffer".to_string(),
            Step::SampleFelt => {
                addr += 1;
                format!("exec.random_coin::sample_felt mem_store.{}", addr - 1)
            },
            Step::SampleExt => {
                addr += 2;
                format!(
                    "exec.random_coin::sample_ext mem_store.{} mem_store.{}",
                    addr - 2,
                    addr - 1
                )
            },
            Step::SampleBits(bits) => {
                addr += 1;
                format!("push.{bits} exec.random_coin::sample_bits mem_store.{}", addr - 1)
            },
        };
        body.push_str("\n        ");
        body.push_str(&line);
    }
    format!(
        "{RANDOM_COIN_IMPORTS}
        use {{FOLDING_POW_BITS_PTR}} from miden::core::stark::constants
        begin
            {body}
        end
        "
    )
}

fn replay_steps(challenger: &mut Challenger, steps: &[Step]) -> Vec<Felt> {
    let mut samples = Vec::new();
    for step in steps {
        match *step {
            Step::ObserveFelt(x) => challenger.observe(x),
            Step::ObserveWord(w) | Step::ObserveWordAndFlush(w) | Step::ReseedDirect(w) => {
                w.into_iter().for_each(|x| challenger.observe(x))
            },
            Step::FoldingPow { commitment, witness, bits } => {
                commitment.into_iter().for_each(|x| challenger.observe(x));
                assert!(challenger.check_witness(bits as usize, witness));
                let alpha: QuadFelt = challenger.sample_algebra_element();
                samples.extend_from_slice(alpha.as_basis_coefficients_slice());
            },
            // The Rust challenger incorporates pending inputs when it next samples.
            Step::Flush => {},
            Step::SampleFelt => samples.push(challenger.sample_algebra_element::<Felt>()),
            Step::SampleExt => {
                let x: QuadFelt = challenger.sample_algebra_element();
                samples.extend_from_slice(x.as_basis_coefficients_slice());
            },
            Step::SampleBits(bits) => {
                let value = sample_bits(challenger, bits as usize);
                samples.push(Felt::from_usize(value));
            },
        }
    }
    samples
}

fn assert_steps_match_native(state: [Felt; 4], steps: &[Step]) {
    let mut challenger = challenger_with(state, 0);
    let expected = replay_steps(&mut challenger, steps);
    let caller: [u64; 16] = core::array::from_fn(|i| 501 + i as u64);
    let outputs = [false, true].map(|combined| {
        let (output, _) = build_test!(&steps_source(&state, steps, combined), &caller)
            .execute_for_output()
            .unwrap_or_else(|err| panic!("combined={combined}, steps={steps:?}: {err}"));
        for (i, expected) in expected.iter().enumerate() {
            assert_eq!(
                read_memory_felt(&output, SAMPLES_PTR + i as u32),
                *expected,
                "combined={combined}, sample {i}, steps={steps:?}"
            );
        }
        assert_random_coin_state(&output, &challenger, "transcript sequence");
        assert_eq!(output.stack.get_num_elements(16), caller.map(Felt::new_unchecked));
        read_state(&output)
    });
    assert_eq!(outputs[0], outputs[1], "challenger state differs for steps {steps:?}");
}

#[test]
fn random_coin_boundary_sequences_match_the_rust_challenger() {
    for seed in 0..4 {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let state = random_word(&mut rng);
        assert_steps_match_native(state, &boundary_steps(&mut rng, state));
    }
}

#[rstest]
fn word_observations_match_scalar_and_native(
    #[values(0, 1, 2, 3, 4, 5, 6, 7)] prefix_len: u32,
    #[values(false, true)] flush: bool,
) {
    let word = if flush { [13, 17, 19, 23] } else { [3, 5, 7, 11] }.map(Felt::from_u32);
    let mut steps: Vec<_> =
        (1..=prefix_len).map(|x| Step::ObserveFelt(Felt::from_u32(x))).collect();
    steps.push(if flush {
        Step::ObserveWordAndFlush(word)
    } else {
        Step::ObserveWord(word)
    });
    // Preserve a buffered suffix after a standalone word observation.
    if !flush {
        steps.extend([
            Step::ObserveFelt(Felt::from_u32(13)),
            Step::ObserveFelt(Felt::from_u32(17)),
            Step::Flush,
        ]);
    }
    steps.push(Step::SampleFelt);
    assert_steps_match_native([109, 107, 103, 101].map(Felt::from_u32), &steps);
}

#[rstest]
fn folding_reseed_matches_native(#[values(0, 1)] bits: u8) {
    let state = [131, 127, 113, 109].map(Felt::from_u32);
    assert_steps_match_native(
        state,
        &[Step::FoldingPow {
            commitment: [23, 29, 31, 41].map(Felt::from_u32),
            witness: Felt::ZERO,
            bits,
        }],
    );
}

#[rstest]
fn folding_reseed_with_pending_input(#[values(0, 1)] bits: u8) {
    let state = [131, 127, 113, 109].map(Felt::from_u32);
    let steps = [
        Step::ObserveFelt(Felt::from_u32(17)),
        Step::FoldingPow {
            commitment: [23, 29, 31, 41].map(Felt::from_u32),
            witness: Felt::ZERO,
            bits,
        },
    ];
    if bits == 0 {
        assert_steps_match_native(state, &steps);
    } else {
        let source = steps_source(&state, &steps, true);
        expect_assert_error_code_from_msg!(
            build_test!(&source, &[]),
            "reseed_with_folding_pow_and_ext: buffer must be empty"
        );
    }
}

#[test]
fn sampling_clears_the_absorb_buffer_and_matches_rust() {
    let state = [11, 12, 13, 14].map(Felt::from_u32);
    let mut challenger = challenger_with(state, 0);
    let observations: String = (21..26)
        .map(|value| {
            challenger.observe(Felt::from_u32(value));
            format!("push.{value} exec.random_coin::observe_felt\n")
        })
        .collect();
    // Sampling must clear its buffer without reading the separate hash-helper zero word.
    let source = format!(
        "{RANDOM_COIN_IMPORTS}
        use {{ZERO_WORD_PTR}} from miden::core::stark::constants
        begin
            {store}
            push.97.89.83.79 mem_storew_le.ZERO_WORD_PTR dropw
            {observations}
            exec.random_coin::sample_felt mem_store.{SAMPLES_PTR}
        end",
        store = store_random_coin(&state, 0),
    );
    let (output, _) = build_test!(&source, &[]).execute_for_output().unwrap();
    assert_eq!(read_memory_felt(&output, SAMPLES_PTR), challenger.sample_felt());
    assert_random_coin_state(&output, &challenger, "partial absorb buffer");
    let buffer = stark_constant("RANDOM_COIN_INPUT_BUF_PTR");
    for offset in 0..8 {
        assert_eq!(read_memory_felt(&output, buffer + offset), Felt::ZERO);
    }
    assert_eq!(read_memory_felt(&output, stark_constant("ZERO_WORD_PTR")), Felt::from_u32(79));
}

// OUT-OF-DOMAIN POINT
// ================================================================================================

/// Supplies controlled cached samples, then continues the real challenger at its next refill.
struct CachedOutputChannel<'a> {
    cached: std::slice::Iter<'a, Felt>,
    challenger: Challenger,
    samples: usize,
}

impl Channel for CachedOutputChannel<'_> {
    type F = Felt;
    type Commitment = [Felt; 4];
    type Challenger = Challenger;

    fn sample(&mut self) -> Felt {
        self.samples += 1;
        self.cached.next().copied().unwrap_or_else(|| self.challenger.sample_felt())
    }

    fn sample_bits(&mut self, _: usize) -> usize {
        unreachable!("the OOD sampler only draws field elements")
    }
}

#[rstest]
#[case::minimum_height(MIN_TRACE_LEN.ilog2() as u8)]
#[case::setup_height(16)]
#[case::maximum_height(Felt::TWO_ADICITY as u8 - config::pcs_params().log_blowup())]
fn ood_rejection_matches_rust_and_preserves_the_transcript(#[case] log_height: u8) {
    let domain = canonical_domain::<Felt>(log_height, config::pcs_params().log_blowup());
    // Eidos samples are below 2^63. Pick nontrivial domain points within that support.
    let in_subgroup = (1..domain.trace_height())
        .map(|i| domain.trace_subgroup().point_at(i as u64))
        .find(|x| x.as_canonical_u64() < 1 << 63 && *x != Felt::ONE)
        .expect("the trace subgroup has a supported nontrivial point");
    let in_lde = (0..domain.lde_height())
        .map(|i| domain.lde_coset().point_at(i as u64))
        .find(|x| x.as_canonical_u64() < 1 << 63)
        .expect("the LDE coset has a supported point");
    let allowed_base = (2..100)
        .map(Felt::from_u32)
        .find(|x| !domain.trace_subgroup().contains(*x) && !domain.lde_coset().contains(*x))
        .expect("a base-field point outside both domains exists");
    let [zero, one, a, b] = [0, 1, 7, 11].map(Felt::from_u32);
    let initial_cv = [19, 20, 21, 22].map(Felt::from_u32);
    let caller: [u64; 16] = core::array::from_fn(|i| 101 + i as u64);
    let state = store_random_coin(&initial_cv, 4);
    let lookahead = (0..4)
        .map(|i| format!("exec.random_coin::sample_felt mem_store.{}\n", SAMPLES_PTR + i))
        .collect::<String>();
    let cases: &[(&str, &[Felt], usize)] = &[
        ("zero", &[zero, zero, a, b], 4),
        ("trace subgroup", &[in_subgroup, zero, a, b], 4),
        ("LDE coset", &[in_lde, zero, a, b], 4),
        ("allowed base-field point", &[allowed_base, zero, a, b], 2),
        ("non-base-field point", &[zero, one, a, b], 2),
        ("two rejections then refill", &[zero, zero, in_subgroup, zero], 6),
        ("rejection then split candidate", &[zero, zero, a], 4),
    ];
    for &(case, cached, expected_samples) in cases {
        let cached_len = cached.len();
        let mut channel = CachedOutputChannel {
            cached: cached.iter(),
            challenger: challenger_with(initial_cv, 4),
            samples: 0,
        };
        let z: QuadFelt = domain.sample_ood_point(&mut channel);
        assert_eq!(channel.samples, expected_samples, "{case}: fixture must exercise its branch");
        let next = Word::new(core::array::from_fn(|_| channel.sample()));

        let cached_stores = masm_store_felts(
            cached,
            stark_constant("RANDOM_COIN_OUTPUT_WORD_PTR") + 4 - cached_len as u32,
        );
        let source = init_seed_source(
            &[Felt::ZERO; 4],
            log_height,
            "use {RANDOM_COIN_CV_PTR, RANDOM_COIN_COUNTER_PTR, RANDOM_COIN_OUTPUT_LENGTH_PTR}
                from miden::core::stark::constants",
            &format!(
                "{state}
                {cached_stores}
                push.{cached_len} mem_store.RANDOM_COIN_OUTPUT_LENGTH_PTR
                exec.random_coin::generate_z_zN
                {lookahead}",
            ),
        );
        let test = build_test!(&source, &caller);
        let (output, _) = test.execute_for_output().unwrap_or_else(|err| {
            panic!("{case} at height 2^{log_height}: OOD sampling failed: {err}")
        });
        let z_n = z.exp_power_of_2(log_height as usize);
        let expected: Vec<Felt> =
            [z_n.as_basis_coefficients_slice(), z.as_basis_coefficients_slice()].concat();
        assert_eq!(
            read_memory_word(&output, stark_constant("OOD_POINT_PTR")).as_elements(),
            expected,
            "{case}: stored [z^N, z] differs from Rust"
        );
        assert_eq!(read_memory_word(&output, SAMPLES_PTR), next, "{case}: following samples");
        assert_eq!(output.stack.get_num_elements(16), caller.map(Felt::new_unchecked), "{case}");
        assert_random_coin_state(&output, &channel.challenger, case);
        let refill_samples = channel.samples - cached_len;
        for (name, expected) in [
            ("RANDOM_COIN_OUTPUT_LENGTH_PTR", (4 - refill_samples % 4) % 4),
            ("RANDOM_COIN_COUNTER_PTR", 1 + refill_samples.div_ceil(4)),
        ] {
            assert_eq!(
                read_memory_felt(&output, stark_constant(name)),
                Felt::from_usize(expected),
                "{case}: {name}"
            );
        }
        test.check_constraints();
    }
}

#[test]
fn ood_point_matches_the_rust_sampler_at_every_supported_height() {
    let mut rng = ChaCha20Rng::seed_from_u64(2923);
    let log_blowup = config::pcs_params().log_blowup();
    let min_height = MIN_TRACE_LEN.ilog2() as u8;
    let cases = supported_log_heights()
        .map(|height| (height, 1 + usize::from((height - min_height) % 4)))
        .chain(core::iter::once((min_height, 2)));
    for (log_height, output_len) in cases {
        let state: [Felt; 4] = core::array::from_fn(|_| random_felt(&mut rng));
        let lookahead = if output_len > 2 {
            format!("exec.random_coin::sample_felt mem_store.{SAMPLES_PTR}")
        } else {
            String::new()
        };
        let source = format!(
            "{RANDOM_COIN_IMPORTS}
            use {{LOG_TRACE_LENGTH_PTR}} from miden::core::stark::constants
            begin
                {store}
                push.{log_height} mem_store.LOG_TRACE_LENGTH_PTR
                exec.random_coin::generate_z_zN
                {lookahead}
            end
            ",
            store = store_random_coin(&state, 4 - output_len),
        );
        let (output, _) = build_test!(&source, &[])
            .execute_for_output()
            .unwrap_or_else(|err| panic!("height 2^{log_height}: generate_z_zN failed: {err}"));

        let challenger = challenger_with(state, 4 - output_len);
        let domain = canonical_domain::<Felt>(log_height, log_blowup);
        let (z, next): (QuadFelt, Felt) =
            sample_ood_point_and_next::<Felt, QuadFelt, [Felt; 4], _>(&domain, challenger.clone());
        let mut after_draw = challenger;
        assert_eq!(
            after_draw.sample_algebra_element::<QuadFelt>(),
            z,
            "height 2^{log_height}: the Rust sampler drew more than one candidate"
        );
        // Rust can refill for this lookahead when MASM has no output left.
        let mut after_next = after_draw.clone();
        assert_eq!(
            after_next.sample_algebra_element::<Felt>(),
            next,
            "height 2^{log_height}: the Rust sampler consumed extra transcript data"
        );
        if output_len > 2 {
            assert_eq!(
                read_memory_felt(&output, SAMPLES_PTR),
                next,
                "height 2^{log_height}: the next transcript sample differs"
            );
            after_draw = after_next;
        }
        let z_n = z.exp_power_of_2(log_height as usize);

        let ood_point = stark_constant("OOD_POINT_PTR");
        let expected: Vec<Felt> =
            [z_n.as_basis_coefficients_slice(), z.as_basis_coefficients_slice()].concat();
        for (i, expected) in expected.iter().enumerate() {
            assert_eq!(
                read_memory_felt(&output, ood_point + i as u32),
                *expected,
                "height 2^{log_height}: OOD word element {i} ([z^N, z])"
            );
        }
        assert_random_coin_state(&output, &after_draw, &format!("height 2^{log_height}"));
    }
}

// TRANSCRIPT SEEDING AND DOMAIN PARAMETERS
// ================================================================================================

fn init_seed_source(
    relation_digest: &[Felt; 4],
    log_height: u8,
    imports: &str,
    extra: &str,
) -> String {
    let params = config::pcs_params();
    format!(
        "
        use miden::core::stark::random_coin
        {imports}
        use {{
            DEEP_POW_BITS_PTR, FOLDING_POW_BITS_PTR, LOG_TRACE_LENGTH_PTR, NUM_QUERIES_PTR,
            QUERY_POW_BITS_PTR, RELATION_DIGEST_PTR, PREPROCESSED_TRACE_COM_PTR
        }} from miden::core::stark::constants
        begin
            push.{num_queries} mem_store.NUM_QUERIES_PTR
            push.{query_pow_bits} mem_store.QUERY_POW_BITS_PTR
            push.{deep_pow_bits} mem_store.DEEP_POW_BITS_PTR
            push.{folding_pow_bits} mem_store.FOLDING_POW_BITS_PTR
            {digest} mem_storew_le.RELATION_DIGEST_PTR dropw
            push.{log_height} mem_store.LOG_TRACE_LENGTH_PTR
            padw mem_storew_le.PREPROCESSED_TRACE_COM_PTR dropw
            exec.random_coin::init_seed
            {extra}
        end
        ",
        num_queries = params.num_queries(),
        query_pow_bits = params.query_pow_bits(),
        deep_pow_bits = params.deep_pow_bits(),
        folding_pow_bits = params.folding_pow_bits(),
        digest = masm_push_word(&Word::from(*relation_digest)),
    )
}

/// The first sampled word binds the relation, PCS parameters, and preprocessed commitment.
#[test]
fn init_seed_matches_the_rust_transcript_seeding() {
    let mut rng = ChaCha20Rng::seed_from_u64(2355);
    let relation_digest = random_word(&mut rng);
    let draws = (0..4)
        .map(|i| format!("exec.random_coin::sample_felt mem_store.{}", SAMPLES_PTR + i))
        .collect::<Vec<_>>()
        .join("\n");
    let source = init_seed_source(&relation_digest, 10, "", &draws);
    let (output, _) =
        build_test!(&source, &[]).execute_for_output().expect("init_seed must execute");

    let mut challenger = eidos_config(config::pcs_params(), relation_digest).challenger();
    miden_stark::config::observe_protocol_params(&config::pcs_params(), &mut challenger);
    for _ in 0..4 {
        challenger.observe(Felt::ZERO);
    }
    for i in 0..4 {
        assert_eq!(
            read_memory_felt(&output, SAMPLES_PTR + i),
            challenger.sample_algebra_element::<Felt>(),
            "sample {i} after init_seed"
        );
    }
}

#[test]
fn domain_and_fri_parameters_match_rust_at_every_supported_height() {
    let params = config::pcs_params();
    let relation_digest = [Felt::ZERO; 4];
    for log_height in supported_log_heights() {
        let source = init_seed_source(
            &relation_digest,
            log_height,
            "use miden::core::pcs::fri::helper",
            "exec.helper::generate_fri_parameters",
        );
        let (output, _) = build_test!(&source, &[]).execute_for_output().unwrap_or_else(|err| {
            panic!("height 2^{log_height}: parameter derivation failed: {err}")
        });
        let read = |name: &str| read_memory_felt(&output, stark_constant(name));

        let domain = canonical_domain::<Felt>(log_height, params.log_blowup());
        let expected = [
            ("TRACE_LENGTH_PTR", Felt::from_usize(domain.trace_height())),
            ("TRACE_DOMAIN_GENERATOR_PTR", domain.trace_subgroup().generator()),
            ("LDE_DOMAIN_SIZE_PTR", Felt::from_usize(domain.lde_height())),
            ("LOG_LDE_DOMAIN_SIZE_PTR", Felt::from_u8(domain.log_lde_height())),
            ("LDE_DOMAIN_GENERATOR_PTR", domain.lde_coset().generator()),
            ("DOMAIN_OFFSET_PTR", domain.lde_shift()),
            ("DOMAIN_OFFSET_INV_PTR", domain.lde_shift().inverse()),
            ("NUM_FRI_LAYERS_PTR", Felt::from_usize(fri_num_rounds(&params, &domain))),
            (
                "REMAINDER_POLY_SIZE_PTR",
                Felt::from_usize(fri_final_poly_degree(&params, &domain)),
            ),
        ];
        for (name, expected) in expected {
            assert_eq!(read(name), expected, "height 2^{log_height}: {name}");
        }
    }
}

#[test]
fn eidos_absorb_block_matches_rust_challenger() {
    const SQUEEZED_WORD_PTR: u32 = 1000;

    let source = "
        use miden::core::stark::random_coin
        use {RANDOM_COIN_CV_PTR} from miden::core::stark::constants

        begin
            push.13.12.11.10 mem_storew_le.RANDOM_COIN_CV_PTR
            dropw
            exec.random_coin::eidos_clear_buffer
            push.8.7.6.5
            push.4.3.2.1
            exec.random_coin::eidos_absorb_block
            exec.random_coin::eidos_squeeze_word
            push.1000 mem_storew_le
            dropw
        end
        ";

    let test = build_test!(source, &[]);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    let init_cv = Word::new([10, 11, 12, 13].map(Felt::from_u32));
    let mut challenger = Challenger::new(init_cv);
    challenger.observe([1, 2, 3, 4, 5, 6, 7, 8].map(Felt::from_u32));
    let expected_word = challenger.squeeze_word();

    assert_eq!(read_memory_word(&output, SQUEEZED_WORD_PTR), expected_word);
}

#[test]
fn eidos_absorb_block_rejects_nonempty_buffer() {
    let source = "
        use {RANDOM_COIN_CV_PTR} from miden::core::stark::constants
        use miden::core::stark::random_coin

        begin
            push.13.12.11.10 mem_storew_le.RANDOM_COIN_CV_PTR dropw
            exec.random_coin::eidos_clear_buffer
            push.17 exec.random_coin::observe_felt

            push.8.7.6.5
            push.4.3.2.1
            exec.random_coin::eidos_absorb_block
        end
        ";

    let test = build_test!(source, &[]);
    expect_assert_error_code_from_msg!(test, "eidos_absorb_block: buffer must be empty");
}
