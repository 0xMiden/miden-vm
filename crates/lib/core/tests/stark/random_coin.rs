//! Rust oracles for the MASM random coin and verifier parameters.

use miden_air::{config, trace::MIN_TRACE_LEN};
use miden_core::{
    Felt, Word,
    field::{
        BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64, QuadFelt, TwoAdicField,
    },
};
use miden_crypto::{
    hash::poseidon2::Poseidon2Permutation256,
    stark::{
        StarkConfig,
        challenger::{CanObserve, DuplexChallenger, FieldChallenger},
    },
};
use miden_lifted_stark::testing::{
    Coset, canonical_domain, fri_final_poly_degree, fri_num_rounds, sample_ood_point_and_next,
};
use miden_processor::ExecutionOutput;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::helpers::{masm_push_word, read_memory_felt, stark_constant};

type Challenger = DuplexChallenger<Felt, Poseidon2Permutation256, 12, 8>;

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

/// A challenger holding `state` with `output_len` rate elements available for sampling, matching
/// a MASM random coin with the same state and output length.
fn challenger_with(state: [Felt; 12], output_len: usize) -> Challenger {
    let mut challenger = Challenger::new(Poseidon2Permutation256);
    challenger.sponge_state = state;
    challenger.output_buffer = state[..output_len].to_vec();
    challenger
}

/// MASM that writes `state` into the random coin with an empty input buffer and `output_len`
/// rate elements available for sampling.
fn store_random_coin(state: &[Felt; 12], output_len: usize) -> String {
    let word = |i: usize| {
        masm_push_word(&Word::from([state[i], state[i + 1], state[i + 2], state[i + 3]]))
    };
    format!(
        "
        {r1} mem_storew_le.RANDOM_COIN_RATE_1_PTR dropw
        {r2} mem_storew_le.RANDOM_COIN_RATE_2_PTR dropw
        {c} mem_storew_le.RANDOM_COIN_CAPACITY_PTR dropw
        push.0 mem_store.RANDOM_COIN_INPUT_LENGTH_PTR
        push.{output_len} mem_store.RANDOM_COIN_OUTPUT_LENGTH_PTR
        ",
        r1 = word(0),
        r2 = word(4),
        c = word(8),
    )
}

const RANDOM_COIN_IMPORTS: &str = "
    use miden::core::stark::random_coin
    use {
        RANDOM_COIN_CAPACITY_PTR, RANDOM_COIN_INPUT_LENGTH_PTR, RANDOM_COIN_OUTPUT_LENGTH_PTR,
        RANDOM_COIN_RATE_1_PTR, RANDOM_COIN_RATE_2_PTR
    } from miden::core::stark::constants
";

fn assert_random_coin_state(output: &ExecutionOutput, challenger: &Challenger, context: &str) {
    let rate = stark_constant("RANDOM_COIN_RATE_1_PTR");
    let capacity = stark_constant("RANDOM_COIN_CAPACITY_PTR");
    for (i, expected) in challenger.sponge_state.iter().enumerate() {
        let addr = if i < 8 {
            rate + i as u32
        } else {
            capacity + (i - 8) as u32
        };
        assert_eq!(read_memory_felt(output, addr), *expected, "{context}: sponge element {i}");
    }
    assert_eq!(
        read_memory_felt(output, stark_constant("RANDOM_COIN_INPUT_LENGTH_PTR")),
        Felt::from_usize(challenger.input_buffer.len()),
        "{context}: input length"
    );
    assert_eq!(
        read_memory_felt(output, stark_constant("RANDOM_COIN_OUTPUT_LENGTH_PTR")),
        Felt::from_usize(challenger.output_buffer.len()),
        "{context}: output length"
    );
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
    ObservePair([Felt; 2]),
    ObserveWordAndFlush([Felt; 4]),
    ReseedDirect([Felt; 4]),
    ReseedWithFelt([Felt; 4], Felt),
    Flush,
    SampleFelt,
    SampleExt,
    SampleBits(u8),
}

/// MASM flushes pending input eagerly; Rust flushes on the next sample. Each buffered sequence
/// ends with a sample, so both sides have incorporated its input before the next observation.
fn boundary_steps(rng: &mut ChaCha20Rng) -> Vec<Step> {
    let mut steps = Vec::new();

    // Exercise each pending-input length, including a word that crosses a full rate.
    for prefix_len in 0..8 {
        steps.extend((0..prefix_len).map(|_| Step::ObserveFelt(random_felt(rng))));
        steps.push(Step::ObserveWordAndFlush(random_word(rng)));
        steps.push(Step::SampleFelt);
    }

    steps.push(Step::ObserveWord(random_word(rng)));
    steps.push(Step::ObservePair([random_felt(rng), random_felt(rng)]));
    steps.push(Step::ObserveFelt(random_felt(rng)));
    steps.push(Step::Flush);
    steps.push(Step::Flush); // Flushing an empty input buffer leaves the output untouched.
    steps.extend([
        Step::SampleExt,
        Step::SampleBits(1),
        Step::SampleBits(31),
        Step::SampleExt,
        Step::SampleExt, // Consume the last two rate elements.
    ]);

    steps.push(Step::ReseedDirect(random_word(rng)));
    steps.push(Step::SampleFelt);
    steps.push(Step::ReseedWithFelt(random_word(rng), random_felt(rng)));
    steps.push(Step::SampleExt);

    // Eight scalar observations trigger a permutation without an explicit flush.
    steps.extend((0..8).map(|_| Step::ObserveFelt(random_felt(rng))));
    steps.push(Step::SampleFelt);
    steps
}

fn steps_source(state: &[Felt; 12], steps: &[Step]) -> String {
    let mut body = store_random_coin(state, 8);
    let mut addr = SAMPLES_PTR;
    for step in steps {
        let line = match step {
            Step::ObserveFelt(x) => format!("push.{x} exec.random_coin::observe_felt"),
            Step::ObserveWord(w) => {
                format!("{} exec.random_coin::observe_word", masm_push_word(&Word::from(*w)))
            },
            Step::ObservePair([a, b]) => format!("push.{b}.{a} exec.random_coin::observe_pair"),
            Step::ObserveWordAndFlush(w) => {
                format!(
                    "{} exec.random_coin::observe_word_and_flush_buffer",
                    masm_push_word(&Word::from(*w))
                )
            },
            Step::ReseedDirect(w) => {
                format!("{} exec.random_coin::reseed_direct", masm_push_word(&Word::from(*w)))
            },
            Step::ReseedWithFelt(w, f) => {
                format!(
                    "{} push.{f} exec.random_coin::reseed_with_felt",
                    masm_push_word(&Word::from(*w))
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
    format!("{RANDOM_COIN_IMPORTS}\n    begin\n        {body}\n    end\n")
}

fn replay_steps(challenger: &mut Challenger, steps: &[Step]) -> Vec<Felt> {
    let mut samples = Vec::new();
    for step in steps {
        match *step {
            Step::ObserveFelt(x) => challenger.observe(x),
            Step::ObserveWord(w) | Step::ObserveWordAndFlush(w) | Step::ReseedDirect(w) => {
                w.into_iter().for_each(|x| challenger.observe(x))
            },
            Step::ObservePair(pair) => pair.into_iter().for_each(|x| challenger.observe(x)),
            Step::ReseedWithFelt(w, f) => {
                w.into_iter().for_each(|x| challenger.observe(x));
                challenger.observe(f);
            },
            // The Rust challenger permutes pending inputs when it next samples.
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

#[test]
fn random_coin_boundary_sequences_match_the_rust_challenger() {
    for seed in 0..4 {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let state: [Felt; 12] = core::array::from_fn(|_| random_felt(&mut rng));
        let steps = boundary_steps(&mut rng);

        let (output, _) = build_test!(&steps_source(&state, &steps), &[])
            .execute_for_output()
            .unwrap_or_else(|err| panic!("seed {seed}: transcript program failed: {err}"));

        let mut challenger = challenger_with(state, 8);
        let expected = replay_steps(&mut challenger, &steps);
        for (i, expected) in expected.iter().enumerate() {
            assert_eq!(
                read_memory_felt(&output, SAMPLES_PTR + i as u32),
                *expected,
                "seed {seed}: sample {i} differs"
            );
        }
        assert_random_coin_state(&output, &challenger, &format!("seed {seed}"));
    }
}

// OUT-OF-DOMAIN POINT
// ================================================================================================

#[test]
fn ood_point_matches_the_rust_sampler_at_every_supported_height() {
    let mut rng = ChaCha20Rng::seed_from_u64(2923);
    let log_blowup = config::pcs_params().log_blowup();
    let min_height = MIN_TRACE_LEN.ilog2() as u8;
    let cases = supported_log_heights()
        .map(|height| (height, 3 + usize::from((height - min_height) % 6)))
        .chain(core::iter::once((min_height, 2)));
    for (log_height, output_len) in cases {
        let state: [Felt; 12] = core::array::from_fn(|_| random_felt(&mut rng));
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
            store = store_random_coin(&state, output_len),
        );
        let (output, _) = build_test!(&source, &[])
            .execute_for_output()
            .unwrap_or_else(|err| panic!("height 2^{log_height}: generate_z_zN failed: {err}"));

        let challenger = challenger_with(state, output_len);
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
            QUERY_POW_BITS_PTR, RELATION_DIGEST_PTR
        }} from miden::core::stark::constants
        begin
            push.{num_queries} mem_store.NUM_QUERIES_PTR
            push.{query_pow_bits} mem_store.QUERY_POW_BITS_PTR
            push.{deep_pow_bits} mem_store.DEEP_POW_BITS_PTR
            push.{folding_pow_bits} mem_store.FOLDING_POW_BITS_PTR
            {digest} mem_storew_le.RELATION_DIGEST_PTR dropw
            push.{log_height} mem_store.LOG_TRACE_LENGTH_PTR
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

/// Full-state equality also checks the blowup, final degree, and folding arity absorbed by
/// `init_seed` against the Rust PCS configuration.
#[test]
fn init_seed_matches_the_rust_transcript_seeding() {
    let mut rng = ChaCha20Rng::seed_from_u64(2355);
    let relation_digest = random_word(&mut rng);
    let (output, _) = build_test!(&init_seed_source(&relation_digest, 10, "", ""), &[])
        .execute_for_output()
        .expect("init_seed must execute");

    let mut challenger =
        config::poseidon2_config(config::pcs_params(), relation_digest).challenger();
    config::observe_protocol_params(&config::pcs_params(), &mut challenger);
    assert_random_coin_state(&output, &challenger, "after init_seed");
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
