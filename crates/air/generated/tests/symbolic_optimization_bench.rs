//! Manual release-mode row evaluator and ACE size comparison.
//!
//! `MIDEN_FOLD_POLICIES` selects generated alternatives at build time. Runtime sample counts use
//! `MIDEN_EVAL_ITERATIONS` and `MIDEN_EVAL_REPEATS`. The folding comparison prepares both sessions
//! before timing, shares inputs and output allocation, warms both evaluators, alternates timed
//! order, and reports scalar and packed calls separately. Build first, then run the executable:
//!
//! ```sh
//! MIDEN_FOLD_POLICIES=production,cancel cargo test --release -p miden-air \
//!   --features symbolic-experiments --test symbolic_optimization_bench --no-run
//! MIDEN_EVAL_ITERATIONS=16384 MIDEN_EVAL_REPEATS=11 \
//!   /path/to/built-test --ignored --exact folding_variants --nocapture
//! ```
use miden_ace::compiler::{CapturedAir, CompiledRelation, LayoutKind};
use miden_air::{precompiles::ChipletAir, vm::AIRS};
use miden_core::field::QuadFelt;

#[test]
#[ignore = "manual protocol pin derivation after an intentional circuit change"]
fn derive_current_pins() {
    let vm = miden_air_definitions::compiler::vm::build_recursive_verifier_ace_circuit().unwrap();
    let pvm =
        miden_air_definitions::compiler::precompiles::build_pvm_recursive_verifier_ace_circuit()
            .unwrap();
    for (name, id, digest) in [
        ("vm", miden_air::vm::config::PROTOCOL_ID, vm.commitment),
        ("pvm", miden_air::precompiles::policy::PROTOCOL_ID, pvm.commitment),
    ] {
        println!(
            "PINS,{name},ace={:?},relation={:?}",
            digest.map(|v| v.as_canonical_u64()),
            miden_stark::config::relation_digest(id, &digest).map(|v| v.as_canonical_u64())
        );
    }
}

#[cfg(feature = "symbolic-experiments")]
include!(concat!(env!("OUT_DIR"), "/folding_experiment_modules.rs"));

#[cfg(feature = "symbolic-experiments")]
#[test]
#[ignore = "manual release-mode folding comparison"]
fn folding_variants() {
    let iterations: usize = std::env::var("MIDEN_EVAL_ITERATIONS")
        .unwrap_or_else(|_| "8192".into())
        .parse()
        .unwrap();
    let repeats: usize = std::env::var("MIDEN_EVAL_REPEATS")
        .unwrap_or_else(|_| "9".into())
        .parse()
        .unwrap();
    for repeat in 0..repeats {
        run_variants(repeat, iterations);
    }
}

#[cfg(feature = "symbolic-experiments")]
fn run<A: miden_stark::air::AirKernel<F = miden_core::Felt>>(
    policy: &str,
    group: &str,
    index: usize,
    air: &A,
    repeat: usize,
    iterations: usize,
) {
    if repeat == 0 {
        for seed in [0, 42, u64::MAX] {
            if group == "vm" {
                let source =
                    miden_stark::air::DirectKernel::new(miden_air_definitions::vm::AIRS[index])
                        .unwrap();
                miden_constraint_compiler::testing::assert_concrete_evaluations_equal(
                    &source, air, seed,
                );
            } else {
                let source = miden_stark::air::DirectKernel::new(
                    miden_air_definitions::precompiles::relation::AIRS[index],
                )
                .unwrap();
                miden_constraint_compiler::testing::assert_concrete_evaluations_equal(
                    &source, air, seed,
                );
            }
        }
    }
    let times = if group == "vm" {
        time_pair(&AIRS[index], air, iterations, repeat % 2 == 1)
    } else {
        time_pair(&ChipletAir::all()[index], air, iterations, repeat % 2 == 1)
    };
    println!(
        "BENCH,control_{policy}/{group}/{index},{repeat},{},{},{iterations}",
        times[0][0].as_nanos(),
        times[1][0].as_nanos()
    );
    println!(
        "BENCH,{policy}/{group}/{index},{repeat},{},{},{iterations}",
        times[0][1].as_nanos(),
        times[1][1].as_nanos()
    );
}

#[test]
#[ignore = "manual release-mode optimization comparison"]
fn symbolic_optimization_benchmark() {
    let iterations: usize = std::env::var("MIDEN_EVAL_ITERATIONS")
        .unwrap_or_else(|_| "8192".into())
        .parse()
        .unwrap();
    let repeats: usize = std::env::var("MIDEN_EVAL_REPEATS")
        .unwrap_or_else(|_| "9".into())
        .parse()
        .unwrap();
    for air in AIRS {
        let _ = miden_constraint_compiler::testing::time_evaluation(&air, 256);
    }
    for air in ChipletAir::all() {
        let _ = miden_constraint_compiler::testing::time_evaluation(&air, 256);
    }
    for repeat in 0..repeats {
        for air in AIRS {
            let times = miden_constraint_compiler::testing::time_evaluation(&air, iterations);
            println!(
                "BENCH,vm/{},{repeat},{},{},{iterations}",
                air.name(),
                times[0].as_nanos(),
                times[1].as_nanos()
            );
        }
        for air in ChipletAir::all() {
            let times = miden_constraint_compiler::testing::time_evaluation(&air, iterations);
            println!(
                "BENCH,pvm/{},{repeat},{},{},{iterations}",
                air.definition().file_token(),
                times[0].as_nanos(),
                times[1].as_nanos()
            );
        }
    }
    let captured: Vec<_> = miden_air_definitions::vm::AIRS
        .iter()
        .map(|air| CapturedAir::new_native(air).unwrap())
        .collect();
    let refs: Vec<_> = captured.iter().collect();
    let relation = CompiledRelation::from_captured(&refs, 8).unwrap();
    sizes("vm", &relation.build_circuit(LayoutKind::Masm).unwrap());
    sizes(
        "pvm",
        &miden_air_definitions::compiler::precompiles::build_canonical_precompile_ace_circuit()
            .unwrap(),
    );
}

fn sizes(name: &str, circuit: &miden_ace::compiler::AceCircuit<QuadFelt>) {
    let encoded = circuit.to_ace().unwrap();
    println!(
        "ACE,{name},{},{},{},{},{}",
        circuit.num_operations(),
        circuit.num_constants(),
        encoded.num_vars(),
        encoded.num_eval_rows(),
        encoded.size_in_felt()
    );
}

#[cfg(feature = "symbolic-experiments")]
fn time_pair<S, A>(
    source: &S,
    candidate: &A,
    iterations: usize,
    reverse: bool,
) -> [[std::time::Duration; 2]; 2]
where
    S: miden_stark::air::AirKernel<F = miden_core::Felt>,
    A: miden_stark::air::AirKernel<F = miden_core::Felt>,
{
    fn carriers<S, A, P, PE>(
        source: &S,
        candidate: &A,
        iterations: usize,
        reverse: bool,
    ) -> [std::time::Duration; 2]
    where
        S: miden_stark::air::AirKernel<F = miden_core::Felt>,
        A: miden_stark::air::AirKernel<F = miden_core::Felt>,
        P: p3_field::PackedField<Scalar = miden_core::Felt>,
        PE: p3_field::Algebra<P>
            + p3_field::Algebra<QuadFelt>
            + p3_field::BasedVectorSpace<P>
            + Copy
            + Send
            + Sync,
    {
        use miden_constraint_compiler::testing::{EvaluationBuilder, EvaluationInputs};
        let inputs = EvaluationInputs::<P, PE>::new(source.descriptor().spec(), 0x243f6a8885a308d3);
        let frame = inputs.frame();
        let baseline =
            source.bind(inputs.inputs()).expect("control dimensions match its descriptor");
        let candidate = candidate
            .bind(inputs.inputs())
            .expect("candidate dimensions match the control inputs");
        let mut builder = EvaluationBuilder::<P, PE>::default();
        for _ in 0..256 {
            builder.clear();
            baseline.eval(std::hint::black_box(&frame), &mut builder);
            std::hint::black_box(&builder);
            builder.clear();
            candidate.eval(std::hint::black_box(&frame), &mut builder);
            std::hint::black_box(&builder);
        }
        fn timed<P, PE>(
            iterations: usize,
            builder: &mut EvaluationBuilder<P, PE>,
            mut evaluate: impl FnMut(&mut EvaluationBuilder<P, PE>),
        ) -> std::time::Duration {
            let start = std::time::Instant::now();
            for _ in 0..iterations {
                builder.clear();
                evaluate(builder);
                std::hint::black_box(&builder);
            }
            start.elapsed()
        }
        let mut result = [std::time::Duration::ZERO; 2];
        for arm in if reverse { [1, 0] } else { [0, 1] } {
            result[arm] = if arm == 0 {
                timed(iterations, &mut builder, |builder| {
                    baseline.eval(std::hint::black_box(&frame), builder)
                })
            } else {
                timed(iterations, &mut builder, |builder| {
                    candidate.eval(std::hint::black_box(&frame), builder)
                })
            };
        }
        result
    }
    [
        carriers::<_, _, miden_core::Felt, QuadFelt>(source, candidate, iterations, reverse),
        carriers::<
            _,
            _,
            <miden_core::Felt as miden_core::field::Field>::Packing,
            <QuadFelt as miden_core::field::ExtensionField<miden_core::Felt>>::ExtensionPacking,
        >(source, candidate, iterations, reverse),
    ]
}
