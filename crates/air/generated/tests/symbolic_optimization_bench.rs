//! Manual release-mode row evaluator and ACE size comparison.
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
                let source = miden_stark::air::DirectKernel::new(
                    miden_air_definitions::vm::AIRS[index],
                )
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
    let _ = miden_constraint_compiler::testing::time_evaluation(air, 256);
    let times = miden_constraint_compiler::testing::time_evaluation(air, iterations);
    println!(
        "BENCH,{policy}/{group}/{index},{repeat},{},{},{iterations}",
        times[0].as_nanos(),
        times[1].as_nanos()
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
