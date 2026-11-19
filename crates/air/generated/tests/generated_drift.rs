//! Compare authored AIRs with the prepared code generated for CPU execution.

use miden_air::{precompiles::ChipletAir, vm::AIRS};
use miden_constraint_compiler::{
    ir::{Graph, capture_kernel_native_into, capture_native_into},
    testing::{
        assert_concrete_evaluation, constraint_degrees, eval_graph, kernel_constraint_degrees,
    },
};
use miden_core::Felt;
use miden_stark::air::{AirKernel, DirectKernel, LiftedAir};

const SEEDS: [u64; 4] =
    [0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89];

#[test]
fn production_dispatch_preserves_each_vm_relation() {
    for air in AIRS {
        assert_eq!(air.0.build_preprocessed_trace(), air.build_preprocessed_trace());
        assert_native_registration(&air.0, &air);
    }
}

#[test]
fn production_dispatch_preserves_each_pvm_relation() {
    for air in ChipletAir::all() {
        assert_native_registration(&air.definition(), &air);
    }
}

#[test]
#[ignore = "manual evaluator timing; use release mode"]
fn evaluator_timing() {
    let iterations = std::env::var("MIDEN_EVAL_ITERATIONS")
        .map(|value| value.parse::<usize>().expect("positive iteration count"))
        .unwrap_or(256);
    assert!(iterations > 0);
    for air in AIRS {
        time_relation(air.0, &air, air.name(), iterations);
    }
    for air in ChipletAir::all() {
        time_relation(air.definition(), &air, air.definition().file_token(), iterations);
    }
}

fn time_relation<A, K>(source: A, kernel: &K, label: &str, iterations: usize)
where
    A: LiftedAir<F = Felt>,
    K: AirKernel<F = Felt>,
{
    use miden_constraint_compiler::testing::time_evaluation;

    let handwritten = time_evaluation(&DirectKernel::new(source).unwrap(), iterations);
    let generated = time_evaluation(kernel, iterations);
    eprintln!(
        "{label}: {iterations} evaluations, handwritten scalar={:?} packed={:?}, generated scalar={:?} packed={:?}",
        handwritten[0], handwritten[1], generated[0], generated[1],
    );
}

/// Authored equations are expected; actual prepared generated execution is the comparison subject.
fn assert_native_registration<A, K>(source: &A, kernel: &K)
where
    A: LiftedAir<F = Felt>,
    K: AirKernel<F = Felt>,
{
    let mut builder = Graph::builder();
    let (authored, descriptor) = capture_native_into(source, &mut builder).unwrap();
    assert_eq!(kernel.descriptor().spec(), descriptor.spec());
    assert_eq!(kernel.descriptor().analysis(), descriptor.analysis());
    assert_eq!(kernel.descriptor().fingerprint(), descriptor.fingerprint());
    let geometry = kernel.geometry();
    assert_eq!(geometry.main_width, descriptor.spec().main_width);
    assert_eq!(geometry.aux_width, descriptor.spec().aux_width);
    assert_eq!(geometry.preprocessed_width, descriptor.spec().preprocessed_width());
    assert_eq!(geometry.raw_degrees, descriptor.analysis().raw_degrees());

    // Capturing the wrapper's Source method would evaluate the authored equations again.
    // Bind its kernel instead, retaining non-Copy symbolic preparation and actual generated eval.
    let (generated, _) = capture_kernel_native_into(kernel, &mut builder).unwrap();
    assert_eq!(authored.base_global_indices, generated.base_global_indices);
    assert_eq!(authored.ext_global_indices, generated.ext_global_indices);
    assert_eq!(authored.base_roots.len(), generated.base_roots.len());
    assert_eq!(authored.ext_roots.len(), generated.ext_roots.len());
    assert_eq!(constraint_degrees(source), kernel_constraint_degrees(kernel));
    let graph = builder.freeze();
    let direct = DirectKernel::new(source).unwrap();
    for seed in SEEDS {
        assert_concrete_evaluation(&direct, &graph, &authored, seed);
        assert_concrete_evaluation(kernel, &graph, &authored, seed);
        let values = eval_graph(&graph, seed);
        for (source, prepared) in authored
            .base_roots
            .iter()
            .zip(&generated.base_roots)
            .chain(authored.ext_roots.iter().zip(&generated.ext_roots))
        {
            assert_eq!(values[source.index()], values[prepared.index()], "seed {seed:#x}");
        }
    }
}
