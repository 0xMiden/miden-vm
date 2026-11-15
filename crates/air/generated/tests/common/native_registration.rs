use miden_constraint_compiler::{
    ir::{Graph, capture_kernel_native_into, capture_native_into},
    testing::{
        assert_concrete_evaluation, constraint_degrees, eval_graph, kernel_constraint_degrees,
    },
};
use miden_core::Felt;
use miden_stark::air::native::{AirKernel, DirectKernel, LiftedAir};

/// Authored equations are expected; actual prepared generated execution is the comparison subject.
pub fn assert_native_registration<A, K>(source: &A, kernel: &K, seeds: &[u64])
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
    for seed in seeds {
        assert_concrete_evaluation(&direct, &graph, &authored, *seed);
        assert_concrete_evaluation(kernel, &graph, &authored, *seed);
        let values = eval_graph(&graph, *seed);
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
