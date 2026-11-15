use miden_constraint_compiler::{
    ir::{Graph, capture_into, capture_kernel_native_into, capture_native_into},
    testing::eval_graph,
};
use miden_core::{Felt, field::QuadFelt};

/// Compare each completed port against its authored source and temporary legacy facade.
pub fn assert_native_registration<A, L, K>(source: &A, legacy: &L, kernel: &K, seeds: &[u64])
where
    A: miden_stark::air::native::LiftedAir<F = Felt>,
    L: miden_stark::air::LiftedAir<Felt, QuadFelt>,
    K: miden_stark::air::native::AirKernel<F = Felt>,
{
    let mut builder = Graph::builder();
    let (authored, descriptor) = capture_native_into(source, &mut builder).unwrap();
    let legacy = capture_into(legacy, &mut builder);
    assert_eq!(authored.base_roots, legacy.base_roots);
    assert_eq!(authored.ext_roots, legacy.ext_roots);
    assert_eq!(authored.base_global_indices, legacy.base_global_indices);
    assert_eq!(authored.ext_global_indices, legacy.ext_global_indices);
    assert_eq!(kernel.descriptor().spec(), descriptor.spec());
    assert_eq!(kernel.descriptor().analysis(), descriptor.analysis());
    assert_eq!(kernel.descriptor().fingerprint(), descriptor.fingerprint());

    // Kernel capture binds non-Copy symbolic inputs and observes generated execution only as
    // the comparison subject. Canonical authored roots remain the expected relation.
    let (generated, _) = capture_kernel_native_into(kernel, &mut builder).unwrap();
    assert_eq!(authored.base_global_indices, generated.base_global_indices);
    assert_eq!(authored.ext_global_indices, generated.ext_global_indices);
    let graph = builder.freeze();
    for seed in seeds {
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
