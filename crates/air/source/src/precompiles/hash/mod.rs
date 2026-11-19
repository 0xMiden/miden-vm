//! Hashers and shared hasher infrastructure.
//!
//! Houses the [`memory64`] bus (the shared 64-bit memory namespace
//! hashers read state and input from), the [`chunk`] chiplet (input
//! chunking + Eidos content commitment, shared across hashers),
//! and the [`keccak`] hasher.

pub mod chunk;
pub mod chunk_node;
pub mod chunk_node_sponge;
pub mod keccak;
pub mod memory64;
pub mod sha256;
pub mod sha512;

#[cfg(all(test, feature = "std"))]
fn assert_sha_source<A>(
    source: A,
    main_width: usize,
    aux_width: usize,
    periodic_columns: usize,
    max_period: usize,
    base_count: usize,
) where
    A: miden_stark::air::LiftedAir<F = miden_core::Felt>,
    for<'a> A: miden_stark::lookup::LookupAir<miden_stark::lookup::NativeValidationBuilder<'a>>,
{
    use miden_core::field::QuadFelt;
    use miden_stark::{air, lookup};

    let captured = air::capture_with::<_, QuadFelt>(&source).unwrap();
    let spec = captured.descriptor.spec();
    let analysis = captured.descriptor.analysis();
    assert_eq!((spec.main_width, spec.aux_width), (main_width, aux_width));
    assert_eq!((spec.num_public_values, spec.num_challenges, spec.num_exports), (0, 2, 1));
    assert_eq!(spec.preprocessed, None);
    assert_eq!(spec.periodic_columns.len(), periodic_columns);
    assert_eq!(spec.max_periodic_length(), max_period);

    let ext_count = aux_width + 1;
    let layout = analysis.layout();
    assert!(layout.base_indices().iter().copied().eq(0..base_count));
    assert!(layout.ext_indices().iter().copied().eq(base_count..base_count + ext_count));
    assert!(analysis.raw_degrees().max() <= 5, "SHA constraints exceed the deployed degree");
    lookup::validate_native(&source, spec).expect("declared SHA lookup degrees match capture");
}
