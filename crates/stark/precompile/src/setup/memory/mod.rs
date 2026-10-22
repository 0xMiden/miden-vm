//! Peak prover memory using build-compiled relation geometry.

mod model;

use miden_air::precompile::{NUM_CHIPLETS, protocol};
use miden_core::proof::HashFunction;
pub use miden_stark::pcs::PcsParams;
pub use model::{
    SAFETY_DENOMINATOR, SAFETY_NUMERATOR, prover_peak_bytes_for_shape,
    prover_peak_bytes_with_quotient_chunks,
};

/// Peak prover memory, in bytes, for the given canonical padded trace heights.
/// The quotient geometry is compiled at build time; repeated estimates do not evaluate AIRs.
pub fn prover_peak_bytes(
    heights: &[usize; NUM_CHIPLETS],
    params: &PcsParams,
    hash_fn: HashFunction,
) -> Option<u64> {
    let metadata = protocol::metadata();
    let preprocessed_width = metadata.raw_widths.iter().map(|widths| widths.0).sum();
    prover_peak_bytes_for_shape(
        heights,
        metadata.raw_widths,
        (
            miden_air_source::precompile::primitives::byte_pair_lut::TRACE_HEIGHT,
            preprocessed_width,
        ),
        metadata.num_quotient_chunks,
        params,
        hash_fn,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Estimates from the compiled degrees must match the symbolic ones for every supported
    /// commitment hash, PCS blowup, and overflow path, even across repeated estimates.
    #[test]
    fn compiled_degrees_preserve_symbolic_memory_estimates() {
        for params in [
            miden_air::precompile::policy::precompile_pcs_params(),
            PcsParams::new(1, 1, 3, 0, 0, 1, 0).unwrap(),
        ] {
            for hash_fn in [HashFunction::Blake3_256, HashFunction::Keccak, HashFunction::Eidos] {
                for heights in [
                    [0; NUM_CHIPLETS],
                    [1; NUM_CHIPLETS],
                    core::array::from_fn(|index| 1 << (index + 1)),
                    [usize::MAX; NUM_CHIPLETS],
                ] {
                    let independent = model::prover_peak_bytes(&heights, &params, hash_fn);
                    for _ in 0..3 {
                        assert_eq!(
                            prover_peak_bytes(&heights, &params, hash_fn),
                            independent,
                            "{hash_fn:?}"
                        );
                    }
                }
            }
        }
    }
}
