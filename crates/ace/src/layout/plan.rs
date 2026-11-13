use core::num::NonZeroUsize;

use super::SELECTORS_PER_AIR;

/// A contiguous region of inputs within the ACE READ layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InputRegion {
    pub offset: usize,
    pub width: usize,
}

impl InputRegion {
    /// Map a region-local index to a global input index.
    pub fn index(&self, local: usize) -> Option<usize> {
        (local < self.width).then(|| self.offset + local)
    }
}

/// Counts needed to build the ACE input layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputCounts {
    /// Width of the preprocessed trace.
    pub preprocessed_width: usize,
    /// Width of the main trace.
    pub width: usize,
    /// Width of the aux trace.
    pub aux_width: usize,
    /// Number of committed boundary values.
    pub num_aux_boundary: usize,
    /// Number of public inputs.
    pub num_public: usize,
    /// Number of quotient chunks.
    pub num_quotient_chunks: usize,
}

/// Grouped regions for the ACE input layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LayoutRegions {
    /// Region containing fixed public values.
    pub public_values: InputRegion,
    /// Region containing randomness inputs (alpha, beta).
    pub randomness: InputRegion,
    /// Preprocessed trace OOD values at `zeta`.
    pub preprocessed_curr: InputRegion,
    /// Main trace OOD values at `zeta`.
    pub main_curr: InputRegion,
    /// Aux trace OOD coordinates at `zeta`.
    pub aux_curr: InputRegion,
    /// Quotient chunk OOD coordinates at `zeta`.
    pub quotient_curr: InputRegion,
    /// Preprocessed trace OOD values at `g * zeta`.
    pub preprocessed_next: InputRegion,
    /// Main trace OOD values at `g * zeta`.
    pub main_next: InputRegion,
    /// Aux trace OOD coordinates at `g * zeta`.
    pub aux_next: InputRegion,
    /// Quotient chunk OOD coordinates at `g * zeta`.
    pub quotient_next: InputRegion,
    /// Aux bus boundary values.
    pub aux_bus_boundary: InputRegion,
    /// Stark variables (selectors, powers, weights).
    pub stark_vars: InputRegion,
}

/// Indexes of verifier scalars inside the stark-vars block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StarkVarIndices {
    /// Composition challenge `alpha`.
    pub alpha: usize,
    /// `zeta^N_max`, where `N_max` is the maximum trace length represented by the circuit.
    pub z_pow_n: usize,
    /// Shared periodic-column basis `zeta^(N_max / shared_period)`.
    pub z_k: usize,
    /// First-row selector.
    pub is_first: usize,
    /// Last-row selector.
    pub is_last: usize,
    /// Transition selector.
    pub is_transition: usize,
    /// Reserved slot kept zero.
    pub reserved: usize,
    /// First barycentric weight.
    pub weight0: usize,
    /// Chunk shift ratio.
    pub f: usize,
    /// First coset shift.
    pub s0: usize,
    /// Extra slots present only for a multi-AIR layout.
    pub multi_air: Option<MultiAirIndices>,
}

/// Stark-var slots added by a multi-AIR layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MultiAirIndices {
    /// Number of AIR instances represented in the layout.
    pub air_count: NonZeroUsize,
    /// First per-AIR selector slot.
    pub selector_start: usize,
    /// First per-AIR fold-coefficient slot.
    pub fold_coeff_start: usize,
}

/// ACE input layout for circuit evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputLayout {
    /// Grouped regions for the ACE input layout.
    pub(crate) regions: LayoutRegions,
    /// Input index for aux randomness alpha.
    pub(crate) aux_rand_alpha: usize,
    /// Input index for aux randomness beta.
    pub(crate) aux_rand_beta: usize,
    /// Indexes into the stark-vars region.
    pub(crate) stark: StarkVarIndices,
    /// Total number of ACE READ inputs.
    pub total_inputs: usize,
    /// Counts used to derive the layout.
    pub counts: InputCounts,
}

impl InputLayout {
    /// Number of quotient coordinate READ slots, including committed row padding.
    ///
    /// The logical quotient chunk count remains `counts.num_quotient_chunks`.
    pub fn quotient_width(&self) -> usize {
        self.regions.quotient_curr.width
    }
}

impl StarkVarIndices {
    pub(crate) fn multi_air_fold_coeff_index(&self, air_index: usize) -> Option<usize> {
        let multi_air = self.multi_air?;
        let start = multi_air.fold_coeff_start;
        (air_index < multi_air.air_count.get()).then_some(start + air_index)
    }

    pub(crate) fn air_selector_index(
        &self,
        air_index: usize,
        selector_offset: usize,
    ) -> Option<usize> {
        let multi_air = self.multi_air?;
        (air_index < multi_air.air_count.get() && selector_offset < SELECTORS_PER_AIR)
            .then_some(multi_air.selector_start + air_index * SELECTORS_PER_AIR + selector_offset)
    }
}
