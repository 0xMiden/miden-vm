use core::num::NonZeroUsize;

use super::{InputKey, SELECTORS_PER_AIR};
use crate::EXT_DEGREE;

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
#[derive(Debug, Clone, Copy)]
pub struct InputCounts {
    /// Width of the main trace.
    pub width: usize,
    /// Width of the aux trace.
    pub aux_width: usize,
    /// Number of committed boundary values.
    pub num_aux_boundary: usize,
    /// Number of public inputs.
    pub num_public: usize,
    /// Number of randomness challenges used by the AIR.
    pub num_randomness: usize,
    /// Number of periodic columns.
    pub num_periodic: usize,
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
    /// Main trace OOD values at `zeta`.
    pub main_curr: InputRegion,
    /// Aux trace OOD coordinates at `zeta`.
    pub aux_curr: InputRegion,
    /// Quotient chunk OOD coordinates at `zeta`.
    pub quotient_curr: InputRegion,
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
    /// `zeta^N`, where N is the trace length.
    pub z_pow_n: usize,
    /// `zeta^(N / max_cycle_len)` for periodic column evaluation.
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
    /// Multi-AIR fold beta slot.
    pub fold_beta: usize,
    /// First per-AIR selector slot.
    pub selector_start: usize,
}

/// ACE input layout for circuit evaluation.
#[derive(Debug, Clone)]
pub struct InputLayout {
    /// Grouped regions for the ACE input layout.
    pub(crate) regions: LayoutRegions,
    /// Input index for aux randomness alpha.
    pub(crate) aux_rand_alpha: usize,
    /// Input index for aux randomness beta.
    pub(crate) aux_rand_beta: usize,
    /// Indexes into the stark-vars region.
    pub(crate) stark: StarkVarIndices,
    /// Total number of inputs.
    pub total_inputs: usize,
    /// Counts used to derive the layout.
    pub counts: InputCounts,
}

impl InputLayout {
    pub(crate) fn mapper(&self) -> super::InputKeyMapper<'_> {
        super::InputKeyMapper { layout: self }
    }

    /// Map a logical `InputKey` into the flat input index, if present.
    pub fn index(&self, key: InputKey) -> Option<usize> {
        self.mapper().index_of(key)
    }

    /// Validate internal layout invariants.
    pub(crate) fn validate(&self) {
        let mut max_end = 0usize;
        for region in [
            self.regions.public_values,
            self.regions.randomness,
            self.regions.main_curr,
            self.regions.aux_curr,
            self.regions.quotient_curr,
            self.regions.main_next,
            self.regions.aux_next,
            self.regions.quotient_next,
            self.regions.aux_bus_boundary,
            self.regions.stark_vars,
        ] {
            max_end = max_end.max(region.offset.saturating_add(region.width));
        }

        assert!(max_end <= self.total_inputs, "regions exceed total_inputs");

        let aux_coord_width = self.counts.aux_width * EXT_DEGREE;
        assert_eq!(self.regions.aux_curr.width, aux_coord_width, "aux_curr width mismatch");
        assert_eq!(self.regions.aux_next.width, aux_coord_width, "aux_next width mismatch");

        let quotient_width = self.counts.num_quotient_chunks * EXT_DEGREE;
        assert_eq!(
            self.regions.quotient_curr.width, quotient_width,
            "quotient_curr width mismatch"
        );
        assert_eq!(
            self.regions.quotient_next.width, quotient_width,
            "quotient_next width mismatch"
        );
        assert_eq!(
            self.regions.aux_bus_boundary.width, self.counts.num_aux_boundary,
            "aux bus boundary width mismatch"
        );

        let stark_start = self.regions.stark_vars.offset;
        let stark_end = stark_start + self.regions.stark_vars.width;
        let check = |name: &str, idx: usize| {
            assert!(idx >= stark_start && idx < stark_end, "stark var {name} out of range");
        };
        check("alpha", self.stark.alpha);
        check("z_pow_n", self.stark.z_pow_n);
        check("z_k", self.stark.z_k);
        check("is_first", self.stark.is_first);
        check("is_last", self.stark.is_last);
        check("is_transition", self.stark.is_transition);
        check("reserved", self.stark.reserved);
        check("weight0", self.stark.weight0);
        check("f", self.stark.f);
        check("s0", self.stark.s0);
        if let Some(multi_air) = self.stark.multi_air {
            check("multi_air_fold_beta", multi_air.fold_beta);
            for i in 0..(multi_air.air_count.get() * SELECTORS_PER_AIR) {
                check("air_selector", multi_air.selector_start + i);
            }
        }

        let rand_start = self.regions.randomness.offset;
        let rand_end = rand_start + self.regions.randomness.width;
        assert!(
            self.aux_rand_alpha >= rand_start && self.aux_rand_alpha < rand_end,
            "aux_rand_alpha out of randomness region"
        );
        assert!(
            self.aux_rand_beta >= rand_start && self.aux_rand_beta < rand_end,
            "aux_rand_beta out of randomness region"
        );
    }
}

impl StarkVarIndices {
    pub(crate) fn multi_air_fold_beta_index(&self) -> Option<usize> {
        self.multi_air.map(|multi_air| multi_air.fold_beta)
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
