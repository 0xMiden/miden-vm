use super::InputKey;
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
    /// Number of committed boundary values (running-sum column finals).
    pub num_aux_boundary: usize,
    /// Number of public inputs.
    pub num_public: usize,
    /// Number of variable-length public input (VLPI) reduction slots (in EF elements).
    /// This is derived from `AceConfig::num_vlpi_groups` by the layout policy:
    /// MASM expands each group to 2 EF slots (word-aligned); Native uses 1 per group.
    pub num_vlpi: usize,
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
    /// Region containing fixed-length public values.
    pub public_values: InputRegion,
    /// Region containing variable-length public input reductions.
    pub vlpi_reductions: InputRegion,
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

/// Indexes of canonical verifier scalars inside the stark-vars block.
///
/// Every slot in the ACE input array is an extension-field (EF) element --
/// the circuit operates entirely in the extension field. However, some of
/// these scalars are inherently base-field values that the MASM verifier
/// stores as `(val, 0)` in the EF slot.
///
/// See the module documentation on [`super::super::dag::lower`] for how each
/// variable enters the verifier expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StarkVarIndices {
    // -- Extension-field values (slots 0-5) --
    /// Composition challenge `alpha` for folding constraints.
    pub alpha: usize,
    /// `zeta^N` where N is the trace length.
    pub z_pow_n: usize,
    /// `zeta^(N / max_cycle_len)` for periodic column evaluation.
    pub z_k: usize,
    /// Precomputed first-row selector: `(z^N - 1) / (z - 1)`.
    pub is_first: usize,
    /// Precomputed last-row selector: `(z^N - 1) / (z - g^{-1})`.
    pub is_last: usize,
    /// Precomputed transition selector: `z - g^{-1}`.
    pub is_transition: usize,
    /// Batching challenge `gamma` for reduced_aux_values.
    pub gamma: usize,

    // -- Base-field values stored as (val, 0) in EF slots --
    /// First barycentric weight `1 / (k * s0^{k-1})`.
    pub weight0: usize,
    /// `f = h^N` (chunk shift ratio between cosets).
    pub f: usize,
    /// `s0 = offset^N` (first chunk shift).
    pub s0: usize,
}

/// ACE input layout for Plonky3-based verifier logic.
///
/// This describes the exact ordering and alignment of inputs consumed by the
/// ACE chiplet (READ section).
#[derive(Debug, Clone)]
pub struct InputLayout {
    /// Grouped regions for the ACE input layout.
    pub(crate) regions: LayoutRegions,
    /// Input index for aux randomness alpha.
    pub(crate) aux_rand_alpha: usize,
    /// Input index for aux randomness beta.
    pub(crate) aux_rand_beta: usize,
    /// Stride between logical VLPI groups (2 for MASM word-aligned, 1 for native).
    pub(crate) vlpi_stride: usize,
    /// Indexes into the stark-vars region.
    pub(crate) stark: StarkVarIndices,
    /// Total number of inputs (length of the READ section).
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

    /// Validate internal invariants for this layout (region sizes, key ranges, randomness inputs).
    pub(crate) fn validate(&self) {
        let mut max_end = 0usize;
        for region in [
            self.regions.public_values,
            self.regions.vlpi_reductions,
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
        // Extension-field slots.
        check("alpha", self.stark.alpha);
        check("z_pow_n", self.stark.z_pow_n);
        check("z_k", self.stark.z_k);
        check("is_first", self.stark.is_first);
        check("is_last", self.stark.is_last);
        check("is_transition", self.stark.is_transition);
        check("gamma", self.stark.gamma);
        // Base-field slots (stored as (val, 0) in the EF slot).
        check("weight0", self.stark.weight0);
        check("f", self.stark.f);
        check("s0", self.stark.s0);

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
