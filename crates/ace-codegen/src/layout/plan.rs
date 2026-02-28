use super::InputKey;
use crate::{AceError, randomness::RandomnessPlan};

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
    /// Number of public inputs.
    pub num_public: usize,
    /// Number of randomness challenges used by the AIR.
    pub num_randomness: usize,
    /// Number of randomness values supplied as inputs.
    ///
    /// Use `num_randomness` for direct randomness, or `2` for alpha/beta seeds.
    pub num_randomness_inputs: usize,
    /// Number of periodic columns.
    pub num_periodic: usize,
    /// Number of auxiliary (stark var) inputs reserved.
    pub num_aux_inputs: usize,
    /// Number of quotient chunks.
    pub num_quotient_chunks: usize,
    /// Extension field degree.
    pub ext_degree: usize,
}

/// Grouped regions for the ACE input layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LayoutRegions {
    /// Region containing fixed-length public values.
    pub public_values: InputRegion,
    /// Region containing randomness inputs (alpha/beta or expanded).
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StarkVarIndices {
    /// Width of the base-field portion of the stark-vars block.
    pub base_width: usize,
    /// Index of `zeta` in the stark-vars block.
    pub z: usize,
    /// Index of the composition challenge `alpha`.
    pub alpha: usize,
    /// Index of `g^{-1}`.
    pub g_inv: usize,
    /// Index of `zeta^N`.
    pub z_pow_n: usize,
    /// Index of `g^{-2}`.
    pub g_inv2: usize,
    /// Index of `z_k`.
    pub z_k: usize,
    /// Index of `weight0`.
    pub weight0: usize,
    /// Index of `g`.
    pub g: usize,
    /// Index of `s0`.
    pub s0: usize,
    /// Index of `1 / (zeta - g^{-1})`.
    pub inv_z_minus_g_inv: usize,
    /// Index of `1 / (zeta - 1)`.
    pub inv_z_minus_one: usize,
    /// Index of `1 / (zeta^N - 1)`.
    pub inv_vanishing: usize,
}

/// ACE input layout for Plonky3-based verifier logic.
///
/// This describes the exact ordering and alignment of inputs consumed by the
/// ACE chiplet (READ section).
#[derive(Debug, Clone)]
pub struct InputLayout {
    /// Grouped regions for the ACE input layout.
    pub(crate) regions: LayoutRegions,
    /// Input index for aux randomness alpha (if provided directly).
    pub(crate) aux_rand_alpha: Option<usize>,
    /// Input index for aux randomness beta (if provided directly).
    pub(crate) aux_rand_beta: Option<usize>,
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
    pub(crate) fn validate(&self) -> Result<(), AceError> {
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

        if max_end > self.total_inputs {
            return Err(AceError::InvalidInputLayout {
                message: "regions exceed total_inputs".to_string(),
            });
        }

        let aux_coord_width =
            self.counts.aux_width.checked_mul(self.counts.ext_degree).ok_or_else(|| {
                AceError::InvalidInputLayout {
                    message: "aux_coord_width overflow".to_string(),
                }
            })?;
        if self.regions.aux_curr.width != aux_coord_width
            || self.regions.aux_next.width != aux_coord_width
        {
            return Err(AceError::InvalidInputLayout {
                message: "aux region width mismatch".to_string(),
            });
        }
        let quotient_width =
            self.counts.num_quotient_chunks.checked_mul(self.counts.ext_degree).ok_or_else(
                || AceError::InvalidInputLayout {
                    message: "quotient_width overflow".to_string(),
                },
            )?;
        if self.regions.quotient_curr.width != quotient_width
            || self.regions.quotient_next.width != quotient_width
        {
            return Err(AceError::InvalidInputLayout {
                message: "quotient region width mismatch".to_string(),
            });
        }
        if self.regions.aux_bus_boundary.width != self.counts.aux_width {
            return Err(AceError::InvalidInputLayout {
                message: "aux bus boundary width mismatch".to_string(),
            });
        }

        let stark_end = self.regions.stark_vars.offset + self.regions.stark_vars.width;
        for (name, idx) in [
            ("z", self.stark.z),
            ("alpha", self.stark.alpha),
            ("g_inv", self.stark.g_inv),
            ("z_pow_n", self.stark.z_pow_n),
            ("g_inv2", self.stark.g_inv2),
            ("z_k", self.stark.z_k),
            ("weight0", self.stark.weight0),
            ("g", self.stark.g),
            ("s0", self.stark.s0),
            ("inv_z_minus_g_inv", self.stark.inv_z_minus_g_inv),
            ("inv_z_minus_one", self.stark.inv_z_minus_one),
            ("inv_vanishing", self.stark.inv_vanishing),
        ] {
            if idx < self.regions.stark_vars.offset || idx >= stark_end {
                return Err(AceError::InvalidInputLayout {
                    message: format!("stark var {name} out of range"),
                });
            }
        }

        if let Some(idx) = self.aux_rand_alpha
            && (idx < self.regions.randomness.offset
                || idx >= self.regions.randomness.offset + self.regions.randomness.width)
        {
            return Err(AceError::InvalidInputLayout {
                message: "aux_rand_alpha out of randomness region".to_string(),
            });
        }
        if let Some(idx) = self.aux_rand_beta
            && (idx < self.regions.randomness.offset
                || idx >= self.regions.randomness.offset + self.regions.randomness.width)
        {
            return Err(AceError::InvalidInputLayout {
                message: "aux_rand_beta out of randomness region".to_string(),
            });
        }

        RandomnessPlan::from_layout(self)?;

        Ok(())
    }
}
