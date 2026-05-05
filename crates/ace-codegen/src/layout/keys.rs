use super::InputLayout;
use crate::EXT_DEGREE;

/// Logical inputs required by the ACE circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputKey {
    /// Public input at the given index.
    Public(usize),
    /// Aux randomness α supplied as an input.
    AuxRandAlpha,
    /// Aux randomness β supplied as an input.
    AuxRandBeta,
    /// Multi-AIR accumulation challenge β_multi, used when β-folding per-AIR
    /// constraint roots in the combined ACE circuit. Only present in layouts
    /// built with `AceConfig::is_multi_air = true`.
    MultiAirBeta,
    /// Main trace value at (offset, index).
    Main { offset: usize, index: usize },
    /// Base-field coordinate for an aux trace column.
    AuxCoord {
        offset: usize,
        index: usize,
        coord: usize,
    },
    /// Aux bus boundary value at the given index.
    AuxBusBoundary(usize),
    /// Variable-length public input reduction at the given group index.
    VlpiReduction(usize),
    /// Batching challenge gamma for combining the constraint evaluation with the
    /// auxiliary trace boundary checks.
    Gamma,
    /// Composition challenge used to fold constraints.
    Alpha,
    /// `zeta^N`, where `N` is the trace length.
    ZPowN,
    /// `zeta^(N / max_cycle_len)` for periodic columns.
    ZK,
    /// Precomputed first-row selector: `(z^N - 1) / (z - 1)`.
    IsFirst,
    /// Precomputed last-row selector: `(z^N - 1) / (z - g^{-1})`.
    IsLast,
    /// Precomputed transition selector: `z - g^{-1}`.
    IsTransition,
    /// Multi-AIR per-AIR lifted first-row selector for the smaller AIR (Core, when
    /// `core_height ≤ chiplets_height`): `(z^{n_max} - 1) / (z^r - 1)` where
    /// `r = n_max / n_core`. Only present in `is_multi_air = true` layouts.
    IsFirstCore,
    /// Multi-AIR per-AIR lifted last-row selector for the smaller AIR:
    /// `(z^{n_max} - 1) / (z^r - g_core^{-1})` where `g_core = g_max^r`. Only
    /// present in `is_multi_air = true` layouts.
    IsLastCore,
    /// Multi-AIR per-AIR lifted transition selector for the smaller AIR:
    /// `z^r - g_core^{-1}`. Only present in `is_multi_air = true` layouts.
    IsTransitionCore,
    /// First barycentric weight for quotient recomposition.
    Weight0,
    /// `f = h^N`, the chunk shift ratio between cosets.
    F,
    /// `s0 = offset^N`, the first chunk shift.
    S0,
    /// Base-field coordinate for a quotient chunk opening at `offset`
    /// (0 = zeta, 1 = g * zeta).
    QuotientChunkCoord {
        offset: usize,
        chunk: usize,
        coord: usize,
    },
}

/// Canonical InputKey → index mapping for a given layout.
#[derive(Debug, Clone, Copy)]
pub(crate) struct InputKeyMapper<'a> {
    pub(super) layout: &'a InputLayout,
}

impl InputKeyMapper<'_> {
    /// Return the input index for a key, if it exists in the layout.
    pub(crate) fn index_of(self, key: InputKey) -> Option<usize> {
        let layout = self.layout;
        match key {
            InputKey::Public(i) => layout.regions.public_values.index(i),
            InputKey::AuxRandAlpha => Some(layout.aux_rand_alpha),
            InputKey::AuxRandBeta => Some(layout.aux_rand_beta),
            InputKey::MultiAirBeta => layout.stark.multi_air_beta,
            InputKey::Main { offset, index } => match offset {
                0 => layout.regions.main_curr.index(index),
                1 => layout.regions.main_next.index(index),
                _ => None,
            },
            InputKey::AuxCoord { offset, index, coord } => {
                if index >= layout.counts.aux_width || coord >= EXT_DEGREE {
                    return None;
                }
                let local = index * EXT_DEGREE + coord;
                match offset {
                    0 => layout.regions.aux_curr.index(local),
                    1 => layout.regions.aux_next.index(local),
                    _ => None,
                }
            },
            InputKey::AuxBusBoundary(i) => layout.regions.aux_bus_boundary.index(i),
            InputKey::VlpiReduction(i) => {
                let local = i * layout.vlpi_stride;
                layout.regions.vlpi_reductions.index(local)
            },
            // Extension-field stark vars.
            InputKey::Alpha => Some(layout.stark.alpha),
            InputKey::ZPowN => Some(layout.stark.z_pow_n),
            InputKey::ZK => Some(layout.stark.z_k),
            InputKey::IsFirst => Some(layout.stark.is_first),
            InputKey::IsLast => Some(layout.stark.is_last),
            InputKey::IsTransition => Some(layout.stark.is_transition),
            InputKey::IsFirstCore => layout.stark.is_first_core,
            InputKey::IsLastCore => layout.stark.is_last_core,
            InputKey::IsTransitionCore => layout.stark.is_transition_core,
            InputKey::Gamma => Some(layout.stark.gamma),
            // Base-field stark vars (stored as (val, 0) in the EF slot).
            InputKey::Weight0 => Some(layout.stark.weight0),
            InputKey::F => Some(layout.stark.f),
            InputKey::S0 => Some(layout.stark.s0),
            InputKey::QuotientChunkCoord { offset, chunk, coord } => {
                if chunk >= layout.counts.num_quotient_chunks || coord >= EXT_DEGREE {
                    return None;
                }
                let idx = chunk * EXT_DEGREE + coord;
                match offset {
                    0 => layout.regions.quotient_curr.index(idx),
                    1 => layout.regions.quotient_next.index(idx),
                    _ => None,
                }
            },
        }
    }
}
