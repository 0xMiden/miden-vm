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
    /// First barycentric weight for quotient recomposition.
    Weight0,
    /// `f = h^N`, the chunk shift ratio between cosets.
    F,
    /// `s0 = offset^N`, the first chunk shift.
    S0,
    /// Base-field coordinate for a quotient chunk opening at `offset`
    /// (0 = zeta, 1 = g * zeta).
    /// Used when `quotient_extension = false` (flattened to base field).
    QuotientChunkCoord {
        offset: usize,
        chunk: usize,
        coord: usize,
    },
    /// Extension-field quotient chunk opening at `offset` (0 = zeta, 1 = g * zeta).
    /// Used when `quotient_extension = true` (committed as EF codewords).
    /// Each chunk occupies 1 EF slot (no coordinate reconstruction needed).
    QuotientChunk { offset: usize, chunk: usize },
}

/// Canonical InputKey → index mapping for a given layout.
#[derive(Debug, Clone, Copy)]
pub(crate) struct InputKeyMapper<'a> {
    pub(super) layout: &'a InputLayout,
}

impl InputKeyMapper<'_> {
    /// Return the input index for a key, if it exists in the layout.
    pub(crate) fn index_of(&self, key: InputKey) -> Option<usize> {
        let layout = self.layout;
        match key {
            InputKey::Public(i) => layout.regions.public_values.index(i),
            InputKey::AuxRandAlpha => Some(layout.aux_rand_alpha),
            InputKey::AuxRandBeta => Some(layout.aux_rand_beta),
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
            InputKey::Gamma => Some(layout.stark.gamma),
            // Base-field stark vars (stored as (val, 0) in the EF slot).
            InputKey::Weight0 => Some(layout.stark.weight0),
            InputKey::F => Some(layout.stark.f),
            InputKey::S0 => Some(layout.stark.s0),
            InputKey::QuotientChunkCoord { offset, chunk, coord } => {
                // Only valid when quotient_extension=false (flattened to base coords).
                if layout.counts.quotient_extension
                    || chunk >= layout.counts.num_quotient_chunks
                    || coord >= EXT_DEGREE
                {
                    return None;
                }
                let idx = chunk * EXT_DEGREE + coord;
                match offset {
                    0 => layout.regions.quotient_curr.index(idx),
                    1 => layout.regions.quotient_next.index(idx),
                    _ => None,
                }
            },
            InputKey::QuotientChunk { offset, chunk } => {
                // Only valid when quotient_extension=true (EF quotient chunks).
                if !layout.counts.quotient_extension || chunk >= layout.counts.num_quotient_chunks {
                    return None;
                }
                match offset {
                    0 => layout.regions.quotient_curr.index(chunk),
                    1 => layout.regions.quotient_next.index(chunk),
                    _ => None,
                }
            },
        }
    }
}
