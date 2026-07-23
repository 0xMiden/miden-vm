use super::InputLayout;
use crate::EXT_DEGREE;

const AIR_SELECTOR_FIRST_OFFSET: usize = 0;
const AIR_SELECTOR_LAST_OFFSET: usize = 1;
const AIR_SELECTOR_TRANSITION_OFFSET: usize = 2;

/// Logical inputs required by the ACE circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputKey {
    /// Public input at the given index.
    Public(usize),
    /// Aux randomness alpha supplied as an input.
    AuxRandAlpha,
    /// Aux randomness beta supplied as an input.
    AuxRandBeta,
    /// Challenge used to fold per-AIR constraint roots in proof order.
    MultiAirFoldBeta,
    /// Preprocessed trace value at (offset, index).
    Preprocessed { offset: usize, index: usize },
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
    /// Reserved stark-vars slot, kept zero.
    Reserved,
    /// Composition challenge used to fold constraints.
    Alpha,
    /// `zeta^N`, where `N` is the trace length.
    ZPowN,
    /// `zeta^(N / max_cycle_len)` for periodic columns.
    ZK,
    /// Precomputed first-row selector: `(z^N - 1) / (z - 1)`.
    IsFirst,
    /// Precomputed last-row selector: `(z^N - 1) / (z - g^-1)`.
    IsLast,
    /// Precomputed transition selector: `z - g^-1`.
    IsTransition,
    /// Per-AIR lifted first-row selector.
    IsFirstAir(usize),
    /// Per-AIR lifted last-row selector.
    IsLastAir(usize),
    /// Per-AIR lifted transition selector.
    IsTransitionAir(usize),
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

/// Canonical InputKey -> index mapping for a given layout.
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
            InputKey::MultiAirFoldBeta => layout.stark.multi_air_fold_beta_index(),
            InputKey::Preprocessed { offset, index } => match offset {
                0 => layout.regions.preprocessed_curr.index(index),
                1 => layout.regions.preprocessed_next.index(index),
                _ => None,
            },
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
            InputKey::Reserved => Some(layout.stark.reserved),
            InputKey::Alpha => Some(layout.stark.alpha),
            InputKey::ZPowN => Some(layout.stark.z_pow_n),
            InputKey::ZK => Some(layout.stark.z_k),
            InputKey::IsFirst => Some(layout.stark.is_first),
            InputKey::IsLast => Some(layout.stark.is_last),
            InputKey::IsTransition => Some(layout.stark.is_transition),
            InputKey::IsFirstAir(i) => {
                layout.stark.air_selector_index(i, AIR_SELECTOR_FIRST_OFFSET)
            },
            InputKey::IsLastAir(i) => layout.stark.air_selector_index(i, AIR_SELECTOR_LAST_OFFSET),
            InputKey::IsTransitionAir(i) => {
                layout.stark.air_selector_index(i, AIR_SELECTOR_TRANSITION_OFFSET)
            },
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
