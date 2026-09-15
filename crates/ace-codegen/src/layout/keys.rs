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
    /// Fold coefficient for the AIR instance at the given index.
    ///
    /// Has a real READ-layout slot. Each relation's generated evaluator
    /// (`sys/<relation>/constraints_eval.masm`) populates it with `beta^(N-1-pos(k))`, where
    /// `pos(k)` is the AIR's position in the height-sorted proof order, by walking the staged
    /// proof-order maps.
    MultiAirFoldCoeff(usize),
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
    /// `zeta^N_max`, where `N_max` is the maximum trace length represented by the circuit.
    ZPowN,
    /// Periodic-column evaluation basis `zeta^(N_max / shared_period)`.
    /// A period-`p` column is evaluated at `ZK^(shared_period / p)`.
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
    /// Primitive `D`-th root of unity, where `D` is the quotient chunk count; the chunk shift
    /// ratio between cosets after taking the trace-height power.
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

impl InputLayout {
    /// Map a logical `InputKey` into the flat input index, if present.
    pub fn index(&self, key: InputKey) -> Option<usize> {
        match key {
            InputKey::Public(i) => self.regions.public_values.index(i),
            InputKey::AuxRandAlpha => Some(self.aux_rand_alpha),
            InputKey::AuxRandBeta => Some(self.aux_rand_beta),
            InputKey::MultiAirFoldBeta => self.stark.multi_air_fold_beta_index(),
            // Present in the READ layout only under a canonical composition; the per-order
            // oracle composition leaves `fold_coeff_start` unset and this falls through to
            // `None`, since `build_multi_air_ace_circuit` bakes each AIR's fold coefficient
            // into that order's circuit gates directly instead of reading it.
            InputKey::MultiAirFoldCoeff(i) => self.stark.multi_air_fold_coeff_index(i),
            InputKey::Preprocessed { offset, index } => match offset {
                0 => self.regions.preprocessed_curr.index(index),
                1 => self.regions.preprocessed_next.index(index),
                _ => None,
            },
            InputKey::Main { offset, index } => match offset {
                0 => self.regions.main_curr.index(index),
                1 => self.regions.main_next.index(index),
                _ => None,
            },
            InputKey::AuxCoord { offset, index, coord } => {
                if index >= self.counts.aux_width || coord >= EXT_DEGREE {
                    return None;
                }
                let local = index * EXT_DEGREE + coord;
                match offset {
                    0 => self.regions.aux_curr.index(local),
                    1 => self.regions.aux_next.index(local),
                    _ => None,
                }
            },
            InputKey::AuxBusBoundary(i) => self.regions.aux_bus_boundary.index(i),
            InputKey::Reserved => Some(self.stark.reserved),
            InputKey::Alpha => Some(self.stark.alpha),
            InputKey::ZPowN => Some(self.stark.z_pow_n),
            InputKey::ZK => Some(self.stark.z_k),
            InputKey::IsFirst => Some(self.stark.is_first),
            InputKey::IsLast => Some(self.stark.is_last),
            InputKey::IsTransition => Some(self.stark.is_transition),
            InputKey::IsFirstAir(i) => self.stark.air_selector_index(i, AIR_SELECTOR_FIRST_OFFSET),
            InputKey::IsLastAir(i) => self.stark.air_selector_index(i, AIR_SELECTOR_LAST_OFFSET),
            InputKey::IsTransitionAir(i) => {
                self.stark.air_selector_index(i, AIR_SELECTOR_TRANSITION_OFFSET)
            },
            InputKey::Weight0 => Some(self.stark.weight0),
            InputKey::F => Some(self.stark.f),
            InputKey::S0 => Some(self.stark.s0),
            InputKey::QuotientChunkCoord { offset, chunk, coord } => {
                if chunk >= self.counts.num_quotient_chunks || coord >= EXT_DEGREE {
                    return None;
                }
                let idx = chunk * EXT_DEGREE + coord;
                match offset {
                    0 => self.regions.quotient_curr.index(idx),
                    1 => self.regions.quotient_next.index(idx),
                    _ => None,
                }
            },
        }
    }
}
