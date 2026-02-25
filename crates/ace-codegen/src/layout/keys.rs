use super::InputLayout;

/// Logical inputs required by the ACE circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputKey {
    /// Public input at the given index.
    Public(usize),
    /// Randomness challenge at the given index.
    ///
    /// This variant is used when randomness is supplied directly; MASM layouts
    /// typically use `AuxRandAlpha`/`AuxRandBeta` instead.
    Randomness(usize),
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
    /// Out-of-domain evaluation point `zeta`.
    Z,
    /// Composition challenge used to fold constraints.
    Alpha,
    /// `zeta^N`, where `N` is the trace length.
    ZPowN,
    /// `g^{-1}`, inverse trace domain generator.
    GInv,
    /// `g^{-2}`, squared inverse trace domain generator.
    GInv2,
    /// `zeta^(N / max_cycle_len)` for periodic columns.
    ZK,
    /// First barycentric weight for quotient recomposition.
    Weight0,
    /// `g = h^N`, the chunk shift ratio.
    G,
    /// `s0 = offset^N`, the first chunk shift.
    S0,
    /// `1 / (zeta - g^{-1})` (selector denominator).
    InvZMinusGInv,
    /// `1 / (zeta - 1)` (selector denominator).
    InvZMinusOne,
    /// `1 / (zeta^N - 1)` (vanishing inverse).
    InvVanishing,
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
    pub(crate) fn index_of(&self, key: InputKey) -> Option<usize> {
        let layout = self.layout;
        match key {
            InputKey::Public(i) => layout.regions.public_values.index(i),
            InputKey::Randomness(i) => {
                if layout.counts.num_randomness_inputs == layout.counts.num_randomness {
                    layout.regions.randomness.index(i)
                } else {
                    None
                }
            },
            InputKey::AuxRandAlpha => layout.aux_rand_alpha,
            InputKey::AuxRandBeta => layout.aux_rand_beta,
            InputKey::Main { offset, index } => match offset {
                0 => layout.regions.main_curr.index(index),
                1 => layout.regions.main_next.index(index),
                _ => None,
            },
            InputKey::AuxCoord { offset, index, coord } => {
                if index >= layout.counts.aux_width || coord >= layout.counts.ext_degree {
                    return None;
                }
                let local = index * layout.counts.ext_degree + coord;
                match offset {
                    0 => layout.regions.aux_curr.index(local),
                    1 => layout.regions.aux_next.index(local),
                    _ => None,
                }
            },
            InputKey::AuxBusBoundary(i) => layout.regions.aux_bus_boundary.index(i),
            InputKey::Z => Some(layout.stark.z),
            InputKey::Alpha => Some(layout.stark.alpha),
            InputKey::GInv => Some(layout.stark.g_inv),
            InputKey::ZPowN => Some(layout.stark.z_pow_n),
            InputKey::GInv2 => Some(layout.stark.g_inv2),
            InputKey::ZK => Some(layout.stark.z_k),
            InputKey::Weight0 => Some(layout.stark.weight0),
            InputKey::G => Some(layout.stark.g),
            InputKey::S0 => Some(layout.stark.s0),
            InputKey::InvZMinusGInv => Some(layout.stark.inv_z_minus_g_inv),
            InputKey::InvZMinusOne => Some(layout.stark.inv_z_minus_one),
            InputKey::InvVanishing => Some(layout.stark.inv_vanishing),
            InputKey::QuotientChunkCoord { offset, chunk, coord } => {
                if chunk >= layout.counts.num_quotient_chunks || coord >= layout.counts.ext_degree {
                    return None;
                }
                let idx = chunk * layout.counts.ext_degree + coord;
                match offset {
                    0 => layout.regions.quotient_curr.index(idx),
                    1 => layout.regions.quotient_next.index(idx),
                    _ => None,
                }
            },
        }
    }
}
