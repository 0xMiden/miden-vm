//! Eidos rotation relations shared by the MVM and PVM byte-pair tables.
//!
//! Compression rows keep each byte's physical contribution to the rotated word. Lookup messages
//! divide that contribution by a position-only scale, leaving every message affine in the trace
//! while allowing three rotation positions to reuse the canonical XOR relation.

use miden_core::{Felt, field::Algebra};

/// Number of byte-pair relations, excluding the independent range-check relation.
pub const NUM_RELATIONS: usize = BytePairRelation::Rot7Pos3 as usize + 1;

/// Eidos rotation family used by the second half of a BLAKE3 G function.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Rotation {
    Rot12,
    Rot7,
}

impl Rotation {
    /// Returns the supported Eidos rotation for `bits`.
    ///
    /// # Panics
    ///
    /// Panics unless `bits` is 7 or 12.
    pub const fn from_bits(bits: u32) -> Self {
        match bits {
            12 => Self::Rot12,
            7 => Self::Rot7,
            _ => panic!("Eidos rotation must be 7 or 12 bits"),
        }
    }

    const fn bits(self) -> u32 {
        match self {
            Self::Rot12 => 12,
            Self::Rot7 => 7,
        }
    }
}

/// Normalized relation selected by one byte-pair interaction.
///
/// Each discriminant is also the relation's multiplicity-column index; provider values use the
/// same order internally.
#[repr(usize)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum BytePairRelation {
    CanonicalXor = 0,
    Rot12Pos1 = 1,
    Rot7Pos0 = 2,
    Rot7Pos2 = 3,
    Rot12Pos3 = 4,
    Rot7Pos3 = 5,
}

impl BytePairRelation {
    pub const fn index(self) -> usize {
        self as usize
    }

    /// Returns the normalized relation for one byte position of `rotation`.
    ///
    /// # Panics
    ///
    /// Panics unless `byte_position` is in `0..4`.
    pub const fn for_rotation(rotation: Rotation, byte_position: usize) -> Self {
        match (rotation, byte_position) {
            (Rotation::Rot12, 0 | 2) | (Rotation::Rot7, 1) => Self::CanonicalXor,
            (Rotation::Rot12, 1) => Self::Rot12Pos1,
            (Rotation::Rot7, 0) => Self::Rot7Pos0,
            (Rotation::Rot7, 2) => Self::Rot7Pos2,
            (Rotation::Rot12, 3) => Self::Rot12Pos3,
            (Rotation::Rot7, 3) => Self::Rot7Pos3,
            _ => panic!("Eidos byte position must be in 0..4"),
        }
    }
}

/// Returns one XOR byte's contribution to the selected 32-bit rotation.
///
/// # Panics
///
/// Panics unless `byte_position` is in `0..4`.
pub const fn contribution(rotation: Rotation, byte_position: usize, lhs: u8, rhs: u8) -> u32 {
    assert!(byte_position < 4, "Eidos byte position must be in 0..4");
    let word = ((lhs ^ rhs) as u32) << (8 * byte_position);
    word.rotate_right(rotation.bits())
}

// Explicit base-field scalars avoid expanding generic power-of-two operations in the symbolic ACE
// circuit.
const INV_TWO_POW_20: Felt = Felt::new_unchecked(18_446_726_477_228_544_001);
const INV_TWO: Felt = Felt::new_unchecked(9_223_372_034_707_292_161);
const INV_TWO_POW_4: Felt = Felt::new_unchecked(17_293_822_565_076_172_801);
const TWO_POW_5: Felt = Felt::new_unchecked(1 << 5);
const TWO_POW_12: Felt = Felt::new_unchecked(1 << 12);
const TWO_POW_17: Felt = Felt::new_unchecked(1 << 17);

const fn position_scale(byte_position: usize) -> Felt {
    match byte_position {
        0 => Felt::new_unchecked(1 << 20),
        1 => Felt::new_unchecked(1 << 1),
        2 => Felt::new_unchecked(1 << 4),
        3 => Felt::new_unchecked(1),
        _ => panic!("Eidos byte position must be in 0..4"),
    }
}

const fn normalization_factor(byte_position: usize) -> Felt {
    match byte_position {
        0 => INV_TWO_POW_20,
        1 => INV_TWO,
        2 => INV_TWO_POW_4,
        3 => Felt::ONE,
        _ => panic!("Eidos byte position must be in 0..4"),
    }
}

/// Maps an actual rotation contribution to its position-normalized lookup value.
///
/// # Panics
///
/// Panics unless `byte_position` is in `0..4`.
pub fn normalize<E: Algebra<Felt>>(byte_position: usize, contribution: E) -> E {
    contribution * normalization_factor(byte_position)
}

/// Maps a normalized lookup value back to the physical position representation.
///
/// # Panics
///
/// Panics unless `byte_position` is in `0..4`.
pub fn denormalize<E: Algebra<Felt>>(byte_position: usize, value: E) -> E {
    value * position_scale(byte_position)
}

/// Returns the six provider values in [`BytePairRelation`] order.
pub fn provider_values<E: Algebra<Felt>>(x: E, wrap12: E, wrap7: E) -> [E; NUM_RELATIONS] {
    [
        x.clone(),
        normalize(1, wrap12),
        normalize(0, wrap7),
        x.clone() * TWO_POW_5,
        x.clone() * TWO_POW_12,
        x * TWO_POW_17,
    ]
}

#[cfg(test)]
impl BytePairRelation {
    pub(crate) fn expected_value(self, lhs: u8, rhs: u8) -> Felt {
        let x = Felt::from(lhs ^ rhs);
        let wrap12 = Felt::from(contribution(Rotation::Rot12, 1, lhs, rhs));
        let wrap7 = Felt::from(contribution(Rotation::Rot7, 0, lhs, rhs));
        provider_values(x, wrap12, wrap7)[self.index()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_contribution(rotation: Rotation, byte_position: usize, lhs: u8, rhs: u8) -> u32 {
        let bits = match rotation {
            Rotation::Rot12 => 12,
            Rotation::Rot7 => 7,
        };
        (u32::from(lhs ^ rhs) << (8 * byte_position)).rotate_right(bits)
    }

    #[test]
    fn normalized_relations_match_every_rotation_contribution() {
        for lhs in 0u16..=255 {
            for rhs in 0u16..=255 {
                let (lhs, rhs) = (lhs as u8, rhs as u8);
                for rotation in [Rotation::Rot12, Rotation::Rot7] {
                    for byte_position in 0..4 {
                        let relation = BytePairRelation::for_rotation(rotation, byte_position);
                        let reference = reference_contribution(rotation, byte_position, lhs, rhs);
                        assert_eq!(contribution(rotation, byte_position, lhs, rhs), reference,);
                        assert_eq!(
                            relation.expected_value(lhs, rhs),
                            normalize(byte_position, Felt::from(reference)),
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn position_normalization_is_invertible() {
        for byte_position in 0..4 {
            for value in 0u16..=255 {
                let value = Felt::from(value);
                assert_eq!(denormalize(byte_position, normalize(byte_position, value)), value);
            }
        }
    }
}
