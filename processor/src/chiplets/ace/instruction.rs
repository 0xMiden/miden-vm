use miden_core::Felt;

use crate::PrimeField64;

/// Number of bits used to represent the ID of a node in the evaluation graph.
/// Define as 30 bits to ensure two indices and the operation can be encoded in a single `Felt`
pub const ID_BITS: u64 = 30;

/// Maximum allowed ID, also equal to the mask extracting an ID from the lower 30 bits of a
/// `uint`.
pub const MAX_ID: u32 = (1 << ID_BITS) - 1;

/// Arithmetic operation applied to two incoming wires in the evaluation graph.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Op {
    Sub = 0,
    Mul = 1,
    Add = 2,
}

impl TryFrom<u64> for Op {
    type Error = u64;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let op = match value {
            0 => Self::Sub,
            1 => Self::Mul,
            2 => Self::Add,
            _ => return Err(value),
        };
        Ok(op)
    }
}

/// Given a `Felt`, tries to recover the components `id_l, id_r, op`.
pub fn decode_instruction(instruction: Felt) -> Option<(u32, u32, Op)> {
    let mut remaining = instruction.as_canonical_u64();
    let id_l = (remaining & MAX_ID as u64) as u32;
    remaining >>= ID_BITS;
    let id_r = (remaining & MAX_ID as u64) as u32;
    remaining >>= ID_BITS;

    // Ensure the ID did not overflow
    if id_l > MAX_ID || id_r > MAX_ID {
        return None;
    }

    let op = Op::try_from(remaining).ok()?;
    Some((id_l, id_r, op))
}
