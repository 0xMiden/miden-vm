//! Deferred unsigned 256-bit integer precompile.
//!
//! Values are represented as eight little-endian u32 limbs packed into one deferred data chunk.
//! Arithmetic evaluates modulo `2^256`, matching the wrapping behavior of fixed-width unsigned
//! integer instructions. Division is Euclidean integer division and rejects division by zero during
//! deferred evaluation.

use alloc::{vec, vec::Vec};

use miden_core::{
    Felt, ZERO,
    deferred::{
        DeferredContext, DeferredError, Digest, Node, NodeType, Payload, Precompile,
        PrecompileError, Tag, precompile_id,
    },
};

// PRECOMPILE
// ================================================================================================

/// Deferred precompile for unsigned 256-bit arithmetic.
#[derive(Debug, Default, Clone, Copy)]
pub struct U256Precompile;

impl U256Precompile {
    /// Stable precompile name used to derive the tag id.
    pub const NAME: &'static str = "u256";

    /// Tag discriminants owned by this precompile.
    pub const VALUE_TAG_ID: u32 = 0;
    pub const ADD_TAG_ID: u32 = 1;
    pub const SUB_TAG_ID: u32 = 2;
    pub const MUL_TAG_ID: u32 = 3;
    pub const DIV_TAG_ID: u32 = 4;
    pub const EQ_TAG_ID: u32 = 5;

    /// Stable precompile id derived from [`Self::NAME`].
    pub fn id() -> Felt {
        precompile_id(Self::NAME)
    }

    /// Tag for a canonical U256 value carried in one data chunk.
    pub fn value_tag() -> Tag {
        Self::tag([Felt::from_u32(Self::VALUE_TAG_ID), ZERO, ZERO])
    }

    /// Tag for a wrapping-add expression node.
    pub fn add_tag() -> Tag {
        Self::tag([Felt::from_u32(Self::ADD_TAG_ID), ZERO, ZERO])
    }

    /// Tag for a wrapping-sub expression node.
    pub fn sub_tag() -> Tag {
        Self::tag([Felt::from_u32(Self::SUB_TAG_ID), ZERO, ZERO])
    }

    /// Tag for a wrapping-mul expression node.
    pub fn mul_tag() -> Tag {
        Self::tag([Felt::from_u32(Self::MUL_TAG_ID), ZERO, ZERO])
    }

    /// Tag for a U256 integer-division expression node.
    pub fn div_tag() -> Tag {
        Self::tag([Felt::from_u32(Self::DIV_TAG_ID), ZERO, ZERO])
    }

    /// Tag for a U256 equality predicate.
    pub fn eq_tag() -> Tag {
        Self::tag([Felt::from_u32(Self::EQ_TAG_ID), ZERO, ZERO])
    }

    fn tag(args: [Felt; 3]) -> Tag {
        Tag::precompile(Self::id(), args).expect("u256 precompile id is not framework-reserved")
    }

    /// Builds a canonical U256 value node from little-endian limbs.
    pub fn value_node(limbs: [u32; 8]) -> Node {
        Node::value(Self::value_tag(), limbs.map(Felt::from_u32))
            .expect("value tag is precompile-owned")
    }

    /// Builds a binary expression node.
    pub fn binary_node(op: BinaryOp, lhs: Digest, rhs: Digest) -> Node {
        Node::join(Self::tag_for_op(op), lhs, rhs).expect("binary op tag is precompile-owned")
    }

    /// Builds an equality predicate node.
    pub fn eq_node(lhs: Digest, rhs: Digest) -> Node {
        Node::join(Self::eq_tag(), lhs, rhs).expect("eq tag is precompile-owned")
    }

    fn tag_for_op(op: BinaryOp) -> Tag {
        match op {
            BinaryOp::Add => Self::add_tag(),
            BinaryOp::Sub => Self::sub_tag(),
            BinaryOp::Mul => Self::mul_tag(),
            BinaryOp::Div => Self::div_tag(),
        }
    }

    /// Extracts canonical little-endian u32 limbs from a U256 value node.
    pub fn value_of(node: &Node) -> Result<[u32; 8], DeferredError> {
        decode_limbs(node.payload_for_tag(Self::value_tag())?.as_value()?)
    }

    /// Adds two little-endian U256 values modulo `2^256`.
    pub fn wrapping_add(a: [u32; 8], b: [u32; 8]) -> [u32; 8] {
        let mut out = [0u32; 8];
        let mut carry = 0u64;
        for i in 0..8 {
            let sum = a[i] as u64 + b[i] as u64 + carry;
            out[i] = sum as u32;
            carry = sum >> 32;
        }
        out
    }

    /// Subtracts two little-endian U256 values modulo `2^256`.
    pub fn wrapping_sub(a: [u32; 8], b: [u32; 8]) -> [u32; 8] {
        let mut out = [0u32; 8];
        let mut borrow = 0u64;
        for i in 0..8 {
            let subtrahend = b[i] as u64 + borrow;
            out[i] = a[i].wrapping_sub(subtrahend as u32);
            borrow = u64::from((a[i] as u64) < subtrahend);
        }
        out
    }

    /// Multiplies two little-endian U256 values modulo `2^256`.
    pub fn wrapping_mul(a: [u32; 8], b: [u32; 8]) -> [u32; 8] {
        let mut out = [0u32; 8];
        for i in 0..8 {
            let mut carry = 0u64;
            for j in 0..(8 - i) {
                let cur = out[i + j] as u64 + a[i] as u64 * b[j] as u64 + carry;
                out[i + j] = cur as u32;
                carry = cur >> 32;
            }
        }
        out
    }

    /// Divides `a` by `b` as unsigned U256 integers.
    pub fn checked_div(a: [u32; 8], b: [u32; 8]) -> Option<[u32; 8]> {
        if is_zero(&b) {
            return None;
        }

        let mut quotient = [0u32; 8];
        let mut remainder = [0u32; 8];

        for bit in (0..256).rev() {
            shl1(&mut remainder);
            if bit_is_set(&a, bit) {
                remainder[0] |= 1;
            }
            if cmp(&remainder, &b) != core::cmp::Ordering::Less {
                remainder = Self::wrapping_sub(remainder, b);
                set_bit(&mut quotient, bit);
            }
        }

        Some(quotient)
    }
}

impl Precompile for U256Precompile {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn id(&self) -> Felt {
        Self::id()
    }

    fn init(&self) -> Vec<Node> {
        let mut one = [0u32; 8];
        one[0] = 1;
        vec![Self::value_node([0; 8]), Self::value_node(one), Self::value_node([u32::MAX; 8])]
    }

    fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
        if args[1] != ZERO || args[2] != ZERO {
            return None;
        }

        Some(match Discriminant::classify(args[0])? {
            Discriminant::Value => NodeType::value(),
            Discriminant::BinaryOp(_) | Discriminant::Eq => NodeType::Join,
        })
    }

    fn evaluate(
        &self,
        args: [Felt; 3],
        payload: &Payload,
        context: &mut DeferredContext<'_>,
    ) -> Result<Node, PrecompileError> {
        match U256Node::parse(args, payload)? {
            U256Node::Value => Ok(Node::value(Self::tag(args), *payload.as_value()?)?),
            U256Node::BinaryOp { op, lhs, rhs } => {
                let (lhs, rhs) = context.evaluate_digest_pair(lhs, rhs)?;
                let lhs = context.get_node(&lhs).ok_or(PrecompileError::MissingNode)?;
                let rhs = context.get_node(&rhs).ok_or(PrecompileError::MissingNode)?;
                let a = Self::value_of(lhs)?;
                let b = Self::value_of(rhs)?;
                let value = op.apply(a, b)?;
                Ok(Self::value_node(value))
            },
            U256Node::Eq { lhs, rhs } => {
                context.ensure_equal(lhs, rhs)?;
                Ok(Node::TRUE)
            },
        }
    }
}

// NODE PARSING
// ================================================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Discriminant {
    Value,
    BinaryOp(BinaryOp),
    Eq,
}

impl Discriminant {
    fn classify(disc: Felt) -> Option<Self> {
        match disc.as_canonical_u64() {
            0 => Some(Self::Value),
            1 => Some(Self::BinaryOp(BinaryOp::Add)),
            2 => Some(Self::BinaryOp(BinaryOp::Sub)),
            3 => Some(Self::BinaryOp(BinaryOp::Mul)),
            4 => Some(Self::BinaryOp(BinaryOp::Div)),
            5 => Some(Self::Eq),
            _ => None,
        }
    }
}

/// Recognized U256 binary operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
}

impl BinaryOp {
    fn apply(self, a: [u32; 8], b: [u32; 8]) -> Result<[u32; 8], PrecompileError> {
        Ok(match self {
            Self::Add => U256Precompile::wrapping_add(a, b),
            Self::Sub => U256Precompile::wrapping_sub(a, b),
            Self::Mul => U256Precompile::wrapping_mul(a, b),
            Self::Div => U256Precompile::checked_div(a, b)
                .ok_or(PrecompileError::Other(DeferredError::InvalidPayload))?,
        })
    }
}

enum U256Node {
    Value,
    BinaryOp { op: BinaryOp, lhs: Digest, rhs: Digest },
    Eq { lhs: Digest, rhs: Digest },
}

impl U256Node {
    fn parse(args: [Felt; 3], payload: &Payload) -> Result<Self, PrecompileError> {
        let kind = Discriminant::classify(args[0]).ok_or(PrecompileError::InvalidNode)?;
        Ok(match kind {
            Discriminant::Value => {
                decode_limbs(payload.as_value()?)?;
                Self::Value
            },
            Discriminant::BinaryOp(op) => {
                let (lhs, rhs) = payload.as_join()?;
                Self::BinaryOp { op, lhs, rhs }
            },
            Discriminant::Eq => {
                let (lhs, rhs) = payload.as_join()?;
                Self::Eq { lhs, rhs }
            },
        })
    }
}

// HELPERS
// ================================================================================================

fn decode_limbs(felts: &[Felt; 8]) -> Result<[u32; 8], DeferredError> {
    let mut limbs = [0u32; 8];
    for (i, felt) in felts.iter().enumerate() {
        let v = felt.as_canonical_u64();
        if v > u32::MAX as u64 {
            return Err(DeferredError::InvalidPayload);
        }
        limbs[i] = v as u32;
    }
    Ok(limbs)
}

fn is_zero(limbs: &[u32; 8]) -> bool {
    limbs.iter().all(|limb| *limb == 0)
}

fn bit_is_set(limbs: &[u32; 8], bit: usize) -> bool {
    ((limbs[bit / 32] >> (bit % 32)) & 1) == 1
}

fn set_bit(limbs: &mut [u32; 8], bit: usize) {
    limbs[bit / 32] |= 1u32 << (bit % 32);
}

fn shl1(limbs: &mut [u32; 8]) {
    let mut carry = 0u32;
    for limb in limbs.iter_mut() {
        let next_carry = *limb >> 31;
        *limb = (*limb << 1) | carry;
        carry = next_carry;
    }
}

fn cmp(a: &[u32; 8], b: &[u32; 8]) -> core::cmp::Ordering {
    for i in (0..8).rev() {
        match a[i].cmp(&b[i]) {
            core::cmp::Ordering::Equal => {},
            ordering => return ordering,
        }
    }
    core::cmp::Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;
    fn masm_const(source: &str, name: &str) -> u64 {
        source
            .lines()
            .filter_map(|line| line.trim().strip_prefix("const "))
            .find_map(|assignment| {
                let (const_name, value) = assignment.split_once(" = ")?;
                (const_name == name).then(|| value.parse().ok()).flatten()
            })
            .expect("MASM const must be present and parse as u64")
    }

    const MASM: &str = include_str!("../../asm/math/u256.masm");

    #[test]
    fn arithmetic_wraps_and_divides() {
        assert_eq!(U256Precompile::wrapping_add([u32::MAX; 8], [1, 0, 0, 0, 0, 0, 0, 0]), [0; 8]);
        assert_eq!(U256Precompile::wrapping_sub([0; 8], [1, 0, 0, 0, 0, 0, 0, 0]), [u32::MAX; 8]);
        assert_eq!(
            U256Precompile::wrapping_mul([u32::MAX, 0, 0, 0, 0, 0, 0, 0], [2, 0, 0, 0, 0, 0, 0, 0]),
            [u32::MAX - 1, 1, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            U256Precompile::checked_div([100, 0, 0, 0, 0, 0, 0, 0], [7, 0, 0, 0, 0, 0, 0, 0]),
            Some([14, 0, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(U256Precompile::checked_div([1, 0, 0, 0, 0, 0, 0, 0], [0; 8]), None);
    }

    #[test]
    fn masm_pinned_ids_match_derived_ids() {
        assert_eq!(masm_const(MASM, "PRECOMPILE_ID"), U256Precompile::id().as_canonical_u64());
        assert_eq!(masm_const(MASM, "VALUE_TAG_ID"), U256Precompile::VALUE_TAG_ID as u64);
        assert_eq!(masm_const(MASM, "ADD_TAG_ID"), U256Precompile::ADD_TAG_ID as u64);
        assert_eq!(masm_const(MASM, "SUB_TAG_ID"), U256Precompile::SUB_TAG_ID as u64);
        assert_eq!(masm_const(MASM, "MUL_TAG_ID"), U256Precompile::MUL_TAG_ID as u64);
        assert_eq!(masm_const(MASM, "DIV_TAG_ID"), U256Precompile::DIV_TAG_ID as u64);
        assert_eq!(masm_const(MASM, "EQ_TAG_ID"), U256Precompile::EQ_TAG_ID as u64);

        let mut one = [0u32; 8];
        one[0] = 1;
        assert_digest_consts("ZERO_DIGEST", U256Precompile::value_node([0; 8]).digest());
        assert_digest_consts("ONE_DIGEST", U256Precompile::value_node(one).digest());
        assert_digest_consts("MAX_DIGEST", U256Precompile::value_node([u32::MAX; 8]).digest());
    }

    fn assert_digest_consts(prefix: &str, digest: miden_core::Word) {
        for (i, felt) in digest.as_elements().iter().enumerate() {
            assert_eq!(masm_const(MASM, &alloc::format!("{prefix}_{i}")), felt.as_canonical_u64(),);
        }
    }
}
