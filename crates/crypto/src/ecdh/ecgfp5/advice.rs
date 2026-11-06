use alloc::vec::Vec;

use super::{
    SecretKey,
    native::{curve::Point, field::GFp5},
};
use crate::{Felt, merkle::InnerNodeInfo, utils::zeroize::Zeroizing};

pub(super) const A_OVER_THREE: GFp5 = GFp5::from_u64_reduce(6148914689804861441, 0, 0, 0, 0);
const WEIERSTRASS_A: GFp5 = GFp5::from_u64_reduce(6148914689804861439, 263, 0, 0, 0);

/// Private scalar-multiplication witnesses, including Merkle paths for preprocessed keys.
///
/// The owned advice-element buffer is erased on drop. Copies handed to a VM advice provider
/// and intermediate arithmetic values are outside that guarantee. Merkle nodes are selected
/// using secret digits and must also be treated as private witness data.
pub struct AgreementAdvice {
    pub(super) elements: Zeroizing<Vec<u64>>,
    pub(super) nodes: Vec<InnerNodeInfo>,
}

impl AgreementAdvice {
    pub(super) fn new(secret: &SecretKey, capacity: usize) -> Self {
        let mut elements = Zeroizing::new(Vec::with_capacity(capacity));
        for chunk in secret.to_bytes().chunks_exact(4) {
            elements.push(u32::from_le_bytes(chunk.try_into().unwrap()) as u64);
        }
        Self { elements, nodes: Vec::new() }
    }

    /// Returns advice elements in consumption order, from the top of the advice stack down.
    pub fn elements(&self) -> impl ExactSizeIterator<Item = Felt> + '_ {
        self.elements.iter().copied().map(Felt::new_unchecked)
    }

    /// Returns the Merkle-store nodes for the selected table entries.
    pub fn merkle_nodes(&self) -> &[InnerNodeInfo] {
        &self.nodes
    }
}

#[derive(Clone, Copy)]
pub(super) struct Affine {
    pub x: GFp5,
    pub y: GFp5,
}

impl Affine {
    pub const ZERO: Self = Self { x: GFp5::ZERO, y: GFp5::ZERO };

    pub fn from_point(point: Point) -> Self {
        let (x, y) = point.to_weierstrass();
        Self { x, y }
    }

    pub fn encode(self) -> GFp5 {
        self.y / (A_OVER_THREE - self.x)
    }

    // Requires finite, unequal, nonopposite points; callers establish this from scalar bounds.
    pub fn add_finite(self, rhs: Self) -> (Self, GFp5) {
        let denominator = rhs.x - self.x;
        debug_assert_eq!(denominator.iszero(), 0);
        let slope = (rhs.y - self.y) / denominator;
        let x = slope.square() - self.x - rhs.x;
        let y = slope * (self.x - x) - self.y;
        (Self { x, y }, slope)
    }

    // A nonidentity point in the odd prime-order subgroup has y != 0.
    pub fn double(self) -> (Self, GFp5) {
        debug_assert_eq!(self.y.iszero(), 0);
        let slope = (self.x.square().mul_small(3) + WEIERSTRASS_A) / self.y.double();
        let x = slope.square() - self.x.double();
        let y = slope * (self.x - x) - self.y;
        (Self { x, y }, slope)
    }
}
