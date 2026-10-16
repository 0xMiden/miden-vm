use alloc::vec::Vec;

use super::{
    PublicKey, SecretKey,
    advice::{Affine, AgreementAdvice},
    native::{curve::Point, field::GFp},
};
use crate::{
    Felt, SequentialCommit, Word,
    hash::eidos::{Eidos, domains::ECGFP5_PREPROCESSED_PUBLIC_KEY},
    merkle::{MerklePath, MerkleTree, NodeIndex},
};

const WINDOWS: usize = 20;
const AXIS_SIZE: usize = 256;
const REBUILD_DEPTH: u8 = 5;
const REBUILD_SIZE: usize = 1 << REBUILD_DEPTH;
const UPPER_DEPTH: u8 = 16 - REBUILD_DEPTH;
const UPPER_LEAVES: usize = 1 << UPPER_DEPTH;

/// A preprocessed public key for the VM's windowed Diffie-Hellman procedure.
///
/// Let `G` be the curve generator and `Q` the recipient's public key. Entry `d` of window `i`
/// stores the pair `(d * 2^(16*i) * G, d * 2^(16*i) * Q)`. The VM selects entries using the
/// scalar's 16-bit digits and sums each side to compute the ephemeral and shared points.
/// Each window has a depth-16 Merkle tree; hashing the twenty roots in order gives the
/// four-Felt public-key commitment against which the VM checks the selected entries.
///
/// The cache occupies about 4.1 MiB of element storage. Each digit is split into two 8-bit
/// axes, and the lowest five Merkle levels are reconstructed when preparing advice. Building
/// the cache hashes all 1,310,720 leaves once; reuse it across agreements with this recipient.
/// All cache contents are public and immutable after construction.
pub struct PreparedPublicKey {
    public_key: PublicKey,
    axes: [Vec<Affine>; 2],
    windows: Vec<MerkleTree>,
    commitment: Word,
}

impl PreparedPublicKey {
    /// Builds the multiplication tables and their commitment for a validated public key.
    pub fn new(public_key: PublicKey) -> Self {
        let axes = [build_axes(Point::GENERATOR), build_axes(public_key.point())];
        let mut result = Self {
            public_key,
            axes,
            windows: Vec::with_capacity(WINDOWS),
            commitment: Word::default(),
        };
        for window in 0..WINDOWS {
            let roots: Vec<_> =
                (0..UPPER_LEAVES).map(|block| result.block(window, block).root()).collect();
            result.windows.push(MerkleTree::new(roots).expect("2048 window subtrees"));
        }
        result.commitment =
            Eidos::hash_elements_in_domain(&result.to_elements(), ECGFP5_PREPROCESSED_PUBLIC_KEY);
        result
    }

    /// Returns the domain-separated Eidos commitment to the twenty window roots.
    pub fn to_commitment(&self) -> Word {
        self.commitment
    }

    /// Returns the curve-point representation of the recipient key.
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// Prepares private advice for `crypto::ecdh::ecgfp5::agree_preprocessed`.
    ///
    /// See the [module-level guidance](super) on handling private advice.
    pub fn advise(&self, ephemeral_secret: &SecretKey) -> AgreementAdvice {
        let (mut advice, accumulators) = self.multiplication_advice::<2>(ephemeral_secret);
        for point in accumulators {
            advice.elements.extend(point.encode().0.map(GFp::to_u64));
        }
        // Window zero, digit one contains (G, Q), independently of the ephemeral scalar.
        let leaf = pack_leaf(self.points(0, 1), false);
        advice.elements.extend(leaf.map(|x| x.as_canonical_u64()));
        advice.nodes.extend(
            self.path(0, 1)
                .authenticated_nodes(1, Eidos::hash_elements(&leaf))
                .expect("digit one lies in the first window"),
        );
        advice
            .elements
            .extend(self.public_key.to_elements().map(|x| x.as_canonical_u64()));
        advice
    }

    /// Supplies only the generator-side slopes for the ordinary-key procedure.
    pub(super) fn generator_advice(&self, secret: &SecretKey) -> (AgreementAdvice, Affine) {
        let (advice, points) = self.multiplication_advice::<1>(secret);
        (advice, points[0])
    }

    // N=1 supplies the generator side; N=2 supplies both sides of each paired entry.
    fn multiplication_advice<const N: usize>(
        &self,
        ephemeral_secret: &SecretKey,
    ) -> (AgreementAdvice, [Affine; N]) {
        let bytes = ephemeral_secret.to_bytes();
        // Reserve space for the scalar, roots, entries and slopes, plus the caller's output advice.
        let mut advice = AgreementAdvice::new(ephemeral_secret, 10 + 80 + 21 * 24 + 19 * 10 + 15);
        let elements = &mut advice.elements;
        for tree in &self.windows {
            elements.extend(tree.root().iter().map(Felt::as_canonical_u64));
        }
        let nodes = &mut advice.nodes;
        nodes.reserve((WINDOWS + 1) * 16);
        let mut accumulators: Option<[Affine; N]> = None;
        for (window, chunk) in bytes.chunks_exact(2).enumerate() {
            let digit = u16::from_le_bytes(chunk.try_into().unwrap());
            if digit == 0 {
                continue;
            }
            let points = self.points(window, digit);
            let leaf = pack_leaf(points, false);
            elements.extend(leaf.map(|x| x.as_canonical_u64()));
            let path = self.path(window, digit);
            nodes.extend(
                path.authenticated_nodes(digit.into(), Eidos::hash_elements(&leaf))
                    .expect("16-bit digit fits the Merkle path"),
            );
            accumulators = Some(match accumulators {
                None => core::array::from_fn(|i| points[i]),
                Some(mut accumulators) => {
                    // The lower-digit prefix s and new term t satisfy
                    // 0 < s < 2^(16*window) <= t and s+t <= r < n: no equal/opposite points.
                    for (accumulator, term) in accumulators.iter_mut().zip(points) {
                        let (sum, slope) = accumulator.add_finite(term);
                        elements.extend(slope.0.map(GFp::to_u64));
                        *accumulator = sum;
                    }
                    accumulators
                },
            });
        }
        (advice, accumulators.expect("a nonzero scalar has a nonzero digit"))
    }

    fn points(&self, window: usize, digit: u16) -> [Affine; 2] {
        self.axes.each_ref().map(|axes| {
            let low = axes[(2 * window) * AXIS_SIZE + (digit & 255) as usize];
            let high = axes[(2 * window + 1) * AXIS_SIZE + (digit >> 8) as usize];
            if digit & 255 == 0 {
                high
            } else if digit >> 8 == 0 {
                low
            } else {
                // For P = G or Q of order n, B = 2^(16*window)*P also has order n, since n is odd.
                // Relative to B, the coefficients are lo = digit & 255 and hi = digit & 0xff00.
                // Since 0 < hi-lo < hi+lo < 2^16 < n, the points are neither equal nor opposite.
                low.add_finite(high).0
            }
        })
    }

    fn block(&self, window: usize, block: usize) -> MerkleTree {
        let leaves: Vec<_> = (0..REBUILD_SIZE)
            .map(|offset| {
                let digit = (block * REBUILD_SIZE + offset) as u16;
                Eidos::hash_elements(&pack_leaf(self.points(window, digit), digit == 0))
            })
            .collect();
        MerkleTree::new(leaves).expect("32 leaves in a reconstructed subtree")
    }

    fn path(&self, window: usize, digit: u16) -> MerklePath {
        let block = digit as usize / REBUILD_SIZE;
        let tree = self.block(window, block);
        let lower_index = NodeIndex::new(REBUILD_DEPTH, digit as u64 % REBUILD_SIZE as u64)
            .expect("index lies within the reconstructed subtree");
        let upper_index =
            NodeIndex::new(UPPER_DEPTH, block as u64).expect("index lies within the window tree");
        let mut nodes = tree.get_path(lower_index).unwrap().nodes().to_vec();
        nodes.extend_from_slice(self.windows[window].get_path(upper_index).unwrap().nodes());
        MerklePath::new(nodes)
    }
}

impl SequentialCommit for PreparedPublicKey {
    type Commitment = Word;

    fn to_commitment(&self) -> Word {
        self.commitment
    }

    fn to_elements(&self) -> Vec<Felt> {
        self.windows.iter().flat_map(|tree| tree.root().into_elements()).collect()
    }
}

fn build_axes(mut base: Point) -> Vec<Affine> {
    let mut axes = Vec::with_capacity(WINDOWS * 2 * AXIS_SIZE);
    for _ in 0..WINDOWS * 2 {
        axes.push(Affine::ZERO);
        let mut point = base;
        for _ in 1..AXIS_SIZE {
            let (x, y) = point.to_weierstrass();
            axes.push(Affine { x, y });
            point += base;
        }
        base = base.mdouble(8);
    }
    axes
}

// Word-aligned x/y prefixes permit streaming loads. The fifth coefficients share the last
// coordinate word; the final word contains a shared identity flag followed by three zeroes.
fn pack_leaf(points: [Affine; 2], identity: bool) -> [Felt; 24] {
    let mut leaf = [Felt::ZERO; 24];
    for (i, coordinate) in
        [points[0].x, points[0].y, points[1].x, points[1].y].into_iter().enumerate()
    {
        for j in 0..4 {
            leaf[4 * i + j] = Felt::new_unchecked(coordinate.0[j].to_u64());
        }
        leaf[16 + i] = Felt::new_unchecked(coordinate.0[4].to_u64());
    }
    leaf[20] = Felt::from_u32(identity as u32);
    leaf
}
