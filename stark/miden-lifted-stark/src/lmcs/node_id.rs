//! Heap-indexed node address in a binary Merkle tree.

/// A node address in a binary Merkle tree using heap indexing.
///
/// Depth 0 = root. At depth `d`, positions range over `0..2^d`.
/// The heap index `(1 << depth) + position` yields a single `usize`
/// whose natural ordering is top-down, left-to-right. Standard tree
/// operations reduce to bit manipulation:
///
/// - `parent()` = `id >> 1`
/// - `sibling()` = `id ^ 1`
/// - `depth()` = `ilog2(id)`
/// - `position()` = `id − 2^depth`
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(usize);

impl NodeId {
    /// Create a node ID from a (depth, position) pair.
    ///
    /// Callers must ensure `position < 2^depth` (except for the root at depth 0,
    /// where position must be 0).
    #[inline]
    pub const fn new(depth: usize, position: usize) -> Self {
        Self((1 << depth) + position)
    }

    /// The depth in the tree (0 = root).
    #[inline]
    pub const fn depth(&self) -> usize {
        self.0.ilog2() as usize
    }

    /// The position within the depth level.
    #[inline]
    pub const fn position(&self) -> usize {
        self.0 - (1 << self.depth())
    }

    /// The sibling node (same depth, position XOR 1).
    #[inline]
    pub const fn sibling(&self) -> Self {
        Self(self.0 ^ 1)
    }

    /// The parent node (depth − 1, position >> 1).
    #[inline]
    pub const fn parent(&self) -> Self {
        Self(self.0 >> 1)
    }
}
