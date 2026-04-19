/// The representation of a single Merkle path.
use alloc::vec::Vec;

use super::{super::MerklePath, MmrError, forest::Forest};
use crate::Word;

// MMR PROOF
// ================================================================================================

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct MmrPath {
    /// The state of the MMR when the MMR path was created.
    forest: Forest,

    /// The position of the leaf value within the MMR.
    position: usize,

    /// The Merkle opening, starting from the value's sibling up to and excluding the root of the
    /// responsible tree.
    merkle_path: MerklePath,
}

impl MmrPath {
    /// Creates a new `MmrPath` with the given forest, position, and merkle path.
    pub fn new(forest: Forest, position: usize, merkle_path: MerklePath) -> Self {
        Self { forest, position, merkle_path }
    }

    /// Returns the state of the MMR when the MMR path was created.
    pub fn forest(&self) -> Forest {
        self.forest
    }

    /// Returns the position of the leaf value within the MMR.
    pub fn position(&self) -> usize {
        self.position
    }

    /// Returns the Merkle opening, starting from the value's sibling up to and excluding the root
    /// of the responsible tree.
    pub fn merkle_path(&self) -> &MerklePath {
        &self.merkle_path
    }

    /// Converts the leaf global position into a local position that can be used to verify the
    /// Merkle path.
    pub fn relative_pos(&self) -> usize {
        self.forest
            .leaf_relative_position(self.position)
            .expect("position must be part of the forest")
    }

    /// Returns index of the MMR peak against which the Merkle path in this proof can be verified.
    pub fn peak_index(&self) -> usize {
        self.forest.tree_index(self.position)
    }

    /// Returns a new [MmrPath] adjusted for a smaller target forest.
    ///
    /// This is useful when receiving authenticated data from a larger MMR and needing to adjust
    /// the path for a smaller MMR. The path is trimmed to include only the nodes relevant
    /// for the target forest.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The target forest does not include this path's position
    /// - The target forest is larger than the current forest
    pub fn with_forest(&self, target_forest: Forest) -> Result<MmrPath, MmrError> {
        // Validate target forest includes the position
        if target_forest.num_leaves() <= self.position {
            return Err(MmrError::PositionNotFound(self.position));
        }

        // Validate target forest is not larger than current forest
        if target_forest > self.forest {
            return Err(MmrError::ForestOutOfBounds(
                target_forest.num_leaves(),
                self.forest.num_leaves(),
            ));
        }

        // Get expected path length for the target forest
        let target_path_len = target_forest
            .leaf_to_corresponding_tree(self.position)
            .expect("position is in target forest") as usize;

        // Trim the merkle path to the target length
        let trimmed_nodes: Vec<_> =
            self.merkle_path.nodes().iter().take(target_path_len).copied().collect();
        let trimmed_path = MerklePath::new(trimmed_nodes);

        Ok(MmrPath::new(target_forest, self.position, trimmed_path))
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct MmrProof {
    /// The Merkle path data describing how to authenticate the leaf.
    path: MmrPath,

    /// The leaf value that was opened.
    leaf: Word,
}

impl MmrProof {
    /// Creates a new `MmrProof` with the given path and leaf.
    pub fn new(path: MmrPath, leaf: Word) -> Self {
        Self { path, leaf }
    }

    /// Returns the Merkle path data describing how to authenticate the leaf.
    pub fn path(&self) -> &MmrPath {
        &self.path
    }

    /// Returns the leaf value that was opened.
    pub fn leaf(&self) -> Word {
        self.leaf
    }

    /// Returns the state of the MMR when the proof was created.
    pub fn forest(&self) -> Forest {
        self.path.forest()
    }

    /// Returns the position of the leaf value within the MMR.
    pub fn position(&self) -> usize {
        self.path.position()
    }

    /// Returns the Merkle opening, starting from the value's sibling up to and excluding the root
    /// of the responsible tree.
    pub fn merkle_path(&self) -> &MerklePath {
        self.path.merkle_path()
    }

    /// Converts the leaf global position into a local position that can be used to verify the
    /// merkle_path.
    pub fn relative_pos(&self) -> usize {
        self.path.relative_pos()
    }

    /// Returns index of the MMR peak against which the Merkle path in this proof can be verified.
    pub fn peak_index(&self) -> usize {
        self.path.peak_index()
    }

    /// Returns a new [MmrProof] adjusted for a smaller target forest.
    ///
    /// This is useful when receiving authenticated data from a larger MMR and needing to adjust
    /// the proof for a smaller MMR. The path is trimmed to include only the nodes relevant
    /// for the target forest.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The target forest does not include this proof's position
    /// - The target forest is larger than the current forest
    pub fn with_forest(&self, target_forest: Forest) -> Result<MmrProof, MmrError> {
        let adjusted_path = self.path.with_forest(target_forest)?;
        Ok(MmrProof::new(adjusted_path, self.leaf))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{MerklePath, MmrPath, MmrProof};
    use crate::{
        Word,
        merkle::{
            int_to_node,
            mmr::{Mmr, forest::Forest},
        },
    };

    #[test]
    fn test_peak_index() {
        // --- single peak forest ---------------------------------------------
        let forest = Forest::new(11).unwrap();

        // the first 4 leaves belong to peak 0
        for position in 0..8 {
            let proof = make_dummy_proof(forest, position);
            assert_eq!(proof.peak_index(), 0);
        }

        // --- forest with non-consecutive peaks ------------------------------
        let forest = Forest::new(11).unwrap();

        // the first 8 leaves belong to peak 0
        for position in 0..8 {
            let proof = make_dummy_proof(forest, position);
            assert_eq!(proof.peak_index(), 0);
        }

        // the next 2 leaves belong to peak 1
        for position in 8..10 {
            let proof = make_dummy_proof(forest, position);
            assert_eq!(proof.peak_index(), 1);
        }

        // the last leaf is the peak 2
        let proof = make_dummy_proof(forest, 10);
        assert_eq!(proof.peak_index(), 2);

        // --- forest with consecutive peaks ----------------------------------
        let forest = Forest::new(7).unwrap();

        // the first 4 leaves belong to peak 0
        for position in 0..4 {
            let proof = make_dummy_proof(forest, position);
            assert_eq!(proof.peak_index(), 0);
        }

        // the next 2 leaves belong to peak 1
        for position in 4..6 {
            let proof = make_dummy_proof(forest, position);
            assert_eq!(proof.peak_index(), 1);
        }

        // the last leaf is the peak 2
        let proof = make_dummy_proof(forest, 6);
        assert_eq!(proof.peak_index(), 2);
    }

    fn make_dummy_proof(forest: Forest, position: usize) -> MmrProof {
        let path = MmrPath::new(forest, position, MerklePath::default());
        MmrProof::new(path, Word::empty())
    }

    #[test]
    fn test_mmr_proof_with_forest() {
        // Create an MMR with 5 leaves
        let mut small_mmr = Mmr::new();
        for i in 0..5 {
            small_mmr.add(int_to_node(i)).unwrap();
        }
        let small_forest = small_mmr.forest();

        // Clone and add 5 more leaves to create larger MMR
        let mut large_mmr = small_mmr.clone();
        for i in 5..10 {
            large_mmr.add(int_to_node(i)).unwrap();
        }

        // Get proof for position 2 from the larger MMR
        let large_proof = large_mmr.open(2).unwrap();
        let small_path_len = small_forest.leaf_to_corresponding_tree(2).unwrap() as u8;

        // Sanity check: larger MMR should have a longer path (otherwise we're not testing trimming)
        assert!(large_proof.merkle_path().depth() > small_path_len);

        // Adjust proof to smaller forest (should remove 1 node from the path)
        let adjusted_proof = large_proof.with_forest(small_forest).unwrap();
        assert_eq!(large_proof.merkle_path().depth() - adjusted_proof.merkle_path().depth(), 1);

        // Verify the adjusted proof is valid in the smaller MMR
        let peak_idx = adjusted_proof.peak_index();
        let relative_pos = adjusted_proof.relative_pos();
        let computed_root = adjusted_proof
            .merkle_path()
            .compute_root(relative_pos as u64, adjusted_proof.leaf())
            .unwrap();
        assert_eq!(computed_root, small_mmr.peaks().peaks()[peak_idx]);
    }

    #[test]
    fn test_mmr_path_with_forest_errors() {
        // Create a MMR with 7 leaves
        let mut mmr = Mmr::new();
        for i in 0..7 {
            mmr.add(int_to_node(i)).unwrap();
        }
        let proof = mmr.open(2).unwrap();
        let path = proof.path();

        // Error: target forest doesn't include position
        let small_forest = Forest::new(2).unwrap();
        assert!(path.with_forest(small_forest).is_err());

        // Error: target forest is larger than current
        let large_forest = Forest::new(15).unwrap();
        assert!(path.with_forest(large_forest).is_err());

        // Same forest should work
        assert!(path.with_forest(mmr.forest()).is_ok());
    }
}
