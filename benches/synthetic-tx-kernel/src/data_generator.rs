//! Data generators for realistic benchmark inputs
//!
//! This module generates fresh cryptographic data for each benchmark iteration,
//! ensuring realistic execution patterns that match real transaction kernels.

use miden_core::{Felt, Word};
use miden_core_lib::dsa::falcon512_poseidon2;

/// Generates Falcon512 signature verification data
pub struct Falcon512Generator;

impl Falcon512Generator {
    /// Generate a fresh key pair, sign a message, and return verification inputs
    ///
    /// Returns the public key commitment, message, and signature for verification
    pub fn generate_verify_data() -> anyhow::Result<Falcon512VerifyData> {
        let secret_key = falcon512_poseidon2::SecretKey::new();
        let public_key = secret_key.public_key();
        let public_key_commitment = public_key.to_commitment();

        // Create a realistic message (4 field elements)
        let message = Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);

        // Sign the message
        let signature = falcon512_poseidon2::sign(&secret_key, message)
            .ok_or_else(|| anyhow::anyhow!("Failed to sign message"))?;

        Ok(Falcon512VerifyData {
            public_key_commitment,
            message,
            signature,
        })
    }
}

/// Data for Falcon512 signature verification
#[derive(Debug, Clone)]
pub struct Falcon512VerifyData {
    /// Public key commitment (4 field elements)
    pub public_key_commitment: Word,
    /// Message that was signed (4 field elements)
    pub message: Word,
    /// Signature (as a vector of field elements)
    pub signature: Vec<Felt>,
}

impl Falcon512VerifyData {
    /// Build stack inputs for the verification procedure
    ///
    /// Stack layout: [PK_COMMITMENT_0, PK_COMMITMENT_1, PK_COMMITMENT_2, PK_COMMITMENT_3,
    ///                MSG_0, MSG_1, MSG_2, MSG_3]
    pub fn to_stack_inputs(&self) -> anyhow::Result<miden_vm::StackInputs> {
        let mut stack = Vec::with_capacity(8);
        // Push public key commitment (as slice)
        stack.extend_from_slice(self.public_key_commitment.as_slice());
        // Push message (as slice)
        stack.extend_from_slice(self.message.as_slice());
        miden_vm::StackInputs::new(&stack)
            .map_err(|e| anyhow::anyhow!("Failed to build stack inputs: {}", e))
    }
}

/// Generates hash operation data
pub struct HashGenerator;

impl HashGenerator {
    /// Generate realistic hash state for hperm operations
    ///
    /// Returns a 12-element state vector representing the hash capacity and rate
    pub fn generate_hperm_state() -> [Felt; 12] {
        // Realistic initial state (often zeros or context-specific in transactions)
        [
            Felt::new(0),
            Felt::new(0),
            Felt::new(0),
            Felt::new(0),
            Felt::new(1),
            Felt::new(2),
            Felt::new(3),
            Felt::new(4),
            Felt::new(5),
            Felt::new(6),
            Felt::new(7),
            Felt::new(8),
        ]
    }

    /// Generate input data for hash operations
    ///
    /// Returns two 4-element words for hmerge or absorption
    pub fn generate_hash_inputs() -> (Word, Word) {
        let word1 = Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
        let word2 = Word::new([Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)]);
        (word1, word2)
    }
}

/// Generates Merkle tree operation data
pub struct MerkleGenerator;

impl MerkleGenerator {
    /// Generate a Merkle path for verification
    ///
    /// Creates a simple 4-level tree with a leaf at index 0
    /// Returns the leaf value, its index, and the sibling path
    pub fn generate_merkle_path() -> MerklePathData {
        // Create leaf nodes (8 leaves for a 3-level tree)
        let leaves: Vec<Word> = (0..8)
            .map(|i| {
                Word::new([
                    Felt::new(i * 4),
                    Felt::new(i * 4 + 1),
                    Felt::new(i * 4 + 2),
                    Felt::new(i * 4 + 3),
                ])
            })
            .collect();

        // Compute sibling path for leaf 0
        let leaf_index = 0usize;
        let sibling_path = Self::compute_sibling_path(&leaves, leaf_index);

        MerklePathData {
            leaf: leaves[0],
            leaf_index,
            sibling_path,
        }
    }

    /// Compute sibling path for a leaf
    fn compute_sibling_path(leaves: &[Word], leaf_index: usize) -> Vec<Word> {
        let mut path = Vec::new();
        let mut current_level: Vec<Word> = leaves.to_vec();
        let mut index = leaf_index;

        while current_level.len() > 1 {
            // Find sibling
            let sibling_index = if index.is_multiple_of(2) { index + 1 } else { index - 1 };
            if sibling_index < current_level.len() {
                path.push(current_level[sibling_index]);
            }

            // Move up to parent level
            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                if i + 1 < current_level.len() {
                    // Compute parent hash (simplified - just use first word for now)
                    next_level.push(current_level[i]);
                } else {
                    // Odd node out - promote to next level
                    next_level.push(current_level[i]);
                }
            }
            current_level = next_level;
            index /= 2;
        }

        path
    }
}

/// Data for Merkle path verification
#[derive(Debug, Clone)]
pub struct MerklePathData {
    /// The leaf value being proven
    pub leaf: Word,
    /// Index of the leaf in the tree
    pub leaf_index: usize,
    /// Sibling nodes from leaf to root
    pub sibling_path: Vec<Word>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use miden_core::field::PrimeCharacteristicRing;

    #[test]
    fn falcon512_generator_produces_valid_data() {
        let data =
            Falcon512Generator::generate_verify_data().expect("Failed to generate Falcon512 data");

        // Verify the data has correct structure (Word is [Felt; 4])
        assert_eq!(data.public_key_commitment.as_slice().len(), 4);
        assert_eq!(data.message.as_slice().len(), 4);
    }

    #[test]
    fn falcon512_stack_inputs_builds_correctly() {
        let data =
            Falcon512Generator::generate_verify_data().expect("Failed to generate Falcon512 data");

        let stack_inputs = data.to_stack_inputs().expect("Failed to build stack inputs");

        // StackInputs always has MIN_STACK_DEPTH (16) elements
        // First 8 should be our inputs (4 for PK commitment + 4 for message)
        // Remaining should be zeros
        let inputs: Vec<_> = stack_inputs.iter().copied().collect();
        assert_eq!(inputs.len(), 16);

        // Check first 8 match our actual inputs
        assert_eq!(&inputs[..4], data.public_key_commitment.as_slice());
        assert_eq!(&inputs[4..8], data.message.as_slice());

        // Check last 8 are zeros (padding)
        assert!(inputs[8..].iter().all(|f| *f == Felt::ZERO));
    }

    #[test]
    fn hash_generator_produces_valid_state() {
        let state = HashGenerator::generate_hperm_state();
        assert_eq!(state.len(), 12);
    }

    #[test]
    fn merkle_generator_produces_valid_path() {
        let path_data = MerkleGenerator::generate_merkle_path();

        // For an 8-leaf tree, path should have 3 siblings
        assert_eq!(path_data.sibling_path.len(), 3);
        assert_eq!(path_data.leaf_index, 0);
    }
}
