use alloc::{string::ToString, vec::Vec};

use miden_crypto::{
    Word,
    hash::eidos::{Eidos, EidosDomain},
    merkle::MerkleTree,
};

use crate::serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// CONSTANTS
// ================================================================================================

/// Reserved domain tag for the legacy sequential kernel commitment.
pub const KERNEL_DOMAIN_TAG: crate::Felt = super::domain::KernelCommitmentDomain::TAG.as_felt();

/// Hashes the identity export pair `procedure_root || procedure_root` under `KERNEL_EXPORT`.
/// This separates authorized leaves from Merkle inner nodes, independently of the path depth.
pub fn hash_kernel_leaf(procedure_root: Word) -> Word {
    Eidos::hash_double_word_in_domain(
        &[procedure_root, procedure_root],
        super::domain::KERNEL_EXPORT,
    )
}

// KERNEL
// ================================================================================================

/// A list of exported kernel procedure hashes defining a VM kernel.
///
/// The internally-stored list always has a consistent order, regardless of the order of procedure
/// list used to instantiate a descriptor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serialization_macros::serialization_test
)]
pub struct KernelDescriptor(Vec<Word>);

impl KernelDescriptor {
    /// The maximum number of procedures which can be exported from a KernelDescriptor.
    pub const MAX_NUM_PROCEDURES: usize = u8::MAX as usize;

    /// Returns a new [KernelDescriptor] instantiated with the specified procedure hashes.
    ///
    /// Hashes are canonicalized into a consistent internal order.
    ///
    /// # Errors
    /// Returns an error if:
    /// - `proc_hashes` contains duplicates.
    /// - `proc_hashes.len()` exceeds [`MAX_NUM_PROCEDURES`](Self::MAX_NUM_PROCEDURES).
    pub fn new(proc_hashes: &[Word]) -> Result<Self, KernelError> {
        Self::from_hashes(proc_hashes.to_vec())
    }

    /// Returns a new [KernelDescriptor] from owned procedure hashes.
    ///
    /// Hashes are canonicalized into a consistent internal order.
    ///
    /// # Errors
    /// Returns an error if:
    /// - `hashes` contains duplicates.
    /// - `hashes.len()` exceeds [`MAX_NUM_PROCEDURES`](Self::MAX_NUM_PROCEDURES).
    pub fn from_hashes(mut hashes: Vec<Word>) -> Result<Self, KernelError> {
        if hashes.len() > Self::MAX_NUM_PROCEDURES {
            return Err(KernelError::TooManyProcedures(Self::MAX_NUM_PROCEDURES, hashes.len()));
        }

        // Canonical ordering is a separate kernel invariant (not just a dedup side effect), so
        // we sort first and then validate uniqueness over the canonical representation.
        hashes.sort_by_key(Word::as_bytes); // ensure consistent order
        let duplicated = hashes.windows(2).any(|data| data[0] == data[1]);

        if duplicated {
            Err(KernelError::DuplicatedProcedures)
        } else {
            Ok(Self(hashes))
        }
    }

    /// Creates a kernel from raw hashes without enforcing constructor invariants.
    ///
    /// This is only intended for tests that need intentionally malformed kernels.
    #[cfg(test)]
    pub(crate) fn from_hashes_unchecked(hashes: Vec<Word>) -> Self {
        Self(hashes)
    }

    /// Returns true if this kernel does not contain any procedures.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns true if a procedure with the specified hash belongs to this kernel.
    ///
    /// Note: the kernel is constructed from exported kernel procedures only.
    pub fn contains_proc(&self, proc_hash: Word) -> bool {
        // Note: we can't use `binary_search()` here because the hashes were sorted using a
        // different key that the `binary_search` algorithm uses.
        self.0.contains(&proc_hash)
    }

    /// Returns a list of procedure hashes contained in this kernel.
    pub fn proc_hashes(&self) -> &[Word] {
        &self.0
    }

    /// Builds the kernel tree from sorted identity export-pair hashes, followed by zeros.
    /// Empty and singleton kernels use two leaves; larger kernels use the next power of two.
    pub fn to_merkle_tree(&self) -> MerkleTree {
        let mut leaves: Vec<_> = self.0.iter().copied().map(hash_kernel_leaf).collect();
        leaves.resize(leaves.len().next_power_of_two().max(2), Word::default());
        MerkleTree::new(leaves).expect("kernel leaf count is a power of two and at least two")
    }

    /// Returns the root of the canonical kernel Merkle tree.
    pub fn commitment(&self) -> Word {
        self.to_merkle_tree().root()
    }
}

// The full descriptor is retained in program artifacts and private execution witnesses.
impl Serializable for KernelDescriptor {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // expect is OK here because the number of procedures is enforced by the constructor
        target.write_u8(self.0.len().try_into().expect("too many kernel procedures"));
        target.write_many(&self.0)
    }
}

impl Deserializable for KernelDescriptor {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let len = source.read_u8()? as usize;
        let kernel = source.read_many_iter::<Word>(len)?.collect::<Result<_, _>>()?;
        Self::from_hashes(kernel).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// KERNEL ERROR
// ================================================================================================

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KernelError {
    #[error("kernel cannot have duplicated procedures")]
    DuplicatedProcedures,
    #[error("kernel can have at most {0} procedures, received {1}")]
    TooManyProcedures(usize, usize),
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::{KernelDescriptor, hash_kernel_leaf};
    use crate::{
        Felt, Word,
        serde::{ByteWriter, Deserializable, Serializable, SliceReader},
    };

    #[test]
    fn padded_kernel_tree_vectors() {
        use crate::chiplets::hasher::merge;
        let z = Word::default();
        let a = Word::from([1_u32, 0, 0, 0]);
        let b = Word::from([2_u32, 0, 0, 0]);
        let c = Word::from([3_u32, 0, 0, 0]);
        let [la, lb, lc] = [a, b, c].map(hash_kernel_leaf);
        for (leaves, root, depth) in [
            (vec![], merge(&[z, z]), 1),
            (vec![a], merge(&[la, z]), 1),
            (vec![a, b], merge(&[la, lb]), 1),
            (vec![c, a, b], merge(&[merge(&[la, lb]), merge(&[lc, z])]), 2),
        ] {
            let kernel = KernelDescriptor::new(&leaves).unwrap();
            assert_eq!(kernel.commitment(), root);
            assert_eq!(kernel.to_merkle_tree().depth(), depth);
        }
        let leaves: Vec<_> = (1..=KernelDescriptor::MAX_NUM_PROCEDURES)
            .map(|i| Word::from([i as u32, 0, 0, 0]))
            .collect();
        assert_eq!(KernelDescriptor::new(&leaves).unwrap().to_merkle_tree().depth(), 8);
    }

    #[test]
    fn kernel_inner_nodes_cannot_be_reinterpreted_as_leaves() {
        use crate::chiplets::hasher::merge;
        let procedure = Word::from([1_u32, 2, 3, 4]);
        let zero = Word::default();
        let inner = merge(&[hash_kernel_leaf(procedure), zero]);
        let authority = KernelDescriptor::new(&[inner]).unwrap();
        // A two-level path for `procedure` reaches this root if the authority's leaf is raw.
        let descendant_root = merge(&[inner, zero]);
        assert_ne!(authority.commitment(), descendant_root);
        assert!(!authority.contains_proc(procedure));
    }

    #[test]
    fn kernel_commitment_is_independent_of_procedure_order() {
        let a: Word = [
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
        ]
        .into();
        let b: Word = [
            Felt::new_unchecked(5),
            Felt::new_unchecked(6),
            Felt::new_unchecked(7),
            Felt::new_unchecked(8),
        ]
        .into();

        // The kernel canonicalizes procedure order, so the commitment binds the set of
        // procedures, not the order in which they were supplied.
        let in_order = KernelDescriptor::new(&[a, b]).unwrap();
        let reversed = KernelDescriptor::new(&[b, a]).unwrap();
        assert_eq!(in_order.commitment(), reversed.commitment());
    }

    #[test]
    fn kernel_read_from_rejects_duplicate_procedure_hashes() {
        let a: Word = [
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
        ]
        .into();
        let b: Word = [
            Felt::new_unchecked(5),
            Felt::new_unchecked(6),
            Felt::new_unchecked(7),
            Felt::new_unchecked(8),
        ]
        .into();

        assert!(
            KernelDescriptor::new(&[a, a]).is_err(),
            "test precondition: KernelDescriptor::new must reject duplicates"
        );

        // Manually serialize a KernelDescriptor that contains duplicates. This cannot be
        // constructed via `KernelDescriptor::new`, but it can be produced via the binary
        // format.
        let mut bytes = Vec::new();
        bytes.write_u8(3);
        b.write_into(&mut bytes);
        a.write_into(&mut bytes);
        a.write_into(&mut bytes);

        let mut reader = SliceReader::new(&bytes);
        let result = KernelDescriptor::read_from(&mut reader);

        assert!(
            result.is_err(),
            "expected KernelDescriptor::read_from to reject duplicate procedure hashes"
        );
    }
}
