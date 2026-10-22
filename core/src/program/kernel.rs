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
    hash_kernel_export(procedure_root, procedure_root)
}

/// Hashes an export key and its implementation root into a kernel Merkle leaf.
pub fn hash_kernel_export(key: Word, procedure_root: Word) -> Word {
    Eidos::hash_double_word_in_domain(&[key, procedure_root], super::domain::KERNEL_EXPORT)
}

/// Derives a stable kernel export key from a canonical, fully qualified procedure path.
///
/// The caller must supply the exported path, including the procedure name, rather than a local
/// import alias. Renaming the export changes its key; changing its implementation does not.
pub fn hash_kernel_key(canonical_path: &str) -> Word {
    Eidos::hash_in_domain(canonical_path.as_bytes(), super::domain::KERNEL_KEY)
}

// KERNEL
// ================================================================================================

/// A kernel export binding a call target key to an implementation MAST root.
///
/// Identity exports use the implementation root as their key and authorize legacy syscalls.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct KernelExport {
    /// The target committed to by the syscall node.
    pub key: Word,
    /// The MAST root of the implementation executed by this export.
    pub procedure_root: Word,
}

impl Serializable for KernelExport {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.key.write_into(target);
        self.procedure_root.write_into(target);
    }
}

impl Deserializable for KernelExport {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            key: source.read()?,
            procedure_root: source.read()?,
        })
    }
}

/// The exported key-to-implementation bindings defining a VM kernel.
///
/// Exports are stored in canonical key order, independent of their input order.
///
/// # Serialization
///
/// This prototype encodes a one-byte export count followed by `(key, procedure_root)` pairs.
/// It replaces the previous identity-only descriptor encoding and is not compatible with its
/// nonempty serialized descriptors or program artifacts. Identity exports retain their previous
/// Merkle commitment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serialization_macros::serialization_test
)]
pub struct KernelDescriptor(Vec<KernelExport>);

impl KernelDescriptor {
    /// The maximum number of export bindings in a KernelDescriptor, including identity aliases.
    pub const MAX_NUM_PROCEDURES: usize = u8::MAX as usize;

    /// Returns a new [KernelDescriptor] with identity exports for the specified procedure hashes.
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

    /// Returns a new [KernelDescriptor] from owned procedure hashes as identity exports.
    ///
    /// Hashes are canonicalized into a consistent internal order.
    ///
    /// # Errors
    /// Returns an error if:
    /// - `hashes` contains duplicates.
    /// - `hashes.len()` exceeds [`MAX_NUM_PROCEDURES`](Self::MAX_NUM_PROCEDURES).
    pub fn from_hashes(hashes: Vec<Word>) -> Result<Self, KernelError> {
        Self::from_exports(
            hashes
                .into_iter()
                .map(|procedure_root| KernelExport { key: procedure_root, procedure_root })
                .collect(),
        )
    }

    /// Creates a kernel from export bindings, sorted by the byte representation of their keys.
    ///
    /// Different keys may name the same implementation. Duplicate keys, including conflicting
    /// stable and identity bindings, are rejected. The number of exports must not exceed
    /// [`MAX_NUM_PROCEDURES`](Self::MAX_NUM_PROCEDURES).
    pub fn from_exports(mut exports: Vec<KernelExport>) -> Result<Self, KernelError> {
        if exports.len() > Self::MAX_NUM_PROCEDURES {
            return Err(KernelError::TooManyProcedures(Self::MAX_NUM_PROCEDURES, exports.len()));
        }

        // Canonical ordering is a separate kernel invariant (not just a dedup side effect), so
        // we sort first and then validate uniqueness over the canonical representation.
        exports.sort_by_key(|export| export.key.as_bytes());
        let duplicated = exports.windows(2).any(|pair| pair[0].key == pair[1].key);

        if duplicated {
            Err(KernelError::DuplicatedExportKeys)
        } else {
            Ok(Self(exports))
        }
    }

    /// Creates a kernel from raw hashes without enforcing constructor invariants.
    ///
    /// This is only intended for tests that need intentionally malformed kernels.
    #[cfg(test)]
    pub(crate) fn from_hashes_unchecked(hashes: Vec<Word>) -> Self {
        Self(
            hashes
                .into_iter()
                .map(|procedure_root| KernelExport { key: procedure_root, procedure_root })
                .collect(),
        )
    }

    /// Returns true if this kernel does not contain any procedures.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns true if a procedure is authorized for a legacy syscall by its implementation root.
    ///
    /// A stable export alone does not authorize its implementation root as a call target; that
    /// requires an identity export as well.
    pub fn contains_proc(&self, proc_hash: Word) -> bool {
        self.resolve(proc_hash) == Some(proc_hash)
    }

    /// Returns the implementation root authorized for a call target key.
    pub fn resolve(&self, key: Word) -> Option<Word> {
        self.0
            .binary_search_by_key(&key.as_bytes(), |export| export.key.as_bytes())
            .ok()
            .map(|index| self.0[index].procedure_root)
    }

    /// Returns the exports in canonical key order.
    pub fn exports(&self) -> &[KernelExport] {
        &self.0
    }

    /// Builds the kernel tree from sorted export-pair hashes, followed by zeros.
    /// Empty and singleton kernels use two leaves; larger kernels use the next power of two.
    pub fn to_merkle_tree(&self) -> MerkleTree {
        let mut leaves: Vec<_> = self
            .0
            .iter()
            .map(|export| hash_kernel_export(export.key, export.procedure_root))
            .collect();
        leaves.resize(leaves.len().next_power_of_two().max(2), Word::default());
        MerkleTree::new(leaves).expect("kernel leaf count is a power of two and at least two")
    }

    /// Returns the root of the canonical kernel Merkle tree.
    pub fn commitment(&self) -> Word {
        self.to_merkle_tree().root()
    }
}

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
        let exports = source.read_many_iter::<KernelExport>(len)?.collect::<Result<_, _>>()?;
        Self::from_exports(exports)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// KERNEL ERROR
// ================================================================================================

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KernelError {
    #[error("kernel cannot have duplicated export keys")]
    DuplicatedExportKeys,
    #[error("kernel can have at most {0} exports, received {1}")]
    TooManyProcedures(usize, usize),
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::{
        KernelDescriptor, KernelError, KernelExport, hash_kernel_export, hash_kernel_key,
        hash_kernel_leaf,
    };
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
        let stable =
            KernelDescriptor::from_exports(vec![KernelExport { key: a, procedure_root: b }])
                .unwrap();
        assert_eq!(stable.commitment(), merge(&[hash_kernel_export(a, b), z]));
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
    fn kernel_commitment_is_independent_of_export_order() {
        let key = hash_kernel_key("$kernel::math::increment");
        let alias = hash_kernel_key("$kernel::math::inc");
        let procedure_root = Word::from([1_u32, 2, 3, 4]);
        let stable = KernelExport { key, procedure_root };
        let alias = KernelExport { key: alias, procedure_root };
        let kernel = KernelDescriptor::from_exports(vec![stable, alias]).unwrap();

        assert_eq!(kernel.resolve(key), Some(procedure_root));
        assert_eq!(kernel.resolve(alias.key), Some(procedure_root));
        assert_eq!(kernel.resolve(procedure_root), None);
        assert!(!kernel.contains_proc(procedure_root));
        assert_eq!(kernel, KernelDescriptor::from_exports(vec![alias, stable]).unwrap());

        let identity = KernelExport { key: procedure_root, procedure_root };
        let with_identity = KernelDescriptor::from_exports(vec![stable, alias, identity]).unwrap();
        assert!(with_identity.contains_proc(procedure_root));
        for changed in [
            KernelExport {
                key: hash_kernel_key("$kernel::math::decrement"),
                procedure_root,
            },
            KernelExport {
                key,
                procedure_root: Word::from([5_u32, 6, 7, 8]),
            },
        ] {
            assert_ne!(
                kernel.commitment(),
                KernelDescriptor::from_exports(vec![changed, alias]).unwrap().commitment(),
            );
        }
    }

    #[test]
    fn kernel_read_from_rejects_duplicate_export_keys() {
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

        let stable = KernelExport { key: a, procedure_root: b };
        let identity = KernelExport { key: b, procedure_root: b };
        let kernel = KernelDescriptor::from_exports(vec![stable, identity]).unwrap();
        assert_eq!(KernelDescriptor::read_from_bytes(&kernel.to_bytes()).unwrap(), kernel);

        // Reject repeated keys even when they bind different implementations.
        for duplicate in [stable, KernelExport { key: a, procedure_root: a }] {
            assert_eq!(
                KernelDescriptor::from_exports(vec![stable, duplicate]),
                Err(KernelError::DuplicatedExportKeys),
            );
            let mut bytes = Vec::new();
            bytes.write_u8(3);
            for export in [identity, stable, duplicate] {
                export.write_into(&mut bytes);
            }
            assert!(KernelDescriptor::read_from(&mut SliceReader::new(&bytes)).is_err());
        }
    }
}
