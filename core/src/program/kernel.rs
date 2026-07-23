use alloc::{string::ToString, vec::Vec};

use miden_crypto::Word;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    chiplets::hasher,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// CONSTANTS
// ================================================================================================

/// Domain tag for the kernel commitment: the registered selector
/// `(KERNEL_COMMITMENT_DOMAIN_ID << 8) | 1` (see the [`domain`](super::domain) module).
pub const KERNEL_DOMAIN_TAG: crate::Felt =
    super::domain::domain_selector(super::domain::KERNEL_COMMITMENT_DOMAIN_ID, 1);

// KERNEL
// ================================================================================================

/// A list of exported kernel procedure hashes defining a VM kernel.
///
/// The internally-stored list always has a consistent order, regardless of the order of procedure
/// list used to instantiate a descriptor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true))
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

    /// Returns the canonical commitment to this kernel: the domain-tagged sequential hash of the
    /// flattened procedure digests, `hash_elements_in_domain(flatten(procs), KERNEL_DOMAIN_TAG)`.
    ///
    /// This is the fixed-size identifier observed by the recursive verifier in place of the raw
    /// digest list. The encoding is normative:
    /// - element order is this descriptor's canonical procedure order (fixed at construction);
    /// - length binding comes from the Sponge2 padding rule (<https://eprint.iacr.org/2024/911>:
    ///   the first capacity element carries `len % rate` and inputs are zero-padded to a rate
    ///   multiple), so digest lists of different lengths cannot collide;
    /// - the empty kernel hashes to the rule's canonical empty-input value.
    pub fn commitment(&self) -> Word {
        hasher::hash_elements_in_domain(Word::words_as_elements(&self.0), KERNEL_DOMAIN_TAG)
    }
}

// this is required by AIR as public inputs will be serialized with the proof
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

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for KernelDescriptor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let kernel = Vec::<Word>::deserialize(deserializer)?;
        Self::from_hashes(kernel).map_err(serde::de::Error::custom)
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

    use super::KernelDescriptor;
    use crate::{
        Felt, Word,
        serde::{ByteWriter, Deserializable, Serializable, SliceReader},
    };

    #[test]
    fn empty_kernel_commitment_matches_hash_of_no_elements() {
        // The empty kernel is the common case; its commitment must equal the canonical
        // domain-tagged hash of zero elements, which the recursive verifier mirrors via
        // `hash_elements_in_domain(ptr, 0, KERNEL_DOMAIN_TAG)`.
        let empty = KernelDescriptor::default();
        assert_eq!(
            empty.commitment(),
            crate::chiplets::hasher::hash_elements_in_domain(&[], super::KERNEL_DOMAIN_TAG)
        );
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

    #[cfg(feature = "serde")]
    #[test]
    fn kernel_serde_deserialisation_rejects_duplicate_procedure_hashes() {
        let a: Word = [
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
        ]
        .into();

        assert!(
            KernelDescriptor::new(&[a, a]).is_err(),
            "test precondition: KernelDescriptor::new must reject duplicates"
        );

        // KernelDescriptor deserialization should reject duplicates.
        let json = serde_json::to_string(&vec![a, a]).unwrap();
        let result: Result<KernelDescriptor, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "expected serde deserialization to reject duplicate procedure hashes"
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn kernel_serde_deserialisation_rejects_too_many_procedure_hashes() {
        let proc_hashes: Vec<Word> = (0u64..=255)
            .map(|n| {
                [
                    Felt::new_unchecked(n),
                    Felt::new_unchecked(n + 1),
                    Felt::new_unchecked(n + 2),
                    Felt::new_unchecked(n + 3),
                ]
                .into()
            })
            .collect();

        let json = serde_json::to_string(&proc_hashes).unwrap();
        let result: Result<KernelDescriptor, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "expected serde deserialization to reject more than MAX_NUM_PROCEDURES hashes"
        );
    }
}
