use alloc::{string::ToString, vec::Vec};

use miden_crypto::Word;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// KERNEL
// ================================================================================================

/// A list of exported kernel procedure hashes defining a VM kernel.
///
/// The internally-stored list always has a consistent order, regardless of the order of procedure
/// list used to instantiate a kernel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true))
)]
pub struct Kernel(Vec<Word>);

impl Kernel {
    /// The maximum number of procedures which can be exported from a Kernel.
    pub const MAX_NUM_PROCEDURES: usize = u8::MAX as usize;

    /// Returns a new [Kernel] instantiated with the specified procedure hashes.
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

    /// Returns a new [Kernel] from owned procedure hashes.
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
        hashes.sort_by_key(|v| v.as_bytes()); // ensure consistent order
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
}

// this is required by AIR as public inputs will be serialized with the proof
impl Serializable for Kernel {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // expect is OK here because the number of procedures is enforced by the constructor
        target.write_u8(self.0.len().try_into().expect("too many kernel procedures"));
        target.write_many(&self.0)
    }
}

impl Deserializable for Kernel {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let len = source.read_u8()? as usize;
        let kernel = source.read_many_iter::<Word>(len)?.collect::<Result<_, _>>()?;
        Self::from_hashes(kernel).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Kernel {
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

    use super::Kernel;
    use crate::{
        Felt, Word,
        serde::{ByteWriter, Deserializable, Serializable, SliceReader},
    };

    #[test]
    fn kernel_read_from_rejects_duplicate_procedure_hashes() {
        let a: Word = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)].into();
        let b: Word = [Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)].into();

        assert!(
            Kernel::new(&[a, a]).is_err(),
            "test precondition: Kernel::new must reject duplicates"
        );

        // Manually serialize a Kernel that contains duplicates. This cannot be constructed via
        // `Kernel::new`, but it can be produced via the binary format.
        let mut bytes = Vec::new();
        bytes.write_u8(3);
        b.write_into(&mut bytes);
        a.write_into(&mut bytes);
        a.write_into(&mut bytes);

        let mut reader = SliceReader::new(&bytes);
        let result = Kernel::read_from(&mut reader);

        assert!(
            result.is_err(),
            "expected Kernel::read_from to reject duplicate procedure hashes"
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn kernel_serde_deserialisation_rejects_duplicate_procedure_hashes() {
        let a: Word = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)].into();

        assert!(
            Kernel::new(&[a, a]).is_err(),
            "test precondition: Kernel::new must reject duplicates"
        );

        // Kernel deserialization should reject duplicates.
        let json = serde_json::to_string(&vec![a, a]).unwrap();
        let result: Result<Kernel, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "expected serde deserialization to reject duplicate procedure hashes"
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn kernel_serde_deserialisation_rejects_too_many_procedure_hashes() {
        let proc_hashes: Vec<Word> = (0u64..=255)
            .map(|n| [Felt::new(n), Felt::new(n + 1), Felt::new(n + 2), Felt::new(n + 3)].into())
            .collect();

        let json = serde_json::to_string(&proc_hashes).unwrap();
        let result: Result<Kernel, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "expected serde deserialization to reject more than MAX_NUM_PROCEDURES hashes"
        );
    }
}
