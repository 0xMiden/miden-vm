use alloc::vec::Vec;

use miden_crypto::Word;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    errors::KernelError,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// KERNEL
// ================================================================================================

/// A list of procedure hashes defining a VM kernel.
///
/// The internally-stored list always has a consistent order, regardless of the order of procedure
/// list used to instantiate a kernel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Kernel(Vec<Word>);

impl Kernel {
    /// The maximum number of procedures which can be exported from a Kernel.
    pub const MAX_NUM_PROCEDURES: usize = u8::MAX as usize;

    /// Returns a new [Kernel] instantiated with the specified procedure hashes.
    pub fn new(proc_hashes: &[Word]) -> Result<Self, KernelError> {
        if proc_hashes.len() > Self::MAX_NUM_PROCEDURES {
            Err(KernelError::TooManyProcedures(Self::MAX_NUM_PROCEDURES, proc_hashes.len()))
        } else {
            let mut hashes = proc_hashes.to_vec();
            hashes.sort_by_key(|v| v.as_bytes()); // ensure consistent order

            let duplicated = hashes.windows(2).any(|data| data[0] == data[1]);

            if duplicated {
                Err(KernelError::DuplicatedProcedures)
            } else {
                Ok(Self(hashes))
            }
        }
    }

    /// Returns true if this kernel does not contain any procedures.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns true if a procedure with the specified hash belongs to this kernel.
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
        let kernel = source.read_many::<Word>(len)?;
        Ok(Self(kernel))
    }
}
