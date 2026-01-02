use alloc::{collections::BTreeMap, string::String};

use miden_core::{
    Word,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Maps MAST root digests to procedure names for debugging purposes.
///
/// This section contains the names of all procedures (both exported and private)
/// in a package, keyed by their MAST root digest. This allows debuggers to
/// resolve human-readable procedure names during execution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DebugFunctions {
    /// Map from MAST root digest to procedure name
    functions: BTreeMap<[u8; 32], String>,
}

impl DebugFunctions {
    /// Creates a new empty `DebugFunctions` section.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a procedure name for the given MAST root digest.
    pub fn insert(&mut self, digest: Word, name: String) {
        self.functions.insert(word_to_bytes(digest), name);
    }

    /// Returns the procedure name for the given MAST root digest, if present.
    pub fn get(&self, digest: &Word) -> Option<&str> {
        self.functions.get(&word_to_bytes(*digest)).map(|s| s.as_str())
    }

    /// Returns an iterator over all (digest, name) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (Word, &String)> {
        self.functions.iter().map(|(bytes, name)| (bytes_to_word(*bytes), name))
    }

    /// Returns the number of functions in this section.
    pub fn len(&self) -> usize {
        self.functions.len()
    }

    /// Returns true if this section contains no functions.
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }
}

/// Converts a Word to a 32-byte array for use as a map key.
fn word_to_bytes(word: Word) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, felt) in word.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&felt.as_int().to_le_bytes());
    }
    bytes
}

/// Converts a 32-byte array back to a Word.
fn bytes_to_word(bytes: [u8; 32]) -> Word {
    let mut word = Word::default();
    for (i, felt) in word.iter_mut().enumerate() {
        let mut felt_bytes = [0u8; 8];
        felt_bytes.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        *felt = miden_core::Felt::new(u64::from_le_bytes(felt_bytes));
    }
    word
}

impl Serializable for DebugFunctions {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Write number of entries
        target.write_usize(self.functions.len());

        // Write each (digest, name) pair
        for (digest_bytes, name) in &self.functions {
            target.write_bytes(digest_bytes);
            name.write_into(target);
        }
    }
}

impl Deserializable for DebugFunctions {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let count = source.read_usize()?;
        let mut functions = BTreeMap::new();

        for _ in 0..count {
            let digest_bytes: [u8; 32] = source.read_array()?;
            let name = String::read_from(source)?;
            functions.insert(digest_bytes, name);
        }

        Ok(Self { functions })
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use miden_core::Felt;

    use super::*;

    fn make_test_word(val: u64) -> Word {
        Word::new([Felt::new(val), Felt::new(val + 1), Felt::new(val + 2), Felt::new(val + 3)])
    }

    #[test]
    fn test_debug_functions_insert_and_get() {
        let mut debug_fns = DebugFunctions::new();
        let digest1 = make_test_word(100);
        let digest2 = make_test_word(200);

        debug_fns.insert(digest1, "std::math::add".to_string());
        debug_fns.insert(digest2, "my_local_fn".to_string());

        assert_eq!(debug_fns.len(), 2);
        assert_eq!(debug_fns.get(&digest1), Some("std::math::add"));
        assert_eq!(debug_fns.get(&digest2), Some("my_local_fn"));
        assert_eq!(debug_fns.get(&make_test_word(300)), None);
    }

    #[test]
    fn test_debug_functions_serialization_roundtrip() {
        let mut debug_fns = DebugFunctions::new();
        let digest1 = make_test_word(100);
        let digest2 = make_test_word(200);

        debug_fns.insert(digest1, "std::math::add".to_string());
        debug_fns.insert(digest2, "my_local_fn".to_string());

        // Serialize
        let bytes = debug_fns.to_bytes();

        // Deserialize
        let restored = DebugFunctions::read_from_bytes(&bytes).unwrap();

        assert_eq!(debug_fns, restored);
        assert_eq!(restored.get(&digest1), Some("std::math::add"));
        assert_eq!(restored.get(&digest2), Some("my_local_fn"));
    }

    #[test]
    fn test_debug_functions_empty() {
        let debug_fns = DebugFunctions::new();
        assert!(debug_fns.is_empty());
        assert_eq!(debug_fns.len(), 0);

        // Serialization roundtrip of empty section
        let bytes = debug_fns.to_bytes();
        let restored = DebugFunctions::read_from_bytes(&bytes).unwrap();
        assert!(restored.is_empty());
    }

    #[test]
    fn test_word_bytes_roundtrip() {
        let word = make_test_word(12345);
        let bytes = word_to_bytes(word);
        let restored = bytes_to_word(bytes);
        assert_eq!(word, restored);
    }
}
