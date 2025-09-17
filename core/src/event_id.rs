use core::fmt::{Display, Formatter};

use crate::{Felt, utils::hash_string_to_word};

/// A type-safe wrapper around a [`Felt`] that represents an event identifier.
///
/// Event IDs are used to identify events that can be emitted by the VM or handled by the host.
/// This newtype provides type safety and ensures that event IDs are not accidentally confused
/// with other [`Felt`] values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventId(Felt);

impl EventId {
    /// Computes the canonical event identifier for the given `name`.
    ///
    /// This function provides a stable, deterministic mapping from human-readable event names
    /// to field elements that can be used as event identifiers in the VM. The mapping works by:
    /// 1. Computing the BLAKE3 hash of the event name (produces 32 bytes)
    /// 2. Taking the first 8 bytes of the hash
    /// 3. Interpreting these bytes as a little-endian u64
    /// 4. Reducing modulo the field prime to create a valid Felt
    ///
    /// Note that this is the same procedure performed by [`hash_string_to_word`], where we take
    /// the first element of the resulting [`Word`](crate::Word).
    ///
    /// This ensures that identical event names always produce the same event ID, while
    /// providing good distribution properties to minimize collisions between different names.
    pub fn from_name(name: impl AsRef<str>) -> Self {
        let digest_word = hash_string_to_word(name.as_ref());

        Self(digest_word[0])
    }

    /// Creates a new event ID from a [`Felt`].
    pub const fn from_felt(value: Felt) -> Self {
        Self(value)
    }

    /// Creates a new event ID from a u64, converting it to a [`Felt`].
    pub const fn from_u64(value: u64) -> Self {
        Self(Felt::new(value))
    }

    /// Returns the underlying [`Felt`] value.
    pub const fn as_felt(&self) -> Felt {
        self.0
    }
}

impl PartialOrd for EventId {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EventId {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.inner().cmp(&other.0.inner())
    }
}

impl Display for EventId {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, f)
    }
}
