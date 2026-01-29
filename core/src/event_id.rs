use alloc::{borrow::Cow, string::String};
use core::fmt::{Display, Formatter};

use miden_crypto::{
    field::PrimeField64,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{Felt, utils::hash_string_to_word};

// EVENT ID
// ================================================================================================

/// A type-safe event identifier that semantically represents a [`Felt`] value.
///
/// Event IDs are used to identify events that can be emitted by the VM or handled by the host.
/// This newtype provides type safety and ensures that event IDs are not accidentally confused
/// with other field element values.
///
/// Internally stored as `u64` rather than [`Felt`] to enable `const` construction.
///
/// [`EventId`] contains only the identifier. For events with human-readable names,
/// use [`EventName`] instead.
///
/// Event IDs are derived from event names using blake3 hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true))
)]
pub struct EventId(u64);

impl EventId {
    /// Computes the canonical event identifier for the given `name`.
    ///
    /// This function provides a stable, deterministic mapping from human-readable event names
    /// to field elements that can be used as event identifiers in the VM. The mapping works by:
    /// 1. Computing the BLAKE3 hash of the event name (produces 32 bytes)
    /// 2. Taking the first 8 bytes of the hash
    /// 3. Interpreting these bytes as a little-endian u64
    /// 4. Reducing modulo the field prime to produce a valid field element
    ///
    /// Note that this is the same procedure performed by [`hash_string_to_word`], where we take
    /// the first element of the resulting [`Word`](crate::Word).
    ///
    /// This ensures that identical event names always produce the same event ID, while
    /// providing good distribution properties to minimize collisions between different names.
    pub fn from_name(name: impl AsRef<str>) -> Self {
        let digest_word = hash_string_to_word(name.as_ref());
        Self(digest_word[0].as_canonical_u64())
    }

    /// Creates an EventId from a [`Felt`] value (e.g., from the stack).
    pub fn from_felt(event_id: Felt) -> Self {
        Self(event_id.as_canonical_u64())
    }

    /// Creates an EventId from a `u64` value, reducing modulo the field prime.
    pub const fn from_u64(event_id: u64) -> Self {
        Self(event_id % Felt::ORDER_U64)
    }

    /// Converts this event ID to a [`Felt`].
    pub const fn as_felt(&self) -> Felt {
        Felt::new(self.0)
    }

    /// Returns the inner `u64` representation.
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl Display for EventId {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, f)
    }
}

// EVENT NAME
// ================================================================================================

/// A human-readable name for an event.
///
/// [`EventName`] is used for:
/// - Event handler registration (EventId computed from name at registration time)
/// - Error messages and debugging
/// - Resolving EventIds back to names via the event registry
///
/// System events use the "sys::" namespace prefix to distinguish them from user-defined events.
///
/// For event identification during execution (e.g., reading from the stack), use [`EventId`]
/// directly. Names can be looked up via the event registry when needed for error reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true))
)]
pub struct EventName(Cow<'static, str>);

impl EventName {
    /// Creates an EventName from a static string.
    ///
    /// This is the primary constructor for compile-time event name constants.
    pub const fn new(name: &'static str) -> Self {
        Self(Cow::Borrowed(name))
    }

    /// Creates an EventName from an owned String.
    ///
    /// Use this for dynamically constructed event names (e.g., in error messages).
    pub fn from_string(name: String) -> Self {
        Self(Cow::Owned(name))
    }

    /// Returns the event name as a string slice.
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }

    /// Returns the [`EventId`] for this event name.
    ///
    /// The ID is computed by hashing the name using blake3.
    pub fn to_event_id(&self) -> EventId {
        EventId::from_name(self.as_str())
    }
}

impl Display for EventName {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for EventName {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for EventId {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.as_felt().write_into(target);
    }
}

impl Deserializable for EventId {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self(Felt::read_from(source)?.as_canonical_u64()))
    }
}

impl Serializable for EventName {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Serialize as a string (supports both Borrowed and Owned variants)
        self.0.as_ref().write_into(target)
    }
}

impl Deserializable for EventName {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let name = String::read_from(source)?;
        Ok(Self::from_string(name))
    }
}

#[cfg(all(feature = "arbitrary", test))]
impl proptest::prelude::Arbitrary for EventId {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;
        any::<u64>().prop_map(EventId::from_u64).boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

#[cfg(all(feature = "arbitrary", test))]
impl proptest::prelude::Arbitrary for EventName {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        // Test both Cow::Borrowed (static) and Cow::Owned (dynamic) variants
        prop_oneof![
            // Static strings (Cow::Borrowed)
            Just(EventName::new("test::static::event")),
            Just(EventName::new("core::handler::example")),
            Just(EventName::new("user::custom::event")),
            // Dynamic strings (Cow::Owned)
            any::<(u32, u32)>()
                .prop_map(|(a, b)| EventName::from_string(format!("dynamic::event::{}::{}", a, b))),
        ]
        .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn event_basics() {
        // EventId constructors and conversions
        let id1 = EventId::from_u64(100);
        assert_eq!(id1.as_u64(), 100);
        assert_eq!(id1.as_felt(), Felt::new(100));

        let id2 = EventId::from_felt(Felt::new(200));
        assert_eq!(id2.as_u64(), 200);

        // EventId from name hashes consistently
        let id3 = EventId::from_name("test::event");
        let id4 = EventId::from_name("test::event");
        assert_eq!(id3, id4);

        // EventName constructors and conversions
        let name1 = EventName::new("static::event");
        assert_eq!(name1.as_str(), "static::event");
        assert_eq!(format!("{}", name1), "static::event");

        let name2 = EventName::from_string("dynamic::event".to_string());
        assert_eq!(name2.as_str(), "dynamic::event");

        // EventName to EventId
        assert_eq!(name1.to_event_id(), EventId::from_name("static::event"));
    }
}
