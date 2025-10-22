use alloc::{borrow::Cow, string::String};
use core::fmt::{Display, Formatter};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use winter_utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

use crate::{Felt, sys_events::SystemEvent, utils::hash_string_to_word};

// EVENT ID
// ================================================================================================

/// A type-safe wrapper around a [`Felt`] that represents an event identifier.
///
/// Event IDs are used to identify events that can be emitted by the VM or handled by the host.
/// This newtype provides type safety and ensures that event IDs are not accidentally confused
/// with other [`Felt`] values.
///
/// [`EventId`] contains only the identifier. For events with human-readable names,
/// use [`EventName`] instead.
///
/// Event IDs are derived from event names using blake3 hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(winter_serde(true))
)]
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
    ///
    /// # Panics
    /// Panics if the event name starts with "sys::" as this namespace is reserved for
    /// [`SystemEvent`]s.
    pub fn from_name(name: impl AsRef<str>) -> Self {
        let name_str = name.as_ref();
        assert!(
            !SystemEvent::is_system_event_name(name_str),
            "Event name '{}' uses reserved namespace 'sys::' - use SystemEvent instead",
            name_str
        );
        let digest_word = hash_string_to_word(name_str);
        Self(digest_word[0])
    }

    /// Creates an EventId from a [`Felt`] value (e.g., from the stack).
    pub const fn from_felt(event_id: Felt) -> Self {
        Self(event_id)
    }

    /// Creates an EventId from a u64, converting it to a [`Felt`].
    pub const fn from_u64(event_id: u64) -> Self {
        Self(Felt::new(event_id))
    }

    /// Returns the underlying [`Felt`] value.
    pub const fn as_felt(&self) -> Felt {
        self.0
    }

    /// Returns the underlying `u64` value.
    pub const fn as_u64(&self) -> u64 {
        self.0.as_int()
    }

    /// Returns `true` if this EventId corresponds to a system event.
    ///
    /// System events use the "sys::" namespace and have predefined EventIds that are checked
    /// against a const lookup table.
    pub const fn is_system_event(&self) -> bool {
        let lookup = crate::sys_events::SYSTEM_EVENT_LOOKUP;
        let mut i = 0;
        while i < lookup.len() {
            if self.as_u64() == lookup[i].0.as_u64() {
                return true;
            }
            i += 1;
        }
        false
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

impl core::hash::Hash for EventId {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.inner().hash(state);
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
    miden_test_serde_macros::serde_test(winter_serde(true))
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

    /// Returns `true` if this event name uses the "sys::" system event namespace.
    pub fn is_system_event(&self) -> bool {
        SystemEvent::is_system_event_name(self.as_str())
    }

    /// Returns the [`EventId`] for this event name.
    ///
    /// The ID is computed by hashing the name using blake3.
    ///
    /// # Panics
    /// Panics if the event name starts with "sys::" as this namespace is reserved for
    /// [`SystemEvent`]s. System events should use [`SystemEvent::to_event_id()`] instead.
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
        self.0.write_into(target);
    }
}

impl Deserializable for EventId {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self(Felt::read_from(source)?))
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
            Just(EventName::new("stdlib::handler::example")),
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
    fn event_id_basics() {
        // Constructors
        assert_eq!(EventId::from_u64(100).as_u64(), 100);
        assert_eq!(EventId::from_felt(Felt::new(200)).as_u64(), 200);

        // Conversion to Felt
        assert_eq!(EventId::from_u64(100).as_felt(), Felt::new(100));

        // Event ID from name
        let event_id = EventId::from_name("test::event");
        assert!(event_id.as_u64() > 0);

        // Same name produces same ID
        let event_id2 = EventId::from_name("test::event");
        assert_eq!(event_id, event_id2);

        // Different names produce different IDs
        let event_id3 = EventId::from_name("test::different");
        assert_ne!(event_id, event_id3);
    }

    #[test]
    fn event_name_basics() {
        // Static constructor
        let static_event = EventName::new("test::event");
        assert_eq!(static_event.as_str(), "test::event");

        // Dynamic constructor
        let dynamic_event = EventName::from_string("dynamic::event".to_string());
        assert_eq!(dynamic_event.as_str(), "dynamic::event");

        // Display
        assert_eq!(format!("{}", static_event), "test::event");

        // to_event_id computes hash
        let event_id = static_event.to_event_id();
        assert_eq!(event_id, EventId::from_name("test::event"));

        // is_system_event checks namespace
        assert!(!static_event.is_system_event());
        assert!(!dynamic_event.is_system_event());
        let sys_event = EventName::new("sys::test");
        assert!(sys_event.is_system_event());
    }

    #[test]
    #[should_panic(expected = "uses reserved namespace 'sys::'")]
    fn event_id_from_name_panics_on_sys_prefix() {
        EventId::from_name("sys::my_event");
    }

    #[test]
    #[should_panic(expected = "uses reserved namespace 'sys::'")]
    fn event_name_to_event_id_panics_on_sys_prefix() {
        let event = EventName::new("sys::my_event");
        event.to_event_id();
    }

    #[test]
    fn event_id_is_system_event() {
        // Test that system event IDs are correctly identified
        for system_event in crate::sys_events::SystemEvent::all() {
            let event_id = system_event.to_event_id();
            assert!(
                event_id.is_system_event(),
                "SystemEvent {:?} should be identified as a system event",
                system_event
            );
        }

        // Test that user event IDs are not identified as system events
        let user_event_id = EventId::from_name("user::my_event");
        assert!(!user_event_id.is_system_event());

        let another_user_event = EventId::from_name("stdlib::crypto::hash");
        assert!(!another_user_event.is_system_event());

        // Test some arbitrary EventIds
        assert!(!EventId::from_u64(0).is_system_event());
        assert!(!EventId::from_u64(12345).is_system_event());
    }
}
