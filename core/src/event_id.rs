use alloc::{borrow::Cow, string::String};
use core::fmt::{Display, Formatter};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use winter_utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

use crate::{Felt, utils::hash_string_to_word};

// EVENT ID
// ================================================================================================

/// A lightweight, type-safe wrapper around a [`Felt`] that represents an event identifier.
///
/// Event IDs are used to identify events that can be emitted by the VM or handled by the host.
/// This newtype provides type safety and ensures that event IDs are not accidentally confused
/// with other [`Felt`] values.
///
/// [`EventId`] is a Copy type containing only the identifier. For events with human-readable
/// names, use [`NamedEvent`] instead.
///
/// While not enforced by this type, the values 0..256 are reserved for
/// [`SystemEvent`](crate::sys_events::SystemEvent)s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
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
    /// Use this at runtime when you don't have a pre-declared event. For compile-time constants,
    /// prefer using [`NamedEvent`] with the [`declare_event!`](crate::declare_event) macro.
    pub fn from_name(name: impl AsRef<str>) -> Self {
        let digest_word = hash_string_to_word(name.as_ref());
        let event_id = Self(digest_word[0]);

        assert!(
            !event_id.is_reserved(),
            "Event ID with name {} collides with an ID reserved for a system event",
            name.as_ref()
        );

        event_id
    }

    /// Creates an EventId from a [`Felt`] value (e.g., from the stack).
    pub const fn from_felt(value: Felt) -> Self {
        Self(value)
    }

    /// Creates an EventId from a u64, converting it to a [`Felt`].
    pub const fn from_u64(value: u64) -> Self {
        Self(Felt::new(value))
    }

    /// Returns the underlying [`Felt`] value.
    pub const fn as_felt(&self) -> Felt {
        self.0
    }

    /// Returns `true` if this event ID is reserved for a
    /// [`SystemEvent`](crate::sys_events::SystemEvent).
    pub const fn is_reserved(&self) -> bool {
        self.0.as_int() <= u8::MAX as u64
    }
}

impl PartialOrd for EventId {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EventId {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.as_int().cmp(&other.0.as_int())
    }
}

impl core::hash::Hash for EventId {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.as_int().hash(state);
    }
}

impl Display for EventId {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        // Display just the felt value
        write!(f, "{}", self.0)
    }
}

// NAMED EVENT
// ================================================================================================

/// An event with both an identifier and a human-readable name.
///
/// [`NamedEvent`] combines an [`EventId`] with its associated name for better error messages
/// and debugging. This type is used for:
/// - Event handler registration
/// - Error messages
/// - Debug output
///
/// For lightweight event identification (e.g., when reading from the stack), use [`EventId`]
/// directly. The name can be looked up later via the event registry if needed.
///
/// # Equality and Ordering
///
/// Two [`NamedEvent`]s are considered equal if they have the same [`EventId`], regardless of
/// their names. This ensures consistent behavior when the same event is referenced with
/// different name representations. Ordering and hashing are also based solely on the ID.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NamedEvent {
    id: EventId,
    name: Cow<'static, str>,
}

impl NamedEvent {
    /// Creates a NamedEvent, computing the ID from the name.
    ///
    /// This is for runtime/dynamic event creation. The ID is computed by hashing the name.
    /// For compile-time constants, use the [`declare_event!`](crate::declare_event) macro
    /// instead.
    pub fn from_name(name: impl Into<String>) -> Self {
        let name_str = name.into();
        let id = EventId::from_name(&name_str);
        Self { id, name: Cow::Owned(name_str) }
    }

    /// Creates a NamedEvent from a static name and pre-computed ID.
    ///
    /// # Warning
    ///
    /// The caller must ensure `id` matches `EventId::from_name(name)`, meaning the ID should
    /// be the first element of the BLAKE3 hash of the name. Providing a mismatched ID can cause
    /// handler lookup failures and incorrect program behavior.
    ///
    /// **Prefer using the [`declare_event!`](crate::declare_event) macro instead**, which
    /// generates both the constant and a compile-time test to validate the ID is correct.
    pub const fn from_name_and_id(name: &'static str, id: EventId) -> Self {
        Self { id, name: Cow::Borrowed(name) }
    }

    /// Returns the event identifier.
    pub const fn id(&self) -> EventId {
        self.id
    }

    /// Returns the event name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Display for NamedEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.name)
    }
}

// Equality for NamedEvent only compares the underlying ID, not the name.
// This means that two NamedEvents with different names but the same ID are considered equal.
// The name is only used for debugging and error messages, and is not part of the identity.
impl PartialEq for NamedEvent {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for NamedEvent {}

impl PartialOrd for NamedEvent {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NamedEvent {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl core::hash::Hash for NamedEvent {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        // Hash only the ID, not the name
        self.id.hash(state);
    }
}

// EVENT DECLARATION MACRO
// ================================================================================================

/// Declares a named event constant with compile-time ID validation.
///
/// This macro creates a public constant [`NamedEvent`] and automatically generates a test to
/// verify that the provided ID matches the hash of the event name.
///
/// # Workflow
///
/// 1. Write the declaration with a placeholder ID (e.g., 0)
/// 2. Run the tests - the test will fail and display the correct ID
/// 3. Update the declaration with the correct ID
/// 4. The test will pass, confirming the ID is correct
///
/// # Example
///
/// ```rust,ignore
/// use miden_core::declare_event;
///
/// // Step 1: Write with placeholder
/// declare_event!(MY_EVENT, "miden::foo::bar", 0);
///
/// // Step 2: Run test, see error: "declared 0 but hash is 12345678901234567"
///
/// // Step 3: Update with correct ID
/// declare_event!(MY_EVENT, "miden::foo::bar", 12345678901234567);
///
/// // Step 4: Test passes!
/// ```
///
/// The macro expands to:
/// - A `pub const` [`NamedEvent`] with the given name
/// - A test module with the same name containing validation logic
///
/// # Note on Naming
///
/// The generated test module uses the constant's name. This is safe because Rust naming
/// conventions naturally separate these: constants use `SCREAMING_SNAKE_CASE` while modules
/// use `snake_case`. Conflicts would only occur if violating both conventions simultaneously.
#[macro_export]
macro_rules! declare_event {
    ($name:ident, $event_name:expr, $event_id:expr) => {
        // Note: constant naming conventions (UPPER_SNAKE_CASE) are still enforced.
        // The macro always generates a public constant; underscore prefix only suppresses
        // unused warnings, not visibility.
        pub const $name: $crate::NamedEvent =
            $crate::NamedEvent::from_name_and_id($event_name, $crate::EventId::from_u64($event_id));

        #[cfg(test)]
        #[allow(non_snake_case)]
        mod $name {
            #[test]
            fn validate_event_id() {
                let computed = $crate::EventId::from_name($event_name);
                assert_eq!(
                    $event_id,
                    computed.as_felt().as_int(),
                    "EventId mismatch for '{}': declared {} but hash is {}.\n\
     Update your declaration to:\n\
     declare_event!({}, \"{}\", {});",
                    $event_name,
                    $event_id,
                    computed.as_felt().as_int(),
                    stringify!($name),
                    $event_name,
                    computed.as_felt().as_int()
                );
            }
        }
    };
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

impl Serializable for NamedEvent {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.id.write_into(target);
        // Serialize the name as String
        let name_string = String::from(self.name.as_ref());
        name_string.write_into(target);
    }
}

impl Deserializable for NamedEvent {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let id = EventId::read_from(source)?;
        let name_string = String::read_from(source)?;
        Ok(Self { id, name: Cow::Owned(name_string) })
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
impl proptest::prelude::Arbitrary for NamedEvent {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;
        any::<String>().prop_map(NamedEvent::from_name).boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_id_basics() {
        // Constructors
        assert_eq!(EventId::from_u64(100).as_felt().as_int(), 100);
        assert_eq!(EventId::from_felt(Felt::new(200)).as_felt().as_int(), 200);

        // Reserved range: 0-255
        assert!(EventId::from_u64(0).is_reserved());
        assert!(EventId::from_u64(255).is_reserved());
        assert!(!EventId::from_u64(256).is_reserved());
    }

    #[test]
    fn named_event_basics() {
        let event = NamedEvent::from_name("test::event");
        assert_eq!(event.name(), "test::event");
        assert!(event.id().as_felt().as_int() > 0);

        let id = EventId::from_u64(999);
        let static_event = NamedEvent::from_name_and_id("static", id);
        assert_eq!(static_event.name(), "static");
        assert_eq!(static_event.id(), id);
    }

    #[test]
    fn named_event_compares_by_id_not_name() {
        use core::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let id = EventId::from_u64(100);
        let event1 = NamedEvent::from_name_and_id("foo", id);
        let event2 = NamedEvent::from_name_and_id("bar", id);

        // Same ID, different names
        assert_eq!(event1, event2);

        let mut h1 = DefaultHasher::new();
        event1.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        event2.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());

        // Different IDs
        let event3 = NamedEvent::from_name_and_id("zzz", EventId::from_u64(50));
        assert!(event3 < event1);
    }

    declare_event!(_TEST_EVENT, "test::event::correct", 4588470772146341859u64);

    #[test]
    fn declare_event_macro_works() {
        assert_eq!(_TEST_EVENT.name(), "test::event::correct");
        assert_eq!(_TEST_EVENT.id().as_felt().as_int(), 4588470772146341859u64);
    }
}
