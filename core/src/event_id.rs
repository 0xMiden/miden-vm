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
/// While not enforced by this type, the values 0..256 are reserved for
/// [`SystemEvent`](crate::sys_events::SystemEvent)s.
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
    /// Panics if the computed event ID collides with a reserved system event ID (0-255).
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

    /// Returns `true` if this event ID is reserved for a
    /// [`SystemEvent`](crate::sys_events::SystemEvent).
    pub const fn is_reserved(&self) -> bool {
        let value = self.0.as_int();
        value <= u8::MAX as u64
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
/// For event identification during execution (e.g., reading from the stack), use [`EventId`]
/// directly. Names can be looked up via the event registry when needed for error reporting.
///
/// The enum has three variants:
/// - [`Event`](EventName::Event): For named user events, computes EventId from the name hash
/// - [`System`](EventName::System): For system events (IDs 0-255), preserves the system EventId
/// - [`Unknown`](EventName::Unknown): For events without registered names, preserves the original EventId
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_serde_test_macros::serde_test(winter_serde(true))
)]
pub enum EventName {
    /// A named event
    Event(Cow<'static, str>),
    /// A system event (IDs 0-255)
    System(EventId),
    /// An unknown event with only an ID available
    Unknown(EventId),
}

impl EventName {
    /// Creates an EventName from a static string.
    ///
    /// This is the primary constructor for compile-time event name constants.
    pub const fn new(name: &'static str) -> Self {
        Self::Event(Cow::Borrowed(name))
    }

    /// Creates an EventName from an owned String.
    ///
    /// Use this for dynamically constructed event names (e.g., in error messages).
    pub fn from_string(name: String) -> Self {
        Self::Event(Cow::Owned(name))
    }

    /// Creates an EventName for an unknown event, preserving its EventId.
    ///
    /// This is used when an event has no registered name but we still want to report its ID.
    /// The returned EventName will display as "unknown" and `to_event_id()` will return the
    /// original event_id (not a hash of the string "unknown").
    pub const fn unknown(event_id: EventId) -> Self {
        Self::Unknown(event_id)
    }

    /// Creates an EventName for a system event.
    ///
    /// System events use their enum discriminant (0-255) as their EventId.
    pub const fn system(sys_event: SystemEvent) -> Self {
        Self::System(EventId::from_u64(sys_event as u64))
    }

    /// Returns the event name as a string slice.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Event(cow) => cow.as_ref(),
            Self::System(event_id) => {
                // Try to convert EventId back to SystemEvent to get the name
                SystemEvent::try_from(*event_id)
                    .map(|sys_event| sys_event.name_str())
                    .unwrap_or("system")
            },
            Self::Unknown(_) => "unknown",
        }
    }

    /// Returns the [`EventId`] for this event name.
    ///
    /// - For [`Event`](EventName::Event) events, computes the EventId by hashing the name
    /// - For [`System`](EventName::System) events, returns the system event ID (0-255)
    /// - For [`Unknown`](EventName::Unknown) events, returns the preserved EventId
    pub fn to_event_id(&self) -> EventId {
        match self {
            Self::Event(name) => EventId::from_name(name.as_ref()),
            Self::System(event_id) => *event_id,
            Self::Unknown(event_id) => *event_id,
        }
    }
}

impl Display for EventName {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Event(name) => write!(f, "{}", name),
            Self::System(event_id) => {
                // Try to convert EventId back to SystemEvent to get the name
                match SystemEvent::try_from(*event_id) {
                    Ok(sys_event) => write!(f, "{}", sys_event.name_str()),
                    Err(_) => write!(f, "system event (ID: {})", event_id),
                }
            },
            Self::Unknown(event_id) => write!(f, "unknown event (ID: {})", event_id),
        }
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
        match self {
            Self::Event(name) => {
                target.write_u8(0);
                name.write_into(target)
            },
            Self::System(event_id) => {
                target.write_u8(1);
                event_id.write_into(target);
            },
            Self::Unknown(event_id) => {
                target.write_u8(2);
                event_id.write_into(target);
            },
        }
    }
}

impl Deserializable for EventName {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let discriminant = source.read_u8()?;
        match discriminant {
            0 => {
                let name = String::read_from(source)?;
                Ok(Self::from_string(name))
            },
            1 => {
                let event_id = EventId::read_from(source)?;
                Ok(Self::System(event_id))
            },
            2 => {
                let event_id = EventId::read_from(source)?;
                Ok(Self::Unknown(event_id))
            },
            _ => Err(DeserializationError::InvalidValue(
                alloc::format!("invalid EventName discriminant: {}", discriminant).into()
            )),
        }
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

        // Reserved range: 0-255
        assert!(EventId::from_u64(0).is_reserved());
        assert!(EventId::from_u64(255).is_reserved());
        assert!(!EventId::from_u64(256).is_reserved());
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
    }
}
