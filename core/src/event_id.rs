use alloc::{borrow::Cow, string::String};
use core::fmt::{Display, Formatter};

use crate::{Felt, utils::hash_string_to_word};

/// A type-safe wrapper around a [`Felt`] that represents an event identifier.
///
/// Event IDs are used to identify events that can be emitted by the VM or handled by the host.
/// This newtype provides type safety and ensures that event IDs are not accidentally confused
/// with other [`Felt`] values.
///
/// Event IDs can optionally store the human-readable event name for better error messages and
/// debugging. The name can be either a static string (for compile-time defined events) or an
/// owned string (for runtime-generated events).
///
/// While not enforced by this type, the values 0..256 are reserved for
/// [`SystemEvent`](crate::sys_events::SystemEvent)s.
#[derive(Debug, Clone)]
pub struct EventId {
    id: Felt,
    name: Option<Cow<'static, str>>,
}

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
    /// The event name is stored and will be displayed in error messages.
    pub fn from_name(name: impl Into<String>) -> Self {
        let name_str = name.into();
        let digest_word = hash_string_to_word(name_str.as_ref());

        Self {
            id: digest_word[0],
            name: Some(Cow::Owned(name_str)),
        }
    }

    /// Creates a new event ID from a [`Felt`] without an associated name.
    pub const fn from_felt(value: Felt) -> Self {
        Self { id: value, name: None }
    }

    /// Creates a new event ID from a u64, converting it to a [`Felt`], without an associated name.
    pub const fn from_u64(value: u64) -> Self {
        Self { id: Felt::new(value), name: None }
    }

    /// Creates a new event ID from a static string name and its pre-computed ID value.
    ///
    /// This constructor is `const` and can be used to define event IDs as compile-time constants.
    ///
    /// # Safety
    ///
    /// The caller must ensure the ID correctly corresponds to `hash_string_to_word(name)[0]`.
    /// Providing an incorrect ID can lead to event handler mismatches and incorrect program
    /// behavior.
    ///
    /// **Prefer using the [`declare_event!`](crate::declare_event) macro instead**, which generates
    /// both the constant and a compile-time test to validate the ID is correct.
    pub const unsafe fn from_static(name: &'static str, id: u64) -> Self {
        Self {
            id: Felt::new(id),
            name: Some(Cow::Borrowed(name)),
        }
    }

    /// Returns the underlying [`Felt`] value.
    pub const fn as_felt(&self) -> Felt {
        self.id
    }

    /// Returns the event name, if one was associated with this event ID.
    pub fn name(&self) -> Option<&str> {
        self.name.as_ref().map(|cow| cow.as_ref())
    }

    /// Returns `true` if this event ID is reserved for a
    /// [`SystemEvent`](crate::sys_events::SystemEvent).
    pub const fn is_reserved(&self) -> bool {
        let value = self.id.as_int();
        value <= u8::MAX as u64
    }
}

impl PartialEq for EventId {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for EventId {}

impl PartialOrd for EventId {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EventId {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.id.inner().cmp(&other.id.inner())
    }
}

impl core::hash::Hash for EventId {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        // Hash only the ID, not the name
        self.id.as_int().hash(state);
    }
}

impl Display for EventId {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match &self.name {
            Some(name) => write!(f, "{name}"),
            None => write!(f, "unknown event"),
        }
    }
}

// EVENT DECLARATION MACRO
// ================================================================================================

/// Declares an event constant with compile-time ID validation.
///
/// This macro creates a public constant [`EventId`] and automatically generates a test to
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
/// // Step 2: Run test, see error: "claimed 0 but should be 12345678901234567"
///
/// // Step 3: Update with correct ID
/// declare_event!(MY_EVENT, "miden::foo::bar", 12345678901234567);
///
/// // Step 4: Test passes!
/// ```
///
/// The macro expands to:
/// - A `pub const` [`EventId`] with the given name
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
        // Use _ prefix for test-only constants to suppress unused warnings.
        pub const $name: $crate::EventId =
            unsafe { $crate::EventId::from_static($event_name, $event_id) };

        #[cfg(test)]
        #[allow(non_snake_case)]
        mod $name {
            #[test]
            fn validate_event_id() {
                let computed = $crate::EventId::from_name($event_name);
                assert_eq!(
                    $event_id,
                    computed.as_felt().as_int(),
                    "EventId mismatch for '{}': claimed {} but should be {}.\n\
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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Test the declare_event! macro - the generated test validates the ID
    declare_event!(_TEST_EVENT, "test::event::correct", 4588470772146341859u64);

    #[test]
    fn constructors_and_accessors() {
        // from_u64 - no name
        let no_name = EventId::from_u64(100);
        assert_eq!(no_name.as_felt().as_int(), 100);
        assert_eq!(no_name.name(), None);

        // from_name - derives ID from name and stores it
        let with_name = EventId::from_name("test::event");
        assert_eq!(with_name.name(), Some("test::event"));

        // from_static - unsafe constructor with custom ID and name (tested via declare_event!)
        let static_event = unsafe { EventId::from_static("static::event", 999) };
        assert_eq!(static_event.as_felt().as_int(), 999);
        assert_eq!(static_event.name(), Some("static::event"));
    }

    #[test]
    fn display() {
        assert_eq!(format!("{}", EventId::from_name("foo::bar")), "foo::bar");
        assert_eq!(format!("{}", EventId::from_u64(100)), "unknown event");
    }

    #[test]
    fn comparison_ignores_names() {
        let id100_named = unsafe { EventId::from_static("foo", 100) };
        let id100_unnamed = EventId::from_u64(100);
        let id50_named = unsafe { EventId::from_static("zzz", 50) };

        // Equality based only on ID
        assert_eq!(id100_named, id100_unnamed);

        // Ordering based only on ID
        assert!(id100_named > id50_named);
        assert!(id50_named < id100_unnamed);
    }
}
