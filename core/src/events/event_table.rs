use alloc::collections::BTreeMap;

use super::{EventID, EventName};
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// SIMPLIFIED EVENT TABLE
// ================================================================================================

/// A simple lookup table for reverse mapping EventID → EventName for debugging.
///
/// Legacy u32 events are handled directly via EventID::from_u32() and don't need storage.
/// The reverse mapping may not be maintained in size-optimized MAST forests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventTable(BTreeMap<EventID, EventName>);

impl EventTable {
    /// Creates a new empty event table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a structured EventName in the table, computing its EventID.
    ///
    /// Returns the EventID for the EventName (computed via Blake3 hash).
    /// Stores the reverse mapping for debugging purposes.
    pub fn register(&mut self, event_name: EventName) -> EventID {
        let event_id = event_name.id();

        // Store the reverse mapping for debugging
        // Hash collisions are cryptographically unlikely, but if they occur,
        // we use last-write-wins behavior
        self.0.insert(event_id, event_name);

        event_id
    }

    /// Looks up the structured EventName from its EventID.
    ///
    /// Returns None if:
    /// - The EventID corresponds to a legacy event
    /// - The event is not registered in this table
    /// - The reverse mapping was stripped for size optimization
    pub fn lookup_by_event_id(&self, event_id: EventID) -> Option<&EventName> {
        self.0.get(&event_id)
    }

    /// Merges another EventTable into this one.
    ///
    /// Uses last-write-wins for any duplicate EventIDs (hash collisions).
    pub fn merge(&mut self, other: EventTable) {
        self.0.extend(other.0);
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for EventTable {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Write the number of structured events
        target.write_usize(self.0.len());

        // Write each structured event
        for (&event_id, event_name) in &self.0 {
            event_id.write_into(target);
            event_name.write_into(target);
        }
    }
}

impl Deserializable for EventTable {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut table = BTreeMap::new();

        // Read the number of structured events
        let num_events = source.read_usize()?;

        // Read each structured event
        for _ in 0..num_events {
            let event_id = EventID::read_from(source)?;
            let event_name = EventName::read_from(source)?;

            // Build the reverse mapping
            table.insert(event_id, event_name);
        }

        Ok(Self(table))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::events::EventName;

    // Test-only methods for EventTable
    impl EventTable {
        pub fn len(&self) -> usize {
            self.0.len()
        }

        pub fn is_empty(&self) -> bool {
            self.0.is_empty()
        }

        pub fn contains_event_id(&self, event_id: EventID) -> bool {
            self.0.contains_key(&event_id)
        }

        pub fn iter(&self) -> impl Iterator<Item = (EventID, &EventName)> {
            self.0.iter().map(|(&event_id, event_name)| (event_id, event_name))
        }
    }

    #[test]
    fn test_basic_registration() {
        let mut table = EventTable::new();

        let event1 = EventName::system("map_value");
        let event2 = EventName::system("hash");

        // Register events
        let id1 = table.register(event1.clone());
        let id2 = table.register(event2.clone());

        // Test reverse lookup
        assert_eq!(table.lookup_by_event_id(id1), Some(&event1));
        assert_eq!(table.lookup_by_event_id(id2), Some(&event2));

        assert_eq!(table.len(), 2);
    }

    #[test]
    fn test_duplicate_registration() {
        let mut table = EventTable::new();

        let event = EventName::system("map_value");

        // Register same event twice
        let id1 = table.register(event.clone());
        let id2 = table.register(event.clone());

        // Should return same EventID and only store once
        assert_eq!(id1, id2);
        assert_eq!(table.len(), 1);
        assert_eq!(table.lookup_by_event_id(id1), Some(&event));
    }

    #[test]
    fn test_merge() {
        let mut table1 = EventTable::new();
        let mut table2 = EventTable::new();

        let event1 = EventName::system("map_value");
        let event2 = EventName::new("crypto_lib", "hash").unwrap();

        let id1 = table1.register(event1.clone());
        let id2 = table2.register(event2.clone());

        table1.merge(table2);

        assert_eq!(table1.len(), 2);
        assert!(table1.contains_event_id(id1));
        assert!(table1.contains_event_id(id2));
    }

    #[test]
    fn test_iteration() {
        let mut table = EventTable::new();

        let event1 = EventName::system("map_value");
        let event2 = EventName::new("crypto_lib", "hash").unwrap();

        let id1 = table.register(event1.clone());
        let id2 = table.register(event2.clone());

        let entries: Vec<_> = table.iter().collect();
        assert_eq!(entries.len(), 2);

        // Verify both entries are present (order may vary due to BTreeMap)
        assert!(entries.contains(&(id1, &event1)));
        assert!(entries.contains(&(id2, &event2)));
    }

    #[test]
    fn test_hash_collision_handling() {
        let mut table = EventTable::new();

        let event1 = EventName::system("test_event");
        let event2 = EventName::new("lib", "different_event").unwrap();

        let id1 = table.register(event1.clone());
        let id2 = table.register(event2.clone());

        // Even in the very unlikely case of hash collision, both events should be handled
        // The last registered event wins in case of collision
        assert_eq!(table.lookup_by_event_id(id1), Some(&event1));
        assert_eq!(table.lookup_by_event_id(id2), Some(&event2));
    }
}
