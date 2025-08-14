use alloc::collections::BTreeMap;

use super::{EventId, ReducedEventID};
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// SIMPLIFIED EVENT TABLE
// ================================================================================================

/// A simplified bidirectional mapping between EventId and ReducedEventID.
/// 
/// This table ONLY handles structured EventIds. Legacy u32 events are handled 
/// directly via ReducedEventID::from_u32() and don't need storage.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventTable {
    /// Forward lookup: EventId -> ReducedEventID (for structured events only)
    forward: BTreeMap<EventId, ReducedEventID>,
    /// Reverse lookup: ReducedEventID -> EventId (for structured events only)  
    reverse: BTreeMap<ReducedEventID, EventId>,
}

impl EventTable {
    /// Creates a new empty event table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a structured EventId in the table, computing its ReducedEventID.
    /// 
    /// If the EventId was already registered, returns the existing ReducedEventID.
    /// If a different EventId maps to the same ReducedEventID (hash collision), 
    /// the previous mapping is overwritten (last-write-wins).
    pub fn register(&mut self, event_id: EventId) -> ReducedEventID {
        let reduced_id = event_id.reduced_id();

        // Check if this exact EventId is already registered
        if let Some(&existing_reduced_id) = self.forward.get(&event_id) {
            return existing_reduced_id;
        }

        // Simple overwrite behavior - no complex collision detection
        // Hash collisions are cryptographically unlikely, so we don't fail-fast
        self.forward.insert(event_id.clone(), reduced_id);
        self.reverse.insert(reduced_id, event_id);

        reduced_id
    }

    /// Looks up the ReducedEventID for a structured EventId.
    pub fn lookup_by_event(&self, event_id: &EventId) -> Option<ReducedEventID> {
        self.forward.get(event_id).copied()
    }

    /// Looks up the structured EventId from its ReducedEventID.
    /// Returns None if the ReducedEventID corresponds to a legacy event or is not registered.
    pub fn lookup_by_reduced_id(&self, reduced_id: ReducedEventID) -> Option<&EventId> {
        self.reverse.get(&reduced_id)
    }

    /// Returns true if the structured EventId is registered.
    pub fn contains_event(&self, event_id: &EventId) -> bool {
        self.forward.contains_key(event_id)
    }

    /// Returns the number of registered structured events.
    pub fn len(&self) -> usize {
        self.forward.len()
    }

    /// Returns true if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.forward.is_empty()
    }

    /// Returns an iterator over all registered structured events.
    pub fn iter(&self) -> impl Iterator<Item = (&EventId, ReducedEventID)> {
        self.forward.iter().map(|(event, &reduced)| (event, reduced))
    }

    /// Merges another EventTable into this one.
    /// 
    /// Uses last-write-wins for any duplicate EventIds.
    pub fn merge(&mut self, other: EventTable) {
        for (event_id, reduced_id) in other.forward {
            self.forward.insert(event_id.clone(), reduced_id);
            self.reverse.insert(reduced_id, event_id);
        }
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for EventTable {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Write the number of structured events
        target.write_usize(self.forward.len());
        
        // Write each structured event
        for (event_id, &reduced_id) in &self.forward {
            event_id.write_into(target);
            reduced_id.write_into(target);
        }
    }
}

impl Deserializable for EventTable {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut table = EventTable::new();
        
        // Read the number of structured events
        let num_events = source.read_usize()?;
        
        // Read each structured event
        for _ in 0..num_events {
            let event_id = EventId::read_from(source)?;
            let reduced_id = ReducedEventID::read_from(source)?;
            
            // Rebuild both forward and reverse mappings
            table.forward.insert(event_id.clone(), reduced_id);
            table.reverse.insert(reduced_id, event_id);
        }
        
        Ok(table)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EventId;
    use alloc::{string::ToString, vec::Vec};

    #[test]
    fn test_basic_registration() {
        let mut table = EventTable::new();
        
        let event1 = EventId::system("MAP_VALUE".to_string());
        let event2 = EventId::system("HASH".to_string());
        
        // Register events
        let reduced1 = table.register(event1.clone());
        let reduced2 = table.register(event2.clone());
        
        // Test forward lookup
        assert_eq!(table.lookup_by_event(&event1), Some(reduced1));
        assert_eq!(table.lookup_by_event(&event2), Some(reduced2));
        
        // Test reverse lookup
        assert_eq!(table.lookup_by_reduced_id(reduced1), Some(&event1));
        assert_eq!(table.lookup_by_reduced_id(reduced2), Some(&event2));
        
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn test_duplicate_registration() {
        let mut table = EventTable::new();
        
        let event = EventId::system("MAP_VALUE".to_string());
        
        // Register same event twice
        let reduced1 = table.register(event.clone());
        let reduced2 = table.register(event.clone());
        
        // Should return same ReducedEventID
        assert_eq!(reduced1, reduced2);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_merge() {
        let mut table1 = EventTable::new();
        let mut table2 = EventTable::new();
        
        let event1 = EventId::system("MAP_VALUE".to_string());
        let event2 = EventId::new("crypto-lib".to_string(), "HASH".to_string()).unwrap();
        
        table1.register(event1.clone());
        table2.register(event2.clone());
        
        table1.merge(table2);
        
        assert_eq!(table1.len(), 2);
        assert!(table1.contains_event(&event1));
        assert!(table1.contains_event(&event2));
    }

    #[test]
    fn test_iteration() {
        let mut table = EventTable::new();
        
        let event1 = EventId::system("MAP_VALUE".to_string());
        let event2 = EventId::new("crypto-lib".to_string(), "HASH".to_string()).unwrap();
        
        let reduced1 = table.register(event1.clone());
        let reduced2 = table.register(event2.clone());
        
        let entries: Vec<_> = table.iter().collect();
        assert_eq!(entries.len(), 2);
        
        // Verify both entries are present (order may vary due to BTreeMap)
        assert!(entries.contains(&(&event1, reduced1)));
        assert!(entries.contains(&(&event2, reduced2)));
    }
}