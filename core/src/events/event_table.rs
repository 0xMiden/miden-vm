use alloc::collections::BTreeMap;
use core::fmt;

use super::{EventId, ReducedEventID};
use crate::{
    Felt,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// EVENT TABLE
// ================================================================================================

/// A bidirectional mapping between EventId and ReducedEventID with fail-fast collision handling.
/// 
/// The EventTable provides reverse lookup capabilities, allowing the VM to map from ReducedEventID 
/// back to human-readable event names. Collisions cause immediate errors rather than complex resolution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventTable {
    /// Forward lookup: EventId -> ReducedEventID
    event_to_reduced: BTreeMap<EventId, ReducedEventID>,
    
    /// Reverse lookup: ReducedEventID -> EventId  
    reduced_to_event: BTreeMap<ReducedEventID, EventId>,
}

impl EventTable {
    /// Creates a new empty event table.
    pub fn new() -> Self {
        Self {
            event_to_reduced: BTreeMap::new(),
            reduced_to_event: BTreeMap::new(),
        }
    }

    /// Registers an EventId in the table, computing its ReducedEventID.
    /// 
    /// Returns an error immediately if there's a collision (fail-fast approach).
    pub fn register(&mut self, event_id: EventId) -> Result<ReducedEventID, EventTableError> {
        let reduced_id = event_id.reduced_id();

        // Check if this exact EventId is already registered
        if let Some(existing_reduced) = self.event_to_reduced.get(&event_id) {
            return Ok(*existing_reduced);
        }

        // Check for collision with a different EventId (fail-fast)
        if let Some(existing_event) = self.reduced_to_event.get(&reduced_id) {
            if existing_event != &event_id {
                return Err(EventTableError::Collision {
                    reduced_id,
                    existing: existing_event.clone(),
                    conflicting: event_id,
                });
            }
        }

        // No collision - register the mapping
        self.event_to_reduced.insert(event_id.clone(), reduced_id);
        self.reduced_to_event.insert(reduced_id, event_id);

        Ok(reduced_id)
    }

    /// Registers an EventId from a legacy u32 event ID.
    /// 
    /// This creates a ReducedEventID directly from the u32 for backward compatibility.
    pub fn register_u32(&mut self, event_id: EventId, legacy_id: u32) -> Result<ReducedEventID, EventTableError> {
        let reduced_id = ReducedEventID::from_u32(legacy_id);

        // Check if this exact EventId is already registered
        if let Some(existing_reduced) = self.event_to_reduced.get(&event_id) {
            if *existing_reduced != reduced_id {
                return Err(EventTableError::InconsistentLegacyMapping {
                    event_id: event_id.clone(),
                    expected: reduced_id,
                    existing: *existing_reduced,
                });
            }
            return Ok(*existing_reduced);
        }

        // Check for collision with a different EventId (fail-fast)
        if let Some(existing_event) = self.reduced_to_event.get(&reduced_id) {
            if existing_event != &event_id {
                return Err(EventTableError::Collision {
                    reduced_id,
                    existing: existing_event.clone(),
                    conflicting: event_id,
                });
            }
        }

        // Register the legacy mapping
        self.event_to_reduced.insert(event_id.clone(), reduced_id);
        self.reduced_to_event.insert(reduced_id, event_id);

        Ok(reduced_id)
    }

    /// Looks up the ReducedEventID for an EventId.
    pub fn lookup_by_event(&self, event_id: &EventId) -> Option<ReducedEventID> {
        self.event_to_reduced.get(event_id).copied()
    }

    /// Looks up the EventId from its ReducedEventID.
    pub fn lookup_by_reduced_id(&self, reduced_id: ReducedEventID) -> Option<&EventId> {
        self.reduced_to_event.get(&reduced_id)
    }

    /// Looks up the EventId from a Felt (for backward compatibility).
    pub fn lookup_by_felt(&self, felt: Felt) -> Option<&EventId> {
        let reduced_id = ReducedEventID::new(felt);
        self.reduced_to_event.get(&reduced_id)
    }

    /// Returns true if the EventId is registered.
    pub fn contains_event(&self, event_id: &EventId) -> bool {
        self.event_to_reduced.contains_key(event_id)
    }

    /// Returns true if the ReducedEventID is registered.
    pub fn contains_reduced_id(&self, reduced_id: ReducedEventID) -> bool {
        self.reduced_to_event.contains_key(&reduced_id)
    }

    /// Returns true if the Felt is registered (backward compatibility).
    pub fn contains_felt(&self, felt: Felt) -> bool {
        let reduced_id = ReducedEventID::new(felt);
        self.reduced_to_event.contains_key(&reduced_id)
    }

    /// Returns the number of registered events.
    pub fn len(&self) -> usize {
        self.event_to_reduced.len()
    }

    /// Returns true if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.event_to_reduced.is_empty()
    }

    /// Returns an iterator over all registered events.
    pub fn iter(&self) -> impl Iterator<Item = (&EventId, ReducedEventID)> {
        self.event_to_reduced.iter().map(|(event, &reduced)| (event, reduced))
    }

    /// Returns an iterator over all reduced event IDs.
    pub fn reduced_ids(&self) -> impl Iterator<Item = ReducedEventID> + '_ {
        self.reduced_to_event.keys().copied()
    }

    /// Merges another EventTable into this one.
    /// 
    /// Returns an error immediately if any collisions are detected (fail-fast approach).
    pub fn merge(&mut self, other: EventTable) -> Result<(), EventTableError> {
        for (event_id, _) in other.event_to_reduced {
            self.register(event_id)?;
        }
        
        Ok(())
    }


    /// Validates the table for consistency.
    pub fn validate(&self) -> Result<(), EventTableError> {
        // Check that forward and reverse mappings are consistent
        for (event, &reduced_id) in &self.event_to_reduced {
            if let Some(reverse_event) = self.reduced_to_event.get(&reduced_id) {
                if reverse_event != event {
                    return Err(EventTableError::InconsistentMapping {
                        event: event.clone(),
                        reduced_id,
                        reverse_event: reverse_event.clone(),
                    });
                }
            } else {
                return Err(EventTableError::MissingReverseMapping {
                    event: event.clone(),
                    reduced_id,
                });
            }
        }

        // Check reverse mappings
        for (&reduced_id, event) in &self.reduced_to_event {
            if let Some(&forward_reduced_id) = self.event_to_reduced.get(event) {
                if forward_reduced_id != reduced_id {
                    return Err(EventTableError::InconsistentMapping {
                        event: event.clone(),
                        reduced_id,
                        reverse_event: event.clone(),
                    });
                }
            } else {
                return Err(EventTableError::MissingForwardMapping {
                    event: event.clone(),
                    reduced_id,
                });
            }
        }

        Ok(())
    }
}

// EVENT TABLE ERROR
// ================================================================================================

/// Errors that can occur when working with EventTables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventTableError {
    /// Multiple EventIds map to the same ReducedEventID (fail-fast collision)
    Collision {
        reduced_id: ReducedEventID,
        existing: EventId,
        conflicting: EventId,
    },
    
    /// Legacy mapping conflicts with computed mapping
    InconsistentLegacyMapping {
        event_id: EventId,
        expected: ReducedEventID,
        existing: ReducedEventID,
    },
    
    /// Forward and reverse mappings are inconsistent
    InconsistentMapping {
        event: EventId,
        reduced_id: ReducedEventID,
        reverse_event: EventId,
    },
    
    /// Missing reverse mapping for an event
    MissingReverseMapping {
        event: EventId,
        reduced_id: ReducedEventID,
    },
    
    /// Missing forward mapping for a ReducedEventID
    MissingForwardMapping {
        event: EventId,
        reduced_id: ReducedEventID,
    },
}

impl fmt::Display for EventTableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventTableError::Collision { reduced_id, existing, conflicting } => {
                write!(f, "Event collision: EventIds '{}' and '{}' both map to ReducedEventID {}", 
                       existing, conflicting, reduced_id)
            },
            EventTableError::InconsistentLegacyMapping { event_id, expected, existing } => {
                write!(f, "Inconsistent legacy mapping: event '{}' expected ReducedEventID {}, \
                          but already has {}", event_id, expected, existing)
            },
            EventTableError::InconsistentMapping { event, reduced_id, reverse_event } => {
                write!(f, "Inconsistent mapping: event '{}' maps to ReducedEventID {}, \
                          but ReducedEventID maps back to '{}'", event, reduced_id, reverse_event)
            },
            EventTableError::MissingReverseMapping { event, reduced_id } => {
                write!(f, "Missing reverse mapping: event '{}' maps to ReducedEventID {}, \
                          but no reverse mapping exists", event, reduced_id)
            },
            EventTableError::MissingForwardMapping { event, reduced_id } => {
                write!(f, "Missing forward mapping: ReducedEventID {} maps to event '{}', \
                          but no forward mapping exists", reduced_id, event)
            },
        }
    }
}

impl core::error::Error for EventTableError {}

// SERIALIZATION
// ================================================================================================

impl Serializable for EventTable {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Write the number of entries
        target.write_usize(self.event_to_reduced.len());
        
        // Write each (EventId, ReducedEventID) pair
        for (event_id, &reduced_id) in &self.event_to_reduced {
            event_id.write_into(target);
            reduced_id.write_into(target);
        }
    }
}

impl Deserializable for EventTable {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut table = EventTable::new();
        
        // Read the number of entries
        let num_entries = source.read_usize()?;
        
        // Read each (EventId, ReducedEventID) pair and register them
        for _ in 0..num_entries {
            let event_id = EventId::read_from(source)?;
            let reduced_id = ReducedEventID::read_from(source)?;
            
            // Directly insert without re-hashing since we trust the serialized data
            table.event_to_reduced.insert(event_id.clone(), reduced_id);
            table.reduced_to_event.insert(reduced_id, event_id);
        }
        
        Ok(table)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventId, EventSource};
    use alloc::vec::Vec;

    #[test]
    fn test_event_table_basic_operations() {
        let mut table = EventTable::new();
        
        let event1 = EventId::new(EventSource::System, "memory", "MAP_VALUE_TO_STACK").unwrap();
        let event2 = EventId::new(EventSource::Stdlib, "crypto", "FALCON_SIG_VERIFY").unwrap();
        
        // Register events
        let reduced1 = table.register(event1.clone()).unwrap();
        let reduced2 = table.register(event2.clone()).unwrap();
        
        // Test lookups
        assert_eq!(table.lookup_by_event(&event1), Some(reduced1));
        assert_eq!(table.lookup_by_event(&event2), Some(reduced2));
        assert_eq!(table.lookup_by_reduced_id(reduced1), Some(&event1));
        assert_eq!(table.lookup_by_reduced_id(reduced2), Some(&event2));
        assert_eq!(table.lookup_by_felt(reduced1.as_felt()), Some(&event1));
        assert_eq!(table.lookup_by_felt(reduced2.as_felt()), Some(&event2));
        
        // Test contains
        assert!(table.contains_event(&event1));
        assert!(table.contains_reduced_id(reduced1));
        assert!(table.contains_felt(reduced1.as_felt()));
        assert!(!table.contains_felt(Felt::new(99999)));
        
        // Test length
        assert_eq!(table.len(), 2);
        assert!(!table.is_empty());
    }

    #[test]
    fn test_duplicate_registration() {
        let mut table = EventTable::new();
        
        let event = EventId::new(EventSource::System, "memory", "MAP_VALUE").unwrap();
        
        // Register same event twice
        let reduced1 = table.register(event.clone()).unwrap();
        let reduced2 = table.register(event).unwrap();
        
        // Should return same ReducedEventID
        assert_eq!(reduced1, reduced2);
        assert_eq!(table.len(), 1); // Should not duplicate
    }

    #[test]
    fn test_table_validation() {
        let mut table = EventTable::new();
        
        let event = EventId::new(EventSource::System, "memory", "MAP_VALUE").unwrap();
        table.register(event).unwrap();
        
        // Should validate successfully
        assert!(table.validate().is_ok());
    }

    #[test]
    fn test_table_merge() {
        let mut table1 = EventTable::new();
        let mut table2 = EventTable::new();
        
        let event1 = EventId::new(EventSource::System, "memory", "MAP_VALUE").unwrap();
        let event2 = EventId::new(EventSource::Stdlib, "crypto", "FALCON_SIG").unwrap();
        
        table1.register(event1.clone()).unwrap();
        table2.register(event2.clone()).unwrap();
        
        // Merge should work
        table1.merge(table2).unwrap();
        
        assert_eq!(table1.len(), 2);
        assert!(table1.contains_event(&event1));
        assert!(table1.contains_event(&event2));
    }

    #[test]
    fn test_legacy_u32_registration() {
        let mut table = EventTable::new();
        
        let event = EventId::new(EventSource::System, "test", "EVENT").unwrap();
        let legacy_id = 12345u32;
        
        // Register with legacy ID
        let reduced_id = table.register_u32(event.clone(), legacy_id).unwrap();
        assert_eq!(reduced_id, ReducedEventID::from_u32(legacy_id));
        
        // Verify lookup works
        assert_eq!(table.lookup_by_event(&event), Some(reduced_id));
        assert_eq!(table.lookup_by_reduced_id(reduced_id), Some(&event));
    }

    #[test]
    fn test_iteration() {
        let mut table = EventTable::new();
        
        let event1 = EventId::new(EventSource::System, "memory", "MAP_VALUE").unwrap();
        let event2 = EventId::new(EventSource::Stdlib, "crypto", "FALCON_SIG").unwrap();
        
        let reduced1 = table.register(event1.clone()).unwrap();
        let reduced2 = table.register(event2.clone()).unwrap();
        
        let entries: Vec<_> = table.iter().collect();
        assert_eq!(entries.len(), 2);
        
        // Verify both entries are present (order may vary due to BTreeMap)
        assert!(entries.contains(&(&event1, reduced1)));
        assert!(entries.contains(&(&event2, reduced2)));
    }
}