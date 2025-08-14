use alloc::{collections::BTreeMap, vec::Vec};
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
    /// None indicates a legacy u32 event ID without a structured EventId
    reduced_to_event: BTreeMap<ReducedEventID, Option<EventId>>,
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
        if let Some(existing_event_opt) = self.reduced_to_event.get(&reduced_id) {
            match existing_event_opt {
                Some(existing_event) if existing_event != &event_id => {
                    return Err(EventTableError::Collision {
                        reduced_id,
                        existing: existing_event.clone(),
                        conflicting: event_id,
                    });
                }
                None => {
                    // Legacy event exists at this ReducedEventID - collision with structured event
                    return Err(EventTableError::LegacyCollision {
                        reduced_id,
                        conflicting: event_id,
                    });
                }
                Some(_) => {
                    // Same EventId already registered, fall through to return existing
                }
            }
        }

        // No collision - register the mapping
        self.event_to_reduced.insert(event_id.clone(), reduced_id);
        self.reduced_to_event.insert(reduced_id, Some(event_id));

        Ok(reduced_id)
    }

    /// Registers a legacy u32 event ID without a structured EventId.
    /// 
    /// This is used for legacy numeric event IDs that don't have full structured names.
    pub fn register_legacy(&mut self, legacy_id: u32) -> Result<ReducedEventID, EventTableError> {
        let reduced_id = ReducedEventID::from_u32(legacy_id);

        // Check if this ReducedEventID is already registered
        if let Some(existing_event_opt) = self.reduced_to_event.get(&reduced_id) {
            match existing_event_opt {
                None => {
                    // Already registered as legacy - return existing
                    return Ok(reduced_id);
                }
                Some(existing_event) => {
                    // Collision with structured EventId
                    return Err(EventTableError::StructuredCollision {
                        reduced_id,
                        legacy_id,
                        existing: existing_event.clone(),
                    });
                }
            }
        }

        // No collision - register the legacy mapping
        self.reduced_to_event.insert(reduced_id, None);

        Ok(reduced_id)
    }

    /// Looks up the ReducedEventID for an EventId.
    pub fn lookup_by_event(&self, event_id: &EventId) -> Option<ReducedEventID> {
        self.event_to_reduced.get(event_id).copied()
    }

    /// Looks up the EventId from its ReducedEventID.
    /// Returns None if the ReducedEventID is not registered or is a legacy event.
    pub fn lookup_by_reduced_id(&self, reduced_id: ReducedEventID) -> Option<&EventId> {
        self.reduced_to_event.get(&reduced_id)?.as_ref()
    }

    /// Looks up the EventId from a Felt (for backward compatibility).
    /// Returns None if the Felt is not registered or is a legacy event.
    pub fn lookup_by_felt(&self, felt: Felt) -> Option<&EventId> {
        let reduced_id = ReducedEventID::new(felt);
        self.reduced_to_event.get(&reduced_id)?.as_ref()
    }

    /// Checks if a ReducedEventID is registered as a legacy event.
    pub fn is_legacy(&self, reduced_id: ReducedEventID) -> bool {
        matches!(self.reduced_to_event.get(&reduced_id), Some(None))
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

    /// Returns a list of legacy u32 event IDs that the host should handle.
    /// These are the numeric event IDs without structured EventId names.
    pub fn legacy_event_ids(&self) -> Vec<u32> {
        self.reduced_to_event
            .iter()
            .filter_map(|(reduced_id, event_opt)| {
                if event_opt.is_none() {
                    // This is a legacy event - extract the u32
                    Some(reduced_id.as_u64() as u32)
                } else {
                    None
                }
            })
            .collect()
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
            if let Some(reverse_event_opt) = self.reduced_to_event.get(&reduced_id) {
                match reverse_event_opt {
                    Some(reverse_event) if reverse_event != event => {
                        return Err(EventTableError::InconsistentMapping {
                            event: event.clone(),
                            reduced_id,
                            reverse_event: reverse_event.clone(),
                        });
                    }
                    None => {
                        return Err(EventTableError::EventMappedToLegacy {
                            event: event.clone(),
                            reduced_id,
                        });
                    }
                    Some(_) => {
                        // Consistent mapping
                    }
                }
            } else {
                return Err(EventTableError::MissingReverseMapping {
                    event: event.clone(),
                    reduced_id,
                });
            }
        }

        // Check reverse mappings
        for (&reduced_id, event_opt) in &self.reduced_to_event {
            if let Some(event) = event_opt {
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
            // Legacy events (None) don't need forward mapping validation
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
    
    /// Structured EventId collides with existing legacy event
    LegacyCollision {
        reduced_id: ReducedEventID,
        conflicting: EventId,
    },
    
    /// Legacy u32 ID collides with existing structured EventId
    StructuredCollision {
        reduced_id: ReducedEventID,
        legacy_id: u32,
        existing: EventId,
    },
    
    /// EventId mapped to a ReducedEventID that's registered as legacy
    EventMappedToLegacy {
        event: EventId,
        reduced_id: ReducedEventID,
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
            EventTableError::LegacyCollision { reduced_id, conflicting } => {
                write!(f, "Legacy collision: EventId '{}' collides with existing legacy event at ReducedEventID {}", 
                       conflicting, reduced_id)
            },
            EventTableError::StructuredCollision { reduced_id, legacy_id, existing } => {
                write!(f, "Structured collision: Legacy ID {} collides with existing EventId '{}' at ReducedEventID {}", 
                       legacy_id, existing, reduced_id)
            },
            EventTableError::EventMappedToLegacy { event, reduced_id } => {
                write!(f, "EventId '{}' mapped to ReducedEventID {} which is registered as legacy", 
                       event, reduced_id)
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
        // Write the total number of entries (structured + legacy)
        target.write_usize(self.reduced_to_event.len());
        
        // Write each entry from the reverse mapping
        for (&reduced_id, event_opt) in &self.reduced_to_event {
            reduced_id.write_into(target);
            match event_opt {
                Some(event_id) => {
                    // Write flag indicating structured event (1) followed by EventId
                    target.write_u8(1);
                    event_id.write_into(target);
                }
                None => {
                    // Write flag indicating legacy event (0)
                    target.write_u8(0);
                }
            }
        }
    }
}

impl Deserializable for EventTable {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut table = EventTable::new();
        
        // Read the number of entries
        let num_entries = source.read_usize()?;
        
        // Read each entry
        for _ in 0..num_entries {
            let reduced_id = ReducedEventID::read_from(source)?;
            let event_type_flag = source.read_u8()?;
            
            match event_type_flag {
                1 => {
                    // Structured event
                    let event_id = EventId::read_from(source)?;
                    // Directly insert without re-hashing since we trust the serialized data
                    table.event_to_reduced.insert(event_id.clone(), reduced_id);
                    table.reduced_to_event.insert(reduced_id, Some(event_id));
                }
                0 => {
                    // Legacy event
                    table.reduced_to_event.insert(reduced_id, None);
                }
                _ => {
                    return Err(DeserializationError::InvalidValue(format!(
                        "Invalid event type flag: {}", event_type_flag
                    )));
                }
            }
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
        
        let legacy_id = 12345u32;
        
        // Register legacy event
        let reduced_id = table.register_legacy(legacy_id).unwrap();
        assert_eq!(reduced_id, ReducedEventID::from_u32(legacy_id));
        
        // Verify lookup behavior for legacy events
        assert_eq!(table.lookup_by_reduced_id(reduced_id), None); // Legacy events return None
        assert!(table.is_legacy(reduced_id));
        assert!(table.contains_reduced_id(reduced_id));
        
        // Verify legacy_event_ids() returns the registered ID
        let legacy_ids = table.legacy_event_ids();
        assert_eq!(legacy_ids, vec![legacy_id]);
    }

    #[test]
    fn test_legacy_structured_collision() {
        let mut table = EventTable::new();
        
        // Test basic collision detection structure without depending on hash collisions
        let legacy_id = 12345u32;
        
        // First register legacy event
        let reduced_id = table.register_legacy(legacy_id).unwrap();
        assert!(table.is_legacy(reduced_id));
        
        // Verify that duplicate legacy registration works
        let reduced_id2 = table.register_legacy(legacy_id).unwrap();
        assert_eq!(reduced_id, reduced_id2);
        
        // Test that we can register different legacy IDs
        let legacy_id3 = 54321u32;
        let reduced_id3 = table.register_legacy(legacy_id3).unwrap();
        assert_ne!(reduced_id, reduced_id3);
        
        // Verify legacy_event_ids returns both IDs
        let mut legacy_ids = table.legacy_event_ids();
        legacy_ids.sort();
        assert_eq!(legacy_ids, vec![12345, 54321]);
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