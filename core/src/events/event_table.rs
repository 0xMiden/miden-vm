use alloc::{
    collections::BTreeMap,
    string::ToString,
    vec::Vec,
};
use core::fmt;

use super::EventId;
use crate::{
    Felt,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// EVENT TABLE
// ================================================================================================

/// A bidirectional mapping between EventId and Felt representations with collision detection.
/// 
/// The EventTable is essential for reverse lookup capabilities, allowing the VM to map
/// from Felt event IDs back to human-readable event names. It also detects and handles
/// hash collisions that could occur when multiple EventIds map to the same Felt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventTable {
    /// Forward lookup: EventId -> Felt
    event_to_felt: BTreeMap<EventId, Felt>,
    
    /// Reverse lookup: Felt -> EventId  
    felt_to_event: BTreeMap<u64, EventId>,
    
    /// Collision tracking and resolution
    collisions: Vec<EventCollision>,
}

impl EventTable {
    /// Creates a new empty event table.
    pub fn new() -> Self {
        Self {
            event_to_felt: BTreeMap::new(),
            felt_to_event: BTreeMap::new(),
            collisions: Vec::new(),
        }
    }

    /// Registers an EventId in the table, computing its Felt representation.
    /// 
    /// Returns an error if there's a collision that cannot be resolved.
    pub fn register(&mut self, event_id: EventId) -> Result<Felt, EventTableError> {
        let felt_id = event_id.felt_id();
        let felt_key = felt_id.as_int();

        // Check if this exact EventId is already registered
        if let Some(existing_felt) = self.event_to_felt.get(&event_id) {
            return Ok(*existing_felt);
        }

        // Check for collision with a different EventId
        if let Some(existing_event) = self.felt_to_event.get(&felt_key) {
            if existing_event != &event_id {
                // We have a collision - record it
                let collision = EventCollision {
                    felt: felt_id,
                    events: vec![existing_event.clone(), event_id.clone()],
                    resolution: CollisionResolution::Error,
                };
                
                return Err(EventTableError::Collision(collision));
            }
        }

        // No collision - register the mapping
        self.event_to_felt.insert(event_id.clone(), felt_id);
        self.felt_to_event.insert(felt_key, event_id);

        Ok(felt_id)
    }

    /// Registers an EventId with explicit collision resolution.
    pub fn register_with_resolution(
        &mut self,
        event_id: EventId,
        resolution: CollisionResolution,
    ) -> Result<Felt, EventTableError> {
        match self.register(event_id.clone()) {
            Ok(felt) => Ok(felt),
            Err(EventTableError::Collision(mut collision)) => {
                // Apply the resolution strategy
                match resolution {
                    CollisionResolution::Error => Err(EventTableError::Collision(collision)),
                    CollisionResolution::Rename(new_event_id) => {
                        // Try to register the renamed event
                        let new_felt = self.register(new_event_id.clone())?;
                        
                        // Update collision record
                        collision.resolution = CollisionResolution::Rename(new_event_id);
                        self.collisions.push(collision);
                        
                        Ok(new_felt)
                    },
                    CollisionResolution::Manual(ref mapping) => {
                        // Use the manually specified Felt
                        if let Some(&manual_felt) = mapping.get(&event_id) {
                            // Verify the manual Felt doesn't conflict
                            let manual_key = manual_felt.as_int();
                            if let Some(existing) = self.felt_to_event.get(&manual_key) {
                                if existing != &event_id {
                                    return Err(EventTableError::ManualMappingConflict {
                                        felt: manual_felt,
                                        existing: existing.clone(),
                                        requested: event_id,
                                    });
                                }
                            }
                            
                            // Register with manual mapping
                            self.event_to_felt.insert(event_id.clone(), manual_felt);
                            self.felt_to_event.insert(manual_key, event_id);
                            
                            collision.resolution = resolution;
                            self.collisions.push(collision);
                            
                            Ok(manual_felt)
                        } else {
                            Err(EventTableError::ManualMappingMissing(event_id))
                        }
                    },
                }
            },
            Err(other_error) => Err(other_error),
        }
    }

    /// Looks up the Felt representation of an EventId.
    pub fn lookup_by_event(&self, event_id: &EventId) -> Option<Felt> {
        self.event_to_felt.get(event_id).copied()
    }

    /// Looks up the EventId from its Felt representation.
    pub fn lookup_by_felt(&self, felt: Felt) -> Option<&EventId> {
        self.felt_to_event.get(&felt.as_int())
    }

    /// Returns true if the EventId is registered.
    pub fn contains_event(&self, event_id: &EventId) -> bool {
        self.event_to_felt.contains_key(event_id)
    }

    /// Returns true if the Felt is registered.
    pub fn contains_felt(&self, felt: Felt) -> bool {
        self.felt_to_event.contains_key(&felt.as_int())
    }

    /// Returns the number of registered events.
    pub fn len(&self) -> usize {
        self.event_to_felt.len()
    }

    /// Returns true if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.event_to_felt.is_empty()
    }

    /// Returns an iterator over all registered events.
    pub fn iter(&self) -> impl Iterator<Item = (&EventId, Felt)> {
        self.event_to_felt.iter().map(|(event, &felt)| (event, felt))
    }

    /// Returns all recorded collisions.
    pub fn collisions(&self) -> &[EventCollision] {
        &self.collisions
    }

    /// Merges another EventTable into this one.
    /// 
    /// Returns an error if any unresolvable collisions are detected.
    pub fn merge(&mut self, other: EventTable) -> Result<(), EventTableError> {
        for (event_id, _) in other.event_to_felt {
            self.register(event_id)?;
        }
        
        // Merge collision records
        self.collisions.extend(other.collisions);
        
        Ok(())
    }

    /// Merges another EventTable with collision resolution strategy.
    pub fn merge_with_resolution(
        &mut self,
        other: EventTable,
        default_resolution: CollisionResolution,
    ) -> Result<(), EventTableError> {
        for (event_id, _) in other.event_to_felt {
            self.register_with_resolution(event_id, default_resolution.clone())?;
        }
        
        // Merge collision records
        self.collisions.extend(other.collisions);
        
        Ok(())
    }

    /// Validates the table for consistency.
    pub fn validate(&self) -> Result<(), EventTableError> {
        // Check that forward and reverse mappings are consistent
        for (event, &felt) in &self.event_to_felt {
            let felt_key = felt.as_int();
            if let Some(reverse_event) = self.felt_to_event.get(&felt_key) {
                if reverse_event != event {
                    return Err(EventTableError::InconsistentMapping {
                        event: event.clone(),
                        felt,
                        reverse_event: reverse_event.clone(),
                    });
                }
            } else {
                return Err(EventTableError::MissingReverseMapping {
                    event: event.clone(),
                    felt,
                });
            }
        }

        // Check reverse mappings
        for (&felt_key, event) in &self.felt_to_event {
            let felt = Felt::new(felt_key);
            if let Some(&forward_felt) = self.event_to_felt.get(event) {
                if forward_felt != felt {
                    return Err(EventTableError::InconsistentMapping {
                        event: event.clone(),
                        felt,
                        reverse_event: event.clone(),
                    });
                }
            } else {
                return Err(EventTableError::MissingForwardMapping {
                    event: event.clone(),
                    felt,
                });
            }
        }

        Ok(())
    }
}

// EVENT COLLISION
// ================================================================================================

/// Represents a collision between multiple EventIds that map to the same Felt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventCollision {
    /// The Felt value that multiple events map to
    pub felt: Felt,
    
    /// The conflicting events
    pub events: Vec<EventId>,
    
    /// How the collision was resolved
    pub resolution: CollisionResolution,
}

/// Strategies for resolving event ID collisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollisionResolution {
    /// Fail with an error (default behavior)
    Error,
    
    /// Rename one of the colliding events
    Rename(EventId),
    
    /// Use manually specified Felt mappings
    Manual(BTreeMap<EventId, Felt>),
}

impl Serializable for EventCollision {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.felt.write_into(target);
        
        target.write_usize(self.events.len());
        for event in &self.events {
            event.write_into(target);
        }
        
        self.resolution.write_into(target);
    }
}

impl Deserializable for EventCollision {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let felt = Felt::read_from(source)?;
        
        let num_events = source.read_usize()?;
        let mut events = Vec::with_capacity(num_events);
        for _ in 0..num_events {
            events.push(EventId::read_from(source)?);
        }
        
        let resolution = CollisionResolution::read_from(source)?;
        
        Ok(EventCollision {
            felt,
            events,
            resolution,
        })
    }
}

impl Serializable for CollisionResolution {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            CollisionResolution::Error => {
                target.write_u8(0);
            }
            CollisionResolution::Rename(event_id) => {
                target.write_u8(1);
                event_id.write_into(target);
            }
            CollisionResolution::Manual(mappings) => {
                target.write_u8(2);
                target.write_usize(mappings.len());
                for (event_id, felt) in mappings {
                    event_id.write_into(target);
                    felt.write_into(target);
                }
            }
        }
    }
}

impl Deserializable for CollisionResolution {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let variant = source.read_u8()?;
        match variant {
            0 => Ok(CollisionResolution::Error),
            1 => {
                let event_id = EventId::read_from(source)?;
                Ok(CollisionResolution::Rename(event_id))
            }
            2 => {
                let num_mappings = source.read_usize()?;
                let mut mappings = BTreeMap::new();
                for _ in 0..num_mappings {
                    let event_id = EventId::read_from(source)?;
                    let felt = Felt::read_from(source)?;
                    mappings.insert(event_id, felt);
                }
                Ok(CollisionResolution::Manual(mappings))
            }
            _ => Err(DeserializationError::InvalidValue("invalid CollisionResolution variant".to_string())),
        }
    }
}

// EVENT TABLE ERROR
// ================================================================================================

/// Errors that can occur when working with EventTables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventTableError {
    /// Multiple EventIds map to the same Felt
    Collision(EventCollision),
    
    /// Manual mapping conflicts with existing registration
    ManualMappingConflict {
        felt: Felt,
        existing: EventId,
        requested: EventId,
    },
    
    /// Manual mapping doesn't specify a Felt for the EventId
    ManualMappingMissing(EventId),
    
    /// Forward and reverse mappings are inconsistent
    InconsistentMapping {
        event: EventId,
        felt: Felt,
        reverse_event: EventId,
    },
    
    /// Missing reverse mapping for an event
    MissingReverseMapping {
        event: EventId,
        felt: Felt,
    },
    
    /// Missing forward mapping for a Felt
    MissingForwardMapping {
        event: EventId,
        felt: Felt,
    },
}

impl fmt::Display for EventTableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventTableError::Collision(collision) => {
                write!(f, "Event collision: {} events map to Felt {}: ", 
                       collision.events.len(), collision.felt)?;
                for (i, event) in collision.events.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "'{}'", event)?;
                }
                Ok(())
            },
            EventTableError::ManualMappingConflict { felt, existing, requested } => {
                write!(f, "Manual mapping conflict: Felt {} is already mapped to '{}', \
                          cannot map to '{}'", felt, existing, requested)
            },
            EventTableError::ManualMappingMissing(event) => {
                write!(f, "Manual mapping missing for event '{}'", event)
            },
            EventTableError::InconsistentMapping { event, felt, reverse_event } => {
                write!(f, "Inconsistent mapping: event '{}' maps to Felt {}, \
                          but Felt maps back to '{}'", event, felt, reverse_event)
            },
            EventTableError::MissingReverseMapping { event, felt } => {
                write!(f, "Missing reverse mapping: event '{}' maps to Felt {}, \
                          but no reverse mapping exists", event, felt)
            },
            EventTableError::MissingForwardMapping { event, felt } => {
                write!(f, "Missing forward mapping: Felt {} maps to event '{}', \
                          but no forward mapping exists", felt, event)
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
        target.write_usize(self.event_to_felt.len());
        
        // Write each (EventId, Felt) pair
        for (event_id, &felt) in &self.event_to_felt {
            event_id.write_into(target);
            felt.write_into(target);
        }
        
        // Write collision information
        target.write_usize(self.collisions.len());
        for collision in &self.collisions {
            collision.write_into(target);
        }
    }
}

impl Deserializable for EventTable {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut table = EventTable::new();
        
        // Read the number of entries
        let num_entries = source.read_usize()?;
        
        // Read each (EventId, Felt) pair and register them
        for _ in 0..num_entries {
            let event_id = EventId::read_from(source)?;
            let felt = Felt::read_from(source)?;
            
            // Directly insert without re-hashing since we trust the serialized data
            table.event_to_felt.insert(event_id.clone(), felt);
            table.felt_to_event.insert(felt.as_int(), event_id);
        }
        
        // Read collision information
        let num_collisions = source.read_usize()?;
        for _ in 0..num_collisions {
            let collision = EventCollision::read_from(source)?;
            table.collisions.push(collision);
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

    #[test]
    fn test_event_table_basic_operations() {
        let mut table = EventTable::new();
        
        let event1 = EventId::new(EventSource::System, "memory", "MAP_VALUE_TO_STACK").unwrap();
        let event2 = EventId::new(EventSource::Stdlib, "crypto", "FALCON_SIG_VERIFY").unwrap();
        
        // Register events
        let felt1 = table.register(event1.clone()).unwrap();
        let felt2 = table.register(event2.clone()).unwrap();
        
        // Test lookups
        assert_eq!(table.lookup_by_event(&event1), Some(felt1));
        assert_eq!(table.lookup_by_event(&event2), Some(felt2));
        assert_eq!(table.lookup_by_felt(felt1), Some(&event1));
        assert_eq!(table.lookup_by_felt(felt2), Some(&event2));
        
        // Test contains
        assert!(table.contains_event(&event1));
        assert!(table.contains_felt(felt1));
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
        let felt1 = table.register(event.clone()).unwrap();
        let felt2 = table.register(event).unwrap();
        
        // Should return same Felt
        assert_eq!(felt1, felt2);
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
    fn test_collision_detection() {
        // This test would require crafting EventIds that produce the same Felt,
        // which is computationally difficult with Blake3. In practice, we'd
        // use mock implementations for testing collision scenarios.
        
        let mut table = EventTable::new();
        let event = EventId::new(EventSource::System, "test", "EVENT").unwrap();
        table.register(event).unwrap();
        
        // For now, just verify the collision detection framework exists
        assert!(table.collisions().is_empty());
    }

    #[test]
    fn test_iteration() {
        let mut table = EventTable::new();
        
        let event1 = EventId::new(EventSource::System, "memory", "MAP_VALUE").unwrap();
        let event2 = EventId::new(EventSource::Stdlib, "crypto", "FALCON_SIG").unwrap();
        
        let felt1 = table.register(event1.clone()).unwrap();
        let felt2 = table.register(event2.clone()).unwrap();
        
        let entries: Vec<_> = table.iter().collect();
        assert_eq!(entries.len(), 2);
        
        // Verify both entries are present (order may vary due to BTreeMap)
        assert!(entries.contains(&(&event1, felt1)));
        assert!(entries.contains(&(&event2, felt2)));
    }
}