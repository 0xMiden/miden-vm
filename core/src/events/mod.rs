// Module-level imports for re-exports only

// RE-EXPORTS
// ================================================================================================

pub use event_name::{EventName, EventNameError};
pub use event_table::EventTable;
pub use event_id::EventID;

// MODULES
// ================================================================================================

mod event_name;
mod event_table;
mod event_id;

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn test_event_system_integration() {
        // Test the complete event system workflow with library::event API
        let mut table = EventTable::new();

        // Create events using the new library::event API
        let system_event = EventName::system("map_value_to_stack".to_string());
        let library_event = EventName::new("crypto_lib".to_string(), "sign".to_string()).unwrap();
        let another_event = EventName::new("dex_lib".to_string(), "swap".to_string()).unwrap();

        // Register events
        let id1 = table.register(system_event.clone());
        let id2 = table.register(library_event.clone());
        let id3 = table.register(another_event.clone());

        // Verify lookups work
        assert_eq!(table.lookup_by_event_id(id1), Some(&system_event));
        assert_eq!(table.lookup_by_event_id(id2), Some(&library_event));
        assert_eq!(table.lookup_by_event_id(id3), Some(&another_event));

        // Verify event IDs are deterministic (Blake3 hashing)
        assert_eq!(system_event.id(), id1);
        assert_eq!(library_event.id(), id2);
        assert_eq!(another_event.id(), id3);

        // Verify different events produce different IDs
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_display_format() {
        let system_event = EventName::system("test_event".to_string());
        let library_event = EventName::new("my_lib".to_string(), "event_one".to_string()).unwrap();
        let another_event =
            EventName::new("different_lib".to_string(), "event_two".to_string()).unwrap();

        assert_eq!(format!("{system_event}"), "system::test_event");
        assert_eq!(format!("{library_event}"), "my_lib::event_one");
        assert_eq!(format!("{another_event}"), "different_lib::event_two");
    }

    #[test]
    fn test_no_namespace_collisions() {
        // This test demonstrates the fix for the main issue with the old design
        let lib1_event = EventName::new("crypto_lib".to_string(), "sign".to_string()).unwrap();
        let lib2_event = EventName::new("different_crypto".to_string(), "sign".to_string()).unwrap();

        // Different libraries with same event name should have different IDs
        assert_ne!(lib1_event.id(), lib2_event.id());

        // But identical library::event should have same ID
        let duplicate = EventName::new("crypto_lib".to_string(), "sign".to_string()).unwrap();
        assert_eq!(lib1_event.id(), duplicate.id());
    }
}
