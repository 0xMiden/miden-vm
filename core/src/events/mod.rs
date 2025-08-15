// Module-level imports for re-exports only

// RE-EXPORTS
// ================================================================================================

pub use event_id::EventID;
pub use event_name::{EventName, EventNameError};
pub use event_table::EventTable;

// MODULES
// ================================================================================================

mod event_id;
mod event_name;
mod event_table;

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_system_integration() {
        // Test the complete event system workflow with library::event API
        let mut table = EventTable::new();

        // Create events using the new library::event API
        let system_event = EventName::system("map_value_to_stack");
        let library_event = EventName::new("crypto_lib", "sign").unwrap();
        let another_event = EventName::new("dex_lib", "swap").unwrap();

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
        let system_event = EventName::system("test_event");
        let library_event = EventName::new("my_lib", "event_one").unwrap();
        let another_event = EventName::new("different_lib", "event_two").unwrap();

        assert_eq!(format!("{system_event}"), "system::test_event");
        assert_eq!(format!("{library_event}"), "my_lib::event_one");
        assert_eq!(format!("{another_event}"), "different_lib::event_two");
    }

    #[test]
    fn test_no_namespace_collisions() {
        // This test demonstrates the fix for the main issue with the old design
        let lib1_event = EventName::new("crypto_lib", "sign").unwrap();
        let lib2_event = EventName::new("different_crypto", "sign").unwrap();

        // Different libraries with same event name should have different IDs
        assert_ne!(lib1_event.id(), lib2_event.id());

        // But identical library::event should have same ID
        let duplicate = EventName::new("crypto_lib", "sign").unwrap();
        assert_eq!(lib1_event.id(), duplicate.id());
    }
}
