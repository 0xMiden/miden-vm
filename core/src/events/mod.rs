// Module-level imports for re-exports only

// RE-EXPORTS
// ================================================================================================

pub use event_id::{EventId, EventIdError};
pub use event_table::EventTable;
pub use reduced_id::ReducedEventID;

// MODULES
// ================================================================================================

mod event_id;
mod event_table;
mod reduced_id;

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
        let system_event = EventId::system("MAP_VALUE_TO_STACK".to_string());
        let library_event = EventId::new("crypto-lib".to_string(), "SIGN".to_string()).unwrap();
        let another_event = EventId::new("dex-lib".to_string(), "SWAP".to_string()).unwrap();

        // Register events
        let reduced1 = table.register(system_event.clone());
        let reduced2 = table.register(library_event.clone());
        let reduced3 = table.register(another_event.clone());

        // Verify lookups work
        assert_eq!(table.lookup_by_reduced_id(reduced1), Some(&system_event));
        assert_eq!(table.lookup_by_reduced_id(reduced2), Some(&library_event));
        assert_eq!(table.lookup_by_reduced_id(reduced3), Some(&another_event));

        // Verify event IDs are deterministic (Blake3 hashing)
        assert_eq!(system_event.reduced_id(), reduced1);
        assert_eq!(library_event.reduced_id(), reduced2);
        assert_eq!(another_event.reduced_id(), reduced3);

        // Verify different events produce different reduced IDs
        assert_ne!(reduced1, reduced2);
        assert_ne!(reduced2, reduced3);
        assert_ne!(reduced1, reduced3);
    }

    #[test]
    fn test_display_format() {
        let system_event = EventId::system("TEST_EVENT".to_string());
        let library_event = EventId::new("my-lib".to_string(), "EVENT1".to_string()).unwrap();
        let another_event =
            EventId::new("different-lib".to_string(), "EVENT2".to_string()).unwrap();

        assert_eq!(format!("{}", system_event), "system::TEST_EVENT");
        assert_eq!(format!("{}", library_event), "my-lib::EVENT1");
        assert_eq!(format!("{}", another_event), "different-lib::EVENT2");
    }

    #[test]
    fn test_no_namespace_collisions() {
        // This test demonstrates the fix for the main issue with the old design
        let lib1_event = EventId::new("crypto-lib".to_string(), "SIGN".to_string()).unwrap();
        let lib2_event = EventId::new("different-crypto".to_string(), "SIGN".to_string()).unwrap();

        // Different libraries with same event name should have different reduced IDs
        assert_ne!(lib1_event.reduced_id(), lib2_event.reduced_id());

        // But identical library::event should have same reduced ID
        let duplicate = EventId::new("crypto-lib".to_string(), "SIGN".to_string()).unwrap();
        assert_eq!(lib1_event.reduced_id(), duplicate.reduced_id());
    }
}
