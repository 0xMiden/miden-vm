// Module-level imports for re-exports only

// RE-EXPORTS
// ================================================================================================

pub use event_id::{EventId, EventIdError, EventSource};
pub use event_table::{EventTable, EventTableError};
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
    use super::*;

    #[test]
    fn test_event_system_integration() {
        // Test the complete event system workflow
        let mut table = EventTable::new();
        
        // Create events from different sources
        let system_event = EventId::new(EventSource::System, "memory", "MAP_VALUE_TO_STACK").unwrap();
        let stdlib_event = EventId::new(EventSource::Stdlib, "crypto", "FALCON_SIG_VERIFY").unwrap();
        let user_event = EventId::new(EventSource::User(42), "app", "CUSTOM_EVENT").unwrap();
        
        // Register events
        let reduced1 = table.register(system_event.clone()).unwrap();
        let reduced2 = table.register(stdlib_event.clone()).unwrap();
        let reduced3 = table.register(user_event.clone()).unwrap();
        
        // Verify lookups work
        assert_eq!(table.lookup_by_felt(reduced1.as_felt()), Some(&system_event));
        assert_eq!(table.lookup_by_felt(reduced2.as_felt()), Some(&stdlib_event));
        assert_eq!(table.lookup_by_felt(reduced3.as_felt()), Some(&user_event));
        
        // Verify event IDs are deterministic
        assert_eq!(system_event.reduced_id(), reduced1);
        assert_eq!(stdlib_event.reduced_id(), reduced2);
        assert_eq!(user_event.reduced_id(), reduced3);
        
        // Verify different events produce different reduced IDs
        assert_ne!(reduced1, reduced2);
        assert_ne!(reduced2, reduced3);
        assert_ne!(reduced1, reduced3);
    }

    #[test]
    fn test_canonical_string_format() {
        let event = EventId::new(EventSource::Stdlib, "crypto", "FALCON_SIG_VERIFY").unwrap();
        assert_eq!(event.canonical_string(), "miden-stdlib/crypto::FALCON_SIG_VERIFY");
        
        let system_event = EventId::new(EventSource::System, "memory", "MAP_VALUE").unwrap();
        assert_eq!(system_event.canonical_string(), "miden-vm/memory::MAP_VALUE");
        
        let user_event = EventId::new(EventSource::User(123), "app", "MY_EVENT").unwrap();
        assert_eq!(user_event.canonical_string(), "user-123/app::MY_EVENT");
    }

    #[test]
    fn test_parsing_canonical_strings() {
        let parsed: EventId = "miden-stdlib/crypto::FALCON_SIG_VERIFY".parse().unwrap();
        let expected = EventId::new(EventSource::Stdlib, "crypto", "FALCON_SIG_VERIFY").unwrap();
        assert_eq!(parsed, expected);
        
        let parsed2: EventId = "user-42/app::CUSTOM_EVENT".parse().unwrap();
        let expected2 = EventId::new(EventSource::User(42), "app", "CUSTOM_EVENT").unwrap();
        assert_eq!(parsed2, expected2);
    }
}