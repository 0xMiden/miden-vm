use core::fmt;

use miden_core::Felt;
use blake3::Hasher;

use crate::AsmError;

// CANONICAL EVENT ID
// ================================================================================================

/// ASCII-only, canonical form: "<namespace>/<library>::<EVENT_NAME>"
pub fn canonicalize_event_id(s: &str) -> Result<String, AsmError> {
    // Check that the string is valid UTF-8
    if !s.is_ascii() {
        return Err(AsmError::InvalidEventId {
            event_id: s.to_string(),
            reason: "Event ID must contain only ASCII characters".to_string(),
        });
    }

    // Split the string into namespace/library and event name parts
    let parts: Vec<&str> = s.split("::").collect();
    if parts.len() != 2 {
        return Err(AsmError::InvalidEventId {
            event_id: s.to_string(),
            reason: "Event ID must be in the format '<namespace>/<library>::<EVENT_NAME>'".to_string(),
        });
    }

    let namespace_library = parts[0];
    let event_name = parts[1];

    // Validate namespace/library: lowercase ASCII [a-z0-9._-]+
    if namespace_library.is_empty() {
        return Err(AsmError::InvalidEventId {
            event_id: s.to_string(),
            reason: "Namespace/library part cannot be empty".to_string(),
        });
    }

    for (i, c) in namespace_library.chars().enumerate() {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_' || c == '-' || c == '/') {
            return Err(AsmError::InvalidEventId {
                event_id: s.to_string(),
                reason: format!(
                    "Invalid character '{}' at position {} in namespace/library part. \
                     Only lowercase letters, digits, '.', '_', '-', and '/' are allowed",
                    c, i
                ),
            });
        }
    }

    // Validate event name: uppercase ASCII [A-Z0-9_]+
    if event_name.is_empty() {
        return Err(AsmError::InvalidEventId {
            event_id: s.to_string(),
            reason: "Event name part cannot be empty".to_string(),
        });
    }

    for (i, c) in event_name.chars().enumerate() {
        if !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
            return Err(AsmError::InvalidEventId {
                event_id: s.to_string(),
                reason: format!(
                    "Invalid character '{}' at position {} in event name part. \
                     Only uppercase letters, digits, and '_' are allowed",
                    c, i + namespace_library.len() + 2
                ),
            });
        }
    }

    // Return the canonical form (which is the same as the input if it's valid)
    Ok(s.to_string())
}

/// Domain-separated hash to 256 bits, then reduce mod p to Felt.
pub fn felt_event_id(canon: &str) -> Felt {
    // Create a domain-separated hasher
    let mut hasher = Hasher::new();
    hasher.update(b"miden/event-id/v1");
    hasher.update(canon.as_bytes());
    
    // Get the hash output
    let hash = hasher.finalize();
    let hash_bytes = hash.as_bytes();
    
    // Convert the first 8 bytes to a u64 (little-endian)
    let mut value = 0u64;
    for i in 0..8 {
        value |= (hash_bytes[i] as u64) << (i * 8);
    }
    
    // Reduce mod p to get a Felt
    Felt::new(value)
}

// ERROR HANDLING
// ================================================================================================

/// Errors that can occur during event ID processing
#[derive(Debug)]
pub enum EventIdError {
    /// The event ID string is not in the canonical format
    InvalidFormat(String),
}

impl fmt::Display for EventIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat(msg) => write!(f, "Invalid event ID format: {}", msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize_valid_event_ids() {
        let valid_ids = [
            "miden/stdlib::EVENT_NAME",
            "namespace/library::EXAMPLE_EVENT",
            "my.namespace/my-library::MY_EVENT_123",
            "a/b::C",
        ];

        for id in valid_ids.iter() {
            assert_eq!(canonicalize_event_id(id).unwrap(), *id);
        }
    }

    #[test]
    fn test_canonicalize_invalid_event_ids() {
        let invalid_ids = [
            // Missing ::
            "miden/stdlib/EVENT_NAME",
            // Empty namespace
            "::EVENT_NAME",
            // Empty event name
            "miden/stdlib::",
            // Lowercase event name
            "miden/stdlib::event_name",
            // Uppercase namespace
            "MIDEN/stdlib::EVENT_NAME",
            // Invalid characters in namespace
            "miden@stdlib::EVENT_NAME",
            // Invalid characters in event name
            "miden/stdlib::EVENT-NAME",
            // Non-ASCII characters
            "miden/stdlib::EVENT_NÅME",
        ];

        for id in invalid_ids.iter() {
            assert!(canonicalize_event_id(id).is_err());
        }
    }

    #[test]
    fn test_felt_event_id() {
        // Test that the same canonical string always produces the same Felt
        let id1 = felt_event_id("miden/stdlib::EVENT_NAME");
        let id2 = felt_event_id("miden/stdlib::EVENT_NAME");
        assert_eq!(id1, id2);

        // Test that different strings produce different Felts
        let id1 = felt_event_id("miden/stdlib::EVENT_ONE");
        let id2 = felt_event_id("miden/stdlib::EVENT_TWO");
        assert_ne!(id1, id2);

        // Test that similar strings produce different Felts
        let id1 = felt_event_id("miden/stdlib::EVENT_NAME");
        let id2 = felt_event_id("miden/stdlib::EVENT_NAME_");
        assert_ne!(id1, id2);
    }
}