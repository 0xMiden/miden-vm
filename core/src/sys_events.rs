use core::fmt;

use crate::{EventId, EventName};

// SYSTEM EVENTS
// ================================================================================================

/// Defines a set of actions which can be initiated from the VM to inject new data into the advice
/// provider.
///
/// These actions can affect all 3 components of the advice provider: Merkle store, advice stack,
/// and advice map.
///
/// All actions, except for `MerkleNodeMerge`, `Ext2Inv` and `UpdateMerkleNode` can be invoked
/// directly from Miden assembly via dedicated instructions.
///
/// System event IDs are derived from blake3-hashing their names (prefixed with "sys::").
///
/// The enum variant order matches the indices in SYSTEM_EVENT_LOOKUP, allowing efficient const
/// lookup via `to_event_id()`. The discriminants are implicitly 0, 1, 2, ... 15.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SystemEvent {
    // MERKLE STORE EVENTS
    // --------------------------------------------------------------------------------------------
    /// Creates a new Merkle tree in the advice provider by combining Merkle trees with the
    /// specified roots. The root of the new tree is defined as `Hash(LEFT_ROOT, RIGHT_ROOT)`.
    ///
    /// Inputs:
    ///   Operand stack: [RIGHT_ROOT, LEFT_ROOT, ...]
    ///   Merkle store: {RIGHT_ROOT, LEFT_ROOT}
    ///
    /// Outputs:
    ///   Operand stack: [RIGHT_ROOT, LEFT_ROOT, ...]
    ///   Merkle store: {RIGHT_ROOT, LEFT_ROOT, hash(LEFT_ROOT, RIGHT_ROOT)}
    ///
    /// After the operation, both the original trees and the new tree remains in the advice
    /// provider (i.e., the input trees are not removed).
    MerkleNodeMerge,

    // ADVICE STACK SYSTEM EVENTS
    // --------------------------------------------------------------------------------------------
    /// Pushes a node of the Merkle tree specified by the values on the top of the operand stack
    /// onto the advice stack.
    ///
    /// Inputs:
    ///   Operand stack: [depth, index, TREE_ROOT, ...]
    ///   Advice stack: [...]
    ///   Merkle store: {TREE_ROOT<-NODE}
    ///
    /// Outputs:
    ///   Operand stack: [depth, index, TREE_ROOT, ...]
    ///   Advice stack: [NODE, ...]
    ///   Merkle store: {TREE_ROOT<-NODE}
    MerkleNodeToStack,

    /// Pushes a list of field elements onto the advice stack. The list is looked up in the advice
    /// map using the specified word from the operand stack as the key.
    ///
    /// Inputs:
    ///   Operand stack: [KEY, ...]
    ///   Advice stack: [...]
    ///   Advice map: {KEY: values}
    ///
    /// Outputs:
    ///   Operand stack: [KEY, ...]
    ///   Advice stack: [values, ...]
    ///   Advice map: {KEY: values}
    MapValueToStack,

    /// Pushes the number of elements in a list of field elements onto the advice stack. The list is
    /// looked up in the advice map using the specified word from the operand stack as the key.
    ///
    /// Inputs:
    ///   Operand stack: [KEY, ...]
    ///   Advice stack: [...]
    ///   Advice map: {KEY: values}
    ///
    /// Outputs:
    ///   Operand stack: [KEY, ...]
    ///   Advice stack: [values.len(), ...]
    ///   Advice map: {KEY: values}
    MapValueCountToStack,

    /// Pushes a list of field elements onto the advice stack, along with the number of elements in
    /// that list. The list is looked up in the advice map using the word at the top of the operand
    /// stack as the key.
    ///
    /// Notice that the resulting elements list is not padded.
    ///
    /// Inputs:
    ///   Operand stack: [KEY, ...]
    ///   Advice stack: [...]
    ///   Advice map: {KEY: values}
    ///
    /// Outputs:
    ///   Operand stack: [KEY, ...]
    ///   Advice stack: [num_values, values, ...]
    ///   Advice map: {KEY: values}
    MapValueToStackN0,

    /// Pushes a padded list of field elements onto the advice stack, along with the number of
    /// elements in that list. The list is looked up in the advice map using the word at the top of
    /// the operand stack as the key.
    ///
    /// Notice that the elements list obtained from the advice map will be padded with zeros,
    /// increasing its length to the next multiple of 4.
    ///
    /// Inputs:
    ///   Operand stack: [KEY, ...]
    ///   Advice stack: [...]
    ///   Advice map: {KEY: values}
    ///
    /// Outputs:
    ///   Operand stack: [KEY, ...]
    ///   Advice stack: [num_values, values, padding, ...]
    ///   Advice map: {KEY: values}
    MapValueToStackN4,

    /// Pushes a padded list of field elements onto the advice stack, along with the number of
    /// elements in that list. The list is looked up in the advice map using the word at the top of
    /// the operand stack as the key.
    ///
    /// Notice that the elements list obtained from the advice map will be padded with zeros,
    /// increasing its length to the next multiple of 8.
    ///
    /// Inputs:
    ///   Operand stack: [KEY, ...]
    ///   Advice stack: [...]
    ///   Advice map: {KEY: values}
    ///
    /// Outputs:
    ///   Operand stack: [KEY, ...]
    ///   Advice stack: [num_values, values, padding, ...]
    ///   Advice map: {KEY: values}
    MapValueToStackN8,

    /// Pushes a flag onto the advice stack whether advice map has an entry with specified key.
    ///
    /// If the advice map has the entry with the key equal to the key placed at the top of the
    /// operand stack, `1` will be pushed to the advice stack and `0` otherwise.
    ///
    /// Inputs:
    ///   Operand stack: [KEY, ...]
    ///   Advice stack:  [...]
    ///
    /// Outputs:
    ///   Operand stack: [KEY, ...]
    ///   Advice stack:  [has_mapkey, ...]
    HasMapKey,

    /// Given an element in a quadratic extension field on the top of the stack (i.e., a0, b1),
    /// computes its multiplicative inverse and push the result onto the advice stack.
    ///
    /// Inputs:
    ///   Operand stack: [a1, a0, ...]
    ///   Advice stack: [...]
    ///
    /// Outputs:
    ///   Operand stack: [a1, a0, ...]
    ///   Advice stack: [b0, b1...]
    ///
    /// Where (b0, b1) is the multiplicative inverse of the extension field element (a0, a1) at the
    /// top of the stack.
    Ext2Inv,

    /// Pushes the number of the leading zeros of the top stack element onto the advice stack.
    ///
    /// Inputs:
    ///   Operand stack: [n, ...]
    ///   Advice stack: [...]
    ///
    /// Outputs:
    ///   Operand stack: [n, ...]
    ///   Advice stack: [leading_zeros, ...]
    U32Clz,

    /// Pushes the number of the trailing zeros of the top stack element onto the advice stack.
    ///
    /// Inputs:
    ///   Operand stack: [n, ...]
    ///   Advice stack: [...]
    ///
    /// Outputs:
    ///   Operand stack: [n, ...]
    ///   Advice stack: [trailing_zeros, ...]
    U32Ctz,

    /// Pushes the number of the leading ones of the top stack element onto the advice stack.
    ///
    /// Inputs:
    ///   Operand stack: [n, ...]
    ///   Advice stack: [...]
    ///
    /// Outputs:
    ///   Operand stack: [n, ...]
    ///   Advice stack: [leading_ones, ...]
    U32Clo,

    /// Pushes the number of the trailing ones of the top stack element onto the advice stack.
    ///
    /// Inputs:
    ///   Operand stack: [n, ...]
    ///   Advice stack: [...]
    ///
    /// Outputs:
    ///   Operand stack: [n, ...]
    ///   Advice stack: [trailing_ones, ...]
    U32Cto,

    /// Pushes the base 2 logarithm of the top stack element, rounded down.
    /// Inputs:
    ///   Operand stack: [n, ...]
    ///   Advice stack: [...]
    ///
    /// Outputs:
    ///   Operand stack: [n, ...]
    ///   Advice stack: [ilog2(n), ...]
    ILog2,

    // ADVICE MAP SYSTEM EVENTS
    // --------------------------------------------------------------------------------------------
    /// Reads words from memory at the specified range and inserts them into the advice map under
    /// the key `KEY` located at the top of the stack.
    ///
    /// Inputs:
    ///   Operand stack: [KEY, start_addr, end_addr, ...]
    ///   Advice map: {...}
    ///
    /// Outputs:
    ///   Operand stack: [KEY, start_addr, end_addr, ...]
    ///   Advice map: {KEY: values}
    ///
    /// Where `values` are the elements located in memory[start_addr..end_addr].
    MemToMap,

    /// Reads two word from the operand stack and inserts them into the advice map under the key
    /// defined by the hash of these words.
    ///
    /// Inputs:
    ///   Operand stack: [B, A, ...]
    ///   Advice map: {...}
    ///
    /// Outputs:
    ///   Operand stack: [B, A, ...]
    ///   Advice map: {KEY: [a0, a1, a2, a3, b0, b1, b2, b3]}
    ///
    /// Where KEY is computed as hash(A || B, domain=0)
    HdwordToMap,

    /// Reads two words from the operand stack and inserts them into the advice map under the key
    /// defined by the hash of these words (using `d` as the domain).
    ///
    /// Inputs:
    ///   Operand stack: [B, A, d, ...]
    ///   Advice map: {...}
    ///
    /// Outputs:
    ///   Operand stack: [B, A, d, ...]
    ///   Advice map: {KEY: [a0, a1, a2, a3, b0, b1, b2, b3]}
    ///
    /// Where KEY is computed as hash(A || B, d).
    HdwordToMapWithDomain,

    /// Reads four words from the operand stack and inserts them into the advice map under the key
    /// defined by the hash of these words.
    ///
    /// Inputs:
    ///   Operand stack: [D, C, B, A, ...]
    ///   Advice map: {...}
    ///
    /// Outputs:
    ///   Operand stack: [D, C, B, A, ...]
    ///   Advice map: {KEY: [A', B', C', D'])}
    ///
    /// Where:
    /// - KEY is the hash computed as hash(hash(hash(A || B) || C) || D) with domain=0.
    /// - A' (and other words with `'`) is the A word with the reversed element order: A = [a3, a2,
    ///   a1, a0], A' = [a0, a1, a2, a3].
    HqwordToMap,

    /// Reads three words from the operand stack and inserts the top two words into the advice map
    /// under the key defined by applying an RPO permutation to all three words.
    ///
    /// Inputs:
    ///   Operand stack: [B, A, C, ...]
    ///   Advice map: {...}
    ///
    /// Outputs:
    ///   Operand stack: [B, A, C, ...]
    ///   Advice map: {KEY: [a0, a1, a2, a3, b0, b1, b2, b3]}
    ///
    /// Where KEY is computed by extracting the digest elements from hperm([C, A, B]). For example,
    /// if C is [0, d, 0, 0], KEY will be set as hash(A || B, d).
    HpermToMap,
}

impl SystemEvent {
    /// Attempts to convert an EventId into a SystemEvent by looking it up in the const table.
    ///
    /// Returns `Some(SystemEvent)` if the ID matches a known system event, `None` otherwise.
    /// This uses a const lookup table with hardcoded EventIds, avoiding runtime hash computation.
    pub const fn from_event_id(event_id: EventId) -> Option<Self> {
        let lookup = Self::LOOKUP;
        let mut i = 0;
        while i < lookup.len() {
            if lookup[i].id.as_u64() == event_id.as_u64() {
                return Some(lookup[i].event);
            }
            i += 1;
        }
        None
    }

    /// Attempts to convert a name into a SystemEvent by looking it up in the const table.
    ///
    /// Returns `Some(SystemEvent)` if the name matches a known system event, `None` otherwise.
    /// This uses const string comparison against the lookup table.
    pub const fn from_name(name: &str) -> Option<Self> {
        let lookup = Self::LOOKUP;
        let mut i = 0;
        while i < lookup.len() {
            if str_eq(name, lookup[i].name) {
                return Some(lookup[i].event);
            }
            i += 1;
        }
        None
    }

    /// Returns the human-readable name of this system event as an [`EventName`].
    ///
    /// System event names are prefixed with `sys::` to distinguish them from user-defined events.
    pub const fn event_name(&self) -> EventName {
        EventName::new(Self::LOOKUP[*self as usize].name)
    }

    /// Returns the [`EventId`] for this system event.
    ///
    /// The ID is looked up from the const LOOKUP table using the enum's discriminant
    /// as the index. The discriminants are explicitly set to match the array indices.
    pub const fn event_id(&self) -> EventId {
        Self::LOOKUP[*self as usize].id
    }

    /// Returns an array of all system event variants.
    pub const fn all() -> [Self; Self::COUNT] {
        [
            Self::MerkleNodeMerge,
            Self::MerkleNodeToStack,
            Self::MapValueToStack,
            Self::MapValueCountToStack,
            Self::MapValueToStackN0,
            Self::MapValueToStackN4,
            Self::MapValueToStackN8,
            Self::HasMapKey,
            Self::Ext2Inv,
            Self::U32Clz,
            Self::U32Ctz,
            Self::U32Clo,
            Self::U32Cto,
            Self::ILog2,
            Self::MemToMap,
            Self::HdwordToMap,
            Self::HdwordToMapWithDomain,
            Self::HqwordToMap,
            Self::HpermToMap,
        ]
    }
}

impl From<SystemEvent> for EventName {
    fn from(system_event: SystemEvent) -> Self {
        system_event.event_name()
    }
}

impl crate::prettier::PrettyPrint for SystemEvent {
    fn render(&self) -> crate::prettier::Document {
        crate::prettier::display(self)
    }
}

impl fmt::Display for SystemEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const PREFIX_LEN: usize = "sys::".len();

        let (_prefix, rest) = Self::LOOKUP[*self as usize].name.split_at(PREFIX_LEN);
        write!(f, "{rest}")
    }
}

// LOOKUP TABLE
// ================================================================================================

/// An entry in the system event lookup table, containing all metadata for a system event.
#[derive(Copy, Clone, Debug)]
pub(crate) struct SystemEventEntry {
    /// The unique event ID (hash of the name)
    pub id: EventId,
    /// The system event variant
    pub event: SystemEvent,
    /// The full event name string (e.g., "sys::merkle_node_merge")
    pub name: &'static str,
}

impl SystemEvent {
    /// The total number of system events.
    pub const COUNT: usize = 19;

    /// Lookup table mapping system events to their metadata.
    ///
    /// The enum variant order matches the indices in this table, allowing efficient const
    /// lookup via array indexing using discriminants.
    const LOOKUP: [SystemEventEntry; Self::COUNT] = [
        SystemEventEntry {
            id: EventId::from_u64(7243907139105902342),
            event: SystemEvent::MerkleNodeMerge,
            name: "sys::merkle_node_merge",
        },
        SystemEventEntry {
            id: EventId::from_u64(6873007751276594108),
            event: SystemEvent::MerkleNodeToStack,
            name: "sys::merkle_node_to_stack",
        },
        SystemEventEntry {
            id: EventId::from_u64(17843484659000820118),
            event: SystemEvent::MapValueToStack,
            name: "sys::map_value_to_stack",
        },
        SystemEventEntry {
            id: EventId::from_u64(3470274154276391308),
            event: SystemEvent::MapValueCountToStack,
            name: "sys::map_value_count_to_stack",
        },
        SystemEventEntry {
            id: EventId::from_u64(11775886982554463322),
            event: SystemEvent::MapValueToStackN0,
            name: "sys::map_value_to_stack_n_0",
        },
        SystemEventEntry {
            id: EventId::from_u64(3443305460233942990),
            event: SystemEvent::MapValueToStackN4,
            name: "sys::map_value_to_stack_n_4",
        },
        SystemEventEntry {
            id: EventId::from_u64(1741586542981559489),
            event: SystemEvent::MapValueToStackN8,
            name: "sys::map_value_to_stack_n_8",
        },
        SystemEventEntry {
            id: EventId::from_u64(5642583036089175977),
            event: SystemEvent::HasMapKey,
            name: "sys::has_map_key",
        },
        SystemEventEntry {
            id: EventId::from_u64(9660728691489438960),
            event: SystemEvent::Ext2Inv,
            name: "sys::ext2_inv",
        },
        SystemEventEntry {
            id: EventId::from_u64(1503707361178382932),
            event: SystemEvent::U32Clz,
            name: "sys::u32_clz",
        },
        SystemEventEntry {
            id: EventId::from_u64(10656887096526143429),
            event: SystemEvent::U32Ctz,
            name: "sys::u32_ctz",
        },
        SystemEventEntry {
            id: EventId::from_u64(12846584985739176048),
            event: SystemEvent::U32Clo,
            name: "sys::u32_clo",
        },
        SystemEventEntry {
            id: EventId::from_u64(6773574803673468616),
            event: SystemEvent::U32Cto,
            name: "sys::u32_cto",
        },
        SystemEventEntry {
            id: EventId::from_u64(7444351342957461231),
            event: SystemEvent::ILog2,
            name: "sys::ilog2",
        },
        SystemEventEntry {
            id: EventId::from_u64(5768534446586058686),
            event: SystemEvent::MemToMap,
            name: "sys::mem_to_map",
        },
        SystemEventEntry {
            id: EventId::from_u64(5988159172915333521),
            event: SystemEvent::HdwordToMap,
            name: "sys::hdword_to_map",
        },
        SystemEventEntry {
            id: EventId::from_u64(6143777601072385586),
            event: SystemEvent::HdwordToMapWithDomain,
            name: "sys::hdword_to_map_with_domain",
        },
        SystemEventEntry {
            id: EventId::from_u64(11723176702659679401),
            event: SystemEvent::HqwordToMap,
            name: "sys::hqword_to_map",
        },
        SystemEventEntry {
            id: EventId::from_u64(6190830263511605775),
            event: SystemEvent::HpermToMap,
            name: "sys::hperm_to_map",
        },
    ];
}

// HELPERS
// ================================================================================================

/// Const-compatible string equality check.
const fn str_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    if a_bytes.len() != b_bytes.len() {
        return false;
    }

    let mut i = 0;
    while i < a_bytes.len() {
        if a_bytes[i] != b_bytes[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_system_events() {
        // Comprehensive test verifying consistency between SystemEvent::all() and
        // SystemEvent::LOOKUP. This ensures all() and LOOKUP are in sync, lookup table has
        // correct IDs/names, and all variants are covered.

        // Verify lengths match COUNT
        assert_eq!(SystemEvent::all().len(), SystemEvent::COUNT);
        assert_eq!(SystemEvent::LOOKUP.len(), SystemEvent::COUNT);

        // Iterate through both all() and LOOKUP together, checking all invariants
        for (i, (event, entry)) in
            SystemEvent::all().iter().zip(SystemEvent::LOOKUP.iter()).enumerate()
        {
            // Verify LOOKUP entry matches the event at the same index
            assert_eq!(
                entry.event, *event,
                "LOOKUP[{}].event ({:?}) doesn't match all()[{}] ({:?})",
                i, entry.event, i, event
            );

            // Verify LOOKUP entry ID matches the computed ID
            let computed_id = event.event_id();
            assert_eq!(
                entry.id,
                computed_id,
                "LOOKUP[{}].id is EventId::from_u64({}), but {:?}.to_event_id() returns EventId::from_u64({})",
                i,
                entry.id.as_u64(),
                event,
                computed_id.as_u64()
            );

            // Verify name has correct "sys::" prefix
            assert!(
                entry.name.starts_with("sys::"),
                "SystemEvent name should start with 'sys::': {}",
                entry.name
            );

            // Verify from_event_id lookup works
            let looked_up =
                SystemEvent::from_event_id(entry.id).expect("SystemEvent should be found by ID");
            assert_eq!(looked_up, *event);

            // Verify from_name lookup works
            let looked_up_by_name =
                SystemEvent::from_name(entry.name).expect("SystemEvent should be found by name");
            assert_eq!(looked_up_by_name, *event);

            // Verify EventName conversion works
            let event_name = event.event_name();
            assert_eq!(event_name.as_str(), entry.name);
            assert!(SystemEvent::from_name(event_name.as_str()).is_some());
            let event_name_from_into: EventName = (*event).into();
            assert_eq!(event_name_from_into.as_str(), entry.name);
            assert!(SystemEvent::from_name(event_name_from_into.as_str()).is_some());

            // Exhaustive match to ensure compile-time error when adding new variants
            match event {
                SystemEvent::MerkleNodeMerge
                | SystemEvent::MerkleNodeToStack
                | SystemEvent::MapValueToStack
                | SystemEvent::MapValueCountToStack
                | SystemEvent::MapValueToStackN0
                | SystemEvent::MapValueToStackN4
                | SystemEvent::MapValueToStackN8
                | SystemEvent::HasMapKey
                | SystemEvent::Ext2Inv
                | SystemEvent::U32Clz
                | SystemEvent::U32Ctz
                | SystemEvent::U32Clo
                | SystemEvent::U32Cto
                | SystemEvent::ILog2
                | SystemEvent::MemToMap
                | SystemEvent::HdwordToMap
                | SystemEvent::HdwordToMapWithDomain
                | SystemEvent::HqwordToMap
                | SystemEvent::HpermToMap => {},
            }
        }
    }
}
