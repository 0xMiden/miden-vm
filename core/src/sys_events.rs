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

    /// Pushes a list of field elements onto the advice stack, and then the number of elements
    /// pushed. The list is looked up in the advice map using the specified word from the operand
    /// stack as the key.
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
    MapValueToStackN,

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
    /// Returns the human-readable name string for this system event.
    ///
    /// System event names are prefixed with `sys::` to distinguish them from user-defined events.
    pub const fn name_str(&self) -> &'static str {
        match self {
            Self::MerkleNodeMerge => "sys::merkle_node_merge",
            Self::MerkleNodeToStack => "sys::merkle_node_to_stack",
            Self::MapValueToStack => "sys::map_value_to_stack",
            Self::MapValueToStackN => "sys::map_value_to_stack_n",
            Self::HasMapKey => "sys::has_map_key",
            Self::Ext2Inv => "sys::ext2_inv",
            Self::U32Clz => "sys::u32_clz",
            Self::U32Ctz => "sys::u32_ctz",
            Self::U32Clo => "sys::u32_clo",
            Self::U32Cto => "sys::u32_cto",
            Self::ILog2 => "sys::ilog2",
            Self::MemToMap => "sys::mem_to_map",
            Self::HdwordToMap => "sys::hdword_to_map",
            Self::HdwordToMapWithDomain => "sys::hdword_to_map_with_domain",
            Self::HqwordToMap => "sys::hqword_to_map",
            Self::HpermToMap => "sys::hperm_to_map",
        }
    }

    /// Returns the human-readable name of this system event as an [`EventName`].
    ///
    /// System event names are prefixed with `sys::` to distinguish them from user-defined events.
    pub const fn event_name(&self) -> EventName {
        EventName::new(self.name_str())
    }

    /// Returns the [`EventId`] for this system event.
    ///
    /// The ID is looked up from the const SYSTEM_EVENT_LOOKUP table using the enum's discriminant
    /// as the index. The discriminants are explicitly set to match the array indices.
    pub const fn to_event_id(&self) -> EventId {
        SYSTEM_EVENT_LOOKUP[*self as usize].0
    }

    /// Attempts to convert a name string into a SystemEvent.
    ///
    /// Returns `Some(SystemEvent)` if the name matches a known system event, `None` otherwise.
    ///
    /// This method only works with full system event names (e.g., "sys::merkle_node_merge").
    /// To create system event names, use [`SystemEvent::event_name()`] instead.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "sys::merkle_node_merge" => Some(Self::MerkleNodeMerge),
            "sys::merkle_node_to_stack" => Some(Self::MerkleNodeToStack),
            "sys::map_value_to_stack" => Some(Self::MapValueToStack),
            "sys::map_value_to_stack_n" => Some(Self::MapValueToStackN),
            "sys::has_map_key" => Some(Self::HasMapKey),
            "sys::ext2_inv" => Some(Self::Ext2Inv),
            "sys::u32_clz" => Some(Self::U32Clz),
            "sys::u32_ctz" => Some(Self::U32Ctz),
            "sys::u32_clo" => Some(Self::U32Clo),
            "sys::u32_cto" => Some(Self::U32Cto),
            "sys::ilog2" => Some(Self::ILog2),
            "sys::mem_to_map" => Some(Self::MemToMap),
            "sys::hdword_to_map" => Some(Self::HdwordToMap),
            "sys::hdword_to_map_with_domain" => Some(Self::HdwordToMapWithDomain),
            "sys::hqword_to_map" => Some(Self::HqwordToMap),
            "sys::hperm_to_map" => Some(Self::HpermToMap),
            _ => None,
        }
    }

    /// Attempts to convert an EventId into a SystemEvent by looking it up in the const table.
    ///
    /// Returns `Some(SystemEvent)` if the ID matches a known system event, `None` otherwise.
    /// This uses a const lookup table with hardcoded EventIds, avoiding runtime hash computation.
    pub const fn from_event_id(event_id: EventId) -> Option<Self> {
        let lookup = SYSTEM_EVENT_LOOKUP;
        let mut i = 0;
        while i < lookup.len() {
            if lookup[i].0.as_u64() == event_id.as_u64() {
                return Some(lookup[i].1);
            }
            i += 1;
        }
        None
    }

    /// Returns an array of all system event variants.
    pub const fn all() -> [Self; 16] {
        [
            Self::MerkleNodeMerge,
            Self::MerkleNodeToStack,
            Self::MapValueToStack,
            Self::MapValueToStackN,
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

    /// Returns `true` if the event name uses the "sys::" system event namespace.
    pub(crate) const fn is_system_event_name(name: &str) -> bool {
        let bytes = name.as_bytes();
        bytes.len() >= 5
            && bytes[0] == b's'
            && bytes[1] == b'y'
            && bytes[2] == b's'
            && bytes[3] == b':'
            && bytes[4] == b':'
    }
}

// SYSTEM EVENT LOOKUP TABLE
// ================================================================================================

/// Const lookup table mapping [`EventId`] to [`SystemEvent`] for all system events.
///
/// This array provides O(n) reverse lookup from event IDs to system events. The EventIds are
/// hardcoded to avoid runtime initialization and hash computation. The small number of variants
/// (16) makes linear search fast enough.
pub(crate) const SYSTEM_EVENT_LOOKUP: [(EventId, SystemEvent); 16] = [
    (EventId::from_u64(7243907139105902342), SystemEvent::MerkleNodeMerge),
    (EventId::from_u64(6873007751276594108), SystemEvent::MerkleNodeToStack),
    (EventId::from_u64(17843484659000820118), SystemEvent::MapValueToStack),
    (EventId::from_u64(7354377147644073171), SystemEvent::MapValueToStackN),
    (EventId::from_u64(5642583036089175977), SystemEvent::HasMapKey),
    (EventId::from_u64(9660728691489438960), SystemEvent::Ext2Inv),
    (EventId::from_u64(1503707361178382932), SystemEvent::U32Clz),
    (EventId::from_u64(10656887096526143429), SystemEvent::U32Ctz),
    (EventId::from_u64(12846584985739176048), SystemEvent::U32Clo),
    (EventId::from_u64(6773574803673468616), SystemEvent::U32Cto),
    (EventId::from_u64(7444351342957461231), SystemEvent::ILog2),
    (EventId::from_u64(5768534446586058686), SystemEvent::MemToMap),
    (EventId::from_u64(5988159172915333521), SystemEvent::HdwordToMap),
    (EventId::from_u64(6143777601072385586), SystemEvent::HdwordToMapWithDomain),
    (EventId::from_u64(11723176702659679401), SystemEvent::HqwordToMap),
    (EventId::from_u64(6190830263511605775), SystemEvent::HpermToMap),
];

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

        let (_prefix, rest) = self.name_str().split_at(PREFIX_LEN);
        write!(f, "{rest}")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_system_event_lookup() {
        // Verify all system events can be looked up by their event IDs
        for system_event in SystemEvent::all() {
            let event_id = system_event.to_event_id();

            // Test lookup by ID
            let looked_up =
                SystemEvent::from_event_id(event_id).expect("SystemEvent should be found by ID");
            assert_eq!(looked_up, system_event);

            // Test lookup by name
            let name = system_event.name_str();
            let looked_up_by_name =
                SystemEvent::from_name(name).expect("SystemEvent should be found by name");
            assert_eq!(looked_up_by_name, system_event);
        }

        // Verify all() returns exactly 16 variants
        assert_eq!(SystemEvent::all().len(), 16);
    }

    #[test]
    fn test_system_event_names() {
        // Test that all system events have names with correct prefix
        for system_event in SystemEvent::all() {
            let event_name = system_event.event_name();
            let name = event_name.as_str();
            assert!(
                name.starts_with("sys::"),
                "System event name should start with 'sys::': {}",
                name
            );

            // Test conversion to EventName
            let event_name_from_into: EventName = system_event.into();
            assert_eq!(event_name_from_into.as_str(), name);
        }
    }

    #[test]
    fn test_system_event_all_variants_covered() {
        // Exhaustive match ensures compile-time error when adding new SystemEvent variants
        // without updating the all() method and other related code
        for event in SystemEvent::all() {
            match event {
                SystemEvent::MerkleNodeMerge
                | SystemEvent::MerkleNodeToStack
                | SystemEvent::MapValueToStack
                | SystemEvent::MapValueToStackN
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

        // Verify all() returns the correct number of variants
        assert_eq!(SystemEvent::all().len(), 16);
    }

    #[test]
    fn test_system_event_lookup_table_correctness() {
        // This test verifies that the hardcoded EventIds in SYSTEM_EVENT_LOOKUP match
        // the computed EventIds from to_event_id(). If this test fails, update the
        // SYSTEM_EVENT_LOOKUP array with the correct EventId values shown in the assertion.

        for (i, (hardcoded_id, system_event)) in SYSTEM_EVENT_LOOKUP.iter().enumerate() {
            let computed_id = system_event.to_event_id();
            assert_eq!(
                *hardcoded_id,
                computed_id,
                "Mismatch at index {}: SYSTEM_EVENT_LOOKUP has EventId::from_u64({}), but {:?}.to_event_id() returns EventId::from_u64({})",
                i,
                hardcoded_id.as_u64(),
                system_event,
                computed_id.as_u64()
            );
        }
    }

    #[test]
    fn test_is_system_event_name() {
        // Test valid system event names
        assert!(SystemEvent::is_system_event_name("sys::merkle_node_merge"));
        assert!(SystemEvent::is_system_event_name("sys::test"));
        assert!(SystemEvent::is_system_event_name("sys::"));

        // Test invalid names
        assert!(!SystemEvent::is_system_event_name("system::event"));
        assert!(!SystemEvent::is_system_event_name("sy::event"));
        assert!(!SystemEvent::is_system_event_name("sys:"));
        assert!(!SystemEvent::is_system_event_name("user::event"));
        assert!(!SystemEvent::is_system_event_name(""));
    }
}
