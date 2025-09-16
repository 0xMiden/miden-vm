use core::fmt;

// SYSTEM EVENTS
// ================================================================================================
use crate::EventId;

/// Defines a set of actions which can be initiated from the VM to inject new data into the advice
/// provider.
///
/// These actions can affect all 3 components of the advice provider: Merkle store, advice stack,
/// and advice map.
///
/// All actions, except for `MerkleNodeMerge`, `Ext2Inv` and `UpdateMerkleNode` can be invoked
/// directly from Miden assembly via dedicated instructions.
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

/// Last variant of the `SystemEvent` enum, used to derive the number of cases.
const LAST_EVENT: SystemEvent = SystemEvent::HpermToMap;

impl TryFrom<EventId> for SystemEvent {
    type Error = u64;

    fn try_from(event_id: EventId) -> Result<Self, Self::Error> {
        let event_id = event_id.as_felt().as_int();

        // This dummy match statement ensures a compile-time error is raised when this function
        // has not been updated after adding a new SystemEvent variant.
        // Make sure the match statement below is also updated, as well as `LAST_EVENT` above.
        match LAST_EVENT {
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
        };

        match event_id {
            0 => Ok(SystemEvent::MerkleNodeMerge),
            1 => Ok(SystemEvent::MerkleNodeToStack),
            2 => Ok(SystemEvent::MapValueToStack),
            3 => Ok(SystemEvent::MapValueToStackN),
            4 => Ok(SystemEvent::HasMapKey),
            5 => Ok(SystemEvent::Ext2Inv),
            6 => Ok(SystemEvent::U32Clz),
            7 => Ok(SystemEvent::U32Ctz),
            8 => Ok(SystemEvent::U32Clo),
            9 => Ok(SystemEvent::U32Cto),
            10 => Ok(SystemEvent::ILog2),
            11 => Ok(SystemEvent::MemToMap),
            12 => Ok(SystemEvent::HdwordToMap),
            13 => Ok(SystemEvent::HdwordToMapWithDomain),
            14 => Ok(SystemEvent::HqwordToMap),
            15 => Ok(SystemEvent::HpermToMap),
            other => Err(other),
        }
    }
}

impl From<SystemEvent> for EventId {
    fn from(system_event: SystemEvent) -> Self {
        Self::from_u64(system_event as u64)
    }
}

impl crate::prettier::PrettyPrint for SystemEvent {
    fn render(&self) -> crate::prettier::Document {
        crate::prettier::display(self)
    }
}

impl fmt::Display for SystemEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MerkleNodeMerge => write!(f, "merkle_node_merge"),
            Self::MerkleNodeToStack => write!(f, "merkle_node_to_stack"),
            Self::MapValueToStack => write!(f, "map_value_to_stack"),
            Self::MapValueToStackN => write!(f, "map_value_to_stack_with_len"),
            Self::HasMapKey => write!(f, "has_key_in_map"),
            Self::Ext2Inv => write!(f, "ext2_inv"),
            Self::U32Clz => write!(f, "u32clz"),
            Self::U32Ctz => write!(f, "u32ctz"),
            Self::U32Clo => write!(f, "u32clo"),
            Self::U32Cto => write!(f, "u32cto"),
            Self::ILog2 => write!(f, "ilog2"),
            Self::MemToMap => write!(f, "mem_to_map"),
            Self::HdwordToMap => write!(f, "hdword_to_map"),
            Self::HdwordToMapWithDomain => write!(f, "hdword_to_map_with_domain"),
            Self::HqwordToMap => write!(f, "hqword_to_map"),
            Self::HpermToMap => write!(f, "hperm_to_map"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_try_from() {
        let last_event_id = LAST_EVENT as u8;

        // Check that the event IDs are contiguous
        for id in 0..=last_event_id {
            let event_id = EventId::from_u64(id as u64);
            assert!(event_id.is_reserved());
            let event = SystemEvent::try_from(event_id).unwrap();
            assert_eq!(id, event as u8)
        }

        // Creating from an the next index results in an error.
        let invalid_event_id = EventId::from_u64((last_event_id + 1) as u64);
        SystemEvent::try_from(invalid_event_id).unwrap_err();
    }
}
