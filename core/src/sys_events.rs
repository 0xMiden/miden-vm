use core::fmt;

// SYSTEM EVENTS
// ================================================================================================

// Randomly generated constant values for the VM's system events. All values were sampled
// between 0 and 2^32.
pub use constants::*;

use crate::EventId;

#[rustfmt::skip]
mod constants {
    pub const EVENT_MERKLE_NODE_MERGE: u32            = 276124218;
    pub const EVENT_MERKLE_NODE_TO_STACK: u32         = 361943238;
    pub const EVENT_MAP_VALUE_TO_STACK: u32           = 574478993;
    pub const EVENT_MAP_VALUE_TO_STACK_N: u32         = 630847990;
    pub const EVENT_HAS_MAP_KEY: u32                  = 652777600;
    pub const EVENT_EXT2_INV: u32                     = 1251967401;
    pub const EVENT_U32_CLZ: u32                      = 1951932030;
    pub const EVENT_U32_CTZ: u32                      = 2008979519;
    pub const EVENT_U32_CLO: u32                      = 2032895094;
    pub const EVENT_U32_CTO: u32                      = 2083700134;
    pub const EVENT_ILOG2: u32                        = 2297972669;
    pub const EVENT_MEM_TO_MAP: u32                   = 2389394361;
    pub const EVENT_HDWORD_TO_MAP: u32                = 2391452729;
    pub const EVENT_HDWORD_TO_MAP_WITH_DOMAIN: u32    = 2822590340;
    pub const EVENT_HQWORD_TO_MAP: u32                = 2913039991;
    pub const EVENT_HPERM_TO_MAP: u32                 = 3297060969;
}

/// Defines a set of actions which can be initiated from the VM to inject new data into the advice
/// provider.
///
/// These actions can affect all 3 components of the advice provider: Merkle store, advice stack,
/// and advice map.
///
/// All actions, except for `MerkleNodeMerge`, `Ext2Inv` and `UpdateMerkleNode` can be invoked
/// directly from Miden assembly via dedicated instructions.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
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
    pub fn into_event_id(self) -> u32 {
        match self {
            SystemEvent::MerkleNodeMerge => EVENT_MERKLE_NODE_MERGE,
            SystemEvent::MerkleNodeToStack => EVENT_MERKLE_NODE_TO_STACK,
            SystemEvent::MapValueToStack => EVENT_MAP_VALUE_TO_STACK,
            SystemEvent::MapValueToStackN => EVENT_MAP_VALUE_TO_STACK_N,
            SystemEvent::HasMapKey => EVENT_HAS_MAP_KEY,
            SystemEvent::Ext2Inv => EVENT_EXT2_INV,
            SystemEvent::U32Clz => EVENT_U32_CLZ,
            SystemEvent::U32Ctz => EVENT_U32_CTZ,
            SystemEvent::U32Clo => EVENT_U32_CLO,
            SystemEvent::U32Cto => EVENT_U32_CTO,
            SystemEvent::ILog2 => EVENT_ILOG2,
            SystemEvent::MemToMap => EVENT_MEM_TO_MAP,
            SystemEvent::HdwordToMap => EVENT_HDWORD_TO_MAP,
            SystemEvent::HdwordToMapWithDomain => EVENT_HDWORD_TO_MAP_WITH_DOMAIN,
            SystemEvent::HqwordToMap => EVENT_HQWORD_TO_MAP,
            SystemEvent::HpermToMap => EVENT_HPERM_TO_MAP,
        }
    }

    /// Returns a system event corresponding to the specified event ID, or `None` if the event
    /// ID is not recognized.
    pub fn from_event_id(event_id: EventId) -> Option<Self> {
        let event_id: u32 = event_id.as_felt().as_int().try_into().ok()?;
        match event_id {
            EVENT_MERKLE_NODE_MERGE => Some(SystemEvent::MerkleNodeMerge),
            EVENT_MERKLE_NODE_TO_STACK => Some(SystemEvent::MerkleNodeToStack),
            EVENT_MAP_VALUE_TO_STACK => Some(SystemEvent::MapValueToStack),
            EVENT_MAP_VALUE_TO_STACK_N => Some(SystemEvent::MapValueToStackN),
            EVENT_HAS_MAP_KEY => Some(SystemEvent::HasMapKey),
            EVENT_EXT2_INV => Some(SystemEvent::Ext2Inv),
            EVENT_U32_CLZ => Some(SystemEvent::U32Clz),
            EVENT_U32_CTZ => Some(SystemEvent::U32Ctz),
            EVENT_U32_CLO => Some(SystemEvent::U32Clo),
            EVENT_U32_CTO => Some(SystemEvent::U32Cto),
            EVENT_ILOG2 => Some(SystemEvent::ILog2),
            EVENT_MEM_TO_MAP => Some(SystemEvent::MemToMap),
            EVENT_HDWORD_TO_MAP => Some(SystemEvent::HdwordToMap),
            EVENT_HDWORD_TO_MAP_WITH_DOMAIN => Some(SystemEvent::HdwordToMapWithDomain),
            EVENT_HQWORD_TO_MAP => Some(SystemEvent::HqwordToMap),
            EVENT_HPERM_TO_MAP => Some(SystemEvent::HpermToMap),
            _ => None,
        }
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
