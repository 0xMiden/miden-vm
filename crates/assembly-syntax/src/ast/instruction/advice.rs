use core::fmt;

use miden_core::sys_events::SystemEvent;

// SYSTEM EVENT NODE
// ================================================================================================

/// Instructions which inject data into the advice provider.
///
/// These instructions can be used to perform two broad sets of operations:
/// - Push new data onto the advice stack.
/// - Insert new data into the advice map.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SystemEventNode {
    PushMapVal,
    PushMapValCount,
    PushMapValN0,
    PushMapValN4,
    PushMapValN8,
    HasMapKey,
    PushMtNode,
    InsertMem,
    InsertHdword,
    InsertHdwordWithDomain,
    InsertHqword,
    InsertHperm,
}

impl From<&SystemEventNode> for SystemEvent {
    fn from(value: &SystemEventNode) -> Self {
        use SystemEventNode::*;
        match value {
            PushMapVal => Self::MapValueToStack,
            PushMapValCount => Self::MapValueCountToStack,
            PushMapValN0 => Self::MapValueToStackN0,
            PushMapValN4 => Self::MapValueToStackN4,
            PushMapValN8 => Self::MapValueToStackN8,
            HasMapKey => Self::HasMapKey,
            PushMtNode => Self::MerkleNodeToStack,
            InsertMem => Self::MemToMap,
            InsertHdword => Self::HdwordToMap,
            InsertHdwordWithDomain => Self::HdwordToMapWithDomain,
            InsertHqword => Self::HqwordToMap,
            InsertHperm => Self::HpermToMap,
        }
    }
}

impl crate::prettier::PrettyPrint for SystemEventNode {
    fn render(&self) -> crate::prettier::Document {
        crate::prettier::display(self)
    }
}

impl fmt::Display for SystemEventNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PushMapVal => write!(f, "push_mapval"),
            Self::PushMapValCount => write!(f, "push_mapval_count"),
            Self::PushMapValN0 => write!(f, "push_mapvaln.0"),
            Self::PushMapValN4 => write!(f, "push_mapvaln.4"),
            Self::PushMapValN8 => write!(f, "push_mapvaln.8"),
            Self::HasMapKey => write!(f, "has_mapkey"),
            Self::PushMtNode => write!(f, "push_mtnode"),
            Self::InsertMem => write!(f, "insert_mem"),
            Self::InsertHdword => write!(f, "insert_hdword"),
            Self::InsertHdwordWithDomain => write!(f, "insert_hdword_d"),
            Self::InsertHqword => write!(f, "insert_hqword"),
            Self::InsertHperm => writeln!(f, "insert_hperm"),
        }
    }
}
