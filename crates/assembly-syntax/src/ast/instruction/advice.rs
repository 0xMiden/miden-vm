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
    PushMapValN,
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
            PushMapValN => Self::MapValueToStackN,
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
            Self::PushMapValN => write!(f, "push_mapvaln"),
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
