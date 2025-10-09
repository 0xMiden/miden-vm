use crate::mast::{MastForest, MastForestError, MastNodeId};

use super::{
    BasicBlockNodeBuilder, CallNodeBuilder, DynNodeBuilder, ExternalNodeBuilder, JoinNodeBuilder,
    LoopNodeBuilder, SplitNodeBuilder,
};
use enum_dispatch::enum_dispatch;

#[allow(dead_code)]
#[enum_dispatch]
pub trait MastForestContributor {
    fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError>;
}

/// Enum of all MAST node builders that can be added to a forest.
/// This allows for generic handling of different builder types through enum_dispatch.
#[enum_dispatch(MastForestContributor)]
pub enum MastNodeBuilder {
    BasicBlock(BasicBlockNodeBuilder),
    Call(CallNodeBuilder),
    Dyn(DynNodeBuilder),
    External(ExternalNodeBuilder),
    Join(JoinNodeBuilder),
    Loop(LoopNodeBuilder),
    Split(SplitNodeBuilder),
}
