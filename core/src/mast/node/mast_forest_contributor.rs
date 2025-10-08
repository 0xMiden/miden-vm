use crate::mast::{MastForest, MastForestError, MastNodeId};

#[allow(dead_code)]
pub trait MastForestContributor {
    fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError>;
}
