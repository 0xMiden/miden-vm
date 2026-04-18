use alloc::vec::Vec;

use super::{super::Word, forest::Forest};

/// Container for the update data of a [super::PartialMmr]
#[derive(Debug)]
pub struct MmrDelta {
    /// The new version of the [super::Mmr]
    pub forest: Forest,

    /// Update data.
    ///
    /// The data is packed as follows:
    /// 1. All the elements needed to perform authentication path updates. These are the right
    ///    siblings required to perform tree merges on the [super::PartialMmr].
    /// 2. The new peaks.
    pub data: Vec<Word>,
}
