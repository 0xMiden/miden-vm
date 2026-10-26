//! Relation-specific input layout construction.

use crate::{InputCounts, InputLayout};

impl InputLayout {
    pub(crate) fn for_relation(
        counts: InputCounts,
        num_airs: usize,
        quotient_width: usize,
        masm: bool,
    ) -> Self {
        Self::build_multi_air(counts, num_airs, Some(quotient_width), masm)
    }
}
