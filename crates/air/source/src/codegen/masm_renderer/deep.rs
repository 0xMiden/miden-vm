//! Query-row presentation derived from the same canonical geometry as OOD.

use std::vec::Vec;

use super::{
    input::V1RenderInput,
    layout::{sum, u32_count},
};

#[derive(Clone, Debug)]
pub(crate) struct QueryGroup {
    pub width: u32,
    pub blocks: u32,
    pub cv: [u64; 4],
}

#[derive(Clone, Debug)]
pub(crate) struct DeepPlan {
    pub groups: [QueryGroup; 4],
}

impl DeepPlan {
    pub fn new(input: &V1RenderInput) -> Self {
        let widths = [
            sum(&input.geometry.preprocessed),
            sum(&input.geometry.main),
            sum(&input.geometry.aux_coordinates),
            input.geometry.quotient_coordinates,
        ];
        let groups: [QueryGroup; 4] = core::array::from_fn(|i| {
            let width = widths[i];
            assert!(
                width > 0 && width.is_multiple_of(8),
                "DEEP query groups must contain whole eight-felt blocks"
            );
            QueryGroup {
                width: u32_count(width, 1),
                blocks: u32_count(width / 8, 1),
                cv: input.query_leaf_initial_cvs[i],
            }
        });
        let mut unique_widths: Vec<QueryGroup> = Vec::new();
        for group in &groups {
            if let Some(existing) = unique_widths.iter().find(|g| g.width == group.width) {
                assert!(
                    existing.cv == group.cv,
                    "DEEP: equal query widths have contradictory chaining words"
                );
            } else {
                unique_widths.push(group.clone());
            }
        }
        Self { groups }
    }
}
