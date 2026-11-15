use miden_core::{Felt, field::QuadFelt};
use miden_stark::security::{AirShape, LookupShape};
use miden_stark::{
    air::native::DescriptorError,
    lookup::{ProverLookupBuilder, native::LookupAir},
};

use crate::precompiles::{ChipletAir, relations::MAX_MESSAGE_WIDTH};

/// Derive the member's checked security shape from its authored relation.
pub fn derive_air_shape() -> Result<AirShape, DescriptorError> {
    crate::shared::geometry::derive_air_shape(
        &ChipletAir::all(),
        lookup_shape(),
        crate::precompiles::ace::LMCS_ALIGNMENT,
    )
}

pub(crate) fn lookup_shape() -> LookupShape {
    type ShapeBuilder<'a> = ProverLookupBuilder<'a, Felt, QuadFelt>;
    LookupShape {
        fractions_per_row: ChipletAir::all()
            .iter()
            .map(|air| {
                <ChipletAir as LookupAir<ShapeBuilder<'_>>>::column_shape(air)
                    .iter()
                    .sum::<usize>()
            })
            .sum::<usize>() as u32,
        max_message_width: MAX_MESSAGE_WIDTH as u32,
    }
}
