use miden_ace_codegen::EXT_DEGREE;
#[cfg(feature = "compiler")]
use p3_security::budget::{AirShape, LookupShape};

#[cfg(feature = "compiler")]
use crate::{AIRS, logup::MIDEN_MAX_MESSAGE_WIDTH};

/// Number of out-of-domain points opened per committed column.
///
/// The AIRs use `local` and `next` rotations only.
pub const NUM_OOD_POINTS: u32 = 2;

/// Derive the security shape for tooling and differential validation.
#[cfg(feature = "compiler")]
pub fn derive_air_shape() -> AirShape {
    crate::shared::geometry::derive_air_shape(
        &AIRS,
        LookupShape {
            fractions_per_row: AIRS
                .iter()
                .map(|air| air.column_shape().iter().sum::<usize>())
                .sum::<usize>() as u32,
            max_message_width: MIDEN_MAX_MESSAGE_WIDTH as u32,
        },
        crate::shared::config::SPONGE_RATE,
    )
}

/// Number of DEEP terms for raw committed widths emitted by the relation compiler.
/// Widths are base-field coordinates; each matrix is padded independently.
pub fn num_deep_terms_for_widths(
    raw_widths: &[(usize, usize, usize)],
    chunks: usize,
    alignment: usize,
) -> u32 {
    let columns: usize = raw_widths
        .iter()
        .map(|&(preprocessed, main, aux)| {
            preprocessed.next_multiple_of(alignment)
                + main.next_multiple_of(alignment)
                + aux.next_multiple_of(alignment)
        })
        .sum();
    (columns + (chunks * EXT_DEGREE).next_multiple_of(alignment)) as u32 + NUM_OOD_POINTS
}
