use super::{EvaluationFrame, ExtensionOf, Felt, FieldElement};
use crate::{
    trace::{
        chiplets::{MEMORY_D0_COL_IDX, MEMORY_D1_COL_IDX},
        decoder::{DECODER_OP_BITS_OFFSET, DECODER_USER_OP_HELPERS_OFFSET},
    },
    utils::binary_not,
};

pub mod chiplets;
pub mod range;
pub mod stack;

// ACCESSORS
// ================================================================================================
/// Trait to allow other processors to easily access the column values they need for constraint
/// calculations.
pub trait MainFrameExt<F, E>
where
    F: FieldElement<BaseField = Felt>,
    E: FieldElement<BaseField = Felt> + ExtensionOf<F>,
{
    /// Returns true when a u32 stack operation that requires range checks is being performed.
    fn u32_rc_op(&self) -> F;

    // --- Range check lookup accessors -----------------------------------------------------------

    /// The value required for the first memory lookup when the memory chiplet requests range
    /// checks. The value returned is the denominator used for including the value into the LogUp
    /// lookup: (alpha + d0). The value d0 which is being range-checked is the lower 16-bits of the
    /// delta value being tracked between two consecutive context IDs, addresses, or clock cycles in
    /// the current row.
    fn lookup_mv0(&self, alpha: E) -> E;
    /// The value required for the second memory lookup when the memory chiplet requests range
    /// checks. The value returned is the denominator used for including the value into the LogUp
    /// lookup: (alpha + d1). The value d1 which is being range-checked is the upper 16-bits of the
    /// delta value being tracked between two consecutive context IDs, addresses, or clock cycles in
    /// the current row.
    fn lookup_mv1(&self, alpha: E) -> E;
    /// The value required for the first stack lookup when the stack requests range checks. The
    /// value returned is the denominator used for including the value into the LogUp lookup:
    /// (alpha + h0). The value h0 which is being range checked by the stack operation is stored in
    /// the helper columns of the decoder section of the trace.
    fn lookup_sv0(&self, alpha: E) -> E;
    /// The value required for the second stack lookup when the stack requests range checks. The
    /// value returned is the denominator used for including the value into the LogUp lookup:
    /// (alpha + h1). The value h1 which is being range checked by the stack operation is stored in
    /// the helper columns of the decoder section of the trace.
    fn lookup_sv1(&self, alpha: E) -> E;
    /// The value required for the third stack lookup when the stack requests range checks. The
    /// value returned is the denominator used for including the value into the LogUp lookup:
    /// (alpha + h2). The value h2 which is being range checked by the stack operation is stored in
    /// the helper columns of the decoder section of the trace.
    fn lookup_sv2(&self, alpha: E) -> E;
    /// The value required for the fourth stack lookup when the stack requests range checks. The
    /// value returned is the denominator used for including the value into the LogUp lookup:
    /// (alpha + h3). The value h3 which is being range checked by the stack operation is stored in
    /// the helper columns of the decoder section of the trace.
    fn lookup_sv3(&self, alpha: E) -> E;
}

impl<F, E> MainFrameExt<F, E> for EvaluationFrame<F>
where
    F: FieldElement<BaseField = Felt>,
    E: FieldElement<BaseField = Felt> + ExtensionOf<F>,
{
    /// Returns true when the stack operation is a u32 operation that requires range checks.
    /// TODO: this is also defined in the op flags. It's redefined here to avoid computing all of
    /// the op flags when this is the only one needed, but ideally this should only be defined once.
    #[inline(always)]
    fn u32_rc_op(&self) -> F {
        let not_4 = binary_not(self.current()[DECODER_OP_BITS_OFFSET + 4]);
        let not_5 = binary_not(self.current()[DECODER_OP_BITS_OFFSET + 5]);
        self.current()[DECODER_OP_BITS_OFFSET + 6].mul(not_5).mul(not_4)
    }

    // --- Intermediate values for LogUp lookups --------------------------------------------------

    #[inline(always)]
    fn lookup_mv0(&self, alpha: E) -> E {
        alpha + self.current()[MEMORY_D0_COL_IDX].into()
    }

    #[inline(always)]
    fn lookup_mv1(&self, alpha: E) -> E {
        alpha + self.current()[MEMORY_D1_COL_IDX].into()
    }

    #[inline(always)]
    fn lookup_sv0(&self, alpha: E) -> E {
        alpha + self.current()[DECODER_USER_OP_HELPERS_OFFSET].into()
    }

    #[inline(always)]
    fn lookup_sv1(&self, alpha: E) -> E {
        alpha + self.current()[DECODER_USER_OP_HELPERS_OFFSET + 1].into()
    }

    #[inline(always)]
    fn lookup_sv2(&self, alpha: E) -> E {
        alpha + self.current()[DECODER_USER_OP_HELPERS_OFFSET + 2].into()
    }

    #[inline(always)]
    fn lookup_sv3(&self, alpha: E) -> E {
        alpha + self.current()[DECODER_USER_OP_HELPERS_OFFSET + 3].into()
    }
}
