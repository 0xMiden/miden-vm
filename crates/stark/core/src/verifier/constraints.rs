//! Scalar OOD folding in exact global assertion order.

use core::marker::PhantomData;

use p3_field::{ExtensionField, Field};

use crate::air::native;

/// The verifier streams `acc = acc * alpha + assertion` across both assertion classes.
pub(super) struct ConstraintFolder<F: Field, EF: ExtensionField<F>> {
    pub alpha: EF,
    pub accumulator: EF,
    pub _phantom: PhantomData<F>,
}

impl<F: Field, EF: ExtensionField<F>> ConstraintFolder<F, EF> {
    fn fold(&mut self, value: EF) {
        self.accumulator = self.accumulator * self.alpha + value;
    }
}

impl<F: Field, EF: ExtensionField<F>> native::LiftedAirBuilder for ConstraintFolder<F, EF> {
    type F = F;
    type Expr = EF;
    type ExtExpr = EF;

    fn emit_base(&mut self, value: EF, _meta: native::ConstraintMeta<'_>) {
        self.fold(value);
    }

    fn emit_ext(&mut self, value: EF, _meta: native::ConstraintMeta<'_>) {
        self.fold(value);
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::testing::configs::{Felt, QuadFelt};

    fn folder(alpha: QuadFelt) -> ConstraintFolder<Felt, QuadFelt> {
        ConstraintFolder {
            alpha,
            accumulator: QuadFelt::ZERO,
            _phantom: PhantomData,
        }
    }

    #[test]
    fn native_scalar_folder_keeps_zero_and_repeated_interleaved_emissions() {
        let alpha = QuadFelt::new([Felt::from_u32(7), Felt::from_u32(11)]);
        let first = QuadFelt::from_u32(13);
        let repeated = QuadFelt::new([Felt::from_u32(17), Felt::from_u32(19)]);
        let last = QuadFelt::from_u32(23);
        let mut native_folder = folder(alpha);
        native::LiftedAirBuilder::assert_zero(&mut native_folder, first);
        native::LiftedAirBuilder::assert_zero_ext(
            &mut native::LiftedAirBuilder::when(&mut native_folder, QuadFelt::ZERO),
            repeated,
        );
        native::LiftedAirBuilder::assert_zero(&mut native_folder, repeated);
        native::LiftedAirBuilder::assert_zero_ext(&mut native_folder, repeated);
        native::LiftedAirBuilder::assert_zero(&mut native_folder, last);

        // Five emissions assign descending powers 4 through 0, including the zero-gated emission.
        let expected =
            first * alpha.exp_u64(4) + repeated * alpha.square() + repeated * alpha + last;
        assert_eq!(native_folder.accumulator, expected);
    }
}
