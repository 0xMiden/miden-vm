//! Native inputs and assertion emission over the shared LogUp column arithmetic.

use p3_field::Dup;

use super::{LookupAir, LookupBuilder, LookupFrame};
use crate::{
    air::native::{Frame, Inputs, LiftedAirBuilder, Rows},
    lookup::{
        Challenges, Deg,
        constraint::{AccumulatorInputs, ConstraintColumn, column_constraints},
    },
};

/// Constraint adapter with immutable row inputs separate from mutable assertion emission.
///
/// The builder owns one challenge table and duplicates only the first selector and normalized
/// export it needs. Column callbacks borrow that table, not the sink or row frame. Auxiliary
/// columns after the declared LogUp prefix are independently constrained by the source.
pub struct ConstraintLookupBuilder<'rows, 'sink, B: LiftedAirBuilder> {
    sink: &'sink mut B,
    aux: Rows<'rows, B::ExtExpr>,
    first: B::Expr,
    sigma: B::ExtExpr,
    challenges: Challenges<B::ExtExpr>,
    column_idx: usize,
    num_columns: usize,
}

impl<'rows, 'sink, B: LiftedAirBuilder> ConstraintLookupBuilder<'rows, 'sink, B> {
    /// Build challenge tables once for one lookup evaluation.
    ///
    /// The caller supplies the same frame/uniform inputs as its source evaluation. LogUp requires
    /// two challenge values, normalized export zero, and enough current/next auxiliary columns.
    /// Malformed source geometry is a construction invariant and panics here.
    pub fn new<A>(
        frame: &Frame<'rows, B>,
        inputs: Inputs<'_, B>,
        sink: &'sink mut B,
        air: &A,
    ) -> Self
    where
        A: LookupAir<Self>,
    {
        let num_columns = air.column_shape().len();
        assert!(num_columns > 0, "a LogUp argument must declare at least one column");
        assert!(inputs.challenges.len() >= 2, "LogUp requires alpha and beta challenges");
        assert!(!inputs.exports.is_empty(), "LogUp requires normalized export zero");
        assert!(frame.aux.current.len() >= num_columns, "LogUp auxiliary prefix is missing");
        assert!(frame.aux.next.len() >= num_columns, "LogUp next auxiliary prefix is missing");
        let challenges = Challenges::new(
            inputs.challenge(0),
            inputs.challenge(1),
            air.max_message_width(),
            air.num_bus_ids(),
        );
        Self {
            sink,
            aux: frame.aux,
            first: frame.first_row(),
            sigma: inputs.export(0),
            challenges,
            column_idx: 0,
            num_columns,
        }
    }

    pub fn finish(self) {
        assert_eq!(
            self.column_idx, self.num_columns,
            "LookupAir::eval emitted {} columns, but column_shape declares {}",
            self.column_idx, self.num_columns,
        );
    }
}

impl<B: LiftedAirBuilder> LookupBuilder for ConstraintLookupBuilder<'_, '_, B> {
    type F = B::F;
    type Expr = B::Expr;
    type ExprEF = B::ExtExpr;

    type Column<'a>
        = ConstraintColumn<'a, B::Expr, B::ExtExpr>
    where
        Self: 'a;

    fn next_column<'a, R>(
        &'a mut self,
        f: impl FnOnce(&mut Self::Column<'a>) -> R,
        _deg: Deg,
    ) -> R {
        let mut column = ConstraintColumn::new(&self.challenges);
        let result = f(&mut column);
        let (u, v) = column.into_pair();
        let index = self.column_idx;
        assert!(index < self.num_columns, "LookupAir::eval emitted more columns than declared");
        self.column_idx += 1;

        let (band, accumulator) = if index == 0 {
            (
                &self.aux.current[..self.num_columns],
                Some(AccumulatorInputs {
                    next: self.aux.next[0].dup(),
                    sigma: self.sigma.dup(),
                    first: self.first.dup(),
                }),
            )
        } else {
            (&self.aux.current[index..index + 1], None)
        };
        let (anchor, relation) = column_constraints(u, v, band.iter().map(Dup::dup), accumulator);
        if let Some(anchor) = anchor {
            self.sink.assert_zero_ext(anchor);
        }
        self.sink.assert_zero_ext(relation);
        result
    }
}

/// Evaluate one authored lookup declaration using the source's exact frame and inputs.
pub fn eval_lookup<'rows, 'sink, A, B>(
    air: &A,
    frame: &Frame<'rows, B>,
    inputs: Inputs<'_, B>,
    sink: &'sink mut B,
) where
    B: LiftedAirBuilder,
    A: LookupAir<ConstraintLookupBuilder<'rows, 'sink, B>>,
{
    let lookup_frame = LookupFrame::from_frame(frame);
    let mut builder = ConstraintLookupBuilder::new(frame, inputs, sink, air);
    air.eval(&lookup_frame, &mut builder);
    builder.finish();
}

#[cfg(test)]
mod tests {
    use alloc::{borrow::Cow, vec, vec::Vec};

    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks as F;

    use super::*;
    use crate::{
        air::native::{
            AirFrame, AirSpec, Assertion, ConstraintMeta, LiftedAir, Selectors, UniformInputs,
            capture,
            symbolic::{AuxInput, BaseLeaf, ExtLeaf, RowOffset, SymbolicExpr},
        },
        lookup::{LookupColumn, LookupGroup},
    };

    struct EmptyLookup;

    impl<LB: LookupBuilder<F = F>> LookupAir<LB> for EmptyLookup {
        fn column_shape(&self) -> &[usize] {
            &[1, 1]
        }
        fn max_message_width(&self) -> usize {
            1
        }
        fn num_bus_ids(&self) -> usize {
            1
        }

        fn eval(&self, _frame: &LookupFrame<'_, LB::Expr>, builder: &mut LB) {
            for result in [17, 23] {
                let observed = builder.next_column(
                    |column| {
                        column.group("empty", |_| {}, Deg { v: 0, u: 0 });
                        result
                    },
                    Deg { v: 0, u: 0 },
                );
                assert_eq!(observed, result);
            }
        }
    }

    impl LiftedAir for EmptyLookup {
        type F = F;

        fn spec(&self) -> AirSpec<'_, F> {
            AirSpec {
                main_width: 1,
                aux_width: 3,
                num_public_values: 0,
                num_challenges: 2,
                num_exports: 1,
                preprocessed: None,
                periodic_columns: Cow::Borrowed(&[]),
            }
        }

        fn eval<B: LiftedAirBuilder<F = F>>(
            &self,
            frame: &Frame<'_, B>,
            inputs: Inputs<'_, B>,
            sink: &mut B,
        ) {
            eval_lookup(self, frame, inputs, sink);
        }
    }

    struct CachedLookup;

    impl<LB: LookupBuilder<F = F>> LookupAir<LB> for CachedLookup {
        fn column_shape(&self) -> &[usize] {
            &[2]
        }
        fn max_message_width(&self) -> usize {
            1
        }
        fn num_bus_ids(&self) -> usize {
            1
        }

        fn eval(&self, _frame: &LookupFrame<'_, LB::Expr>, builder: &mut LB) {
            builder.next_column(
                |column| {
                    column.group_with_cached_encoding(
                        "cached",
                        |_| panic!("constraint path must use the encoded description"),
                        |group| {
                            group.selected_batch2_encoded(
                                "two slots",
                                "first",
                                LB::Expr::ONE,
                                || LB::ExprEF::from(LB::Expr::from_u32(3)),
                                "second",
                                LB::Expr::TWO,
                                || LB::ExprEF::from(LB::Expr::from_u32(5)),
                            )
                        },
                        Deg { v: 0, u: 0 },
                    );
                },
                Deg { v: 0, u: 0 },
            );
        }
    }

    #[derive(Default)]
    struct Sink(Vec<F>);

    impl LiftedAirBuilder for Sink {
        type F = F;
        type Expr = F;
        type ExtExpr = F;

        fn emit_base(&mut self, _value: F, _meta: ConstraintMeta<'_>) {
            panic!("lookup equations must remain extension assertions")
        }

        fn emit_ext(&mut self, value: F, _meta: ConstraintMeta<'_>) {
            self.0.push(value);
        }
    }

    #[test]
    fn zero_anchor_prefix_and_fraction_slots_preserve_their_order() {
        let current = [F::TWO, F::from_u32(3), F::from_u32(999)];
        let next = [F::from_u32(7), F::from_u32(11), F::from_u32(888)];
        let frame = AirFrame {
            main: Rows { current: &[F::ZERO], next: &[F::ZERO] },
            preprocessed: Rows { current: &[], next: &[] },
            aux: Rows { current: &current, next: &next },
            periodic: &[],
            selectors: Selectors {
                first: F::ZERO,
                last: F::ONE,
                transition: F::ONE,
            },
        };
        let inputs = UniformInputs {
            public_values: &[],
            challenges: &[F::from_u32(13), F::from_u32(17)],
            exports: &[F::from_u32(5)],
        };
        let mut sink = Sink::default();
        eval_lookup(&EmptyLookup, &frame, inputs, &mut sink);
        // 2*0; 1*(7-(2+3)+5)-0; 1*3-0. Suffix 999 is not part of LogUp.
        assert_eq!(sink.0, vec![F::ZERO, F::from_u32(7), F::from_u32(3)]);
        let mut sink = Sink::default();
        eval_lookup(&CachedLookup, &frame, inputs, &mut sink);
        // The two fractions combine to (V,U)=(11,15), so 15*(7-2+5)-11=139.
        assert_eq!(sink.0, vec![F::ZERO, F::from_u32(139)]);
    }

    #[test]
    fn noncopy_symbolic_inputs_keep_anchor_operand_and_emission_order() {
        let captured = capture(&EmptyLookup).unwrap();
        assert_eq!(captured.assertions.len(), 3);
        assert_eq!(captured.descriptor.analysis().counts().ext, 3);
        let Assertion::Extension(SymbolicExpr::Mul { x, y, .. }) = &captured.assertions[0] else {
            panic!("anchor must be acc * first")
        };
        assert!(matches!(
            x.as_ref(),
            SymbolicExpr::Leaf(ExtLeaf::Input(AuxInput::Trace {
                offset: RowOffset::Current,
                index: 0,
            }))
        ));
        assert!(matches!(
            y.as_ref(),
            SymbolicExpr::Leaf(ExtLeaf::Base(SymbolicExpr::Leaf(BaseLeaf::IsFirstRow)))
        ));
        assert!(
            captured
                .assertions
                .iter()
                .all(|assertion| matches!(assertion, Assertion::Extension(_)))
        );
    }
}
