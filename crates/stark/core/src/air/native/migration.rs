//! Bounded, temporary forwarding from legacy callers to native source bodies.
//!
//! Snapshots own expressions rather than old window handles. Consequently the
//! mutable forwarding sink/lookup handle never aliases the rows a declaration
//! reads. This deliberately allocates at the raw-source boundary; production
//! generated evaluators keep their existing prepared path during coexistence.
//! Remove this module when the single runtime and all consumers are native.

use alloc::vec::Vec;

use p3_field::Dup;

use super::{
    AirFrame, ConstraintMeta, LiftedAir, LiftedAirBuilder, Rows, Selectors, UniformInputs,
};
use crate::{
    air::{self as legacy, WindowAccess},
    lookup::{self, native},
};

/// Invoke a native source through a legacy builder without adapting preparation.
///
/// Concrete legacy source implementations must retain unit `EvalData`. This
/// helper does not wrap native kernels or translate symbolic expression trees.
#[doc(hidden)]
pub fn eval_source<A, AB>(source: &A, builder: &mut AB)
where
    A: LiftedAir<F = AB::F>,
    AB: legacy::LiftedAirBuilder,
{
    let spec = source.spec();
    let snapshot = SourceSnapshot::new(builder, spec.preprocessed_width(), spec.aux_width);
    source.eval(&snapshot.frame(), snapshot.inputs(), &mut LegacySink(builder));
}

/// Owned inputs for a legacy source whose helper bodies are migrating independently.
///
/// Construct before borrowing the mutable forwarding sink. The snapshot can outlive successive
/// short sink reborrows, including an unmigrated helper call between native helper calls.
#[doc(hidden)]
pub struct SourceSnapshot<E, EE> {
    main: [Vec<E>; 2],
    preprocessed: [Vec<E>; 2],
    aux: [Vec<EE>; 2],
    periodic: Vec<E>,
    public: Vec<E>,
    challenges: Vec<EE>,
    exports: Vec<EE>,
    selectors: Selectors<E>,
}

impl<E: Dup, EE> SourceSnapshot<E, EE> {
    /// Snapshot declared channels, skipping absent optional windows.
    ///
    /// The legacy symbolic builder represents zero-width matrices with zero rows, so their
    /// `WindowAccess` methods cannot be called. Widths come from the trusted source configuration.
    pub fn new<AB>(builder: &AB, preprocessed_width: usize, aux_width: usize) -> Self
    where
        AB: legacy::LiftedAirBuilder<Expr = E, ExprEF = EE>,
    {
        let main = builder.main();
        Self {
            main: [
                main.current_slice().iter().copied().map(Into::into).collect(),
                main.next_slice().iter().copied().map(Into::into).collect(),
            ],
            preprocessed: if preprocessed_width == 0 {
                [Vec::new(), Vec::new()]
            } else {
                let preprocessed = builder.preprocessed();
                [
                    preprocessed.current_slice().iter().copied().map(Into::into).collect(),
                    preprocessed.next_slice().iter().copied().map(Into::into).collect(),
                ]
            },
            aux: if aux_width == 0 {
                [Vec::new(), Vec::new()]
            } else {
                let aux = builder.permutation();
                [
                    aux.current_slice().iter().copied().map(Into::into).collect(),
                    aux.next_slice().iter().copied().map(Into::into).collect(),
                ]
            },
            periodic: builder.periodic_values().iter().copied().map(Into::into).collect(),
            public: builder.public_values().iter().copied().map(Into::into).collect(),
            challenges: builder.permutation_randomness().iter().copied().map(Into::into).collect(),
            // Upstream exports are Clone; unlike row variables they need not be Copy.
            exports: builder.permutation_values().iter().cloned().map(Into::into).collect(),
            selectors: Selectors {
                first: builder.is_first_row(),
                last: builder.is_last_row(),
                transition: builder.is_transition(),
            },
        }
    }

    pub fn frame(&self) -> AirFrame<'_, E, EE> {
        AirFrame {
            main: Rows {
                current: &self.main[0],
                next: &self.main[1],
            },
            preprocessed: Rows {
                current: &self.preprocessed[0],
                next: &self.preprocessed[1],
            },
            aux: Rows {
                current: &self.aux[0],
                next: &self.aux[1],
            },
            periodic: &self.periodic,
            selectors: Selectors {
                first: self.selectors.first.dup(),
                last: self.selectors.last.dup(),
                transition: self.selectors.transition.dup(),
            },
        }
    }

    pub fn inputs(&self) -> UniformInputs<'_, E, EE> {
        UniformInputs {
            public_values: &self.public,
            challenges: &self.challenges,
            exports: &self.exports,
        }
    }
}

/// A short mutable reborrow for one native helper in a partially migrated source.
#[doc(hidden)]
pub struct LegacySink<'a, AB>(&'a mut AB);

impl<'a, AB> LegacySink<'a, AB> {
    pub fn new(builder: &'a mut AB) -> Self {
        Self(builder)
    }
}

impl<AB: legacy::LiftedAirBuilder> LiftedAirBuilder for LegacySink<'_, AB> {
    type F = AB::F;
    type Expr = AB::Expr;
    type ExtExpr = AB::ExprEF;

    fn emit_base(&mut self, value: Self::Expr, _meta: ConstraintMeta<'_>) {
        legacy::AirBuilder::assert_zero(self.0, value);
    }

    fn emit_ext(&mut self, value: Self::ExtExpr, _meta: ConstraintMeta<'_>) {
        legacy::ExtensionBuilder::assert_zero_ext(self.0, value);
    }
}

/// Forward a native lookup declaration through the existing adapter callbacks.
///
/// `preprocessed_width` is the source-declared fixed width. An absent window must not be read:
/// the legacy symbolic builder represents it as a zero-row matrix.
#[doc(hidden)]
pub fn eval_lookup<'b, A, LB>(air: &A, builder: &'b mut LB, preprocessed_width: usize)
where
    LB: lookup::LookupBuilder,
    A: native::LookupAir<LegacyLookup<'b, LB>>,
{
    let main = builder.main();
    let main: [Vec<LB::Expr>; 2] = [
        main.current_slice().iter().copied().map(Into::into).collect(),
        main.next_slice().iter().copied().map(Into::into).collect(),
    ];
    let preprocessed: [Vec<LB::Expr>; 2] = if preprocessed_width == 0 {
        [Vec::new(), Vec::new()]
    } else {
        let preprocessed = builder.preprocessed();
        [
            preprocessed.current_slice().iter().copied().map(Into::into).collect(),
            preprocessed.next_slice().iter().copied().map(Into::into).collect(),
        ]
    };
    let periodic: Vec<LB::Expr> =
        builder.periodic_values().iter().copied().map(Into::into).collect();
    let frame = native::LookupFrame {
        main: Rows { current: &main[0], next: &main[1] },
        preprocessed: Rows {
            current: &preprocessed[0],
            next: &preprocessed[1],
        },
        periodic: &periodic,
    };
    air.eval(&frame, &mut LegacyLookup(builder));
}

/// A reborrow of an old lookup adapter, containing no row/window references.
#[doc(hidden)]
pub struct LegacyLookup<'a, LB>(&'a mut LB);

impl<LB> LegacyLookup<'_, LB> {
    /// Reborrow the stable legacy row reader for a source-specific construction hook.
    ///
    /// The bridge constructs the native frame from these same current/next rows. Hooks return
    /// owned expressions before mutable column callbacks begin; the constructor stays private.
    #[doc(hidden)]
    pub fn legacy(&self) -> &LB {
        &*self.0
    }
}

impl<LB: lookup::LookupBuilder> native::LookupBuilder for LegacyLookup<'_, LB> {
    type F = LB::F;
    type Expr = LB::Expr;
    type ExprEF = LB::ExprEF;
    type Column<'a>
        = LB::Column<'a>
    where
        Self: 'a;

    fn next_column<'a, R>(
        &'a mut self,
        f: impl FnOnce(&mut Self::Column<'a>) -> R,
        deg: lookup::Deg,
    ) -> R {
        self.0.next_column(f, deg)
    }
}
