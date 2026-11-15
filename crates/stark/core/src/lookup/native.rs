//! Lookup declarations over immutable expression-valued rows.
//!
//! Constraint and witness paths share columns, groups, batches, messages and degree annotations.
//! Declarations read borrowed rows separately from mutable callback handles, so both paths
//! evaluate one authored interaction definition.

use p3_field::{Algebra, Field};

use super::{BoundaryBuilder, Deg, LookupColumn};
use crate::air::native::{AirFrame, Rows};

mod constraint;
mod prover;

pub use super::ProverLookupBuilder;
#[cfg(feature = "std")]
pub use super::debug::validation::{NativeValidationBuilder, validate_native};
pub use constraint::{ConstraintLookupBuilder, eval_lookup};
pub use prover::{LookupError, build_logup_aux_trace, build_lookup_fractions};

/// The inputs a per-row lookup declaration may read.
///
/// Auxiliary registers, challenges, exports and public inputs deliberately stay
/// with the adapter. `next` already denotes the caller's cyclic successor row.
pub struct LookupFrame<'a, E> {
    pub main: Rows<'a, E>,
    pub preprocessed: Rows<'a, E>,
    pub periodic: &'a [E],
}

impl<E> Copy for LookupFrame<'_, E> {}

impl<E> Clone for LookupFrame<'_, E> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, E> LookupFrame<'a, E> {
    /// Borrow the lookup-visible portion of an AIR frame.
    pub fn from_frame<EE>(frame: &AirFrame<'a, E, EE>) -> Self {
        Self {
            main: frame.main,
            preprocessed: frame.preprocessed,
            periodic: frame.periodic,
        }
    }
}

/// A mutable per-column handle, independent of the immutable lookup inputs.
pub trait LookupBuilder: Sized {
    type F: Field;
    type Expr: Algebra<Self::F>;
    type ExprEF: Algebra<Self::Expr>;

    type Column<'a>: LookupColumn<Expr = Self::Expr, ExprEF = Self::ExprEF>
    where
        Self: 'a;

    /// Evaluate and finalize one column, forwarding the callback result unchanged.
    fn next_column<'a, R>(&'a mut self, f: impl FnOnce(&mut Self::Column<'a>) -> R, deg: Deg) -> R;
}

/// One authored lookup declaration, usable with constraint or witness adapters.
///
/// Shape and interaction order depend only on immutable source configuration.
/// `column_shape` describes the LogUp prefix of the auxiliary trace; independently
/// constrained registers may follow it. Every evaluation must open exactly that
/// many columns, respecting the declared mutually-exclusive fraction bounds.
pub trait LookupAir<LB: LookupBuilder> {
    fn num_columns(&self) -> usize {
        self.column_shape().len()
    }

    fn column_shape(&self) -> &[usize];
    fn max_message_width(&self) -> usize;
    fn num_bus_ids(&self) -> usize;

    fn eval(&self, frame: &LookupFrame<'_, LB::Expr>, builder: &mut LB);

    /// Emit once-per-proof interactions in the boundary adapter's concrete field.
    fn eval_boundary<B>(&self, _boundary: &mut B)
    where
        B: BoundaryBuilder<F = LB::F>,
    {
    }
}
