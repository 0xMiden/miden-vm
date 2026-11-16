//! Immutable borrowed inputs to an authored relation.

use p3_field::Dup;

use super::LiftedAirBuilder;

/// Current and next row expressions. The caller owns cyclic row selection.
#[derive(Debug)]
pub struct Rows<'a, E> {
    pub current: &'a [E],
    pub next: &'a [E],
}

impl<E> Copy for Rows<'_, E> {}

impl<E> Clone for Rows<'_, E> {
    fn clone(&self) -> Self {
        *self
    }
}

/// Selector expressions supplied by the current evaluator.
///
/// Polynomial evaluation uses the protocol's actual selector polynomials, while a row checker may
/// supply indicator values. A frame never normalizes or reinterprets them.
#[derive(Clone, Copy, Debug)]
pub struct Selectors<E> {
    pub first: E,
    pub last: E,
    pub transition: E,
}

/// Row-dependent expression inputs, borrowed independently of the mutable assertion sink.
#[derive(Debug)]
pub struct AirFrame<'a, E, EE> {
    pub main: Rows<'a, E>,
    pub preprocessed: Rows<'a, E>,
    pub aux: Rows<'a, EE>,
    pub periodic: &'a [E],
    pub selectors: Selectors<E>,
}

impl<E: Copy, EE> Copy for AirFrame<'_, E, EE> {}

impl<E: Clone, EE> Clone for AirFrame<'_, E, EE> {
    fn clone(&self) -> Self {
        Self {
            main: self.main,
            preprocessed: self.preprocessed,
            aux: self.aux,
            periodic: self.periodic,
            selectors: self.selectors.clone(),
        }
    }
}

impl<E: Dup, EE> AirFrame<'_, E, EE> {
    pub fn first_row(&self) -> E {
        self.selectors.first.dup()
    }

    pub fn last_row(&self) -> E {
        self.selectors.last.dup()
    }

    pub fn transition(&self) -> E {
        self.selectors.transition.dup()
    }
}

/// Inputs whose values are uniform throughout one evaluation pass.
///
/// These slices belong to the caller. Preparation may duplicate their expressions but must not
/// replace them with row data or retain references to temporary conversion buffers.
#[derive(Debug)]
pub struct UniformInputs<'a, E, EE> {
    pub public_values: &'a [E],
    pub challenges: &'a [EE],
    pub exports: &'a [EE],
}

impl<E, EE> Copy for UniformInputs<'_, E, EE> {}

impl<E, EE> Clone for UniformInputs<'_, E, EE> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<E: Dup, EE: Dup> UniformInputs<'_, E, EE> {
    pub fn public(&self, index: usize) -> E {
        self.public_values[index].dup()
    }

    pub fn challenge(&self, index: usize) -> EE {
        self.challenges[index].dup()
    }

    pub fn export(&self, index: usize) -> EE {
        self.exports[index].dup()
    }
}

/// A frame using an assertion sink's expression types.
pub type Frame<'a, B> =
    AirFrame<'a, <B as LiftedAirBuilder>::Expr, <B as LiftedAirBuilder>::ExtExpr>;

/// Uniform inputs using an assertion sink's expression types.
pub type Inputs<'a, B> =
    UniformInputs<'a, <B as LiftedAirBuilder>::Expr, <B as LiftedAirBuilder>::ExtExpr>;
