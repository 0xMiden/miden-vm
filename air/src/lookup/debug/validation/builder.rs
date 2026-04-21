//! Concrete `(U, V)` fold walker used for the cached-encoding equivalence and
//! simple-group scope checks in [`validate`](super::validate).
//!
//! Operates on `Felt` / `QuadFelt` values over a single random row pair. For each
//! cached-encoding group it runs both the canonical and encoded closures and
//! compares their resulting `(U, V)` pairs; a disagreement yields an
//! [`EncodingMismatch`](super::ValidationError::EncodingMismatch). For each simple
//! group it records whether the canonical closure called `insert_encoded`; if it
//! did, a [`ScopeViolation`](super::ValidationError::ScopeViolation) is emitted.
//!
//! Short-circuits via an [`Option<ValidationError>`] slot on the outer builder; the
//! first problem observed is retained and later emits are ignored.

use miden_core::field::{PrimeCharacteristicRing, QuadFelt};
use miden_crypto::stark::air::RowWindow;

use super::{
    super::super::{
        Challenges, Deg, LookupBatch, LookupBuilder, LookupColumn, LookupGroup, LookupMessage,
    },
    ValidationError,
};
use crate::Felt;

// BUILDER
// ================================================================================================

/// Concrete-row walker that verifies the canonical / encoded equivalence contract of
/// every cached-encoding group and the simple-group scope contract.
pub struct EncodingCheckBuilder<'a> {
    main: RowWindow<'a, Felt>,
    periodic_values: &'a [Felt],
    public_values: &'a [Felt],
    challenges: &'a Challenges<QuadFelt>,
    column_idx: usize,
    /// First problem observed across the whole walk; later ones are ignored.
    error: Option<ValidationError>,
}

impl<'a> EncodingCheckBuilder<'a> {
    pub fn new(
        main: RowWindow<'a, Felt>,
        periodic_values: &'a [Felt],
        public_values: &'a [Felt],
        challenges: &'a Challenges<QuadFelt>,
    ) -> Self {
        Self {
            main,
            periodic_values,
            public_values,
            challenges,
            column_idx: 0,
            error: None,
        }
    }

    pub fn take_error(self) -> Option<ValidationError> {
        self.error
    }
}

impl<'a> LookupBuilder for EncodingCheckBuilder<'a> {
    type F = Felt;
    type Expr = Felt;
    type Var = Felt;

    type EF = QuadFelt;
    type ExprEF = QuadFelt;
    type VarEF = QuadFelt;

    type PeriodicVar = Felt;
    type PublicVar = Felt;

    type MainWindow = RowWindow<'a, Felt>;

    type Column<'c>
        = EncodingCheckColumn<'c>
    where
        Self: 'c;

    fn main(&self) -> Self::MainWindow {
        self.main
    }

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.periodic_values
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }

    fn next_column<'c, R>(
        &'c mut self,
        f: impl FnOnce(&mut Self::Column<'c>) -> R,
        _deg: Deg,
    ) -> R {
        let column_idx = self.column_idx;
        self.column_idx += 1;
        let mut col = EncodingCheckColumn {
            challenges: self.challenges,
            column_idx,
            next_group_idx: 0,
            error: self.error.take(),
        };
        let result = f(&mut col);
        self.error = col.error;
        result
    }
}

// COLUMN
// ================================================================================================

pub struct EncodingCheckColumn<'c> {
    challenges: &'c Challenges<QuadFelt>,
    column_idx: usize,
    next_group_idx: usize,
    error: Option<ValidationError>,
}

impl<'c> LookupColumn for EncodingCheckColumn<'c> {
    type Expr = Felt;
    type ExprEF = QuadFelt;

    type Group<'g>
        = EncodingCheckGroup<'g>
    where
        Self: 'g;

    fn group<'g>(
        &'g mut self,
        name: &'static str,
        f: impl FnOnce(&mut Self::Group<'g>),
        _deg: Deg,
    ) {
        let group_idx = self.next_group_idx;
        self.next_group_idx += 1;

        let mut group = EncodingCheckGroup {
            challenges: self.challenges,
            u: QuadFelt::ONE,
            v: QuadFelt::ZERO,
            inside_encoded_closure: false,
            used_insert_encoded: false,
        };
        f(&mut group);
        if self.error.is_none() && group.used_insert_encoded {
            self.error = Some(ValidationError::ScopeViolation {
                column_idx: self.column_idx,
                group_idx,
                name,
            });
        }
    }

    fn group_with_cached_encoding<'g>(
        &'g mut self,
        name: &'static str,
        canonical: impl FnOnce(&mut Self::Group<'g>),
        encoded: impl FnOnce(&mut Self::Group<'g>),
        _deg: Deg,
    ) {
        let group_idx = self.next_group_idx;
        self.next_group_idx += 1;

        let mut canon = EncodingCheckGroup {
            challenges: self.challenges,
            u: QuadFelt::ONE,
            v: QuadFelt::ZERO,
            inside_encoded_closure: false,
            used_insert_encoded: false,
        };
        canonical(&mut canon);

        let mut enc = EncodingCheckGroup {
            challenges: self.challenges,
            u: QuadFelt::ONE,
            v: QuadFelt::ZERO,
            inside_encoded_closure: true,
            used_insert_encoded: false,
        };
        encoded(&mut enc);

        if self.error.is_none() && (canon.u != enc.u || canon.v != enc.v) {
            self.error = Some(ValidationError::EncodingMismatch {
                column_idx: self.column_idx,
                group_idx,
                name,
                u_canonical: canon.u,
                v_canonical: canon.v,
                u_encoded: enc.u,
                v_encoded: enc.v,
            });
        }
    }
}

// GROUP
// ================================================================================================

pub struct EncodingCheckGroup<'g> {
    challenges: &'g Challenges<QuadFelt>,
    u: QuadFelt,
    v: QuadFelt,
    /// Set when this group was opened via the `encoded` closure of
    /// `group_with_cached_encoding`; toggles the legal use of `insert_encoded`.
    inside_encoded_closure: bool,
    /// `true` if this group called `insert_encoded` at least once. The column
    /// inspects this flag at close time and raises `ScopeViolation` if the group
    /// was simple.
    used_insert_encoded: bool,
}

impl<'g> LookupGroup for EncodingCheckGroup<'g> {
    type Expr = Felt;
    type ExprEF = QuadFelt;

    type Batch<'b>
        = EncodingCheckBatch<'b>
    where
        Self: 'b;

    fn add<M>(&mut self, _name: &'static str, flag: Felt, msg: impl FnOnce() -> M, _deg: Deg)
    where
        M: LookupMessage<Felt, QuadFelt>,
    {
        let v_msg = msg().encode(self.challenges);
        self.u += (v_msg - QuadFelt::ONE) * flag;
        self.v += flag;
    }

    fn remove<M>(&mut self, _name: &'static str, flag: Felt, msg: impl FnOnce() -> M, _deg: Deg)
    where
        M: LookupMessage<Felt, QuadFelt>,
    {
        let v_msg = msg().encode(self.challenges);
        self.u += (v_msg - QuadFelt::ONE) * flag;
        self.v -= flag;
    }

    fn insert<M>(
        &mut self,
        _name: &'static str,
        flag: Felt,
        multiplicity: Felt,
        msg: impl FnOnce() -> M,
        _deg: Deg,
    ) where
        M: LookupMessage<Felt, QuadFelt>,
    {
        let v_msg = msg().encode(self.challenges);
        self.u += (v_msg - QuadFelt::ONE) * flag;
        self.v += flag * multiplicity;
    }

    fn batch<'b>(
        &'b mut self,
        _name: &'static str,
        flag: Felt,
        build: impl FnOnce(&mut Self::Batch<'b>),
        _deg: Deg,
    ) {
        let (n, d) = {
            let mut batch = EncodingCheckBatch {
                challenges: self.challenges,
                n: QuadFelt::ZERO,
                d: QuadFelt::ONE,
            };
            build(&mut batch);
            (batch.n, batch.d)
        };
        self.u += (d - QuadFelt::ONE) * flag;
        self.v += n * flag;
    }

    fn beta_powers(&self) -> &[QuadFelt] {
        &self.challenges.beta_powers[..]
    }

    fn bus_prefix(&self, bus_id: usize) -> QuadFelt {
        self.challenges.bus_prefix[bus_id]
    }

    fn insert_encoded(
        &mut self,
        _name: &'static str,
        flag: Felt,
        multiplicity: Felt,
        encoded: impl FnOnce() -> QuadFelt,
        _deg: Deg,
    ) {
        // Flag the misuse; the column turns it into a `ScopeViolation` on close.
        if !self.inside_encoded_closure {
            self.used_insert_encoded = true;
        }
        let v_msg = encoded();
        self.u += (v_msg - QuadFelt::ONE) * flag;
        self.v += flag * multiplicity;
    }
}

// BATCH
// ================================================================================================

pub struct EncodingCheckBatch<'b> {
    challenges: &'b Challenges<QuadFelt>,
    n: QuadFelt,
    d: QuadFelt,
}

impl<'b> LookupBatch for EncodingCheckBatch<'b> {
    type Expr = Felt;
    type ExprEF = QuadFelt;

    fn insert<M>(&mut self, _name: &'static str, multiplicity: Felt, msg: M, _deg: Deg)
    where
        M: LookupMessage<Felt, QuadFelt>,
    {
        let v_msg = msg.encode(self.challenges);
        let d_prev = self.d;
        self.n = self.n * v_msg + d_prev * multiplicity;
        self.d *= v_msg;
    }

    fn insert_encoded(
        &mut self,
        _name: &'static str,
        multiplicity: Felt,
        encoded: impl FnOnce() -> QuadFelt,
        _deg: Deg,
    ) {
        let v_msg = encoded();
        let d_prev = self.d;
        self.n = self.n * v_msg + d_prev * multiplicity;
        self.d *= v_msg;
    }
}
