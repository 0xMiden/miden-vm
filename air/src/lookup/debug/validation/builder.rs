//! `DebugStructureBuilder` — the `LookupBuilder` adapter that records inventory +
//! per-group `(U, V)` folds into a [`super::DebugStructure`].
//!
//! Pure implementation detail: instantiation happens inside
//! [`super::inspect_structure`]. The builder, column, group, and batch handles all
//! collapse their associated types to `Felt` / `QuadFelt`.

use alloc::vec::Vec;

use miden_core::field::{PrimeCharacteristicRing, QuadFelt};
use miden_crypto::stark::air::RowWindow;

use super::{
    super::super::{
        Challenges, Deg, LookupBatch, LookupBuilder, LookupColumn, LookupGroup, LookupMessage,
    },
    ColumnRecord, DebugStructure, EncodingMode, GroupRecord, InteractionRecord, MultSign,
    PassRecord,
};
use crate::Felt;

// BUILDER
// ================================================================================================

/// `LookupBuilder` that records inventory + per-group `(U, V)` folds into a
/// [`super::DebugStructure`].
pub struct DebugStructureBuilder<'a> {
    main: RowWindow<'a, Felt>,
    periodic_values: &'a [Felt],
    public_values: &'a [Felt],
    challenges: &'a Challenges<QuadFelt>,
    out: &'a mut DebugStructure,
    column_idx: usize,
}

impl<'a> DebugStructureBuilder<'a> {
    pub fn new(
        main: RowWindow<'a, Felt>,
        periodic_values: &'a [Felt],
        public_values: &'a [Felt],
        challenges: &'a Challenges<QuadFelt>,
        out: &'a mut DebugStructure,
    ) -> Self {
        Self {
            main,
            periodic_values,
            public_values,
            challenges,
            out,
            column_idx: 0,
        }
    }
}

impl<'a> LookupBuilder for DebugStructureBuilder<'a> {
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
        = DebugStructureColumn<'c>
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

    fn next_column<'c, R>(&'c mut self, f: impl FnOnce(&mut Self::Column<'c>) -> R, deg: Deg) -> R {
        let column_idx = self.column_idx;
        self.out.columns.push(ColumnRecord {
            column_idx,
            claimed_column_degree: deg,
            groups: Vec::new(),
        });
        let col_slot = self.out.columns.last_mut().expect("just pushed");
        let mut col = DebugStructureColumn {
            challenges: self.challenges,
            column: col_slot,
            next_group_idx: 0,
        };
        let result = f(&mut col);
        self.column_idx += 1;
        result
    }
}

// COLUMN
// ================================================================================================

pub struct DebugStructureColumn<'c> {
    challenges: &'c Challenges<QuadFelt>,
    column: &'c mut ColumnRecord,
    next_group_idx: usize,
}

impl<'c> LookupColumn for DebugStructureColumn<'c> {
    type Expr = Felt;
    type ExprEF = QuadFelt;

    type Group<'g>
        = DebugStructureGroup<'g>
    where
        Self: 'g;

    fn group<'g>(&'g mut self, name: &'static str, f: impl FnOnce(&mut Self::Group<'g>), deg: Deg) {
        let idx = self.next_group_idx;
        self.column.groups.push(GroupRecord {
            name,
            column_idx: self.column.column_idx,
            group_idx: idx,
            encoding_mode: EncodingMode::Simple,
            claimed_degree: deg,
            canonical: PassRecord::default(),
            encoded: PassRecord::default(),
        });
        let rec = self.column.groups.last_mut().expect("just pushed");
        {
            let mut g = DebugStructureGroup {
                pass_rec: &mut rec.canonical,
                u: QuadFelt::ONE,
                v: QuadFelt::ZERO,
                challenges: self.challenges,
            };
            f(&mut g);
            let pair = (g.u, g.v);
            g.pass_rec.fold = Some(pair);
        }
        self.next_group_idx += 1;
    }

    fn group_with_cached_encoding<'g>(
        &'g mut self,
        name: &'static str,
        canonical: impl FnOnce(&mut Self::Group<'g>),
        encoded: impl FnOnce(&mut Self::Group<'g>),
        deg: Deg,
    ) {
        let idx = self.next_group_idx;
        self.column.groups.push(GroupRecord {
            name,
            column_idx: self.column.column_idx,
            group_idx: idx,
            encoding_mode: EncodingMode::CachedEncoding,
            claimed_degree: deg,
            canonical: PassRecord::default(),
            encoded: PassRecord::default(),
        });
        let rec = self.column.groups.last_mut().expect("just pushed");

        // Canonical pass — mutable borrow of the disjoint `rec.canonical` field only, so
        // the subsequent `&mut rec.encoded` in the next block is allowed under Rust's
        // split-field borrow rule even with the GAT's `'g`-pinned lifetime.
        {
            let mut g = DebugStructureGroup {
                pass_rec: &mut rec.canonical,
                u: QuadFelt::ONE,
                v: QuadFelt::ZERO,
                challenges: self.challenges,
            };
            canonical(&mut g);
            let pair = (g.u, g.v);
            g.pass_rec.fold = Some(pair);
        }

        // Encoded pass — disjoint field, independent borrow.
        {
            let mut g = DebugStructureGroup {
                pass_rec: &mut rec.encoded,
                u: QuadFelt::ONE,
                v: QuadFelt::ZERO,
                challenges: self.challenges,
            };
            encoded(&mut g);
            let pair = (g.u, g.v);
            g.pass_rec.fold = Some(pair);
        }

        self.next_group_idx += 1;
    }
}

// GROUP
// ================================================================================================

pub struct DebugStructureGroup<'g> {
    pass_rec: &'g mut PassRecord,
    u: QuadFelt,
    v: QuadFelt,
    challenges: &'g Challenges<QuadFelt>,
}

impl<'g> LookupGroup for DebugStructureGroup<'g> {
    type Expr = Felt;
    type ExprEF = QuadFelt;

    type Batch<'b>
        = DebugStructureBatch<'b>
    where
        Self: 'b;

    fn add<M>(&mut self, name: &'static str, flag: Felt, msg: impl FnOnce() -> M, deg: Deg)
    where
        M: LookupMessage<Felt, QuadFelt>,
    {
        let v_msg = msg().encode(self.challenges);
        self.u += (v_msg - QuadFelt::ONE) * flag;
        self.v += flag;
        self.pass_rec.interactions.push(InteractionRecord {
            name,
            kind: Some(core::any::type_name::<M>()),
            sign: MultSign::Add,
            claimed_degree: deg,
            inside_batch: false,
        });
    }

    fn remove<M>(&mut self, name: &'static str, flag: Felt, msg: impl FnOnce() -> M, deg: Deg)
    where
        M: LookupMessage<Felt, QuadFelt>,
    {
        let v_msg = msg().encode(self.challenges);
        self.u += (v_msg - QuadFelt::ONE) * flag;
        self.v -= flag;
        self.pass_rec.interactions.push(InteractionRecord {
            name,
            kind: Some(core::any::type_name::<M>()),
            sign: MultSign::Remove,
            claimed_degree: deg,
            inside_batch: false,
        });
    }

    fn insert<M>(
        &mut self,
        name: &'static str,
        flag: Felt,
        multiplicity: Felt,
        msg: impl FnOnce() -> M,
        deg: Deg,
    ) where
        M: LookupMessage<Felt, QuadFelt>,
    {
        let v_msg = msg().encode(self.challenges);
        self.u += (v_msg - QuadFelt::ONE) * flag;
        self.v += flag * multiplicity;
        self.pass_rec.interactions.push(InteractionRecord {
            name,
            kind: Some(core::any::type_name::<M>()),
            sign: MultSign::Insert,
            claimed_degree: deg,
            inside_batch: false,
        });
    }

    fn batch<'b>(
        &'b mut self,
        _name: &'static str,
        flag: Felt,
        build: impl FnOnce(&mut Self::Batch<'b>),
        _deg: Deg,
    ) {
        let (n, d) = {
            let mut batch = DebugStructureBatch {
                pass_rec: &mut *self.pass_rec,
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
        name: &'static str,
        flag: Felt,
        multiplicity: Felt,
        encoded: impl FnOnce() -> QuadFelt,
        deg: Deg,
    ) {
        let v_msg = encoded();
        self.u += (v_msg - QuadFelt::ONE) * flag;
        self.v += flag * multiplicity;
        self.pass_rec.interactions.push(InteractionRecord {
            name,
            kind: None,
            sign: MultSign::InsertEncoded,
            claimed_degree: deg,
            inside_batch: false,
        });
    }
}

// BATCH
// ================================================================================================

pub struct DebugStructureBatch<'b> {
    pass_rec: &'b mut PassRecord,
    challenges: &'b Challenges<QuadFelt>,
    n: QuadFelt,
    d: QuadFelt,
}

impl<'b> LookupBatch for DebugStructureBatch<'b> {
    type Expr = Felt;
    type ExprEF = QuadFelt;

    fn insert<M>(&mut self, name: &'static str, multiplicity: Felt, msg: M, deg: Deg)
    where
        M: LookupMessage<Felt, QuadFelt>,
    {
        let v_msg = msg.encode(self.challenges);
        let d_prev = self.d;
        self.n = self.n * v_msg + d_prev * multiplicity;
        self.d *= v_msg;
        self.pass_rec.interactions.push(InteractionRecord {
            name,
            kind: Some(core::any::type_name::<M>()),
            sign: MultSign::Insert,
            claimed_degree: deg,
            inside_batch: true,
        });
    }

    fn insert_encoded(
        &mut self,
        name: &'static str,
        multiplicity: Felt,
        encoded: impl FnOnce() -> QuadFelt,
        deg: Deg,
    ) {
        let v_msg = encoded();
        let d_prev = self.d;
        self.n = self.n * v_msg + d_prev * multiplicity;
        self.d *= v_msg;
        self.pass_rec.interactions.push(InteractionRecord {
            name,
            kind: None,
            sign: MultSign::InsertEncoded,
            claimed_degree: deg,
            inside_batch: true,
        });
    }
}
