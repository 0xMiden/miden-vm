//! EC layer — short-Weierstrass groups and points over the uint layer.
//!
//! Three chiplets, two stores and a relation:
//!
//! - [`groups::EcGroupsAir`] — the **group table**: one row per group binding `group_ptr → (a, b,
//!   bound, scalar_bound)`; *provides* [`EcGroup`](crate::relations::BusId::EcGroup).
//! - [`EcPointStoreAir`] (this module) — the **point store**: one row per point; *provides*
//!   [`EcPoint`](crate::relations::BusId::EcPoint), *consumes* its group's tuple and — unless
//!   `is_pai` — the curve-membership MAC trio.
//! - [`add::EcGroupAddAir`] — the complete group-law addition over the two stores.
//!
//! Both stores are **binding stores**, deliberately the thinnest
//! chiplets in the stack: one row per entity, no periodic columns, a
//! single aux column each. Everything heavy is delegated downward —
//! coordinate canonicity to the [UintStore](crate::uint), curve
//! membership to three [`UintMul`](crate::relations::BusId::UintMul)
//! MACs sharing a result ptr, group-op field math to the uint relation
//! chiplets.
//!
//! See the design notes for the full design.
//!
//! ## Point rows
//!
//! A point row binds `point_ptr → (group_ptr, x_ptr, y_ptr, is_pai)`,
//! *provides* `EcPoint`, *consumes* its group's `EcGroup` tuple (which
//! certifies the `(a, b, bound, scalar_bound)` cells it carries — for
//! PAI rows this consume is the *only* thing tying the row to a real
//! group), and — unless `is_pai` — *consumes* the three
//! curve-membership MACs
//!
//! ```text
//! u ≡ 1·(x·x) + 1·a     w ≡ 1·(x·u) + 1·b     w ≡ 1·(y·y) + 0·dummy
//! ```
//!
//! whose shared `r_ptr = w` makes `y² = x³ + ax + b` an identity of
//! stored values ("stored ⟹ on-curve", mirroring "stored ⟹
//! canonical").
//!
//! PAI is the **`is_pai` flag** with the coordinate/transient ptrs tied
//! to the none-sentinel 0 — never magic coordinate values (which would
//! collide on `b = 0` curves and hide the flag every consumer wants).
//!
//! ## Ptr discipline
//!
//! Groups and points are **separate ptr namespaces**. Group rows are
//! dense and consecutive, with VM-owned fixed slots preseeded from
//! `CurveId::ALL` (K1 row 1, R1 row 2, Ed25519 row 3 today); later groups and
//! points are allocator-assigned. Injectivity is the chain `ptr' = ptr +
//! 1` gated to the active prefix — no gap column, no `Range16`. `act` is
//! monotone (pads only at the tail) and all-zero pad rows touch no bus.

pub mod add;
pub mod groups;
pub mod msm;
pub mod require;
pub mod trace;

use alloc::vec::Vec;

use add::EcOnCurveCertMsg;
use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_lifted_air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder};
pub use require::{EcRequire, EcStores};

use crate::{
    logup::{
        Challenges, CyclicConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder,
        LookupColumn, LookupGroup, LookupMessage, NUM_PUBLIC_VALUES, NUM_RANDOMNESS,
        NUM_SIGMA_VALUES,
    },
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    uint::mul::UintMulMsg,
    utils::{current_main, next_main},
};

// MESSAGES
// ================================================================================================

/// LogUp message for the [`EcGroup`](BusId::EcGroup) relation: the
/// 5-tuple `(group_ptr, a_ptr, b_ptr, bound_ptr, scalar_bound_ptr)`
/// binding a short-Weierstrass group to its curve context — the params
/// (stored uints sharing `bound_ptr`, which fixes the base field) plus
/// the scalar-field modulus handle (= `bound_ptr` while nothing
/// constrains it; see [`groups`]).
#[derive(Debug, Clone)]
pub struct EcGroupMsg<E> {
    pub group_ptr: E,
    pub a_ptr: E,
    pub b_ptr: E,
    pub bound_ptr: E,
    pub scalar_bound_ptr: E,
}

impl<E, EF> LookupMessage<E, EF> for EcGroupMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(
            BusId::EcGroup as usize,
            [
                self.group_ptr.clone(),
                self.a_ptr.clone(),
                self.b_ptr.clone(),
                self.bound_ptr.clone(),
                self.scalar_bound_ptr.clone(),
            ],
        )
    }
}

/// LogUp message for the [`EcPoint`](BusId::EcPoint) relation: the
/// 5-tuple `(point_ptr, group_ptr, x_ptr, y_ptr, is_pai)` binding a
/// stored point — on-curve when finite, the group's `∞` when `is_pai`
/// (coordinate ptrs 0, the none-sentinel).
#[derive(Debug, Clone)]
pub struct EcPointMsg<E> {
    pub point_ptr: E,
    pub group_ptr: E,
    pub x_ptr: E,
    pub y_ptr: E,
    pub is_pai: E,
}

impl<E, EF> LookupMessage<E, EF> for EcPointMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(
            BusId::EcPoint as usize,
            [
                self.point_ptr.clone(),
                self.group_ptr.clone(),
                self.x_ptr.clone(),
                self.y_ptr.clone(),
                self.is_pai.clone(),
            ],
        )
    }
}

// COLUMN LAYOUT
// ================================================================================================

/// Point ptr (allocator-consecutive from 1; 0 is the none-sentinel).
pub const COL_PTR: usize = 0;
/// The owning group's ptr (the group namespace).
pub const COL_GROUP_PTR: usize = 1;
/// Curve `a`'s uint ptr (certified by the `EcGroup` consume; feeds
/// membership MAC `u`).
pub const COL_A_PTR: usize = 2;
/// Curve `b`'s uint ptr (feeds membership MAC `w`).
pub const COL_B_PTR: usize = 3;
/// The base-field modulus ptr (fixes the field).
pub const COL_BOUND_PTR: usize = 4;
/// The group's scalar-field modulus ptr (carried only to close the
/// `EcGroup` consume; = `bound_ptr` while unconstrained).
pub const COL_SBOUND_PTR: usize = 5;
/// Coordinate uint ptrs (0 when `is_pai`).
pub const COL_X_PTR: usize = 6;
pub const COL_Y_PTR: usize = 7;
/// Membership transients: `u = x² + a`, `w = x³ + ax + b = y²` (0 when
/// `is_pai` — and also 0 when `is_cert`, where the closure cert replaces
/// the trio).
pub const COL_U_PTR: usize = 8;
pub const COL_W_PTR: usize = 9;
/// Point-at-infinity flag.
pub const COL_IS_PAI: usize = 10;
/// `EcPoint` provide multiplicity.
pub const COL_ECPOINT_MULT: usize = 11;
/// Row-active flag (pads are all-zero tail rows).
pub const COL_ACT: usize = 12;
/// Closure-cert flag: this finite point is a fresh group-law result whose
/// on-curve membership is discharged by consuming one
/// [`EcOnCurveCert`](crate::relations::BusId::EcOnCurveCert) (provided
/// by its minting `EcGroupAdd` op) *instead of* the MAC trio. Mutually
/// exclusive with `is_pai`; the trio gate drops on these rows.
pub const COL_IS_CERT: usize = 13;
pub const NUM_MAIN_COLS: usize = 14;

// Aux: the single LogUp running-sum column. Six fractions: the `EcPoint`
// provide, the `EcGroup` consume, the three trio MAC consumes (finite,
// non-cert rows) and the one cert consume (finite, cert rows) — the trio
// and the cert are mutually-exclusive membership modes.
const NUM_LOGUP_COLS: usize = 1;
const AUX_WIDTH: usize = 1;
const COLUMN_SHAPE: [usize; NUM_LOGUP_COLS] = [6];

// AIR
// ================================================================================================

#[derive(Debug, Default, Clone, Copy)]
pub struct EcPointStoreAir;

impl BaseAir<Felt> for EcPointStoreAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

impl LiftedAir<Felt, QuadFelt> for EcPointStoreAir {
    fn num_randomness(&self) -> usize {
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        AUX_WIDTH
    }

    fn num_aux_values(&self) -> usize {
        NUM_SIGMA_VALUES
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        trace::build_points_aux(main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let next: [AB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);

        let is_pai: AB::Expr = local[COL_IS_PAI].into();
        let is_cert: AB::Expr = local[COL_IS_CERT].into();
        let act: AB::Expr = local[COL_ACT].into();
        let act_next: AB::Expr = next[COL_ACT].into();
        let ptr: AB::Expr = local[COL_PTR].into();
        let ptr_next: AB::Expr = next[COL_PTR].into();

        // Booleanity.
        builder.assert_zero(is_pai.clone() * (AB::Expr::ONE - is_pai.clone()));
        builder.assert_zero(is_cert.clone() * (AB::Expr::ONE - is_cert.clone()));
        builder.assert_zero(act.clone() * (AB::Expr::ONE - act.clone()));
        // A cert point is finite — the two membership modes are exclusive.
        builder.assert_zero(is_pai.clone() * is_cert.clone());

        // PAI rows reference no uints: coordinate / transient ptrs are the
        // none-sentinel.
        for col in [COL_X_PTR, COL_Y_PTR, COL_U_PTR, COL_W_PTR] {
            let cell: AB::Expr = local[col].into();
            builder.assert_zero(is_pai.clone() * cell);
        }
        // Cert rows carry real coordinates but no MAC transients — the trio
        // ptrs are the none-sentinel (the cert discharges membership instead).
        for col in [COL_U_PTR, COL_W_PTR] {
            let cell: AB::Expr = local[col].into();
            builder.assert_zero(is_cert.clone() * cell);
        }
        // Inactive rows cannot provide phantom EcPoint tuples: their group and
        // membership consumes are act-gated, while the provide self-gates via
        // this multiplicity cell.
        let point_mult: AB::Expr = local[COL_ECPOINT_MULT].into();
        builder.assert_zero((AB::Expr::ONE - act.clone()) * point_mult);

        // act is monotone (pads only at the tail; the wrap is dropped so
        // the cyclic last → first edge stays free)…
        builder
            .when_transition()
            .assert_zero((AB::Expr::ONE - act.clone()) * act_next.clone());
        // …and ptrs are consecutive along the active prefix, starting at 1
        // (an all-pad trace starts at 0).
        builder
            .when_transition()
            .assert_zero(act_next * (ptr_next - ptr.clone() - AB::Expr::ONE));
        builder.when_first_row().assert_zero(ptr - act);

        // Phase 2: LogUp.
        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

// LOOKUP AIR
// ================================================================================================

impl<LB> LookupAir<LB> for EcPointStoreAir
where
    LB: LookupBuilder<F = Felt>,
{
    fn num_columns(&self) -> usize {
        NUM_LOGUP_COLS
    }

    fn column_shape(&self) -> &[usize] {
        &COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        NUM_BUS_IDS
    }

    fn eval(&self, builder: &mut LB) {
        let local: [LB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);

        let ptr: LB::Expr = local[COL_PTR].into();
        let group_ptr: LB::Expr = local[COL_GROUP_PTR].into();
        let a_ptr: LB::Expr = local[COL_A_PTR].into();
        let b_ptr: LB::Expr = local[COL_B_PTR].into();
        let bound_ptr: LB::Expr = local[COL_BOUND_PTR].into();
        let sbound_ptr: LB::Expr = local[COL_SBOUND_PTR].into();
        let x_ptr: LB::Expr = local[COL_X_PTR].into();
        let y_ptr: LB::Expr = local[COL_Y_PTR].into();
        let u_ptr: LB::Expr = local[COL_U_PTR].into();
        let w_ptr: LB::Expr = local[COL_W_PTR].into();
        let is_pai: LB::Expr = local[COL_IS_PAI].into();
        let is_cert: LB::Expr = local[COL_IS_CERT].into();
        let act: LB::Expr = local[COL_ACT].into();

        // Pads zero the mult cell, so the provide needs no act gate; the
        // consumes do (an all-zero pad row must touch no bus). The trio fires
        // on finite, non-cert rows; the cert consume on finite cert rows —
        // disjoint, partitioning a finite point's one membership obligation.
        let neg_mult: LB::Expr = LB::Expr::ZERO - local[COL_ECPOINT_MULT].into();
        let member_flag: LB::Expr =
            act.clone() * (LB::Expr::ONE - is_pai.clone()) * (LB::Expr::ONE - is_cert.clone());
        let cert_flag: LB::Expr = act.clone() * is_cert;

        let one: LB::Expr = LB::Expr::ONE;
        let zero: LB::Expr = LB::Expr::ZERO;

        let provide_deg = Deg { v: 1, u: 1 };
        let consume_deg = Deg { v: 1, u: 1 };
        let member_deg = Deg { v: 3, u: 1 };
        let cert_deg = Deg { v: 2, u: 1 };
        let col_deg = Deg { v: 8, u: 6 };

        builder.next_column(
            |col| {
                col.group(
                    "ec-points",
                    |g| {
                        g.batch(
                            "ec-point-fractions",
                            LB::Expr::ONE,
                            |b| {
                                // The point binding…
                                b.insert(
                                    "provide-ecpoint",
                                    neg_mult,
                                    EcPointMsg {
                                        point_ptr: ptr.clone(),
                                        group_ptr: group_ptr.clone(),
                                        x_ptr: x_ptr.clone(),
                                        y_ptr: y_ptr.clone(),
                                        is_pai: is_pai.clone(),
                                    },
                                    provide_deg,
                                );
                                // …consumes its group's binding (forcing
                                // group_ptr onto a real group row and the
                                // a/b/bound/sbound cells onto its context —
                                // for PAI rows the only tie to a real
                                // group)…
                                b.insert(
                                    "consume-ecgroup",
                                    act,
                                    EcGroupMsg {
                                        group_ptr: group_ptr.clone(),
                                        a_ptr: a_ptr.clone(),
                                        b_ptr: b_ptr.clone(),
                                        bound_ptr: bound_ptr.clone(),
                                        scalar_bound_ptr: sbound_ptr.clone(),
                                    },
                                    consume_deg,
                                );
                                // …and, when finite, the curve-membership
                                // MAC trio (shared r_ptr = w makes
                                // y² = x³ + ax + b an identity of stored
                                // values).
                                b.insert(
                                    "consume-mac-u",
                                    member_flag.clone(),
                                    UintMulMsg {
                                        kappa_a: one.clone(),
                                        kappa_c: one.clone(),
                                        a_ptr: x_ptr.clone(),
                                        b_ptr: x_ptr.clone(),
                                        c_ptr: a_ptr.clone(),
                                        r_ptr: u_ptr.clone(),
                                        bound_ptr: bound_ptr.clone(),
                                        is_sub: LB::Expr::ZERO,
                                    },
                                    member_deg,
                                );
                                b.insert(
                                    "consume-mac-w",
                                    member_flag.clone(),
                                    UintMulMsg {
                                        kappa_a: one.clone(),
                                        kappa_c: one.clone(),
                                        a_ptr: x_ptr.clone(),
                                        b_ptr: u_ptr.clone(),
                                        c_ptr: b_ptr.clone(),
                                        r_ptr: w_ptr.clone(),
                                        bound_ptr: bound_ptr.clone(),
                                        is_sub: LB::Expr::ZERO,
                                    },
                                    member_deg,
                                );
                                b.insert(
                                    "consume-mac-y",
                                    member_flag,
                                    UintMulMsg {
                                        kappa_a: one,
                                        kappa_c: zero,
                                        a_ptr: y_ptr.clone(),
                                        b_ptr: y_ptr.clone(),
                                        c_ptr: bound_ptr.clone(),
                                        r_ptr: w_ptr.clone(),
                                        bound_ptr: bound_ptr.clone(),
                                        is_sub: LB::Expr::ZERO,
                                    },
                                    member_deg,
                                );
                                // …or, for a fresh group-law result, one
                                // closure cert in place of the trio: `r` is
                                // on-curve because `r = p + q` for on-curve
                                // operands (the minting op's own block), and
                                // the ptr ordering grounds the induction.
                                b.insert(
                                    "consume-ecgroupadd-cert",
                                    cert_flag,
                                    EcOnCurveCertMsg {
                                        group_ptr: group_ptr.clone(),
                                        r_ptr: ptr.clone(),
                                    },
                                    cert_deg,
                                );
                            },
                            col_deg,
                        );
                    },
                    col_deg,
                );
            },
            col_deg,
        );
    }
}
