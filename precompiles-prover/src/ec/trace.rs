//! EC store trace generation + aux builders — the group table and the
//! point store, fed by one [`EcStoreRequires`] accumulator.
//!
//! One row per entity in each store, allocator-consecutive ptrs from 1
//! in **separate group / point namespaces**, all-zero pad rows to a
//! power-of-two height. The membership MACs themselves are recorded
//! into [`UintMulRequires`](crate::uint::mul::trace::UintMulRequires)
//! by [`EcRequire`](crate::ec::require::EcRequire) at point-creation
//! time (with their provides `require`d); this module only lays the
//! binding rows and their demand ledgers.
//!
//! The **scalar bound** is per-group state: `None` until something
//! constrains the scalar field (recorded via
//! [`EcStoreRequires::set_scalar_bound`]), resolving at trace-gen to
//! the group's own `bound` when still vacuous — every consumer reads
//! the resolved handle through [`EcStoreRequires::group_sbound`], so
//! the tuple is identical across the group row and all its consumes.

use std::collections::{BTreeMap, HashMap};

use miden_core::{Felt, field::QuadFelt};
use p3_matrix::dense::RowMajorMatrix;

use super::{
    COL_A_PTR, COL_ACT, COL_B_PTR, COL_BOUND_PTR, COL_ECPOINT_MULT, COL_GROUP_PTR, COL_IS_CERT,
    COL_IS_PAI, COL_PTR, COL_SBOUND_PTR, COL_U_PTR, COL_W_PTR, COL_X_PTR, COL_Y_PTR,
    EcPointStoreAir, NUM_MAIN_COLS,
    groups::{
        COL_A_PTR as G_COL_A_PTR, COL_B_PTR as G_COL_B_PTR, COL_BOUND_PTR as G_COL_BOUND_PTR,
        COL_MULT as G_COL_MULT, COL_PTR as G_COL_PTR, COL_SBOUND_PTR as G_COL_SBOUND_PTR,
        EcGroupsAir, NUM_MAIN_COLS as G_NUM_MAIN_COLS,
    },
};
use crate::{logup::build_logup_aux_trace, relations::ProvideMult, uint::trace::UintPtr};

/// Handle to a stored EC group — minted only by
/// [`EcStoreRequires::create_group`], so holding one is proof the group
/// row exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EcGroupPtr(u32);

impl EcGroupPtr {
    /// The raw store address (trace cells, diagnostics).
    pub fn addr(self) -> u32 {
        self.0
    }

    /// Reconstruct a handle from a raw address — for the MSM layer (whose
    /// `EcGroupAdd` consumes name groups by ptr) and tests.
    pub fn from_addr(addr: u32) -> Self {
        Self(addr)
    }
}

/// Handle to a stored EC point — minted only by the point entries
/// ([`EcStoreRequires::add_point`] / [`EcStoreRequires::add_pai`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EcPointPtr(u32);

impl EcPointPtr {
    /// The raw store address (trace cells, diagnostics).
    pub fn addr(self) -> u32 {
        self.0
    }

    /// Reconstruct a handle from a raw address — for the MSM layer (whose
    /// `MsmTerm` / `EcGroupAdd` consumes name points by ptr) and tests.
    pub fn from_addr(addr: u32) -> Self {
        Self(addr)
    }
}

/// A group-table entry: the curve params + base-field bound, and the
/// scalar bound once something constrains it (`None` = vacuous,
/// resolving to `bound` at trace-gen).
#[derive(Debug, Clone, Copy)]
struct Group {
    a: UintPtr,
    b: UintPtr,
    bound: UintPtr,
    scalar_bound: Option<UintPtr>,
}

/// A finite point's uint bindings: coordinates plus its membership
/// certificate. `membership = Some((u, w))` is the on-curve MAC trio's
/// transients (`u = x² + a`, `w = x³ + ax + b = y²`); `None` marks a
/// **closure-cert** point — a fresh group-law result whose membership is
/// discharged by an [`EcOnCurveCert`](crate::relations::BusId::EcOnCurveCert)
/// consume instead, so it carries no trio transients.
#[derive(Debug, Clone, Copy)]
struct PointBinding {
    x: UintPtr,
    y: UintPtr,
    membership: Option<(UintPtr, UintPtr)>,
}

/// A point-store entry (`binding = None` = the point at infinity, laid
/// as the 0 none-sentinels).
#[derive(Debug, Clone, Copy)]
struct Point {
    group: EcGroupPtr,
    binding: Option<PointBinding>,
}

/// `*Requires` accumulator for the EC stores: the group and point
/// ledgers (each ptr = position + 1 in its own namespace) plus the
/// `EcGroup` / `EcPoint` demand ledgers. The entries are the only
/// [`EcGroupPtr`] / [`EcPointPtr`] constructors.
#[derive(Debug, Default)]
pub struct EcStoreRequires {
    groups: Vec<Group>,
    points: Vec<Point>,
    /// Canonical-dedup reverse index for finite points: equal
    /// `(group, x, y)` shares one row, mirroring the uint store's
    /// `by_value` (honest-prover dedup — a value-dedup'd add result
    /// lands on its existing certified row, demanding no fresh
    /// membership).
    by_coords: HashMap<(EcGroupPtr, UintPtr, UintPtr), EcPointPtr>,
    /// Canonical-dedup reverse index for groups: an equal curve
    /// `(a, b, bound)` shares one group row. The DAG layer creates a
    /// point's group per `EcCreate` node, so identical curves must
    /// collapse to one `group_ptr` (else operands land on distinct
    /// groups and the add's same-group assertion fails); bare callers
    /// that create each group once are unaffected.
    by_curve: HashMap<(UintPtr, UintPtr, UintPtr), EcGroupPtr>,
    group_demand: BTreeMap<EcGroupPtr, ProvideMult>,
    point_demand: BTreeMap<EcPointPtr, ProvideMult>,
    /// Each group's canonical PAI row (deduped per group) — the
    /// well-defined result ptr for the add relation's `cancel` case.
    pai_rows: BTreeMap<EcGroupPtr, EcPointPtr>,
}

impl EcStoreRequires {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind a group to its curve params (uints sharing the modulus at
    /// `bound`). The scalar bound starts vacuous. **Deduped by the curve
    /// `(a, b, bound)`** — a repeat returns the existing group (its PAI
    /// rides [`add_pai`](Self::add_pai)'s own per-group dedup). Returns
    /// the group's handle.
    pub fn create_group(&mut self, a: UintPtr, b: UintPtr, bound: UintPtr) -> EcGroupPtr {
        if let Some(&existing) = self.by_curve.get(&(a, b, bound)) {
            return existing;
        }
        let ptr = EcGroupPtr(self.groups.len() as u32 + 1);
        self.groups.push(Group { a, b, bound, scalar_bound: None });
        self.by_curve.insert((a, b, bound), ptr);
        ptr
    }

    /// Constrain the group's scalar field: from here on the group tuple
    /// carries `sbound` as its scalar-bound handle (the stored `n − 1`
    /// of the group order — the modulus scalar arithmetic runs under).
    /// Idempotent on the same handle; panics on a conflicting one.
    pub fn set_scalar_bound(&mut self, group: EcGroupPtr, sbound: UintPtr) {
        let entry = &mut self.groups[group.0 as usize - 1].scalar_bound;
        match entry {
            None => *entry = Some(sbound),
            Some(prev) => assert_eq!(*prev, sbound, "conflicting scalar bound for the group"),
        }
    }

    /// Bind a finite point `(x, y)` of `group`, with `u`/`w` the
    /// membership transients (`u = x² + a`, `w = x³ + ax + b = y²`) whose
    /// MACs the caller has recorded + `require`d. **Canonically deduped**
    /// by `(group, x, y)`: an equal point returns its existing row (no
    /// new row, no second `EcGroup` consume) — the caller skips the
    /// membership recording on a hit (see
    /// [`point_by_coords`](Self::point_by_coords)). Returns the point's
    /// handle.
    pub fn add_point(
        &mut self,
        group: EcGroupPtr,
        x: UintPtr,
        y: UintPtr,
        u: UintPtr,
        w: UintPtr,
    ) -> EcPointPtr {
        if let Some(&existing) = self.by_coords.get(&(group, x, y)) {
            return existing;
        }
        *self.group_demand.entry(group).or_insert(0) += 1;
        let ptr = EcPointPtr(self.points.len() as u32 + 1);
        self.points.push(Point {
            group,
            binding: Some(PointBinding { x, y, membership: Some((u, w)) }),
        });
        self.by_coords.insert((group, x, y), ptr);
        ptr
    }

    /// Bind a finite point `(x, y)` as a **closure-cert** point — a fresh
    /// group-law result whose membership rides an
    /// [`EcOnCurveCert`](crate::relations::BusId::EcOnCurveCert) consume
    /// (no MAC trio). **Canonically deduped** by `(group, x, y)`, returning
    /// `(ptr, minted)`: `minted = true` only on a fresh row (the caller is
    /// the op that owns the cert and must provide it); on a hit the existing
    /// row — already certified by *its* minting op or by an eager trio —
    /// is reused with `minted = false`, so no second cert is provided.
    pub fn add_point_cert(
        &mut self,
        group: EcGroupPtr,
        x: UintPtr,
        y: UintPtr,
    ) -> (EcPointPtr, bool) {
        if let Some(&existing) = self.by_coords.get(&(group, x, y)) {
            return (existing, false);
        }
        *self.group_demand.entry(group).or_insert(0) += 1;
        let ptr = EcPointPtr(self.points.len() as u32 + 1);
        self.points.push(Point {
            group,
            binding: Some(PointBinding { x, y, membership: None }),
        });
        self.by_coords.insert((group, x, y), ptr);
        (ptr, true)
    }

    /// The existing finite point at `(group, x, y)`, if any — the gate
    /// the require layer checks before recording membership, so a
    /// deduped point pays no second MAC trio.
    pub fn point_by_coords(
        &self,
        group: EcGroupPtr,
        x: UintPtr,
        y: UintPtr,
    ) -> Option<EcPointPtr> {
        self.by_coords.get(&(group, x, y)).copied()
    }

    /// Bind the group's point-at-infinity row (coordinate ptrs are the
    /// none-sentinel; no membership). **Deduped per group** — every
    /// `add_pai` of a group returns its one canonical PAI row (see
    /// [`Self::group_pai`]).
    pub fn add_pai(&mut self, group: EcGroupPtr) -> EcPointPtr {
        if let Some(&existing) = self.pai_rows.get(&group) {
            return existing;
        }
        *self.group_demand.entry(group).or_insert(0) += 1;
        let ptr = EcPointPtr(self.points.len() as u32 + 1);
        self.points.push(Point { group, binding: None });
        self.pai_rows.insert(group, ptr);
        ptr
    }

    /// Record one external consumer of the group's `EcGroup` tuple
    /// (e.g. an add op resolving the curve's `a`).
    pub fn require_ecgroup(&mut self, group: EcGroupPtr) {
        *self.group_demand.entry(group).or_insert(0) += 1;
    }

    /// Record one external consumer of the point's `EcPoint` tuple
    /// (e.g. an add op's operand).
    pub fn require_ecpoint(&mut self, point: EcPointPtr) {
        *self.point_demand.entry(point).or_insert(0) += 1;
    }

    /// The group's `(a, b, bound)` binding.
    pub fn group_params(&self, group: EcGroupPtr) -> (UintPtr, UintPtr, UintPtr) {
        let g = &self.groups[group.0 as usize - 1];
        (g.a, g.b, g.bound)
    }

    /// The group's **resolved** scalar-bound handle: the constrained
    /// `F_s` modulus if set, else (vacuously) the group's own `bound` —
    /// the value every `EcGroup` tuple site lays in its trace cell.
    pub fn group_sbound(&self, group: EcGroupPtr) -> UintPtr {
        let g = &self.groups[group.0 as usize - 1];
        g.scalar_bound.unwrap_or(g.bound)
    }

    /// The point's group plus its coordinate handles — `None` for the
    /// point at infinity.
    pub fn point_params(&self, point: EcPointPtr) -> (EcGroupPtr, Option<(UintPtr, UintPtr)>) {
        let p = &self.points[point.0 as usize - 1];
        (p.group, p.binding.map(|b| (b.x, b.y)))
    }

    /// The group's canonical PAI row — the add relation's `cancel`-case
    /// result (and the `∞ + ∞` fixed point).
    pub fn group_pai(&self, group: EcGroupPtr) -> EcPointPtr {
        self.pai_rows
            .get(&group)
            .copied()
            .unwrap_or_else(|| panic!("group {} has no PAI row", group.0))
    }
}

/// Build **both** EC store main traces from the accumulator (consumed —
/// trace-gen is terminal, so the double-lay hazard is a compile error),
/// returning `(groups_main, points_main)` in
/// [`SessionTraces`](crate::session::SessionTraces) order. Pure reads of
/// the demand ledgers: every cross-chiplet consumer has already fed them
/// — the points' own `EcGroup` consume at intern (the store's
/// bound-ref analogue), the add relation's `EcGroup` / `EcPoint`
/// consumes in [`super::add::trace::generate_trace`], run first by the
/// Session sweep.
pub fn generate_traces(
    requires: EcStoreRequires,
) -> (RowMajorMatrix<Felt>, RowMajorMatrix<Felt>) {
    (groups_trace(&requires), points_trace(&requires))
}

/// The group table — one row per group in allocation order, padded to a
/// power-of-two height (min 2). The ungated chain forces `ptr = row + 1`
/// on every row, so pads carry their ptr too — they are simply rows
/// whose `mult` (and params) stay zero, touching no bus.
fn groups_trace(requires: &EcStoreRequires) -> RowMajorMatrix<Felt> {
    let height = requires.groups.len().next_power_of_two().max(2);
    let mut vals = Vec::with_capacity(height * G_NUM_MAIN_COLS);

    for i in 0..height {
        let ptr = i as u32 + 1;
        let mut row = [Felt::ZERO; G_NUM_MAIN_COLS];
        row[G_COL_PTR] = Felt::from(ptr);
        if let Some(group) = requires.groups.get(i) {
            row[G_COL_A_PTR] = Felt::from(group.a.addr());
            row[G_COL_B_PTR] = Felt::from(group.b.addr());
            row[G_COL_BOUND_PTR] = Felt::from(group.bound.addr());
            row[G_COL_SBOUND_PTR] = Felt::from(group.scalar_bound.unwrap_or(group.bound).addr());
            row[G_COL_MULT] =
                Felt::from(requires.group_demand.get(&EcGroupPtr(ptr)).copied().unwrap_or(0));
        }
        vals.extend(row);
    }

    RowMajorMatrix::new(vals, G_NUM_MAIN_COLS)
}

/// The point store — one row per point in allocation order
/// (ptr = row + 1), padded to a power-of-two height (min 2) with
/// all-zero (`act = 0`) rows that touch no bus.
fn points_trace(requires: &EcStoreRequires) -> RowMajorMatrix<Felt> {
    let height = requires.points.len().next_power_of_two().max(2);
    let mut vals = Vec::with_capacity(height * NUM_MAIN_COLS);

    for (i, point) in requires.points.iter().enumerate() {
        let ptr = i as u32 + 1;
        let (a, b, bound) = requires.group_params(point.group);
        let mut row = [Felt::ZERO; NUM_MAIN_COLS];
        row[COL_PTR] = Felt::from(ptr);
        row[COL_GROUP_PTR] = Felt::from(point.group.addr());
        row[COL_A_PTR] = Felt::from(a.addr());
        row[COL_B_PTR] = Felt::from(b.addr());
        row[COL_BOUND_PTR] = Felt::from(bound.addr());
        row[COL_SBOUND_PTR] = Felt::from(requires.group_sbound(point.group).addr());
        row[COL_X_PTR] = Felt::from(point.binding.map_or(0, |b| b.x.addr()));
        row[COL_Y_PTR] = Felt::from(point.binding.map_or(0, |b| b.y.addr()));
        let membership = point.binding.and_then(|b| b.membership);
        row[COL_U_PTR] = Felt::from(membership.map_or(0, |(u, _)| u.addr()));
        row[COL_W_PTR] = Felt::from(membership.map_or(0, |(_, w)| w.addr()));
        row[COL_IS_PAI] = Felt::from(point.binding.is_none() as u32);
        // Closure-cert points are finite (binding Some) with no trio.
        row[COL_IS_CERT] = Felt::from(point.binding.is_some_and(|b| b.membership.is_none()) as u32);
        row[COL_ECPOINT_MULT] =
            Felt::from(requires.point_demand.get(&EcPointPtr(ptr)).copied().unwrap_or(0));
        row[COL_ACT] = Felt::ONE;
        vals.extend(row);
    }
    // Pad to the power-of-two height with all-zero (act = 0) rows.
    vals.resize(height * NUM_MAIN_COLS, Felt::ZERO);

    RowMajorMatrix::new(vals, NUM_MAIN_COLS)
}

/// Aux-trace builder for [`EcGroupsAir`] — the aux trace is exactly the
/// LogUp column.
pub(crate) fn build_groups_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    build_logup_aux_trace(&EcGroupsAir, main, challenges)
}

/// Aux-trace builder for [`EcPointStoreAir`] — the aux trace is exactly
/// the LogUp column.
pub(crate) fn build_points_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    build_logup_aux_trace(&EcPointStoreAir, main, challenges)
}
