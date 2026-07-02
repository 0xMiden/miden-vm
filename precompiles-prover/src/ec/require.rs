//! [`EcRequire`] — the EC layer's recording facade.
//!
//! A transient view over the two EC chiplet accumulators (group/point
//! store + group-law add relation) and the [`UintRequire`] layer below,
//! hiding the full cross-chiplet plumbing of the EC operations: curve
//! coordinates enter by *value* and are interned canonically; membership
//! MACs, group-law certificates and the EcGroupAdd block itself are
//! recorded with their demand routed — a caller only ever sees group /
//! point ptr handles.

use crate::{
    ec::{
        add::trace::{EcAddCase, EcAddOp, EcAddRequires},
        trace::{EcGroupPtr, EcPointPtr, EcStoreRequires},
    },
    math::{U256, add_reduce, mac_reduce, mod_inv, sub_reduce},
    relations::ProvideMult,
    uint::{UintRequire, trace::UintPtr},
};

/// Borrowed view over the EC chiplet accumulators plus the uint layer;
/// construct one per recording burst.
#[derive(Debug)]
pub struct EcRequire<'a> {
    store: &'a mut EcStoreRequires,
    add: &'a mut EcAddRequires,
    uint: UintRequire<'a>,
}

impl<'a> EcRequire<'a> {
    pub fn new(
        store: &'a mut EcStoreRequires,
        add: &'a mut EcAddRequires,
        uint: UintRequire<'a>,
    ) -> Self {
        Self { store, add, uint }
    }

    /// Bind a short-Weierstrass group `y² = x³ + ax + b` over the field
    /// whose modulus is `bound`, interning the curve params and laying
    /// the group's canonical point-at-infinity row. Returns
    /// `(group, pai)`.
    ///
    /// Asserts `b ≠ 0` — the EcCreate guard that keeps `(0, 0)` off
    /// the curve, so the DAG may encode PAI as zero coordinates.
    ///
    /// VM-owned fixed groups are preseeded with their canonical scalar
    /// bound. An ad-hoc group's **scalar bound** starts vacuous (the tuple
    /// carries the `F_p` handle) until
    /// [`constrain_scalar_bound`](Self::constrain_scalar_bound) names
    /// the scalar-field modulus.
    pub fn create_group(&mut self, a: U256, b: U256, bound: UintPtr) -> (EcGroupPtr, EcPointPtr) {
        assert_ne!(b, U256::ZERO, "b = 0 puts (0,0) on the curve");
        let a_ptr = self.uint.intern(a, bound);
        let b_ptr = self.uint.intern(b, bound);
        let group = self.store.create_group(a_ptr, b_ptr, bound);
        let pai = self.store.add_pai(group);
        (group, pai)
    }

    /// Constrain the group's scalar field: `sbound` is the stored
    /// `n − 1` of the group order — the modulus scalar arithmetic
    /// (addition-chain exponents, ladder scalars) runs under. Until the
    /// first call the group tuple vacuously carries its `F_p` handle;
    /// mathematically `(a, b, p)` determines `F_s`, so this names a
    /// value, it never chooses one. Idempotent on the same handle.
    pub fn constrain_scalar_bound(&mut self, group: EcGroupPtr, sbound: UintPtr) {
        self.store.set_scalar_bound(group, sbound);
    }

    /// Bind a finite point `(x, y)` of the group, interning the
    /// coordinates in the group's field and proving curve membership via
    /// the MAC trio (`u ≡ x² + a`, `w ≡ x·u + b`, `w ≡ y²` — the shared
    /// `r_ptr = w` makes `y² = x³ + ax + b` an identity of stored
    /// values). Returns the point's handle. Panics if `(x, y)` is not on
    /// the curve.
    pub fn add_point(&mut self, group: EcGroupPtr, x: U256, y: U256) -> EcPointPtr {
        let (_, _, bound) = self.store.group_params(group);
        let x_ptr = self.uint.intern(x, bound);
        let y_ptr = self.uint.intern(y, bound);
        self.add_point_at(group, x_ptr, y_ptr)
    }

    /// [`add_point`](Self::add_point) over already-interned coordinate
    /// handles — the **eager-membership** entry (the MAC trio), shared by
    /// the direct point constructors and the `sub` / `neg` operand
    /// witnesses. The group law's *result* takes the cheaper
    /// [`add_point_cert`](crate::ec::trace::EcStoreRequires::add_point_cert)
    /// path instead. **Dedup-aware**: an equal `(group, x, y)` already
    /// stored returns its row and records *no* membership (paid once at
    /// first creation) — mirroring the uint store's intern-on-hit.
    fn add_point_at(&mut self, group: EcGroupPtr, x: UintPtr, y: UintPtr) -> EcPointPtr {
        if let Some(existing) = self.store.point_by_coords(group, x, y) {
            return existing;
        }
        let (a, b, bound) = self.store.group_params(group);
        let u = self.uint.mac(1, x, x, 1, a);
        let w = self.uint.mac(1, x, u, 1, b);
        // y² ≡ w, the dummy addend riding the modulus ptr under κ_c = 0.
        self.uint.mac_into(1, y, y, 0, bound, w);
        self.store.add_point(group, x, y, u, w)
    }

    /// A curve point from already-interned handles on an existing group row
    /// — the EC-DAG entry a `EcCreate` node lowers to once the transcript API
    /// names `group_ptr` directly. The group's `(a, b, bound)` metadata is
    /// read from the EC store; the canonical PAI is materialized for later
    /// group-law cancel/pass-through cases, then the finite point pays eager
    /// membership. The create row consumes the resulting `EcPoint` tuple; the
    /// point-store row itself consumes the `EcGroup` tuple, so this helper does
    /// not add a separate create-row `EcGroup` consume.
    pub fn point_on_group(
        &mut self,
        group: EcGroupPtr,
        x_ptr: UintPtr,
        y_ptr: UintPtr,
    ) -> EcPointPtr {
        let (_, b_ptr, _) = self.store.group_params(group);
        assert_ne!(self.uint.value(b_ptr), U256::ZERO, "b = 0 puts (0,0) on the curve");
        self.store.add_pai(group);
        let point = self.add_point_at(group, x_ptr, y_ptr);
        self.store.require_ecpoint(point);
        point
    }

    /// The group's point-at-infinity from an existing group row — the
    /// EC-DAG entry a `EcCreate`/PAI node lowers to once the transcript API
    /// names `group_ptr` directly. Routes the eval row's `EcPoint(∞)` demand;
    /// the PAI point-store row consumes the `EcGroup` tuple.
    pub fn pai_on_group(&mut self, group: EcGroupPtr) -> EcPointPtr {
        let (_, b_ptr, _) = self.store.group_params(group);
        assert_ne!(self.uint.value(b_ptr), U256::ZERO, "b = 0 puts (0,0) on the curve");
        let pai = self.store.add_pai(group);
        self.store.require_ecpoint(pai);
        pai
    }

    /// A curve point from already-interned handles — the legacy coefficient
    /// entry retained for direct callers/tests. Creates/dedups the group
    /// `(a, b, bound)`, then delegates the point work to
    /// [`point_on_group`](Self::point_on_group).
    pub fn point_on_curve(
        &mut self,
        a_ptr: UintPtr,
        b_ptr: UintPtr,
        bound: UintPtr,
        x_ptr: UintPtr,
        y_ptr: UintPtr,
    ) -> (EcGroupPtr, EcPointPtr) {
        assert_ne!(self.uint.value(b_ptr), U256::ZERO, "b = 0 puts (0,0) on the curve");
        let group = self.store.create_group(a_ptr, b_ptr, bound);
        let point = self.point_on_group(group, x_ptr, y_ptr);
        (group, point)
    }

    /// The group's point-at-infinity from already-interned curve handles — the
    /// legacy coefficient entry retained for direct callers/tests.
    /// Creates/dedups the group `(a, b, bound)`, then delegates to
    /// [`pai_on_group`](Self::pai_on_group).
    pub fn pai_on_curve(
        &mut self,
        a_ptr: UintPtr,
        b_ptr: UintPtr,
        bound: UintPtr,
    ) -> (EcGroupPtr, EcPointPtr) {
        assert_ne!(self.uint.value(b_ptr), U256::ZERO, "b = 0 puts (0,0) on the curve");
        let group = self.store.create_group(a_ptr, b_ptr, bound);
        let pai = self.pai_on_group(group);
        (group, pai)
    }

    /// The group law `R = P + Q` over stored points: select the case
    /// from the operands' values, record the per-case certificate
    /// arrangements into the uint relation chiplets, lay one EcGroupAdd
    /// block, and return `R`'s ptr — the other operand for the `pai`
    /// pass-throughs, the group's canonical PAI row for `cancel`, and a
    /// fresh eager-membership store point for the live formulas.
    ///
    /// **Interns by relation identity** `(group, p, q)`: a repeat returns
    /// the recorded result and re-derives nothing — no second case
    /// selection, no second set of certificates (its `EcGroupAdd` tuple
    /// just counts another consumer). The provide multiplicity is 0
    /// today (the tuple is dormant until the MSM / DAG layer consumes
    /// it); a consumer would pass its count here.
    fn add_inner(
        &mut self,
        group: EcGroupPtr,
        p: EcPointPtr,
        q: EcPointPtr,
        mult: ProvideMult,
    ) -> EcPointPtr {
        if let Some(r) = self.add.consume(group, p, q, mult) {
            return r;
        }

        let (a, b, bound) = self.store.group_params(group);
        let (p_group, p_coords) = self.store.point_params(p);
        let (q_group, q_coords) = self.store.point_params(q);
        assert!(p_group == group && q_group == group, "add operands must belong to the group");

        // Case selection by value; the AIR re-derives the claim
        // adversarially from the flags + the per-case certificate
        // demands.
        let (case, r, transients, mints) = match (p_coords, q_coords) {
            (None, None) => {
                // ∞ + ∞: both pass flags ride the consumed tuples, and
                // the AIR's ties force `p = q = r`.
                assert_eq!(p, q, "∞ + ∞ takes the canonical PAI twice");
                (EcAddCase::PaiBoth, p, None, false)
            },
            (None, Some(_)) => (EcAddCase::PaiP, q, None, false),
            (Some(_), None) => (EcAddCase::PaiQ, p, None, false),
            (Some((px, py)), Some((qx, qy))) => {
                let bound_v = self.uint.value(bound);
                let b_v = self.uint.value(b);
                let (x1, y1) = (self.uint.value(px), self.uint.value(py));
                let (x2, y2) = (self.uint.value(qx), self.uint.value(qy));

                if x1 != x2 {
                    // generic: d = x₂ − x₁, the chord λ·d + y₁ ≡ y₂ with
                    // λ = (y₂ − y₁)·d⁻¹ interned, and the disequality
                    // witness inv = b·d⁻¹ certified by inv·d ≡ b ≠ 0 —
                    // what pins λ to the unique chord slope.
                    let d = self.uint.sub(qx, px);
                    let d_inv = mod_inv(sub_reduce(x2, x1, bound_v), bound_v);
                    let dy = sub_reduce(y2, y1, bound_v);
                    let lambda_val = mac_reduce(1, dy, d_inv, 0, U256::ZERO, bound_v);
                    let lambda = self.uint.intern(lambda_val, bound);
                    self.uint.mac_into(1, lambda, d, 1, py, qy);
                    let inv_val = mac_reduce(1, b_v, d_inv, 0, U256::ZERO, bound_v);
                    let inv = self.uint.intern(inv_val, bound);
                    self.uint.mac_into(1, inv, d, 0, bound, b);
                    let (transients, r, fresh) = self.add_tail(d, lambda, inv, px, py, qx, group);
                    (EcAddCase::Generic, r, Some(transients), fresh)
                } else if add_reduce(y1, y2, bound_v) == U256::ZERO {
                    // cancel (covers `y = 0` 2-torsion doubling): the
                    // x-equality certificate + the `is_c_zero` negation
                    // tuple; `R` is the group's canonical PAI row.
                    self.uint.value_eq(px, qx);
                    self.uint.add_to_zero(py, qy);
                    (EcAddCase::Cancel, self.store.group_pai(group), None, false)
                } else {
                    // double: s ≡ 3x² + a and 2λy ≡ s (the κ's carry the
                    // tangent constants; shared r_ptr = s), λ = s·(2y)⁻¹,
                    // the equality certificates x₁ = x₂ / y₁ = y₂, and
                    // the nonzero witness inv = b·y₁⁻¹ certified by
                    // inv·y₁ ≡ b — the 2y denominator's invertibility.
                    debug_assert_eq!(y1, y2, "on-curve x₁ = x₂ forces y₂ = ±y₁");
                    let s = self.uint.mac(3, px, px, 1, a);
                    let s_v = self.uint.value(s);
                    let two_y_inv = mod_inv(add_reduce(y1, y1, bound_v), bound_v);
                    let lambda_val = mac_reduce(1, s_v, two_y_inv, 0, U256::ZERO, bound_v);
                    let lambda = self.uint.intern(lambda_val, bound);
                    self.uint.mac_into(2, lambda, py, 0, bound, s);
                    let inv_val = mac_reduce(1, b_v, mod_inv(y1, bound_v), 0, U256::ZERO, bound_v);
                    let inv = self.uint.intern(inv_val, bound);
                    self.uint.mac_into(1, inv, py, 0, bound, b);
                    self.uint.value_eq(px, qx);
                    self.uint.value_eq(py, qy);
                    let (transients, r, fresh) = self.add_tail(s, lambda, inv, px, py, qx, group);
                    (EcAddCase::Double, r, Some(transients), fresh)
                }
            },
        };

        // The op's cross-chiplet demand (the operands' / result's
        // `EcPoint`, the live case's `EcGroup`) is routed by the add
        // relation's trace pass, not here — one site, mult tracking the
        // laid blocks.
        self.add.record(
            EcAddOp {
                case,
                group,
                bound,
                a,
                b,
                p,
                q,
                r,
                p_coords,
                q_coords,
                transients,
                mints,
            },
            mult,
        );
        r
    }

    /// The group law `R = P + Q` over stored points — the recording
    /// layer's one add entry, shared by the eval `EcBinOp` row and the
    /// bare-`*Requires` tests. The group is derived from `p` (operands
    /// must share it). `mult` is the `EcGroupAdd` provide multiplicity =
    /// the consumer count: 1 per eval row, 0 when nothing consumes the
    /// tuple yet (the dormant EC-stack tests). Returns `R`.
    pub fn add(&mut self, p: EcPointPtr, q: EcPointPtr, mult: ProvideMult) -> EcPointPtr {
        let group = self.store.point_params(p).0;
        self.add_inner(group, p, q, mult)
    }

    /// The group a stored point belongs to — what a caller laying the op
    /// into its own row (the eval `EcBinOp` group-ptr cell) reads
    /// alongside the result of [`add`](Self::add).
    pub fn group_of(&self, p: EcPointPtr) -> EcGroupPtr {
        self.store.point_params(p).0
    }

    /// The group law `R = P − Q` over stored points, laid as the
    /// *rearranged* relation `R + Q = P` — one `EcGroupAdd` block, the EC
    /// parallel of [`UintRequire::sub`](crate::uint::UintRequire::sub)'s
    /// `y + z = x`. The witness `R` (value-only
    /// `sub_value`) is interned, then
    /// `add_inner` for `(R, Q)` re-derives and
    /// *certifies* `R + Q`, deduping its result onto the existing `P` — so
    /// `R` is the block's bound operand, `P` its result. `mult` is the
    /// `EcGroupAdd` provide multiplicity (1 per eval `EcBinOp/Sub` row).
    /// Returns `R`.
    pub fn sub(&mut self, p: EcPointPtr, q: EcPointPtr, mult: ProvideMult) -> EcPointPtr {
        let group = self.store.point_params(p).0;
        let r = match self.sub_value(group, p, q) {
            // P = Q ⇒ R = ∞; `∞ + Q = P` rides add_inner's PaiP case.
            None => self.store.group_pai(group),
            Some((rx, ry)) => self.add_point(group, rx, ry),
        };
        let p_back = self.add_inner(group, r, q, mult);
        debug_assert_eq!(p_back, p, "R + Q must dedup onto P (sub rearrangement)");
        r
    }

    /// Value-only `R = P − Q = P + (−Q)` affine coordinates (`None` = ∞) —
    /// the witness [`sub`](Self::sub) interns before
    /// [`add_inner`](Self::add_inner) certifies `R + Q = P`. **Not a proof
    /// source**: a wrong `R` just fails to dedup onto `P` (debug-asserted,
    /// else the bus unbalances), so the curve math here is a hint — the
    /// authority stays the add relation's per-case certificates.
    fn sub_value(&self, group: EcGroupPtr, p: EcPointPtr, q: EcPointPtr) -> Option<(U256, U256)> {
        let p_coords = self.store.point_params(p).1;
        let q_coords = self.store.point_params(q).1;
        let (a, _, bound) = self.store.group_params(group);
        let m = self.uint.value(bound);
        match (p_coords, q_coords) {
            // Q = ∞ ⇒ R = P (also covers ∞ − ∞ = ∞ via the None map).
            (_, None) => p_coords.map(|(px, py)| (self.uint.value(px), self.uint.value(py))),
            // P = ∞ ⇒ R = −Q.
            (None, Some((qx, qy))) => {
                Some((self.uint.value(qx), sub_reduce(U256::ZERO, self.uint.value(qy), m)))
            },
            (Some((px, py)), Some((qx, qy))) => {
                let (x1, y1) = (self.uint.value(px), self.uint.value(py));
                let x2 = self.uint.value(qx);
                // The second operand is −Q: its y is negated.
                let y2 = sub_reduce(U256::ZERO, self.uint.value(qy), m);
                let lambda = if x1 != x2 {
                    // Generic chord between P and −Q.
                    let d_inv = mod_inv(sub_reduce(x2, x1, m), m);
                    mac_reduce(1, sub_reduce(y2, y1, m), d_inv, 0, U256::ZERO, m)
                } else if add_reduce(y1, y2, m) == U256::ZERO {
                    // P = Q ⇒ P − Q = ∞.
                    return None;
                } else {
                    // P = −Q ⇒ P − Q = 2P, the tangent at P.
                    let s = mac_reduce(3, x1, x1, 1, self.uint.value(a), m); // 3x₁² + a
                    mac_reduce(1, s, mod_inv(add_reduce(y1, y1, m), m), 0, U256::ZERO, m)
                };
                // x₃ = λ² − x₁ − x₂, y₃ = λ(x₁ − x₃) − y₁.
                let w = mac_reduce(1, lambda, lambda, 0, U256::ZERO, m);
                let x3 = sub_reduce(sub_reduce(w, x1, m), x2, m);
                let y3 = sub_reduce(
                    mac_reduce(1, lambda, sub_reduce(x1, x3, m), 0, U256::ZERO, m),
                    y1,
                    m,
                );
                Some((x3, y3))
            },
        }
    }

    /// Negate a point — the cancel-case primitive: intern `R = −P =
    /// (x, −y)` (eager membership) and record the cancel relation
    /// `P + R = ∞` at `EcGroupAdd` provide `mult` (one per cancel-relation
    /// consumer). Returns `(group, R, pai)`, where `pai` is the group's ∞
    /// row (the cancel result, the `EcGroupAdd` result-slot the consumer
    /// carries). The cancel block routes its own `EcGroup` /
    /// `EcPoint(P, R, ∞)` demand; the caller's `EcPoint(∞)` pin forces
    /// `R = −P`, since the `EcGroupAdd` bus alone carries no case flag and
    /// so doesn't pin the ∞ result slot. Route one more ∞ consume here for
    /// that pin.
    pub fn neg(
        &mut self,
        p: EcPointPtr,
        mult: ProvideMult,
    ) -> (EcGroupPtr, EcPointPtr, EcPointPtr) {
        let (group, coords) = self.store.point_params(p);
        let (px, py) = coords.expect("Neg of the point at infinity");
        let (_, _, bound) = self.store.group_params(group);
        // Intern −py's *value* (no relation) — the cancel block's
        // `add_to_zero(py, −py)` below is what certifies the negation. A
        // `uint.neg` here would mint a dangling `UintAdd` provide (no eval
        // consumer), unbalancing the bus.
        let neg_py_val = sub_reduce(U256::ZERO, self.uint.value(py), self.uint.value(bound));
        let neg_py = self.uint.intern(neg_py_val, bound);
        let r = self.add_point_at(group, px, neg_py);
        let pai = self.add_inner(group, p, r, mult);
        // The consumer also consumes the ∞ result-slot's `EcPoint(is_pai =
        // 1)` to pin `R = −P` — without it the slot is free (the
        // `EcGroupAdd` tuple matches any case) and a negation consumer could
        // bind any point. Route that demand so the store provides one extra ∞
        // copy.
        self.store.require_ecpoint(pai);
        (group, r, pai)
    }

    /// The live cases' shared tail: `t = x₁ + x₂`, `x₃ = λ² − t`,
    /// `e = x₁ − x₃`, `y₃ = λ·e − y₁` — the two mul-subtracts fused (no `w`
    /// / `u` intermediate store, no `x₃` / `y₃` sub op). `R` is minted as a
    /// **closure-cert** point — its membership rides this block's
    /// `EcOnCurveCert` (the group law is closed → on-curve operands give an
    /// on-curve result), so it pays *no* MAC trio.
    /// Returns the block's transient ptr cells (in cell order), `R`'s
    /// handle, and whether `R` was freshly minted (`mints` — the op owns
    /// `R`'s cert iff so; a value-dedup hit reuses an already-certified row).
    fn add_tail(
        &mut self,
        slope_aux: UintPtr,
        lambda: UintPtr,
        inv: UintPtr,
        px: UintPtr,
        py: UintPtr,
        qx: UintPtr,
        group: EcGroupPtr,
    ) -> ([UintPtr; 9], EcPointPtr, bool) {
        let t = self.uint.add(px, qx);
        let x3 = self.uint.mac_sub(1, lambda, lambda, 1, t);
        let e = self.uint.sub(px, x3);
        let y3 = self.uint.mac_sub(1, lambda, e, 1, py);
        // A fresh result (the value-dedup miss) mints — its ptr is the
        // maximum (> operands), satisfying the strict ordering the cert
        // rests on; a hit reuses its existing certified row and mints = false.
        let (r, mints) = self.store.add_point_cert(group, x3, y3);
        let null = UintPtr::from_addr(0);
        ([slope_aux, lambda, inv, t, y3, e, null, x3, null], r, mints)
    }
}

/// The two EC chiplet accumulators that travel together — the group /
/// point store plus the group-law add relation. [`require`](Self::require)
/// lends an [`EcRequire`] view over both, given the uint-layer view it
/// sits on top of; trace-gen consumes the fields individually.
#[derive(Debug, Default)]
pub struct EcStores {
    pub(crate) store: EcStoreRequires,
    pub(crate) add: EcAddRequires,
}

impl EcStores {
    pub fn new() -> Self {
        Self::default()
    }

    /// An [`EcRequire`] view over both accumulators plus the uint view
    /// below it. One borrow of the bundle (alongside the disjoint uint
    /// borrow `uint` already holds), so it composes with sibling borrows.
    pub fn require<'a>(&'a mut self, uint: UintRequire<'a>) -> EcRequire<'a> {
        EcRequire::new(&mut self.store, &mut self.add, uint)
    }
}
