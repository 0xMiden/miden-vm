//! EC store tests — the group table + point store pair: bindings, the
//! curve-membership MAC trio (the `UintMul` provide's first consumer),
//! PAI rows, the consecutive-ptr chains, act padding, the vacuous /
//! constrained scalar bound, and the adversarial matrix (off-curve
//! coordinates, PAI forgeries, phantom groups, forged scalar bounds,
//! duplicate ptrs — each rejected by the constraint or the bus that
//! owns it).

use std::collections::HashMap;

use miden_air::lookup::{
    Challenges, LookupAir,
    debug::{check_trace_balance, trace::DebugTraceBuilder},
};
use miden_core::{Felt, field::QuadFelt};
use miden_lifted_air::LiftedAir;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use rand::{Rng, SeedableRng, rngs::StdRng};

use crate::{
    ec::{
        COL_GROUP_PTR, COL_IS_PAI, COL_PTR, COL_SBOUND_PTR, COL_X_PTR, COL_Y_PTR, EcPointStoreAir,
        EcRequire, NUM_MAIN_COLS,
        add::trace::EcAddRequires,
        groups::{
            COL_B_PTR as G_COL_B_PTR, COL_SBOUND_PTR as G_COL_SBOUND_PTR, EcGroupsAir,
            NUM_MAIN_COLS as G_NUM_MAIN_COLS,
        },
        trace::{EcPointPtr, EcStoreRequires, generate_traces as ec_store_traces},
    },
    math::{U256, from_hex},
    primitives::byte_pair_lut::{BytePairLutAir, BytePairLutRequires, generate_trace as bpl_trace},
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    uint::{
        UintRequire, UintStoreAir,
        add::trace::UintAddRequires,
        mul::{
            UintMulAir,
            trace::{UintMulRequires, generate_trace as mul_trace},
        },
        trace::{UintStoreRequires, generate_trace as store_trace},
    },
};

fn rand_qf(rng: &mut impl Rng) -> QuadFelt {
    QuadFelt::new([Felt::from(rng.random::<u32>()), Felt::from(rng.random::<u32>())])
}

/// Accumulate one chiplet's net per-denom LogUp multiplicity. Mirrors
/// `tests::uint::fold_balance`.
fn fold_balance<A>(
    air: &A,
    main: &RowMajorMatrix<Felt>,
    challenges: &Challenges<QuadFelt>,
    net: &mut HashMap<QuadFelt, Felt>,
) where
    A: LiftedAir<Felt, QuadFelt>,
    for<'a> A: LookupAir<DebugTraceBuilder<'a>>,
{
    let periodic = air.periodic_columns();
    let combined = crate::tests::combined_lookup_main(air, main);
    let lookup_main = combined.as_ref().unwrap_or(main);
    let report = check_trace_balance(air, lookup_main, &periodic, &[], &[], challenges);
    for u in report.unmatched {
        *net.entry(u.denom).or_insert(Felt::ZERO) += u.net_multiplicity;
    }
}

/// A curve fixture: the uint store holds the modulus + params +
/// coordinates + membership transients, the mul requires hold the
/// membership trio (provides required), the group table holds group @1
/// and the point store PAI @1, the point @2.
struct Fixture {
    store: UintStoreRequires,
    muls: UintMulRequires,
    ec: EcStoreRequires,
    point: EcPointPtr,
}

/// Build a fixture for the curve `y² = x³ + ax + b` over `p = bound + 1`
/// with one finite point `(x, y)` (must be on-curve; asserted by the
/// membership MACs) — the modulus pinned @1, everything else recorded
/// through [`EcRequire`]. The add-relation and EcGroupAdd accumulators
/// stay empty (point binding records only MACs) and are dropped.
fn fixture(bound: U256, a: U256, b: U256, x: U256, y: U256) -> Fixture {
    let mut store = UintStoreRequires::new();
    let fp = store.pin_modulus(1, bound);
    let mut adds = UintAddRequires::new();
    let mut muls = UintMulRequires::new();
    let mut ec = EcStoreRequires::new();
    let mut ec_add = EcAddRequires::new();

    let mut req =
        EcRequire::new(&mut ec, &mut ec_add, UintRequire::new(&mut store, &mut adds, &mut muls));
    let (g, _pai) = req.create_group(a, b, fp);
    let point = req.add_point(g, x, y);

    Fixture { store, muls, ec, point }
}

/// secp256k1: y² = x³ + 7, with the standard base point.
fn k1_fixture() -> Fixture {
    let bound = from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E");
    let gx = from_hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    let gy = from_hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
    fixture(bound, from_hex("0"), from_hex("7"), gx, gy)
}

/// The five involved mains, laid in one consuming sweep over a fixture.
struct FixtureTraces {
    bpl: RowMajorMatrix<Felt>,
    store: RowMajorMatrix<Felt>,
    mul: RowMajorMatrix<Felt>,
    groups: RowMajorMatrix<Felt>,
    points: RowMajorMatrix<Felt>,
}

impl Fixture {
    /// Lay all five mains, each pass consuming its accumulator and
    /// routing the demand its rows consume (mul → store; the point
    /// store's own `EcGroup` consume was fed at intern). Bus-closed over
    /// {BPL, UintStore, UintMul, EcGroups, EcPointStore} — no `UintAdd`
    /// (membership is MACs only).
    fn traces(mut self) -> FixtureTraces {
        let mut bpl = BytePairLutRequires::new();
        let mul = mul_trace(self.muls, &mut self.store, &mut bpl);
        self.ec.route_uintval_demands(&mut self.store);
        let store = store_trace(self.store, &mut bpl);
        let (groups, points) = ec_store_traces(self.ec);
        FixtureTraces {
            bpl: bpl_trace(bpl),
            store,
            mul,
            groups,
            points,
        }
    }
}

/// Net LogUp residual across the five mains (0 ⟺ balanced); the EC mains
/// are passed explicitly so tamper tests can substitute a forged one for
/// the laid one.
fn residual(
    t: &FixtureTraces,
    groups: &RowMajorMatrix<Felt>,
    points: &RowMajorMatrix<Felt>,
    rng: &mut impl Rng,
) -> usize {
    let [alpha, beta] = [rand_qf(rng), rand_qf(rng)];
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);
    let mut net: HashMap<QuadFelt, Felt> = HashMap::new();
    fold_balance(&EcGroupsAir, groups, &challenges, &mut net);
    fold_balance(&EcPointStoreAir, points, &challenges, &mut net);
    fold_balance(&UintMulAir, &t.mul, &challenges, &mut net);
    fold_balance(&UintStoreAir, &t.store, &challenges, &mut net);
    fold_balance(&BytePairLutAir, &t.bpl, &challenges, &mut net);
    net.values().filter(|m| **m != Felt::ZERO).count()
}

fn check_points(main: &RowMajorMatrix<Felt>) {
    crate::tests::check_local(EcPointStoreAir, main);
}

fn check_groups(main: &RowMajorMatrix<Felt>) {
    crate::tests::check_local(EcGroupsAir, main);
}

#[test]
fn ec_stores_hold_and_balance() {
    let mut rng = StdRng::seed_from_u64(0xec_0001);
    let t = k1_fixture().traces();
    // Group table: group @1 pads to height 2. Point store: PAI @1,
    // point @2 — exactly height 2, no pad.
    assert_eq!(t.groups.height(), 2);
    assert_eq!(t.points.height(), 2);
    assert_eq!(t.points.values[COL_IS_PAI], Felt::ONE, "row 0 is the canonical PAI",);
    assert_eq!(t.points.values[NUM_MAIN_COLS + COL_IS_PAI], Felt::ZERO);
    // The vacuous scalar bound defaults to the F_p handle on both sides.
    assert_eq!(t.groups.values[G_COL_SBOUND_PTR], t.points.values[COL_SBOUND_PTR],);

    check_groups(&t.groups);
    check_points(&t.points);
    assert_eq!(residual(&t, &t.groups, &t.points, &mut rng), 0);
}

#[test]
fn ec_store_ed25519_image_torsion_point() {
    // The ed25519 SW image (docs/ed25519-sw-image.md) and its single
    // rational 2-torsion point (A/3, 0): a finite point whose y is the
    // stored zero — cleanly distinct from PAI — passing membership with
    // w = y² = 0. Constants machine-verified against the map derivation.
    let mut rng = StdRng::seed_from_u64(0xec_25519);
    let bound = from_hex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC");
    let a_w = from_hex("2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA984914A144");
    let b_w = from_hex("7B425ED097B425ED097B425ED097B425ED097B425ED097B4260B5E9C7710C864");
    let x_t = from_hex("2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2451");
    let t = fixture(bound, a_w, b_w, x_t, from_hex("0")).traces();

    check_groups(&t.groups);
    check_points(&t.points);
    assert_eq!(residual(&t, &t.groups, &t.points, &mut rng), 0);
}

#[test]
fn constrained_scalar_bound_balances() {
    // Pin the secp256k1 group order's n − 1 as a second modulus and
    // constrain the group's scalar field with it: every EcGroup tuple
    // site (group row, point rows) must carry the F_s handle instead of
    // the vacuous F_p default, and the bus still closes.
    let mut rng = StdRng::seed_from_u64(0xec_f5);
    let mut fx = k1_fixture();
    let n_minus_1 = from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140");
    let fs = fx.store.pin_modulus(2, n_minus_1);
    let (group, _) = fx.ec.point_params(fx.point);
    let mut adds = UintAddRequires::new();
    let mut ec_add = EcAddRequires::new();
    EcRequire::new(
        &mut fx.ec,
        &mut ec_add,
        UintRequire::new(&mut fx.store, &mut adds, &mut fx.muls),
    )
    .constrain_scalar_bound(group, fs);
    let t = fx.traces();
    assert_eq!(t.groups.values[G_COL_SBOUND_PTR], Felt::from(fs.addr()));
    assert_eq!(
        t.points.values[COL_SBOUND_PTR],
        Felt::from(fs.addr()),
        "point rows resolve the constrained scalar bound",
    );

    check_groups(&t.groups);
    check_points(&t.points);
    assert_eq!(residual(&t, &t.groups, &t.points, &mut rng), 0);
}

#[test]
fn forged_scalar_bound_unbalances() {
    // A point row claiming a different scalar bound than its group's:
    // every local constraint holds, but the 5-tuple EcGroup consume
    // matches no provide.
    let mut rng = StdRng::seed_from_u64(0xec_f5bad);
    let t = k1_fixture().traces();
    let mut forged = t.points.clone();
    forged.values[NUM_MAIN_COLS + COL_SBOUND_PTR] = Felt::from(7u32);

    check_points(&forged);
    assert_ne!(residual(&t, &t.groups, &forged, &mut rng), 0);
}

#[test]
fn off_curve_point_unbalances() {
    // Repoint the stored point's y at a different (valid, canonical)
    // uint: every local constraint still holds — the cells are bindings,
    // not equations — but the y² membership MAC consume now names a tuple
    // nothing proves, so the bus rejects what the AIR alone cannot see.
    let mut rng = StdRng::seed_from_u64(0xec_0ff);
    let fx = k1_fixture();
    let (_, coords) = fx.ec.point_params(fx.point);
    let (x_ptr, _) = coords.expect("finite point");
    let t = fx.traces();
    let mut forged = t.points.clone();
    forged.values[NUM_MAIN_COLS + COL_Y_PTR] = Felt::from(x_ptr.addr()); // y := x

    check_points(&forged);
    assert_ne!(residual(&t, &t.groups, &forged, &mut rng), 0);
}

#[test]
#[should_panic]
fn pai_forgery_on_finite_point_rejected() {
    // Claiming is_pai on the finite point row (to skip membership) trips
    // the none-sentinel ties: is_pai · x_ptr = 0.
    let mut forged = k1_fixture().traces().points;
    forged.values[NUM_MAIN_COLS + COL_IS_PAI] = Felt::ONE;

    check_points(&forged);
}

#[test]
#[should_panic]
fn pai_with_coordinates_rejected() {
    // A PAI row naming real coordinates is equally rejected (the dual
    // forgery: smuggling a point binding under the membership-free flag).
    let fx = k1_fixture();
    let (_, coords) = fx.ec.point_params(fx.point);
    let (x_ptr, _) = coords.expect("finite point");
    let mut forged = fx.traces().points;
    forged.values[COL_X_PTR] = Felt::from(x_ptr.addr()); // the PAI row is row 0

    check_points(&forged);
}

#[test]
#[should_panic]
fn duplicate_point_ptr_rejected() {
    // Two points sharing a ptr would break ptr → point; the consecutive
    // chain (act-gated ptr' = ptr + 1) rejects it.
    let mut forged = k1_fixture().traces().points;
    forged.values[NUM_MAIN_COLS + COL_PTR] = Felt::ONE; // duplicate of row 0

    check_points(&forged);
}

#[test]
fn phantom_group_unbalances() {
    // A point claiming a group that was never created: constraints hold,
    // the EcGroup consume finds no provider.
    let mut rng = StdRng::seed_from_u64(0xec_9457);
    let t = k1_fixture().traces();
    let mut forged = t.points.clone();
    forged.values[NUM_MAIN_COLS + COL_GROUP_PTR] = Felt::from(7u32);

    check_points(&forged);
    assert_ne!(residual(&t, &t.groups, &forged, &mut rng), 0);
}

#[test]
#[should_panic]
fn group_ptr_chain_is_ungated() {
    // The group table has an act flag for lookup liveness, but ptr = row + 1
    // remains forced on every row, pads included. Rewriting a pad row's ptr,
    // the move that would mint a duplicate group id, trips the ungated chain.
    let mut forged = k1_fixture().traces().groups;
    forged.values[G_NUM_MAIN_COLS] = Felt::ONE; // pad row ptr := 1 (dup of row 0)

    check_groups(&forged);
}

#[test]
fn forged_group_mult_unbalances() {
    // Zeroing the group row's provide mult leaves the point rows'
    // EcGroup consumes dangling — the dual of the phantom group.
    let mut rng = StdRng::seed_from_u64(0xec_3017);
    let t = k1_fixture().traces();
    let mut forged = t.groups.clone();
    forged.values[crate::ec::groups::COL_MULT] = Felt::ZERO;

    check_groups(&forged);
    assert_ne!(residual(&t, &forged, &t.points, &mut rng), 0);
}

#[test]
fn forged_group_b_zero_unbalances() {
    // Repoint the group row's b coefficient at the stored zero coefficient.
    // The group table has no local arithmetic over b, but its nonzero
    // certificate now demands an unrecorded b_inv * 0 = 1 tuple.
    let mut rng = StdRng::seed_from_u64(0xec_b000);
    let t = k1_fixture().traces();
    let mut forged = t.groups.clone();
    forged.values[G_COL_B_PTR] = t.groups.values[crate::ec::groups::COL_A_PTR];

    check_groups(&forged);
    assert_ne!(residual(&t, &forged, &t.points, &mut rng), 0);
}

#[test]
fn forged_group_a_ptr_unbalances() {
    // Repoint the group row's a coefficient while leaving the committed
    // a-limb view untouched. Local group constraints still hold, but the
    // UintVal consume now asks the uint store for b's ptr with a's limbs.
    let mut rng = StdRng::seed_from_u64(0xec_a000);
    let t = k1_fixture().traces();
    let mut forged = t.groups.clone();
    forged.values[crate::ec::groups::COL_A_PTR] = t.groups.values[G_COL_B_PTR];

    check_groups(&forged);
    assert_ne!(residual(&t, &forged, &t.points, &mut rng), 0);
}

#[test]
fn empty_stores_hold() {
    // No groups, no points: each store is all-zero pad rows that must
    // satisfy every constraint and touch no bus.
    let (groups_main, points_main) = ec_store_traces(EcStoreRequires::new());
    assert_eq!(groups_main.height(), 2);
    assert_eq!(points_main.height(), 2);
    assert_eq!(groups_main.values.len(), 2 * G_NUM_MAIN_COLS);
    check_groups(&groups_main);
    check_points(&points_main);
}
