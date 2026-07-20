//! EcGroupAdd tests — the five-case lattice end-to-end through the
//! arithmetic + EC chiplet subset, driven by [`EcRequire`] over bare
//! `*Requires` accumulators (KAT results checked by *value* through
//! canonical interning — never by hardcoded ptrs), the `∞ + ∞`
//! both-flags block, ed25519-image 2-torsion doubling through `cancel`,
//! the subset prove/verify round-trip, and the adversarial matrix:
//! with every predicate a ptr-level certificate, *all* case-flag and
//! result forgeries are owned by the bus — a forged case demands
//! certificate tuples nothing recorded (the λ-float attack's inv·d ≡ b
//! is unrecordable at d = 0) while the honest case's recorded
//! certificates dangle.

use std::{collections::HashMap, format, string::String, vec, vec::Vec};

use k256::{ProjectivePoint, Scalar, elliptic_curve::sec1::ToSec1Point};
use miden_air::lookup::Challenges;
use miden_core::{
    Felt,
    field::QuadFelt,
    utils::{Matrix, RowMajorMatrix},
};
use miden_lifted_air::{MultiAir, ProverStatement, ReductionError, Statement};
use miden_lifted_stark::{Preprocessed, ProverInstance, VerifierInstance};
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};

// `sigma_sum` closes the subset `MultiAir`'s cross-AIR bus identity for the
// (ignored) prove round-trip.
use crate::logup::{NUM_PUBLIC_VALUES, sigma_sum};
use crate::{
    ec::{
        COL_IS_CERT, EcPointStoreAir, EcRequire, NUM_MAIN_COLS as POINT_COLS,
        add::{
            CELL_R, COL_CANCEL, COL_DBL, COL_GEN, COL_MINTS, COL_PAI_P, COL_PAI_Q, EcGroupAddAir,
            NUM_MAIN_COLS as ADD_COLS, PERIOD, ROW_RES,
            trace::{EcAddRequires, generate_trace as ec_add_trace},
        },
        groups::EcGroupsAir,
        trace::{EcGroupPtr, EcPointPtr, EcStoreRequires, generate_traces as ec_store_traces},
    },
    math::{U256, from_hex},
    primitives::byte_pair_lut::{BytePairLutAir, BytePairLutRequires, generate_trace as bpl_trace},
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    session::ChipletAir,
    stark_config::{test_challenger, test_config},
    tests::bus_balance::fold_balance,
    uint::{
        UintRequire, UintStoreAir,
        add::{
            UintAddAir,
            trace::{UintAddRequires, generate_trace as uint_add_trace},
        },
        mul::{
            UintMulAir,
            trace::{UintMulRequires, generate_trace as uint_mul_trace},
        },
        trace::{UintPtr, UintStoreRequires, generate_trace as uint_trace},
    },
};

fn rand_qf(rng: &mut impl Rng) -> QuadFelt {
    QuadFelt::new([Felt::from(rng.random::<u32>()), Felt::from(rng.random::<u32>())])
}

// secp256k1 KATs (machine-verified small multiples of G).
const P_MINUS_1: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E";
const GX: &str = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
const GY: &str = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
const G2X: &str = "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5";
const G2Y: &str = "1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A";
const G3X: &str = "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9";
const G3Y: &str = "388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672";
const NEG_GY: &str = "B7C52588D95C3B9AA25B0403F1EEF75702E84BB7597AABE663B82F6F04EF2777";
/// β·Gx for secp256k1's cube root of unity β: the x of a curve point
/// whose y is −Gy — same y-negation as −G, *different* x.
const BETA_GX: &str = "BCACE2E99DA01887AB0102B696902325872844067F15E98DA7BBA04400B88FCB";

/// Non-fixed modulus protocol address used by these ad-hoc tests.
const FP: u32 = 1000;

/// The arithmetic + EC chiplet subset, in canonical
/// [`SessionTraces::mains`](crate::session::SessionTraces::mains) order:
/// byte-pair LUT, uint store, uint add, uint mul, EC groups, EC points,
/// EC add.
const NUM_STACK: usize = 7;

/// Bare-requires stack over the arithmetic + EC chiplet subset — the EC
/// layer's analogue of the Session sweep, driven through [`EcRequire`].
/// The subset is bus-closed: `Range16` nets against the LUT, `UintVal` /
/// `UintLimbs` / `UintAdd` / `UintMul` / `EcGroup` / `EcPoint` all net
/// within the six chiplets.
struct EcStack {
    store: UintStoreRequires,
    /// The pinned modulus's handle.
    fp: UintPtr,
    adds: UintAddRequires,
    muls: UintMulRequires,
    ec: EcStoreRequires,
    ec_add: EcAddRequires,
}

impl EcStack {
    /// A stack over the field `p = bound + 1`, its modulus pinned at
    /// [`FP`].
    fn new(bound: U256) -> Self {
        let mut store = UintStoreRequires::new();
        let fp = store.pin_modulus(FP, bound);
        Self {
            store,
            fp,
            adds: UintAddRequires::new(),
            muls: UintMulRequires::new(),
            ec: EcStoreRequires::new(),
            ec_add: EcAddRequires::new(),
        }
    }

    /// The EC recording layer over this stack's accumulators.
    fn require(&mut self) -> EcRequire<'_> {
        EcRequire::new(
            &mut self.ec,
            &mut self.ec_add,
            UintRequire::new(&mut self.store, &mut self.adds, &mut self.muls),
        )
    }

    /// The stored coordinate values `(x, y)` of a finite point.
    fn point_coords(&self, point: EcPointPtr) -> (U256, U256) {
        let (_, coords) = self.ec.point_params(point);
        let (x_ptr, y_ptr) = coords.expect("PAI has no coordinates");
        (self.store.uint(x_ptr).value, self.store.uint(y_ptr).value)
    }

    /// Run the dependency-ordered trace sweep — each pass consumes its
    /// accumulator and routes the demand its rows consume, so relations
    /// run before the store / EC stores read their provide ledgers and
    /// every `Range16` consumer fires before the LUT — and bundle the
    /// seven main traces in [`NUM_STACK`] order.
    fn traces(mut self) -> EcStackTraces {
        let mut bpl = BytePairLutRequires::new();
        let add = uint_add_trace(self.adds, &mut self.store);
        let mul = uint_mul_trace(self.muls, &mut self.store, &mut bpl);
        let ec_add = ec_add_trace(self.ec_add, &mut self.ec, &mut bpl);
        let uint = uint_trace(self.store, &mut bpl);
        let (ec_groups, ec_points) = ec_store_traces(self.ec);
        EcStackTraces([bpl_trace(bpl), uint, add, mul, ec_groups, ec_points, ec_add])
    }
}

/// The six subset main traces, with the per-chiplet check / balance /
/// prove harness over them.
struct EcStackTraces([RowMajorMatrix<Felt>; NUM_STACK]);

/// The subset's AIRs as [`ChipletAir`] variants, in [`NUM_STACK`] order.
fn stack_airs() -> [ChipletAir; NUM_STACK] {
    [
        ChipletAir::BytePairLut,
        ChipletAir::UintStore,
        ChipletAir::UintAdd,
        ChipletAir::UintMul,
        ChipletAir::EcGroups,
        ChipletAir::EcPointStore,
        ChipletAir::EcGroupAdd,
    ]
}

/// The subset as a [`MultiAir`] over the seven [`stack_airs`] in
/// [`NUM_STACK`] order, closing the same cross-AIR `Σ σ = 0` bus identity
/// as the full [`ChipletMultiAir`](crate::session::ChipletMultiAir) — the
/// subset is bus-closed, so the residue sum vanishes. Drives the
/// [`prove_and_verify`](EcStackTraces::prove_and_verify) round-trip under
/// 0.26's unified `ProverStatement` / `VerifierInstance` driver.
#[derive(Clone, Debug)]
struct EcStackMultiAir {
    airs: Vec<ChipletAir>,
}

impl EcStackMultiAir {
    fn new() -> Self {
        Self { airs: stack_airs().to_vec() }
    }
}

impl MultiAir<Felt, QuadFelt> for EcStackMultiAir {
    type Air = ChipletAir;

    fn airs(&self) -> &[ChipletAir] {
        &self.airs
    }

    fn eval_external(
        &self,
        _challenges: &[QuadFelt],
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        aux_values: &[&[QuadFelt]],
        _log_trace_heights: &[u8],
    ) -> Result<Vec<QuadFelt>, ReductionError> {
        Ok(vec![sigma_sum(aux_values)])
    }
}

impl EcStackTraces {
    fn mains(&self) -> [&RowMajorMatrix<Felt>; NUM_STACK] {
        let [a, b, c, d, e, f, g] = &self.0;
        [a, b, c, d, e, f, g]
    }

    /// The EcGroupAdd main — the tamper tests' target.
    fn ec_add_main(&self) -> &RowMajorMatrix<Felt> {
        &self.0[6]
    }

    /// The EcPointStore main — the closure-cert necessity tests' target.
    fn ec_points_main(&self) -> &RowMajorMatrix<Felt> {
        &self.0[5]
    }

    /// Per-chiplet local-constraint check (one AIR at a time, no
    /// cross-chiplet bus balance — that's [`stack_residual`] / the prove
    /// round-trip).
    fn check(&self) {
        for (air, main) in stack_airs().into_iter().zip(&self.0) {
            crate::tests::check_local(air, main);
        }
    }

    /// The shared `air_inputs` for the subset [`MultiAir`]: every chiplet
    /// declares the 4-felt transcript root ([`NUM_PUBLIC_VALUES`]), but the
    /// subset carries no eval chip to read it, so a dummy zero root satisfies
    /// the length check and constrains nothing.
    fn dummy_air_inputs() -> Vec<Felt> {
        vec![Felt::ZERO; NUM_PUBLIC_VALUES]
    }

    /// The subset's [`ProverStatement`]: the [`EcStackMultiAir`] + the dummy
    /// shared `air_inputs` + the seven main traces in [`NUM_STACK`] order.
    fn prover_statement(&self) -> ProverStatement<Felt, QuadFelt, EcStackMultiAir> {
        let statement =
            Statement::new(EcStackMultiAir::new(), Self::dummy_air_inputs(), Vec::new())
                .expect("subset statement inputs are valid");
        let mains: Vec<RowMajorMatrix<Felt>> = self.0.to_vec();
        ProverStatement::new(statement, mains).expect("subset trace shapes are valid")
    }

    /// Prove the subset under the test config and re-verify the proof,
    /// asserting the prover and verifier digests agree.
    fn prove_and_verify(&self) {
        let config = test_config();
        let prover_statement = self.prover_statement();
        // The subset includes BytePairLut, which declares preprocessed
        // columns, so the bundle is `Some`.
        let preprocessed = Preprocessed::build(prover_statement.statement(), &config);
        let output = ProverInstance::new(&config, &prover_statement, preprocessed.as_ref())
            .expect("preprocessed bundle matches the declared columns")
            .prove(test_challenger())
            .expect("prove");

        let statement =
            Statement::new(EcStackMultiAir::new(), Self::dummy_air_inputs(), Vec::new())
                .expect("subset statement inputs are valid");
        let preprocessed = Preprocessed::build(&statement, &config);
        let digest = VerifierInstance::new(
            &config,
            &statement,
            preprocessed.as_ref().map(Preprocessed::commitment),
        )
        .expect("preprocessed commitment matches the declared columns")
        .verify(&output.proof, test_challenger())
        .expect("the arithmetic + EC subset must verify");
        assert_eq!(digest, output.digest, "prover/verifier digests must agree");
    }
}

/// Net unmatched LogUp denominators across the subset (0 ⟺ every bus
/// closes). Takes the mains explicitly so tamper tests can substitute a
/// forged matrix.
fn stack_residual(mains: &[&RowMajorMatrix<Felt>; NUM_STACK], rng: &mut impl Rng) -> usize {
    let challenges = Challenges::new(rand_qf(rng), rand_qf(rng), MAX_MESSAGE_WIDTH, NUM_BUS_IDS);
    let mut net: HashMap<QuadFelt, (Felt, String)> = HashMap::new();
    fold_balance(&BytePairLutAir, mains[0], &challenges, &mut net);
    fold_balance(&UintStoreAir, mains[1], &challenges, &mut net);
    fold_balance(&UintAddAir, mains[2], &challenges, &mut net);
    fold_balance(&UintMulAir, mains[3], &challenges, &mut net);
    fold_balance(&EcGroupsAir, mains[4], &challenges, &mut net);
    fold_balance(&EcPointStoreAir, mains[5], &challenges, &mut net);
    fold_balance(&EcGroupAddAir, mains[6], &challenges, &mut net);
    net.into_values().filter(|(m, _)| *m != Felt::ZERO).count()
}

/// A secp256k1-shaped stack over a non-fixed uint modulus pin: the group
/// table keeps VM-owned fixed rows first, while the point store holds this
/// group's canonical PAI @1, G @2, 2G @3 — every uint (params,
/// coordinates, membership transients) interned canonically by the require
/// layer.
struct K1 {
    stack: EcStack,
    group: EcGroupPtr,
    pai: EcPointPtr,
    g_pt: EcPointPtr,
    g2_pt: EcPointPtr,
}

fn k1_stack() -> K1 {
    let mut stack = EcStack::new(from_hex(P_MINUS_1));
    let fp = stack.fp;
    let mut ec = stack.require();
    let (group, pai) = ec.create_group(from_hex("0"), from_hex("7"), fp);
    let g_pt = ec.add_point(group, from_hex(GX), from_hex(GY));
    let g2_pt = ec.add_point(group, from_hex(G2X), from_hex(G2Y));
    K1 { stack, group, pai, g_pt, g2_pt }
}

/// Local-constraint check on the EcGroupAdd chiplet alone (the tamper
/// tests' constraint oracle; bus balance is judged separately).
fn check_ec_add(main: &RowMajorMatrix<Felt>) {
    crate::tests::check_local(EcGroupAddAir, main);
}

/// Clone the EcGroupAdd main and rewrite columns of block 0's rows.
fn tamper_block0(main: &RowMajorMatrix<Felt>, cols: &[(usize, u32)]) -> RowMajorMatrix<Felt> {
    let mut m = main.clone();
    for row in 0..PERIOD {
        for &(col, v) in cols {
            m.values[row * ADD_COLS + col] = Felt::from(v);
        }
    }
    m
}

/// Rewrite one hosted cell of block 0 (e.g. the res row's `r`).
fn tamper_cell(m: &mut RowMajorMatrix<Felt>, row: usize, cell: usize, v: u32) {
    m.values[row * ADD_COLS + cell] = Felt::from(v);
}

/// Clone the EcPointStore main and rewrite one column of a given row.
fn tamper_ec_points(
    main: &RowMajorMatrix<Felt>,
    row: usize,
    col: usize,
    v: u32,
) -> RowMajorMatrix<Felt> {
    let mut m = main.clone();
    m.values[row * POINT_COLS + col] = Felt::from(v);
    m
}

/// The case flags of the add trace's block 0, `(pai_p, pai_q, cancel,
/// dbl, generic)`, read off row 0.
fn block0_flags(main: &RowMajorMatrix<Felt>) -> [Felt; 5] {
    [COL_PAI_P, COL_PAI_Q, COL_CANCEL, COL_DBL, COL_GEN].map(|c| main.values[c])
}

// ============================================================================
// k256 cross-validation (M1) — the EC circuit's results checked against
// the RustCrypto secp256k1 reference across the five-case lattice. k256
// is the oracle; canonical interning makes the comparison ptr-free (we
// compare stored coordinate *values*, or the result ptr for ∞).
// ============================================================================

/// Big-endian field bytes → our `U256` (through the KAT hex path).
fn be_to_u256(bytes: impl AsRef<[u8]>) -> U256 {
    let hex: String = bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    from_hex(&hex)
}

/// Affine coordinates of a k256 point as a `U256` pair — `None` for the
/// identity (∞).
fn k256_coords(p: &ProjectivePoint) -> Option<(U256, U256)> {
    let enc = p.to_affine().to_sec1_point(false);
    Some((be_to_u256(enc.x()?), be_to_u256(enc.y()?)))
}

/// Build a secp256k1 stack and drive the full five-case lattice, asserting
/// every result against k256 before the stack is consumed for tracing.
/// Returns the stack so the caller can `traces()` it (check / prove).
fn k256_validated_stack() -> EcStack {
    let g = ProjectivePoint::GENERATOR;
    let mut s = EcStack::new(from_hex(P_MINUS_1));
    let fp = s.fp;
    let (group, pai) = s.require().create_group(from_hex("0"), from_hex("7"), fp);

    // generic (x₁ ≠ x₂) and double (a = b) — the oracle decides the case.
    for &(a, b) in &[(1u64, 2u64), (3, 7), (9, 4), (5, 5), (6, 6)] {
        let (pa, pb) = (g * Scalar::from(a), g * Scalar::from(b));
        let (pax, pay) = k256_coords(&pa).expect("aG is finite");
        let (pbx, pby) = k256_coords(&pb).expect("bG is finite");
        let p_pt = s.require().add_point(group, pax, pay);
        let q_pt = s.require().add_point(group, pbx, pby);
        let r = s.require().add(p_pt, q_pt, 0);
        match k256_coords(&(pa + pb)) {
            Some(want) => assert_eq!(s.point_coords(r), want, "P+Q vs k256 (a={a}, b={b})"),
            None => assert_eq!(r, pai, "k256 says ∞ (a={a}, b={b})"),
        }
    }

    // cancel: P + (−P) = ∞.
    let p = g * Scalar::from(8u64);
    let (px, py) = k256_coords(&p).unwrap();
    let (nx, ny) = k256_coords(&(-p)).unwrap();
    let p_pt = s.require().add_point(group, px, py);
    let n_pt = s.require().add_point(group, nx, ny);
    assert_eq!(s.require().add(p_pt, n_pt, 0), pai, "P + (−P) = ∞");

    // pass-throughs: ∞ + Q = Q, P + ∞ = P, ∞ + ∞ = ∞.
    let q = g * Scalar::from(12u64);
    let (qx, qy) = k256_coords(&q).unwrap();
    let q_pt = s.require().add_point(group, qx, qy);
    assert_eq!(s.require().add(pai, q_pt, 0), q_pt, "∞ + Q = Q");
    assert_eq!(s.require().add(q_pt, pai, 0), q_pt, "P + ∞ = P");
    assert_eq!(s.require().add(pai, pai, 0), pai, "∞ + ∞ = ∞");

    s
}

#[test]
fn ec_add_matches_k256() {
    // The lattice is validated against k256 inside the builder; here we
    // also close the subset: per-chiplet constraints + full bus balance.
    let traces = k256_validated_stack().traces();
    let mut rng = StdRng::seed_from_u64(0x000e_cadd_c256);
    traces.check();
    assert_eq!(stack_residual(&traces.mains(), &mut rng), 0, "subset must balance");
}

#[test]
#[ignore = "full prove/verify round-trip; run explicitly"]
fn ec_add_matches_k256_proves() {
    k256_validated_stack().traces().prove_and_verify();
}

#[test]
fn create_group_dedups_by_curve() {
    // EC-DAG foundation: the eval layer creates a point's group per
    // EcCreate node, so an identical curve (a, b, bound) must collapse
    // to one group_ptr (and one canonical PAI) — else add operands land
    // on distinct groups and the same-group assertion fails. Bare callers
    // that create each group once are unaffected.
    let mut s = EcStack::new(from_hex(P_MINUS_1));
    let fp = s.fp;
    let (g1, pai1) = s.require().create_group(from_hex("0"), from_hex("7"), fp);
    let (g2, pai2) = s.require().create_group(from_hex("0"), from_hex("7"), fp);
    assert_eq!(g1, g2, "same curve must share one group");
    assert_eq!(pai1, pai2, "and its one canonical PAI");
    let (g3, _) = s.require().create_group(from_hex("0"), from_hex("3"), fp);
    assert_ne!(g1, g3, "a different curve (b = 3) is a distinct group");
}

// ============================================================================
// Honest cases
// ============================================================================

#[test]
fn generic_add_computes_kat() {
    // G + 2G through the chord path: R's stored coordinate *values* are
    // the 3G known answers — canonical interning makes the check
    // ptr-free.
    let mut k1 = k1_stack();
    let r = k1.stack.require().add(k1.g_pt, k1.g2_pt, 0);
    let (x3, y3) = k1.stack.point_coords(r);
    assert_eq!(x3, from_hex(G3X), "x₃ must be the 3G KAT");
    assert_eq!(y3, from_hex(G3Y), "y₃ must be the 3G KAT");

    let traces = k1.stack.traces();
    assert_eq!(
        block0_flags(traces.ec_add_main()),
        [0, 0, 0, 0, 1].map(Felt::from_u32),
        "the block claims generic",
    );
    assert_eq!(
        traces.ec_add_main().values[ROW_RES * ADD_COLS + CELL_R],
        Felt::from(r.addr()),
        "the res row hosts the result ptr",
    );
    assert_eq!(traces.ec_add_main().height(), PERIOD, "one add op = one block");

    let mut rng = StdRng::seed_from_u64(0xecad_d001);
    traces.check();
    assert_eq!(stack_residual(&traces.mains(), &mut rng), 0);
}

#[test]
fn duplicate_adds_collapse() {
    // The same group add requested twice interns by relation identity
    // (group, p, q): one EcGroupAdd block, one set of certificates, and
    // the second call re-derives nothing — the honest-prover dedup that
    // lets an MSM table combine reused across windows cost one block.
    let mut k1 = k1_stack();
    let r1 = k1.stack.require().add(k1.g_pt, k1.g2_pt, 0);
    let r2 = k1.stack.require().add(k1.g_pt, k1.g2_pt, 0);
    assert_eq!(r1, r2, "the repeat returns the recorded result");

    let traces = k1.stack.traces();
    assert_eq!(
        traces.ec_add_main().height(),
        PERIOD,
        "two identical adds collapse onto one block",
    );

    let mut rng = StdRng::seed_from_u64(0xecad_dded);
    traces.check();
    assert_eq!(stack_residual(&traces.mains(), &mut rng), 0);
}

#[test]
fn double_binds_canonically() {
    // G + G through the κ-fused tangent path (s ≡ 3x² + a, 2λy ≡ s):
    // the computed x₃ / y₃ equal 2G's coordinates (added first), so the
    // **point store dedups the result onto 2G's existing row** — honest-
    // prover dedup observed through handles: R *is* the 2G point, paying
    // no second membership trio.
    let mut k1 = k1_stack();
    let r = k1.stack.require().add(k1.g_pt, k1.g_pt, 0);
    assert_eq!(r, k1.g2_pt, "the doubling result dedups onto the 2G row");
    assert_eq!(k1.stack.point_coords(r), (from_hex(G2X), from_hex(G2Y)));

    let traces = k1.stack.traces();
    assert_eq!(block0_flags(traces.ec_add_main()), [0, 0, 0, 1, 0].map(Felt::from_u32));

    let mut rng = StdRng::seed_from_u64(0xecad_d002);
    traces.check();
    assert_eq!(stack_residual(&traces.mains(), &mut rng), 0);
}

#[test]
fn cancel_resolves_to_canonical_pai() {
    // G + (−G): equal x, y₁ + y₂ ≡ 0 — the is_c_zero tuple is the whole
    // certificate and R is the group's canonical PAI row.
    let mut k1 = k1_stack();
    let mut ec = k1.stack.require();
    let neg_g = ec.add_point(k1.group, from_hex(GX), from_hex(NEG_GY));
    let r = ec.add(k1.g_pt, neg_g, 0);
    assert_eq!(r, k1.pai);

    let traces = k1.stack.traces();
    assert_eq!(block0_flags(traces.ec_add_main()), [0, 0, 1, 0, 0].map(Felt::from_u32));

    let mut rng = StdRng::seed_from_u64(0xecad_d003);
    traces.check();
    assert_eq!(stack_residual(&traces.mains(), &mut rng), 0);
}

#[test]
fn pai_passthroughs_tie_results() {
    // ∞ + Q = Q, P + ∞ = P, and ∞ + ∞ = ∞ — the last with *both* pass
    // flags riding the consumed tuples' is_pai fields.
    let mut k1 = k1_stack();
    let mut ec = k1.stack.require();
    assert_eq!(ec.add(k1.pai, k1.g_pt, 0), k1.g_pt);
    assert_eq!(ec.add(k1.g2_pt, k1.pai, 0), k1.g2_pt);
    assert_eq!(ec.add(k1.pai, k1.pai, 0), k1.pai);

    let traces = k1.stack.traces();
    let main = traces.ec_add_main();
    assert_eq!(main.height(), 16, "three blocks pad to four");
    let block2 = 2 * PERIOD * ADD_COLS;
    assert_eq!(
        [COL_PAI_P, COL_PAI_Q].map(|c| main.values[block2 + c]),
        [Felt::ONE; 2],
        "∞ + ∞ sets both pass flags",
    );

    let mut rng = StdRng::seed_from_u64(0xecad_d004);
    traces.check();
    assert_eq!(stack_residual(&traces.mains(), &mut rng), 0);
}

#[test]
fn ed25519_torsion_doubles_to_pai() {
    // The ed25519 SW image's rational 2-torsion point T = (A/3, 0):
    // T + T routes through cancel (x₁ = x₂, 0 + 0 ≡ 0 — the is_c_zero
    // k = 0 branch), the same vertical-tangent geometry the generic
    // double cannot express. Live on this curve, dead code on
    // prime-order curves — exactly why it gets its own test.
    let bound = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC";
    let a_w = "2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA984914A144";
    let b_w = "7B425ED097B425ED097B425ED097B425ED097B425ED097B4260B5E9C7710C864";
    let x_t = "2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2451";

    let mut stack = EcStack::new(from_hex(bound));
    let fp = stack.fp;
    let mut ec = stack.require();
    let (group, pai) = ec.create_group(from_hex(a_w), from_hex(b_w), fp);
    let t_pt = ec.add_point(group, from_hex(x_t), from_hex("0"));
    let r = ec.add(t_pt, t_pt, 0);
    assert_eq!(r, pai, "2-torsion doubling cancels to ∞");

    let traces = stack.traces();
    assert_eq!(block0_flags(traces.ec_add_main()), [0, 0, 1, 0, 0].map(Felt::from_u32));

    let mut rng = StdRng::seed_from_u64(0xecadd_25519);
    traces.check();
    assert_eq!(stack_residual(&traces.mains(), &mut rng), 0);
}

#[test]
fn empty_trace_holds() {
    // No ops: one all-zero pad block must satisfy every constraint and
    // touch no bus.
    let main = ec_add_trace(
        EcAddRequires::new(),
        &mut EcStoreRequires::new(),
        &mut BytePairLutRequires::new(),
    );
    assert_eq!(main.height(), PERIOD);
    check_ec_add(&main);
}

/// The subset proved and verified for real — `#[ignore]`d (slow in
/// debug); run explicitly or in release alongside the bench.
#[test]
#[ignore = "full prove/verify round-trip; run explicitly"]
fn arithmetic_ec_stack_proves() {
    // One chord add and one tangent double over secp256k1: every uint
    // arrangement the EC layer uses (scaled MAC, squaring, κ_c = 0
    // products, sub arrangements) inside one proof.
    let mut k1 = k1_stack();
    let mut ec = k1.stack.require();
    let r3 = ec.add(k1.g_pt, k1.g2_pt, 0);
    let r2 = ec.add(k1.g_pt, k1.g_pt, 0);
    let (_, r2_coords) = k1.stack.ec.point_params(r2);
    let (_, g2_coords) = k1.stack.ec.point_params(k1.g2_pt);
    assert_eq!(r2_coords, g2_coords);
    assert_eq!(k1.stack.point_coords(r3).0, from_hex(G3X));

    k1.stack.traces().prove_and_verify();
}

// ============================================================================
// Adversarial cases — each forgery rejected by the layer that owns it
// ============================================================================

#[test]
fn double_forged_as_generic_unbalances() {
    // The λ-float attack: claim generic on a doubling configuration so
    // the chord MAC degenerates to 0 ≡ 0 and λ floats. Every local
    // constraint holds — predicates left the AIR — but generic demands
    // the disequality witness inv·d ≡ b, which is unrecordable at d = 0
    // (it would read 0 ≡ b ≠ 0), and the rest of the chord certificates
    // were never recorded either, while double's recorded ones dangle.
    // The disequality certificate is what pins λ; the mul chiplet owns
    // the rejection now, deterministically.
    let mut k1 = k1_stack();
    k1.stack.require().add(k1.g_pt, k1.g_pt, 0);
    let traces = k1.stack.traces();

    let forged = tamper_block0(traces.ec_add_main(), &[(COL_DBL, 0), (COL_GEN, 1)]);
    let mut rng = StdRng::seed_from_u64(0xecad_da01);
    check_ec_add(&forged);

    let mut mains = traces.mains();
    mains[6] = &forged;
    assert_ne!(stack_residual(&mains, &mut rng), 0);
}

#[test]
fn generic_forged_as_double_unbalances() {
    // The dual flip: claiming double on distinct x's demands the
    // x₁ + 0 ≡ x₂ equality certificate — unrecordable for unequal
    // values — plus the tangent MACs nothing recorded.
    let mut k1 = k1_stack();
    k1.stack.require().add(k1.g_pt, k1.g2_pt, 0);
    let traces = k1.stack.traces();

    let forged = tamper_block0(traces.ec_add_main(), &[(COL_GEN, 0), (COL_DBL, 1)]);
    let mut rng = StdRng::seed_from_u64(0xecad_da02);
    check_ec_add(&forged);

    let mut mains = traces.mains();
    mains[6] = &forged;
    assert_ne!(stack_residual(&mains, &mut rng), 0);
}

#[test]
fn cancel_forged_on_distinct_x_unbalances() {
    // G + (β·Gx, −Gy): the y's cancel but the x's differ — an honest
    // *generic* configuration. Forging cancel (tying R to the PAI row)
    // satisfies every constraint, but cancel demands the x₁ + 0 ≡ x₂
    // equality certificate, unrecordable across distinct x's — exactly
    // the certificate that keeps "vertical chord" forgeries out.
    let mut k1 = k1_stack();
    let pai = k1.pai;
    let mut ec = k1.stack.require();
    let q_pt = ec.add_point(k1.group, from_hex(BETA_GX), from_hex(NEG_GY));
    ec.add(k1.g_pt, q_pt, 0);
    let traces = k1.stack.traces();

    // Clear mints too: a real forger vacates the (now-false) mint claim, so
    // the cancel x-equality certificate — not the ptr-ordering — is what
    // must reject this (an honest generic mint set mints = 1 here).
    let mut forged =
        tamper_block0(traces.ec_add_main(), &[(COL_GEN, 0), (COL_CANCEL, 1), (COL_MINTS, 0)]);
    tamper_cell(&mut forged, ROW_RES, CELL_R, pai.addr());
    let mut rng = StdRng::seed_from_u64(0xecad_da06);
    check_ec_add(&forged);

    let mut mains = traces.mains();
    mains[6] = &forged;
    assert_ne!(stack_residual(&mains, &mut rng), 0);
}

#[test]
fn finite_forged_as_pai_unbalances() {
    // Claim pai_p against a finite P, tying r = q to satisfy the
    // pass-through constraint. Every local constraint holds — but the
    // forged flag rides P's consumed tuple as is_pai = 1, which no
    // store row provides (and the certificates the require layer
    // recorded dangle), so the bus rejects what the AIR cannot see.
    let mut k1 = k1_stack();
    k1.stack.require().add(k1.g_pt, k1.g2_pt, 0);
    let q_ptr = k1.g2_pt;
    let traces = k1.stack.traces();

    let mut forged =
        tamper_block0(traces.ec_add_main(), &[(COL_GEN, 0), (COL_PAI_P, 1), (COL_MINTS, 0)]);
    tamper_cell(&mut forged, ROW_RES, CELL_R, q_ptr.addr());
    let mut rng = StdRng::seed_from_u64(0xecad_da03);
    check_ec_add(&forged);

    let mut mains = traces.mains();
    mains[6] = &forged;
    assert_ne!(stack_residual(&mains, &mut rng), 0);
}

#[test]
fn double_forged_as_cancel_unbalances() {
    // Claim cancel on an honest doubling, repointing R at the PAI row:
    // constraints hold (and the x-equality certificate even exists —
    // double recorded it), but cancel's is_c_zero certificate
    // (bound, y₁, y₂, 0) was never recorded — y₁ + y₂ = 2y ≠ 0 is
    // exactly what makes it unrecordable — and double's tangent / tail
    // certificates dangle. Structural disjointness, policed by the bus.
    let mut k1 = k1_stack();
    k1.stack.require().add(k1.g_pt, k1.g_pt, 0);
    let pai = k1.pai;
    let traces = k1.stack.traces();

    let mut forged = tamper_block0(traces.ec_add_main(), &[(COL_DBL, 0), (COL_CANCEL, 1)]);
    tamper_cell(&mut forged, ROW_RES, CELL_R, pai.addr());
    let mut rng = StdRng::seed_from_u64(0xecad_da04);
    check_ec_add(&forged);

    let mut mains = traces.mains();
    mains[6] = &forged;
    assert_ne!(stack_residual(&mains, &mut rng), 0);
}

#[test]
fn forged_result_ptr_unbalances() {
    // Repoint R at a different stored point: the result consume binds
    // (r, group, x₃, y₃) and G's row binds different coordinates — no
    // provide matches, and the honest R row's demanded tuple dangles.
    let mut k1 = k1_stack();
    k1.stack.require().add(k1.g_pt, k1.g2_pt, 0);
    let g_pt = k1.g_pt;
    let traces = k1.stack.traces();

    // Clear mints (the honest generic op minted R, mints = 1): repointing R
    // would otherwise be caught locally by the ptr-ordering reconstruction;
    // here we want the EcPoint-mismatch bus catch.
    let mut forged = tamper_block0(traces.ec_add_main(), &[(COL_MINTS, 0)]);
    tamper_cell(&mut forged, ROW_RES, CELL_R, g_pt.addr());
    let mut rng = StdRng::seed_from_u64(0xecad_da05);
    check_ec_add(&forged);

    let mut mains = traces.mains();
    mains[6] = &forged;
    assert_ne!(stack_residual(&mains, &mut rng), 0);
}

// ============================================================================
// Closure-certificate soundness (Phase 2). A fresh generic / double result
// no longer pays the on-curve MAC trio — its point-store row consumes one
// `EcOnCurveCert`, provided only by a genuine mint op (gated `mints`, with
// the case guard `mints ⟹ generic ∨ double` and the strict ptr ordering
// `r > p ∧ r > q`). These check the two forgeries the cert's well-foundedness
// rests on, plus that the cert consume is load-bearing.
// ============================================================================

#[test]
#[should_panic(expected = "constraint")]
fn passthrough_cannot_mint() {
    // The pass-through cycle: ∞ + G = G ties r to an operand. A forger sets
    // mints = 1 to *cert* that operand (forging membership for a point it
    // didn't compute). The case guard `mints ⟹ generic ∨ double` rejects it
    // locally — a pai case can never mint — and the ordering (r = q, so
    // r ≯ q) piles on. Without the guard a pass-through could mint a cert
    // for an off-curve point laundered through the tie.
    let mut k1 = k1_stack();
    k1.stack.require().add(k1.pai, k1.g_pt, 0);
    let traces = k1.stack.traces();

    let forged = tamper_block0(traces.ec_add_main(), &[(COL_MINTS, 1)]);
    check_ec_add(&forged);
}

#[test]
#[should_panic(expected = "constraint")]
fn mint_result_equal_operand_rejected() {
    // The live fixed-point: an honest generic mint (G + 2G = 3G) forged so
    // its result *is* an operand (r := p = G), keeping mints = 1 to
    // self-certify. The strict ordering r > p is exactly what forbids it —
    // r − p − 1 = −1 reconstructs against no in-range limbs, so the
    // ptr-ordering constraint rejects it locally (a point may only cite
    // strictly-smaller operands, grounding the induction).
    let mut k1 = k1_stack();
    k1.stack.require().add(k1.g_pt, k1.g2_pt, 0);
    let g_pt = k1.g_pt;
    let traces = k1.stack.traces();

    let mut forged = traces.ec_add_main().clone();
    tamper_cell(&mut forged, ROW_RES, CELL_R, g_pt.addr());
    check_ec_add(&forged);
}

#[test]
fn cert_point_forged_as_trio_unbalances() {
    // Necessity of the cert consume: 3G = G + 2G is a fresh mint, so its
    // point-store row rides the closure cert (is_cert = 1, no trio). Flipping
    // it to trio mode (is_cert → 0) is locally valid — the row carries
    // u = w = 0, so the trio-suppression constraints still hold — but now the
    // row *demands* the three membership MACs (which a cert point never
    // recorded) while the mint op's cert provide loses its consumer. Both
    // dangle: the bus rejects what the store AIR cannot see.
    let mut k1 = k1_stack();
    let r = k1.stack.require().add(k1.g_pt, k1.g2_pt, 0);
    let traces = k1.stack.traces();

    let forged = tamper_ec_points(traces.ec_points_main(), r.addr() as usize - 1, COL_IS_CERT, 0);
    let mut rng = StdRng::seed_from_u64(0xecad_dce3);
    let mut mains = traces.mains();
    mains[5] = &forged;
    assert_ne!(stack_residual(&mains, &mut rng), 0);
}
