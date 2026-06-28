//! EcMsm session integration tests.

use miden_core::{Felt, field::QuadFelt};
use miden_lifted_air::{MultiAir, ProverStatement, ReductionError, Statement};
use miden_lifted_stark::check_constraints;
use p3_matrix::Matrix;

use crate::{
    ec::{
        EcStores,
        msm::{
            NUM_MAIN_COLS, require as msm_require,
            trace::{EcMsmRequires, generate_trace},
        },
        trace::generate_traces as ec_store_traces,
    },
    math::from_hex,
    primitives::byte_pair_lut::{BytePairLutRequires, generate_trace as bpl_trace},
    session::{ChipletAir, NUM_CHIPLETS, Session},
    stark_config::test_challenger,
    uint::{
        UintStores,
        add::trace::generate_trace as uint_add_trace,
        mul::trace::generate_trace as uint_mul_trace,
        trace::{UintStoreRequires, generate_trace as uint_trace},
    },
};

const P_MINUS_1: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E";
const N_MINUS_1: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140";
const GX: &str = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
const GY: &str = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
const G2X: &str = "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5";
const G2Y: &str = "1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A";

#[test]
fn empty_msm_trace_has_stable_shape() {
    let mut uint = UintStoreRequires::new();
    let mut bpl = BytePairLutRequires::new();
    let main = generate_trace(Default::default(), &mut uint, &mut bpl);

    assert_eq!(main.width(), NUM_MAIN_COLS);
    assert_eq!(main.height(), 2);
    crate::tests::check_local(crate::ec::msm::EcMsmAir, &main);
}

#[test]
fn default_session_includes_empty_msm_chiplet() {
    let mut session = Session::new();
    let root = session.zero();
    let traces = session.finish(root);

    assert_eq!(traces.mains().len(), NUM_CHIPLETS);
    assert_eq!(traces.msm_main().width(), NUM_MAIN_COLS);
    assert_eq!(traces.msm_main().height(), 2);

    traces.check();
}

#[test]
fn non_empty_msm_require_stack_balances() {
    let mut uint = UintStores::new();
    let fp = uint.store.pin_modulus(1, from_hex(P_MINUS_1));
    let fs = uint.store.pin_modulus(2, from_hex(N_MINUS_1));
    let mut ec = EcStores::new();
    let mut msm = EcMsmRequires::new();

    let (g, g2) = {
        let (group, _) = ec.require(uint.require()).create_group(from_hex("0"), from_hex("7"), fp);
        ec.require(uint.require()).constrain_scalar_bound(group, fs);
        let g = ec.require(uint.require()).add_point(group, from_hex(GX), from_hex(GY));
        let g2 = ec.require(uint.require()).add_point(group, from_hex(G2X), from_hex(G2Y));
        (g, g2)
    };

    let g_expr = msm_require::intro(&mut msm, &mut ec, &mut uint, g);
    let g2_expr = msm_require::intro(&mut msm, &mut ec, &mut uint, g2);
    let sum_expr = msm_require::combine(&mut msm, &mut ec, &mut uint, g_expr, g2_expr);
    let _neg_sum = msm_require::neg(&mut msm, &mut ec, &mut uint, sum_expr);

    let traces = MsmStackTraces::from_requires(uint, ec, msm);
    assert!(traces.msm_main().height() > 2, "the MSM chiplet must contain active rows");
    traces.check();
}

const NUM_MSM_STACK: usize = 8;

struct MsmStackTraces([p3_matrix::dense::RowMajorMatrix<Felt>; NUM_MSM_STACK]);

fn msm_stack_airs() -> [ChipletAir; NUM_MSM_STACK] {
    [
        ChipletAir::BytePairLut,
        ChipletAir::UintStore,
        ChipletAir::UintAdd,
        ChipletAir::UintMul,
        ChipletAir::EcGroups,
        ChipletAir::EcPointStore,
        ChipletAir::EcGroupAdd,
        ChipletAir::EcMsm,
    ]
}

#[derive(Clone, Debug)]
struct MsmStackMultiAir {
    airs: Vec<ChipletAir>,
}

impl MsmStackMultiAir {
    fn new() -> Self {
        Self { airs: msm_stack_airs().to_vec() }
    }
}

impl MultiAir<Felt, QuadFelt> for MsmStackMultiAir {
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
        Ok(vec![crate::logup::sigma_sum(aux_values)])
    }
}

impl MsmStackTraces {
    fn from_requires(mut uint: UintStores, mut ec: EcStores, msm: EcMsmRequires) -> Self {
        let mut bpl = BytePairLutRequires::new();
        let uint_add = uint_add_trace(uint.add, &mut uint.store);
        let uint_mul = uint_mul_trace(uint.mul, &mut uint.store, &mut bpl);
        let ec_add = crate::ec::add::trace::generate_trace(ec.add, &mut ec.store, &mut bpl);
        let msm = generate_trace(msm, &mut uint.store, &mut bpl);
        ec.store.route_uintval_demands(&mut uint.store);
        let uint_store = uint_trace(uint.store, &mut bpl);
        let (ec_groups, ec_points) = ec_store_traces(ec.store);
        Self([
            bpl_trace(bpl),
            uint_store,
            uint_add,
            uint_mul,
            ec_groups,
            ec_points,
            ec_add,
            msm,
        ])
    }

    fn msm_main(&self) -> &p3_matrix::dense::RowMajorMatrix<Felt> {
        &self.0[7]
    }

    fn check(&self) {
        let statement = Statement::new(
            MsmStackMultiAir::new(),
            vec![Felt::ZERO; crate::logup::NUM_PUBLIC_VALUES],
            Vec::new(),
        )
        .expect("MSM subset statement inputs are valid");
        let mains = self.0.to_vec();
        let prover_statement =
            ProverStatement::new(statement, mains).expect("MSM subset trace shapes are valid");
        check_constraints(&prover_statement, test_challenger());
    }
}
