//! Fixed-catalogue admission at the transcript boundary.

use std::vec::Vec;

use miden_air::precompiles::ChipletAir;
use miden_core::{Felt, utils::RowMajorMatrix};
use miden_precompiles::{CurveId, CurvePoint, UintDomain};

use super::{
    SessionTracesTestExt, assert_local_rejects_inputs, check_local_inputs, verify_deferred,
};
use crate::prover::{
    math::{U256, from_limbs32},
    session::{Session, SessionTraces},
    transcript::eval::{
        COL_BOUND_PTR, COL_EC_CONTEXT_GROUP_PTR, COL_FRAME_PARAM1, COL_IS_EC_CREATE, COL_IS_EC_MSM,
        COL_IS_EC_OP, COL_IS_EC_PAI, COL_IS_IS, COL_IS_MSM_LAST, COL_IS_SUB, COL_IS_UINT_LEAF,
        COL_IS_UINT_OP, COL_UINT_DOMAIN_SELECTOR, NUM_MAIN_COLS, TranscriptEvalAir,
    },
};

fn assert_transcript_rejects(main: &RowMajorMatrix<Felt>, inputs: Vec<Felt>) {
    assert_local_rejects_inputs(TranscriptEvalAir, main, inputs.clone());
    assert_local_rejects_inputs(ChipletAir::TRANSCRIPT_EVAL, main, inputs);
}

fn catalogue_traces() -> SessionTraces {
    let mut session = Session::new();
    let mut claims = Vec::new();
    for domain in UintDomain::ALL {
        let a = session.uint_leaf(U256::from(7u8), domain.bound_ptr());
        let b = session.uint_add(&a, &a);
        claims.push(session.uint_is(&b, &b));
    }
    for curve in CurveId::ALL {
        let CurvePoint::Affine { x, y } = curve.generator() else {
            panic!("finite generator")
        };
        let x = session.uint_leaf(from_limbs32(&x), curve.base_domain().bound_ptr());
        let y = session.uint_leaf(from_limbs32(&y), curve.base_domain().bound_ptr());
        let point = session.ec_create(curve.group_ptr(), &x, &y);
        let identity = session.ec_pai(curve.group_ptr());
        let sum = session.ec_add(&point, &identity);
        let difference = session.ec_sub(&sum, &identity);
        claims.push(session.ec_is(&difference, &point));
        let expr = session.msm_intro(&point);
        let scalar = session.uint_leaf(U256::from(1u8), curve.scalar_domain().bound_ptr());
        let result = session.ec_msm(expr, &[(point, scalar)]);
        claims.push(session.ec_is(&result, &point));
    }
    let root = session.assert_and_fold(claims);
    session.finish(root)
}

#[test]
fn fixed_native_catalogue_checks() {
    catalogue_traces().check();
}

#[test]
#[ignore = "full prove/verify round-trip; run explicitly"]
fn fixed_native_catalogue_proves() {
    verify_deferred(&catalogue_traces().prove())
        .expect("all native uint domains and curves must verify");
}

#[test]
fn unknown_uint_bound_is_rejected_in_every_context() {
    let traces = catalogue_traces();
    let main = traces.mains()[ChipletAir::TRANSCRIPT_EVAL_INDEX];
    let inputs = traces.public_root().as_array().to_vec();
    check_local_inputs(TranscriptEvalAir, main, inputs.clone());
    for family in [COL_IS_UINT_LEAF, COL_IS_UINT_OP, COL_IS_EC_CREATE, COL_IS_EC_MSM] {
        let row = main
            .values
            .as_chunks::<NUM_MAIN_COLS>()
            .0
            .iter()
            .position(|row| row[family] == Felt::ONE)
            .expect("context is exercised");
        // Cover the catalogue's gaps, both outer boundaries, and large field elements under
        // every selector. On VALUE rows, update the frame so it cannot mask admission.
        for bound in [0, 7, 13, 16, 60_000].map(Felt::from_u32).into_iter().chain([-Felt::ONE]) {
            for selector in [0, 3, 8] {
                let mut tampered = main.clone();
                let row = &mut tampered.values[row * NUM_MAIN_COLS..(row + 1) * NUM_MAIN_COLS];
                row[COL_BOUND_PTR] = bound;
                if family == COL_IS_UINT_LEAF {
                    row[COL_FRAME_PARAM1] = bound;
                }
                row[COL_UINT_DOMAIN_SELECTOR] = Felt::from_u8(selector);
                assert_transcript_rejects(&tampered, inputs.clone());
            }
        }
    }
}

#[test]
fn shared_uint_bound_accepts_either_catalogue_group() {
    let traces = catalogue_traces();
    let mut main = traces.mains()[ChipletAir::TRANSCRIPT_EVAL_INDEX].clone();
    let row = main
        .values
        .as_chunks_mut::<NUM_MAIN_COLS>()
        .0
        .iter_mut()
        .find(|row| row[COL_IS_UINT_LEAF] == Felt::ONE && row[COL_BOUND_PTR] == Felt::ONE)
        .expect("U256 leaf");
    // The builder uses selector 0 for bound 1. Selector 8 repeats that supported bound
    // as its third root, alongside 14 and 15; it must not introduce another bound.
    row[COL_UINT_DOMAIN_SELECTOR] = Felt::from_u8(8);
    let inputs = traces.public_root().as_array().to_vec();
    check_local_inputs(TranscriptEvalAir, &main, inputs.clone());
    check_local_inputs(ChipletAir::TRANSCRIPT_EVAL, &main, inputs);
}

#[test]
fn uint_domain_selector_must_select_a_catalogue_group() {
    let traces = catalogue_traces();
    let main = traces.mains()[ChipletAir::TRANSCRIPT_EVAL_INDEX];
    let row = main
        .values
        .as_chunks::<NUM_MAIN_COLS>()
        .0
        .iter()
        .position(|row| row[COL_IS_UINT_LEAF] == Felt::ONE)
        .unwrap();
    let mut tampered = main.clone();
    let row = &mut tampered.values[row * NUM_MAIN_COLS..(row + 1) * NUM_MAIN_COLS];
    // At bound 2, the membership cubic is selector*(11*selector - 49). This
    // nonzero root must be rejected by the separate selector constraint.
    row[COL_UINT_DOMAIN_SELECTOR] = Felt::from_u8(49) / Felt::from_u8(11);
    row[COL_BOUND_PTR] = Felt::from_u8(2);
    row[COL_FRAME_PARAM1] = row[COL_BOUND_PTR];
    assert_transcript_rejects(&tampered, traces.public_root().as_array().to_vec());
}

#[test]
fn native_registry_rejects_unknown_uint_bound() {
    use miden_core::{
        deferred::{EidosFrame, PrecompileError},
        program::domain::Uint256PrecompileDomain,
    };
    let frame = EidosFrame::for_domain(Uint256PrecompileDomain, [0, 60_000, 0]);
    assert!(matches!(miden_precompiles::registry().decode_precompile_frame(frame),
        Err(PrecompileError::Precompile { source, .. }) if matches!(*source, PrecompileError::InvalidNode)));
}

#[test]
fn unknown_curve_group_is_rejected_in_every_context() {
    let traces = catalogue_traces();
    let main = traces.mains()[ChipletAir::TRANSCRIPT_EVAL_INDEX];
    let rows = main.values.as_chunks::<NUM_MAIN_COLS>().0;
    let inputs = traces.public_root().as_array().to_vec();
    for (family, is_sub) in [
        (COL_IS_EC_CREATE, false),
        (COL_IS_EC_PAI, false),
        (COL_IS_EC_OP, false),
        (COL_IS_EC_OP, true),
        (COL_IS_EC_MSM, false),
    ] {
        let start = rows
            .iter()
            .position(|row| {
                row[family] == Felt::ONE
                    && row[COL_IS_IS] == Felt::ZERO
                    && (row[COL_IS_SUB] == Felt::ONE) == is_sub
            })
            .expect("curve context is exercised");
        // Change the whole MSM run so group constancy cannot mask admission.
        let end = if family == COL_IS_EC_MSM {
            start
                + rows[start..]
                    .iter()
                    .position(|row| row[COL_IS_MSM_LAST] == Felt::ONE)
                    .expect("MSM run has a tail")
                + 1
        } else {
            start + 1
        };
        for group in [0, 4, 60_000].map(Felt::from_u32).into_iter().chain([-Felt::ONE]) {
            let mut tampered = main.clone();
            for row in tampered.values[start * NUM_MAIN_COLS..end * NUM_MAIN_COLS]
                .as_chunks_mut::<NUM_MAIN_COLS>()
                .0
            {
                row[COL_EC_CONTEXT_GROUP_PTR] = group;
                // Keep both copies equal so the frame constraint cannot mask admission.
                if matches!(family, COL_IS_EC_CREATE | COL_IS_EC_PAI) {
                    row[COL_FRAME_PARAM1] = group;
                }
            }
            assert_transcript_rejects(&tampered, inputs.clone());
        }
    }
}

#[test]
fn curve_value_frame_must_match_its_group() {
    let traces = catalogue_traces();
    let main = traces.mains()[ChipletAir::TRANSCRIPT_EVAL_INDEX];
    let inputs = traces.public_root().as_array().to_vec();
    for family in [COL_IS_EC_CREATE, COL_IS_EC_PAI] {
        let row = main
            .values
            .as_chunks::<NUM_MAIN_COLS>()
            .0
            .iter()
            .position(|row| row[family] == Felt::ONE)
            .expect("curve value context is exercised");
        let other_group = CurveId::ALL
            .into_iter()
            .map(|curve| Felt::from(curve.group_ptr()))
            .find(|group| *group != main.values[row * NUM_MAIN_COLS + COL_EC_CONTEXT_GROUP_PTR])
            .unwrap();
        // Each group is supported, isolating the equality between the two cells.
        for column in [COL_FRAME_PARAM1, COL_EC_CONTEXT_GROUP_PTR] {
            let mut tampered = main.clone();
            tampered.values[row * NUM_MAIN_COLS + column] = other_group;
            assert_transcript_rejects(&tampered, inputs.clone());
        }
    }
}

#[test]
fn point_equality_has_no_curve_context() {
    let traces = catalogue_traces();
    let main = traces.mains()[ChipletAir::TRANSCRIPT_EVAL_INDEX];
    let row = main
        .values
        .as_chunks::<NUM_MAIN_COLS>()
        .0
        .iter()
        .position(|row| row[COL_IS_EC_OP] == Felt::ONE && row[COL_IS_IS] == Felt::ONE)
        .expect("point equality is exercised");
    let mut tampered = main.clone();
    tampered.values[row * NUM_MAIN_COLS + COL_EC_CONTEXT_GROUP_PTR] =
        Felt::from(CurveId::Secp256k1.group_ptr());
    assert_transcript_rejects(&tampered, traces.public_root().as_array().to_vec());
}

#[test]
fn native_registry_rejects_unknown_curve_group() {
    use miden_core::{
        deferred::{EidosFrame, PrecompileError},
        program::domain::CurvePrecompileDomain,
    };
    let frame = EidosFrame::for_domain(CurvePrecompileDomain, [0, 60_000, 0]);
    assert!(matches!(miden_precompiles::registry().decode_precompile_frame(frame),
        Err(PrecompileError::Precompile { source, .. }) if matches!(*source, PrecompileError::InvalidNode)));
}
