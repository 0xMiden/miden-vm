//! Transcript eval chiplet for assertion and uint DAG nodes.

pub mod trace;

use core::array;

use miden_core::{
    Felt,
    deferred::Tag,
    field::{PrimeCharacteristicRing, QuadFelt},
};
use miden_lifted_air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder};
use miden_precompiles::{CurvePrecompile, UintDomain, UintPrecompile};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    ec::{EcGroupMsg, EcPointMsg, add::EcGroupAddMsg},
    logup::{
        CyclicConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn,
        LookupGroup, NUM_RANDOMNESS, NUM_SIGMA_VALUES,
    },
    relations::{FieldMsg, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    transcript::{
        binding::{BindingMsg, ValueTag},
        nodes::{EcOpId, UintOpId},
        poseidon2::{Poseidon2InMsg, Poseidon2OutMsg},
    },
    uint::{UintValMsg, add::UintAddMsg, mul::UintMulMsg},
    utils::{current_main, next_main},
};

pub const COL_ACT: usize = 0;
pub const COL_PERM_SEQ_ID: usize = 1;
pub const COL_LHS_BEGIN: usize = 2;
pub const NUM_HASH: usize = 4;
pub const COL_RHS_BEGIN: usize = COL_LHS_BEGIN + NUM_HASH;
pub const COL_H_BEGIN: usize = COL_RHS_BEGIN + NUM_HASH;
pub const COL_IS_ZERO: usize = COL_H_BEGIN + NUM_HASH;
pub const COL_OUT_MULT: usize = COL_IS_ZERO + 1;
pub const COL_IS_AND: usize = COL_OUT_MULT + 1;
pub const COL_IS_UINT_LEAF: usize = COL_IS_AND + 1;
pub const COL_IS_UINT_OP: usize = COL_IS_UINT_LEAF + 1;
pub const COL_IS_EC_CREATE: usize = COL_IS_UINT_OP + 1;
pub const COL_IS_EC_PAI: usize = COL_IS_EC_CREATE + 1;
pub const COL_IS_EC_OP: usize = COL_IS_EC_PAI + 1;
pub const COL_IS_ADD: usize = COL_IS_EC_OP + 1;
pub const COL_IS_SUB: usize = COL_IS_ADD + 1;
pub const COL_IS_MUL: usize = COL_IS_SUB + 1;
pub const COL_IS_NEG: usize = COL_IS_MUL + 1;
pub const COL_IS_IS: usize = COL_IS_NEG + 1;
pub const COL_IS_PINNED: usize = COL_IS_IS + 1;
pub const COL_PTR: usize = COL_IS_PINNED + 1;
pub const COL_BOUND_PTR: usize = COL_PTR + 1;
pub const COL_PIN_PTR: usize = COL_BOUND_PTR + 1;
pub const COL_A_PTR: usize = COL_PIN_PTR + 1;
pub const COL_B_PTR: usize = COL_A_PTR + 1;
pub const COL_PARAM_A: usize = COL_B_PTR + 1;
pub const COL_GROUP_PTR: usize = COL_PARAM_A + 1;
pub const COL_CURVE_B: usize = COL_GROUP_PTR + 1;
pub const COL_SBOUND_PTR: usize = COL_CURVE_B + 1;
pub const COL_ABSORB_CAP_BEGIN: usize = COL_SBOUND_PTR + 1;
pub const COL_ABSORB_CAP_END: usize = COL_ABSORB_CAP_BEGIN + NUM_HASH;
pub const COL_IS_FIELD_TAG: usize = COL_ABSORB_CAP_END;
pub const NUM_MAIN_COLS: usize = COL_IS_FIELD_TAG + 1;

pub const PUBLIC_ROOT_BEGIN: usize = 0;
pub const PUBLIC_ROOT_END: usize = PUBLIC_ROOT_BEGIN + NUM_HASH;
pub const NUM_PUBLIC_VALUES: usize = PUBLIC_ROOT_END;

pub const NUM_AUX_COLS: usize = 9;
const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [3, 5, 3, 2, 2, 4, 3, 3, 1];

#[derive(Debug, Default, Clone, Copy)]
pub struct TranscriptEvalAir;

impl BaseAir<Felt> for TranscriptEvalAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

fn domain_selector<AB: LiftedAirBuilder<F = Felt>>(
    domain_id: AB::Expr,
    domain: UintDomain,
) -> AB::Expr {
    let mut selector = AB::Expr::ONE;
    let id = domain.id();
    for other in UintDomain::ALL {
        if other == UintDomain::U256 || other == domain {
            continue;
        }
        let denominator = (id - other.id()).inverse();
        selector = selector
            * (domain_id.clone() - AB::Expr::from(other.id()))
            * AB::Expr::from(denominator);
    }
    selector
}

impl LiftedAir<Felt, QuadFelt> for TranscriptEvalAir {
    fn num_randomness(&self) -> usize {
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        NUM_AUX_COLS
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
        trace::build_aux(main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let next: [AB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);

        let act: AB::Expr = local[COL_ACT].into();
        let act_next: AB::Expr = next[COL_ACT].into();
        let is_zero: AB::Expr = local[COL_IS_ZERO].into();
        let out_mult: AB::Expr = local[COL_OUT_MULT].into();
        let h: [AB::Expr; NUM_HASH] = array::from_fn(|i| local[COL_H_BEGIN + i].into());
        let public_root: [AB::Expr; NUM_HASH] =
            array::from_fn(|i| builder.public_values()[PUBLIC_ROOT_BEGIN + i].into());

        builder.assert_bool(local[COL_ACT]);
        builder.when_transition().assert_zero((AB::Expr::ONE - act.clone()) * act_next);
        builder.assert_zero((AB::Expr::ONE - act.clone()) * out_mult.clone());

        for i in 0..NUM_HASH {
            builder.assert_zero(is_zero.clone() * h[i].clone());
            builder.when_first_row().assert_zero(h[i].clone() - public_root[i].clone());
        }

        for col in [
            COL_IS_ZERO,
            COL_IS_AND,
            COL_IS_UINT_LEAF,
            COL_IS_UINT_OP,
            COL_IS_EC_CREATE,
            COL_IS_EC_PAI,
            COL_IS_EC_OP,
            COL_IS_ADD,
            COL_IS_SUB,
            COL_IS_MUL,
            COL_IS_NEG,
            COL_IS_IS,
            COL_IS_PINNED,
            COL_IS_FIELD_TAG,
        ] {
            builder.assert_bool(local[col]);
        }

        let is_and: AB::Expr = local[COL_IS_AND].into();
        let is_uint_leaf: AB::Expr = local[COL_IS_UINT_LEAF].into();
        let is_uint_op: AB::Expr = local[COL_IS_UINT_OP].into();
        let is_ec_create: AB::Expr = local[COL_IS_EC_CREATE].into();
        let is_ec_pai: AB::Expr = local[COL_IS_EC_PAI].into();
        let is_ec_op: AB::Expr = local[COL_IS_EC_OP].into();
        let is_field_tag: AB::Expr = local[COL_IS_FIELD_TAG].into();
        let is_add: AB::Expr = local[COL_IS_ADD].into();
        let is_sub: AB::Expr = local[COL_IS_SUB].into();
        let is_mul: AB::Expr = local[COL_IS_MUL].into();
        let is_neg: AB::Expr = local[COL_IS_NEG].into();
        let is_is: AB::Expr = local[COL_IS_IS].into();
        let is_op =
            is_add.clone() + is_sub.clone() + is_mul.clone() + is_neg.clone() + is_is.clone();
        builder.assert_zero(is_op.clone() - is_uint_op.clone() - is_ec_op.clone());
        builder.assert_zero(is_uint_op.clone() * is_neg.clone());
        builder.assert_zero(is_ec_op.clone() * is_mul.clone());
        let is_create = is_ec_create.clone() + is_ec_pai.clone();
        builder.assert_zero(
            is_and.clone()
                + is_zero.clone()
                + is_field_tag.clone()
                + is_uint_leaf.clone()
                + is_uint_op.clone()
                + is_ec_create.clone()
                + is_ec_pai.clone()
                + is_ec_op.clone()
                - act,
        );

        let is_pinned: AB::Expr = local[COL_IS_PINNED].into();
        builder
            .when_first_row()
            .assert_zero(AB::Expr::ONE - is_zero - is_and - is_is.clone() - is_pinned.clone());

        let ptr: AB::Expr = local[COL_PTR].into();
        let bound_ptr: AB::Expr = local[COL_BOUND_PTR].into();
        let pin_ptr: AB::Expr = local[COL_PIN_PTR].into();
        let a_ptr: AB::Expr = local[COL_A_PTR].into();
        let b_ptr: AB::Expr = local[COL_B_PTR].into();
        let param_a: AB::Expr = local[COL_PARAM_A].into();
        let group_ptr: AB::Expr = local[COL_GROUP_PTR].into();
        let curve_b: AB::Expr = local[COL_CURVE_B].into();
        let sbound_ptr: AB::Expr = local[COL_SBOUND_PTR].into();
        let is_result_op = is_op.clone() - is_is.clone();
        let field_domain_id = h[2].clone();

        builder.assert_zero((AB::Expr::ONE - is_uint_leaf.clone()) * is_pinned.clone());
        builder.when_transition().assert_zero(next[COL_IS_PINNED]);
        builder.assert_zero(is_pinned.clone() * out_mult);
        builder.assert_zero((AB::Expr::ONE - is_pinned.clone()) * pin_ptr.clone());
        builder.assert_zero(is_pinned * (pin_ptr - ptr.clone()));
        builder.assert_zero(
            (AB::Expr::ONE - is_uint_leaf.clone() - is_result_op - is_create.clone()) * ptr,
        );
        builder.assert_zero(
            (AB::Expr::ONE
                - is_uint_leaf.clone()
                - is_uint_op.clone()
                - is_create.clone()
                - is_field_tag.clone())
                * bound_ptr,
        );
        builder.assert_zero((AB::Expr::ONE - is_op.clone() - is_ec_create.clone()) * a_ptr.clone());
        builder.assert_zero(
            (AB::Expr::ONE - is_op + is_neg.clone() * is_uint_op.clone() - is_ec_create)
                * b_ptr.clone(),
        );
        builder.assert_zero(is_is.clone() * (b_ptr - a_ptr));
        for i in 0..NUM_HASH {
            let lhs_i: AB::Expr = local[COL_LHS_BEGIN + i].into();
            let rhs_i: AB::Expr = local[COL_RHS_BEGIN + i].into();
            builder.assert_zero(is_neg.clone() * rhs_i.clone());
            builder.assert_zero(is_ec_pai.clone() * lhs_i);
            builder.assert_zero(is_ec_pai.clone() * rhs_i);
        }
        builder.assert_zero(
            (AB::Expr::ONE
                - is_create.clone()
                - is_ec_op.clone() * (AB::Expr::ONE - is_is.clone()))
                * group_ptr,
        );
        builder.assert_zero((AB::Expr::ONE - is_create.clone()) * curve_b);
        builder.assert_zero((AB::Expr::ONE - is_create.clone()) * sbound_ptr);
        builder.assert_zero(
            is_field_tag.clone() * (h[0].clone() - AB::Expr::from(UintPrecompile::id())),
        );
        builder.assert_zero(is_field_tag.clone() * h[1].clone());
        builder.assert_zero(is_field_tag.clone() * h[3].clone());

        let mut supported_domain = AB::Expr::ONE;
        for domain in UintDomain::ALL {
            if domain != UintDomain::U256 {
                supported_domain *= field_domain_id.clone() - AB::Expr::from(domain.id());
            }
        }
        builder.assert_zero(is_field_tag.clone() * supported_domain);

        for i in 0..8 {
            let actual: AB::Expr = if i < NUM_HASH {
                local[COL_LHS_BEGIN + i].into()
            } else {
                local[COL_RHS_BEGIN + i - NUM_HASH].into()
            };
            let mut expected = AB::Expr::ZERO;
            for domain in UintDomain::ALL {
                if domain == UintDomain::U256 {
                    continue;
                }
                expected += domain_selector::<AB>(field_domain_id.clone(), domain)
                    * AB::Expr::from(Felt::from_u32(domain.minus_one()[i]));
            }
            builder.assert_zero(is_field_tag.clone() * (actual - expected));
        }

        let uint_op_id: AB::Expr = is_add.clone()
            + is_sub.clone() * AB::Expr::from(Felt::from(UintOpId::Sub as u8))
            + is_mul * AB::Expr::from(Felt::from(UintOpId::Mul as u8))
            + is_neg.clone() * AB::Expr::from(Felt::from(UintOpId::Neg as u8))
            + is_is.clone() * AB::Expr::from(Felt::from(UintOpId::Is as u8));
        let ec_op_id: AB::Expr = is_add
            + is_sub * AB::Expr::from(Felt::from(EcOpId::Sub as u8))
            + is_neg * AB::Expr::from(Felt::from(EcOpId::Neg as u8))
            + is_is * AB::Expr::from(Felt::from(EcOpId::Is as u8));
        let op_param = is_uint_op.clone() * uint_op_id + is_ec_op * ec_op_id;
        builder.assert_zero((AB::Expr::ONE - is_create.clone()) * (param_a - op_param));

        let field_consumer = is_uint_leaf + is_uint_op + is_create;
        for i in 0..NUM_HASH {
            let cap_i: AB::Expr = local[COL_ABSORB_CAP_BEGIN + i].into();
            builder.assert_zero((AB::Expr::ONE - field_consumer.clone()) * cap_i);
        }

        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

impl<LB> LookupAir<LB> for TranscriptEvalAir
where
    LB: LookupBuilder<F = Felt>,
{
    fn num_columns(&self) -> usize {
        NUM_AUX_COLS
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

        let is_and: LB::Expr = local[COL_IS_AND].into();
        let is_zero: LB::Expr = local[COL_IS_ZERO].into();
        let is_uint_leaf: LB::Expr = local[COL_IS_UINT_LEAF].into();
        let is_uint_op: LB::Expr = local[COL_IS_UINT_OP].into();
        let is_ec_create: LB::Expr = local[COL_IS_EC_CREATE].into();
        let is_ec_pai: LB::Expr = local[COL_IS_EC_PAI].into();
        let is_ec_op: LB::Expr = local[COL_IS_EC_OP].into();
        let is_create = is_ec_create.clone() + is_ec_pai;
        let is_field_tag: LB::Expr = local[COL_IS_FIELD_TAG].into();
        let is_pinned: LB::Expr = local[COL_IS_PINNED].into();
        let is_add: LB::Expr = local[COL_IS_ADD].into();
        let is_sub: LB::Expr = local[COL_IS_SUB].into();
        let is_mul: LB::Expr = local[COL_IS_MUL].into();
        let is_neg: LB::Expr = local[COL_IS_NEG].into();
        let is_is: LB::Expr = local[COL_IS_IS].into();
        let perm_seq_id: LB::Expr = local[COL_PERM_SEQ_ID].into();
        let out_mult: LB::Expr = local[COL_OUT_MULT].into();
        let ptr: LB::Expr = local[COL_PTR].into();
        let bound_ptr: LB::Expr = local[COL_BOUND_PTR].into();
        let field_id = bound_ptr.clone();
        let a_ptr: LB::Expr = local[COL_A_PTR].into();
        let b_ptr: LB::Expr = local[COL_B_PTR].into();
        let param_a: LB::Expr = local[COL_PARAM_A].into();
        let group_ptr: LB::Expr = local[COL_GROUP_PTR].into();
        let curve_b: LB::Expr = local[COL_CURVE_B].into();
        let lhs: [LB::Expr; NUM_HASH] = array::from_fn(|i| local[COL_LHS_BEGIN + i].into());
        let rhs: [LB::Expr; NUM_HASH] = array::from_fn(|i| local[COL_RHS_BEGIN + i].into());
        let h: [LB::Expr; NUM_HASH] = array::from_fn(|i| local[COL_H_BEGIN + i].into());
        let field_tag: [LB::Expr; NUM_HASH] =
            array::from_fn(|i| local[COL_ABSORB_CAP_BEGIN + i].into());

        let is_value_op = is_uint_op.clone() * (LB::Expr::ONE - is_is.clone());
        let node = is_and.clone()
            + is_uint_leaf.clone()
            + is_uint_op.clone()
            + is_create.clone()
            + is_ec_op.clone();
        let static_node =
            is_and.clone() + is_uint_op.clone() + is_create.clone() + is_ec_op.clone();
        let op_rhs_gate = is_uint_op.clone() * (LB::Expr::ONE - is_neg.clone());
        let neg_out_mult = LB::Expr::ZERO - out_mult;
        let true_provide = neg_out_mult.clone() * (is_and.clone() + is_zero + is_is.clone());
        let value_provide = neg_out_mult.clone() * (is_uint_leaf.clone() + is_value_op);
        let transient = LB::Expr::ONE - is_pinned;
        let and_cap = Tag::AND.as_word();
        let cap_static = [
            is_and.clone() * LB::Expr::from(and_cap[0])
                + is_uint_op.clone() * LB::Expr::from(UintPrecompile::id())
                + is_create.clone() * LB::Expr::from(CurvePrecompile::id())
                + is_ec_op.clone() * LB::Expr::from(CurvePrecompile::id()),
            is_and.clone() * LB::Expr::from(and_cap[1])
                + (is_uint_op.clone() + is_ec_op.clone()) * param_a.clone(),
            is_and.clone() * LB::Expr::from(and_cap[2]) + is_create.clone() * param_a,
            is_and.clone() * LB::Expr::from(and_cap[3]) + is_create.clone() * curve_b,
        ];

        let one_deg = Deg { v: 1, u: 1 };
        let two_deg = Deg { v: 2, u: 1 };
        let mixed_deg = Deg { v: 1, u: 2 };
        let col0_deg = Deg { v: 5, u: 4 };
        let col1_deg = Deg { v: 5, u: 5 };
        let col2_deg = Deg { v: 4, u: 4 };
        let col3_deg = Deg { v: 2, u: 2 };
        let col4_deg = Deg { v: 3, u: 3 };
        let col5_deg = Deg { v: 5, u: 4 };
        let col6_deg = Deg { v: 5, u: 4 };
        let col7_deg = Deg { v: 4, u: 4 };
        let col8_deg = Deg { v: 1, u: 1 };

        builder.next_column(
            |col| {
                col.group(
                    "binding-true",
                    |g| {
                        g.batch(
                            "fractions",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "consume-lhs",
                                    is_and.clone(),
                                    BindingMsg::truth(lhs.clone()),
                                    one_deg,
                                );
                                b.insert(
                                    "consume-rhs",
                                    is_and.clone(),
                                    BindingMsg::truth(rhs.clone()),
                                    one_deg,
                                );
                                b.insert(
                                    "provide-h",
                                    true_provide,
                                    BindingMsg::truth(h.clone()),
                                    two_deg,
                                );
                            },
                            col0_deg,
                        );
                    },
                    col0_deg,
                );
            },
            col0_deg,
        );

        builder.next_column(
            |col| {
                col.group(
                    "unhash-p2",
                    |g| {
                        g.batch(
                            "fractions",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "p2in-rate0",
                                    node.clone(),
                                    Poseidon2InMsg::rate0(perm_seq_id.clone(), lhs.clone()),
                                    one_deg,
                                );
                                b.insert(
                                    "p2in-rate1",
                                    node.clone(),
                                    Poseidon2InMsg::rate1(perm_seq_id.clone(), rhs.clone()),
                                    one_deg,
                                );
                                b.insert(
                                    "p2in-cap-static",
                                    static_node,
                                    Poseidon2InMsg::cap(perm_seq_id.clone(), cap_static),
                                    one_deg,
                                );
                                b.insert(
                                    "p2in-cap-leaf",
                                    is_uint_leaf.clone(),
                                    Poseidon2InMsg::cap(perm_seq_id.clone(), field_tag.clone()),
                                    one_deg,
                                );
                                b.insert(
                                    "p2out",
                                    node,
                                    Poseidon2OutMsg { perm_seq_id, digest: h.clone() },
                                    one_deg,
                                );
                            },
                            col1_deg,
                        );
                    },
                    col1_deg,
                );
            },
            col1_deg,
        );

        builder.next_column(
            |col| {
                col.group(
                    "binding-uint",
                    |g| {
                        g.batch(
                            "fractions",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "consume-lo",
                                    is_uint_leaf.clone(),
                                    UintValMsg {
                                        ptr: ptr.clone(),
                                        bound_ptr: bound_ptr.clone(),
                                        offset: LB::Expr::ZERO,
                                        limbs: lhs.clone(),
                                    },
                                    one_deg,
                                );
                                b.insert(
                                    "consume-hi",
                                    is_uint_leaf.clone(),
                                    UintValMsg {
                                        ptr: ptr.clone(),
                                        bound_ptr: bound_ptr.clone(),
                                        offset: LB::Expr::ONE,
                                        limbs: rhs.clone(),
                                    },
                                    one_deg,
                                );
                                b.insert(
                                    "provide-binding",
                                    value_provide,
                                    BindingMsg {
                                        h: h.clone(),
                                        kind: transient.clone()
                                            * LB::Expr::from(Felt::from(ValueTag::FieldElem as u8)),
                                        ptr: transient.clone() * ptr.clone(),
                                        domain_id: transient * field_id.clone(),
                                    },
                                    two_deg,
                                );
                            },
                            col2_deg,
                        );
                    },
                    col2_deg,
                );
            },
            col2_deg,
        );

        builder.next_column(
            |col| {
                col.group(
                    "binding-op-children",
                    |g| {
                        g.batch(
                            "fractions",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "consume-lhs",
                                    is_uint_op.clone() + is_ec_create.clone(),
                                    BindingMsg::field_elem(
                                        lhs.clone(),
                                        a_ptr.clone(),
                                        field_id.clone(),
                                    ),
                                    one_deg,
                                );
                                b.insert(
                                    "consume-rhs",
                                    op_rhs_gate + is_ec_create.clone(),
                                    BindingMsg::field_elem(rhs.clone(), b_ptr.clone(), field_id),
                                    one_deg,
                                );
                            },
                            col3_deg,
                        );
                    },
                    col3_deg,
                );
            },
            col3_deg,
        );

        builder.next_column(
            |col| {
                col.group(
                    "uint-relations",
                    |g| {
                        g.batch(
                            "fractions",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "consume-uintadd",
                                    is_uint_op.clone()
                                        * (is_add.clone() + is_sub.clone() + is_neg.clone()),
                                    UintAddMsg {
                                        bound_ptr: bound_ptr.clone(),
                                        a_ptr: (is_add.clone() + is_neg.clone()) * a_ptr.clone()
                                            + is_sub.clone() * b_ptr.clone(),
                                        b_ptr: is_add.clone() * b_ptr.clone()
                                            + (is_sub.clone() + is_neg.clone()) * ptr.clone(),
                                        c_ptr: is_add.clone() * ptr.clone()
                                            + is_sub.clone() * a_ptr.clone(),
                                    },
                                    mixed_deg,
                                );
                                b.insert(
                                    "consume-uintmul",
                                    is_mul,
                                    UintMulMsg {
                                        kappa_a: LB::Expr::ONE,
                                        kappa_c: LB::Expr::ZERO,
                                        a_ptr,
                                        b_ptr,
                                        c_ptr: bound_ptr.clone(),
                                        r_ptr: ptr,
                                        bound_ptr,
                                    },
                                    one_deg,
                                );
                            },
                            col4_deg,
                        );
                    },
                    col4_deg,
                );
            },
            col4_deg,
        );

        let f_bound: LB::Expr = local[COL_BOUND_PTR].into();
        let f_id = f_bound.clone();
        let f_lhs: [LB::Expr; NUM_HASH] = array::from_fn(|i| local[COL_LHS_BEGIN + i].into());
        let f_rhs: [LB::Expr; NUM_HASH] = array::from_fn(|i| local[COL_RHS_BEGIN + i].into());
        let f_h: [LB::Expr; NUM_HASH] = array::from_fn(|i| local[COL_H_BEGIN + i].into());
        let f_tag: [LB::Expr; NUM_HASH] =
            array::from_fn(|i| local[COL_ABSORB_CAP_BEGIN + i].into());
        let field_consume_gate = is_uint_leaf + is_uint_op + is_create.clone();
        let field_provide = neg_out_mult * is_field_tag.clone();
        builder.next_column(
            |col| {
                col.group(
                    "field-domain",
                    |g| {
                        g.batch(
                            "fractions",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "consume-bound-lo",
                                    is_field_tag.clone(),
                                    UintValMsg {
                                        ptr: f_bound.clone(),
                                        bound_ptr: f_bound.clone(),
                                        offset: LB::Expr::ZERO,
                                        limbs: f_lhs,
                                    },
                                    one_deg,
                                );
                                b.insert(
                                    "consume-bound-hi",
                                    is_field_tag,
                                    UintValMsg {
                                        ptr: f_bound.clone(),
                                        bound_ptr: f_bound.clone(),
                                        offset: LB::Expr::ONE,
                                        limbs: f_rhs,
                                    },
                                    one_deg,
                                );
                                b.insert(
                                    "provide-field",
                                    field_provide,
                                    FieldMsg {
                                        field_id: f_id.clone(),
                                        field_tag: f_h,
                                        bound_ptr: f_bound.clone(),
                                    },
                                    two_deg,
                                );
                                b.insert(
                                    "consume-field",
                                    field_consume_gate,
                                    FieldMsg {
                                        field_id: f_id,
                                        field_tag: f_tag,
                                        bound_ptr: f_bound,
                                    },
                                    one_deg,
                                );
                            },
                            col5_deg,
                        );
                    },
                    col5_deg,
                );
            },
            col5_deg,
        );

        let g_lhs: [LB::Expr; NUM_HASH] = array::from_fn(|i| local[COL_LHS_BEGIN + i].into());
        let g_rhs: [LB::Expr; NUM_HASH] = array::from_fn(|i| local[COL_RHS_BEGIN + i].into());
        let g_h: [LB::Expr; NUM_HASH] = array::from_fn(|i| local[COL_H_BEGIN + i].into());
        let g_ptr: LB::Expr = local[COL_PTR].into();
        let g_a: LB::Expr = local[COL_A_PTR].into();
        let g_b: LB::Expr = local[COL_B_PTR].into();
        let g_bound: LB::Expr = local[COL_BOUND_PTR].into();
        let g_param_a: LB::Expr = local[COL_PARAM_A].into();
        let g_curve_b: LB::Expr = local[COL_CURVE_B].into();
        let g_group: LB::Expr = local[COL_GROUP_PTR].into();
        let g_sbound: LB::Expr = local[COL_SBOUND_PTR].into();
        let g_pai: LB::Expr = local[COL_IS_EC_PAI].into();
        let g_out_mult: LB::Expr = local[COL_OUT_MULT].into();
        let g_neg_out_mult = LB::Expr::ZERO - g_out_mult;
        let ec_binary = is_ec_op.clone() * (LB::Expr::ONE - is_neg.clone());
        let ec_result = is_ec_op.clone() * (LB::Expr::ONE - is_is);

        builder.next_column(
            |col| {
                col.group(
                    "binding-curve-point",
                    |g| {
                        g.batch(
                            "fractions",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "consume-p",
                                    is_ec_op.clone(),
                                    BindingMsg::curve_point(g_lhs.clone(), g_a.clone()),
                                    one_deg,
                                );
                                b.insert(
                                    "consume-q",
                                    ec_binary,
                                    BindingMsg::curve_point(g_rhs.clone(), g_b.clone()),
                                    one_deg,
                                );
                                b.insert(
                                    "provide-result",
                                    g_neg_out_mult * (is_create.clone() + ec_result.clone()),
                                    BindingMsg::curve_point(g_h, g_ptr.clone()),
                                    two_deg,
                                );
                            },
                            col6_deg,
                        );
                    },
                    col6_deg,
                );
            },
            col6_deg,
        );

        builder.next_column(
            |col| {
                col.group(
                    "ec-relations",
                    |g| {
                        g.batch(
                            "fractions",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "consume-ecgroup",
                                    is_create.clone(),
                                    EcGroupMsg {
                                        group_ptr: g_group.clone(),
                                        a_ptr: g_param_a.clone(),
                                        b_ptr: g_curve_b.clone(),
                                        bound_ptr: g_bound.clone(),
                                        scalar_bound_ptr: g_sbound,
                                    },
                                    one_deg,
                                );
                                b.insert(
                                    "consume-ecpoint",
                                    is_create.clone(),
                                    EcPointMsg {
                                        point_ptr: g_ptr.clone(),
                                        group_ptr: g_group.clone(),
                                        x_ptr: g_a.clone(),
                                        y_ptr: g_b.clone(),
                                        is_pai: g_pai,
                                    },
                                    one_deg,
                                );
                                b.insert(
                                    "consume-ecgroupadd",
                                    ec_result.clone(),
                                    EcGroupAddMsg {
                                        group_ptr: g_group.clone(),
                                        p_ptr: (is_add.clone() + is_neg.clone()) * g_a.clone()
                                            + is_sub.clone() * g_ptr.clone(),
                                        q_ptr: (is_add.clone() + is_sub.clone()) * g_b.clone()
                                            + is_neg.clone() * g_ptr.clone(),
                                        r_ptr: is_add.clone() * g_ptr.clone()
                                            + is_neg.clone() * g_b.clone()
                                            + is_sub.clone() * g_a.clone(),
                                    },
                                    mixed_deg,
                                );
                            },
                            col7_deg,
                        );
                    },
                    col7_deg,
                );
            },
            col7_deg,
        );

        let is_ec_neg = is_ec_op * is_neg;
        builder.next_column(
            |col| {
                col.group(
                    "ec-neg-infinity",
                    |g| {
                        g.batch(
                            "fractions",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "consume-ecpoint-pai",
                                    is_ec_neg,
                                    EcPointMsg {
                                        point_ptr: g_b,
                                        group_ptr,
                                        x_ptr: LB::Expr::ZERO,
                                        y_ptr: LB::Expr::ZERO,
                                        is_pai: LB::Expr::ONE,
                                    },
                                    one_deg,
                                );
                            },
                            col8_deg,
                        );
                    },
                    col8_deg,
                );
            },
            col8_deg,
        );
    }
}
