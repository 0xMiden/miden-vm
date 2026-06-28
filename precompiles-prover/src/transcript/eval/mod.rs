//! Minimal transcript eval chiplet for the Keccak prover MVP.

pub mod trace;

use core::array;

use miden_core::{
    Felt,
    deferred::Tag,
    field::{PrimeCharacteristicRing, QuadFelt},
};
use miden_lifted_air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder};
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    logup::{
        CyclicConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn,
        LookupGroup, NUM_RANDOMNESS, NUM_SIGMA_VALUES,
    },
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    transcript::{
        binding::BindingMsg,
        poseidon2::{Poseidon2InMsg, Poseidon2OutMsg},
    },
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
pub const NUM_MAIN_COLS: usize = COL_IS_AND + 1;

pub const PUBLIC_ROOT_BEGIN: usize = 0;
pub const PUBLIC_ROOT_END: usize = PUBLIC_ROOT_BEGIN + NUM_HASH;
pub const NUM_PUBLIC_VALUES: usize = PUBLIC_ROOT_END;

pub const NUM_AUX_COLS: usize = 2;
const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [3, 4];

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
        let is_and: AB::Expr = local[COL_IS_AND].into();
        let out_mult: AB::Expr = local[COL_OUT_MULT].into();
        let h: [AB::Expr; NUM_HASH] = array::from_fn(|i| local[COL_H_BEGIN + i].into());
        let public_root: [AB::Expr; NUM_HASH] =
            array::from_fn(|i| builder.public_values()[PUBLIC_ROOT_BEGIN + i].into());

        builder.assert_bool(local[COL_ACT]);
        builder.when_transition().assert_zero((AB::Expr::ONE - act.clone()) * act_next);
        builder.assert_bool(local[COL_IS_ZERO]);
        builder.assert_bool(local[COL_IS_AND]);
        builder.assert_zero(is_zero.clone() + is_and - act.clone());
        builder.assert_zero((AB::Expr::ONE - act) * out_mult);

        for i in 0..NUM_HASH {
            builder.assert_zero(is_zero.clone() * h[i].clone());
            builder.when_first_row().assert_zero(h[i].clone() - public_root[i].clone());
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
        let perm_seq_id: LB::Expr = local[COL_PERM_SEQ_ID].into();
        let out_mult: LB::Expr = local[COL_OUT_MULT].into();
        let lhs: [LB::Expr; NUM_HASH] = array::from_fn(|i| local[COL_LHS_BEGIN + i].into());
        let rhs: [LB::Expr; NUM_HASH] = array::from_fn(|i| local[COL_RHS_BEGIN + i].into());
        let h: [LB::Expr; NUM_HASH] = array::from_fn(|i| local[COL_H_BEGIN + i].into());

        let neg_out_mult = LB::Expr::ZERO - out_mult;
        let provide = neg_out_mult * (is_and.clone() + is_zero);
        let one_deg = Deg { v: 1, u: 1 };
        let two_deg = Deg { v: 2, u: 1 };
        let col0_deg = Deg { v: 5, u: 4 };
        let col1_deg = Deg { v: 4, u: 4 };
        let and_cap = Tag::AND.as_word().map(LB::Expr::from);

        builder.next_column(
            |col| {
                col.group(
                    "binding-and",
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
                                    provide,
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
                                    is_and.clone(),
                                    Poseidon2InMsg::rate0(perm_seq_id.clone(), lhs),
                                    one_deg,
                                );
                                b.insert(
                                    "p2in-rate1",
                                    is_and.clone(),
                                    Poseidon2InMsg::rate1(perm_seq_id.clone(), rhs),
                                    one_deg,
                                );
                                b.insert(
                                    "p2in-cap",
                                    is_and.clone(),
                                    Poseidon2InMsg::cap(perm_seq_id.clone(), and_cap),
                                    one_deg,
                                );
                                b.insert(
                                    "p2out",
                                    is_and,
                                    Poseidon2OutMsg { perm_seq_id, digest: h },
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
    }
}
