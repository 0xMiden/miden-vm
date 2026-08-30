//! Native Eidos chaining chiplet for the deferred transcript.
//!
//! Each logical Eidos compression occupies one physical 32-row cycle. That cycle emits the
//! transcript's input/output relations directly, keyed by the logical chain-step ID.

pub mod compression;
pub mod digest;
pub mod messages;

use alloc::{vec, vec::Vec};
use core::{array, borrow::Borrow};

use compression::{
    EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE, EidosCompressionCols,
    NUM_PERIODIC_COLUMNS as EIDOS_COMPRESSION_PERIODIC_COLS,
    constraints::{enforce_footer_rows, enforce_fused_rows},
    emit_lookup_columns, get_periodic_column_values,
    layout::{
        BLOCK_PERIOD as EIDOS_COMPRESSION_CYCLE_LEN, F_COMPRESSION_CYCLE_ID_COL, FOOTER_ROWS,
        NUM_COLS as NUM_EIDOS_COMPRESSION_COLS, footer_digest_col, footer_msg_word_col,
        footer_r_col,
    },
    selectors::EidosCompressionSelectors,
    universal_cv_word,
};
pub use digest::{EidosChainContext, EidosDigest};
pub use messages::{
    EIDOS_DOMAIN_AND, EIDOS_DOMAIN_CHUNKS, EIDOS_DOMAIN_NODE, EidosChainInputMsg, EidosOutMsg,
};
use miden_air::{
    logup::{BusId as MidenBusId, MIDEN_MAX_MESSAGE_WIDTH},
    lookup::{
        ConstraintLookupBuilder as MidenConstraintLookupBuilder, LookupAir,
        build_logup_aux_trace as build_miden_aux_trace,
    },
};
use miden_core::{
    Felt,
    deferred::{DEFERRED_AND_INIT_CV, DEFERRED_CHUNKS_DOMAIN},
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_crypto::hash::eidos::Eidos;
use miden_lifted_air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder, WindowAccess};

use crate::{
    composite::{SubAirBuilder, concatenate_bands, extract_band},
    logup::{
        ConstraintLookupBuilder, Deg, LookupBatch, LookupBuilder, LookupColumn, LookupGroup,
        LookupMessage, NUM_LOGUP_VALUES, NUM_PUBLIC_VALUES, NUM_RANDOMNESS, build_logup_aux_trace,
    },
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    utils::{current_main, next_main},
};

// MAIN COLUMN LAYOUT
// ================================================================================================

/// The first 108 columns are the PVM-owned Eidos compression layout.
pub const COL_EIDOS_COMPRESSION_BEGIN: usize = 0;
pub const COL_EIDOS_COMPRESSION_END: usize = NUM_EIDOS_COMPRESSION_COLS;

/// Cycle-constant logical input-block identifier.
pub const COL_ABSORPTION_ID: usize = COL_EIDOS_COMPRESSION_END;
pub const COL_IN_MULTIPLICITY: usize = COL_ABSORPTION_ID + 1;
pub const COL_OUT_MULTIPLICITY: usize = COL_IN_MULTIPLICITY + 1;
pub const COL_IS_HEAD: usize = COL_OUT_MULTIPLICITY + 1;
pub const COL_IS_ABSORB: usize = COL_IS_HEAD + 1;
pub const COL_IS_PAYLOAD: usize = COL_IS_ABSORB + 1;
pub const COL_IS_OUTPUT: usize = COL_IS_PAYLOAD + 1;
pub const COL_IS_AND: usize = COL_IS_OUTPUT + 1;
pub const COL_IS_CHUNKS: usize = COL_IS_AND + 1;
pub const COL_IS_GENERIC: usize = COL_IS_CHUNKS + 1;
pub const COL_REMAINING: usize = COL_IS_GENERIC + 1;
pub const COL_REMAINING_INV: usize = COL_REMAINING + 1;
pub const COL_CHAIN_CONTEXT_BEGIN: usize = COL_REMAINING_INV + 1;
pub const COL_CHAIN_CONTEXT_END: usize = COL_CHAIN_CONTEXT_BEGIN + 4;
pub const COL_CV_IN_BEGIN: usize = COL_CHAIN_CONTEXT_END;
pub const COL_CV_IN_END: usize = COL_CV_IN_BEGIN + 4;
pub const NUM_MAIN_COLS: usize = COL_CV_IN_END;

const PVM_AUX_COLS: usize = 2;
const EIDOS_COMPRESSION_AUX_COLS: usize = EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE.len();
pub const NUM_AUX_COLS: usize = PVM_AUX_COLS + EIDOS_COMPRESSION_AUX_COLS;
const PVM_COLUMN_SHAPE: [usize; PVM_AUX_COLS] = [1, 2];

const PVM_VALUE_OFFSET: usize = 0;
const EIDOS_COMPRESSION_VALUE_OFFSET: usize = 1;

// The two lookup families deliberately share alpha/beta but use different bus-prefix exponents:
// PVM prefixes sit at beta^18, while native Miden Eidos compression/And8 prefixes sit at beta^16.
// This keeps their denominator polynomials domain-separated even though both BusId enums start at
// zero. Equal widths would make cross-family bus-id collisions possible.
const _: () = assert!(MAX_MESSAGE_WIDTH != MIDEN_MAX_MESSAGE_WIDTH);

// PUBLIC AIR
// ================================================================================================

/// PVM-native Eidos compression AIR. One compression occupies exactly 32 rows.
#[derive(Debug, Default, Clone, Copy)]
pub struct EidosCompressionAir;

impl BaseAir<Felt> for EidosCompressionAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        get_periodic_column_values()
    }
}

impl LiftedAir<Felt, QuadFelt> for EidosCompressionAir {
    fn num_randomness(&self) -> usize {
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        NUM_AUX_COLS
    }

    fn num_aux_values(&self) -> usize {
        2
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        let (pvm_aux, pvm_values) =
            EidosCompressionInterfaceAir.build_aux_trace(main, air_inputs, aux_inputs, challenges);
        let eidos_compression_main =
            extract_band(main, COL_EIDOS_COMPRESSION_BEGIN..COL_EIDOS_COMPRESSION_END);
        let (eidos_compression_aux, eidos_compression_values) = EidosCompressionNarrowAir
            .build_aux_trace(&eidos_compression_main, air_inputs, aux_inputs, challenges);
        assert_eq!(pvm_values.len(), 1);
        assert_eq!(eidos_compression_values.len(), 1);

        (
            concatenate_bands(&pvm_aux, &eidos_compression_aux),
            vec![pvm_values[0], eidos_compression_values[0]],
        )
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        {
            let mut interface = SubAirBuilder::new(
                builder,
                0..NUM_MAIN_COLS,
                0..0,
                0..PVM_AUX_COLS,
                PVM_VALUE_OFFSET..PVM_VALUE_OFFSET + 1,
                0..EIDOS_COMPRESSION_PERIODIC_COLS,
            );
            <EidosCompressionInterfaceAir as LiftedAir<Felt, QuadFelt>>::eval(
                &EidosCompressionInterfaceAir,
                &mut interface,
            );
        }
        {
            let mut compression = SubAirBuilder::new(
                builder,
                COL_EIDOS_COMPRESSION_BEGIN..COL_EIDOS_COMPRESSION_END,
                0..0,
                PVM_AUX_COLS..NUM_AUX_COLS,
                EIDOS_COMPRESSION_VALUE_OFFSET..EIDOS_COMPRESSION_VALUE_OFFSET + 1,
                0..EIDOS_COMPRESSION_PERIODIC_COLS,
            );
            <EidosCompressionNarrowAir as LiftedAir<Felt, QuadFelt>>::eval(
                &EidosCompressionNarrowAir,
                &mut compression,
            );
        }
    }
}

// EIDOS COMPRESSION CORE
// ================================================================================================

/// The intrinsic Eidos compression constraints and byte/range lookups, without Miden VM controller
/// or AEAD footer relations. The PVM interface below occupies those boundaries directly.
#[derive(Debug, Default, Clone, Copy)]
#[doc(hidden)]
pub struct EidosCompressionNarrowAir;

impl BaseAir<Felt> for EidosCompressionNarrowAir {
    fn width(&self) -> usize {
        NUM_EIDOS_COMPRESSION_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        get_periodic_column_values()
    }
}

impl LiftedAir<Felt, QuadFelt> for EidosCompressionNarrowAir {
    fn num_randomness(&self) -> usize {
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        EIDOS_COMPRESSION_AUX_COLS
    }

    fn num_aux_values(&self) -> usize {
        NUM_LOGUP_VALUES
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        build_miden_aux_trace(self, main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        {
            let main = builder.main();
            let local = main.current_slice();
            let next = main.next_slice();
            let periodic_values: Vec<AB::Expr> =
                builder.periodic_values().iter().map(|value| (*value).into()).collect();
            let selectors = EidosCompressionSelectors::new(&periodic_values, 0);
            enforce_fused_rows(builder, local, next, &selectors);
            enforce_footer_rows(builder, local, next, &selectors);
        }

        let mut lb = MidenConstraintLookupBuilder::new(builder, self);
        <Self as LookupAir<_>>::eval(self, &mut lb);
        lb.finish();
    }
}

impl<LB> LookupAir<LB> for EidosCompressionNarrowAir
where
    LB: LookupBuilder<F = Felt>,
{
    fn column_shape(&self) -> &[usize] {
        &EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        MidenBusId::COUNT
    }

    fn eval(&self, builder: &mut LB) {
        let main = builder.main();
        let local: &EidosCompressionCols<_> = main.current_slice().borrow();
        let next: &EidosCompressionCols<_> = main.next_slice().borrow();
        let periodic_values: Vec<LB::Expr> =
            builder.periodic_values().iter().map(|value| (*value).into()).collect();
        let selectors = EidosCompressionSelectors::new(&periodic_values, 0);
        emit_lookup_columns(builder, local, next, &selectors);
    }
}

// PVM INTERFACE
// ================================================================================================

#[derive(Debug, Default, Clone, Copy)]
#[doc(hidden)]
pub struct EidosCompressionInterfaceAir;

impl BaseAir<Felt> for EidosCompressionInterfaceAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        get_periodic_column_values()
    }
}

impl LiftedAir<Felt, QuadFelt> for EidosCompressionInterfaceAir {
    fn num_randomness(&self) -> usize {
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        PVM_AUX_COLS
    }

    fn num_aux_values(&self) -> usize {
        NUM_LOGUP_VALUES
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        build_logup_aux_trace(self, main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let next: [AB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);
        let periodic_values: Vec<AB::Expr> =
            builder.periodic_values().iter().map(|value| (*value).into()).collect();
        let selectors = EidosCompressionSelectors::new(&periodic_values, 0);
        let is_last = selectors.is_footer_row(3);
        let not_last = AB::Expr::ONE - is_last.clone();

        let head: AB::Expr = local[COL_IS_HEAD].into();
        let absorb: AB::Expr = local[COL_IS_ABSORB].into();
        let payload: AB::Expr = local[COL_IS_PAYLOAD].into();
        let output: AB::Expr = local[COL_IS_OUTPUT].into();
        let is_and: AB::Expr = local[COL_IS_AND].into();
        let is_chunks: AB::Expr = local[COL_IS_CHUNKS].into();
        let is_generic: AB::Expr = local[COL_IS_GENERIC].into();
        let remaining: AB::Expr = local[COL_REMAINING].into();
        let remaining_inv: AB::Expr = local[COL_REMAINING_INV].into();
        let active = head.clone() + absorb.clone();
        let next_head: AB::Expr = next[COL_IS_HEAD].into();
        let next_absorb: AB::Expr = next[COL_IS_ABSORB].into();
        let next_active = next_head + next_absorb.clone();

        for col in [
            COL_IS_HEAD,
            COL_IS_ABSORB,
            COL_IS_PAYLOAD,
            COL_IS_OUTPUT,
            COL_IS_AND,
            COL_IS_CHUNKS,
            COL_IS_GENERIC,
        ] {
            builder.assert_bool(local[col]);
        }

        builder.assert_zero(head.clone() * absorb.clone());
        builder
            .assert_zero(is_and.clone() + is_chunks.clone() + is_generic.clone() - active.clone());
        builder.assert_zero(payload.clone() - active.clone());
        builder.assert_zero(output.clone() * (AB::Expr::ONE - active.clone()));
        builder.assert_zero(AB::Expr::from(local[COL_IN_MULTIPLICITY]) * (AB::Expr::ONE - payload));
        builder.assert_zero(
            AB::Expr::from(local[COL_OUT_MULTIPLICITY]) * (AB::Expr::ONE - output.clone()),
        );
        builder.assert_zero(is_and.clone() * (output.clone() - AB::Expr::ONE));
        builder.assert_zero(is_and.clone() * (remaining.clone() - AB::Expr::ONE));

        let remaining_minus_one = remaining.clone() - AB::Expr::ONE;
        builder.assert_zero(active.clone() * output.clone() * remaining_minus_one.clone());
        builder.assert_zero(
            active.clone()
                * (remaining_minus_one * remaining_inv - (AB::Expr::ONE - output.clone())),
        );

        builder.when_first_row().assert_zero(local[COL_ABSORPTION_ID]);
        builder.when_first_row().assert_zero(absorb);

        // Every metadata column is constant throughout its physical 32-row compression cycle.
        for col in COL_ABSORPTION_ID..NUM_MAIN_COLS {
            builder.assert_zero(
                not_last.clone() * (AB::Expr::from(next[col]) - AB::Expr::from(local[col])),
            );
        }

        // Each physical compression consumes one logical payload block, so active cycle ids are
        // consecutive.
        builder.when_transition().assert_zero(
            is_last.clone()
                * next_active
                * (AB::Expr::from(next[COL_ABSORPTION_ID])
                    - AB::Expr::from(local[COL_ABSORPTION_ID])
                    - AB::Expr::ONE),
        );

        builder.when_transition().assert_zero(
            is_last.clone()
                * (active.clone() - output.clone())
                * (AB::Expr::ONE - next_absorb.clone()),
        );
        builder
            .when_transition()
            .assert_zero(is_last.clone() * output.clone() * next_absorb.clone());
        builder.when_last_row().assert_zero(active * (AB::Expr::ONE - output));

        builder.when_transition().assert_zero(
            is_last.clone()
                * next_absorb.clone()
                * (AB::Expr::from(next[COL_REMAINING]) - remaining.clone() + AB::Expr::ONE),
        );
        for col in [COL_IS_AND, COL_IS_CHUNKS, COL_IS_GENERIC] {
            builder.when_transition().assert_zero(
                is_last.clone()
                    * next_absorb.clone()
                    * (AB::Expr::from(next[col]) - AB::Expr::from(local[col])),
            );
        }
        for i in 0..4 {
            builder.when_transition().assert_zero(
                is_last.clone()
                    * next_absorb.clone()
                    * (AB::Expr::from(next[COL_CHAIN_CONTEXT_BEGIN + i])
                        - AB::Expr::from(local[COL_CHAIN_CONTEXT_BEGIN + i])),
            );
            builder.when_transition().assert_zero(
                is_last.clone()
                    * next_absorb.clone()
                    * (AB::Expr::from(next[COL_CV_IN_BEGIN + i])
                        - AB::Expr::from(local[footer_digest_col(i)])),
            );
            let raw_cv_lo = universal_cv_word(|col| AB::Expr::from(local[col]), 2 * i);
            let raw_cv_hi = universal_cv_word(|col| AB::Expr::from(local[col]), 2 * i + 1);
            builder.assert_zero(
                is_last.clone()
                    * (AB::Expr::from(local[COL_CV_IN_BEGIN + i])
                        - raw_cv_lo
                        - AB::Expr::from(Felt::new_unchecked(1u64 << 32)) * raw_cv_hi),
            );
        }

        let chain_context: [AB::Expr; 4] =
            array::from_fn(|i| local[COL_CHAIN_CONTEXT_BEGIN + i].into());
        let and_init = DEFERRED_AND_INIT_CV.into_elements();
        let chunks_init =
            Eidos::init_chaining_word(DEFERRED_CHUNKS_DOMAIN.as_canonical_u64() as u32, 0)
                .into_elements();
        let init_bases = Eidos::init_chaining_word_with_params(0, [0; 3]).into_elements();
        for i in 0..4 {
            let mut expected = is_and.clone() * AB::Expr::from(and_init[i])
                + is_chunks.clone() * AB::Expr::from(chunks_init[i]);
            if i == 1 {
                expected +=
                    is_chunks.clone() * remaining.clone() * AB::Expr::from(Felt::from_u8(8));
            }
            let generic_param = match i {
                0 => chain_context[0].clone(),
                1 => remaining.clone() * AB::Expr::from(Felt::from_u8(8)),
                2 => chain_context[1].clone(),
                3 => chain_context[2].clone(),
                _ => unreachable!(),
            };
            expected += is_generic.clone() * (AB::Expr::from(init_bases[i]) + generic_param);
            builder.assert_zero(
                head.clone() * (AB::Expr::from(local[COL_CV_IN_BEGIN + i]) - expected),
            );
        }

        let and_context = EidosChainContext::and().as_array();
        let chunks_context = EidosChainContext::chunk().as_array();
        for i in 0..4 {
            builder.assert_zero(
                is_and.clone() * (chain_context[i].clone() - AB::Expr::from(and_context[i])),
            );
            builder.assert_zero(
                is_chunks.clone() * (chain_context[i].clone() - AB::Expr::from(chunks_context[i])),
            );
        }
        builder.assert_zero(is_generic * chain_context[3].clone());

        // The second interface fraction column is inactive outside the first fused row and
        // footer 3. Pinning it closes the zero-denominator edge where its ungated fraction
        // equation would otherwise leave the committed cell unconstrained.
        let aux1: AB::ExprEF = builder.permutation().current_slice()[1].into();
        let aux1_inactive =
            AB::Expr::ONE - selectors.is_first_fused() - selectors.is_footer_row(FOOTER_ROWS - 1);
        builder.assert_zero_ext(aux1 * aux1_inactive);

        let mut lb = ConstraintLookupBuilder::new(builder, self);
        <Self as LookupAir<_>>::eval(self, &mut lb);
        lb.finish();
    }
}

#[doc(hidden)]
pub const INTERNAL_CV_BUS_ID: usize = BusId::EidosCv as usize;

/// Cycle-tagged relation carrying all eight raw Eidos compression chaining-value words atomically.
///
/// This relation is internal to the interface AIR, but its ID lives in the shared PVM registry so
/// every prover, verifier, and diagnostic path constructs the same challenge table.
#[derive(Debug)]
struct FullCvMsg<E> {
    compression_cycle_id: E,
    words: [E; 8],
}

impl<E, EF> LookupMessage<E, EF> for FullCvMsg<E>
where
    E: PrimeCharacteristicRing,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &crate::logup::Challenges<EF>) -> EF {
        let fields: [E; 9] = array::from_fn(|idx| {
            if idx == 0 {
                self.compression_cycle_id.clone()
            } else {
                self.words[idx - 1].clone()
            }
        });
        challenges.encode(INTERNAL_CV_BUS_ID, fields)
    }
}

impl<LB> LookupAir<LB> for EidosCompressionInterfaceAir
where
    LB: LookupBuilder<F = Felt>,
{
    fn column_shape(&self) -> &[usize] {
        &PVM_COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        NUM_BUS_IDS
    }

    fn eval(&self, builder: &mut LB) {
        let local: [LB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let periodic_values: Vec<LB::Expr> =
            builder.periodic_values().iter().map(|value| (*value).into()).collect();
        let selectors = EidosCompressionSelectors::new(&periodic_values, 0);
        let first_fused = selectors.is_first_fused();
        let footer3 = selectors.is_footer_row(FOOTER_ROWS - 1);

        let chain_step_id: LB::Expr = local[COL_ABSORPTION_ID].into();
        let head: LB::Expr = local[COL_IS_HEAD].into();
        let in_mult: LB::Expr = local[COL_IN_MULTIPLICITY].into();
        let out_mult: LB::Expr = local[COL_OUT_MULTIPLICITY].into();
        let is_and: LB::Expr = local[COL_IS_AND].into();
        let is_chunks: LB::Expr = local[COL_IS_CHUNKS].into();
        let is_generic: LB::Expr = local[COL_IS_GENERIC].into();

        let message = footer_block(|col| LB::Expr::from(local[col]));
        let chain_context = array::from_fn(|idx| local[COL_CHAIN_CONTEXT_BEGIN + idx].into());
        let digest = array::from_fn(|idx| local[footer_digest_col(idx)].into());
        let domain = is_generic * LB::Expr::from(Felt::from_u8(EIDOS_DOMAIN_NODE))
            + is_and * LB::Expr::from(Felt::from_u8(EIDOS_DOMAIN_AND))
            + is_chunks * LB::Expr::from(Felt::from_u8(EIDOS_DOMAIN_CHUNKS));
        let raw_cv = raw_cv_words(|col| LB::Expr::from(local[col]));

        // The base constraints pin each multiplicity to zero off its event. Multiplying only by
        // footer3 therefore keeps both multiplicities at degree two.
        let input_multiplicity = -footer3.clone() * in_mult;
        let output_multiplicity = -footer3.clone() * out_mult;
        let cv_multiplicity = footer3 - first_fused;

        let linear = Deg { v: 1, u: 1 };
        let selected = Deg { v: 2, u: 1 };
        let pair = Deg { v: 3, u: 2 };

        builder.next_column(
            |col| {
                col.group(
                    "eidos_compression-pvm-chain-input",
                    |group| {
                        group.batch(
                            "atomic-chain-input",
                            LB::Expr::ONE,
                            |batch| {
                                batch.insert(
                                    "chain-input",
                                    input_multiplicity,
                                    EidosChainInputMsg {
                                        chain_step_id,
                                        is_head: head,
                                        domain,
                                        message,
                                        chain_context,
                                    },
                                    selected,
                                );
                            },
                            selected,
                        );
                    },
                    selected,
                );
            },
            selected,
        );

        builder.next_column(
            |col| {
                col.group(
                    "eidos_compression-pvm-cv-output",
                    |group| {
                        group.batch(
                            "full-cv-and-chain-output",
                            LB::Expr::ONE,
                            |batch| {
                                batch.insert(
                                    "full-cv",
                                    cv_multiplicity,
                                    FullCvMsg {
                                        compression_cycle_id: local[F_COMPRESSION_CYCLE_ID_COL]
                                            .into(),
                                        words: raw_cv,
                                    },
                                    linear,
                                );
                                batch.insert(
                                    "chain-output",
                                    output_multiplicity,
                                    EidosOutMsg {
                                        chain_step_id: local[COL_ABSORPTION_ID].into(),
                                        digest,
                                    },
                                    selected,
                                );
                            },
                            pair,
                        );
                    },
                    pair,
                );
            },
            pair,
        );
    }
}

fn footer_block<E, A>(at: A) -> [E; 8]
where
    E: PrimeCharacteristicRing,
    A: Fn(usize) -> E,
{
    array::from_fn(|idx| {
        if idx < 6 {
            at(footer_r_col(FOOTER_ROWS - 1, idx))
        } else {
            let pair = idx - 6;
            pack_pair(at(footer_msg_word_col(2 * pair)), at(footer_msg_word_col(2 * pair + 1)))
        }
    })
}

fn raw_cv_words<E, A>(at: A) -> [E; 8]
where
    E: PrimeCharacteristicRing,
    A: Fn(usize) -> E,
{
    array::from_fn(|idx| universal_cv_word(&at, idx))
}

fn pack_pair<E: PrimeCharacteristicRing>(lo: E, hi: E) -> E {
    lo + E::from_u64(1u64 << 32) * hi
}

const _: () = assert!(EIDOS_COMPRESSION_CYCLE_LEN == 32);
