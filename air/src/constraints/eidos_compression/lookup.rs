//! Lookup columns for the 32-row Eidos compression layout.

#[cfg(test)]
use alloc::vec::Vec;
use core::borrow::Borrow;

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing},
};
#[cfg(test)]
use miden_crypto::stark::air::WindowAccess;

use super::{
    algebra::{missing_rotation_result, pack_u32_le, universal_cv_word, xor_from_and},
    layout::*,
    narrow::{NARROW_SLOTS, NarrowSlotBus, NarrowSlotFields},
    selectors::EidosCompressionSelectors,
};
#[cfg(test)]
use crate::{constraints::lookup::MIDEN_MAX_MESSAGE_WIDTH, lookup::LookupAir};
use crate::{
    constraints::lookup::messages::{
        AeadEidosCompressionOutputPairMsg, BusId, eidos_compression_rot7_bus,
        eidos_compression_rot12_bus,
    },
    lookup::{
        Challenges, Deg, LookupBatch, LookupBuilder, LookupColumn, LookupGroup, LookupMessage,
    },
};

#[cfg(test)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EidosCompressionMode {
    Compression,
    AeadXof,
}

#[cfg(test)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NarrowLookupKind {
    And8,
    Rot12,
    Rot7,
    MessageWord,
    RangeCheck,
}

#[cfg(test)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NarrowLookup {
    pub kind: NarrowLookupKind,
    pub sign: i8,
}

#[cfg(test)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OverlayRelationKind {
    FullCv,
    CompressionLink,
    AeadInput,
    AeadLowOutputPair,
    AeadHighOutputPair,
}

#[cfg(test)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OverlayRelation {
    pub kind: OverlayRelationKind,
    pub sign: i8,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupPlan {
    pub narrow: Vec<NarrowLookup>,
    pub overlay_relations: Vec<OverlayRelation>,
}

#[cfg(test)]
impl LookupPlan {
    pub fn narrow_aux_columns(&self) -> usize {
        self.narrow.len().div_ceil(2)
    }
}

/// Typed view of the 108 Eidos compression main-trace columns.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct EidosCompressionCols<T> {
    /// Physical columns in the layout documented by the Eidos compression module.
    pub columns: [T; NUM_COLS],
}

/// Mode-selected external input with a shared 16-field payload.
///
/// Compression and AEAD use the same `[block_or_state(8), cv_in(4), tail(4)]` field order. Only
/// their domain-separated bus prefixes differ, so selecting the mode never multiplies a witness
/// value and the encoded denominator remains linear.
#[derive(Debug)]
struct FooterInputMsg<E> {
    mode: E,
    block: [E; 8],
    cv_in: [E; 4],
    tail: [E; 4],
}

/// Cycle-tagged internal relation carrying all eight raw chaining-value words atomically.
#[derive(Debug)]
struct FullCvMsg<E> {
    compression_cycle_id: E,
    words: [E; 8],
}

impl<E, EF> LookupMessage<E, EF> for FooterInputMsg<E>
where
    E: PrimeCharacteristicRing,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        let compression_prefix =
            challenges.bus_prefix[BusId::HasherCompressionLink as usize].clone();
        let aead_prefix = challenges.bus_prefix[BusId::AeadEidosCompressionInput as usize].clone();
        let mut encoded =
            compression_prefix.clone() + (aead_prefix - compression_prefix) * self.mode.clone();
        for (idx, field) in
            self.block.iter().chain(self.cv_in.iter()).chain(self.tail.iter()).enumerate()
        {
            encoded += challenges.beta_powers[idx].clone() * field.clone();
        }
        encoded
    }
}

impl<E, EF> LookupMessage<E, EF> for FullCvMsg<E>
where
    E: PrimeCharacteristicRing,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        let fields: [E; 9] = core::array::from_fn(|idx| {
            if idx == 0 {
                self.compression_cycle_id.clone()
            } else {
                self.words[idx - 1].clone()
            }
        });
        challenges.encode(BusId::EidosCompressionInputCv as usize, fields)
    }
}

impl<T> Borrow<EidosCompressionCols<T>> for [T] {
    fn borrow(&self) -> &EidosCompressionCols<T> {
        debug_assert_eq!(self.len(), NUM_COLS);
        // SAFETY: `EidosCompressionCols<T>` is `repr(C)` and contains exactly one `[T; NUM_COLS]`
        // field. It therefore has the same alignment, size, and valid bit patterns as the input
        // slice after the length check above.
        let (prefix, cols, suffix) = unsafe { self.align_to::<EidosCompressionCols<T>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(cols.len(), 1);
        &cols[0]
    }
}

/// Number of lookup fractions grouped into each Eidos compression auxiliary column.
pub(crate) const EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE: [usize; AUX_COLS] = [2; AUX_COLS];

pub(crate) const NARROW_BATCH_COLUMNS: usize = NARROW_SLOTS.len() / 2;
pub(crate) const FOOTER_INPUT_COLUMN: usize = 18;
pub(crate) const FOOTER_OUTPUT_COLUMN: usize = 19;

const _: () = assert!(FOOTER_INPUT_COLUMN == NARROW_BATCH_COLUMNS);
const _: () = assert!(FOOTER_OUTPUT_COLUMN == FOOTER_INPUT_COLUMN + 1);

const FOOTER_INPUT_DEG: Deg = Deg { v: 3, u: 2 };
const FOOTER_OUTPUT_BATCH2_DEG: Deg = Deg { v: 3, u: 2 };
#[cfg(test)]
#[derive(Copy, Clone, Debug, Default)]
pub struct EidosCompressionLookupAir;

/// Lookup builder accepted by the Eidos compression AIR.
pub(crate) trait EidosCompressionLookupBuilder: LookupBuilder<F = Felt> {}

impl<T> EidosCompressionLookupBuilder for T where T: LookupBuilder<F = Felt> {}

#[cfg(test)]
impl<LB> LookupAir<LB> for EidosCompressionLookupAir
where
    LB: EidosCompressionLookupBuilder,
{
    fn column_shape(&self) -> &[usize] {
        &EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        BusId::COUNT
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

/// Emits all Eidos compression lookup groups in their fixed auxiliary-column order.
pub(crate) fn emit_lookup_columns<LB>(
    builder: &mut LB,
    local: &EidosCompressionCols<LB::Var>,
    next: &EidosCompressionCols<LB::Var>,
    selectors: &EidosCompressionSelectors<LB::Expr>,
) where
    LB: EidosCompressionLookupBuilder,
{
    for aux_col in 0..EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE.len() {
        let column_deg = match aux_col {
            0..NARROW_BATCH_COLUMNS => Deg { v: 2, u: 2 },
            FOOTER_INPUT_COLUMN => FOOTER_INPUT_DEG,
            FOOTER_OUTPUT_COLUMN => FOOTER_OUTPUT_BATCH2_DEG,
            _ => unreachable!("32-row EidosCompression lookup aux column out of range"),
        };
        builder.next_column(
            |col| {
                col.group(
                    "eidos_compression",
                    |group| match aux_col {
                        0..NARROW_BATCH_COLUMNS => {
                            // Narrow columns pair adjacent slots under their row-specific
                            // multiplicities.
                            let slot0 = 2 * aux_col;
                            let slot1 = slot0 + 1;
                            let slot0_multiplicity =
                                narrow_slot_multiplicity::<LB>(slot0, selectors);
                            let slot1_multiplicity =
                                narrow_slot_multiplicity::<LB>(slot1, selectors);
                            let slot0_encoding = narrow_slot_encoding::<LB, _>(
                                &*group, local, next, selectors, slot0,
                            );
                            let slot1_encoding = narrow_slot_encoding::<LB, _>(
                                &*group, local, next, selectors, slot1,
                            );

                            group.selected_batch2_encoded(
                                "narrow_pair",
                                "slot0",
                                slot0_multiplicity,
                                || slot0_encoding,
                                "slot1",
                                slot1_multiplicity,
                                || slot1_encoding,
                            );
                        },
                        FOOTER_INPUT_COLUMN => {
                            // The linear CV and external-input denominators are batched with
                            // degree-one and degree-two multiplicities, giving degree two for U
                            // and degree three for V. The external-input denominator remains in
                            // the cross product when its multiplicity is zero; its unit alpha
                            // coefficient prevents an identically zero cancellation. The
                            // inactive-row constraint pins this column when both multiplicities are
                            // zero.
                            let mode = LB::Expr::from(local.columns[F_MODE_COL]);
                            let is_f3 = selectors.is_footer_row(FOOTER_ROWS - 1);
                            let cv_multiplicity = is_f3.clone() - selectors.is_first_fused();
                            let input_multiplicity = -is_f3
                                * (LB::Expr::from(local.columns[F_COMPRESSION_MULTIPLICITY_COL])
                                    + mode.clone());
                            group.batch(
                                "full_cv_and_external_input",
                                LB::Expr::ONE,
                                |batch| {
                                    batch.insert(
                                        "full_cv",
                                        cv_multiplicity,
                                        FullCvMsg {
                                            compression_cycle_id: LB::Expr::from(
                                                local.columns[F_COMPRESSION_CYCLE_ID_COL],
                                            ),
                                            words: core::array::from_fn(|idx| {
                                                cv_word::<LB>(local, idx)
                                            }),
                                        },
                                        Deg { v: 1, u: 1 },
                                    );
                                    batch.insert(
                                        "compression_or_aead_input",
                                        input_multiplicity,
                                        FooterInputMsg {
                                            mode,
                                            block: footer_block::<LB>(local),
                                            cv_in: core::array::from_fn(|idx| {
                                                pack_pair::<LB>(
                                                    cv_word::<LB>(local, 2 * idx),
                                                    cv_word::<LB>(local, 2 * idx + 1),
                                                )
                                            }),
                                            tail: core::array::from_fn(|idx| {
                                                LB::Expr::from(
                                                    local.columns[footer_interface_tail_col(idx)],
                                                )
                                            }),
                                        },
                                        Deg { v: 2, u: 1 },
                                    );
                                },
                                FOOTER_INPUT_DEG,
                            );
                        },
                        FOOTER_OUTPUT_COLUMN => {
                            // Both output relations are active only in AEAD mode. Their shared
                            // degree-two multiplicity gives degree two for U and degree three for
                            // V; the inactive-row constraint pins this column everywhere else,
                            // including when a denominator is zero.
                            let mode = LB::Expr::from(local.columns[F_MODE_COL]);
                            let multiplicity = -selectors.is_footer() * mode;
                            group.batch(
                                "aead_output_pairs",
                                LB::Expr::ONE,
                                |batch| {
                                    batch.insert(
                                        "aead_low_output_pair",
                                        multiplicity.clone(),
                                        aead_output_pair_msg_for_current_footer::<LB>(
                                            local, selectors, 0,
                                        ),
                                        Deg { v: 2, u: 1 },
                                    );
                                    batch.insert(
                                        "aead_high_output_pair",
                                        multiplicity,
                                        aead_output_pair_msg_for_current_footer::<LB>(
                                            local, selectors, 8,
                                        ),
                                        Deg { v: 2, u: 1 },
                                    );
                                },
                                FOOTER_OUTPUT_BATCH2_DEG,
                            );
                        },
                        _ => unreachable!("32-row EidosCompression lookup aux column out of range"),
                    },
                    column_deg,
                );
            },
            column_deg,
        );
    }
}

fn narrow_slot_multiplicity<LB>(
    slot: usize,
    selectors: &EidosCompressionSelectors<LB::Expr>,
) -> LB::Expr
where
    LB: EidosCompressionLookupBuilder,
{
    let fused = is_fused::<LB>(selectors);
    let footer = selectors.is_footer();
    let spec = NARROW_SLOTS[slot];

    match (spec.fused_bus, spec.footer_bus) {
        (NarrowSlotBus::MessageWord, Some(NarrowSlotBus::MessageWord)) => {
            fused - LB::Expr::from_u64(7) * footer
        },
        (NarrowSlotBus::MessageWord, None) => fused,
        (_, Some(_)) => -(fused + footer),
        (_, None) => -fused,
    }
}

fn narrow_slot_encoding<LB, G>(
    group: &G,
    local: &EidosCompressionCols<LB::Var>,
    next: &EidosCompressionCols<LB::Var>,
    selectors: &EidosCompressionSelectors<LB::Expr>,
    slot: usize,
) -> G::ExprEF
where
    LB: EidosCompressionLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let spec = NARROW_SLOTS[slot];
    let fused = is_fused::<LB>(selectors);
    let footer = selectors.is_footer();
    let mut encoded = G::ExprEF::ZERO;

    match spec.fused_bus {
        NarrowSlotBus::And8 => {
            encoded += group.bus_prefix(BusId::And8Lookup as usize) * fused.clone();
        },
        NarrowSlotBus::Rotation(byte) => {
            let byte = byte as usize;
            encoded +=
                group.bus_prefix(eidos_compression_rot12_bus(byte) as usize) * selectors.is_ab();
            encoded +=
                group.bus_prefix(eidos_compression_rot7_bus(byte) as usize) * selectors.is_cd();
        },
        NarrowSlotBus::MessageWord => {
            let activity = if matches!(spec.footer_bus, Some(NarrowSlotBus::MessageWord)) {
                fused.clone() + footer.clone()
            } else {
                fused.clone()
            };
            encoded += group.bus_prefix(BusId::EidosCompressionMessageWord as usize) * activity;
        },
        NarrowSlotBus::RangeCheck => {
            unreachable!("range checks are not used on fused rows")
        },
    }

    match spec.footer_bus {
        Some(NarrowSlotBus::And8) => {
            encoded += group.bus_prefix(BusId::And8Lookup as usize) * footer.clone();
        },
        Some(NarrowSlotBus::RangeCheck) => {
            encoded += group.bus_prefix(BusId::RangeCheck as usize) * footer.clone();
        },
        Some(NarrowSlotBus::MessageWord) => {},
        Some(NarrowSlotBus::Rotation(_)) => {
            unreachable!("rotations are not used on footer rows")
        },
        None => {},
    }

    // Route every inactive slot to the range-check bus.
    let activity = fused
        + if spec.footer_bus.is_some() {
            footer
        } else {
            LB::Expr::ZERO
        };
    encoded += group.bus_prefix(BusId::RangeCheck as usize) * (LB::Expr::ONE - activity);
    let fields = narrow_slot_fields::<LB>(local, next, selectors, slot);
    for (idx, field) in fields.into_iter().enumerate() {
        encoded += group.beta_powers()[idx].clone() * field;
    }
    encoded
}

fn footer_block<LB>(local: &EidosCompressionCols<LB::Var>) -> [LB::Expr; 8]
where
    LB: EidosCompressionLookupBuilder,
{
    core::array::from_fn(|idx| {
        if idx < 6 {
            LB::Expr::from(local.columns[footer_r_col(FOOTER_ROWS - 1, idx)])
        } else {
            let pair = idx - 6;
            pack_pair::<LB>(
                LB::Expr::from(local.columns[footer_msg_word_col(2 * pair)]),
                LB::Expr::from(local.columns[footer_msg_word_col(2 * pair + 1)]),
            )
        }
    })
}

fn cv_word<LB>(local: &EidosCompressionCols<LB::Var>, idx: usize) -> LB::Expr
where
    LB: EidosCompressionLookupBuilder,
{
    universal_cv_word(|col| LB::Expr::from(local.columns[col]), idx)
}

fn pack_pair<LB>(lo: LB::Expr, hi: LB::Expr) -> LB::Expr
where
    LB: EidosCompressionLookupBuilder,
{
    lo + LB::Expr::from_u64(1u64 << 32) * hi
}

fn aead_output_pair_msg_for_current_footer<LB>(
    local: &EidosCompressionCols<LB::Var>,
    selectors: &EidosCompressionSelectors<LB::Expr>,
    lane_offset: usize,
) -> AeadEidosCompressionOutputPairMsg<LB::Expr>
where
    LB: EidosCompressionLookupBuilder,
{
    let footer_idx = selectors.is_footer_row(1)
        + LB::Expr::from_u64(2) * selectors.is_footer_row(2)
        + LB::Expr::from_u64(3) * selectors.is_footer_row(3);
    let [value0, value1] = if lane_offset == 0 {
        [
            footer_xor_word::<LB>(local, F_OUTPUT_EVEN_SLOT_BASE),
            footer_xor_word::<LB>(local, F_OUTPUT_ODD_SLOT_BASE),
        ]
    } else {
        [
            footer_xor_word::<LB>(local, F_HIGH_EVEN_SLOT_BASE),
            footer_xor_word::<LB>(local, F_HIGH_ODD_SLOT_BASE),
        ]
    };

    AeadEidosCompressionOutputPairMsg {
        clk: LB::Expr::from(local.columns[F_CLK_COL]),
        first_lane_idx: LB::Expr::from_u64(lane_offset as u64) + LB::Expr::from_u64(2) * footer_idx,
        value0,
        value1,
    }
}

fn footer_xor_word<LB>(local: &EidosCompressionCols<LB::Var>, slot_base: usize) -> LB::Expr
where
    LB: EidosCompressionLookupBuilder,
{
    pack_u32_le(
        footer_xor_byte::<LB>(local, slot_base),
        footer_xor_byte::<LB>(local, slot_base + 1),
        footer_xor_byte::<LB>(local, slot_base + 2),
        footer_xor_byte::<LB>(local, slot_base + 3),
    )
}

fn footer_xor_byte<LB>(local: &EidosCompressionCols<LB::Var>, slot: usize) -> LB::Expr
where
    LB: EidosCompressionLookupBuilder,
{
    let base = footer_xor_slot_col(slot, 0);
    let lhs = LB::Expr::from(local.columns[base]);
    let rhs = LB::Expr::from(local.columns[base + 1]);
    let and = LB::Expr::from(local.columns[base + 2]);
    xor_from_and(lhs, rhs, and)
}

fn narrow_slot_fields<LB>(
    local: &EidosCompressionCols<LB::Var>,
    next: &EidosCompressionCols<LB::Var>,
    selectors: &EidosCompressionSelectors<LB::Expr>,
    slot: usize,
) -> [LB::Expr; 3]
where
    LB: EidosCompressionLookupBuilder,
{
    match NARROW_SLOTS[slot].fields {
        NarrowSlotFields::StoredByte(stored_slot) => {
            let base = byte_slot_base(0, stored_slot as usize);
            [
                LB::Expr::from(local.columns[base]),
                LB::Expr::from(local.columns[base + 1]),
                LB::Expr::from(local.columns[base + 2]),
            ]
        },
        NarrowSlotFields::MissingRotation => [
            LB::Expr::from(
                local.columns[g_bd_rot_slot_col(MISSING_ROTATION_G, MISSING_ROTATION_BYTE, 0)],
            ),
            LB::Expr::from(
                local.columns[g_bd_rot_slot_col(MISSING_ROTATION_G, MISSING_ROTATION_BYTE, 1)],
            ),
            missing_rotation_result(
                |col| LB::Expr::from(local.columns[col]),
                |col| LB::Expr::from(next.columns[col]),
            ),
        ],
        NarrowSlotFields::MessageWord(g) => {
            let g = g as usize;
            [
                message_index::<LB>(selectors, g),
                LB::Expr::from(local.columns[g_msg_word_col(g)]),
                LB::Expr::from(local.columns[G_COMPRESSION_CYCLE_ID_COL]),
            ]
        },
    }
}

fn message_index<LB>(selectors: &EidosCompressionSelectors<LB::Expr>, g: usize) -> LB::Expr
where
    LB: EidosCompressionLookupBuilder,
{
    let footer = selectors.is_footer();
    let footer_idx = selectors.is_footer_row(1)
        + LB::Expr::from_u64(2) * selectors.is_footer_row(2)
        + LB::Expr::from_u64(3) * selectors.is_footer_row(3);
    selectors.sigma_msg_index(g)
        + LB::Expr::from_u64(g as u64) * footer
        + LB::Expr::from_u64(4) * footer_idx
}

fn is_fused<LB>(selectors: &EidosCompressionSelectors<LB::Expr>) -> LB::Expr
where
    LB: EidosCompressionLookupBuilder,
{
    selectors.is_ab() + selectors.is_cd()
}

#[cfg(test)]
pub fn lookup_plan(row: usize, mode: EidosCompressionMode) -> LookupPlan {
    let mut plan = LookupPlan {
        narrow: Vec::new(),
        overlay_relations: Vec::new(),
    };

    match row_kind(row) {
        RowKind::Ab => {
            add_fused_g_lookups(&mut plan, NarrowLookupKind::Rot12);
            if row == 0 {
                plan.overlay_relations.push(OverlayRelation {
                    kind: OverlayRelationKind::FullCv,
                    sign: -1,
                });
            }
        },
        RowKind::AbDiag => add_fused_g_lookups(&mut plan, NarrowLookupKind::Rot12),
        RowKind::Cd | RowKind::CdDiag => add_fused_g_lookups(&mut plan, NarrowLookupKind::Rot7),
        RowKind::Footer(footer) => add_footer_lookups(&mut plan, footer, mode),
    }

    plan
}

#[cfg(test)]
fn add_fused_g_lookups(plan: &mut LookupPlan, rotation_kind: NarrowLookupKind) {
    plan.narrow.extend(NARROW_SLOTS.map(|spec| match spec.fused_bus {
        NarrowSlotBus::And8 => NarrowLookup { kind: NarrowLookupKind::And8, sign: -1 },
        NarrowSlotBus::Rotation(_) => NarrowLookup { kind: rotation_kind, sign: -1 },
        NarrowSlotBus::MessageWord => NarrowLookup {
            kind: NarrowLookupKind::MessageWord,
            sign: 1,
        },
        NarrowSlotBus::RangeCheck => unreachable!("range checks are not used on fused rows"),
    }));
}

#[cfg(test)]
fn add_footer_lookups(plan: &mut LookupPlan, footer: usize, mode: EidosCompressionMode) {
    plan.narrow.extend(NARROW_SLOTS.into_iter().filter_map(|spec| {
        let bus = spec.footer_bus?;
        Some(match bus {
            NarrowSlotBus::And8 => NarrowLookup { kind: NarrowLookupKind::And8, sign: -1 },
            NarrowSlotBus::RangeCheck => NarrowLookup {
                kind: NarrowLookupKind::RangeCheck,
                sign: -1,
            },
            NarrowSlotBus::MessageWord => NarrowLookup {
                kind: NarrowLookupKind::MessageWord,
                sign: -7,
            },
            NarrowSlotBus::Rotation(_) => {
                unreachable!("rotations are not used on footer rows")
            },
        })
    }));

    if footer == FOOTER_ROWS - 1 {
        plan.overlay_relations.push(OverlayRelation {
            kind: OverlayRelationKind::FullCv,
            sign: 1,
        });
    }

    match mode {
        EidosCompressionMode::Compression => {
            if footer == FOOTER_ROWS - 1 {
                plan.overlay_relations.push(OverlayRelation {
                    kind: OverlayRelationKind::CompressionLink,
                    sign: -1,
                });
            }
        },
        EidosCompressionMode::AeadXof => {
            if footer == FOOTER_ROWS - 1 {
                plan.overlay_relations.push(OverlayRelation {
                    kind: OverlayRelationKind::AeadInput,
                    sign: -1,
                });
            }
            plan.overlay_relations.push(OverlayRelation {
                kind: OverlayRelationKind::AeadLowOutputPair,
                sign: -1,
            });
            plan.overlay_relations.push(OverlayRelation {
                kind: OverlayRelationKind::AeadHighOutputPair,
                sign: -1,
            });
        },
    }
}
