//! Unit-test support for the standalone Eidos compression AIR.

use alloc::{vec, vec::Vec};
use core::borrow::Borrow;

use miden_core::Felt;
use miden_crypto::stark::air::WindowAccess;

use super::{
    layout::*,
    lookup::{
        EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE, EidosCompressionCols, EidosCompressionLookupBuilder,
        emit_lookup_columns,
    },
    model::initial_working_state,
    narrow::{NARROW_SLOTS, NarrowSlotBus},
    schedule::{G_IDX_COL, G_IDX_DIAG, SIGMA, fused_step_at},
    selectors::EidosCompressionSelectors,
    trace::{
        ByteLookupRecorder, EidosCompressionByteLookup, EidosCompressionFeltRow,
        EidosCompressionFeltTraceBlock, TraceMode, TraceRow, write_footer_rows, write_trace_rows,
        write_trace_rows_from_state,
    },
};
use crate::{constraints::lookup::MIDEN_MAX_MESSAGE_WIDTH, lookup::LookupAir};

// Lookup descriptions used to check the semantic interaction grammar independently of the
// production lookup builder.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EidosCompressionMode {
    Compression,
    AeadXof,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NarrowLookupKind {
    And8,
    Rot12,
    Rot7,
    MessageWord,
    RangeCheck,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NarrowLookup {
    pub kind: NarrowLookupKind,
    pub sign: i8,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OverlayRelationKind {
    FullCv,
    CompressionLink,
    AeadInput,
    AeadLowOutputPair,
    AeadHighOutputPair,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OverlayRelation {
    pub kind: OverlayRelationKind,
    pub sign: i8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupPlan {
    pub narrow: Vec<NarrowLookup>,
    pub overlay_relations: Vec<OverlayRelation>,
}

impl LookupPlan {
    pub fn narrow_aux_columns(&self) -> usize {
        self.narrow.len().div_ceil(2)
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct EidosCompressionLookupAir;

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
        crate::logup::BusId::COUNT
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

// Direct compression models used as test oracles for both the schedule and the trace writer.

pub fn execute_fused_rounds(block: [u32; 16], h: [u32; 8]) -> [u32; 16] {
    let mut v = initial_working_state(h);

    for row in 0..FUSED_G_ROWS {
        let step = fused_step_at(row).expect("row is a fused G row");
        for g in 0..4 {
            let [ai, bi, ci, di] = step.lane_map[g];
            let msg = block[step.message_indices[g]];
            apply_half_g(&mut v, [ai, bi, ci, di], msg, step.first_rotation, step.second_rotation);
        }
    }

    v
}

pub fn execute_unfused_rounds(block: [u32; 16], h: [u32; 8]) -> [u32; 16] {
    let mut v = initial_working_state(h);

    for s in &SIGMA {
        for g in 0..4 {
            apply_full_g(&mut v, G_IDX_COL[g], block[s[2 * g]], block[s[2 * g + 1]]);
        }
        for g in 0..4 {
            apply_full_g(&mut v, G_IDX_DIAG[g], block[s[8 + 2 * g]], block[s[8 + 2 * g + 1]]);
        }
    }

    v
}

pub fn xof_lanes(v: [u32; 16], h: [u32; 8]) -> [u32; 16] {
    core::array::from_fn(|i| if i < 8 { v[i] ^ v[i + 8] } else { v[i] ^ h[i - 8] })
}

fn apply_full_g(v: &mut [u32; 16], lane: [usize; 4], msg0: u32, msg1: u32) {
    apply_half_g(v, lane, msg0, 16, 12);
    apply_half_g(v, lane, msg1, 8, 7);
}

fn apply_half_g(
    v: &mut [u32; 16],
    [ai, bi, ci, di]: [usize; 4],
    msg: u32,
    first_rotation: u32,
    second_rotation: u32,
) {
    v[ai] = v[ai].wrapping_add(v[bi]).wrapping_add(msg);
    v[di] = (v[di] ^ v[ai]).rotate_right(first_rotation);
    v[ci] = v[ci].wrapping_add(v[di]);
    v[bi] = (v[bi] ^ v[ci]).rotate_right(second_rotation);
}

// Raw-row trace adapter and targeted witness constructors used by mutation tests.

pub type EidosCompressionRow = [u64; NUM_COLS];

pub struct EidosCompressionTraceBlock {
    pub rows: [EidosCompressionRow; BLOCK_PERIOD],
    pub final_v: [u32; 16],
}

impl TraceRow for EidosCompressionRow {
    #[inline]
    fn get_u64(&self, col: usize) -> u64 {
        self[col]
    }

    #[inline]
    fn set_u64(&mut self, col: usize, value: u64) {
        self[col] = value;
    }
}

struct NoopByteLookupRecorder;

impl ByteLookupRecorder for NoopByteLookupRecorder {
    fn record(&mut self, _lookup: EidosCompressionByteLookup, _lhs: u8, _rhs: u8, _result: u32) {}
}

pub fn generate_trace_block(
    block: [u32; 16],
    h: [u32; 8],
    mode: TraceMode,
) -> EidosCompressionTraceBlock {
    generate_trace_block_with_cycle_id(block, h, 0, mode)
}

pub fn generate_trace_block_with_cycle_id(
    block: [u32; 16],
    h: [u32; 8],
    compression_cycle_id: u64,
    mode: TraceMode,
) -> EidosCompressionTraceBlock {
    let mut rows = vec![[0u64; NUM_COLS]; BLOCK_PERIOD];
    let mut recorder = NoopByteLookupRecorder;
    let final_v = write_trace_rows(&mut rows, block, h, compression_cycle_id, mode, &mut recorder);
    let rows = rows
        .try_into()
        .unwrap_or_else(|_| unreachable!("fixed Eidos compression trace length"));

    EidosCompressionTraceBlock { rows, final_v }
}

pub fn generate_felt_trace_block_with_initial_state_for_test(
    block: [u32; 16],
    h: [u32; 8],
    initial_v: [u32; 16],
    mode: TraceMode,
) -> EidosCompressionFeltTraceBlock {
    assert_eq!(&initial_v[..8], &h);
    let mut rows = vec![[Felt::ZERO; NUM_COLS]; BLOCK_PERIOD];
    let mut recorder = NoopByteLookupRecorder;
    let final_v =
        write_trace_rows_from_state(&mut rows, block, h, initial_v, 0, mode, &mut recorder);
    let rows = rows
        .try_into()
        .unwrap_or_else(|_| unreachable!("fixed Eidos compression trace length"));

    EidosCompressionFeltTraceBlock { rows, final_v }
}

pub fn rewrite_felt_footer_for_test(
    rows: &mut [EidosCompressionFeltRow; BLOCK_PERIOD],
    block: [u32; 16],
    h: [u32; 8],
    final_v: [u32; 16],
    mode: TraceMode,
) {
    for row in rows.iter_mut().skip(FOOTER_START) {
        row.fill(Felt::ZERO);
    }
    write_footer_rows(rows, block, h, final_v, 0, mode, &mut NoopByteLookupRecorder);
}
