//! EcGroupAdd trace generation + aux builder.
//!
//! [`generate_trace`] lays each recorded add op out as a [`PERIOD`]-row
//! block — the transient / hosted-scalar cells plus the cycle-constant
//! metadata columns; pads are all-zero `act = 0` blocks. Every
//! certificate the block consumes is recorded into the uint relation
//! chiplets by [`EcRequire`](crate::ec::require::EcRequire), and the
//! coordinate limbs never enter this trace — the aux is exactly the
//! LogUp columns, no witness registers.

use alloc::{collections::BTreeMap, vec::Vec};

use miden_core::{Felt, field::QuadFelt, utils::RowMajorMatrix};

use super::{
    CELL_GROUP, CELL_R, CELL_SBOUND, COL_A_PTR, COL_ACT, COL_B_PTR, COL_BOUND_PTR, COL_CANCEL,
    COL_DBL, COL_GEN, COL_MINTS, COL_PAI_P, COL_PAI_Q, COL_PX, COL_PY, COL_QX, COL_QY, COL_RP_HI,
    COL_RP_LO, COL_RQ_HI, COL_RQ_LO, EcGroupAddAir, NUM_CELLS, NUM_MAIN_COLS, PERIOD, ROW_RES,
    ROW_SLOPE, ROW_TAIL, ROW_TERM, TERM_CELL_MULT, TERM_CELL_P, TERM_CELL_Q,
};
use crate::{
    ec::trace::{EcGroupPtr, EcPointPtr, EcStoreRequires},
    logup::build_logup_aux_trace,
    primitives::byte_pair_lut::BytePairLutRequires,
    relations::ProvideMult,
    uint::trace::UintPtr,
};

/// Which row of the case lattice an op claims.
/// [`EcRequire`](crate::ec::require::EcRequire) derives this from the
/// operands' *values* (store rows + `is_pai` flags); the AIR re-derives
/// it adversarially from the witnessed flags + certificate demands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EcAddCase {
    /// `P = ∞`, `Q` finite — pass-through `R = Q`.
    PaiP,
    /// `Q = ∞`, `P` finite — pass-through `R = P`.
    PaiQ,
    /// `P = Q = ∞` — *both* pass flags set (each rides its operand's
    /// consumed tuple as `is_pai`); the ties force `p = q = r`.
    PaiBoth,
    /// Finite, `x₁ = x₂`, `y₁ + y₂ ≡ 0` — `R` = the group's PAI row.
    Cancel,
    /// Finite, `x₁ = x₂`, `y₁ = y₂ ≠ 0` — tangent.
    Double,
    /// Finite, `x₁ ≠ x₂` — chord.
    Generic,
}

impl EcAddCase {
    /// The `(pai_p, pai_q, cancel, double, generic)` flag cells.
    pub(crate) fn flags(self) -> [bool; 5] {
        match self {
            Self::PaiP => [true, false, false, false, false],
            Self::PaiQ => [false, true, false, false, false],
            Self::PaiBoth => [true, true, false, false, false],
            Self::Cancel => [false, false, true, false, false],
            Self::Double => [false, false, false, true, false],
            Self::Generic => [false, false, false, false, true],
        }
    }
}

/// One recorded add op `R = P + Q`: the claimed case and every handle
/// the block's cells and metadata columns carry — pure ptr space. The
/// certificate ops themselves (slope / tail / equality / inverse
/// arrangements) are recorded into the uint relation chiplets by
/// [`EcRequire`](crate::ec::require::EcRequire); this struct only holds
/// what the 4-row block lays out.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EcAddOp {
    pub case: EcAddCase,
    pub group: EcGroupPtr,
    pub bound: UintPtr,
    pub a: UintPtr,
    pub b: UintPtr,
    pub p: EcPointPtr,
    pub q: EcPointPtr,
    pub r: EcPointPtr,
    /// Operand coordinate handles (`None` for a PAI operand, laid as the
    /// 0 none-sentinels).
    pub p_coords: Option<(UintPtr, UintPtr)>,
    pub q_coords: Option<(UintPtr, UintPtr)>,
    /// Transient cells of the live formulas, in cell order — `(slope_aux,
    /// λ, t)` on the slope row, `(y₃, e, x₃)` on the tail row — `None`
    /// (all-zero cells) for the cases that allocate none.
    pub transients: Option<[UintPtr; 6]>,
    /// Fresh-mint flag (closure cert): `true` iff this op *first* minted
    /// `r` (a generic/double `add_point_at` miss) — the op that owns `r`'s
    /// membership certificate. Drives `COL_MINTS` + the ptr-ordering
    /// witnesses; `false` on pass-throughs, cancel, and value-deduped
    /// results (which reuse an existing certified row).
    pub mints: bool,
}

/// `*Requires` accumulator for the EcGroupAdd chiplet: the recorded ops
/// with their accumulated `EcGroupAdd` provide multiplicities, in
/// first-recorded (block) order. Recording **interns by relation
/// identity** `(group, p, q)` — a repeat of an already-recorded add
/// collapses onto its block, the mults adding (e.g. an MSM table combine
/// reused across windows). `(group, p, q)` determines the result and
/// every certificate, so the [`EcRequire`](crate::ec::require::EcRequire)
/// dedup-check on `consume` lets a repeat skip the
/// certificate recording entirely, mirroring the uint relations.
#[derive(Debug, Default)]
pub struct EcAddRequires {
    /// `(op, provide mult)` in first-recorded order; mult 0 = dormant
    /// (no `EcGroupAdd` consumer yet — until the MSM / DAG layer lands).
    pub(crate) ops: Vec<(EcAddOp, ProvideMult)>,
    /// Relation identity `(group, p, q)` → index into `ops`.
    dedup: BTreeMap<(EcGroupPtr, EcPointPtr, EcPointPtr), usize>,
}

impl EcAddRequires {
    pub fn new() -> Self {
        Self::default()
    }

    /// If `(group, p, q)` is already recorded, count one more consumer
    /// of its `EcGroupAdd` tuple (mult += `mult`) and return its result
    /// — the require layer then skips re-deriving the op and its
    /// certificates. `None` on first sighting.
    pub(crate) fn consume(
        &mut self,
        group: EcGroupPtr,
        p: EcPointPtr,
        q: EcPointPtr,
        mult: ProvideMult,
    ) -> Option<EcPointPtr> {
        let &i = self.dedup.get(&(group, p, q))?;
        self.ops[i].1 += mult;
        Some(self.ops[i].0.r)
    }

    /// Record a freshly-derived op (its certificates just laid into the
    /// uint relations) at provide multiplicity `mult` — the caller has
    /// confirmed via [`consume`](Self::consume) that it is new.
    pub(crate) fn record(&mut self, op: EcAddOp, mult: ProvideMult) {
        self.dedup.insert((op.group, op.p, op.q), self.ops.len());
        self.ops.push((op, mult));
    }
}

/// Lay one op's [`PERIOD`]-row block per the layout in [`super`], its
/// `EcGroupAdd` provide at multiplicity `mult` (0 = dormant).
fn op_block(op: &EcAddOp, mult: ProvideMult, ec: &EcStoreRequires) -> Vec<Felt> {
    let mut block = [[Felt::ZERO; NUM_MAIN_COLS]; PERIOD];
    let mut set = |row: usize, col: usize, v: u32| block[row][col] = Felt::from(v);

    // Transient ptr cells: slope row, then tail row.
    let transients = op.transients.map_or([0u32; 6], |t| t.map(UintPtr::addr));
    for (cell, ptr) in transients[..NUM_CELLS].iter().enumerate() {
        set(ROW_SLOPE, cell, *ptr);
    }
    for (cell, ptr) in transients[NUM_CELLS..2 * NUM_CELLS].iter().enumerate() {
        set(ROW_TAIL, cell, *ptr);
    }

    // Hosted scalars: the result / scalar-bound / group ptrs on the res
    // row, the operand ptrs + the `EcGroupAdd` provide multiplicity
    // (term cell 0) on the term row.
    set(ROW_RES, CELL_R, op.r.addr());
    set(ROW_RES, CELL_SBOUND, ec.group_sbound(op.group).addr());
    set(ROW_RES, CELL_GROUP, op.group.addr());
    set(ROW_TERM, TERM_CELL_P, op.p.addr());
    set(ROW_TERM, TERM_CELL_Q, op.q.addr());

    // Cycle-constant metadata.
    let [pai_p, pai_q, cancel, dbl, generic] = op.case.flags();
    let coord = |c: Option<(UintPtr, UintPtr)>, y: bool| -> u32 {
        c.map_or(0, |(cx, cy)| if y { cy.addr() } else { cx.addr() })
    };
    // Closure-cert ptr-ordering witnesses (mint ops only): r_ptr > p_ptr ∧
    // r_ptr > q_ptr (a fresh result is the maximal ptr), proved by the
    // 16-bit limbs of r−p−1 and r−q−1 (Range16-checked in the LookupAir).
    // 0 off mint ops, where the case guard forces COL_MINTS = 0.
    let (rp_lo, rp_hi, rq_lo, rq_hi) = if op.mints {
        let rp = op.r.addr() - op.p.addr() - 1;
        let rq = op.r.addr() - op.q.addr() - 1;
        (rp & 0xffff, rp >> 16, rq & 0xffff, rq >> 16)
    } else {
        (0, 0, 0, 0)
    };
    for row in 0..PERIOD {
        set(row, COL_PX, coord(op.p_coords, false));
        set(row, COL_PY, coord(op.p_coords, true));
        set(row, COL_QX, coord(op.q_coords, false));
        set(row, COL_QY, coord(op.q_coords, true));
        set(row, COL_A_PTR, op.a.addr());
        set(row, COL_B_PTR, op.b.addr());
        set(row, COL_BOUND_PTR, op.bound.addr());
        set(row, COL_PAI_P, u32::from(pai_p));
        set(row, COL_PAI_Q, u32::from(pai_q));
        set(row, COL_CANCEL, u32::from(cancel));
        set(row, COL_DBL, u32::from(dbl));
        set(row, COL_GEN, u32::from(generic));
        set(row, COL_ACT, 1);
        set(row, COL_MINTS, u32::from(op.mints));
        set(row, COL_RP_LO, rp_lo);
        set(row, COL_RP_HI, rp_hi);
        set(row, COL_RQ_LO, rq_lo);
        set(row, COL_RQ_HI, rq_hi);
    }
    // The `EcGroupAdd` provide multiplicity (term cell 0).
    set(ROW_TERM, TERM_CELL_MULT, mult);
    block.into_iter().flatten().collect()
}

/// Build the EcGroupAdd main trace from the recorded ops (the
/// accumulator is consumed — trace-gen is terminal, making the
/// double-lay hazard a compile error) — one op = one [`PERIOD`]-row
/// block, the scalar bound resolved from the group table — padded to a
/// power-of-two height with all-zero (`act = 0`) rows that touch no bus.
///
/// The same pass routes each op's cross-chiplet demand into the EC store
/// (`ec`): both operands' `EcPoint`, and — on the live cases — the
/// result's `EcPoint` and the group's `EcGroup` (the pass-throughs tie
/// their result to an operand, consuming no extra row). Mint ops also
/// raise four `Range16` requires into `bpl` for the ptr-ordering limbs.
/// Run it before the store's and BPL's own traces read their ledgers.
pub fn generate_trace(
    requires: EcAddRequires,
    ec: &mut EcStoreRequires,
    bpl: &mut BytePairLutRequires,
) -> RowMajorMatrix<Felt> {
    #[cfg(feature = "std")]
    if std::env::var_os("DUMP_TRACE_HEIGHTS").is_some() {
        let real = requires.ops.len() * PERIOD;
        std::eprintln!("REAL_HEIGHT EcGroupAdd {real}");
    }
    let height = (requires.ops.len().max(1) * PERIOD).next_power_of_two();
    let mut vals = Vec::with_capacity(height * NUM_MAIN_COLS);
    for (op, mult) in &requires.ops {
        ec.require_ecpoint(op.p);
        ec.require_ecpoint(op.q);
        let [_, _, cancel, dbl, generic] = op.case.flags();
        if cancel || dbl || generic {
            ec.require_ecgroup(op.group);
            ec.require_ecpoint(op.r);
        }
        // Mint ops: route the ptr-ordering limbs (r−p−1, r−q−1) to BPL so
        // the col-3 Range16 consumes balance.
        if op.mints {
            let rp = op.r.addr() - op.p.addr() - 1;
            let rq = op.r.addr() - op.q.addr() - 1;
            bpl.require_range16((rp & 0xffff) as u16);
            bpl.require_range16((rp >> 16) as u16);
            bpl.require_range16((rq & 0xffff) as u16);
            bpl.require_range16((rq >> 16) as u16);
        }
        vals.extend(op_block(op, *mult, ec));
    }
    // Padding blocks: all-zero (act = 0) rows that touch no bus.
    vals.resize(height * NUM_MAIN_COLS, Felt::ZERO);
    RowMajorMatrix::new(vals, NUM_MAIN_COLS)
}

// PROVER
// ================================================================================================

/// Witness-bearing companion to [`EcGroupAddAir`] — the aux trace is
/// exactly the LogUp columns (no fingerprint, no inverse cells).
pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    build_logup_aux_trace(&EcGroupAddAir, main, challenges)
}
