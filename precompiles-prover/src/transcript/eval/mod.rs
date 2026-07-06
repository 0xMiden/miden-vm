//! Transcript eval chiplet — the Transcript AND-tree plus uint and EC value
//! nodes.
//!
//! The narrow, central hasher + binder for the transcript DAG. Each
//! active row evaluates one node: it hashes the node's preimage on
//! Poseidon2 and settles the node's `Binding`-bus tuple. The eval chip is
//! the sole provider of the `Binding` bus, except `KeccakNodeAir`, which
//! fuses its own terminal keccak `True` (there is no transient Keccak —
//! see `docs/transcript-eval.md`). Domain chiplets (the `UintStore`,
//! `UintAdd` / `UintMul`, EC store/add/MSM chiplets) stay ptr-only and never
//! touch `Binding`; this chip hashes their DAG nodes and ptr-references their
//! relations.
//!
//! Node kinds are dispatched by a uniform one-hot `is_and + is_zero +
//! is_uint_leaf + Σ op-flags = act`: the **Transcript AND-combinator**
//! `h = Poseidon2(lhs || rhs || Tag::AND)[0..4]` folding two child
//! `True` bindings; the **uint leaf / pin-claim row**, which hashes a stored uint's
//! value under either `[UintPrecompile::id(), VALUE_OP_ID, bound_ptr, 0]`
//! or `[UINT_PIN_CLAIM_TAG, bound_ptr, pin_ptr, 0]`; and the **uint ops**
//! (`is_add` / `is_sub` / `is_mul` / `is_is`), which hash two child hashes under
//! `[UintPrecompile::id(), op_id, 0, 0]` and tie the children's `Uint` bindings
//! to a [`UintAdd`](crate::uint::add) / [`UintMul`](crate::uint::mul) relation
//! tuple by ptr and bound; and the **EC rows**, including `EcCreate` / PAI under
//! `[CurvePrecompile::id(), VALUE_OP_ID, group_ptr, 0]`, EC binops, and EcMsm
//! absorb runs.
//!
//! Per active row (one node):
//!
//! - **internal node** (`is_and = 1`): unhash `lhs||rhs` under the VM `AND` tag → `h`; consume
//!   `Binding(lhs, True)` and `Binding(rhs, True)`; provide `Binding(h, True)` with multiplicity
//!   `out_mult` = number of parents.
//! - **root** (first row): same unhash + consumes, but `out_mult = 0` (no parent) ⇒ provides
//!   nothing, *absorbing* the Binding σ; its `h` is pinned to `public_root` by `when_first_row`. No
//!   separate flag is needed — `out_mult = 0` is forced by bus balance.
//! - **uint leaf** (`is_uint_leaf = 1`): unhash the uint's 4×32 value → `h` under the uint cap;
//!   consume both `UintVal` halves; provide `Binding(h, True)` when `is_pinned` (folded into the
//!   spine) else `Binding(h, Uint, ptr, bound_ptr)` (a transient value-binding).
//! - **uint op** (one of the op flags): unhash `lhs||rhs` → `h` under the VM uint op cap; consume
//!   the children's `Uint` bindings at the witnessed `a_ptr` / `b_ptr` and row `bound_ptr` (`Is`
//!   forces `b_ptr = a_ptr` — equality asserted by the bus); consume one relation tuple wiring
//!   those ptrs to the witnessed result `ptr`; provide `Binding(h, Uint, ptr, bound_ptr)` — or
//!   `Binding(h, True)` for `Is`, the predicate folding uint values into the spine. All value
//!   soundness lives at the relation chiplets + store; this row is pure ptr wiring. Ptrs never
//!   enter uint-op hashes — the result is nondeterministic, memoized on the binding.
//! - **EC create / PAI**: unhash coordinate child hashes (or zeroes for PAI) under the curve VALUE
//!   cap `[CurvePrecompile::id(), VALUE_OP_ID, group_ptr, 0]`; finite create consumes the
//!   coordinate `Uint` child bindings, both modes consume `EcPoint(point_ptr, group_ptr, x_ptr,
//!   y_ptr, is_pai)`, and both provide `Binding(h, Group, point_ptr)`.
//! - **EC MSM**: hash absorbed `(point, scalar)` child digests under `[CurvePrecompile::id(),
//!   MSM_OP_ID, 0, 0]`.
//! - **ZERO_HASH leaf** (`is_zero = 1`): no unhash, no consumes; `h = 0` pinned; provides
//!   `Binding(0, True)` with multiplicity `out_mult`. The `True` base case / AND identity, usable
//!   as any node's child.
//!
//! Bus balance: every node's `out_mult` equals its consumer count, so the
//! `Binding` σ nets to zero internally — the only external anchor is the
//! first-row `h = public_root`. An empty transcript is `is_zero = 1` on
//! the first row: `public_root = 0`, nothing provided or consumed.
//!
//! See `docs/transcript-eval.md` for the binding-bus model and
//! `docs/transcript-nodes.md` for the node formats.

pub mod trace;

use core::array;

use miden_core::{
    Felt,
    deferred::Tag,
    field::{PrimeCharacteristicRing, QuadFelt},
};
use miden_lifted_air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder};
use miden_precompiles::{CurvePrecompile, UintPrecompile};
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    ec::{
        EcPointMsg,
        add::EcGroupAddMsg,
        msm::{MsmClaimTermMsg, MsmExprMsg},
    },
    logup::{
        CyclicConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn,
        LookupGroup, NUM_RANDOMNESS, NUM_SIGMA_VALUES,
    },
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    transcript::{
        binding::{BindingMsg, ValueTag},
        nodes::UintOpId,
        poseidon2::{Poseidon2InMsg, Poseidon2OutMsg},
    },
    uint::{UintValMsg, add::UintAddMsg, mul::UintMulMsg},
    utils::{current_main, next_main},
};

// MAIN COLUMN LAYOUT
// ================================================================================================
//
// 42 main witness columns:
//
// - Structural (2): act, perm_seq_id.
// - Hashes (12): lhs[4], rhs[4], h[4].
// - Node-family and op flags.
// - Reused pointer/context cells for uint leaves/ops, EC points, and MSM runs.
// - Row-kind-aware cap parameter cells and MSM run controls.

/// Sticky-downward activity flag. Gates the consume / unhash mults; the
/// `out_mult`-pin keeps padding-row provides at zero.
pub const COL_ACT: usize = 0;
/// Foreign key into the Poseidon2 chiplet's cycle namespace for this
/// node's unhash perm. Unused on ZERO_HASH-leaf rows (no perm).
pub const COL_PERM_SEQ_ID: usize = 1;

/// First felt of the left child hash. Bus-pinned by the
/// `Binding(lhs, True)` consume and fed as `rate0` of the unhash perm.
pub const COL_LHS_BEGIN: usize = 2;
/// Number of field elements in each Poseidon2 digest / transcript node hash.
pub const DIGEST_WIDTH: usize = 4;
pub const COL_LHS_END: usize = COL_LHS_BEGIN + DIGEST_WIDTH;

/// First felt of the right child hash. Bus-pinned by the
/// `Binding(rhs, True)` consume and fed as `rate1` of the unhash perm.
pub const COL_RHS_BEGIN: usize = COL_LHS_END;
pub const COL_RHS_END: usize = COL_RHS_BEGIN + DIGEST_WIDTH;

/// First felt of this node's hash. Bus-pinned by `Poseidon2Out` on
/// internal / root rows; pinned to `0` on ZERO_HASH leaves; pinned to
/// `public_root` on the first (root) row.
pub const COL_H_BEGIN: usize = COL_RHS_END;
pub const COL_H_END: usize = COL_H_BEGIN + DIGEST_WIDTH;

/// ZERO_HASH-leaf flag. When 1: `h = 0` (pinned), no unhash, no child
/// consumes — the row provides `Binding(0, True)` only. Boolean.
pub const COL_IS_ZERO: usize = COL_H_END;
/// Provide multiplicity for this node's `Binding(h, True)` = number of
/// parents that consume it (DAG sharing / dedup, mirroring
/// `KeccakNodeAir`'s `out_mult`). A plain count pinned to the
/// consumer count by `Binding` bus balance — not range-checked (see
/// `docs/lookup-argument.md`); `0` on the root (no parent) and on
/// inactive rows.
pub const COL_OUT_MULT: usize = COL_IS_ZERO + 1;

// ================================================================
// Node-family one-hot — exactly one column set per active row,
// summing to `act`. The two *op* families (uint, EC) carry only a
// family bit here; *which* op rides the shared op one-hot below.
// Terminals (zero / and / leaf / create / pai) carry no op.
// ================================================================

/// AND-node flag — this row folds two child `True` bindings.
pub const COL_IS_AND: usize = COL_OUT_MULT + 1;
/// Uint-leaf flag — this row hashes a stored uint's value (pulled over
/// `UintVal`) instead of folding two child bindings; the `is_pinned`
/// fork picks True (pinned → spine) vs Uint (transient).
pub const COL_IS_UINT_LEAF: usize = COL_IS_AND + 1;
/// Uint-op family flag — set on every uint arithmetic / equality node
/// (add/sub/mul/is). The op itself rides the shared op one-hot; this bit
/// gates the `UintAdd`/`UintMul` wiring and, id-weighted against the op
/// flags, materializes the cap's `tag_arg0`.
pub const COL_IS_UINT_OP: usize = COL_IS_UINT_LEAF + 1;
/// EcCreate flag (finite) — hashes two uint coords `(x, y)` into a curve
/// point under the VM curve VALUE cap.
pub const COL_IS_EC_CREATE: usize = COL_IS_UINT_OP + 1;
/// EcCreate/PAI flag (the ∞ mode) — binds the group's point-at-infinity
/// (no coord children). A distinct family bit from finite create so the
/// `EcPoint` consume's `is_pai` field is degree-1.
pub const COL_IS_EC_PAI: usize = COL_IS_EC_CREATE + 1;
/// EcBinOp family flag — set on every EC binary node (add/sub/is).
/// Like the uint-op bit it gates the `EcGroupAdd` wiring while the op rides
/// the shared one-hot below; the two op families are mutually exclusive, so
/// those flags are shared.
pub const COL_IS_EC_OP: usize = COL_IS_EC_PAI + 1;

// ================================================================
// Shared op one-hot — the operation on a uint-op OR ec-op row. The two
// op families never coexist, so one set of columns serves both (the
// flag-column analogue of the reused ptr columns below). Sums to
// `is_uint_op + is_ec_op`. `is_mul` is uint-only (EC has no multiply).
// Op ids differ per family (uint Is=4, EC Is=3), so the cap op id is the
// family-gated id-weighted sum — see `tag_arg0`.
// ================================================================

/// `Add` — `r = a + b` (uint) / `R = P + Q` (EC).
pub const COL_IS_ADD: usize = COL_IS_EC_OP + 1;
/// `Sub` — the rearranged add `b + r = a` (uint) / `R + Q = P` (EC).
pub const COL_IS_SUB: usize = COL_IS_ADD + 1;
/// `Mul` — `r = a · b` (uint only).
pub const COL_IS_MUL: usize = COL_IS_SUB + 1;
/// `Is` — equality predicate, binds `True` (both families).
pub const COL_IS_IS: usize = COL_IS_MUL + 1;

// ================================================================
// Modifiers + reused data columns. These cells are deliberately role-polymorphic:
// ptr = leaf uint / op result / created-or-result point / MSM boundary value;
// bound_ptr = uint modulus / create coord modulus / MSM scalar bound;
// a_ptr / b_ptr = operands / create coords / MSM base+scalar ptrs;
// tag_arg0 / tag_arg1 = physical VM tag args; ec_context_group_ptr = EC op/MSM group.
//
// Note the physical order: tag_arg1 appears before tag_arg0 because it reuses the
// heavily shared bound/pin/create-group slot.
//
// Row-kind map for the polymorphic data cells:
// - uint VALUE:       ptr=value, bound_ptr=modulus, tag_arg1=bound_ptr.
// - uint PIN claim:   ptr=pin,   bound_ptr=modulus, tag_arg0=bound_ptr, tag_arg1=pin.
// - uint/EC op:       ptr=result, a_ptr/b_ptr=operands, tag_arg0=op_id.
// - EcCreate / PAI:   ptr=point, bound_ptr=coord modulus, a_ptr/b_ptr=x/y, tag_arg1=group; PAI
//   zeros bound/x/y.
// - EcMsm absorb:     a_ptr=base, b_ptr=scalar, bound_ptr=scalar bound, ec_context_group_ptr=group;
//   the boundary also sets ptr=value.
// ================================================================

/// Pin-claim flag for a uint leaf row: 1 = explicit pin claim, 0 = runtime
/// VM value row. Locally gates the True / Uint binding fork.
pub const COL_IS_PINNED: usize = COL_IS_IS + 1;
/// The pointer the row's binding carries: stored uint on uint-leaf rows,
/// value-op result ptr, created / result point ptr, or the EcMsm boundary's
/// value point. `Is` rows set this to 0 because they bind `True`, not a value.
pub const COL_PTR: usize = COL_IS_PINNED + 1;
/// The bound pointer read by `Uint`-typed bus messages: uint modulus on
/// uint-leaf / uint-op rows, coordinate-field modulus on finite EcCreate rows,
/// and scalar-field bound on EcMsm absorb rows. VM uint value caps also commit
/// it in tag argument 1.
pub const COL_BOUND_PTR: usize = COL_PTR + 1;
/// Physical tag argument 1 (`Tag::args()[1]`, capacity word 2). Runtime uint
/// VALUE rows put `bound_ptr` here, explicit pin rows put `pin_ptr = ptr`, and
/// EcCreate / PAI rows put the curve `group_ptr` here.
pub const COL_TAG_ARG1: usize = COL_BOUND_PTR + 1;
/// The lhs-style ptr: uint / EC op lhs operand, finite EcCreate x-coordinate,
/// or EcMsm absorb base point. On `Is` rows `b_ptr = a_ptr` *is* the equality.
pub const COL_A_PTR: usize = COL_TAG_ARG1 + 1;
/// The rhs-style ptr: binary-op rhs operand, finite EcCreate y-coordinate, or
/// EcMsm absorb scalar. It is 0 on non-op rows and PAI rows.
pub const COL_B_PTR: usize = COL_A_PTR + 1;
/// Physical tag argument 0 (`Tag::args()[0]`, capacity word 1). Explicit pin
/// rows put `bound_ptr` here, op rows put the op id here, and runtime VM uint
/// VALUE / EcCreate / PAI rows use `VALUE_OP_ID = 0`.
pub const COL_TAG_ARG0: usize = COL_B_PTR + 1;
/// Witnessed EC-store group handle for EC value-producing binops and EcMsm
/// absorb runs. Create / PAI rows commit their group selector through
/// [`COL_TAG_ARG1`], so the hash cap and `EcPoint` consume share one physical
/// cell.
pub const COL_EC_CONTEXT_GROUP_PTR: usize = COL_TAG_ARG0 + 1;

// ================================================================
// ROW-KIND ALIASES — semantic names for reused physical columns. Use these
// where the row family is already known (trace row writers and row-specific
// relation messages); use the physical COL_* names in generic constraints.
// ================================================================

/// Runtime VM uint VALUE row: `bound_ptr` committed in tag argument 1.
pub const COL_UINT_VALUE_BOUND_PTR: usize = COL_TAG_ARG1;
/// Explicit pin-claim row: `bound_ptr` committed in tag argument 0.
pub const COL_PIN_CLAIM_BOUND_PTR: usize = COL_TAG_ARG0;
/// Explicit pin-claim row: `pin_ptr = ptr` committed in tag argument 1.
pub const COL_PIN_CLAIM_PIN_PTR: usize = COL_TAG_ARG1;
/// EcCreate / PAI row: created point pointer.
pub const COL_EC_CREATE_POINT_PTR: usize = COL_PTR;
/// EcCreate / PAI row: curve group selector committed in the VALUE tag and
/// consumed by `EcPoint`.
pub const COL_EC_CREATE_GROUP_PTR: usize = COL_TAG_ARG1;
/// Finite EcCreate row: coordinate-field modulus for x/y child bindings.
pub const COL_EC_CREATE_COORD_BOUND_PTR: usize = COL_BOUND_PTR;
/// Finite EcCreate row: x-coordinate uint pointer.
pub const COL_EC_CREATE_X_PTR: usize = COL_A_PTR;
/// Finite EcCreate row: y-coordinate uint pointer.
pub const COL_EC_CREATE_Y_PTR: usize = COL_B_PTR;

// ================================================================
// EcMsm node (tag 8) — the chip's only *multi-row* node: a run of
// `is_ec_msm` absorb rows (one per claim term), the last marked
// `is_msm_last` (the boundary). Reuses lhs/rhs = (Pᵢ.hash, sᵢ.hash),
// h = this term's Poseidon2 rate0 output, a_ptr/b_ptr = (Pᵢ_ptr, sᵢ_ptr),
// ptr = val_ptr (the claim's value point), group_ptr = the group, bound_ptr =
// the scalar bound. The run is one contiguous VM-style Poseidon2 absorption span
// (`docs/chiplets/ec-msm.md §6.2`): see [`COL_MSM_IS_HEAD`].
// ================================================================

/// EcMsm family flag — set on every absorb row of an MSM-claim run. In
/// the activity one-hot like the other families; the perm rate is
/// `(Pᵢ.hash, sᵢ.hash)`.
pub const COL_IS_EC_MSM: usize = COL_EC_CONTEXT_GROUP_PTR + 1;
/// Marks the run's last absorb (the boundary): `h = h_claim`, it consumes
/// `MsmExpr` and provides the claim's `Group` binding. A 1-term claim has
/// `is_msm_last = 1` on its single row.
pub const COL_IS_MSM_LAST: usize = COL_IS_EC_MSM + 1;
/// The absorb's **position counter** (0 on a run's first row, +1 each row,
/// pinned by the main AIR). The boundary's `k = idx + 1` is the claim's
/// term count (`MsmExpr`). It is *not* a chiplet term tag — the seam
/// matches the positionless `MsmClaimTerm` as a set — so the absorb order
/// (hence the root) is the caller's, decoupled from the chiplet's storage
/// order.
pub const COL_MSM_IDX: usize = COL_IS_MSM_LAST + 1;
/// The claim expression's `expr_ptr` in the EcMsm chiplet — the
/// `MsmClaimTerm` / `MsmExpr` consume key tying the absorb run to the
/// symbolic MSM expression. **Pinned constant within a run** (with
/// `COL_EC_CONTEXT_GROUP_PTR`) by a `continues`-gated transition constraint, so every
/// row attributes its term to the same expression the boundary binds the
/// value to — see the run-constancy constraints below.
pub const COL_MSM_EXPR: usize = COL_MSM_IDX + 1;
/// Head selector for an EcMsm absorption run. The head row consumes the VM
/// curve MSM IV; continuation rows inherit capacity inside Poseidon2.
pub const COL_MSM_IS_HEAD: usize = COL_MSM_EXPR + 1;

/// Total number of main witness columns.
pub const NUM_MAIN_COLS: usize = COL_MSM_IS_HEAD + 1;

// PUBLIC VALUES LAYOUT
// ================================================================================================
//
// `[public_root[0], …, public_root[3]]` — just the transcript's target root
// (`PUBLIC_ROOT_BEGIN = 0`).

/// Index of the first `public_root` felt. Under 0.26 the transcript root is
/// the *whole* shared public-input vector (`air_inputs`); the old `inv_n`
/// slot is gone (see `crate::logup`), so it starts at 0.
pub const PUBLIC_ROOT_BEGIN: usize = 0;
pub const PUBLIC_ROOT_END: usize = PUBLIC_ROOT_BEGIN + DIGEST_WIDTH;
/// Total public-values count: the 4-felt `public_root`. Equals
/// `logup::NUM_PUBLIC_VALUES` — the shared count every AIR agrees on.
pub const NUM_PUBLIC_VALUES: usize = PUBLIC_ROOT_END;

// AUX LAYOUT
// ================================================================================================
//
// Nine aux columns:
//
// - col 0: Binding bus, True path — consume `lhs`, consume `rhs` (AND rows), and provide `h` as
//   `True` (AND / zero / `Is` rows).
// - col 1: the unhash Poseidon2 perm's static-cap path — `In{rate0, rate1, cap}` + `Out` (4
//   fractions). EcMsm's threaded cap rides col 7.
// - col 2: Binding bus, value path — consume both `UintVal` halves on uint-leaf rows (the 4×32 view
//   is the perm rate) + provide the row's value binding (uint-leaf and value-op rows), `(1 −
//   is_pinned)`-scaled so a pinned leaf collapses to the `True` form.
// - col 3: Binding bus, op-children path — consume the lhs / rhs `Uint` bindings at `a_ptr` /
//   `b_ptr`.
// - col 4: the uint relation consumes — one `UintAdd` (add / sub, roles wired per-op) + one
//   `UintMul` (mul; κ slots are the constants 1 / 0).
// - col 5: Binding bus, Group path — consume the P / Q operand `Group` bindings (group add / sub /
//   is) + provide the created / result / MSM boundary point's `Group` binding.
// - col 6: the EC relation consumes — `EcPoint` (create / PAI) and `EcGroupAdd` (group add / sub);
//   raw degree-1 fields for `EcPoint`, role-mixed fields for `EcGroupAdd`.
// - col 7: the EcMsm head Poseidon2 cap fraction.
// - col 8: the EcMsm absorb-run consumes. Per absorb row: `Binding(Pᵢ.hash, Group, Pᵢ_ptr)`,
//   `Binding(sᵢ.hash, Uint, sᵢ_ptr)`, `MsmClaimTerm(expr, Pᵢ_ptr, sᵢ_ptr)`; at the boundary,
//   `MsmExpr(expr, group, val, k = idx + 1)`.
//
// The uniform one-hot keeps every bus mult ≤ degree-2; cols 0/1/2/5/8 top
// out at constraint deg 5 (cols 3/4/6 lower, col 7 trivial), so
// `log_quotient_degree` stays 2 — width, not blowup.

pub const NUM_AUX_COLS: usize = 9;
const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [3, 4, 3, 2, 2, 3, 2, 1, 4];

// AIR
// ================================================================================================

/// Transcript eval chiplet AIR. Period 1.
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

// LIFTED AIR — local constraints
// ================================================================================================

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
        let h: [AB::Expr; DIGEST_WIDTH] = array::from_fn(|i| local[COL_H_BEGIN + i].into());

        let public_root: [AB::Expr; DIGEST_WIDTH] =
            array::from_fn(|i| builder.public_values()[PUBLIC_ROOT_BEGIN + i].into());

        // Activity: binary, sticky-downward.
        builder.assert_bool(local[COL_ACT]);
        builder.when_transition().assert_zero((AB::Expr::ONE - act.clone()) * act_next);

        // ZERO_HASH leaf: boolean flag, and `h = 0` when set (so a prover
        // can't shortcut a non-zero hash to the `True` base case).
        builder.assert_bool(local[COL_IS_ZERO]);
        for h_i in &h {
            builder.assert_zero(is_zero.clone() * h_i.clone());
        }

        // Root pin: the first row is the root; its `h` is the public
        // transcript root. (Empty transcript: row 0 is a ZERO_HASH leaf,
        // so `h = 0` forces `public_root = 0`.)
        for i in 0..DIGEST_WIDTH {
            builder.when_first_row().assert_zero(h[i].clone() - public_root[i].clone());
        }

        // Inactive rows provide nothing: pin `out_mult = 0` so the
        // `Binding(h, True)` provide (mult `−out_mult`) contributes 0 on
        // padding. (The root's `out_mult = 0` is not pinned here — it is
        // forced by bus balance: the root has no consumer.)
        builder.assert_zero((AB::Expr::ONE - act.clone()) * out_mult);

        // Node type is a uniform one-hot over the active row: exactly one
        // of is_and / is_zero / is_uint_leaf / an op family, none on
        // padding — their sum is `act`. Booleans + this sum give mutual
        // exclusion and keep every bus gate degree-1.
        // Node family is a one-hot over the active row: exactly one of
        // is_and / is_zero / is_uint_leaf / is_uint_op / is_ec_create /
        // is_ec_pai / is_ec_op (none on padding) — their sum is `act`. The
        // two *op* families carry only a family bit; which operation rides
        // the shared op one-hot below.
        let is_and: AB::Expr = local[COL_IS_AND].into();
        let is_uint_leaf: AB::Expr = local[COL_IS_UINT_LEAF].into();
        let is_uint_op: AB::Expr = local[COL_IS_UINT_OP].into();
        let is_ec_create: AB::Expr = local[COL_IS_EC_CREATE].into();
        let is_ec_pai: AB::Expr = local[COL_IS_EC_PAI].into();
        let is_ec_op: AB::Expr = local[COL_IS_EC_OP].into();
        // EcMsm: the family bit (every absorb row) + the boundary (last
        // absorb). is_msm_last is a sub-flag, not in the activity one-hot.
        let is_ec_msm: AB::Expr = local[COL_IS_EC_MSM].into();
        let is_msm_last: AB::Expr = local[COL_IS_MSM_LAST].into();
        let is_pinned: AB::Expr = local[COL_IS_PINNED].into();
        for col in [
            COL_IS_AND,
            COL_IS_UINT_LEAF,
            COL_IS_UINT_OP,
            COL_IS_EC_CREATE,
            COL_IS_EC_PAI,
            COL_IS_EC_OP,
            COL_IS_EC_MSM,
            COL_IS_MSM_LAST,
            COL_IS_PINNED,
        ] {
            builder.assert_bool(local[col]);
        }
        // The boundary is an absorb row.
        builder.assert_zero(is_msm_last.clone() * (AB::Expr::ONE - is_ec_msm.clone()));
        // Shared op one-hot: the operation on a uint-op OR ec-op row (the two
        // op families never coexist, so the columns serve both).
        let is_add: AB::Expr = local[COL_IS_ADD].into();
        let is_sub: AB::Expr = local[COL_IS_SUB].into();
        let is_mul: AB::Expr = local[COL_IS_MUL].into();
        let is_is: AB::Expr = local[COL_IS_IS].into();
        for col in [COL_IS_ADD, COL_IS_SUB, COL_IS_MUL, COL_IS_IS] {
            builder.assert_bool(local[col]);
        }
        let is_op = is_add.clone() + is_sub.clone() + is_mul.clone() + is_is.clone();
        // The op one-hot sums to "this is an op row" = is_uint_op + is_ec_op,
        // so a set op flag forces exactly one op family (and conversely).
        builder.assert_zero(is_op.clone() - is_uint_op.clone() - is_ec_op.clone());
        // EC has no multiply — is_mul only ever rides a uint-op row.
        builder.assert_zero(is_ec_op.clone() * is_mul.clone());

        // Row 0 is the public transcript root and must be a True-binding node.
        // This excludes value rows and EcMsm interior absorbs, whose `h` is not
        // a public assertion digest.
        let root_truthy = is_zero.clone() + is_and.clone() + is_is.clone() + is_pinned.clone();
        builder.when_first_row().assert_zero(root_truthy - AB::Expr::ONE);

        // Both create modes (finite + PAI) carry the group in cap slot 2 and
        // consume EcPoint. They do not use COL_EC_CONTEXT_GROUP_PTR. PAI has
        // no coordinate children, so its VALUE payload is the canonical
        // `(TRUE_DIGEST, TRUE_DIGEST)` pair (zero digest in both rate halves).
        let is_create = is_ec_create.clone() + is_ec_pai.clone();
        for i in 0..DIGEST_WIDTH {
            let lhs_i: AB::Expr = local[COL_LHS_BEGIN + i].into();
            let rhs_i: AB::Expr = local[COL_RHS_BEGIN + i].into();
            builder.assert_zero(is_ec_pai.clone() * lhs_i);
            builder.assert_zero(is_ec_pai.clone() * rhs_i);
        }
        let group_ptr: AB::Expr = local[COL_EC_CONTEXT_GROUP_PTR].into();
        // Result-binding op rows (all ops but `Is`, which binds True) —
        // degree-1, since `is_is` is one shared flag pulled out of the op
        // sum; spans both families' value-producing ops.
        let is_result_op: AB::Expr = is_op.clone() - is_is.clone();
        // Activity one-hot: the eight families sum to act.
        builder.assert_zero(
            is_and
                + is_zero
                + is_uint_leaf.clone()
                + is_uint_op.clone()
                + is_ec_create.clone()
                + is_ec_pai.clone()
                + is_ec_op.clone()
                + is_ec_msm.clone()
                - act,
        );
        // is_pinned is a leaf-only flag; ptr carries a binding ptr only on
        // uint-leaf / result-op / Ec-create / Ec-pai rows; bound_ptr only
        // where a Uint-typed message reads it (leaf / uint-op / finite create)
        // or on EcMsm scalar consumes — zero elsewhere, so an AND node's cap
        // stays [1, 0, 0, 0].
        let not_uint_leaf: AB::Expr = AB::Expr::ONE - is_uint_leaf.clone();
        let ptr: AB::Expr = local[COL_PTR].into();
        let bound_ptr: AB::Expr = local[COL_BOUND_PTR].into();
        builder.assert_zero(not_uint_leaf.clone() * is_pinned.clone());
        // ptr also carries the claim's value point on an EcMsm boundary row
        // (the Group binding provide / MsmExpr consume); 0 on the run's
        // earlier absorbs.
        builder.assert_zero(
            (not_uint_leaf.clone()
                - is_result_op
                - is_ec_create.clone()
                - is_ec_pai
                - is_msm_last.clone())
                * ptr.clone(),
        );
        // bound_ptr also carries the scalar bound on every EcMsm absorb row
        // (the sᵢ `Uint` binding consume).
        builder.assert_zero(
            (not_uint_leaf - is_uint_op.clone() - is_ec_create.clone() - is_ec_msm.clone())
                * bound_ptr.clone(),
        );
        // Materialize tag arg[1] without a deg-2 Poseidon2 cap component:
        // VM uint value rows use `bound_ptr`, explicit pin rows use `ptr`, and
        // EcCreate / PAI rows use this physical cell as the VALUE tag's `group_ptr`.
        // On create rows the `EcPoint` consume reads the same cell, tying the
        // hashed group selector to the point's group with no extra constraint.
        let tag_arg1: AB::Expr = local[COL_TAG_ARG1].into();
        let expected_tag_arg1 =
            is_uint_leaf * bound_ptr.clone() + is_pinned.clone() * (ptr - bound_ptr.clone());
        builder.assert_zero((AB::Expr::ONE - is_create) * (tag_arg1 - expected_tag_arg1));

        // Op operand ptrs: a_ptr and b_ptr on any op row (both families) or
        // finite EcCreate. On `Is` (either family) b_ptr = a_ptr *is* the equality.
        // a_ptr / b_ptr also carry the absorb's (Pᵢ_ptr, sᵢ_ptr) on EcMsm
        // rows — the MsmTerm base/scalar and the child binding consumes.
        let a_ptr: AB::Expr = local[COL_A_PTR].into();
        let b_ptr: AB::Expr = local[COL_B_PTR].into();
        builder.assert_zero(
            (AB::Expr::ONE - is_op.clone() - is_ec_create.clone() - is_ec_msm.clone())
                * a_ptr.clone(),
        );
        builder.assert_zero(
            (AB::Expr::ONE - is_op - is_ec_create - is_ec_msm.clone()) * b_ptr.clone(),
        );
        builder.assert_zero(is_is.clone() * (b_ptr - a_ptr));

        // Materialize tag arg[0] / cap slot 1: explicit pin rows use
        // `bound_ptr`, runtime VM uint value and EcCreate rows use
        // `VALUE_OP_ID = 0`, and op rows use their family op id.
        let tag_arg0: AB::Expr = local[COL_TAG_ARG0].into();
        let uint_op_id: AB::Expr = is_add.clone()
            + is_sub.clone() * AB::Expr::from(Felt::from(UintOpId::Sub as u8))
            + is_mul * AB::Expr::from(Felt::from(UintOpId::Mul as u8))
            + is_is.clone() * AB::Expr::from(Felt::from(UintOpId::Is as u8));
        let ec_op_id: AB::Expr = is_add
            * AB::Expr::from(Felt::from_u32(CurvePrecompile::ADD_OP_ID as u32))
            + is_sub * AB::Expr::from(Felt::from_u32(CurvePrecompile::SUB_OP_ID as u32))
            + is_is.clone() * AB::Expr::from(Felt::from_u32(CurvePrecompile::EQ_OP_ID as u32));
        let expected_tag_arg0 =
            is_pinned * bound_ptr + is_uint_op * uint_op_id + is_ec_op.clone() * ec_op_id;
        builder.assert_zero(tag_arg0 - expected_tag_arg0);

        // group_ptr: the witnessed EC-store handle for result-binding ec ops
        // (add/sub, not Is) and EcMsm absorb runs. Create / PAI rows use the
        // VALUE tag `[CurvePrecompile::id(), VALUE_OP_ID, group_ptr, 0]`, with
        // that group selector carried in COL_EC_CREATE_GROUP_PTR (the physical
        // COL_TAG_ARG1 cell) so the hash cap and EcPoint consume share one cell.
        // For EcMsm, group_ptr is not in the public IV; it remains live as the
        // boundary's MsmExpr / Group-binding context on every absorb row.
        builder.assert_zero(
            (AB::Expr::ONE - is_ec_op * (AB::Expr::ONE - is_is) - is_ec_msm.clone()) * group_ptr,
        );

        // ---- EcMsm absorption run: head consumes IV cap, continuations are
        //      private Poseidon2 `is_absorb` cycles, tail consumes `OutRate0`.
        let is_ec_msm_next: AB::Expr = next[COL_IS_EC_MSM].into();
        let is_msm_head: AB::Expr = local[COL_MSM_IS_HEAD].into();
        let is_msm_head_next: AB::Expr = next[COL_MSM_IS_HEAD].into();
        builder.assert_bool(local[COL_MSM_IS_HEAD]);
        builder.assert_zero(is_msm_head.clone() * (AB::Expr::ONE - is_ec_msm.clone()));

        let continues = is_ec_msm.clone() * (AB::Expr::ONE - is_msm_last.clone());
        let starts = is_ec_msm_next.clone() * (AB::Expr::ONE - is_ec_msm.clone() + is_msm_last);
        builder
            .when_first_row()
            .assert_zero(is_ec_msm.clone() * (is_msm_head - AB::Expr::ONE));
        builder
            .when_transition()
            .assert_zero(continues.clone() * (AB::Expr::ONE - is_ec_msm_next));
        builder
            .when_transition()
            .assert_zero(continues.clone() * is_msm_head_next.clone());
        builder
            .when_transition()
            .assert_zero(starts.clone() * (is_msm_head_next - AB::Expr::ONE));

        let perm_seq_id_local_for_msm: AB::Expr = local[COL_PERM_SEQ_ID].into();
        let perm_seq_id_next_for_msm: AB::Expr = next[COL_PERM_SEQ_ID].into();
        builder.when_transition().assert_zero(
            continues.clone()
                * (perm_seq_id_next_for_msm - perm_seq_id_local_for_msm - AB::Expr::ONE),
        );

        // `msm_idx` is a pure **position counter** within an absorb run (0 at
        // the run start, +1 per continuation), so the boundary's `k =
        // msm_idx + 1` (consumed in `MsmExpr`) is the term count regardless of
        // which terms the run absorbed. The seam matches the *positionless*
        // `MsmClaimTerm`, so the absorb order (hence the root) is the caller's,
        // decoupled from the chiplet's `idx`.
        let msm_idx: AB::Expr = local[COL_MSM_IDX].into();
        let msm_idx_next: AB::Expr = next[COL_MSM_IDX].into();
        builder.when_first_row().assert_zero(is_ec_msm * msm_idx.clone());
        builder.when_transition().assert_zero(starts * msm_idx_next.clone());
        builder
            .when_transition()
            .assert_zero(continues.clone() * (msm_idx_next - msm_idx - AB::Expr::ONE));

        // The claim `expr_ptr` (and its `group_ptr`) are **constant across an
        // absorb run**: every row of a claim names the same expression. This
        // is load-bearing, not cosmetic — each absorb row attributes its term
        // via `MsmClaimTerm(msm_expr, …)`, while the boundary binds the node's
        // value and witnessed group via `MsmExpr(msm_expr, group, val, k)`. If
        // `msm_expr` could vary mid-run a prover could hash one expression's
        // terms (a correct, root-matching hash) while binding the node to
        // *another* expression's value — a forged value under a correct hash,
        // which root-comparison cannot catch. Holding `group_ptr` constant
        // aligns the boundary `MsmExpr` with the whole run.
        let msm_expr: AB::Expr = local[COL_MSM_EXPR].into();
        let msm_expr_next: AB::Expr = next[COL_MSM_EXPR].into();
        let group_local: AB::Expr = local[COL_EC_CONTEXT_GROUP_PTR].into();
        let group_next_const: AB::Expr = next[COL_EC_CONTEXT_GROUP_PTR].into();
        builder
            .when_transition()
            .assert_zero(continues.clone() * (msm_expr_next - msm_expr));
        builder
            .when_transition()
            .assert_zero(continues * (group_next_const - group_local));

        // Phase 2: LogUp argument via the LogUp adapter.
        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

// LOOKUP AIR — bus interactions
// ================================================================================================

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
        let is_pinned: LB::Expr = local[COL_IS_PINNED].into();
        let is_add: LB::Expr = local[COL_IS_ADD].into();
        let is_sub: LB::Expr = local[COL_IS_SUB].into();
        let is_mul: LB::Expr = local[COL_IS_MUL].into();
        let is_is: LB::Expr = local[COL_IS_IS].into();
        let perm_seq_id: LB::Expr = local[COL_PERM_SEQ_ID].into();
        let out_mult: LB::Expr = local[COL_OUT_MULT].into();
        let ptr: LB::Expr = local[COL_PTR].into();
        let bound_ptr: LB::Expr = local[COL_BOUND_PTR].into();
        let tag_arg1: LB::Expr = local[COL_TAG_ARG1].into();
        let a_ptr: LB::Expr = local[COL_A_PTR].into();
        let b_ptr: LB::Expr = local[COL_B_PTR].into();
        let tag_arg0: LB::Expr = local[COL_TAG_ARG0].into();
        let is_uint_op: LB::Expr = local[COL_IS_UINT_OP].into();
        let is_ec_create: LB::Expr = local[COL_IS_EC_CREATE].into();
        let is_ec_pai: LB::Expr = local[COL_IS_EC_PAI].into();
        let is_ec_op: LB::Expr = local[COL_IS_EC_OP].into();
        let is_create = is_ec_create.clone() + is_ec_pai;
        // EcMsm: the family bit feeds the perm rate; the head flag feeds the
        // IV cap. Boundary/idx/expr fields are re-read for the MSM column.
        let is_ec_msm: LB::Expr = local[COL_IS_EC_MSM].into();

        let lhs: [LB::Expr; DIGEST_WIDTH] = array::from_fn(|i| local[COL_LHS_BEGIN + i].into());
        let rhs: [LB::Expr; DIGEST_WIDTH] = array::from_fn(|i| local[COL_RHS_BEGIN + i].into());
        let h: [LB::Expr; DIGEST_WIDTH] = array::from_fn(|i| local[COL_H_BEGIN + i].into());

        // Uint value ops (bind Uint, not True). Shared `is_is` spans both
        // families, so gate to uint — degree-2, within col 2's budget.
        let is_value_op: LB::Expr = is_uint_op.clone() * (LB::Expr::ONE - is_is.clone());
        // Node-type gates: the perm fires on every hashing node (AND ∪
        // uint-leaf ∪ uint-op ∪ create ∪ ec-op ∪ EcMsm); the AND child
        // consumes on is_and; uint-op child consumes fire on the family bit.
        let node: LB::Expr = is_and.clone()
            + is_uint_leaf.clone()
            + is_uint_op.clone()
            + is_create.clone()
            + is_ec_op.clone()
            + is_ec_msm.clone();
        let and_gate: LB::Expr = is_and.clone();
        let op_lhs_gate: LB::Expr = is_uint_op.clone();
        let op_rhs_gate: LB::Expr = is_uint_op.clone();
        // Provide multiplicity `−out_mult` (supply), split between the True
        // provide (AND ∪ ZERO ∪ Is — either family, col 0) and the Uint
        // provide (uint-leaf ∪ uint value op, col 2); `out_mult = 0` on the
        // root and padding ⇒ provide nothing.
        let neg_out_mult: LB::Expr = LB::Expr::ZERO - out_mult;
        let and_provide: LB::Expr =
            neg_out_mult.clone() * (is_and.clone() + is_zero + is_is.clone());
        let uint_gate: LB::Expr = is_uint_leaf.clone();
        let uint_provide: LB::Expr = neg_out_mult * (is_uint_leaf.clone() + is_value_op);
        // Value-binding tag fork: a pinned leaf binds True (folded into the
        // spine, e.g. anchoring the modulus in the public root); a transient
        // leaf or a value op binds Uint. value_tag / ptr / bound_ptr collapse
        // to the True form (all 0) when is_pinned = 1 — and is_pinned is 0 on
        // op rows, so their fields pass through.
        let transient: LB::Expr = LB::Expr::ONE - is_pinned.clone();

        // Node-perm capacity, every slot degree-1. Runtime uint values use
        // `[UintPrecompile::id(), VALUE_OP_ID, bound_ptr, 0]`; uint ops use
        // `[UintPrecompile::id(), op_id, 0, 0]`; explicit pins use
        // `[UINT_PIN_CLAIM_TAG, bound_ptr, pin_ptr, 0]`; EcCreate / PAI rows use
        // `[CurvePrecompile::id(), VALUE_OP_ID, group_ptr, 0]`.
        let and_cap = Tag::AND.as_word();
        let static_node = is_and
            + is_uint_leaf.clone()
            + is_uint_op.clone()
            + is_create.clone()
            + is_ec_op.clone();
        let uint_precompile_id = LB::Expr::from(UintPrecompile::id());
        let curve_precompile_id = LB::Expr::from(CurvePrecompile::id());
        let pin_claim_tag =
            LB::Expr::from(Felt::from(crate::transcript::nodes::UINT_PIN_CLAIM_TAG));
        let cap = [
            and_gate.clone() * LB::Expr::from(and_cap[0])
                + (is_uint_leaf + op_lhs_gate.clone()) * uint_precompile_id.clone()
                + is_pinned * (pin_claim_tag - uint_precompile_id)
                + (is_create.clone() + is_ec_op.clone()) * curve_precompile_id,
            and_gate.clone() * LB::Expr::from(and_cap[1]) + tag_arg0,
            and_gate.clone() * LB::Expr::from(and_cap[2]) + tag_arg1,
            and_gate.clone() * LB::Expr::from(and_cap[3]),
        ];

        // Per-insert mult degrees: the one-hot gates (perm `node`, AND / op
        // consumes) are deg 1; the `−out_mult` provides are deg 2.
        let one_deg = Deg { v: 1, u: 1 };
        let two_deg = Deg { v: 2, u: 1 };
        // Per-insert message degrees beyond 1: the value provide's
        // `transient`-scaled fields and the role-mixed UintAdd consume are
        // deg 2 (denominator 2).
        let mixed_deg = Deg { v: 1, u: 2 };
        // col 0: the deg-2 True provide dominates the 3-fraction batch ⇒
        // numerator 5. col 1: all perm mults deg 1 ⇒ 4. col 2: the forked
        // Binding provide carries a deg-2 message (transient·ptr) ⇒ denom 4.
        // cols 3/4: two fractions each, raw / role-mixed fields.
        let col0_deg = Deg { v: 5, u: 4 };
        let col1_deg = Deg { v: 4, u: 4 };
        let col2_deg = Deg { v: 4, u: 4 };
        let col3_deg = Deg { v: 2, u: 2 };
        let col4_deg = Deg { v: 3, u: 3 };
        // col 5 (Group binding) mirrors col 0: two deg-1 consumes + a deg-2
        // provide. col 6 (EC relations): EcPoint (deg-1) + the role-mixed
        // EcGroupAdd (deg-2 message), like col 4.
        let col5_deg = Deg { v: 5, u: 4 };
        let col6_deg = Deg { v: 3, u: 3 };
        // col 7 (EcMsm head P2 cap): the IV cap is degree-1.
        let col7_deg = Deg { v: 1, u: 1 };

        // ---- col 0: Binding bus, True path (consume lhs/rhs on AND rows;
        //             provide h as True on AND / zero / Is rows)
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
                                    and_gate.clone(),
                                    BindingMsg::truth(lhs.clone()),
                                    one_deg,
                                );
                                b.insert(
                                    "consume-rhs",
                                    and_gate,
                                    BindingMsg::truth(rhs.clone()),
                                    one_deg,
                                );
                                b.insert(
                                    "provide-h",
                                    and_provide,
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

        // ---- col 1: unhash Poseidon2 perm (3 In + 1 Out), shared by
        //             every hashing kind; the cap forks on the tag ------
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
                                    "p2in-cap",
                                    static_node,
                                    Poseidon2InMsg::cap(perm_seq_id.clone(), cap),
                                    one_deg,
                                );
                                b.insert(
                                    "p2out",
                                    node.clone() - is_ec_msm.clone()
                                        + local[COL_IS_MSM_LAST].into(),
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

        // ---- col 2: Binding bus, value path — consume both UintVal
        //             halves on leaf rows (the 4×32 view is the perm rate)
        //             + provide the row's binding (leaf ∪ value op): True
        //             if pinned (→ spine), else Uint --------------------
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
                                    uint_gate.clone(),
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
                                    uint_gate,
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
                                    uint_provide,
                                    BindingMsg {
                                        h,
                                        value_tag: transient.clone()
                                            * LB::Expr::from(Felt::from(ValueTag::Uint as u8)),
                                        ptr: transient.clone() * ptr.clone(),
                                        bound_ptr: transient * bound_ptr.clone(),
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

        // ---- col 3: Binding bus, op-children path — consume the lhs / rhs
        //             `Uint` bindings at the witnessed a_ptr / b_ptr. Raw
        //             degree-1 fields: the op gates zero the mults off op
        //             rows, so no field scaling is needed (an `Is` row's
        //             b_ptr = a_ptr — the equality) ---------------------
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
                                    "consume-lhs-uint",
                                    op_lhs_gate.clone() + is_ec_create.clone(),
                                    BindingMsg {
                                        h: lhs,
                                        value_tag: LB::Expr::from(Felt::from(ValueTag::Uint as u8)),
                                        ptr: a_ptr.clone(),
                                        bound_ptr: bound_ptr.clone(),
                                    },
                                    one_deg,
                                );
                                b.insert(
                                    "consume-rhs-uint",
                                    op_rhs_gate + is_ec_create.clone(),
                                    BindingMsg {
                                        h: rhs,
                                        value_tag: LB::Expr::from(Felt::from(ValueTag::Uint as u8)),
                                        ptr: b_ptr.clone(),
                                        bound_ptr: bound_ptr.clone(),
                                    },
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

        // ---- col 4: the pointered relation consumes. One UintAdd serves
        //             add / sub with the roles mixed per-op (sub is the
        //             arrangement b + r = a); one UintMul serves mul with
        //             the κ slots pinned to the constants 1 / 0 and the
        //             modulus as the dummy c_ptr -------------------------
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
                                    is_uint_op.clone() * (is_add.clone() + is_sub.clone()),
                                    UintAddMsg {
                                        bound_ptr: bound_ptr.clone(),
                                        a_ptr: is_add.clone() * a_ptr.clone()
                                            + is_sub.clone() * b_ptr.clone(),
                                        b_ptr: is_add.clone() * b_ptr.clone()
                                            + is_sub.clone() * ptr.clone(),
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

        // The EC columns read their fields fresh from `local` (cheap Copy
        // reads), so the uint columns above are free to move their copies.
        let g_lhs: [LB::Expr; DIGEST_WIDTH] = array::from_fn(|i| local[COL_LHS_BEGIN + i].into());
        let g_rhs: [LB::Expr; DIGEST_WIDTH] = array::from_fn(|i| local[COL_RHS_BEGIN + i].into());
        let g_h: [LB::Expr; DIGEST_WIDTH] = array::from_fn(|i| local[COL_H_BEGIN + i].into());
        let ec_value_ptr: LB::Expr = local[COL_PTR].into();
        let ec_op_lhs_ptr: LB::Expr = local[COL_A_PTR].into();
        let ec_op_rhs_ptr: LB::Expr = local[COL_B_PTR].into();
        let create_point_ptr: LB::Expr = local[COL_EC_CREATE_POINT_PTR].into();
        let create_x_ptr: LB::Expr = local[COL_EC_CREATE_X_PTR].into();
        let create_y_ptr: LB::Expr = local[COL_EC_CREATE_Y_PTR].into();
        // Create / PAI rows commit the group selector in the curve VALUE tag;
        // EcPoint consumes the same physical cell so the hash cap and point
        // group agree.
        let create_group_ptr: LB::Expr = local[COL_EC_CREATE_GROUP_PTR].into();
        let ec_context_group_ptr: LB::Expr = local[COL_EC_CONTEXT_GROUP_PTR].into();
        let create_is_pai: LB::Expr = local[COL_IS_EC_PAI].into();
        // An EcMsm boundary binds its value point as a `Group` node — it
        // rides the same Group provide as create / result ops.
        let g_is_msm_last: LB::Expr = local[COL_IS_MSM_LAST].into();
        // EC family / op gates. The family bit gates the binding + relation
        // consumes (degree-1); a specific op is `is_ec_op · op` (degree-2),
        // used only where a gate must exclude an op. The relation *messages*
        // ride the bare op flags — the consume's family gate already pins us
        // to an ec-op row, keeping those degree-1.
        let ec_binary: LB::Expr = is_ec_op.clone();
        let ec_result: LB::Expr = is_ec_op.clone() * (LB::Expr::ONE - is_is);
        let g_out_mult: LB::Expr = local[COL_OUT_MULT].into();
        let g_neg_out_mult: LB::Expr = LB::Expr::ZERO - g_out_mult;

        // ---- col 5: Binding bus, Group path — consume the P / Q operand
        //             `Group` bindings (group add / sub / is) + provide the
        //             created / result point's `Group` binding (create ∪
        //             add/sub). `Is` binds `True` (col 0), only consuming here.
        builder.next_column(
            |col| {
                col.group(
                    "binding-group",
                    |g| {
                        g.batch(
                            "fractions",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    // Every ec op consumes its P operand binding.
                                    "consume-p",
                                    is_ec_op.clone(),
                                    BindingMsg::group(g_lhs.clone(), ec_op_lhs_ptr.clone()),
                                    one_deg,
                                );
                                b.insert(
                                    // Binary ec ops (add / sub / is) consume Q.
                                    "consume-q",
                                    ec_binary.clone(),
                                    BindingMsg::group(g_rhs.clone(), ec_op_rhs_ptr.clone()),
                                    one_deg,
                                );
                                b.insert(
                                    // Create / pai / result-binding ec ops (not Is,
                                    // which binds True) provide their result binding.
                                    "provide-group",
                                    g_neg_out_mult
                                        * (is_create.clone()
                                            + ec_result.clone()
                                            + g_is_msm_last.clone()),
                                    BindingMsg::group(g_h.clone(), ec_value_ptr.clone()),
                                    two_deg,
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

        // ---- col 6: EC relation consumes — EcPoint pins an EcCreate / PAI
        //             point to the group committed in cap slot 2, and
        //             EcGroupAdd ties an EcBinOp Add/Sub's operands and result.
        //             COL_EC_CONTEXT_GROUP_PTR is only live for the binop/MSM paths.
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
                                    "consume-ecpoint",
                                    is_create.clone(),
                                    EcPointMsg {
                                        // Finite create: (pt, group, x, y, 0).
                                        // PAI: (pai, group, 0, 0, 1). The group
                                        // is the same physical cell as cap slot 2.
                                        point_ptr: create_point_ptr.clone(),
                                        group_ptr: create_group_ptr.clone(),
                                        x_ptr: create_x_ptr.clone(),
                                        y_ptr: create_y_ptr.clone(),
                                        is_pai: create_is_pai.clone(),
                                    },
                                    one_deg,
                                );
                                b.insert(
                                    "consume-ecgroupadd",
                                    ec_result.clone(),
                                    EcGroupAddMsg {
                                        group_ptr: ec_context_group_ptr.clone(),
                                        // The consume's `ec_result` gate already pins
                                        // an add/sub row, so the slot perm rides the bare
                                        // op flags (degree-1). Add: (P, Q, R) — P + Q = R.
                                        // Sub: (R, Q, P) — R + Q = P, R (ptr) the first
                                        // operand, P (a_ptr) the result.
                                        p_ptr: is_add.clone() * ec_op_lhs_ptr.clone()
                                            + is_sub.clone() * ec_value_ptr.clone(),
                                        q_ptr: (is_add.clone() + is_sub.clone())
                                            * ec_op_rhs_ptr.clone(),
                                        r_ptr: is_add.clone() * ec_value_ptr.clone()
                                            + is_sub.clone() * ec_op_lhs_ptr.clone(),
                                    },
                                    mixed_deg,
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

        // ---- col 7: EcMsm head Poseidon2 cap. Continuation capacity is private
        //             to the P2 chiplet's absorption chain.
        let d_perm_seq_id: LB::Expr = local[COL_PERM_SEQ_ID].into();
        let d_is_msm_head: LB::Expr = local[COL_MSM_IS_HEAD].into();
        let d_msm_iv = [
            LB::Expr::from(CurvePrecompile::id()),
            LB::Expr::from(Felt::from_u32(CurvePrecompile::MSM_OP_ID as u32)),
            LB::Expr::ZERO,
            LB::Expr::ZERO,
        ];
        builder.next_column(
            |col| {
                col.group(
                    "msm-head-cap",
                    |g| {
                        g.batch(
                            "fractions",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "p2in-cap-msm-head",
                                    d_is_msm_head,
                                    Poseidon2InMsg::cap(d_perm_seq_id, d_msm_iv),
                                    one_deg,
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

        // ---- col 8: the EcMsm absorb-run consumes. Per absorb row: the
        //             `Pᵢ` `Group` binding + the `sᵢ` `Uint` binding (tying
        //             the perm rate to real child nodes) + `MsmClaimTerm(expr,
        //             Pᵢ, sᵢ)` (positionless — tying to the chiplet's term
        //             *set*, so the absorb order is the caller's). At the
        //             boundary: `MsmExpr(expr, group, val, k = idx + 1)`
        //             (every term named, the value bound). Fields re-read
        //             fresh from `local`.
        let m_msm: LB::Expr = local[COL_IS_EC_MSM].into();
        let m_last: LB::Expr = local[COL_IS_MSM_LAST].into();
        let m_lhs: [LB::Expr; DIGEST_WIDTH] = array::from_fn(|i| local[COL_LHS_BEGIN + i].into());
        let m_rhs: [LB::Expr; DIGEST_WIDTH] = array::from_fn(|i| local[COL_RHS_BEGIN + i].into());
        let m_a: LB::Expr = local[COL_A_PTR].into();
        let m_b: LB::Expr = local[COL_B_PTR].into();
        let m_bound: LB::Expr = local[COL_BOUND_PTR].into();
        let m_group: LB::Expr = local[COL_EC_CONTEXT_GROUP_PTR].into();
        let m_val: LB::Expr = local[COL_PTR].into();
        let m_idx: LB::Expr = local[COL_MSM_IDX].into();
        let m_expr: LB::Expr = local[COL_MSM_EXPR].into();
        let col8_deg = Deg { v: 5, u: 4 };
        builder.next_column(
            |col| {
                col.group(
                    "ec-msm-absorb",
                    |g| {
                        g.batch(
                            "fractions",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "consume-base-group",
                                    m_msm.clone(),
                                    BindingMsg::group(m_lhs, m_a.clone()),
                                    one_deg,
                                );
                                b.insert(
                                    "consume-scalar-uint",
                                    m_msm.clone(),
                                    BindingMsg {
                                        h: m_rhs,
                                        value_tag: LB::Expr::from(Felt::from(ValueTag::Uint as u8)),
                                        ptr: m_b.clone(),
                                        bound_ptr: m_bound,
                                    },
                                    one_deg,
                                );
                                // Positionless set match: the claim's terms,
                                // any order — so the absorb (hash) order is the
                                // caller's, not the chiplet's `idx`.
                                b.insert(
                                    "consume-msmclaimterm",
                                    m_msm,
                                    MsmClaimTermMsg {
                                        expr_ptr: m_expr.clone(),
                                        base_ptr: m_a,
                                        scalar_ptr: m_b,
                                    },
                                    one_deg,
                                );
                                b.insert(
                                    "consume-msmexpr",
                                    m_last,
                                    MsmExprMsg {
                                        expr_ptr: m_expr,
                                        group_ptr: m_group,
                                        val_ptr: m_val,
                                        k: m_idx + LB::Expr::ONE,
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
