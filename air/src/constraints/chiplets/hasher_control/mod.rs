//! Controller sub-chiplet constraints (dispatch side).
//!
//! The hasher uses a dispatch/compute split architecture: the **controller** (this module)
//! records compression requests as compact (input, output) row pairs and responds to the
//! chiplets bus; `BlakeGCompressionAir` executes the actual cycles.
//! A LogUp compression-link bus binds the two regions.
//!
//! The controller is active when `s_ctrl = chiplets[0] = 1`, which covers ALL controller
//! rows (input, output, and padding).
//!
//! ## Sub-modules
//!
//! - [`flags`]: Pure row-kind [`ControllerFlags`](flags::ControllerFlags): compositions of `(s0,
//!   s1, s2)` on current and next rows. Contains no chiplet-level scope; combined with
//!   [`ChipletFlags`] at each call site.
//!
//! ## Constraint layout (narrative by operation lifetime)
//!
//! Constraints are organized in the order an operation walks through them:
//!
//! 1. **Trace skeleton** - first-row boundary, selector booleanity, adjacency/stability rules that
//!    don't depend on the operation kind. These are the trace-layout invariants.
//! 2. **Operation start** - input is_boundary booleanity and the input -> output adjacency law that
//!    every operation hits on its first row.
//! 3. **Hash-state operations** (LINEAR_HASH / 2-to-1 / BCOMPRESS) - input state
//!    pinning plus the respan chaining-value preservation that glues multi-batch spans.
//! 4. **Merkle operations** (MP / MV / MU) - per-level input state, cross-level transitions (index
//!    continuity, direction bit propagation, digest routing), and the MRUPDATE domain-separator
//!    progression.
//! 5. **Operation end** - output is_boundary booleanity and the HOUT / SOUT return-value
//!    constraints.
//!
//! Every constraint takes both a [`ChipletFlags`] (scope: active / transition) and a
//! [`ControllerFlags`] (row-kind: input/output/...), combined by multiplication at each
//! gate site. With one exception - the sub-selector booleanity assertion below - no raw
//! `cols.s0 / cols.s1 / cols.s2` columns are referenced in constraint gates.

pub mod flags;

use flags::ControllerFlags;
use miden_core::{chiplets::blakeg, field::PrimeCharacteristicRing};
use miden_crypto::stark::air::AirBuilder;

use crate::{
    ChipletCols, MidenAirBuilder,
    constraints::{
        chiplets::{columns::ControllerCols, selectors::ChipletFlags},
        utils::BoolNot,
    },
};

// ENTRY POINT
// ================================================================================================

/// Enforce all controller sub-chiplet constraints.
///
/// Receives pre-computed [`ChipletFlags`] from `build_chiplet_selectors`. The `s_ctrl`
/// column (`chiplets[0]`) is never referenced directly by constraint code.
pub fn enforce_controller_constraints<AB>(
    builder: &mut AB,
    local: &ChipletCols<AB::Var>,
    next: &ChipletCols<AB::Var>,
    chiplet: &ChipletFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let cols: &ControllerCols<AB::Var> = local.controller();
    let cols_next: &ControllerCols<AB::Var> = next.controller();

    let rows = ControllerFlags::<AB::Expr>::new(cols, cols_next);

    // =====================================================================
    // 1. TRACE SKELETON
    //
    // Invariants on the shape of the controller section: where it starts,
    // which selectors are binary, what can follow what. These constraints
    // don't depend on which hasher operation is running.
    // =====================================================================

    // --- First-row boundary ---
    // The first row of the trace must be a controller input row: asserting
    // `is_active * is_input = 1` forces both `s_ctrl = 1` and `s0 = 1` because
    // the only solution to a product of booleans equaling 1 is all factors = 1.
    // NOTE: this assumes the controller is the first chiplet section in the trace.
    // The selector transition rules and the trace layout guarantee this, but a
    // reordering of chiplet sections would require moving this constraint.
    builder
        .when_first_row()
        .assert_one(chiplet.is_active.clone() * rows.is_input.clone());

    // --- Sub-selector booleanity ---
    // s0, s1, s2 are binary on all controller rows. On non-controller rows, these cells belong to
    // the active chiplet and are unconstrained here.
    //
    // NOTE: these are the only direct references to the raw `s0/s1/s2` columns
    // in the controller constraint body: booleanity is inherent to the columns
    // themselves and cannot be expressed through a composed row-kind flag.
    builder
        .when(chiplet.is_active.clone())
        .assert_bools([cols.s0, cols.s1, cols.s2]);

    // --- is_boundary booleanity on all controller rows ---
    // `is_boundary = 1` marks the first row of a new operation (linear-hash start or Merkle path
    // level 0); `is_boundary = 0` elsewhere. Hoisted to
    // `when(is_active)` because input, output, and padding cover every ctrl row:
    // padding forces it to 0 (section 1 below) and input/output use it as a bit.
    builder.when(chiplet.is_active.clone()).assert_bool(cols.is_boundary);

    // --- Output non-adjacency ---
    // An output row cannot be followed by another output row. Combined with the
    // input -> output adjacency law (section 2 below), this guarantees strictly alternating
    // (input, output) pairs for every operation.
    //
    // Gated on `is_transition` so `cols_next.*` columns are read only when the
    // next row is also a controller row (on perm/s0 rows, `s0/s1/s2` hold
    // unrelated data).
    // Degree: is_transition(3) * is_output(2) * is_output_next(2) = 7.
    builder
        .when(chiplet.is_transition.clone())
        .when(rows.is_output.clone())
        .assert_zero(rows.is_output_next.clone());

    // --- Padding stability ---
    // A padding row may only be followed by another padding row (or the first
    // non-controller row, which ends the controller section). Gating on
    // `chiplet.is_transition` = `is_transition * s_ctrl * s_ctrl'` makes the
    // constraint vanish on the last padding row when the next row belongs to the
    // following chiplet region.
    //
    // Asserting `is_padding_next = (1-s0')*s1' = 1` forces `s0' = 0` and `s1' = 1`.
    // Degree: is_transition(3) * is_padding(2) * is_padding_next(2) = 7.
    builder
        .when(chiplet.is_transition.clone())
        .when(rows.is_padding.clone())
        .assert_one(rows.is_padding_next.clone());

    // --- Padding confinement ---
    // is_boundary and direction_bit must be zero on padding rows.
    builder
        .when(chiplet.is_active.clone())
        .when(rows.is_padding.clone())
        .assert_zeros([cols.is_boundary, cols.direction_bit]);

    // =====================================================================
    // 2. OPERATION START
    //
    // The first row of every operation is a controller input row (s_ctrl = 1,
    // s0 = 1). These constraints apply to ANY input row regardless of
    // operation kind.
    // =====================================================================

    // --- No input row at the controller boundary ---
    // An input row cannot be the last controller row. Without this, the
    // adjacency rule below (which relies on `s_ctrl'` so that `s0'/s1'` are
    // binary on the next row) would not apply at the end of the controller region.
    // `chiplet.is_last = s_ctrl * (1 - s_ctrl')` fires exactly on that boundary.
    builder.when(chiplet.is_last.clone()).assert_zero(rows.is_input.clone());

    // --- No non-final output at the controller boundary ---
    // Defensive: an output row at the controller boundary must be final
    // (is_boundary = 1). Without this, a non-final output (is_boundary = 0)
    // would expect a continuation input that never comes, since the next row
    // belongs to another chiplet section.
    // Degree: is_last(2) * is_output(2) * inner(1) = 5.
    builder
        .when(chiplet.is_last.clone())
        .when(rows.is_output.clone())
        .assert_one(cols.is_boundary);

    // --- Input -> output adjacency on controller transitions ---
    // On a controller-to-controller transition from an input row, the next row must be an
    // output row. `is_transition` carries the `s_ctrl'` factor, so on this
    // gate `cols_next.s0/s1` are boolean and `(1 - s0')(1 - s1') = 1` really
    // does force both to 0. Combined with the `is_last` guard above, every
    // ctrl_input is followed by a ctrl_output.
    builder
        .when(chiplet.is_transition.clone())
        .when(rows.is_input.clone())
        .assert_one(rows.is_output_next.clone());

    // BlakeG preserves the 8-felt block and updates only the chaining value. The compression-link
    // lookup binds `[block, cv_in, cv_out]`; this local constraint binds the controller output
    // row's block lanes to the input row.
    {
        let gate =
            chiplet.is_transition.clone() * rows.is_input.clone() * rows.is_output_next.clone();
        let builder = &mut builder.when(gate);
        let rate0 = cols.rate0();
        let rate1 = cols.rate1();
        let rate0_next = cols_next.rate0();
        let rate1_next = cols_next.rate1();
        for i in 0..4 {
            builder.assert_eq(rate0_next[i], rate0[i]);
            builder.assert_eq(rate1_next[i], rate1[i]);
        }
    }

    // =====================================================================
    // 3. HASH-STATE OPERATIONS (LINEAR_HASH / 2-to-1 / BCOMPRESS)
    //
    // Hash-state operations process block data in possibly multi-batch spans.
    // The chaining-value lanes are set on the first input (is_boundary = 1) and carried through
    // RESPAN continuations by the preservation constraint below.
    // These operations have no tree position. Their input and response rows keep
    // `direction_bit = 0`; RESPAN continuations keep it zero as well.
    // =====================================================================

    // --- Hash input state ---
    // Hash-state operations don't have a Merkle tree position, so `node_index = 0`.
    //
    // SAFETY: `direction_bit` has two meanings, selected by disjoint row kinds:
    //   - on Merkle rows, it is the path-step direction bit;
    //   - on hash-input rows, it is reserved and constrained to zero.
    // No constraint may read it as both at once; the row-kind flags below enforce that boundary.
    builder
        .when(chiplet.is_active.clone())
        .when(rows.is_hash_input.clone())
        .assert_zero(cols.node_index);
    builder
        .when(chiplet.is_active.clone())
        .when(rows.is_hash_input.clone())
        .assert_bool(cols.direction_bit);

    // RESPAN continuations are packed linear-hash batches.
    builder
        .when(chiplet.is_active.clone())
        .when(rows.is_hash_input.clone())
        .when(Into::<AB::Expr>::into(cols.is_boundary).not())
        .assert_zero(cols.direction_bit);

    // Preserve the reserved zero bit from one-shot hash input to its response row.
    builder
        .when(chiplet.is_transition.clone())
        .when(rows.is_hash_input.clone())
        .when(rows.is_output_next.clone())
        .assert_eq(cols.direction_bit, cols_next.direction_bit);

    // --- Respan chaining-value preservation ---
    // During multi-batch linear hashing (RESPAN), each new batch overwrites the block lanes
    // (h0..h7) but the chaining-value lanes (h8..h11) must carry over from the previous
    // compression output. Without this, a prover could inject arbitrary chaining values on
    // continuation rows.
    //
    // `is_hash_input_next` restricts this to LINEAR_HASH continuations only; Merkle ops set
    // their chaining-value lanes at each level. The `!is_boundary_next` factor restricts to
    // continuations, not new operation starts.
    // `is_transition` guarantees both rows are controller rows.
    // Degree: is_transition(3) * is_hash_input_next(3) * !is_boundary_next(1) * diff(1) = 8.
    {
        let is_boundary_next: AB::Expr = cols_next.is_boundary.into();
        let gate = chiplet.is_transition.clone()
            * rows.is_hash_input_next.clone()
            * is_boundary_next.not();

        let cv = cols.capacity();
        let cv_next = cols_next.capacity();

        let builder = &mut builder.when(gate);
        for i in 0..4 {
            builder.assert_eq(cv_next[i], cv[i]);
        }
    }

    // =====================================================================
    // 4. MERKLE OPERATIONS (MP / MV / MU)
    //
    // Merkle path operations walk a 2-to-1 compression tree from leaf to root.
    // Each level is an (input, output) pair: the input holds the current node
    // plus the sibling in the correct rate half (selected by direction_bit),
    // and the output holds the compressed digest. Between levels, the digest
    // routes into the next input's rate half and the index shifts one bit.
    //
    // See [`flags::ControllerFlags`] for MP / MV / MU operation semantics.
    // MV and MU interact with the sibling table via the hash_kernel bus; the
    // shared sibling set is domain-separated by `mrupdate_id`.
    // =====================================================================

    // --- Merkle input state ---
    // On each Merkle input row:
    //   - index decomposition: `idx = 2 * idx_next + direction_bit` threads the path bits down one
    //     level at a time
    //   - direction_bit is binary (left/right child selector)
    //   - chaining-value lanes h[8..12] are fixed to the domain-0 two-to-one CV
    // Degree: is_active(1) * is_merkle_input(3) * diff(1) = 5 (on the decomp assert).
    {
        let gate = chiplet.is_active.clone() * rows.is_merkle_input.clone();
        let builder = &mut builder.when(gate);

        // idx = 2 * idx_next + direction_bit
        let node_index_next: AB::Expr = cols_next.node_index.into();
        let idx_expected = node_index_next.double() + cols.direction_bit;
        builder.assert_eq(cols.node_index, idx_expected);

        // direction_bit is binary
        builder.assert_bool(cols.direction_bit);

        // Merkle path levels always use the domain-0 two-to-one compression frame.
        let cv = blakeg::two_to_one_chaining_word(0);
        for i in 0..4 {
            builder.assert_eq(cols.capacity()[i], cv[i]);
        }
    }

    // --- Cross-step Merkle index continuity ---
    // On non-final output rows, if the next row is a Merkle input, the node
    // index must carry over: `idx_next = idx`. (The decomposition constraint
    // above shifts the index on the input row itself.)
    //
    // NOTE: `is_merkle_input_next` is read without an explicit `is_active_next`
    // gate. This is safe because `is_active` already scopes the current row to
    // the controller section, and the transition rules enforce that the next
    // row after a controller row must be either another controller row or the
    // following chiplet region.
    // Gate: is_active(1) * is_output(2) * !is_boundary(1) * is_merkle_input_next(3) = 7
    // Constraint degree: gate(7) * diff(1) = 8
    let not_boundary: AB::Expr = cols.is_boundary.into().not();
    builder
        .when(chiplet.is_active.clone())
        .when(rows.is_output.clone())
        .when(not_boundary.clone())
        .when(rows.is_merkle_input_next.clone())
        .assert_eq(cols_next.node_index, cols.node_index);

    // --- Direction bit forward propagation + digest routing ---
    //
    // **Forward propagation.** On non-final output -> next-input Merkle boundaries,
    // the `direction_bit` on the output must equal the `direction_bit` on the next
    // input row. This makes `b_{i+1}` (the next step's direction bit) available on
    // the output row so the digest can be routed to the correct rate half.
    //
    // **Digest routing.** The digest from output_i (`h[8..12]`) must
    // appear in the correct rate half of input_{i+1}, selected by direction_bit:
    // - `direction_bit = 0`: digest goes to rate0 of input_{i+1} (`h_next[j]`)
    // - `direction_bit = 1`: digest goes to rate1 of input_{i+1} (`h_next[4+j]`)
    //
    // Uses the full `is_merkle_input_next = s0' * (s1' + s2' - s1'*s2')` (degree 3)
    // so the gate fires exclusively on genuine Merkle input continuations. This
    // sits the constraint at exactly the max degree of 9, trading 2 degrees of
    // headroom for local soundness: no bus invariant is required to reject
    // hash-operation mislabeling attacks, because the `s0'` factor already forbids them.
    // Gate: is_active(1) * is_output(2) * !is_boundary(1) * is_merkle_input_next(3) = 7
    // Constraint degree: gate(7) * inner(2) = 9
    {
        let gate = chiplet.is_active.clone()
            * rows.is_output.clone()
            * not_boundary
            * rows.is_merkle_input_next.clone();
        let builder = &mut builder.when(gate);

        // Forward propagation: direction_bit on output = direction_bit on next input.
        builder.assert_eq(cols.direction_bit, cols_next.direction_bit);

        // Digest routing: for each j in 0..4, enforce
        //   digest[j] = b * h_next[4+j] + (1-b) * h_next[j]
        //   digest[j] = h_next[j] + b * (h_next[4+j] - h_next[j])
        // where b = direction_bit on the output row.
        let b: AB::Expr = cols.direction_bit.into();
        let digest_curr = cols.digest();
        let rate0_next = cols_next.rate0();
        let rate1_next = cols_next.rate1();
        for j in 0..4 {
            builder.assert_eq(
                digest_curr[j],
                rate0_next[j] + b.clone() * (rate1_next[j] - rate0_next[j]),
            );
        }
    }

    // --- MRUPDATE domain separator (mrupdate_id progression) ---
    // On controller-to-controller transitions:
    //   mrupdate_id_next = mrupdate_id + is_mv_input_next * is_boundary_next
    // i.e. the domain separator ticks forward exactly when the next row is an
    // MV boundary input (the start of an old-path MRUPDATE leg). This separates
    // sibling-table entries from different MRUPDATE operations so siblings from
    // one update can't be replayed in another.
    // Degree: is_transition(3) * (diff + is_mv_input_next(3) * bnd'(1))(4) = 7.
    let mrupdate_id: AB::Expr = cols.mrupdate_id.into();
    let mv_start_next = rows.is_mv_input_next * cols_next.is_boundary;
    builder
        .when(chiplet.is_transition.clone())
        .assert_eq(cols_next.mrupdate_id, mrupdate_id + mv_start_next);

    // =====================================================================
    // 5. OPERATION END
    //
    // Every operation ends on an output row carrying its return value: HOUT
    // returns a 4-element digest, SOUT returns the full 12-element state.
    // The final output of an operation has is_boundary = 1; intermediate
    // outputs (merkle levels, linear-hash batch boundaries) have is_boundary = 0.
    // =====================================================================

    // --- HOUT return digest ---
    // HOUT output rows return a 4-element digest. They have no tree position
    // (`node_index = 0`) and no direction bit (`direction_bit = 0`).
    builder
        .when(chiplet.is_active.clone())
        .when(rows.is_hout.clone())
        .assert_zeros([cols.node_index, cols.direction_bit]);

    // --- SOUT return full state (final row) ---
    // Boundary SOUT rows return a full state. Their direction bit is the
    // packed/raw mode bit copied from the input row.
    builder
        .when(chiplet.is_active.clone())
        .when(rows.is_sout)
        .when(cols.is_boundary)
        .assert_bool(cols.direction_bit);
}
