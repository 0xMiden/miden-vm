//! Hasher controller constraints (dispatch side).
//!
//! The hasher controller records permutation requests as compact (input, output) row pairs and
//! responds to the chiplets bus. The Poseidon2 permutation AIR enforces the requested
//! permutations. The perm-link bus binds each controller pair to its permutation cycle.
//!
//! The controller active flag covers all controller rows: input, output, and padding.
//!
//! ## Sub-modules
//!
//! - [`flags`]: pure row-kind [`ControllerFlags`](flags::ControllerFlags), composed from `(s0, s1,
//!   s2)` on current and next rows. Contains no chiplet-level scope; combined with [`ChipletFlags`]
//!   at each call site.
//!
//! ## Constraint layout (narrative by operation lifetime)
//!
//! Constraints are organized in the order an operation walks through them:
//!
//! 1. **Trace skeleton** - first-row boundary, selector booleanity, adjacency/stability rules that
//!    don't depend on the operation kind. These are the trace-layout invariants.
//! 2. **Operation start** - input is_boundary booleanity and the input-to-output adjacency law that
//!    every operation hits on its first row.
//! 3. **Sponge operations** (LINEAR_HASH / 2-to-1 / HPERM) - input state pinning plus the respan
//!    capacity preservation that glues multi-batch spans.
//! 4. **Merkle operations** (MP / MV / MU) - per-level input state, cross-level transitions (index
//!    continuity, direction bit propagation, digest routing), and the MRUPDATE domain-separator
//!    progression.
//! 5. **Operation end** - output is_boundary booleanity and the HOUT / SOUT return-value
//!    constraints.
//!
//! Every constraint takes both a [`ChipletFlags`] (scope: active / transition) and a
//! [`ControllerFlags`] (row-kind: input/output/padding), combined by multiplication at each
//! gate site. With one exception - the sub-selector booleanity assertion below - no raw
//! `cols.s0 / cols.s1 / cols.s2` columns are referenced in constraint gates.

pub mod flags;

use flags::ControllerFlags;
use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::AirBuilder;

use crate::{
    ChipletCols, MidenAirBuilder,
    constraints::{
        chiplets::{columns::ControllerCols, selectors::ChipletFlags},
        utils::BoolNot,
    },
    trace::chiplets::hasher::MAX_MERKLE_INDEX_HALF,
};

// ENTRY POINT
// ================================================================================================

/// Enforce all hasher controller constraints.
///
/// Receives pre-computed [`ChipletFlags`] from `build_chiplet_selectors`. The top-level chiplet
/// selector is never referenced directly by constraint code.
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
    // `is_active * is_input = 1` forces both the controller active flag and the
    // controller-internal input selector to 1.
    // NOTE: this assumes the controller is the first chiplet section in the trace.
    // A reordering of chiplet sections would require moving this constraint.
    builder
        .when_first_row()
        .assert_one(chiplet.is_active.clone() * rows.is_input.clone());

    // --- Sub-selector booleanity ---
    // s0, s1, s2 are binary on all controller rows.
    //
    // NOTE: these are the only direct references to the raw `s0/s1/s2` columns
    // in the controller constraint body. Booleanity is inherent to the columns
    // themselves and cannot be expressed through a composed row-kind flag.
    builder
        .when(chiplet.is_active.clone())
        .assert_bools([cols.s0, cols.s1, cols.s2]);

    // --- is_boundary booleanity on all controller rows ---
    // `is_boundary = 1` marks the first row of a new operation (sponge start
    // or Merkle path level 0); `is_boundary = 0` elsewhere. Hoisted to
    // `when(is_active)` because input, output, and padding cover every controller row.
    // Padding forces it to 0 in the trace-skeleton block, while input/output rows use it as a bit.
    builder.when(chiplet.is_active.clone()).assert_bool(cols.is_boundary);

    // --- Output non-adjacency ---
    // An output row cannot be followed by another output row. Combined with the
    // input-to-output adjacency law below, this guarantees strictly alternating
    // (input, output) pairs for every operation.
    //
    // Gated on `is_transition` so `cols_next.*` columns are read only when the
    // next row is also a controller row.
    // Degree: is_transition(3) * is_output(2) * is_output_next(2) = 7.
    builder
        .when(chiplet.is_transition.clone())
        .when(rows.is_output.clone())
        .assert_zero(rows.is_output_next.clone());

    // --- Padding stability ---
    // A padding row may only be followed by another padding row or by the first
    // row outside the controller section. Gating on `chiplet.is_transition`
    // makes the constraint vanish on the last padding row.
    //
    // Asserting `is_padding_next = (1-s0')*s1' = 1` forces `s0' = 0` and `s1' = 1`.
    // Degree: is_transition(3) * is_padding(2) * is_padding_next(2) = 7.
    builder
        .when(chiplet.is_transition.clone())
        .when(rows.is_padding.clone())
        .assert_one(rows.is_padding_next.clone());

    // --- Padding confinement ---
    // is_boundary, direction_bit, and perm_id must be zero on padding rows.
    builder
        .when(chiplet.is_active.clone())
        .when(rows.is_padding.clone())
        .assert_zeros([cols.is_boundary, cols.direction_bit, cols.perm_id]);

    // =====================================================================
    // 2. OPERATION START
    //
    // The first row of every operation is a controller input row. These constraints apply to ANY
    // input row regardless of operation kind.
    // =====================================================================

    // --- No input row at the end of the controller section ---
    // An input row cannot be the last controller row. Without this, the
    // adjacency rule below would have a hole at the boundary.
    builder.when(chiplet.is_last.clone()).assert_zero(rows.is_input.clone());

    // --- No non-final output at the end of the controller section ---
    // Defensive: an output row at the boundary must be final
    // (is_boundary = 1). Without this, a non-final output (is_boundary = 0)
    // would expect a continuation input that never comes, since the next row
    // belongs to another chiplet section.
    // Degree: is_last(2) * is_output(2) * inner(1) = 5.
    builder
        .when(chiplet.is_last.clone())
        .when(rows.is_output.clone())
        .assert_one(cols.is_boundary);

    // --- Input-to-output adjacency on controller-to-controller transitions ---
    // On a controller-to-controller transition from an input row, the next row must be an output
    // row. `is_transition` guarantees that the next row is also a controller row, so
    // `cols_next.s0/s1` are binary and `(1 - s0') * (1 - s1') = 1` forces both to 0. Combined
    // with the `is_last` guard above, every controller input is followed by a controller output.
    builder
        .when(chiplet.is_transition.clone())
        .when(rows.is_input.clone())
        .assert_one(rows.is_output_next.clone());

    // --- Pair id continuity ---
    // The perm-link id is shared by the input and output row of an operation.
    builder
        .when(chiplet.is_transition.clone())
        .when(rows.is_input.clone())
        .assert_eq(cols_next.perm_id, cols.perm_id);

    // =====================================================================
    // 3. SPONGE OPERATIONS (LINEAR_HASH / 2-to-1 / HPERM)
    //
    // Sponge operations process rate data in (possibly multi-batch) spans.
    // Capacity is set once on the first input (is_boundary = 1) and carried
    // through RESPAN continuations via the preservation constraint below.
    // Sponge operations have no tree position and don't use direction_bit.
    // =====================================================================

    // --- Sponge input state ---
    // Sponge operations don't have a Merkle tree position, so `node_index = 0`,
    // and they don't use `direction_bit` at all, so it's confined to 0.
    builder
        .when(chiplet.is_active.clone())
        .when(rows.is_sponge_input.clone())
        .assert_zeros([cols.node_index, cols.direction_bit]);

    // --- Respan capacity preservation ---
    // During multi-batch linear hashing (RESPAN), each new batch overwrites the rate
    // (h0..h7) but the capacity (h8..h11) must carry over from the previous permutation
    // output. Without this, a prover could inject arbitrary capacity values on
    // continuation rows, corrupting the sponge state.
    //
    // `is_sponge_input_next` restricts this to LINEAR_HASH continuations. Merkle permutations use
    // zero logical capacity on every input. On the level-0 Merkle input row, however, the four
    // physical controller capacity columns hold the canonical-index witness; the permutation-link
    // lookup sends zeros to Poseidon2 instead. On later Merkle input rows, those columns are
    // physically constrained to zero by the Merkle input constraints below.
    //
    // The `!is_boundary_next` factor restricts this to continuations rather than new operation
    // starts, which set fresh capacity.
    // `is_transition` guarantees both rows are controller rows.
    // Degree: is_transition(3) * is_sponge_input_next(3) * !is_boundary_next(1) * diff(1) = 8.
    {
        let is_boundary_next: AB::Expr = cols_next.is_boundary.into();
        let gate = chiplet.is_transition.clone()
            * rows.is_sponge_input_next.clone()
            * is_boundary_next.not();

        let cap = cols.capacity();
        let cap_next = cols_next.capacity();

        let builder = &mut builder.when(gate);
        builder.assert_eq_arrays(cap_next, cap);
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
    //   - `idx = 2 * idx_next + direction_bit` removes one path bit from the index;
    //   - `direction_bit` is a boolean left/right selector;
    //   - after level 0, the capacity lanes are zero. Level 0 uses those columns for the
    //     canonical-index witness described below.
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
    }

    // --- Canonical Merkle index witness ---
    //
    // The index decomposition is evaluated in F_Q, where Q = 2^64 - 2^32 + 1. A reconstructed
    // 64-bit index can therefore wrap modulo Q. We first bound the path suffix after level 0.
    //
    // Let d be the path depth and b_k the direction bit at level k. Starting from the terminal
    // constraint `node_index_d = 0` and applying the decomposition backwards gives
    //
    //   x = sum_(k=1)^(d-1) 2^(k-1) * b_k,
    //
    // where x is the level-1 index. The sum is empty when d = 1. Because d <= 64, the sum
    // contains at most 63 boolean bits and, read over the integers, stays below 2^63 < Q. This
    // part of the reconstruction therefore cannot wrap, and x is an ordinary integer with
    // 0 <= x < 2^63. Three parts of the AIR establish this bound. This module enforces
    // decomposition, bit booleanity, continuity, and the terminal zero on HOUT rows. The stack
    // AIR bounds d to [1, 64]. Finally, the stack/hasher lookup addresses bind the computation
    // to exactly d levels. See the MPVERIFY, MRUPDATE, and Merkle range checks sections in
    // docs/src/design/stack/crypto_ops.md.
    //
    // The full path index is n = 2*x + b_0. It may contain 64 bits, so it still needs a
    // canonicality check. Write b = b_0 and M = (Q - 1) / 2 = 2^63 - 2^31. Since b is boolean,
    //
    //   n < Q  iff  2*x + b <= 2*M  iff  x + b <= M
    //
    // If b = 0, both bounds say x <= M. If b = 1, integrality turns
    // `2*x <= 2*M - 1` into x <= M - 1.
    //
    // The AIR proves `x + b <= M` with a non-negative slack y. Its four limbs reuse the capacity
    // columns on the level-0 input row:
    //
    //   x + b + y = M,
    //   y = y_0 + 2^16*y_1 + 2^32*y_2 + 2^48*y_3.
    //
    // The range-check bus checks every limb and also checks 2*y_3. The limb check gives
    // y_3 < 2^16, so doubling it cannot wrap in F_Q (2*y_3 < 2^17 < Q). The doubled check then
    // gives y_3 < 2^15. Therefore 0 <= y < 2^63, and recombining the limbs cannot wrap either.
    //
    // The five RangeCheck requests are split across three lookup columns:
    // chiplet_responses: y_0; wiring: y_1 and y_2; hash_kernel: y_3 and 2*y_3. All use
    // BusId::RangeCheck, so only their combined multiset matters.
    //
    // The slack equation is still checked in F_Q. However,
    //
    //   0 <= x + y + b <= 2^64 - 1 < M + Q.
    //
    // The interval above contains only one integer congruent to M modulo Q: M itself. The field
    // equation is therefore an integer equality, which gives x + b <= M and hence n < Q.
    // Conversely, every canonical n < Q has the valid slack y = M - x - b. At n = Q - 1,
    // this slack is zero.
    //
    // Gate degree: is_active(1) * is_merkle_input(3) * is_boundary(1) = 5.
    // Constraint degree: gate(5) * diff(1) = 6.
    {
        const TWO_POW_16: u64 = 1 << 16;
        const TWO_POW_32: u64 = 1 << 32;
        const TWO_POW_48: u64 = 1 << 48;
        let is_boundary: AB::Expr = cols.is_boundary.into();
        let gate = chiplet.is_active.clone() * rows.is_merkle_input.clone() * is_boundary;
        let capacity = cols.capacity();
        let slack = AB::Expr::from(capacity[0])
            + AB::Expr::from(capacity[1]) * AB::Expr::from_u64(TWO_POW_16)
            + AB::Expr::from(capacity[2]) * AB::Expr::from_u64(TWO_POW_32)
            + AB::Expr::from(capacity[3]) * AB::Expr::from_u64(TWO_POW_48);
        let index_next: AB::Expr = cols_next.node_index.into();
        let direction_bit: AB::Expr = cols.direction_bit.into();

        builder.when(gate).assert_eq(
            index_next + slack + direction_bit,
            AB::Expr::from_u64(MAX_MERKLE_INDEX_HALF),
        );
    }

    // Later Merkle input rows do not carry this witness. Their capacity columns are constrained to
    // zero, matching the state sent to the permutation AIR.
    {
        let is_boundary: AB::Expr = cols.is_boundary.into();
        let gate = chiplet.is_active.clone() * rows.is_merkle_input.clone() * is_boundary.not();
        builder.when(gate).assert_zeros(cols.capacity());
    }

    // --- Cross-step Merkle index continuity ---
    // On non-final output rows, if the next row is a Merkle input, the node
    // index must carry over: `idx_next = idx`. (The decomposition constraint
    // above shifts the index on the input row itself.)
    //
    // NOTE: `is_merkle_input_next` is read without an explicit `is_active_next`
    // gate. This is safe because `is_active` already scopes the current row to
    // the controller section, and the transition rules enforce that the next
    // row after a controller row must be another controller row. At the end of
    // the controller section, `!is_boundary` is ruled out by the boundary check above.
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
    // **Forward propagation.** On non-final output-to-next-input Merkle boundaries,
    // the `direction_bit` on the output must equal the `direction_bit` on the next
    // input row. This makes `b_{i+1}` (the next step's direction bit) available on
    // the output row so the digest can be routed to the correct rate half.
    //
    // **Digest routing.** The digest from output_i (in rate0, `h[0..4]`) must
    // appear in the correct rate half of input_{i+1}, selected by direction_bit:
    // - `direction_bit = 0`: digest goes to rate0 of input_{i+1} (`h_next[j]`)
    // - `direction_bit = 1`: digest goes to rate1 of input_{i+1} (`h_next[4+j]`)
    //
    // Uses the full `is_merkle_input_next = s0' * (s1' + s2' - s1'*s2')` (degree 3)
    // so the gate fires exclusively on genuine Merkle input continuations. This
    // sits the constraint at exactly the max degree of 9, trading 2 degrees of
    // headroom for local soundness: no bus invariant is required to reject
    // sponge-mislabeling attacks, because the `s0'` factor already forbids them.
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
        //   h[j] = b * h_next[4+j] + (1-b) * h_next[j]
        //   h[j] = h_next[j] + b * (h_next[4+j] - h_next[j])
        // where b = direction_bit on the output row.
        let b: AB::Expr = cols.direction_bit.into();
        let rate0_curr = cols.rate0();
        let rate0_next = cols_next.rate0();
        let rate1_next = cols_next.rate1();
        for j in 0..4 {
            builder.assert_eq(
                rate0_curr[j],
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
    // outputs (merkle levels, sponge batch boundaries) have is_boundary = 0.
    // =====================================================================

    // --- HOUT return digest ---
    // HOUT output rows return a 4-element digest. They have no tree position
    // (`node_index = 0`) and no direction bit (`direction_bit = 0`).
    builder
        .when(chiplet.is_active.clone())
        .when(rows.is_hout.clone())
        .assert_zeros([cols.node_index, cols.direction_bit]);

    // --- SOUT return full state (final row) ---
    // SOUT on the boundary row (final output of an HPERM) has direction_bit = 0.
    // Intermediate SOUT rows (non-boundary) are unconstrained here.
    builder
        .when(chiplet.is_active.clone())
        .when(rows.is_sout)
        .when(cols.is_boundary)
        .assert_zero(cols.direction_bit);
}
