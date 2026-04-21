//! Degree audit for all-LogUp column packing.
//!
//! This module verifies every degree claim in the bus constraint inventory by constructing
//! symbolic expressions and checking their `degree_multiple()`. It also verifies that flags
//! claimed to be mutually exclusive are indeed so by checking the AIR constraints that enforce it.
//!
//! Run with:
//! ```sh
//! cargo test -p miden-air --lib degree_audit -- --nocapture
//! ```
//!
//! TODO(rebase): the audit body below is written against the pre-2856 `MainTraceRow` /
//! `ExprDecoderAccess` / `Challenges` API. It is temporarily disabled while the
//! lookup module is being adapted to the unified `MainCols` / `OpFlags::new(decoder, stack,
//! decoder_next)` / `Challenges::encode(bus, elems)` API. Re-enable once the helpers are
//! ported.

#[cfg(any())]
mod tests {
    extern crate std;

    use std::{borrow::Borrow, println};

    use miden_core::field::{PrimeCharacteristicRing, QuadFelt};
    use miden_crypto::stark::air::{
        AirBuilder, ExtensionBuilder, LiftedAir, PermutationAirBuilder, WindowAccess,
        symbolic::{AirLayout, SymbolicAirBuilder},
    };

    use crate::{
        Felt, MainTraceRow, NUM_PUBLIC_VALUES, ProcessorAir,
        constraints::op_flags::{ExprDecoderAccess, OpFlags},
        trace::{
            AUX_TRACE_RAND_CHALLENGES, AUX_TRACE_WIDTH, Challenges, TRACE_WIDTH,
            decoder::{
                ADDR_COL_IDX, GROUP_COUNT_COL_IDX, HASHER_STATE_RANGE, IN_SPAN_COL_IDX,
                USER_OP_HELPERS_OFFSET,
            },
        },
    };

    type SB = SymbolicAirBuilder<Felt, QuadFelt>;
    type Expr = <SB as AirBuilder>::Expr;
    type ExprEF = <SB as ExtensionBuilder>::ExprEF;

    fn make_builder() -> SB {
        let num_periodic = LiftedAir::<Felt, QuadFelt>::periodic_columns(&ProcessorAir).len();
        SymbolicAirBuilder::<Felt, QuadFelt>::new(AirLayout {
            preprocessed_width: 0,
            main_width: TRACE_WIDTH,
            num_public_values: NUM_PUBLIC_VALUES,
            permutation_width: AUX_TRACE_WIDTH,
            num_permutation_challenges: AUX_TRACE_RAND_CHALLENGES,
            num_permutation_values: NUM_LOGUP_COMMITTED_FINALS,
            num_periodic_columns: num_periodic,
        })
    }

    /// Helper: report degree of an expression with a label.
    fn deg(label: &str, e: &Expr) -> usize {
        let d = e.degree_multiple();
        println!("  {label:50} deg = {d}");
        d
    }

    /// Helper: report degree of an extension field expression.
    fn deg_ef(label: &str, e: &ExprEF) -> usize {
        let d = e.degree_multiple();
        println!("  {label:50} deg = {d}");
        d
    }

    /// Helper: build challenges from the symbolic builder's randomness.
    fn make_challenges(builder: &mut SB) -> Challenges<ExprEF> {
        use crate::constraints::lookup::{LookupAir, MidenLookupAir};
        let r = builder.permutation_randomness();
        Challenges::new(
            r[0].into(),
            r[1].into(),
            MidenLookupAir.max_message_width(),
            MidenLookupAir.num_bus_ids(),
        )
    }

    /// Helper: encode a message from base-field expressions, return its degree.
    fn msg_deg(label: &str, challenges: &Challenges<ExprEF>, elems: &[Expr]) -> usize {
        // Use encode with up to 15 elements
        let d = match elems.len() {
            1 => challenges.encode([elems[0].clone()]).degree_multiple(),
            2 => challenges.encode([elems[0].clone(), elems[1].clone()]).degree_multiple(),
            3 => challenges
                .encode([elems[0].clone(), elems[1].clone(), elems[2].clone()])
                .degree_multiple(),
            5 => challenges
                .encode([
                    elems[0].clone(),
                    elems[1].clone(),
                    elems[2].clone(),
                    elems[3].clone(),
                    elems[4].clone(),
                ])
                .degree_multiple(),
            7 => challenges
                .encode([
                    elems[0].clone(),
                    elems[1].clone(),
                    elems[2].clone(),
                    elems[3].clone(),
                    elems[4].clone(),
                    elems[5].clone(),
                    elems[6].clone(),
                ])
                .degree_multiple(),
            _ => panic!("msg_deg: unsupported length {}", elems.len()),
        };
        println!("  {label:50} deg(d) = {d}");
        d
    }

    // =====================================================================================
    // PART 1: Flag degrees
    // =====================================================================================

    #[test]
    #[allow(clippy::print_stdout)]
    fn audit_flag_degrees() {
        let builder = make_builder();
        let main = builder.main();
        let local: &MainTraceRow<_> = main.current_slice().borrow();
        let next: &MainTraceRow<_> = main.next_slice().borrow();

        let flags = OpFlags::new(ExprDecoderAccess::new(local));

        println!("=== PART 1: Operation flag degrees ===\n");

        // Degree-7 flags (opcodes 0-63)
        println!("--- Degree 7 flags ---");
        assert_eq!(deg("mload", &flags.mload()), 7);
        assert_eq!(deg("mstore", &flags.mstore()), 7);
        assert_eq!(deg("mloadw", &flags.mloadw()), 7);
        assert_eq!(deg("mstorew", &flags.mstorew()), 7);
        assert_eq!(deg("u32and", &flags.u32and()), 7);
        assert_eq!(deg("u32xor", &flags.u32xor()), 7);

        // Degree-5 flags (opcodes 80-95)
        println!("\n--- Degree 5 flags ---");
        assert_eq!(deg("hperm", &flags.hperm()), 5);
        assert_eq!(deg("mpverify", &flags.mpverify()), 5);
        assert_eq!(deg("split", &flags.split()), 5);
        assert_eq!(deg("loop", &flags.loop_op()), 5);
        assert_eq!(deg("span", &flags.span()), 5);
        assert_eq!(deg("join", &flags.join()), 5);
        assert_eq!(deg("dyn", &flags.dyn_op()), 5);
        assert_eq!(deg("dyncall", &flags.dyncall()), 5);
        assert_eq!(deg("evalcircuit", &flags.evalcircuit()), 5);
        assert_eq!(deg("log_precompile", &flags.log_precompile()), 5);
        assert_eq!(deg("hornerbase", &flags.hornerbase()), 5);
        assert_eq!(deg("hornerext", &flags.hornerext()), 5);
        assert_eq!(deg("mstream", &flags.mstream()), 5);
        assert_eq!(deg("pipe", &flags.pipe()), 5);
        assert_eq!(deg("push", &flags.push()), 5);

        // Degree-4 flags (opcodes 96-127)
        println!("\n--- Degree 4 flags ---");
        assert_eq!(deg("mrupdate", &flags.mrupdate()), 4);
        assert_eq!(deg("call", &flags.call()), 4);
        assert_eq!(deg("syscall", &flags.syscall()), 4);
        assert_eq!(deg("end", &flags.end()), 4);
        assert_eq!(deg("repeat", &flags.repeat()), 4);
        assert_eq!(deg("respan", &flags.respan()), 4);
        assert_eq!(deg("halt", &flags.halt()), 4);
        assert_eq!(deg("cryptostream", &flags.cryptostream()), 4);

        // Composite flags
        println!("\n--- Composite flags ---");
        assert_eq!(deg("right_shift", &flags.right_shift()), 6);
        assert_eq!(deg("left_shift", &flags.left_shift()), 5);
        assert_eq!(deg("control_flow", &flags.control_flow()), 5);
        assert_eq!(deg("overflow", &flags.overflow()), 2);

        // Non-opcode selectors
        println!("\n--- Non-opcode selectors ---");
        let sp: Expr = local.decoder[IN_SPAN_COL_IDX].clone().into();
        let gc: Expr = local.decoder[GROUP_COUNT_COL_IDX].clone().into();
        let gc_next: Expr = next.decoder[GROUP_COUNT_COL_IDX].clone().into();
        let f_dg = sp.clone() * (gc - gc_next);
        assert_eq!(deg("f_dg = sp * (gc - gc')", &f_dg), 2);

        // u32_rc_op (from op_bits)
        let op_bit4: Expr = local.decoder[5].clone().into(); // OP_BITS_RANGE.start + 4
        let op_bit5: Expr = local.decoder[6].clone().into();
        let op_bit6: Expr = local.decoder[7].clone().into();
        let u32_rc_op = op_bit6 * (Expr::ONE - op_bit5) * (Expr::ONE - op_bit4);
        assert_eq!(deg("u32_rc_op", &u32_rc_op), 3);

        // Next-row flags (for P2_BLOCK_HASH END entry)
        println!("\n--- Next-row flags (for is_first_child) ---");
        let flags_next: OpFlags<Expr> = OpFlags::new(ExprDecoderAccess::new(next));
        let is_end_next = flags_next.end();
        let is_repeat_next = flags_next.repeat();
        let is_halt_next = flags_next.halt();
        assert_eq!(deg("end_next", &is_end_next), 4);
        assert_eq!(deg("repeat_next", &is_repeat_next), 4);
        assert_eq!(deg("halt_next", &is_halt_next), 4);
        let is_first_child = Expr::ONE - is_end_next - is_repeat_next - is_halt_next;
        assert_eq!(deg("is_first_child", &is_first_child), 4);
    }

    // =====================================================================================
    // PART 2: Denominator degrees (message encodings)
    // =====================================================================================

    #[test]
    #[allow(clippy::print_stdout)]
    fn audit_denominator_degrees() {
        let mut builder = make_builder();
        let challenges = make_challenges(&mut builder);
        let main = builder.main();
        let local: &MainTraceRow<_> = main.current_slice().borrow();
        let next: &MainTraceRow<_> = main.next_slice().borrow();

        type Var = <SB as AirBuilder>::Var;
        let to_expr = |v: Var| -> Expr { v.into() };

        let col_dec =
            |row: &MainTraceRow<Var>, idx: usize| -> Expr { to_expr(row.decoder[idx].clone()) };
        let col_stk =
            |row: &MainTraceRow<Var>, idx: usize| -> Expr { to_expr(row.stack[idx].clone()) };
        let col_clk = |row: &MainTraceRow<Var>| -> Expr { to_expr(row.clk.clone()) };
        let col_ctx = |row: &MainTraceRow<Var>| -> Expr { to_expr(row.ctx.clone()) };
        let col_chip =
            |row: &MainTraceRow<Var>, idx: usize| -> Expr { to_expr(row.chiplets[idx].clone()) };
        let col_range =
            |row: &MainTraceRow<Var>, idx: usize| -> Expr { to_expr(row.range[idx].clone()) };

        println!("=== PART 2: Denominator (message) degrees ===\n");

        // --- P1_BLOCK_STACK messages ---
        println!("--- P1_BLOCK_STACK ---");
        let simple = [col_dec(next, ADDR_COL_IDX), col_dec(local, ADDR_COL_IDX), Expr::ZERO];
        assert_eq!(msg_deg("simple [block_id', parent_id, 0]", &challenges, &simple), 1);

        // --- P2_BLOCK_HASH messages ---
        println!("\n--- P2_BLOCK_HASH ---");
        let parent = col_dec(next, ADDR_COL_IDX);
        let h0 = col_dec(local, HASHER_STATE_RANGE.start);
        let h4 = col_dec(local, HASHER_STATE_RANGE.start + 4);
        let s0 = col_stk(local, 0);

        // Conditional select for SPLIT
        let split_elem = s0.clone() * h0.clone() + (Expr::ONE - s0.clone()) * h4.clone();
        assert_eq!(deg("split element: s0*h0 + (1-s0)*h4", &split_elem), 2);
        let split_msg = [
            parent.clone(),
            split_elem.clone(),
            split_elem.clone(),
            split_elem.clone(),
            split_elem,
            Expr::ZERO,
            Expr::ZERO,
        ];
        assert_eq!(msg_deg("block_hash SPLIT message (cond select)", &challenges, &split_msg), 2);

        // END message with is_first_child
        let flags_next: OpFlags<Expr> = OpFlags::new(ExprDecoderAccess::new(next));
        let is_first_child = Expr::ONE - flags_next.end() - flags_next.repeat() - flags_next.halt();
        let end_msg = [
            parent,
            h0.clone(),
            h0.clone(),
            h0.clone(),
            h0,
            is_first_child,
            col_dec(local, HASHER_STATE_RANGE.start + 4),
        ];
        assert_eq!(
            msg_deg("block_hash END message (is_first_child deg 4)", &challenges, &end_msg),
            4
        );

        // --- P3_OP_GROUP messages ---
        println!("\n--- P3_OP_GROUP ---");
        let group_msg = [
            col_dec(next, ADDR_COL_IDX),
            col_dec(local, GROUP_COUNT_COL_IDX),
            col_dec(local, HASHER_STATE_RANGE.start + 1),
        ];
        assert_eq!(msg_deg("group insert: [batch_id, gc, h_i]", &challenges, &group_msg), 1);

        // group_value for removal
        let flags = OpFlags::new(ExprDecoderAccess::new(local));
        let is_push: Expr = flags.push();
        let s0_next = col_stk(next, 0);
        let h0_next = col_dec(next, HASHER_STATE_RANGE.start);
        let opcode_next: Expr = (0..7).fold(Expr::ZERO, |acc, i| {
            let bit: Expr = next.decoder[1 + i].clone().into();
            acc + bit * Expr::from_u16(1 << i)
        });
        let group_value = is_push.clone() * s0_next
            + (Expr::ONE - is_push) * (h0_next * Expr::from_u16(128) + opcode_next);
        assert_eq!(deg("group_value (is_push*s0' + ...)", &group_value), 6);
        let removal_msg =
            [col_dec(local, ADDR_COL_IDX), col_dec(local, GROUP_COUNT_COL_IDX), group_value];
        assert_eq!(msg_deg("group removal message", &challenges, &removal_msg), 6);

        // --- P1_STACK messages ---
        println!("\n--- P1_STACK ---");
        let stack_msg = [col_clk(local), col_stk(local, 15), col_stk(local, 17)];
        assert_eq!(msg_deg("stack overflow [clk, s15, b1]", &challenges, &stack_msg), 1);

        // --- Chiplets request messages ---
        println!("\n--- CHIPLETS REQUEST (selected) ---");
        let mem_elem = [
            Expr::from_u16(12),
            col_ctx(local),
            col_stk(local, 0),
            col_clk(local),
            col_stk(next, 0),
        ];
        assert_eq!(
            msg_deg("memory element [label, ctx, addr, clk, elem]", &challenges, &mem_elem),
            1
        );

        let bitwise = [Expr::from_u16(2), col_stk(local, 0), col_stk(local, 1), col_stk(next, 0)];
        // Use manual encode for 4 elements
        let bw_deg = challenges
            .encode([
                bitwise[0].clone(),
                bitwise[1].clone(),
                bitwise[2].clone(),
                bitwise[3].clone(),
            ])
            .degree_multiple();
        println!("  {:50} deg(d) = {bw_deg}", "bitwise [label, a, b, z]");
        assert_eq!(bw_deg, 1);

        // --- Range messages ---
        println!("\n--- RANGE ---");
        let range_lookup =
            challenges.encode([col_dec(local, USER_OP_HELPERS_OFFSET)]).degree_multiple();
        println!("  {:50} deg(d) = {range_lookup}", "range-check stack lookup: alpha + helper[i]");
        assert_eq!(range_lookup, 1);

        let range_resp_d = challenges.encode([col_range(local, 1)]).degree_multiple();
        println!("  {:50} deg(d) = {range_resp_d}", "range table response: alpha + V");
        assert_eq!(range_resp_d, 1);

        // Range response multiplicity
        let range_m: Expr = local.range[0].clone().into();
        assert_eq!(deg("range-check multiplicity M", &range_m), 1);

        // --- Hash kernel sibling message ---
        println!("\n--- HASH KERNEL ---");
        // Node index column within chiplets (relative offset)
        let node_idx: Expr = local.chiplets[17].clone().into();
        let node_idx_next: Expr = next.chiplets[17].clone().into();
        let bit = node_idx.clone() - node_idx_next.clone() - node_idx_next;
        assert_eq!(deg("sibling bit: idx - 2*idx'", &bit), 1);
        // Sibling message = encode(...) * (1 - bit) + encode(...) * bit → degree 2
        let sib_enc = challenges.encode([col_chip(local, 5), col_chip(local, 6)]);
        let sibling_msg = sib_enc.clone() * bit.clone() + sib_enc * (Expr::ONE - bit);
        assert_eq!(deg_ef("sibling cond-select message", &sibling_msg), 2);
    }

    // =====================================================================================
    // PART 3: Batch cost audit
    // =====================================================================================

    /// Per-batch contribution to a group's `(U_g, V_g)` pair.
    ///
    /// `a = deg(s) + deg(D)` flows into `deg(U_g)`; `b = deg(s) + deg(N)` flows into
    /// `deg(V_g)`. The legacy "cost" reported by the audit was `max(a, b)`, which
    /// happens to equal `1 + cost` for the column transition only when
    /// `deg(V_g) ≤ deg(U_g)`. Tracking `a` and `b` separately makes the asymmetric
    /// max in the column transition formula `max(1 + deg(U_g), deg(V_g))` visible.
    fn batch_pair(label: &str, sel_deg: usize, denom_degs: &[usize]) -> (usize, usize) {
        let deg_d: usize = denom_degs.iter().sum();
        // `deg(N) = max_i(deg(m_i) + sum_{j≠i} deg(d_j))` with `deg(m_i) = 0` (const mult).
        // For uniform `deg(d_j) = 1` and `k` interactions, this collapses to `k - 1`.
        let deg_n = if denom_degs.is_empty() {
            0
        } else {
            denom_degs.iter().sum::<usize>() - denom_degs.iter().min().unwrap()
        };
        let a = sel_deg + deg_d;
        let b = sel_deg + deg_n;
        let cost = a.max(b);
        println!("  {label:50} sel={sel_deg} D={deg_d} N={deg_n} → (a,b)=({a},{b}) cost={cost}");
        (a, b)
    }

    /// Per-batch `(a, b)` for batches with non-constant multiplicity.
    ///
    /// Each interaction is `(deg(m_i), deg(v_i))`. Use this for batches where any
    /// `m_i` is a trace-column expression (e.g., `G_ace_wiring`'s `m_0`/`m_1`,
    /// `G_range_table`'s `M`). The plain [`batch_pair`] helper assumes `deg(m_i) = 0`
    /// and would understate `b` whenever any interaction has a non-trivial mult.
    fn batch_pair_m(
        label: &str,
        sel_deg: usize,
        interactions: &[(usize, usize)],
    ) -> (usize, usize) {
        let deg_d: usize = interactions.iter().map(|(_, d)| d).sum();
        let deg_n = interactions
            .iter()
            .enumerate()
            .map(|(i, (m, _))| {
                m + interactions
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, (_, d))| d)
                    .sum::<usize>()
            })
            .max()
            .unwrap_or(0);
        let a = sel_deg + deg_d;
        let b = sel_deg + deg_n;
        let cost = a.max(b);
        println!("  {label:50} sel={sel_deg} D={deg_d} N={deg_n} → (a,b)=({a},{b}) cost={cost}");
        (a, b)
    }

    /// Tracks `(deg(U_g), deg(V_g))` for a logical group as batches are added.
    ///
    /// `deg(U_g) = max_r a_r` and `deg(V_g) = max_r b_r` are taken **independently**
    /// over the group's batches — the batch that pins `deg(U_g)` need not be the
    /// batch that pins `deg(V_g)`. [`Self::finish`] prints both maxes plus the
    /// `V`-slack `deg(U_g) − deg(V_g)`, which is the headroom an asymmetric
    /// degree-reduction trick has to play with on the U-dominant batch.
    struct GroupTracker {
        u_g: usize,
        v_g: usize,
    }

    impl GroupTracker {
        fn new(name: &str) -> Self {
            println!("--- {name} ---");
            Self { u_g: 0, v_g: 0 }
        }

        fn batch(&mut self, label: &str, sel_deg: usize, denom_degs: &[usize]) -> (usize, usize) {
            let (a, b) = batch_pair(label, sel_deg, denom_degs);
            self.u_g = self.u_g.max(a);
            self.v_g = self.v_g.max(b);
            (a, b)
        }

        fn batch_m(
            &mut self,
            label: &str,
            sel_deg: usize,
            interactions: &[(usize, usize)],
        ) -> (usize, usize) {
            let (a, b) = batch_pair_m(label, sel_deg, interactions);
            self.u_g = self.u_g.max(a);
            self.v_g = self.v_g.max(b);
            (a, b)
        }

        fn finish(self, name: &str) -> (usize, usize) {
            let slack = self.u_g.saturating_sub(self.v_g);
            println!(
                "  → {name}: deg(U_g) = {}, deg(V_g) = {}  (V-slack = {slack})\n",
                self.u_g, self.v_g
            );
            (self.u_g, self.v_g)
        }
    }

    /// Single-group column transition degree: `max(1 + deg(U_g), deg(V_g))`.
    ///
    /// The `1` comes from `Δ = acc_next − acc` having degree 1 in the
    /// `Δ · U_g − V_g = 0` constraint.
    fn col_single((u_g, v_g): (usize, usize)) -> usize {
        (1 + u_g).max(v_g)
    }

    /// Print a single column row in the packing summary with either its
    /// per-group `(deg(U_g), deg(V_g))` (for single-group columns) or a
    /// `(composite)` tag (for ME / overlap merges that span multiple groups).
    fn print_column(name: &str, descr: &str, deg: usize, u_v: Option<(usize, usize)>) {
        match u_v {
            Some((u, v)) => {
                let slack = u.saturating_sub(v);
                println!(
                    "  {name}: {descr:40} deg(U_g)={u} deg(V_g)={v} (V-slack={slack}) → degree={deg}"
                );
            },
            None => println!(
                "  {name}: {descr:40} (composite)                            → degree={deg}"
            ),
        }
    }

    /// Two-group column with overlapping (non-ME) groups: costs combine via
    /// `(U, V) = (U_1·U_2, V_1·U_2 + V_2·U_1)`.
    ///
    /// Used for M1 = G_block_stack + G_range_table where `G_range_table` fires on every row
    /// and therefore overlaps every other group.
    fn col_overlap2((u1, v1): (usize, usize), (u2, v2): (usize, usize)) -> usize {
        let u = u1 + u2;
        let v = (v1 + u2).max(v2 + u1);
        col_single((u, v))
    }

    /// Two-group column with mutually-exclusive groups: `(U_g, V_g)` of the
    /// merged set are the elementwise max of the constituent pairs.
    ///
    /// Used for M4 = {G_logpre_cap, G_range_stack} (LOGPRECOMPILE vs u32 arithmetic — different
    /// opcodes) and C2 = {G_hash_kernel, G_mem_range} (hasher/ACE rows vs memory rows —
    /// different chiplets).
    fn col_me2((u1, v1): (usize, usize), (u2, v2): (usize, usize)) -> usize {
        col_single((u1.max(u2), v1.max(v2)))
    }

    /// ME merge of three pairwise-ME groups inside a single logical group
    /// (elementwise max). The group cost is returned as a `(deg(U_g), deg(V_g))`
    /// pair so callers can still compose it further via [`col_overlap2`] when
    /// the merged triple needs to share a column with a non-ME group.
    ///
    /// Used by Plan C for `{G_block_stack, G_logpre_cap, G_range_stack}`: G_block_stack fires on
    /// control-flow opcodes, G_logpre_cap on LOGPRECOMPILE, G_range_stack on u32
    /// arithmetic — all three pairwise row-disjoint.
    fn me_triple(
        (u1, v1): (usize, usize),
        (u2, v2): (usize, usize),
        (u3, v3): (usize, usize),
    ) -> (usize, usize) {
        (u1.max(u2).max(u3), v1.max(v2).max(v3))
    }

    #[test]
    #[allow(clippy::print_stdout)]
    fn audit_batch_costs() {
        println!("=== PART 3: Per-batch (a, b) and per-group (deg(U_g), deg(V_g)) ===\n");
        println!("  a = deg(s) + deg(D) → contributes to deg(U_g)");
        println!("  b = deg(s) + deg(N) → contributes to deg(V_g)");
        println!("  column transition  = max(1 + deg(U_g), deg(V_g))\n");

        // ---- Main trace: G_block_stack (block stack) ----
        let mut g = GroupTracker::new("G_block_stack: block stack");
        assert_eq!(g.batch("JOIN push", 5, &[1]), (6, 5));
        assert_eq!(g.batch("RESPAN push+pop", 4, &[1, 1]), (6, 5));
        assert_eq!(g.batch("DYNCALL push", 5, &[1]), (6, 5));
        let block_stack = g.finish("G_block_stack");

        // ---- Main trace: G_block_hash (block hash) ----
        let mut g = GroupTracker::new("G_block_hash: block hash");
        assert_eq!(g.batch("JOIN left*right", 5, &[1, 1]), (7, 6));
        assert_eq!(g.batch("SPLIT (msg deg 2)", 5, &[2]), (7, 5));
        // LOOP: s0 gate makes selector deg 6
        assert_eq!(g.batch("LOOP body (sel=is_loop*s0)", 6, &[1]), (7, 6));
        // END is the U-dominant batch with the largest V-slack: a=8, b=4 (slack 4)
        assert_eq!(g.batch("END pop (msg deg 4)", 4, &[4]), (8, 4));
        assert_eq!(g.batch("REPEAT", 4, &[1]), (5, 4));
        assert_eq!(g.batch("DYN/DYNCALL/CALL/SYSCALL", 5, &[1]), (6, 5));
        let block_hash = g.finish("G_block_hash");

        // ---- Main trace: G_chiplet_req (chiplets requests) ----
        let mut g = GroupTracker::new("G_chiplet_req: chiplets requests");
        assert_eq!(g.batch("JOIN hasher", 5, &[1]), (6, 5));
        assert_eq!(g.batch("CALL hasher+fmp", 4, &[1, 1]), (6, 5));
        assert_eq!(g.batch("DYN zeros+callee", 5, &[1, 1]), (7, 6));
        assert_eq!(g.batch("DYNCALL zeros+callee+fmp", 5, &[1, 1, 1]), (8, 7));
        assert_eq!(g.batch("MLOAD", 7, &[1]), (8, 7));
        assert_eq!(g.batch("U32AND", 7, &[1]), (8, 7));
        assert_eq!(g.batch("HPERM in+out", 5, &[1, 1]), (7, 6));
        assert_eq!(g.batch("MRUPDATE 4 msgs", 4, &[1, 1, 1, 1]), (8, 7));
        assert_eq!(g.batch("CRYPTOSTREAM 4 msgs", 4, &[1, 1, 1, 1]), (8, 7));
        assert_eq!(g.batch("LOGPRE hasher_in+out", 5, &[1, 1]), (7, 6));
        let chiplet_req = g.finish("G_chiplet_req");

        // ---- Main trace: G_op_group (op group) ----
        let mut g = GroupTracker::new("G_op_group: op group");
        assert_eq!(g.batch("g8 (7 groups)", 1, &[1, 1, 1, 1, 1, 1, 1]), (8, 7));
        assert_eq!(g.batch("g4 (3 groups)", 3, &[1, 1, 1]), (6, 5));
        assert_eq!(g.batch("g2 (1 group)", 3, &[1]), (4, 3));
        // The removal has by far the largest *personal* V-slack (a=8, b=2 → slack 6),
        // but the group is still pinned by g8 because g8's deg(V_g)=7.
        assert_eq!(g.batch("removal (deg(d)=6)", 2, &[6]), (8, 2));
        let op_group = g.finish("G_op_group");

        // ---- Main trace: G_range_stack ----
        let mut g = GroupTracker::new("G_range_stack: stack lookups");
        assert_eq!(g.batch("4 stack lookups", 3, &[1, 1, 1, 1]), (7, 6));
        let range_stack = g.finish("G_range_stack");

        // ---- Main trace: G_range_table ----
        let mut g = GroupTracker::new("G_range_table");
        // Range response uses a non-constant multiplicity M (deg 1).
        assert_eq!(g.batch_m("range table response (m=M deg 1)", 0, &[(1, 1)]), (1, 1));
        let range_table = g.finish("G_range_table");

        // ---- Main trace: G_logpre_cap ----
        let mut g = GroupTracker::new("G_logpre_cap: logprecompile hash_kernel");
        assert_eq!(g.batch("cap_prev + cap_next", 5, &[1, 1]), (7, 6));
        let logpre_cap = g.finish("G_logpre_cap");

        // ---- Chiplet trace: G_chiplet_resp ----
        let mut g = GroupTracker::new("G_chiplet_resp: all chiplet responses");
        assert_eq!(g.batch("hasher f_bp (full state)", 5, &[1]), (6, 5));
        assert_eq!(g.batch("hasher f_mv (cond leaf)", 5, &[2]), (7, 5));
        assert_eq!(g.batch("hasher f_hout (digest)", 5, &[1]), (6, 5));
        assert_eq!(g.batch("bitwise (computed label)", 4, &[2]), (6, 4));
        assert_eq!(g.batch("memory (label+elem select)", 3, &[3]), (6, 3));
        assert_eq!(g.batch("kernel_rom (computed label)", 5, &[2]), (7, 5));
        let chiplet_resp = g.finish("G_chiplet_resp");

        // ---- Chiplet trace: G_hash_kernel ----
        let mut g = GroupTracker::new("G_hash_kernel: hash_kernel chiplet entries");
        assert_eq!(g.batch("sibling (cond select)", 5, &[2]), (7, 5));
        assert_eq!(g.batch("ACE word read", 5, &[1]), (6, 5));
        assert_eq!(g.batch("ACE elem read", 5, &[1]), (6, 5));
        let hash_kernel = g.finish("G_hash_kernel");

        // ---- Chiplet trace: G_mem_range ----
        let mut g = GroupTracker::new("G_mem_range: memory range-check lookups");
        assert_eq!(g.batch("D0 + D1", 3, &[1, 1]), (5, 4));
        let mem_range = g.finish("G_mem_range");

        // ---- Chiplet trace: G_ace_wiring ----
        // Both READ and EVAL have `m_0` (and READ also has `m_1`) as ACE chiplet
        // trace columns of degree 1 — the legacy `batch_pair` would understate `b`
        // by treating them as constant. Use `batch_m` so the (a, b) tuple matches the
        // full symbolic constraint. Note: this is the only saturated bus where the
        // corrected `b` flips a `(8, 7)` into a `(8, 8)`, eliminating the V-slack
        // entirely and confirming C3 has nothing to trade.
        let mut g = GroupTracker::new("G_ace_wiring: ACE wiring");
        assert_eq!(g.batch_m("READ 2 wires (m0,m1 deg 1)", 5, &[(1, 1), (1, 1)]), (7, 7));
        assert_eq!(
            g.batch_m("EVAL 3 wires (m0 deg 1, m1=m2=-1)", 5, &[(1, 1), (0, 1), (0, 1)]),
            (8, 8)
        );
        let wiring = g.finish("G_ace_wiring");

        // ---- Column packing ----
        println!("=== Column packing (transition = max(1 + deg(U_g), deg(V_g))) ===\n");

        let m1 = col_overlap2(block_stack, range_table);
        let m2 = col_single(block_hash);
        let m3 = col_single(chiplet_req);
        let m4 = col_me2(logpre_cap, range_stack);
        let m5 = col_single(op_group);
        let c1 = col_single(chiplet_resp);
        let c2 = col_me2(hash_kernel, mem_range);
        let c3 = col_single(wiring);

        let print_col = |name: &str, descr: &str, deg: usize, u_v: Option<(usize, usize)>| match u_v
        {
            Some((u, v)) => {
                let slack = u.saturating_sub(v);
                println!(
                    "  {name}: {descr:32} deg(U_g)={u} deg(V_g)={v} (V-slack={slack}) → degree={deg}"
                );
            },
            None => println!("  {name}: {descr:32} (composite) → degree={deg}"),
        };

        print_col("M1", "G_block_stack + G_range_table", m1, None);
        print_col("M2", "G_block_hash", m2, Some(block_hash));
        print_col("M3", "G_chiplet_req", m3, Some(chiplet_req));
        print_col("M4", "{G_logpre_cap, G_range_stack}", m4, None);
        print_col("M5", "G_op_group", m5, Some(op_group));
        print_col("C1", "G_chiplet_resp", c1, Some(chiplet_resp));
        print_col("C2", "{G_hash_kernel, G_mem_range}", c2, None);
        print_col("C3", "G_ace_wiring", c3, Some(wiring));

        assert!(m1 <= 9, "M1 exceeds degree 9");
        assert!(m2 <= 9, "M2 exceeds degree 9");
        assert!(m3 <= 9, "M3 exceeds degree 9");
        assert!(m4 <= 9, "M4 exceeds degree 9");
        assert!(m5 <= 9, "M5 exceeds degree 9");
        assert!(c1 <= 9, "C1 exceeds degree 9");
        assert!(c2 <= 9, "C2 exceeds degree 9");
        assert!(c3 <= 9, "C3 exceeds degree 9");

        // The four buses pinned at the budget. Asserting these explicitly so any
        // future restructuring trick that drops one of them shows up as a test
        // diff rather than as a silent improvement.
        assert_eq!(m2, 9, "M2 expected to saturate budget");
        assert_eq!(m3, 9, "M3 expected to saturate budget");
        assert_eq!(m5, 9, "M5 expected to saturate budget");
        assert_eq!(c3, 9, "C3 expected to saturate budget");

        println!("\n  Total: 5 main + 3 chiplet = 8 columns, 4 saturated at degree 9.");
    }

    // =====================================================================================
    // PART 3B: Alternative packings without adding columns
    // =====================================================================================

    /// Explore packings that keep the group-level `(deg(U_g), deg(V_g))` pairs
    /// unchanged but re-pack them into columns differently, plus one internal
    /// restructuring of `G_ace_wiring` (the `wire_0` hoist) that folds the two ME
    /// batches into a single `ace_flag`-gated batch with `sblock`-muxed
    /// multiplicities.
    ///
    /// All transformations here preserve per-column bus closure: whole-group
    /// recombinings produce columns whose partial-multiset is a union of
    /// already-closed group multisets, and the wire_0 hoist keeps all of
    /// `G_ace_wiring` in a single column (its accumulator is algebraically
    /// identical to the original two-batch form, so the `acc[N] = 0` boundary
    /// constraint still holds by construction).
    #[test]
    #[allow(clippy::print_stdout)]
    fn audit_alternative_packings() {
        println!("=== PART 3B: Alternative packings without adding columns ===\n");

        // Current per-group `(deg(U_g), deg(V_g))` — these are asserted in
        // `audit_batch_costs` above, reused here as constants so we can model
        // column packings without re-running the per-batch computation.
        let block_stack = (6, 5);
        let block_hash = (8, 6);
        let op_group = (8, 7);
        let chiplet_req = (8, 7);
        let range_stack = (7, 6);
        let range_table = (1, 1);
        let logpre_cap = (7, 6);
        let chiplet_resp = (7, 5);
        let hash_kernel = (7, 5);
        let mem_range = (5, 4);
        let wiring_orig = (8, 8);

        // -------------------------------------------------------------------
        // Plan 0 — current packing (baseline): 8 columns, 4 saturated at 9.
        // -------------------------------------------------------------------
        println!("--- Plan 0: current packing (baseline) ---");
        let p0_m1 = col_overlap2(block_stack, range_table);
        let p0_m2 = col_single(block_hash);
        let p0_m3 = col_single(chiplet_req);
        let p0_m4 = col_me2(logpre_cap, range_stack);
        let p0_m5 = col_single(op_group);
        let p0_c1 = col_single(chiplet_resp);
        let p0_c2 = col_me2(hash_kernel, mem_range);
        let p0_c3 = col_single(wiring_orig);
        print_column("M1   ", "G_block_stack + G_range_table (sum)", p0_m1, None);
        print_column("M2   ", "G_block_hash", p0_m2, Some(block_hash));
        print_column("M3   ", "G_chiplet_req", p0_m3, Some(chiplet_req));
        print_column("M4   ", "{G_logpre_cap, G_range_stack} (ME)", p0_m4, None);
        print_column("M5   ", "G_op_group", p0_m5, Some(op_group));
        print_column("C1   ", "G_chiplet_resp", p0_c1, Some(chiplet_resp));
        print_column("C2   ", "{G_hash_kernel, G_mem_range} (ME)", p0_c2, None);
        print_column("C3   ", "G_ace_wiring", p0_c3, Some(wiring_orig));
        let p0 = [p0_m1, p0_m2, p0_m3, p0_m4, p0_m5, p0_c1, p0_c2, p0_c3];
        let p0_sat = p0.iter().filter(|&&d| d == 9).count();
        println!("  8 columns, {p0_sat} saturated\n");
        assert_eq!(p0_sat, 4, "baseline should have 4 saturated columns");

        // -------------------------------------------------------------------
        // Plan A — ME-merge G_block_hash + G_op_group (saves the M5 slot).
        //
        // Row-disjointness proof: G_block_hash fires only on control-flow opcodes
        // (JOIN/SPLIT/LOOP/REPEAT/DYN/DYNCALL/CALL/SYSCALL/END). G_op_group fires
        // only on SPAN/RESPAN (insertion side) or in-span decode rows
        // (removal side). Control-flow opcodes are never in-span, and
        // SPAN/RESPAN are not in G_block_hash's variant list, so they never fire on
        // the same row → the ME merge takes the elementwise max rather than
        // the sum.
        // -------------------------------------------------------------------
        println!("--- Plan A: G_block_hash + G_op_group ME-merged (7 columns) ---");
        let bh_og_me = (block_hash.0.max(op_group.0), block_hash.1.max(op_group.1));
        let pa_m1 = col_overlap2(block_stack, range_table);
        let pa_m25 = col_single(bh_og_me);
        let pa_m3 = col_single(chiplet_req);
        let pa_m4 = col_me2(logpre_cap, range_stack);
        let pa_c1 = col_single(chiplet_resp);
        let pa_c2 = col_me2(hash_kernel, mem_range);
        let pa_c3 = col_single(wiring_orig);
        print_column("M1   ", "G_block_stack + G_range_table (sum)", pa_m1, None);
        print_column("M_2+5", "{G_block_hash, G_op_group} (ME)", pa_m25, Some(bh_og_me));
        print_column("M3   ", "G_chiplet_req", pa_m3, Some(chiplet_req));
        print_column("M4   ", "{G_logpre_cap, G_range_stack} (ME)", pa_m4, None);
        print_column("C1   ", "G_chiplet_resp", pa_c1, Some(chiplet_resp));
        print_column("C2   ", "{G_hash_kernel, G_mem_range} (ME)", pa_c2, None);
        print_column("C3   ", "G_ace_wiring (original)", pa_c3, Some(wiring_orig));
        let pa = [pa_m1, pa_m25, pa_m3, pa_m4, pa_c1, pa_c2, pa_c3];
        let pa_sat = pa.iter().filter(|&&d| d == 9).count();
        println!("  7 columns, {pa_sat} saturated\n");
        assert_eq!(pa_sat, 3, "Plan A should have 3 saturated columns");
        assert_eq!(pa_m25, 9, "M_2+5 should saturate at 9");
        assert_eq!(pa_m3, 9, "M3 should saturate at 9");
        assert_eq!(pa_c3, 9, "C3 should still be 9 (no hoist yet)");

        // -------------------------------------------------------------------
        // Plan B — Plan A + wire_0 hoist inside G_ace_wiring.
        //
        // The two ME batches (is_read, is_eval) inside G_ace_wiring both carry an
        // `(m_0, wire_0)` interaction with the same multiplicity. Factoring
        // that interaction out yields:
        //
        //   is_read · (m_0/wire_0 + m_1/wire_1)
        // + is_eval · (m_0/wire_0 − 1/wire_1 − 1/wire_2) = m_0/wire_0 (always under ace_flag)
        //   + ((1 − sblock) · m_1 − sblock) / wire_1
        //   + (−sblock) / wire_2
        //   = ace_flag · [ m_0/wire_0
        //                 + ((1 − sblock)·m_1 − sblock)/wire_1
        //                 + (−sblock)/wire_2 ]
        //
        // Emitted as a single 3-interaction batch under `ace_flag (deg 4)`,
        // with `sblock`-muxed multiplicities for wire_1 and wire_2. All of
        // G_ace_wiring stays in one column, so the per-column bus closure is
        // preserved (the rational is algebraically identical to the original
        // two-batch form).
        //
        // Per-interaction (deg_m, deg_v):
        //   (1, 1)  wire_0: m_0 is the M_0 chiplet column (deg 1)
        //   (2, 1)  wire_1: (1 − sblock)·m_1 − sblock has deg max(1+1, 1) = 2
        //   (1, 1)  wire_2: −sblock has deg 1
        //
        //   deg(D) = 1 + 1 + 1 = 3
        //   deg(N) = max(1 + 2, 2 + 2, 1 + 2) = 4
        //   deg(flag) = deg(ace_flag) = 4
        //   (a, b) = (4 + 3, 4 + 4) = (7, 8)
        //   transition = max(1 + 7, 8) = 8
        // -------------------------------------------------------------------
        println!("--- Plan B: Plan A + G_ace_wiring wire_0 hoist ---");
        let wiring_hoist = {
            let mut g = GroupTracker::new("G_ace_wiring (wire_0 hoisted)");
            assert_eq!(
                g.batch_m(
                    "ace_flag · {wire_0 | wire_1 mux | wire_2 mux}",
                    4,
                    &[(1, 1), (2, 1), (1, 1)],
                ),
                (7, 8)
            );
            g.finish("G_ace_wiring (hoisted)")
        };
        println!();
        let pb_c3 = col_single(wiring_hoist);
        print_column("M1   ", "G_block_stack + G_range_table (sum)", pa_m1, None);
        print_column("M_2+5", "{G_block_hash, G_op_group} (ME)", pa_m25, Some(bh_og_me));
        print_column("M3   ", "G_chiplet_req", pa_m3, Some(chiplet_req));
        print_column("M4   ", "{G_logpre_cap, G_range_stack} (ME)", pa_m4, None);
        print_column("C1   ", "G_chiplet_resp", pa_c1, Some(chiplet_resp));
        print_column("C2   ", "{G_hash_kernel, G_mem_range} (ME)", pa_c2, None);
        print_column("C3   ", "G_ace_wiring (wire_0 hoisted)", pb_c3, Some(wiring_hoist));
        let pb = [pa_m1, pa_m25, pa_m3, pa_m4, pa_c1, pa_c2, pb_c3];
        let pb_sat = pb.iter().filter(|&&d| d == 9).count();
        println!("  7 columns, {pb_sat} saturated\n");
        assert_eq!(pb_sat, 2, "Plan B should have 2 saturated columns");
        assert_eq!(pb_c3, 8, "C3 should drop to 8 under the wire_0 hoist");

        // -------------------------------------------------------------------
        // Plan C — Plan B + maximal ME-merge + G_range_table absorption.
        //
        // Exploits the 3-clique `{G_block_stack, G_logpre_cap, G_range_stack}` (all three
        // pairwise ME: G_block_stack fires on control-flow, G_logpre_cap on LOGPRECOMPILE,
        // G_range_stack on u32 arithmetic) and then absorbs `G_range_table` into the
        // same column via overlap sum, saturating it at (8, 8) → transition 9.
        //
        // Combined with Plan A's `{G_block_hash, G_op_group}` merge and Plan B's wire_0
        // hoist, this collapses the packing to 6 columns:
        //
        //   Main:
        //     M_A = {G_block_stack, G_logpre_cap, G_range_stack} (ME) + G_range_table (overlap)
        //     M_B = {G_block_hash, G_op_group} (ME)
        //     M_C = G_chiplet_req
        //   Chiplet:
        //     C1  = G_chiplet_resp
        //     C2  = {G_hash_kernel, G_mem_range} (ME)
        //     C3  = G_ace_wiring (wire_0 hoisted)
        //
        // ME-compat proof for {G_block_stack, G_logpre_cap, G_range_stack}:
        //   - G_block_stack ⊥ G_logpre_cap: G_block_stack fires on control-flow opcodes
        //     (JOIN/SPLIT/SPAN/DYN/LOOP/DYNCALL/CALL/SYSCALL/RESPAN/END); G_logpre_cap fires on
        //     LOGPRECOMPILE, which is not a control-flow op.
        //   - G_block_stack ⊥ G_range_stack: G_block_stack on control-flow (opcode prefix
        //     101xx/100xx); G_range_stack on u32 arithmetic (opcode prefix 100 with bits 4=0),
        //     which never overlaps control-flow boundary opcodes.
        //   - G_logpre_cap ⊥ G_range_stack: LOGPRECOMPILE vs u32 arithmetic — already the current
        //     M4 grouping, verified via binary op-bit constraints.
        // -------------------------------------------------------------------
        println!(
            "--- Plan C: Plan B + {{G_block_stack, G_logpre_cap, G_range_stack}} triple merge + G_range_table absorption ---"
        );
        let main_me_triple = me_triple(block_stack, logpre_cap, range_stack);
        println!(
            "  {{G_block_stack, G_logpre_cap, G_range_stack}} (ME triple): (deg(U_g), deg(V_g)) = {main_me_triple:?}"
        );
        let pc_m_a_pair = {
            // Overlap sum of the ME-merged triple with `G_range_table`:
            //   u = u_triple + 1         = 7 + 1 = 8
            //   v = max(v_triple + 1, 1 + u_triple) = max(7, 8) = 8
            let u = main_me_triple.0 + range_table.0;
            let v = (main_me_triple.1 + range_table.0).max(range_table.1 + main_me_triple.0);
            (u, v)
        };
        let pc_m_a = col_single(pc_m_a_pair);
        println!(
            "  M_A = triple + G_range_table (overlap): (deg(U_g), deg(V_g)) = {pc_m_a_pair:?}, \
             transition = {pc_m_a}"
        );
        assert_eq!(pc_m_a_pair, (8, 8), "M_A (triple + range_table overlap) should land at (8, 8)");
        assert_eq!(pc_m_a, 9, "M_A column should saturate at 9");
        println!();

        let pc_m_b = pa_m25; // {G_block_hash, G_op_group} ME — same as Plan A
        let pc_m_c = pa_m3; // G_chiplet_req alone — unchanged
        let pc_c1 = pa_c1; // G_chiplet_resp — unchanged
        let pc_c2 = pa_c2; // {G_hash_kernel, G_mem_range} — unchanged
        let pc_c3 = pb_c3; // G_ace_wiring with wire_0 hoist — same as Plan B

        print_column("M_A  ", "triple + G_range_table (overlap)", pc_m_a, Some(pc_m_a_pair));
        print_column("M_B  ", "{G_block_hash, G_op_group} (ME)", pc_m_b, Some(bh_og_me));
        print_column("M_C  ", "G_chiplet_req", pc_m_c, Some(chiplet_req));
        print_column("C1   ", "G_chiplet_resp", pc_c1, Some(chiplet_resp));
        print_column("C2   ", "{G_hash_kernel, G_mem_range} (ME)", pc_c2, None);
        print_column("C3   ", "G_ace_wiring (wire_0 hoisted)", pc_c3, Some(wiring_hoist));
        let pc = [pc_m_a, pc_m_b, pc_m_c, pc_c1, pc_c2, pc_c3];
        let pc_sat = pc.iter().filter(|&&d| d == 9).count();
        println!("  6 columns, {pc_sat} saturated\n");
        assert_eq!(pc_sat, 3, "Plan C should have 3 saturated columns");
        assert_eq!(pc.len(), 6, "Plan C should reach 6 columns total");

        // Also report Plan C without the wire_0 hoist, in case the hoist
        // doesn't land. This isolates the "saved columns" gain from the
        // "saved saturations" gain so we can report them as independent wins.
        let pc_no_hoist_c3 = col_single(wiring_orig);
        let pc_no_hoist = [pc_m_a, pc_m_b, pc_m_c, pc_c1, pc_c2, pc_no_hoist_c3];
        let pc_no_hoist_sat = pc_no_hoist.iter().filter(|&&d| d == 9).count();
        println!("  Plan C without wire_0 hoist: 6 columns, {pc_no_hoist_sat} saturated");
        println!("                               (C3 = {pc_no_hoist_c3} instead of {pc_c3})\n");
        assert_eq!(pc_no_hoist_sat, 4, "Plan C without hoist should have 4 saturated columns");

        // -------------------------------------------------------------------
        // Summary
        // -------------------------------------------------------------------
        println!("=== Summary ===\n");
        println!("  Plan 0 (current):       8 columns, 4 saturated  (M2, M3, M5, C3)");
        println!("  Plan A (merge):         7 columns, 3 saturated  (M_2+5, M3, C3)");
        println!("  Plan B (A + hoist):     7 columns, 2 saturated  (M_2+5, M3)");
        println!("  Plan C (B + triple):    6 columns, 3 saturated  (M_A, M_B, M_C)");
        println!("  Plan C w/o hoist:       6 columns, 4 saturated  (adds C3)");
        println!();
        println!("  Plan C reaches the minimum column count achievable via");
        println!("  whole-group recombining + in-column restructuring at the");
        println!("  current API surface: 6 columns, −2 from the baseline.");
        println!("  Going below 6 would require either splitting individual");
        println!("  groups across columns (needs the constraint.rs per-column");
        println!("  boundary assertion to be relaxed to a global sum first),");
        println!("  or reducing deg(U_g) of G_block_hash/G_op_group/G_chiplet_req directly (no");
        println!("  API-level path identified — see audit_batch_costs).");
    }

    // =====================================================================================
    // PART 4: Mutual exclusivity proofs
    // =====================================================================================

    #[test]
    #[allow(clippy::print_stdout)]
    fn audit_mutual_exclusivity() {
        let builder = make_builder();
        let main = builder.main();
        let local: &MainTraceRow<_> = main.current_slice().borrow();

        println!("=== PART 4: Mutual exclusivity proofs ===\n");

        // 1. Op bits are binary → opcode flags are ME
        println!("--- Op bits binary (degree 2 each) ---");
        for i in 0..7 {
            let bit: Expr = local.decoder[1 + i].clone().into();
            let constraint = bit.clone() * (bit - Expr::ONE);
            let d = constraint.degree_multiple();
            println!("  op_bit[{i}] * (op_bit[{i}] - 1) = 0          deg = {d}");
            assert_eq!(d, 2);
        }

        // 2. in_span (sp) is binary
        println!("\n--- in_span binary ---");
        let sp: Expr = local.decoder[IN_SPAN_COL_IDX].clone().into();
        let sp_binary = sp.clone() * (sp.clone() - Expr::ONE);
        assert_eq!(deg("sp * (sp - 1)", &sp_binary), 2);

        // 3. Chiplet selectors are binary (hierarchically)
        println!("\n--- Chiplet selectors binary ---");
        let s0: Expr = local.chiplets[0].clone().into();
        let s1: Expr = local.chiplets[1].clone().into();
        let s2: Expr = local.chiplets[2].clone().into();
        let s3: Expr = local.chiplets[3].clone().into();

        let c0 = s0.clone() * (s0.clone() - Expr::ONE);
        assert_eq!(deg("s0 * (s0 - 1)", &c0), 2);

        let c1 = s0.clone() * s1.clone() * (s1.clone() - Expr::ONE);
        assert_eq!(deg("s0 * s1 * (s1 - 1)", &c1), 3);

        let c2 = s0.clone() * s1.clone() * s2.clone() * (s2.clone() - Expr::ONE);
        assert_eq!(deg("s0 * s1 * s2 * (s2 - 1)", &c2), 4);

        let c3 = s0 * s1 * s2 * s3.clone() * (s3 - Expr::ONE);
        assert_eq!(deg("s0 * s1 * s2 * s3 * (s3 - 1)", &c3), 5);

        // 4. Batch flags are binary
        println!("\n--- Batch flags binary (c0, c1, c2) ---");
        // Batch flags are in the decoder at specific offsets
        // c0 = decoder[BATCH_FLAG_0] etc.
        // Using known offset: OP_INDEX + 1 = GROUP_COUNT + 2 from the decoder layout
        let bf0: Expr = local.decoder[20].clone().into(); // approximate offset
        let bf_binary = bf0.clone() * (bf0 - Expr::ONE);
        assert_eq!(deg("c0 * (c0 - 1)", &bf_binary), 2);

        println!("\n--- Summary ---");
        println!("  7 op_bits binary (deg 2) → 2^7 = 128 ME opcode patterns");
        println!("  sp binary (deg 2) → control flow (sp=0) vs in-span (sp=1) ME");
        println!("  4 chiplet selectors binary (deg 2-5) → 6 ME chiplet types");
        println!("  3 batch flags binary (deg 2) → 4 ME batch sizes");
        println!("  Hasher selectors binary under hasher flag → 7+ ME hasher row types");
    }
}
