//! Rendering of the recursive verifier's proof-order pass.
//!
//! A lifted STARK commits its AIR traces in ascending `(log height, instance index)` order. The
//! verifier needs that permutation in three places — the out-of-domain scatter table, the
//! auxiliary-boundary placement, and the fold coefficients — so it derives it exactly once from
//! the transcript-bound heights and materializes two inverse maps:
//!
//! - `id_by_pos[position]`: the instance index committed at each proof position;
//! - `pos_by_id[index]`: each instance's proof position.
//!
//! The derivation packs each AIR's key as `PROOF_ORDER_KEY_STRIDE * height + index`, sorts the
//! keys with a fixed comparator network (`cswap` is one VM operation, so the pass is branch-free
//! and data-oblivious), and unpacks the sorted keys with `u32and`.

use std::{format, string::String, vec::Vec};

use crate::{
    AceError,
    proof_order::{MAX_ORDER_AIRS, PROOF_ORDER_KEY_STRIDE, sorting_network},
};

/// Relation-specific inputs to [`render_proof_order_maps`].
#[derive(Clone, Debug)]
pub struct ProofOrderMapsConfig<'a> {
    /// Number of AIR instances; the pass sorts exactly this many keys.
    pub num_airs: usize,
    /// MASM leaving the base of the per-AIR log-height cells on the stack.
    pub heights_ptr: &'a str,
    /// MASM leaving the `pos_by_id` table base on the stack.
    pub pos_by_id_ptr: &'a str,
    /// MASM leaving the `id_by_pos` table base on the stack.
    pub id_by_pos_ptr: &'a str,
    /// Read the heights with one `mem_loadw_le` instead of one `mem_load` per AIR. Only used for
    /// four AIRs (one word), and only valid when the height cells are word-aligned.
    pub word_load_heights: bool,
    /// Write `id_by_pos` with one `mem_storew_le` per four proof positions instead of one
    /// `mem_store` each. Only valid when the `id_by_pos` table is word-aligned.
    pub word_store_ids: bool,
}

/// Tracks the operand stack while the pass is rendered, so every `dup.n`/`movup.n` index is
/// computed from the layout rather than written by hand.
struct Stack {
    items: Vec<String>,
    ops: Vec<String>,
    /// Set when an index beyond the directly addressable 16 stack slots was requested.
    out_of_reach: bool,
}

impl Stack {
    fn new() -> Self {
        Self {
            items: Vec::new(),
            ops: Vec::new(),
            out_of_reach: false,
        }
    }

    fn reach(&mut self, index: usize) {
        if index >= 16 {
            self.out_of_reach = true;
        }
    }

    /// Removes the top two tracked items, refusing to model a consumption of the caller's stack.
    fn pop_two(&mut self, op: &str) {
        for _ in 0..2 {
            self.items
                .pop()
                .unwrap_or_else(|| panic!("{op} would consume the caller's stack"));
        }
    }

    fn depth(&self) -> usize {
        self.items.len()
    }

    /// Index of the named item from the top of the stack.
    fn index_of(&self, name: &str) -> usize {
        let from_bottom = self
            .items
            .iter()
            .rposition(|item| item == name)
            .unwrap_or_else(|| panic!("{name}"));
        self.items.len() - 1 - from_bottom
    }

    fn emit(&mut self, op: &str) {
        // Two consecutive swaps cancel; the comparator choreography produces them at the edges.
        if op == "swap" && self.ops.last().map(String::as_str) == Some("swap") {
            self.ops.pop();
            return;
        }
        self.ops.push(op.into());
    }

    /// Runs `masm` (a pointer accessor or any stack-neutral prelude) that pushes one value.
    fn push_via(&mut self, masm: &str, name: &str) {
        self.emit(masm);
        self.items.push(name.into());
    }

    fn push_const(&mut self, value: usize, name: &str) {
        self.emit(&format!("push.{value}"));
        self.items.push(name.into());
    }

    fn dup(&mut self, index: usize, name: &str) {
        self.reach(index);
        self.emit(
            if index == 0 {
                "dup".into()
            } else {
                format!("dup.{index}")
            }
            .as_str(),
        );
        self.items.push(name.into());
    }

    fn dup_named(&mut self, source: &str, name: &str) {
        let index = self.index_of(source);
        self.dup(index, name);
    }

    fn movup(&mut self, index: usize) {
        self.reach(index);
        match index {
            0 => {},
            1 => self.emit("swap"),
            _ => self.emit(&format!("movup.{index}")),
        }
        let from_bottom = self.items.len() - 1 - index;
        let item = self.items.remove(from_bottom);
        self.items.push(item);
    }

    fn movdn(&mut self, index: usize) {
        self.reach(index);
        match index {
            0 => {},
            1 => self.emit("swap"),
            _ => self.emit(&format!("movdn.{index}")),
        }
        let item = self.items.pop().expect("movdn on an empty stack");
        let from_bottom = self.items.len() - index;
        self.items.insert(from_bottom, item);
    }

    fn drop(&mut self) {
        self.emit("drop");
        self.items.pop().expect("drop on an empty stack");
    }

    /// Replaces the top item's name after a value-transforming op.
    fn rename_top(&mut self, name: &str) {
        *self.items.last_mut().expect("rename on an empty stack") = name.into();
    }

    /// Binary op consuming the top two items and pushing `name`.
    fn binary(&mut self, op: &str, name: &str) {
        self.emit(op);
        self.pop_two(op);
        self.items.push(name.into());
    }

    /// `mem_store` consumes `[addr, value]`.
    fn mem_store(&mut self) {
        self.emit("mem_store");
        self.pop_two("mem_store");
    }

    /// `mem_storew_le` consumes the address and keeps the word beneath it.
    fn mem_storew_le(&mut self) {
        self.emit("mem_storew_le");
        self.items.pop().expect("mem_storew_le needs an address");
    }

    /// `mem_loadw_le` consumes the address and overwrites the word beneath it with `names`
    /// (top first).
    fn mem_loadw_le(&mut self, names: [&str; 4]) {
        self.emit("mem_loadw_le");
        self.items.pop().expect("mem_loadw_le needs an address");
        for _ in 0..4 {
            self.drop_quiet();
        }
        for name in names.iter().rev() {
            self.items.push((*name).into());
        }
    }

    fn padw(&mut self) {
        self.emit("padw");
        for _ in 0..4 {
            self.items.push("pad".into());
        }
    }

    fn dropw(&mut self) {
        self.emit("dropw");
        for _ in 0..4 {
            self.drop_quiet();
        }
    }

    fn drop_quiet(&mut self) {
        self.items.pop().expect("drop on an empty stack");
    }

    fn line(&self, indent: usize) -> String {
        format!("{}{}", " ".repeat(indent), self.ops.join(" "))
    }
}

/// Renders the pass as a complete public MASM procedure named `stage_proof_order_maps`.
///
/// The procedure preserves the caller's operand stack, reads the `num_airs` height cells, and
/// writes exactly `num_airs` cells into each table. It must run after the heights have been
/// bounded: the packed keys assume every height is a validated `u32` below
/// `2^32 / PROOF_ORDER_KEY_STRIDE`.
pub fn render_proof_order_maps(config: &ProofOrderMapsConfig<'_>) -> Result<String, AceError> {
    let num_airs = config.num_airs;
    if !(2..=MAX_ORDER_AIRS).contains(&num_airs) {
        return Err(AceError::InvalidInputLayout {
            message: format!("proof-order maps need 2..={MAX_ORDER_AIRS} AIRs, got {num_airs}"),
        });
    }
    if config.word_load_heights && num_airs != 4 {
        return Err(AceError::InvalidInputLayout {
            message: format!(
                "word-loading proof-order heights requires exactly four AIRs, got {num_airs}"
            ),
        });
    }
    let network = sorting_network(num_airs);
    let stride = PROOF_ORDER_KEY_STRIDE;

    let mut lines = Vec::new();
    let mut stack = Stack::new();

    // The table pointers either sit beneath the keys for the whole pass or are pushed on top of
    // the sorted keys afterwards. `dup.n` and `movup.n` are single operations only up to index 7
    // (plus a few odd indices), so pointers stay beneath when keys and pointers together fit that
    // reach, and go on top otherwise, where each unpacking step lifts the next key above them.
    let num_pointers = 2;
    let pointers_beneath = num_airs + num_pointers <= 8;
    let push_pointers = |stack: &mut Stack| {
        stack.push_via(config.id_by_pos_ptr, "ids_ptr");
        stack.push_via(config.pos_by_id_ptr, "pos_ptr");
    };
    if pointers_beneath {
        push_pointers(&mut stack);
        lines.push(format!("    # => [{}]", describe(&stack)));
        lines.push(stack.line(4));
        stack.ops.clear();
    }

    // Keys: AIR i's key is `stride * height_i + i`, laid out so that AIR 0's key ends on top and
    // index `i` of the stack holds AIR `i`.
    if config.word_load_heights && num_airs == 4 {
        // One word read leaves the four heights in memory order, AIR 0 on top; each key is formed
        // on top and rotated beneath the others, which restores that order once all four are done.
        stack.padw();
        stack.push_via(config.heights_ptr, "heights_ptr");
        stack.mem_loadw_le(["h0", "h1", "h2", "h3"]);
        for air in 0..4 {
            stack.emit(&format!("mul.{stride}"));
            if air > 0 {
                stack.emit(&format!("add.{air}"));
            }
            stack.rename_top(&format!("k{air}"));
            stack.movdn(3);
        }
    } else {
        // Built from the highest index down, one height read each.
        stack.push_via(config.heights_ptr, "heights_ptr");
        for air in (0..num_airs).rev() {
            stack.dup_named("heights_ptr", "h");
            if air > 0 {
                stack.emit(&format!("add.{air}"));
            }
            stack.emit("mem_load");
            stack.emit(&format!("mul.{stride}"));
            if air > 0 {
                stack.emit(&format!("add.{air}"));
            }
            stack.rename_top(&format!("k{air}"));
        }
        let heights_index = stack.index_of("heights_ptr");
        stack.movup(heights_index);
        stack.drop();
    }
    lines.push(format!("    # keys: [{}]", describe(&stack)));
    lines.push(stack.line(4));
    stack.ops.clear();

    // Fixed comparator network over stack indices 0..num_airs; the pointers below are untouched.
    lines.push(format!(
        "    # {} compare-exchanges; each leaves the smaller key at the lower index.",
        network.len()
    ));
    for &(lo, hi) in &network {
        stack.movup(hi);
        stack.movup(lo + 1);
        // [k_lo, k_hi, ...] -> [min, max, ...]. Placing the lower key first lets every
        // comparator whose lower index is nonzero avoid the extra swap hidden inside `u32gt`.
        stack.emit("dup.1 dup.1 u32lt cswap");
        let hi_name = stack.items.pop().expect("hi");
        let lo_name = stack.items.pop().expect("lo");
        stack.items.push(lo_name);
        stack.items.push(hi_name);
        // Place `min` one slot below its final position while `max` is still on the stack. Moving
        // `max` to `hi` then shifts `min` up into `lo`.
        stack.movdn(lo + 1);
        stack.movdn(hi);
        lines.push(format!("{}    # ({lo}, {hi})", stack.line(4)));
        stack.ops.clear();
    }
    // The network permutes key names; from here on the top key is proof position 0.
    for position in 0..num_airs {
        let name = stack.items.len() - 1 - position;
        stack.items[name] = format!("sorted{position}");
    }

    if !pointers_beneath {
        push_pointers(&mut stack);
        lines.push(format!("    # => [{}]", describe(&stack)));
        lines.push(stack.line(4));
        stack.ops.clear();
    }

    // Unpacking order: with word-batched `id_by_pos` stores, each full group of four positions
    // keeps its ids on the stack until `mem_storew_le` writes them, which needs the group's lowest
    // id on top. Each complete group is therefore visited from its highest position down. The
    // remainder (and every position without batching) is stored one id at a time.
    let batched_groups = if config.word_store_ids { num_airs / 4 } else { 0 };
    let mut order: Vec<usize> = Vec::with_capacity(num_airs);
    for group in 0..batched_groups {
        order.extend((4 * group..4 * group + 4).rev());
    }
    order.extend(4 * batched_groups..num_airs);
    lines.push("    # Unpack each sorted key into the maps.".into());
    for position in order.iter().copied() {
        let batched = position < 4 * batched_groups;
        // Lift the key above whatever sits on it, then reduce it to the AIR id.
        let key_index = stack.index_of(&format!("sorted{position}"));
        stack.movup(key_index);
        stack.emit(&format!("u32and.{}", stride - 1));
        let id = format!("id{position}");
        stack.rename_top(&id);
        if !batched {
            // id_by_pos[position] = id
            stack.dup_named(&id, "id_copy");
            stack.dup_named("ids_ptr", "addr");
            if position > 0 {
                stack.emit(&format!("add.{position}"));
            }
            stack.mem_store();
        }
        // pos_by_id[id] = position
        stack.push_const(position, "position");
        stack.dup_named(&id, "id_copy");
        stack.dup_named("pos_ptr", "base");
        stack.binary("add", "addr");
        stack.mem_store();
        if batched {
            // The id stays on the stack until its group of four is written as one word.
            let group_done = position % 4 == 0;
            if group_done {
                let group_start = position / 4 * 4;
                stack.dup_named("ids_ptr", "addr");
                if group_start > 0 {
                    stack.emit(&format!("add.{group_start}"));
                }
                stack.mem_storew_le();
                stack.dropw();
            }
        } else {
            stack.drop();
        }
        lines.push(format!("{}    # position {position} => [{}]", stack.line(4), describe(&stack)));
        stack.ops.clear();
    }

    // Tear down the table pointers.
    while stack.depth() > 0 {
        stack.drop();
    }
    lines.push(stack.line(4));
    if stack.out_of_reach {
        return Err(AceError::InvalidInputLayout {
            message: format!(
                "the proof-order pass for {num_airs} AIRs needs more than the 16 directly \
                 addressable stack slots"
            ),
        });
    }

    Ok(format!(
        "#! Derives the height-sorted proof order once and materializes its two inverse maps.\n\
         #!\n\
         #! Packs each AIR's key as `{stride} * log_height + instance_index`, sorts the keys with a \
         fixed\n\
         #! {comparators}-comparator network (data-oblivious: one `cswap` per comparator), and \
         unpacks them into\n\
         #! `id_by_pos` (instance index at each proof position) and `pos_by_id` (proof position of \
         each\n\
         #! instance). Equal heights order by instance index, exactly like the native \
         `TraceOrder`.\n\
         #!\n\
         #! Must run after every height has been bounded; keys are compared as u32 values.\n\
         #!\n\
         #! Inputs:  []\n\
         #! Outputs: []\n\
         pub proc stage_proof_order_maps\n\
         {body}\n\
         end\n",
        comparators = network.len(),
        body = lines.join("\n"),
    ))
}

fn describe(stack: &Stack) -> String {
    stack.items.iter().rev().cloned().collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ProofOrderMapsConfig<'static> {
        ProofOrderMapsConfig {
            num_airs: 4,
            heights_ptr: "exec.constants::air_trace_length_logs_ptr",
            pos_by_id_ptr: "exec.layout::proof_order_positions_ptr",
            id_by_pos_ptr: "exec.layout::proof_order_ids_ptr",
            word_load_heights: true,
            word_store_ids: true,
        }
    }

    #[test]
    fn renders_one_comparator_line_per_network_entry() {
        let masm = render_proof_order_maps(&config()).expect("renders");
        assert_eq!(masm.matches("u32lt cswap").count(), sorting_network(4).len());
        assert_eq!(masm.matches("u32and.15").count(), 4);
        assert!(masm.starts_with("#! Derives the height-sorted proof order"));
        assert!(masm.contains("pub proc stage_proof_order_maps"));
    }

    #[test]
    fn accepts_the_maximum_and_rejects_unsupported_air_counts() {
        let mut maximum = config();
        maximum.num_airs = MAX_ORDER_AIRS;
        maximum.word_load_heights = false;
        maximum.word_store_ids = true;
        render_proof_order_maps(&maximum).expect("the maximum supported AIR count must render");

        let mut too_few = config();
        too_few.num_airs = 1;
        assert!(render_proof_order_maps(&too_few).is_err());
        let mut too_many = config();
        too_many.num_airs = MAX_ORDER_AIRS + 1;
        assert!(render_proof_order_maps(&too_many).is_err());

        let mut invalid_word_load = config();
        invalid_word_load.num_airs = 8;
        assert!(render_proof_order_maps(&invalid_word_load).is_err());
    }
}
