//! Trace generation for the Poseidon2 chiplet.
//!
//! Callers hold a [`Poseidon2Requires`] accumulator and `require_*`
//! content into it. Each require eagerly runs the permutation oracle
//! (so the digest is known immediately), allocates a `perm_seq_id`
//! range, and returns an [`AbsorptionOutput`] (digest + range) the
//! caller can stamp inline as a foreign key.
//!
//! ## Interning
//!
//! `require_*` interns by digest. Poseidon2 is binding, so equal
//! digests = equal `(cap, blocks)`; identical content collapses to one
//! cycle range with `in_mult` tallied. The same digest queried later
//! via [`Poseidon2Requires::require_digest`] bumps `out_mult` on that
//! range. The multiplicities are plain `ProvideMult` counts pinned to their
//! In/Out consumer counts by bus balance (not range-checked — see
//! the design notes), so this is a true dedup: one span per
//! digest at any count, no cap and no spill.
//!
//! ## Trace generation
//!
//! [`generate_trace`] takes a `&Poseidon2Requires` and walks its
//! recorded absorptions in cycle-allocation order, emitting one
//! 16-row Poseidon2 cycle per block.

use alloc::{collections::BTreeMap, vec::Vec};
use core::ops::Range;

use miden_core::{Felt, chiplets::hasher::Hasher, field::QuadFelt, utils::RowMajorMatrix};

use crate::{
    logup::build_logup_aux_trace,
    relations::ProvideMult,
    transcript::poseidon2::{
        NUM_MAIN_COLS, NUM_WITNESSES, Poseidon2Air,
        digest::{P2Cap, P2Digest},
        math::STATE_WIDTH,
        program::PERIOD,
    },
};

// ABSORPTION OUTPUT
// ================================================================================================

/// Handle to one Poseidon2 permutation cycle — minted only by this
/// accumulator's cycle allocator, so cross-chiplet records reference
/// perms by handle and a raw sequence number never crosses a requires
/// boundary. Trace cells read the number via [`seq`](Self::seq).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PermSeqId(u32);

impl PermSeqId {
    /// The raw cycle sequence number (trace cells, bus messages).
    pub fn seq(self) -> u32 {
        self.0
    }

    /// Mint a handle from a raw sequence number, bypassing the
    /// accumulator — for bare-chiplet tests that lay rows with no
    /// backing Poseidon2 requires.
    #[cfg(test)]
    pub(crate) fn forged(seq: u32) -> Self {
        Self(seq)
    }
}

/// The contiguous perm-cycle span an absorption occupies — the head
/// carries `InCap`, the tail `OutRate0` and `Range16`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermSpan {
    start: u32,
    len: u32,
}

impl PermSpan {
    fn new(range: Range<u32>) -> Self {
        Self {
            start: range.start,
            len: range.end - range.start,
        }
    }

    /// The chain head's cycle (whose `InCap` is provided). For one-shot
    /// absorptions `head == tail`.
    pub fn head(self) -> PermSeqId {
        PermSeqId(self.start)
    }

    /// The chain tail's cycle (whose `OutRate0` and `Range16` are
    /// provided).
    pub fn tail(self) -> PermSeqId {
        PermSeqId(self.start + self.len - 1)
    }

    /// Cycles in the span (= the absorption's block count).
    pub fn n_cycles(self) -> u32 {
        self.len
    }
}

/// What a `Poseidon2Requires::require_*` call returns: the content
/// digest and the perm-cycle span the absorption occupies.
///
/// The digest is content-stable; the span is the one record for this
/// digest (interning hits share it).
#[derive(Debug, Clone)]
pub struct AbsorptionOutput {
    /// 4-felt digest = `state[0..4]` after the last block's permutation.
    /// Consumed via [`Poseidon2OutMsg`](super::Poseidon2OutMsg).
    pub digest: P2Digest,
    /// The cycles occupied by this absorption
    /// (`span.n_cycles() == blocks.len()`).
    pub span: PermSpan,
}

impl AbsorptionOutput {
    /// [`PermSpan::head`] of the absorption's span.
    pub fn head(&self) -> PermSeqId {
        self.span.head()
    }

    /// [`PermSpan::tail`] of the absorption's span.
    pub fn tail(&self) -> PermSeqId {
        self.span.tail()
    }
}

// PERMUTATION ORACLE
// ================================================================================================

/// Apply the Poseidon2 permutation to the input state. Thin wrapper
/// over [`Hasher::apply_permutation`], exposed for callers/tests that
/// want to verify the chiplet's output against the reference without
/// inspecting the trace.
pub fn apply_permutation(state_in: [Felt; STATE_WIDTH]) -> [Felt; STATE_WIDTH] {
    let mut state = state_in;
    Hasher::apply_permutation(&mut state);
    state
}

/// Run the absorption oracle on `(cap, blocks)`: returns the digest =
/// `state[0..4]` after the last block's permutation. Capacity is
/// threaded across blocks (cycle K+1's `state[8..12]` = cycle K's
/// row-15 capacity).
fn absorb_oracle(cap: P2Cap, blocks: &[([Felt; 4], [Felt; 4])]) -> P2Digest {
    let mut cap = cap.as_array();
    let mut digest = [Felt::ZERO; 4];
    for &(rate0, rate1) in blocks {
        let state_out = apply_permutation(state_from_chunks(rate0, rate1, cap));
        digest = chunk_from_state(&state_out, 0);
        cap = chunk_from_state(&state_out, 8);
    }
    P2Digest(digest)
}

// REQUIRES ACCUMULATOR
// ================================================================================================

#[derive(Debug, Clone)]
struct RecordedAbsorption {
    cap: P2Cap,
    blocks: Vec<([Felt; 4], [Felt; 4])>,
    /// Redundant with the `by_digest` key, but kept on the record for
    /// debug/audit and future introspection (e.g. iterating recorded
    /// absorptions without reverse-looking-up the digest map).
    #[allow(dead_code)]
    digest: P2Digest,
    range: Range<u32>,
    /// Consumer counts on the In / Out buses — plain `u32`, pinned to
    /// the consumer count by bus balance (no range check / cap).
    in_mult: ProvideMult,
    out_mult: ProvideMult,
}

/// Streaming accumulator for Poseidon2 cycles, content-addressed by
/// digest.
///
/// Callers `require_*` content into it and get back an
/// [`AbsorptionOutput`] (digest + `perm_seq_id` range) immediately.
/// Identical content shares one cycle range (interning) with
/// `in_mult` tallied; digest readers bump `out_mult` via
/// [`require_digest`](Self::require_digest). True dedup: one record per
/// digest, multiplicities unbounded `ProvideMult` counts pinned by balance.
#[derive(Debug, Clone, Default)]
pub struct Poseidon2Requires {
    /// Recorded absorptions in cycle-allocation order — one record per
    /// distinct digest. [`generate_trace`] walks this vector to emit the
    /// trace.
    absorptions: Vec<RecordedAbsorption>,
    /// `digest → index` of its record (the one each intern hit bumps).
    by_digest: BTreeMap<P2Digest, usize>,
    /// Running `perm_seq_id` allocator = total cycles laid so far.
    next_seq: u32,
}

impl Poseidon2Requires {
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute the absorption digest of `(cap, blocks)` without
    /// recording it. Useful for callers that intern at their own layer
    /// (e.g. a top-level orchestrator keys its dedup map on this
    /// digest) and want to skip the `require_absorption` call on hit.
    pub fn digest_of(cap: P2Cap, blocks: &[([Felt; 4], [Felt; 4])]) -> P2Digest {
        absorb_oracle(cap, blocks)
    }

    /// Register an absorption `(cap, blocks)`. Interns by digest: a hit
    /// bumps the open span's `in_mult` and returns its range; a miss
    /// lays a fresh span. Returns the digest + range. (`in_mult` is a
    /// plain `ProvideMult` count pinned by bus balance — no cap, no spill.)
    pub fn require_absorption(
        &mut self,
        cap: P2Cap,
        blocks: impl IntoIterator<Item = ([Felt; 4], [Felt; 4])>,
    ) -> AbsorptionOutput {
        let blocks: Vec<_> = blocks.into_iter().collect();
        assert!(!blocks.is_empty(), "absorption needs at least one block");
        let digest = absorb_oracle(cap, &blocks);

        if let Some(&idx) = self.by_digest.get(&digest) {
            let rec = &mut self.absorptions[idx];
            rec.in_mult += 1;
            return AbsorptionOutput {
                digest,
                span: PermSpan::new(rec.range.clone()),
            };
        }
        self.lay_span(cap, blocks, digest, 1, 0)
    }

    /// One-shot (single-block) absorption — the 2-to-1 / leaf shape
    /// transcript node hashing leans on. `rate0 || rate1` is the
    /// 8-felt preimage; `cap` is the capacity (e.g. `(tag, param_a,
    /// param_b, 0)` for transcript nodes).
    pub fn require_one_shot(
        &mut self,
        cap: P2Cap,
        rate0: [Felt; 4],
        rate1: [Felt; 4],
    ) -> AbsorptionOutput {
        self.require_absorption(cap, core::iter::once((rate0, rate1)))
    }

    /// Bump `out_mult` for the cycle that produced `digest` and return
    /// its span; the OutRate0 reader builds its consume from the chain
    /// tail. Returns `None` if the digest has never been required.
    /// (`out_mult` is a plain `ProvideMult` count pinned by bus balance —
    /// no cap, no spill.)
    pub fn require_digest(&mut self, digest: P2Digest) -> Option<PermSpan> {
        let &idx = self.by_digest.get(&digest)?;
        let rec = &mut self.absorptions[idx];
        rec.out_mult += 1;
        Some(PermSpan::new(rec.range.clone()))
    }

    /// Pure query — return the perm span currently open for `digest`,
    /// or `None` if it's never been required. Does not bump `out_mult`.
    pub fn lookup(&self, digest: P2Digest) -> Option<PermSpan> {
        self.by_digest
            .get(&digest)
            .map(|&idx| PermSpan::new(self.absorptions[idx].range.clone()))
    }

    /// Total cycles laid (= sum of `blocks.len()` across all records).
    pub fn total_cycles(&self) -> u32 {
        self.next_seq
    }

    fn lay_span(
        &mut self,
        cap: P2Cap,
        blocks: Vec<([Felt; 4], [Felt; 4])>,
        digest: P2Digest,
        in_mult: ProvideMult,
        out_mult: ProvideMult,
    ) -> AbsorptionOutput {
        let n = blocks.len() as u32;
        let range = self.next_seq..self.next_seq + n;
        self.next_seq += n;
        let idx = self.absorptions.len();
        self.absorptions.push(RecordedAbsorption {
            cap,
            blocks,
            digest,
            range: range.clone(),
            in_mult,
            out_mult,
        });
        self.by_digest.insert(digest, idx);
        AbsorptionOutput { digest, span: PermSpan::new(range) }
    }
}

// TRACE GENERATION
// ================================================================================================

/// Build the Poseidon2 chiplet's main trace from the recorded
/// absorptions. Each record is laid as `blocks.len()` consecutive
/// cycles starting at its allocated `range.start`; capacity is threaded
/// across blocks. Trailing cycles up to the next power of two are
/// inactive padding (`in_mult = out_mult = 0`).
///
/// The multiplicities are plain consumer counts, each pinned to its In /
/// Out consumer count by bus balance and *not* range-checked (so the
/// `activity = in + out` gate can't be wrapped — see
/// the design notes); the chiplet consumes no `Range16`.
pub fn generate_trace(requires: Poseidon2Requires) -> RowMajorMatrix<Felt> {
    let total_cycles = requires.next_seq as usize;
    let height = (total_cycles * PERIOD).next_power_of_two().max(PERIOD);
    let num_cycles = height / PERIOD;

    let mut trace = Vec::with_capacity(height * NUM_MAIN_COLS);

    for rec in &requires.absorptions {
        let mut cap = rec.cap.as_array();
        for (block_idx, &(rate0, rate1)) in rec.blocks.iter().enumerate() {
            let cycle_idx = rec.range.start as usize + block_idx;
            debug_assert_eq!(
                trace.len(),
                cycle_idx * PERIOD * NUM_MAIN_COLS,
                "cycles laid in contiguous global order",
            );
            let is_absorb = block_idx > 0;
            let state_in = state_from_chunks(rate0, rate1, cap);
            let state_out =
                write_cycle(&mut trace, cycle_idx, state_in, rec.in_mult, rec.out_mult, is_absorb);
            cap = chunk_from_state(&state_out, 8);
        }
    }

    // Padding cycles: only `perm_seq_id` (col 0) is non-zero — it must be
    // sequential to satisfy the constancy/step constraints. `in_mult =
    // out_mult = 0` makes the Poseidon2 In/Out emissions vacuate, and the
    // chiplet touches no other bus on padding.
    for cycle in total_cycles..num_cycles {
        let perm_seq_id =
            Felt::new(cycle as u64).expect("perm_seq_id fits in canonical Goldilocks");
        for _ in 0..PERIOD {
            trace.push(perm_seq_id); // COL_PERM_SEQ_ID
            trace.extend([Felt::ZERO; NUM_MAIN_COLS - 1]); // remaining columns
        }
    }

    debug_assert_eq!(trace.len(), height * NUM_MAIN_COLS);
    RowMajorMatrix::new(trace, NUM_MAIN_COLS)
}

fn state_from_chunks(rate0: [Felt; 4], rate1: [Felt; 4], cap: [Felt; 4]) -> [Felt; STATE_WIDTH] {
    let mut state = [Felt::ZERO; STATE_WIDTH];
    state[0..4].copy_from_slice(&rate0);
    state[4..8].copy_from_slice(&rate1);
    state[8..12].copy_from_slice(&cap);
    state
}

fn chunk_from_state(state: &[Felt; STATE_WIDTH], offset: usize) -> [Felt; 4] {
    state[offset..offset + 4].try_into().expect("4-felt slice fits")
}

/// Append one 16-row Poseidon2 cycle to `trace`, evolving the state step
/// by step. Returns the row-15 state (= permutation output).
fn write_cycle(
    trace: &mut Vec<Felt>,
    cycle_idx: usize,
    initial_state: [Felt; STATE_WIDTH],
    in_multiplicity: ProvideMult,
    out_multiplicity: ProvideMult,
    is_absorb: bool,
) -> [Felt; STATE_WIDTH] {
    let perm_seq_id =
        Felt::new(cycle_idx as u64).expect("perm_seq_id fits in canonical Goldilocks");
    let in_mult = Felt::from(in_multiplicity);
    let out_mult = Felt::from(out_multiplicity);
    let absorb = Felt::from(is_absorb as u8);

    let mut state = initial_state;

    // Row 0: initial state, no witnesses.
    push_row(trace, &state, &[Felt::ZERO; 3], perm_seq_id, in_mult, out_mult, absorb);

    // Step from row 0 to row 1: init linear + ext1.
    Hasher::apply_matmul_external(&mut state);
    Hasher::add_rc(&mut state, &Hasher::ARK_EXT_INITIAL[0]);
    Hasher::apply_sbox(&mut state);
    Hasher::apply_matmul_external(&mut state);

    // Rows 1-3: single ext (ARK_EXT_INITIAL[1..4]), no witnesses.
    for r in 1..=3 {
        push_row(trace, &state, &[Felt::ZERO; 3], perm_seq_id, in_mult, out_mult, absorb);
        Hasher::add_rc(&mut state, &Hasher::ARK_EXT_INITIAL[r]);
        Hasher::apply_sbox(&mut state);
        Hasher::apply_matmul_external(&mut state);
    }

    // Rows 4-10: packed 3x internal rounds, 3 witnesses each.
    for triple in 0..7_usize {
        let base = triple * 3;
        let pre_state = state;
        let mut witnesses = [Felt::ZERO; 3];
        for (k, witness) in witnesses.iter_mut().enumerate() {
            let sbox_in = state[0] + Hasher::ARK_INT[base + k];
            let sbox_out = sbox_in.exp_const_u64::<7>();
            *witness = sbox_out;
            state[0] = sbox_out;
            Hasher::matmul_internal(&mut state, Hasher::MAT_DIAG);
        }
        push_row(trace, &pre_state, &witnesses, perm_seq_id, in_mult, out_mult, absorb);
    }

    // Row 11: int22 + ext5 merged. Witness w[0] only.
    let pre_state = state;
    let w0_in = state[0] + Hasher::ARK_INT[21];
    let w0 = w0_in.exp_const_u64::<7>();
    state[0] = w0;
    Hasher::matmul_internal(&mut state, Hasher::MAT_DIAG);
    Hasher::add_rc(&mut state, &Hasher::ARK_EXT_TERMINAL[0]);
    Hasher::apply_sbox(&mut state);
    Hasher::apply_matmul_external(&mut state);
    push_row(
        trace,
        &pre_state,
        &[w0, Felt::ZERO, Felt::ZERO],
        perm_seq_id,
        in_mult,
        out_mult,
        absorb,
    );

    // Rows 12-14: single ext (ARK_EXT_TERMINAL[1..4]), no witnesses.
    for r in 1..=3 {
        push_row(trace, &state, &[Felt::ZERO; 3], perm_seq_id, in_mult, out_mult, absorb);
        Hasher::add_rc(&mut state, &Hasher::ARK_EXT_TERMINAL[r]);
        Hasher::apply_sbox(&mut state);
        Hasher::apply_matmul_external(&mut state);
    }

    // Row 15: boundary — final state, no transition.
    push_row(trace, &state, &[Felt::ZERO; 3], perm_seq_id, in_mult, out_mult, absorb);

    state
}

/// Append a single row's main columns in column order: perm_seq_id,
/// in_mult, out_mult, is_absorb, state[12], witnesses[3].
fn push_row(
    trace: &mut Vec<Felt>,
    state: &[Felt; STATE_WIDTH],
    witnesses: &[Felt; NUM_WITNESSES],
    perm_seq_id: Felt,
    in_multiplicity: Felt,
    out_multiplicity: Felt,
    is_absorb: Felt,
) {
    trace.extend([perm_seq_id, in_multiplicity, out_multiplicity, is_absorb]);
    trace.extend(*state);
    trace.extend(*witnesses);
}

// AUX TRACE
// ================================================================================================

/// Build the Poseidon2 chiplet's aux trace via the generic
/// [`build_logup_aux_trace`] driver.
pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    build_logup_aux_trace(&Poseidon2Air, main, challenges)
}
