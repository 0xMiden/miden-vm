//! Trace generation for the Keccak-node chiplet.
//!
//! Callers hold a [`KeccakNodeRequires`] accumulator and submit raw
//! input byte slices via [`KeccakNodeRequires::require`]. The
//! accumulator dedupes by Keccak digest (`(content, len_bytes)`
//! identity) — duplicate inputs bump `out_mult` on the existing row
//! and lay no new sponge / chunk / P2 work. On miss it delegates to
//! the caller-supplied [`SpongeRequires`], computes the digest-chunk
//! hash `H_digest_chunks` and the transcript-DAG hash `H_keccak` via
//! [`Poseidon2Requires`], and records a [`KeccakNodeInvocation`]
//! [`generate_trace`] later stamps into one row of the 30-column
//! main trace.
//!
//! The fall-out wiring:
//! - `chunk_seq_id_head` / `chunk_ptr` and `sponge_seq_id_head` come from the `SpongeOutput`.
//! - `perm_seq_id_chunks` is the chunk-content P2 absorption head.
//! - `perm_seq_id_digest_chunks` and `perm_seq_id_keccak` come from the two one-shot P2 absorptions
//!   this layer drives.

use alloc::{collections::BTreeMap, vec, vec::Vec};

use miden_core::{
    Felt,
    deferred::{Digest, Node},
    field::QuadFelt,
    utils::RowMajorMatrix,
};
use miden_precompiles::Keccak256Precompile;

use crate::{
    hash::{
        chunk::trace::{ChunkRequires, ChunkSeqId},
        keccak::{
            digest::KeccakDigest,
            node::{KeccakNodeAir, NUM_HASH, NUM_MAIN_COLS},
            round::RoundRequires,
            sponge::trace::{
                Invocation as SpongeInvocation, SpongeRequires, SpongeSeqId, keccak_oracle,
            },
        },
    },
    logup::build_logup_aux_trace,
    primitives::byte_pair_lut::BytePairLutRequires,
    relations::ProvideMult,
    transcript::poseidon2::{
        digest::{P2Cap, P2Digest},
        trace::{PermSeqId, Poseidon2Requires},
    },
};

/// One Keccak invocation as seen by this chiplet — everything bundled
/// into one transcript-DAG node.
///
/// `d` and `h_input_chunks` come from elsewhere (the sponge's reference and
/// the chunk chiplet's Poseidon2 absorption respectively); see
/// the design notes for how they line up with the buses.
#[derive(Debug, Clone)]
pub struct KeccakNodeInvocation {
    /// Message byte length.
    pub len_bytes: u32,
    /// The 4-lane Keccak-256 digest, laid out as
    /// `[lo_0, hi_0, lo_1, hi_1, lo_2, hi_2, lo_3, hi_3]` (lane `j` =
    /// `(d[2j], d[2j+1])` as u32 halves on Memory64).
    pub d: [u32; 8],
    /// The chunk chain's cumulative Poseidon2 digest at its tail (= the
    /// `OutRate0` value read from the chunk chiplet's chain end).
    pub h_input_chunks: [Felt; 4],
    /// Head of this invocation's chunk chain in the chunk chiplet's
    /// namespace ([`ChunkSeqId::ptr`] gives the word address the sponge
    /// sees).
    pub chunk_seq_id_head: ChunkSeqId,
    /// P2 cycle at the head of the chunks-absorption chain.
    pub perm_seq_id_chunks: PermSeqId,
    /// P2 cycle for hashing the Keccak digest as a semantic chunk.
    pub perm_seq_id_digest_chunks: PermSeqId,
    /// P2 cycle for the keccak-node hashing
    /// (= `Poseidon2(H_input_chunks || H_digest_chunks || cap_keccak256_assertion(len_bytes))`).
    pub perm_seq_id_keccak: PermSeqId,
    /// Sponge invocation start (the sponge's row at the first row of
    /// this invocation).
    pub sponge_seq_id_head: SpongeSeqId,
    /// Downstream consumer count for the `Binding(H_keccak, True)`
    /// provide on this row. Range-checked to `[0, 2^16)`; the AIR's
    /// `(1 − act) · out_mult = 0` constraint pins it to 0 on
    /// inactive rows. A plain `u32` count — pinned to the `Binding`
    /// consumer count by bus balance, not range-checked.
    pub out_mult: ProvideMult,
}

impl KeccakNodeInvocation {
    /// Sponge perms = Keccak blocks = `floor(len_bytes / 136) + 1`
    /// under multi-rate-10*1 padding.
    pub fn n_sponge_perms(&self) -> u64 {
        u64::from(self.len_bytes) / 136 + 1
    }

    /// Chunks in this invocation's chain = `max(1, ceil(len_bytes / 32))`.
    /// Empty input still carries one canonical zero chunk so the
    /// `H_input_chunks` tail read at `perm_seq_id_chunks + n_chunks − 1`
    /// stays in range (= `perm_seq_id_chunks`).
    pub fn n_chunks(&self) -> u64 {
        u64::from(self.len_bytes).div_ceil(Node::PACKED_BYTES_PER_CHUNK as u64).max(1)
    }
}

/// Build the Keccak-node chiplet's main trace from the recorded
/// invocations. One row per record (interning handled at the
/// accumulator); trailing rows up to the next power of two are
/// inactive padding. `out_mult` is a plain consumer count, pinned to
/// the `Binding` consumer count by bus balance (no range check — see
/// the design notes), so padding rows (`out_mult = 0`) touch
/// no bus.
pub fn generate_trace(requires: KeccakNodeRequires) -> RowMajorMatrix<Felt> {
    let active_rows = requires.total_rows() as usize;
    let height = active_rows.next_power_of_two().max(2);
    let mut trace = Vec::with_capacity(height * NUM_MAIN_COLS);

    for rec in &requires.records {
        push_row(&mut trace, &rec.invocation);
    }
    trace.resize(height * NUM_MAIN_COLS, Felt::ZERO);

    RowMajorMatrix::new(trace, NUM_MAIN_COLS)
}

/// Older entry-point used by the standalone keccak-node tests, which
/// build [`KeccakNodeInvocation`]s by hand without the chunk / sponge /
/// P2 stack (the AIR's local constraints + LogUp σ recurrence are
/// agnostic to where the digest bytes come from).
pub fn generate_trace_from_invocations(
    invocations: &[KeccakNodeInvocation],
) -> RowMajorMatrix<Felt> {
    let height = invocations.len().next_power_of_two().max(2);
    let mut trace = Vec::with_capacity(height * NUM_MAIN_COLS);

    for inv in invocations {
        push_row(&mut trace, inv);
    }

    trace.resize(height * NUM_MAIN_COLS, Felt::ZERO);
    RowMajorMatrix::new(trace, NUM_MAIN_COLS)
}

/// Append one invocation's row to `trace` in column order: act,
/// sponge_seq_id_head, n_sponge_perms, chunk_seq_id_head, n_chunks,
/// perm_seq_id_chunks, len_bytes, perm_seq_id_digest_chunks, perm_seq_id_keccak,
/// d[8], h_input_chunks[4], h_digest_chunks[4], h_keccak[4], out_mult.
fn push_row(trace: &mut Vec<Felt>, inv: &KeccakNodeInvocation) {
    let len_bytes = Felt::from(inv.len_bytes);
    let d_felts: [Felt; 8] = inv.d.map(Felt::from);
    let h_digest_chunks = Node::chunks(vec![d_felts])
        .expect("Keccak digest chunks are non-empty")
        .digest()
        .into_elements();
    let h_keccak = Keccak256Precompile::assert_node(
        inv.len_bytes,
        Digest::new(inv.h_input_chunks),
        Digest::new(h_digest_chunks),
    )
    .digest()
    .into_elements();

    trace.extend([
        Felt::ONE,
        Felt::from(inv.sponge_seq_id_head.seq()),
        Felt::new(inv.n_sponge_perms()).expect("n_sponge_perms fits"),
        Felt::from(inv.chunk_seq_id_head.seq()),
        Felt::new(inv.n_chunks()).expect("n_chunks fits"),
        Felt::from(inv.perm_seq_id_chunks.seq()),
        len_bytes,
        Felt::from(inv.perm_seq_id_digest_chunks.seq()),
        Felt::from(inv.perm_seq_id_keccak.seq()),
    ]);
    trace.extend(d_felts);
    trace.extend(inv.h_input_chunks);
    trace.extend(h_digest_chunks);
    trace.extend(h_keccak);
    trace.extend([Felt::from(inv.out_mult)]);
}

// REQUIRES ACCUMULATOR
// ================================================================================================

/// What a `KeccakNodeRequires::require` call returns: the Keccak
/// digest of this invocation, the transcript-DAG node hash
/// `H_keccak` (the `Binding` key) , and the row of the keccak-node
/// trace where the `Binding(H_keccak, True)` provide fires.
#[derive(Debug, Clone)]
pub struct KeccakNodeOutput {
    pub keccak_digest: KeccakDigest,
    pub h_keccak: P2Digest,
    pub node_row: u32,
}

#[derive(Debug, Clone)]
struct NodeRecord {
    invocation: KeccakNodeInvocation,
    h_keccak: P2Digest,
    #[allow(dead_code)]
    keccak_digest: KeccakDigest,
}

/// Top-level dedup point for Keccak invocations. Pairs with
/// [`SpongeRequires`] (one-to-one below it) and
/// [`ChunkRequires`] (one chunk-tape segment per sponge invocation).
/// Interning by [`KeccakDigest`] collapses two `(input, len_bytes)`-
/// identical calls into one row with `out_mult` tallied — true dedup,
/// one row per digest at any consumer count (no range-check, no spill).
#[derive(Debug, Clone, Default)]
pub struct KeccakNodeRequires {
    records: Vec<NodeRecord>,
    /// `keccak_digest → index of its record` (each hit bumps `out_mult`).
    by_keccak: BTreeMap<KeccakDigest, usize>,
    next_row: u32,
}

impl KeccakNodeRequires {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a Keccak invocation. Empty input is supported: it absorbs
    /// one pad block (`keccak256("")`) and the chunk layer lays one
    /// canonical zero chunk, so the chunk-content P2 chain tail this node
    /// reads for `H_input_chunks` always exists. The zero chunk is consumed by
    /// the sponge as a full garbage-tail (the pad fires at byte 0), so it
    /// doesn't perturb the digest.
    pub fn require(
        &mut self,
        input: &[u8],
        sponge_req: &mut SpongeRequires,
        chunk_req: &mut ChunkRequires,
        round_req: &mut RoundRequires,
        bpl_req: &mut BytePairLutRequires,
        p2: &mut Poseidon2Requires,
    ) -> KeccakNodeOutput {
        let keccak_digest = keccak_oracle(input);

        // True dedup: an identical input bumps the existing row's
        // consumer count (`out_mult` is a plain `usize`, pinned to the
        // count by bus balance — no `2^16` cap, no row split).
        if let Some(&idx) = self.by_keccak.get(&keccak_digest) {
            let rec = &mut self.records[idx];
            rec.invocation.out_mult += 1;
            return KeccakNodeOutput {
                keccak_digest,
                h_keccak: rec.h_keccak,
                node_row: idx as u32,
            };
        }

        // Miss path: full allocation through sponge + 2× P2 one-shots.
        let sponge_inv = SpongeInvocation { input: input.to_vec() };
        let sponge_out = sponge_req.require(&sponge_inv, chunk_req, round_req, bpl_req, p2);
        debug_assert_eq!(sponge_out.keccak_digest, keccak_digest);

        // h_input_chunks = the chunk-content P2 digest. The Keccak-node AIR
        // reads it from `Poseidon2Out` at `perm_seq_id_chunks +
        // n_chunks − 1` (the chunks-absorption chain tail); we bump
        // P2's out_mult on that range here so the bus closes.
        let h_input_chunks_digest = sponge_out.chunk_content_digest;
        let h_input_chunks: [Felt; NUM_HASH] = h_input_chunks_digest.as_array();
        let _ = p2.require_digest(h_input_chunks_digest);

        // H_digest_chunks = Poseidon2(D || cap_chunk). This is a semantic
        // one-chunk digest commitment, not a physical extra ChunkAir row.
        let d_felts = sponge_out.keccak_digest.to_felts();
        let d_rate0: [Felt; 4] = d_felts[0..4].try_into().expect("rate0 slice");
        let d_rate1: [Felt; 4] = d_felts[4..8].try_into().expect("rate1 slice");
        let digest_chunks_out = p2.require_one_shot(P2Cap::chunk(), d_rate0, d_rate1);
        let h_digest_chunks = digest_chunks_out.digest;
        // OutRate0 read at perm_seq_id_digest_chunks — bump.
        let _ = p2.require_digest(h_digest_chunks);

        // H_keccak = Poseidon2(H_input_chunks || H_digest_chunks || cap_keccak)
        let len_bytes = u32::try_from(input.len()).expect("len_bytes fits in u32");
        let keccak_out = p2.require_one_shot(
            P2Cap::keccak256_assertion(len_bytes),
            h_input_chunks,
            h_digest_chunks.as_array(),
        );
        let h_keccak = keccak_out.digest;
        // OutRate0 read at perm_seq_id_keccak — bump.
        let _ = p2.require_digest(h_keccak);

        let invocation = KeccakNodeInvocation {
            len_bytes,
            d: sponge_out.keccak_digest.to_u32s(),
            h_input_chunks,
            chunk_seq_id_head: sponge_out.chunk_head,
            perm_seq_id_chunks: sponge_out.chunk_content_perm_span.head(),
            perm_seq_id_digest_chunks: digest_chunks_out.head(),
            perm_seq_id_keccak: keccak_out.head(),
            sponge_seq_id_head: sponge_out.sponge_head,
            out_mult: 1,
        };

        let node_row = self.next_row;
        self.next_row += 1;
        let idx = self.records.len();
        self.records.push(NodeRecord { invocation, h_keccak, keccak_digest });
        self.by_keccak.insert(keccak_digest, idx);

        KeccakNodeOutput { keccak_digest, h_keccak, node_row }
    }

    /// Total rows laid (= active rows in the keccak-node main trace).
    pub fn total_rows(&self) -> u32 {
        self.next_row
    }
}

// PROVER
// ================================================================================================

/// Witness-bearing companion to [`KeccakNodeAir`]. The aux trace is
/// produced by the generic [`build_logup_aux_trace`] driver.
pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    build_logup_aux_trace(&KeccakNodeAir, main, challenges)
}
