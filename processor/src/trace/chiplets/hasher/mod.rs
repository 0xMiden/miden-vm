use alloc::{collections::BTreeMap, vec::Vec};
#[cfg(feature = "std")]
use std::time::Instant;

use miden_air::trace::{
    and8_lookup::{
        BYTE_LOOKUP_COUNT_LEN, BYTE_LOOKUP_KIND_AND8, BYTE_LOOKUP_KIND_BLAKEG_ROT7,
        BYTE_LOOKUP_KIND_BLAKEG_ROT12, BYTE_PAIR_ROWS, byte_lookup_result,
    },
    blakeg_compression::{
        BLAKEG_COMPRESSION_CYCLE_LEN, BlakeGByteLookup, ByteLookupRecorder,
        NUM_BLAKEG_COMPRESSION_COLS, TraceMode as BlakeGCompressionTraceMode,
        write_felt_trace_block_into_zeroed_with_lookups as write_blakeg_felt_trace_block,
    },
    chiplets::hasher::{
        CONTROLLER_TRACE_ALIGNMENT, DIGEST_RANGE, HASH_ABSORB, LINEAR_HASH, MP_VERIFY,
        MR_UPDATE_NEW, MR_UPDATE_OLD, RATE_LEN, STATE_WIDTH, Selectors,
    },
};
use miden_core::chiplets::{blakeg, hasher::compress_state};
use rayon::prelude::*;

use crate::{ContextId, RowIndex};

use super::{
    ChipletTraceFragment, Felt, HasherState, MerklePath, MerkleRootUpdate, ONE, OpBatch,
    RangeChecker, Word as Digest, ZERO,
};

mod trace;
use trace::HasherTrace;
mod and8_trace;
pub(crate) use and8_trace::build_and8_lookup_trace;

#[cfg(test)]
#[allow(clippy::needless_range_loop)]
mod tests;

// HASH PROCESSOR
// ================================================================================================

/// Key type for digest-based lookups.
type DigestKey = [u64; 4];

/// Key type for BlakeG compression input states.
type StateKey = [u64; STATE_WIDTH];

/// Output shape requested from one BlakeG compression block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CompressionOutput {
    /// Packed digest output used by the VM hash operations.
    Packed,
    /// Direct 16-lane XOF output used by AEAD stream rows.
    AeadXof { clk: Felt },
}

/// Deduplication key for standalone BlakeG compression blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CompressionRequestKey {
    state: StateKey,
    output: CompressionOutput,
}

/// Converts a Digest to a DigestKey for BTreeMap lookup.
fn digest_to_key(digest: Digest) -> DigestKey {
    let elems = digest.as_elements();
    core::array::from_fn(|i| elems[i].as_canonical_u64())
}

/// Converts a HasherState to a StateKey for BTreeMap lookup.
fn state_to_key(state: &HasherState) -> StateKey {
    core::array::from_fn(|i| state[i].as_canonical_u64())
}

/// Hash chiplet for the VM.
///
/// The controller records one row per compression request. Hash rows carry
/// `block[8] || cv_in[4]` in the state columns and `cv_out[4]` in row data; Merkle rows carry
/// `block[8] || cv_out[4]` plus their path-index data. The standalone BlakeG compression AIR
/// executes one block per unique input state, with multiplicity tracked by the
/// compression-link bus.
#[derive(Debug, Default)]
pub struct Hasher {
    trace: HasherTrace,
    /// Maps block digest -> (op_start, op_end) for memoized controller traces.
    memoized_trace_map: BTreeMap<DigestKey, (usize, usize)>,
    /// Maps (input state, output shape) -> multiplicity for compression deduplication.
    /// During trace generation, one standalone BlakeG block is emitted per entry.
    compression_request_map: BTreeMap<CompressionRequestKey, u64>,
    /// Monotonically increasing counter for MRUPDATE domain separation.
    mrupdate_id: Felt,
    /// Whether the controller trace has been finalized.
    finalized: bool,
}

impl Hasher {
    // STATE ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the length of the execution trace.
    ///
    /// Before finalization, this returns an estimate based on the controller region length.
    /// The estimate is verified against the actual length during `fill_trace()` via a
    /// debug assertion.
    pub(super) fn trace_len(&self) -> usize {
        if self.finalized {
            self.trace.trace_len()
        } else {
            self.estimate_trace_len()
        }
    }

    /// Returns the layout of the hasher region as `(controller_len, compression_len)`.
    ///
    /// `controller_len` includes the padding rows that `finalize_trace()` will later append to
    /// align the following chiplet section. `compression_len` is the standalone BlakeG AIR length,
    /// before power-of-two trace padding.
    pub(super) fn region_lengths(&self) -> (usize, usize) {
        debug_assert!(!self.finalized, "region_lengths must be called before finalization");
        let controller_len = self.trace.trace_len().next_multiple_of(CONTROLLER_TRACE_ALIGNMENT);
        let compression_len = self.blakeg_compression_trace_len();
        (controller_len, compression_len)
    }

    /// Returns the unpadded BlakeG-compression AIR trace length.
    ///
    /// Wrapped lookup accumulation lets real compression blocks occupy the full logical trace.
    /// Power-of-two padding may still add zero-multiplicity dummy blocks later.
    pub(super) fn blakeg_compression_trace_len(&self) -> usize {
        if self.finalized {
            0
        } else {
            self.compression_request_map.len() * BLAKEG_COMPRESSION_CYCLE_LEN
        }
    }

    /// Adds range-check requests emitted by the standalone BlakeG compression AIR.
    pub(super) fn append_blakeg_range_checks(
        &self,
        blakeg_height: usize,
        range: &mut RangeChecker,
    ) {
        debug_assert_eq!(blakeg_height % BLAKEG_COMPRESSION_CYCLE_LEN, 0);
        debug_assert!(!self.finalized, "range checks must be collected before finalization");

        let block_count = blakeg_height / BLAKEG_COMPRESSION_CYCLE_LEN;
        debug_assert!(
            block_count >= self.compression_request_map.len(),
            "BlakeG height is too short for recorded compression requests",
        );

        for key in self.compression_request_map.keys() {
            append_message_row_range_checks(&key.state, range);
        }

        append_zero_message_row_range_checks(
            block_count - self.compression_request_map.len(),
            range,
        );
    }

    /// Estimates the controller trace length before finalization.
    ///
    /// This must match the actual length produced by `finalize_trace()`. The invariant is
    /// verified by a debug assertion in `fill_trace()`.
    fn estimate_trace_len(&self) -> usize {
        let (controller_len, _) = self.region_lengths();
        controller_len
    }

    // HASHING METHODS
    // --------------------------------------------------------------------------------------------

    /// Applies one packed BlakeG compression.
    pub fn bcompress(&mut self, state: HasherState) -> (Felt, HasherState) {
        let addr = self.trace.next_row_addr();

        let compressed = self.append_hash_compression(LINEAR_HASH, state, true);

        (addr, compressed)
    }

    /// Applies one BlakeG compression and returns all 16 raw output lanes.
    pub fn compress_aead_xof(
        &mut self,
        _ctx: ContextId,
        clk: RowIndex,
        state: HasherState,
    ) -> [Felt; 16] {
        self.record_compression_request(
            &state,
            CompressionOutput::AeadXof { clk: Felt::from(clk) },
        );
        blakeg::compress_raw_xof_lanes(&state).map(Felt::from_u32)
    }

    /// Computes hash(h1, h2) for a control block and returns the result.
    ///
    /// Returns (addr, digest).
    pub fn hash_control_block(
        &mut self,
        h1: Digest,
        h2: Digest,
        domain: Felt,
        expected_hash: Digest,
    ) -> (Felt, Digest) {
        if let Some(memoized) = self.replay_memoized_trace(expected_hash) {
            return memoized;
        }

        let addr = self.trace.next_row_addr();
        let op_start = self.trace.next_op_index();
        let init_state = init_state_from_words_with_domain(&h1, &h2, domain);
        let compressed = self.append_hash_compression(LINEAR_HASH, init_state, true);

        self.insert_to_memoized_trace_map(op_start, expected_hash);
        let result = get_digest(&compressed);
        (addr, result)
    }

    /// Computes a sequential hash of all operation batches and returns the result.
    ///
    /// Returns (addr, digest).
    pub fn hash_basic_block(
        &mut self,
        op_batches: &[OpBatch],
        expected_hash: Digest,
    ) -> (Felt, Digest) {
        // Check memoization
        if let Some(memoized) = self.replay_memoized_trace(expected_hash) {
            return memoized;
        }

        let addr = self.trace.next_row_addr();
        let op_start = self.trace.next_op_index();
        let num_batches = op_batches.len();
        let n = u32::try_from(num_basic_block_hash_groups(op_batches))
            .expect("felt length must fit in u32");
        let init_state = init_state(op_batches[0].groups(), n);

        if num_batches == 1 {
            let compressed = self.append_hash_compression(LINEAR_HASH, init_state, true);
            self.insert_to_memoized_trace_map(op_start, expected_hash);
            let result = get_digest(&compressed);
            return (addr, result);
        }

        let mut state = self.append_hash_compression(LINEAR_HASH, init_state, false);

        for batch in op_batches.iter().take(num_batches - 1).skip(1) {
            absorb_into_state(&mut state, batch.groups());
            state = self.append_hash_compression(HASH_ABSORB, state, false);
        }

        absorb_into_state(&mut state, op_batches[num_batches - 1].groups());
        let compressed = self.append_hash_compression(HASH_ABSORB, state, true);

        self.insert_to_memoized_trace_map(op_start, expected_hash);
        let result = get_digest(&compressed);
        (addr, result)
    }

    /// Performs Merkle path verification computation and records its execution trace.
    ///
    /// Returns (addr, root).
    pub fn build_merkle_root(
        &mut self,
        value: Digest,
        path: &MerklePath,
        index: Felt,
    ) -> (Felt, Digest) {
        let addr = self.trace.next_row_addr();
        let root = self.verify_merkle_path(
            value,
            path,
            index.as_canonical_u64(),
            MerklePathContext::MpVerify,
        );
        (addr, root)
    }

    /// Performs Merkle root update computation and records its execution trace.
    ///
    /// Increments the mrupdate_id counter. Both MV and MU legs share the same id.
    pub fn update_merkle_root(
        &mut self,
        old_value: Digest,
        new_value: Digest,
        path: &MerklePath,
        index: Felt,
    ) -> MerkleRootUpdate {
        self.mrupdate_id += ONE;

        let address = self.trace.next_row_addr();
        let index = index.as_canonical_u64();

        let old_root =
            self.verify_merkle_path(old_value, path, index, MerklePathContext::MrUpdateOld);
        let new_root =
            self.verify_merkle_path(new_value, path, index, MerklePathContext::MrUpdateNew);

        MerkleRootUpdate { address, old_root, new_root }
    }

    // TRACE GENERATION
    // --------------------------------------------------------------------------------------------

    /// Finalizes and fills the controller and BlakeG-compression traces.
    ///
    /// Finalization pads the controller region and materializes one BlakeG block
    /// per unique input state. Trace-height padding may append zero-multiplicity dummy blocks.
    pub(super) fn fill_trace(
        mut self,
        trace: &mut ChipletTraceFragment,
        blakeg_trace: &mut [Felt],
    ) -> Vec<u64> {
        let compression_request_count = self.compression_request_map.len();
        let controller_estimate = self.estimate_trace_len();
        let blakeg_rows = self.blakeg_compression_trace_len();
        profile_event(format_args!(
            "hasher.shape controller_rows={controller_estimate} compression_requests={compression_request_count} blakeg_rows={blakeg_rows}"
        ));

        if !self.finalized {
            let estimated_len = self.estimate_trace_len();
            profile_scope("hasher.finalize_controller", || self.finalize_trace());
            debug_assert_eq!(
                estimated_len,
                self.trace.trace_len(),
                "hasher trace length estimate ({}) diverged from actual ({})",
                estimated_len,
                self.trace.trace_len(),
            );
        }
        let compression_requests = core::mem::take(&mut self.compression_request_map);
        profile_scope("hasher.controller.fill_trace", || self.trace.fill_trace(trace));
        profile_scope("hasher.blakeg_compression.fill_trace", || {
            fill_blakeg_compression_trace(compression_requests, blakeg_trace)
        })
    }

    /// Finalizes the controller trace by padding it to the chiplet alignment boundary.
    fn finalize_trace(&mut self) {
        if self.finalized {
            return;
        }

        self.trace.pad_to_controller_boundary(self.mrupdate_id);

        self.finalized = true;
    }

    // CORE HELPER: CONTROLLER COMPRESSION
    // --------------------------------------------------------------------------------------------

    /// Appends a hash-controller compression row and records the BlakeG request.
    fn append_hash_compression(
        &mut self,
        selectors: Selectors,
        state: HasherState,
        is_final: bool,
    ) -> HasherState {
        let mut compressed = state;
        compress_state(&mut compressed);

        let digest = get_digest(&compressed).into();
        let op_final = if is_final { ONE } else { ZERO };
        self.trace
            .append_controller_row(selectors, &state, digest, op_final, self.mrupdate_id);

        self.record_compression_request(&state, CompressionOutput::Packed);

        compressed
    }

    /// Appends a Merkle-controller compression row and records the BlakeG request.
    fn append_merkle_compression(
        &mut self,
        selectors: Selectors,
        input_state: HasherState,
        node_index: u64,
        is_start: bool,
        is_final: bool,
    ) -> HasherState {
        let mut compressed = input_state;
        compress_state(&mut compressed);

        let mut row_state = input_state;
        row_state[8..12].copy_from_slice(get_digest(&compressed).as_elements());
        let row_data = [
            Felt::new_unchecked(node_index),
            Felt::new_unchecked(node_index >> 1),
            if is_start { ONE } else { ZERO },
            ZERO,
        ];
        let op_final = if is_final { ONE } else { ZERO };
        self.trace.append_controller_row(
            selectors,
            &row_state,
            row_data,
            op_final,
            self.mrupdate_id,
        );

        self.record_compression_request(&input_state, CompressionOutput::Packed);

        compressed
    }

    // MERKLE PATH HELPERS
    // --------------------------------------------------------------------------------------------

    /// Computes a root of the provided Merkle path in the specified context.
    fn verify_merkle_path(
        &mut self,
        value: Digest,
        path: &MerklePath,
        mut index: u64,
        context: MerklePathContext,
    ) -> Digest {
        assert!(!path.is_empty(), "path is empty");
        assert!(
            index.checked_shr(path.len() as u32).unwrap_or(0) == 0,
            "invalid index for the path"
        );

        let main_selectors = context.main_selectors();
        let mut root = value;

        let last_idx = path.len() - 1;
        for (i, &sibling) in path.iter().enumerate() {
            let b_i = index & 1;
            let state = build_merge_state(&root, &sibling, b_i);

            let compressed =
                self.append_merkle_compression(main_selectors, state, index, i == 0, i == last_idx);

            root = get_digest(&compressed);
            index >>= 1;
        }

        root
    }

    // COMPRESSION DEDUPLICATION
    // --------------------------------------------------------------------------------------------

    /// Records a BlakeG request keyed by input state and output shape.
    fn record_compression_request(&mut self, state: &HasherState, output: CompressionOutput) {
        let key = CompressionRequestKey { state: state_to_key(state), output };
        *self.compression_request_map.entry(key).or_insert(0) += 1;
    }

    // MEMOIZATION
    // --------------------------------------------------------------------------------------------

    /// Attempts to replay a memoized controller trace for the given expected hash.
    ///
    /// If a memoized trace exists, re-pushes the source ops with the current `mrupdate_id`,
    /// re-registers compression requests from copied controller rows, and returns
    /// `Some((addr, digest))`. Otherwise returns `None`.
    fn replay_memoized_trace(&mut self, expected_hash: Digest) -> Option<(Felt, Digest)> {
        let (op_start, op_end) = match self.get_memoized_trace(expected_hash) {
            Some(&(s, e)) => (s, e),
            None => return None,
        };

        let addr = self.trace.next_row_addr();
        let (last_state, input_states) =
            self.trace.replay_ops_range(op_start..op_end, self.mrupdate_id);

        for input_state in input_states {
            self.record_compression_request(&input_state, CompressionOutput::Packed);
        }

        let result = get_digest(&last_state);
        Some((addr, result))
    }

    /// Returns the start and end op indices of a memoized block trace, if it exists.
    fn get_memoized_trace(&self, hash: Digest) -> Option<&(usize, usize)> {
        self.memoized_trace_map.get(&digest_to_key(hash))
    }

    /// Records the op index range of a block's controller trace for memoization.
    fn insert_to_memoized_trace_map(&mut self, op_start: usize, hash: Digest) {
        let op_end = self.trace.next_op_index();
        self.memoized_trace_map.insert(digest_to_key(hash), (op_start, op_end));
    }
}

fn fill_blakeg_compression_trace(
    compression_requests: BTreeMap<CompressionRequestKey, u64>,
    trace: &mut [Felt],
) -> Vec<u64> {
    const W: usize = NUM_BLAKEG_COMPRESSION_COLS;
    const BLOCKS_PER_FILL_CHUNK: usize = 512;
    debug_assert_eq!(trace.len() % W, 0, "BlakeG trace buffer is not row-aligned");

    let (rows, _) = trace.as_chunks_mut::<W>();
    debug_assert_eq!(
        rows.len() % BLAKEG_COMPRESSION_CYCLE_LEN,
        0,
        "BlakeG height must align to blocks"
    );
    debug_assert!(
        compression_requests.len() * BLAKEG_COMPRESSION_CYCLE_LEN <= rows.len(),
        "BlakeG trace buffer is too short for compression requests",
    );

    let request_count = compression_requests.len();
    let block_count = rows.len() / BLAKEG_COMPRESSION_CYCLE_LEN;
    profile_event(format_args!(
        "blakeg_compression.shape rows={} blocks={} real_blocks={} cols={W}",
        rows.len(),
        block_count,
        request_count,
    ));

    let requests: Vec<_> = compression_requests.into_iter().collect();
    let real_rows_len = requests.len() * BLAKEG_COMPRESSION_CYCLE_LEN;
    let (real_rows, dummy_rows) = rows.split_at_mut(real_rows_len);

    let mut counts = profile_scope("blakeg_compression.real_blocks", || {
        real_rows
            .par_chunks_mut(BLAKEG_COMPRESSION_CYCLE_LEN * BLOCKS_PER_FILL_CHUNK)
            .zip(requests.par_chunks(BLOCKS_PER_FILL_CHUNK))
            .map(|(rows_chunk, requests_chunk)| {
                let mut local_counts = vec![0u64; BYTE_LOOKUP_COUNT_LEN];
                for (block_rows, (key, multiplicity)) in rows_chunk
                    .chunks_exact_mut(BLAKEG_COMPRESSION_CYCLE_LEN)
                    .zip(requests_chunk.iter())
                {
                    write_blakeg_compression_block(
                        block_rows,
                        &key.state,
                        key.output,
                        *multiplicity,
                        &mut local_counts,
                    );
                }
                local_counts
            })
            .reduce_with(|mut left, right| {
                for (left, right) in left.iter_mut().zip(right) {
                    *left += right;
                }
                left
            })
            .unwrap_or_else(|| vec![0u64; BYTE_LOOKUP_COUNT_LEN])
    });

    profile_scope("blakeg_compression.dummy_blocks", || {
        if dummy_rows.is_empty() {
            return;
        }

        let zero_state = [0u64; STATE_WIDTH];
        let mut dummy_block = vec![[ZERO; W]; BLAKEG_COMPRESSION_CYCLE_LEN];
        let mut dummy_counts = vec![0u64; BYTE_LOOKUP_COUNT_LEN];
        write_blakeg_compression_block(
            &mut dummy_block,
            &zero_state,
            CompressionOutput::Packed,
            0,
            &mut dummy_counts,
        );

        let dummy_blocks = dummy_rows.len() / BLAKEG_COMPRESSION_CYCLE_LEN;
        for (count, dummy_count) in counts.iter_mut().zip(dummy_counts) {
            *count += dummy_count * dummy_blocks as u64;
        }

        dummy_rows
            .par_chunks_mut(BLAKEG_COMPRESSION_CYCLE_LEN * BLOCKS_PER_FILL_CHUNK)
            .for_each(|chunk| {
                for block_rows in chunk.chunks_exact_mut(BLAKEG_COMPRESSION_CYCLE_LEN) {
                    block_rows.copy_from_slice(&dummy_block);
                }
            });
    });

    counts
}

fn append_message_row_range_checks(state: &StateKey, range: &mut RangeChecker) {
    for &value in &state[..RATE_LEN] {
        let lo = (value & 0xffff_ffff) as u32;
        let hi = (value >> 32) as u32;

        range.add_value((lo & 0xffff) as u16);
        range.add_value((lo >> 16) as u16);
        range.add_value((hi & 0xffff) as u16);
        range.add_value((hi >> 16) as u16);
    }
}

fn append_zero_message_row_range_checks(block_count: usize, range: &mut RangeChecker) {
    if block_count == 0 {
        return;
    }

    range.add_value_repeated(0, RATE_LEN * 4 * block_count);
}

fn num_basic_block_hash_groups(op_batches: &[OpBatch]) -> usize {
    let Some((last, prefix)) = op_batches.split_last() else {
        return 0;
    };
    prefix.len() * RATE_LEN + last.num_groups().next_power_of_two()
}

fn write_blakeg_compression_block(
    rows: &mut [[Felt; NUM_BLAKEG_COMPRESSION_COLS]],
    input_state: &StateKey,
    output_mode: CompressionOutput,
    multiplicity: u64,
    and8_counts: &mut [u64],
) {
    let block = unpack_block_from_state_key(input_state);
    let h = unpack_cv_from_state_key(input_state);
    let trace_mode = match output_mode {
        CompressionOutput::Packed => {
            BlakeGCompressionTraceMode::CompressionWithMultiplicity { multiplicity }
        },
        CompressionOutput::AeadXof { clk } => {
            debug_assert_eq!(multiplicity, 1, "AEAD XOF requests are not deduplicated by clk");
            BlakeGCompressionTraceMode::AeadXof { clk: clk.as_canonical_u64() }
        },
    };

    let mut recorder = BlakeGLookupCounter { counts: and8_counts };
    write_blakeg_felt_trace_block(rows, block, h, trace_mode, &mut recorder);
}

fn unpack_block_from_state_key(state: &StateKey) -> [u32; RATE_LEN * 2] {
    core::array::from_fn(|idx| {
        let packed = state[idx / 2];
        if idx.is_multiple_of(2) {
            (packed & 0xffff_ffff) as u32
        } else {
            (packed >> 32) as u32
        }
    })
}

fn unpack_cv_from_state_key(state: &StateKey) -> [u32; (STATE_WIDTH - RATE_LEN) * 2] {
    core::array::from_fn(|idx| {
        let packed = state[RATE_LEN + idx / 2];
        if idx.is_multiple_of(2) {
            (packed & 0xffff_ffff) as u32
        } else {
            (packed >> 32) as u32
        }
    })
}

struct BlakeGLookupCounter<'a> {
    counts: &'a mut [u64],
}

impl ByteLookupRecorder for BlakeGLookupCounter<'_> {
    fn record(&mut self, lookup: BlakeGByteLookup, lhs: u8, rhs: u8, result: u32) {
        let kind = match lookup {
            BlakeGByteLookup::And8 => BYTE_LOOKUP_KIND_AND8,
            BlakeGByteLookup::Rot12 { byte } => BYTE_LOOKUP_KIND_BLAKEG_ROT12[byte],
            BlakeGByteLookup::Rot7 { byte } => BYTE_LOOKUP_KIND_BLAKEG_ROT7[byte],
        };
        count_byte_lookup(self.counts, kind, lhs, rhs, result);
    }
}

fn count_byte_lookup(counts: &mut [u64], kind: usize, lhs: u8, rhs: u8, result: u32) {
    debug_assert_eq!(
        byte_lookup_result(kind, lhs, rhs),
        result,
        "byte-pair witness does not match table row",
    );
    counts[kind * BYTE_PAIR_ROWS + ((lhs as usize) << 8) + rhs as usize] += 1;
}

#[cfg(feature = "std")]
fn profile_event(args: core::fmt::Arguments<'_>) {
    if std::env::var_os("MIDEN_TRACE_PROFILE").is_some() {
        std::eprintln!("trace_profile {args}");
    }
}

#[cfg(not(feature = "std"))]
fn profile_event(_: core::fmt::Arguments<'_>) {}

#[cfg(feature = "std")]
fn profile_scope<T>(label: &str, f: impl FnOnce() -> T) -> T {
    if std::env::var_os("MIDEN_TRACE_PROFILE").is_none() {
        return f();
    }

    let start = Instant::now();
    let result = f();
    let elapsed_ms = start.elapsed().as_secs_f64() * 1_000.0;
    std::eprintln!("trace_profile {label}: {elapsed_ms:.3} ms");
    result
}

#[cfg(not(feature = "std"))]
fn profile_scope<T>(_: &str, f: impl FnOnce() -> T) -> T {
    f()
}

// MERKLE PATH CONTEXT
// ================================================================================================

/// Specifies the context of a Merkle path computation.
#[derive(Debug, Clone, Copy)]
enum MerklePathContext {
    /// The computation is for verifying a Merkle path (MPVERIFY).
    MpVerify,
    /// The computation is for verifying a Merkle path to an old node during Merkle root update
    /// procedure (MRUPDATE).
    MrUpdateOld,
    /// The computation is for verifying a Merkle path to a new node during Merkle root update
    /// procedure (MRUPDATE).
    MrUpdateNew,
}

impl MerklePathContext {
    /// Returns selector values for this context.
    pub fn main_selectors(self) -> Selectors {
        match self {
            Self::MpVerify => MP_VERIFY,
            Self::MrUpdateOld => MR_UPDATE_OLD,
            Self::MrUpdateNew => MR_UPDATE_NEW,
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Combines two words into a hasher state for Merkle path computation.
#[inline(always)]
fn build_merge_state(a: &Digest, b: &Digest, index_bit: u64) -> HasherState {
    match index_bit {
        0 => init_state_from_words(a, b),
        1 => init_state_from_words(b, a),
        _ => panic!("index bit is not a binary value"),
    }
}

// HASHER STATE MUTATORS
// ================================================================================================

/// Initializes the first BlakeG compression state for sequential hashing.
///
/// `n` is the total number of felts in the hash call.
#[inline(always)]
pub fn init_state(init_values: &[Felt; RATE_LEN], n: u32) -> [Felt; STATE_WIDTH] {
    let cv = blakeg::init_chaining_word(0, n);
    let mut state = [ZERO; STATE_WIDTH];
    state[..RATE_LEN].copy_from_slice(init_values);
    state[RATE_LEN..STATE_WIDTH].copy_from_slice(cv.as_slice());
    state
}

/// Initializes a domain-0 two-word compression state.
#[inline(always)]
pub fn init_state_from_words(w1: &Digest, w2: &Digest) -> [Felt; STATE_WIDTH] {
    init_state_from_words_with_domain(w1, w2, ZERO)
}

/// Initializes a two-word compression state for the provided domain.
#[inline(always)]
pub fn init_state_from_words_with_domain(
    w1: &Digest,
    w2: &Digest,
    domain: Felt,
) -> [Felt; STATE_WIDTH] {
    let domain_u32 =
        u32::try_from(domain.as_canonical_u64()).expect("hasher domain must fit in u32");
    let cv = blakeg::two_to_one_chaining_word(domain_u32);
    [
        w1[0], w1[1], w1[2], w1[3], w2[0], w2[1], w2[2], w2[3], cv[0], cv[1], cv[2], cv[3],
    ]
}

/// Absorbs values into the rate portion of the state.
#[inline(always)]
pub fn absorb_into_state(state: &mut [Felt; STATE_WIDTH], values: &[Felt; RATE_LEN]) {
    state[..RATE_LEN].copy_from_slice(values);
}

/// Returns the digest portion of the hasher state.
pub fn get_digest(state: &[Felt; STATE_WIDTH]) -> Digest {
    state[DIGEST_RANGE].try_into().expect("failed to get digest from hasher state")
}
