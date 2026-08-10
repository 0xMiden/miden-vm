#![no_main]

use core::mem::size_of;
use core::num::NonZero;

use libfuzzer_sys::fuzz_target;
use miden_crypto::{
    Felt, Word,
    merkle::{SparseMerklePath, smt::SMT_MAX_DEPTH},
    utils::{Deserializable, Serializable},
};

fuzz_target!(|data: &[u8]| {
    // Exercise the public deserializer directly, matching the other serde fuzz targets.
    let _ = SparseMerklePath::read_from_bytes(data);
    let _ = Vec::<SparseMerklePath>::read_from_bytes(data);
    let _ = Option::<SparseMerklePath>::read_from_bytes(data);
    let _ = <[SparseMerklePath; 1]>::read_from_bytes(data);

    if data.is_empty() {
        return;
    }

    // Random bytes essentially never form a well-formed `depth` + `empty_nodes_mask` +
    // `nodes` triple (the encoding requires `nodes.len() == depth - mask.count_ones()`),
    // so the raw byte fuzzer above rarely gets past the initial length check. Generate a
    // structured, parse-valid-shaped encoding instead so the fuzzer can regularly reach
    // `get_nonempty_index`/`at_depth`/`compute_root` on a value that *did* pass
    // deserialization - this is exactly the code path where the reviewed
    // out-of-range-mask-bit panic (empty_nodes_mask bit set at position >= depth) lived,
    // since it depends on the *relationship* between the mask's bit positions and the
    // declared depth, not on any single field in isolation.
    let mut input = StructuredInput::new(data);
    let (depth, empty_nodes_mask, nodes) = input.sparse_merkle_path_parts();

    let encoded = encode(depth, empty_nodes_mask, &nodes);
    if let Ok(path) = SparseMerklePath::read_from_bytes(&encoded) {
        exercise(&path);
    }

    // Also go through the safe constructor with the same generated parts, and exercise
    // whatever it accepts. `from_parts` and `read_from`/deserialize are two independent
    // code paths that are expected to agree on which (mask, nodes) shapes are valid; fuzzing
    // both with the same generated inputs helps catch future divergence between them.
    if let Ok(path) = SparseMerklePath::from_parts(empty_nodes_mask, nodes) {
        exercise(&path);
    }
});

/// Exercises every public read-path on a successfully constructed `SparseMerklePath`, so
/// panics reachable only *after* construction (e.g. depth-dependent indexing) are covered too.
fn exercise(path: &SparseMerklePath) {
    let depth = path.depth();
    let _ = path.serialize_to_bytes();

    if let Some(nz_depth) = NonZero::new(depth) {
        let _ = path.at_depth(nz_depth);
        let index_bits = if depth >= 64 { u64::MAX } else { (1u64 << depth) - 1 };
        let _ = path.compute_root(index_bits, Word::default());
        let _ = path.verify(index_bits, Word::default(), &Word::default());
    }
}

fn encode(depth: u8, empty_nodes_mask: u64, nodes: &[Word]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(depth);
    bytes.extend_from_slice(&empty_nodes_mask.to_le_bytes());
    for node in nodes {
        node.write_into(&mut bytes);
    }
    bytes
}

struct StructuredInput<'a> {
    data: &'a [u8],
    cursor: usize,
}

impl<'a> StructuredInput<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, cursor: 0 }
    }

    /// Generates a `(depth, empty_nodes_mask, nodes)` triple. Most of the time `nodes.len()`
    /// is made consistent with `depth - empty_nodes_mask.count_ones()` (the shape
    /// `read_from` expects), but the mask's *bit positions* are left free-ranging over the
    /// full `u64`, independent of `depth` - deliberately including positions `>= depth`,
    /// which is exactly the malformed-but-previously-accepted shape this target exists to
    /// keep covered.
    fn sparse_merkle_path_parts(&mut self) -> (u8, u64, Vec<Word>) {
        let depth = self.next_u8() % (SMT_MAX_DEPTH + 1);
        let empty_nodes_mask = self.next_u64();

        let node_count = if self.next_bool() {
            // Consistent shape: what `read_from` would compute from (depth, mask).
            (depth as u32).saturating_sub(empty_nodes_mask.count_ones()) as usize
        } else {
            // Inconsistent shape, to also cover `from_parts`'s own length validation.
            self.next_u8() as usize % 8
        };

        let nodes = (0..node_count).map(|_| self.next_word()).collect();
        (depth, empty_nodes_mask, nodes)
    }

    fn next_word(&mut self) -> Word {
        Word::new([self.next_felt(), self.next_felt(), self.next_felt(), self.next_felt()])
    }

    fn next_felt(&mut self) -> Felt {
        Felt::new_unchecked(self.next_u64() % Felt::ORDER)
    }

    fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 == 1
    }

    fn next_u8(&mut self) -> u8 {
        if self.data.is_empty() {
            return 0;
        }
        let value = self.data[self.cursor % self.data.len()];
        self.cursor += 1;
        value
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; size_of::<u64>()];
        for byte in &mut bytes {
            *byte = self.next_u8();
        }
        u64::from_le_bytes(bytes)
    }
}
