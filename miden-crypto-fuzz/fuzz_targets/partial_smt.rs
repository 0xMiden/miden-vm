#![no_main]

use core::mem::size_of;

use libfuzzer_sys::fuzz_target;
use miden_crypto::{
    merkle::smt::{LeafIndex, NodeValue, PartialSmt, SmtLeaf, UniqueNodes, SMT_DEPTH},
    utils::{Deserializable, Serializable},
    Felt, Map, Word,
};

const MAX_LEVELS: usize = 16;
const MAX_NODES_PER_LEVEL: usize = 8;
const MAX_LEAVES: usize = 16;
const MAX_VALUE_ONLY_LEAVES: usize = 8;
const MAX_MULTI_LEAF_ENTRIES: usize = 6;

fuzz_target!(|data: &[u8]| {
    // Exercise the public deserializer directly, matching the other serde fuzz targets.
    let _ = PartialSmt::read_from_bytes(data);
    let _ = Vec::<PartialSmt>::read_from_bytes(data);
    let _ = Option::<PartialSmt>::read_from_bytes(data);
    let _ = <[PartialSmt; 1]>::read_from_bytes(data);

    if data.is_empty() {
        return;
    }

    // Generate parse-valid compact PartialSmt encodings from the input bytes. This gives the fuzzer
    // enough structure to regularly reach reconstruction and validation, not just byte parsing.
    let unique_nodes = StructuredInput::new(data).unique_nodes();
    let _ = PartialSmt::read_from_bytes(&unique_nodes.to_bytes());

    // Also try the same leaves without reconstruction nodes. This preserves direct coverage for
    // missing-node cases like the panic path reported in roborev review 3329.
    if !unique_nodes.leaves.is_empty() {
        let mut missing_nodes = unique_nodes;
        missing_nodes.nodes.clear();
        let _ = PartialSmt::read_from_bytes(&missing_nodes.to_bytes());
    }

    // Keep a minimal missing-node shape in the corpus so short inputs can still reach the reviewed
    // failure mode without first discovering the broader structured encoding.
    let _ = PartialSmt::read_from_bytes(&focused_missing_node_payload(data));
});

fn focused_missing_node_payload(data: &[u8]) -> Vec<u8> {
    let leaf_index = leaf_index_from_prefix(data);
    UniqueNodes {
        leaves: vec![(leaf_index, SmtLeaf::new_empty(LeafIndex::new_max_depth(leaf_index)))],
        ..UniqueNodes::empty()
    }
    .to_bytes()
}

fn leaf_index_from_prefix(data: &[u8]) -> u64 {
    let mut bytes = [0; size_of::<u64>()];
    let prefix_len = data.len().min(bytes.len());
    bytes[..prefix_len].copy_from_slice(&data[..prefix_len]);
    u64::from_le_bytes(bytes)
}

struct StructuredInput<'a> {
    data: &'a [u8],
    cursor: usize,
}

impl<'a> StructuredInput<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, cursor: 0 }
    }

    fn unique_nodes(&mut self) -> UniqueNodes {
        let root = if self.next_bool() {
            self.next_word()
        } else {
            UniqueNodes::empty().root
        };

        let mut nodes = Map::new();
        for _ in 0..self.next_count(MAX_LEVELS) {
            let depth = self.next_node_depth();
            let node_count = self.next_count(MAX_NODES_PER_LEVEL);
            let level_nodes = nodes.entry(depth).or_insert_with(Vec::new);

            for _ in 0..node_count {
                level_nodes.push((self.next_node_position(depth), self.next_node_value()));
            }
        }

        let mut leaves = Vec::new();
        for _ in 0..self.next_count(MAX_LEAVES) {
            leaves.push(self.next_leaf_entry());
        }

        let mut value_only_leaves = Vec::new();
        for _ in 0..self.next_count(MAX_VALUE_ONLY_LEAVES) {
            value_only_leaves.push((self.next_node_position(SMT_DEPTH), self.next_word()));
        }

        UniqueNodes { root, nodes, leaves, value_only_leaves }
    }

    fn next_leaf_entry(&mut self) -> (u64, SmtLeaf) {
        let outer_index = self.next_u64();
        let leaf_index = if self.next_bool() { outer_index } else { self.next_u64() };

        let leaf = match self.next_u8() % 3 {
            0 => SmtLeaf::new_empty(LeafIndex::new_max_depth(leaf_index)),
            1 => SmtLeaf::new_single(self.next_key_for_leaf(leaf_index), self.next_word()),
            _ => self.next_multiple_leaf(leaf_index),
        };

        (outer_index, leaf)
    }

    fn next_multiple_leaf(&mut self, leaf_index: u64) -> SmtLeaf {
        let count = 2 + self.next_count(MAX_MULTI_LEAF_ENTRIES.saturating_sub(2));
        let entries = (0..count)
            .map(|_| (self.next_key_for_leaf(leaf_index), self.next_word()))
            .collect();

        SmtLeaf::new_multiple(entries)
            .unwrap_or_else(|_| SmtLeaf::new_empty(LeafIndex::new_max_depth(leaf_index)))
    }

    fn next_key_for_leaf(&mut self, leaf_index: u64) -> Word {
        Word::new([
            self.next_felt(),
            self.next_felt(),
            self.next_felt(),
            Felt::new_unchecked(leaf_index % Felt::ORDER),
        ])
    }

    fn next_node_value(&mut self) -> NodeValue {
        if self.next_bool() {
            NodeValue::Present(self.next_word())
        } else {
            NodeValue::EmptySubtreeRoot
        }
    }

    fn next_node_depth(&mut self) -> u8 {
        self.next_u8() % SMT_DEPTH
    }

    fn next_node_position(&mut self, depth: u8) -> u64 {
        let position = self.next_u64();
        if self.next_bool() {
            bounded_position(depth, position)
        } else {
            position
        }
    }

    fn next_word(&mut self) -> Word {
        Word::new([self.next_felt(), self.next_felt(), self.next_felt(), self.next_felt()])
    }

    fn next_felt(&mut self) -> Felt {
        Felt::new_unchecked(self.next_u64() % Felt::ORDER)
    }

    fn next_count(&mut self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }
        usize::from(self.next_u8()) % (max + 1)
    }

    fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 == 1
    }

    fn next_u8(&mut self) -> u8 {
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

fn bounded_position(depth: u8, position: u64) -> u64 {
    match depth {
        0 => 0,
        1..=63 => position & ((1_u64 << depth) - 1),
        _ => position,
    }
}
