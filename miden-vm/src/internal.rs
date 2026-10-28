use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
};

use miden_assembly::diagnostics::{IntoDiagnostic, Report, WrapErr};
use miden_core::{
    Felt, WORD_SIZE,
    field::{PrimeField64, QuotientMap},
    serde::read_file_bounded,
};
use serde::Deserialize;
pub use tracing::{Level, event, instrument};

#[cfg(test)]
use crate::crypto::merkle::NodeIndex;
use crate::{
    ExecutionOptions, StackInputs, Word, ZERO,
    advice::{AdviceInputs, AdviceProvider, AdviceStack},
    crypto::merkle::SmtWitness,
    serde::{BudgetedReader, ByteReader, Deserializable, SliceReader},
};

mod merkle_builder;

// CONSTANTS
// ================================================================================================

const SIMPLE_SMT_DEPTH: u8 = u64::BITS as u8;

// MERKLE DATA
// ================================================================================================

/// Struct used to deserialize merkle data from input file. Merkle data can be represented as a
/// merkle tree or a Sparse Merkle Tree.
#[derive(Deserialize, Debug)]
pub enum MerkleData {
    /// String representation of a merkle tree. The merkle tree is represented as a vector of
    /// 32 byte hex strings where each string represents a leaf in the tree.
    #[serde(rename = "merkle_tree")]
    MerkleTree(Vec<String>),
    /// String representation of a Sparse Merkle Tree. The Sparse Merkle Tree is represented as a
    /// vector of tuples where each tuple consists of a u64 node index and a 32 byte hex string
    /// representing the value of the node.
    #[serde(rename = "sparse_merkle_tree")]
    SparseMerkleTree(Vec<(u64, String)>),
    /// String representation of a Partial Merkle Tree. The Partial Merkle Tree is represented as a
    /// vector of tuples where each tuple consists of a leaf index tuple (depth, index) and a 32
    /// byte hex string representing the value of the leaf.
    #[serde(rename = "partial_merkle_tree")]
    PartialMerkleTree(Vec<((u8, u64), String)>),
    /// A `0x`-prefixed, hex-encoded versioned `SmtWitness`. Reconstructs shared Merkle nodes and
    /// adds complete leaf preimages to the advice map. Multiple entries may carry different roots.
    #[serde(rename = "smt_witness")]
    SmtWitness(String),
}

// INPUT FILE
// ================================================================================================

// TODO consider using final types instead of string representations.
/// Input file struct that is used to deserialize input data from file. It consists of four
/// components:
/// - operand_stack
/// - advice_stack
/// - advice_map
/// - merkle_store
#[derive(Deserialize, Debug)]
pub struct InputFile {
    /// String representation of the initial operand stack, composed of chained field elements.
    pub operand_stack: Vec<String>,
    /// Optional string representation of the initial advice stack, composed of chained field
    /// elements.
    pub advice_stack: Option<Vec<String>>,
    /// Optional map of 32 byte hex strings to vectors of u64s representing the initial advice map.
    pub advice_map: Option<HashMap<String, Vec<u64>>>,
    /// Optional vector of merkle data which will be loaded into the initial merkle store. Merkle
    /// data is represented as 32 byte hex strings and node indexes are represented as u64s.
    pub merkle_store: Option<Vec<MerkleData>>,
}

impl Default for InputFile {
    fn default() -> Self {
        Self {
            operand_stack: Vec::new(),
            advice_stack: Some(Vec::new()),
            advice_map: Some(HashMap::new()),
            merkle_store: None,
        }
    }
}

/// Helper methods to interact with the input file
impl InputFile {
    /// Maximum input JSON file size in bytes (64 MiB).
    pub const MAX_FILE_SIZE: usize = 64 * 1024 * 1024;

    /// Reads input JSON from a regular file of at most [`Self::MAX_FILE_SIZE`] bytes.
    /// Symlinks to regular files are accepted.
    #[instrument(name = "read_input_file", skip_all)]
    pub fn read(inputs_path: &Option<PathBuf>, program_path: &Path) -> Result<Self, Report> {
        // If inputs_path has been provided then use this as path. Alternatively we will
        // replace the program_path extension with .inputs and use this as a default.
        let path = match inputs_path {
            Some(path) => path.clone(),
            None => program_path.with_extension("inputs"),
        };

        // Bound the file before deserializing any JSON collections.
        let inputs_file = read_file_bounded(&path, Self::MAX_FILE_SIZE)
            .into_diagnostic()
            .wrap_err_with(|| format!("Failed to open input file {}", path.display()))?;
        let inputs_file = String::from_utf8(inputs_file)
            .into_diagnostic()
            .wrap_err_with(|| format!("Failed to open input file {}", path.display()))?;

        // deserialize input data
        let inputs: InputFile = serde_json::from_str(&inputs_file)
            .into_diagnostic()
            .wrap_err("Failed to deserialize input data")?;

        Ok(inputs)
    }

    /// Parse advice inputs using the default execution advice-memory budget.
    pub fn parse_advice_inputs(&self) -> Result<AdviceInputs, String> {
        self.parse_advice_inputs_with_options(&ExecutionOptions::default())
    }

    /// Parse advice inputs under the execution advice-memory budget.
    ///
    /// Final Merkle nodes are inserted through the advice provider as they are computed.
    /// The budget also limits total encoded witness bytes and, separately for each witness,
    /// reconstructed parents at 96 logical bytes per parent. Retained advice is charged after
    /// deduplication, including shared nodes across different tree versions.
    pub fn parse_advice_inputs_with_options(
        &self,
        options: &ExecutionOptions,
    ) -> Result<AdviceInputs, String> {
        let mut provider = AdviceProvider::new(self.parse_advice_inputs_base()?, options)
            .map_err(|err| err.to_string())?;
        self.parse_merkle_store(&mut provider, options)?;
        let (stack, map, store) = provider.into_parts();
        Ok(AdviceInputs::new(stack.into(), map, store))
    }

    /// Parse the stack and normalized map before constructing any Merkle nodes.
    fn parse_advice_inputs_base(&self) -> Result<AdviceInputs, String> {
        let stack = self
            .parse_advice_stack()
            .map_err(|e| format!("failed to parse advice provider: {e}"))?;
        let stack = AdviceStack::try_from_values(stack).map_err(|e| e.to_string())?;
        let mut advice_inputs = AdviceInputs::default().with_stack(stack);
        if let Some(map) = self
            .parse_advice_map()
            .map_err(|e| format!("failed to parse advice provider: {e}"))?
        {
            advice_inputs = advice_inputs.with_map(map);
        }
        Ok(advice_inputs)
    }

    /// Parse advice stack data from the input file.
    fn parse_advice_stack(&self) -> Result<Vec<u64>, String> {
        self.advice_stack
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|v| {
                v.parse::<u64>()
                    .map_err(|e| format!("failed to parse advice stack value '{v}': {e}"))
            })
            .collect::<Result<Vec<_>, _>>()
    }

    /// Parse advice map data from the input file.
    fn parse_advice_map(&self) -> Result<Option<BTreeMap<Word, Vec<Felt>>>, String> {
        let advice_map = match &self.advice_map {
            Some(advice_map) => advice_map,
            None => return Ok(None),
        };

        let map = advice_map
            .iter()
            .map(|(k, v)| {
                // Convert key to Word
                let key = Word::try_from(k)
                    .map_err(|e| format!("failed to decode advice map key '{k}': {e}"))?;

                // convert values to Felt
                let values = v
                    .iter()
                    .map(|v| {
                        Felt::from_canonical_checked(*v).ok_or_else(|| {
                            format!("failed to convert advice map value '{v}' to Felt")
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok((key, values))
            })
            .collect::<Result<BTreeMap<Word, Vec<Felt>>, String>>()?;

        Ok(Some(map))
    }

    /// Parse merkle store data from the input file.
    fn parse_merkle_store(
        &self,
        provider: &mut AdviceProvider,
        options: &ExecutionOptions,
    ) -> Result<(), String> {
        let merkle_data = match &self.merkle_store {
            Some(merkle_data) => merkle_data,
            None => return Ok(()),
        };

        let mut remaining_witness_bytes = options.max_advice_size_bytes();
        for data in merkle_data {
            match data {
                MerkleData::MerkleTree(_)
                | MerkleData::SparseMerkleTree(_)
                | MerkleData::PartialMerkleTree(_) => {
                    let root = merkle_builder::add_tree(data, &mut |left, right| {
                        provider.merge_roots(left, right).map_err(|err| err.to_string())
                    })?;
                    event!(
                        Level::TRACE,
                        "Added Merkle tree with root {} to the Merkle store",
                        root
                    );
                },
                MerkleData::SmtWitness(data) => {
                    let hex = data.strip_prefix("0x").ok_or("SMT witness requires a 0x prefix")?;
                    // Bound binary input before allocating it, across all witnesses in the file.
                    if hex.len() % 2 != 0 || hex.len() / 2 > remaining_witness_bytes {
                        return Err("SMT witness is too large or has an odd hex length".into());
                    }
                    remaining_witness_bytes -= hex.len() / 2;
                    let bytes =
                        hex::decode(hex).map_err(|e| format!("invalid SMT witness hex: {e}"))?;
                    let mut reader = BudgetedReader::new(SliceReader::new(&bytes), bytes.len());
                    let witness = SmtWitness::read_from(&mut reader).map_err(|e| e.to_string())?;
                    if reader.has_more_bytes() {
                        return Err("trailing bytes in SMT witness".into());
                    }
                    // Bound reconstruction work per witness. Previously loaded nodes may be
                    // shared, so they must not reduce this independent work limit.
                    let max_nodes = options.max_advice_size_bytes() / 96;
                    let tree = witness.into_partial_smt(max_nodes).map_err(|e| e.to_string())?;
                    provider.extend_merkle_store(tree.inner_nodes()).map_err(|e| e.to_string())?;
                    for (_, leaf) in tree.leaves() {
                        let hash = leaf.hash();
                        let elements: Vec<_> = leaf.to_elements().collect();
                        if let Some(existing) = provider.get_mapped_values(&hash)
                            && existing != elements.as_slice()
                        {
                            return Err(format!("conflicting SMT leaf preimage for {hash}"));
                        }
                        provider.insert_into_map(hash, elements).map_err(|e| e.to_string())?;
                    }
                    event!(
                        Level::TRACE,
                        "Added SMT witness with root {} to the Merkle store",
                        tree.root()
                    );
                },
            }
        }

        Ok(())
    }

    /// Parse and return merkle tree leaves.
    #[cfg(test)]
    fn parse_merkle_tree(tree: &[String]) -> Result<Vec<Word>, String> {
        tree.iter()
            .map(|v| {
                let leaf = Self::parse_word(v)?;
                Ok(leaf)
            })
            .collect()
    }

    /// Parse and return Sparse Merkle Tree entries.
    #[cfg(test)]
    fn parse_sparse_merkle_tree(tree: &[(u64, String)]) -> Result<Vec<(u64, Word)>, String> {
        tree.iter()
            .map(|(index, v)| {
                let leaf = Self::parse_word(v)?;
                Ok((*index, leaf))
            })
            .collect()
    }

    /// Parse and return Partial Merkle Tree entries.
    #[cfg(test)]
    fn parse_partial_merkle_tree(
        tree: &[((u8, u64), String)],
    ) -> Result<Vec<(NodeIndex, Word)>, String> {
        tree.iter()
            .map(|((depth, index), v)| {
                let node_index = NodeIndex::new(*depth, *index).map_err(|e| {
                    format!(
                        "failed to create node index with depth {depth} and index {index} - {e}"
                    )
                })?;
                let leaf = Self::parse_word(v)?;
                Ok((node_index, leaf))
            })
            .collect()
    }

    /// Parse a `Word` from a hex string.
    pub fn parse_word(word_hex: &str) -> Result<Word, String> {
        let Some(word_value) = word_hex.strip_prefix("0x") else {
            return Err(format!("failed to decode `Word` from hex {word_hex} - missing 0x prefix"));
        };
        let mut word_data = [0u8; 32];
        hex::decode_to_slice(word_value, &mut word_data)
            .map_err(|e| format!("failed to decode `Word` from hex {word_hex} - {e}"))?;
        let mut word = [ZERO; WORD_SIZE];
        for (i, value) in word_data.chunks(8).enumerate() {
            // Convert 8-byte slice to [u8; 8] array, then to u64 (little-endian), then to Felt
            let bytes: [u8; 8] = value.try_into().map_err(|_| {
                format!("failed to convert `Word` data {word_hex} (element {i}) - expected 8 bytes")
            })?;
            let value_u64 = u64::from_le_bytes(bytes);
            word[i] = Felt::from_canonical_checked(value_u64).ok_or_else(|| {
                format!(
                    "failed to convert `Word` data {word_hex} (element {i}) to Felt - \
                     value {} exceeds field modulus {}",
                    value_u64,
                    Felt::ORDER_U64
                )
            })?;
        }
        Ok(word.into())
    }

    /// Parse and return the stack inputs for the program.
    pub fn parse_stack_inputs(&self) -> Result<StackInputs, String> {
        let stack_inputs: Vec<Felt> = self
            .operand_stack
            .iter()
            .map(|v| {
                let value = v.parse::<u64>().map_err(|e| e.to_string())?;
                Felt::from_canonical_checked(value)
                    .ok_or_else(|| format!("failed to convert stack input value '{v}' to Felt"))
            })
            .collect::<Result<_, _>>()?;

        StackInputs::new(&stack_inputs).map_err(|e| e.to_string())
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod budget_tests;

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::crypto::merkle::MerkleStore;

    fn test_file_path(name: &str) -> PathBuf {
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("miden-vm-{name}-{id}"))
    }

    #[test]
    fn test_merkle_data_parsing() {
        let program_with_pmt = "
        {
            \"operand_stack\": [\"1\"],
            \"merkle_store\": [
                {
                    \"partial_merkle_tree\": [
                        [
                            [2, 0],
                            \"0x1400000000000000000000000000000000000000000000000000000000000000\"
                        ],
                        [
                            [2, 1],
                            \"0x1500000000000000000000000000000000000000000000000000000000000000\"
                        ],
                        [
                            [1, 1],
                            \"0x0b00000000000000000000000000000000000000000000000000000000000000\"
                        ]
                    ]
                }
            ]
        }";
        let inputs: InputFile = serde_json::from_str(program_with_pmt).unwrap();
        let advice = inputs.parse_advice_inputs().unwrap();
        assert!(advice.store().num_internal_nodes() > 255);

        let program_with_smt = "
        {
            \"operand_stack\": [\"1\"],
            \"merkle_store\": [
              {
                \"sparse_merkle_tree\": [
                  [
                    0,
                    \"0x1400000000000000000000000000000000000000000000000000000000000000\"
                  ],
                  [
                    1,
                    \"0x1500000000000000000000000000000000000000000000000000000000000000\"
                  ],
                  [
                    3,
                    \"0x1700000000000000000000000000000000000000000000000000000000000000\"
                  ]
                ]
              }
            ]
          }";
        let inputs: InputFile = serde_json::from_str(program_with_smt).unwrap();
        let advice = inputs.parse_advice_inputs().unwrap();
        assert!(advice.store().num_internal_nodes() > 255);

        let program_with_merkle_tree = "
        {
            \"operand_stack\": [\"1\"],
            \"merkle_store\": [
                {
                    \"merkle_tree\": [
                        \"0x1400000000000000000000000000000000000000000000000000000000000000\",
                        \"0x1500000000000000000000000000000000000000000000000000000000000000\",
                        \"0x1600000000000000000000000000000000000000000000000000000000000000\",
                        \"0x1700000000000000000000000000000000000000000000000000000000000000\"
                    ]
                }
            ]
        }";
        let inputs: InputFile = serde_json::from_str(program_with_merkle_tree).unwrap();
        let advice = inputs.parse_advice_inputs().unwrap();
        assert!(advice.store().num_internal_nodes() > 255);
    }

    #[test]
    fn test_smt_witness_inputs_preserve_multiple_versions_and_leaf_preimages() {
        use crate::{
            crypto::merkle::{LeafIndex, PartialSmt, Smt},
            serde::Serializable,
        };

        let key = Word::from([1, 2, 3, 7u32]);
        let colliding_key = Word::from([4, 5, 6, 7u32]);
        let absent = Word::from([8, 9, 10, 31u32]);
        let value = Word::from([11, 12, 13, 14u32]);
        let old = Smt::with_entries([(key, value), (colliding_key, value)]).unwrap();
        let mut new = old.clone();
        let updated_value = Word::from([15, 16, 17, 18u32]);
        new.insert(key, updated_value).unwrap();
        let trees = [old, new];
        let witnesses: Vec<_> = trees.iter().map(|tree| {
            let partial = PartialSmt::from_proofs([tree.open(&key), tree.open(&absent)]).unwrap();
            serde_json::json!({"smt_witness": format!("0x{}", hex::encode(SmtWitness::from(&partial).to_bytes()))})
        }).collect();
        let mut inputs: InputFile = serde_json::from_value(serde_json::json!({
            "operand_stack": [], "merkle_store": witnesses,
        }))
        .unwrap();
        let advice = inputs.parse_advice_inputs().unwrap();
        for (version, tree) in trees.iter().enumerate() {
            for key in [key, colliding_key, absent] {
                let index = NodeIndex::from(LeafIndex::<64>::from(key));
                assert_eq!(
                    advice.store().get_path(tree.root(), index).unwrap().path,
                    tree.open(&key).path().clone()
                );
            }
            let leaf = tree.get_leaf(&key);
            let expected_value = if version == 0 { value } else { updated_value };
            let expected: Vec<_> =
                [key, expected_value, colliding_key, value].into_iter().flatten().collect();
            assert_eq!(advice.map().get(&leaf.hash()).unwrap().as_ref(), expected);
        }
        // An explicit input-map entry must not silently replace an authenticated leaf preimage.
        inputs.advice_map =
            Some(HashMap::from([(trees[0].get_leaf(&key).hash().to_hex(), vec![1])]));
        assert!(
            inputs
                .parse_advice_inputs()
                .unwrap_err()
                .contains("conflicting SMT leaf preimage")
        );
    }

    #[test]
    fn test_smt_witness_inputs_share_nodes_across_large_tree_versions() {
        use crate::{
            advice::AdviceProvider,
            crypto::merkle::{PartialSmt, Smt},
            serde::Serializable,
        };

        let step = u64::MAX / 2048;
        let keys: Vec<_> = (0..2048u64)
            .map(|i| Word::new([1, 2, 3, i * step].map(Felt::new_unchecked)))
            .collect();
        let old = Smt::with_entries(keys.iter().map(|&key| (key, Word::from([4u32; 4])))).unwrap();
        let mut new = old.clone();
        new.insert(keys[0], Word::from([5u32; 4])).unwrap();
        let trees = [old, new];
        let store: MerkleStore = trees.iter().flat_map(Smt::inner_nodes).collect();
        let mut map = BTreeMap::new();
        let witnesses = trees
            .iter()
            .map(|tree| {
                let partial =
                    PartialSmt::from_proofs(keys.iter().map(|key| tree.open(key))).unwrap();
                for (_, leaf) in partial.leaves() {
                    map.insert(leaf.hash(), leaf.to_elements().collect::<Vec<_>>());
                }
                MerkleData::SmtWitness(format!(
                    "0x{}",
                    hex::encode(SmtWitness::from(&partial).to_bytes())
                ))
            })
            .collect();
        let expected = AdviceInputs::default().with_merkle_store(store).with_map(map);
        AdviceProvider::new(expected.clone(), &ExecutionOptions::default()).unwrap();

        let mut inputs = InputFile {
            merkle_store: Some(witnesses),
            ..InputFile::default()
        };
        assert_eq!(inputs.parse_advice_inputs().unwrap(), expected);

        // A disjoint third tree exceeds the default retained-advice budget. Raising the same
        // options used for execution must also allow it through the loader.
        let third_keys: Vec<_> = (0..2048u64)
            .map(|i| Word::new([1, 2, 3, i * step + step / 2].map(Felt::new_unchecked)))
            .collect();
        let third =
            Smt::with_entries(third_keys.iter().map(|&key| (key, Word::from([4u32; 4])))).unwrap();
        let partial =
            PartialSmt::from_proofs(third_keys.iter().map(|key| third.open(key))).unwrap();
        inputs.merkle_store.as_mut().unwrap().push(MerkleData::SmtWitness(format!(
            "0x{}",
            hex::encode(SmtWitness::from(&partial).to_bytes()),
        )));
        assert!(
            inputs
                .parse_advice_inputs()
                .unwrap_err()
                .contains("advice provider size budget")
        );
        let options = ExecutionOptions::default()
            .with_max_advice_size_bytes(2 * ExecutionOptions::DEFAULT_MAX_ADVICE_SIZE_BYTES);
        let advice = inputs.parse_advice_inputs_with_options(&options).unwrap();
        AdviceProvider::new(advice.clone(), &options).unwrap();
        for tree in trees.iter().chain([&third]) {
            assert!(advice.store().get_node(tree.root(), NodeIndex::root()).is_ok());
        }
    }

    #[test]
    fn test_smt_witness_inputs_charge_the_combined_advice_budget() {
        use crate::{
            crypto::merkle::{PartialSmt, Smt},
            serde::Serializable,
        };

        let key = Word::from([1, 2, 3, 7u32]);
        let tree = Smt::with_entries([(key, Word::from([4u32; 4]))]).unwrap();
        let partial = PartialSmt::from_proofs([tree.open(&key)]).unwrap();
        let leaf = tree.get_leaf(&key);
        let inputs = InputFile {
            advice_stack: Some(vec!["1".into(), "2".into(), "3".into()]),
            // The same authenticated leaf must only be charged once.
            advice_map: Some(HashMap::from([(
                leaf.hash().to_hex(),
                leaf.to_elements().map(|value| value.as_canonical_u64()).collect(),
            )])),
            merkle_store: Some(vec![MerkleData::SmtWitness(format!(
                "0x{}",
                hex::encode(SmtWitness::from(&partial).to_bytes()),
            ))]),
            ..InputFile::default()
        };
        let expected = inputs.parse_advice_inputs().unwrap();
        let required = expected.store().num_internal_nodes() * 96
            + expected.map().total_element_count().unwrap() * 8
            + 3 * 8;
        let options = ExecutionOptions::default().with_max_advice_size_bytes(required);
        assert_eq!(inputs.parse_advice_inputs_with_options(&options).unwrap(), expected);
        let options = options.with_max_advice_size_bytes(required - 1);
        assert!(
            inputs
                .parse_advice_inputs_with_options(&options)
                .unwrap_err()
                .contains("advice provider size budget")
        );
    }

    #[test]
    fn test_smt_witness_inputs_limit_total_encoded_bytes() {
        use crate::{crypto::merkle::PartialSmt, serde::Serializable};

        let bytes = SmtWitness::from(&PartialSmt::default()).to_bytes();
        let copies = 600;
        let inputs = InputFile {
            merkle_store: Some(
                (0..copies)
                    .map(|_| MerkleData::SmtWitness(format!("0x{}", hex::encode(&bytes))))
                    .collect(),
            ),
            ..InputFile::default()
        };
        let limit = copies * bytes.len();
        assert!(limit > MerkleStore::default().num_internal_nodes() * 96);
        let options = ExecutionOptions::default().with_max_advice_size_bytes(limit);
        inputs.parse_advice_inputs_with_options(&options).unwrap();
        let options = options.with_max_advice_size_bytes(limit - 1);
        assert!(
            inputs
                .parse_advice_inputs_with_options(&options)
                .unwrap_err()
                .contains("SMT witness is too large")
        );
    }

    #[test]
    fn test_smt_witness_inputs_reject_invalid_hex_and_trailing_bytes() {
        use crate::{crypto::merkle::PartialSmt, serde::Serializable};

        let bytes = SmtWitness::from(&PartialSmt::default()).to_bytes();
        let mut wrong_version = bytes.clone();
        wrong_version[8] = 2;
        for encoded in [
            hex::encode(&bytes),
            "0x0".into(),
            "0xzz".into(),
            format!("0x{}00", hex::encode(&bytes)),
            format!("0x{}", hex::encode(wrong_version)),
            format!("0x{}", "00".repeat(ExecutionOptions::DEFAULT_MAX_ADVICE_SIZE_BYTES + 1)),
        ] {
            let inputs = InputFile {
                merkle_store: Some(vec![MerkleData::SmtWitness(encoded)]),
                ..InputFile::default()
            };
            assert!(inputs.parse_advice_inputs().is_err());
        }
    }

    #[test]
    fn test_parse_word_missing_0x_prefix() {
        let result = InputFile::parse_word(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 0x prefix"));
    }

    #[test]
    fn test_parse_word_edge_cases() {
        // Empty string
        let result = InputFile::parse_word("");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 0x prefix"));

        // Just "0x" without hex data
        let result = InputFile::parse_word("0x");
        assert!(result.is_err());

        // Too short hex (less than 64 chars after 0x)
        let result = InputFile::parse_word("0x123");
        assert!(result.is_err());

        // Hex string longer than 64 characters after 0x
        let too_long =
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let result = InputFile::parse_word(too_long);
        assert!(result.is_err());

        // Invalid hex characters
        let invalid_chars = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdeg";
        let result = InputFile::parse_word(invalid_chars);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_word_valid_hex() {
        let valid_hex = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let result = InputFile::parse_word(valid_hex);
        assert!(result.is_ok());

        // Test that the parsed word is not zero word
        let word = result.unwrap();
        let zero_word = Word::from([ZERO; 4]);
        assert_ne!(word, zero_word);
    }

    #[test]
    fn test_parse_stack_inputs_large_numbers() {
        // Test with felt modulus - 1 (should succeed)
        let felt_modulus_minus_one = Felt::ORDER_U64 - 1;
        let inputs2 = InputFile {
            operand_stack: vec![felt_modulus_minus_one.to_string()],
            advice_stack: None,
            advice_map: None,
            merkle_store: None,
        };
        let result2 = inputs2.parse_stack_inputs();
        assert!(result2.is_ok());

        // Test with felt modulus (should fail)
        let felt_modulus = Felt::ORDER_U64;
        let inputs3 = InputFile {
            operand_stack: vec![felt_modulus.to_string()],
            advice_stack: None,
            advice_map: None,
            merkle_store: None,
        };
        let result3 = inputs3.parse_stack_inputs();
        assert!(result3.is_err());
    }

    #[test]
    fn test_parse_advice_stack_large_numbers() {
        // Test with felt modulus - 1 (should succeed)
        let felt_modulus_minus_one = Felt::ORDER_U64 - 1;
        let inputs2 = InputFile {
            operand_stack: Vec::new(),
            advice_stack: Some(vec![felt_modulus_minus_one.to_string()]),
            advice_map: None,
            merkle_store: None,
        };
        let result2 = inputs2.parse_advice_inputs();
        assert!(result2.is_ok());

        // Test with felt modulus (should fail)
        let felt_modulus = Felt::ORDER_U64;
        let inputs = InputFile {
            operand_stack: Vec::new(),
            advice_stack: Some(vec![felt_modulus.to_string()]),
            advice_map: None,
            merkle_store: None,
        };
        let result = inputs.parse_advice_inputs();
        assert!(result.is_err());
    }

    #[test]
    fn input_file_read_rejects_missing_inferred_inputs_file() {
        let program_path = test_file_path("missing-inferred").with_extension("masm");

        let err =
            InputFile::read(&None, &program_path).expect_err("missing input file should fail");

        assert!(err.to_string().contains("Failed to open input file"));
        assert!(
            err.to_string()
                .contains(&program_path.with_extension("inputs").display().to_string())
        );
    }

    #[test]
    fn input_file_read_rejects_missing_explicit_inputs_file() {
        let program_path = test_file_path("program").with_extension("masm");
        let inputs_path = test_file_path("missing-explicit").with_extension("inputs");

        let err = InputFile::read(&Some(inputs_path.clone()), &program_path)
            .expect_err("missing explicit input file should fail");

        assert!(err.to_string().contains("Failed to open input file"));
        assert!(err.to_string().contains(&inputs_path.display().to_string()));
    }

    #[test]
    fn input_file_read_loads_inferred_inputs_file() {
        let program_path = test_file_path("inferred-present").with_extension("masm");
        let inputs_path = program_path.with_extension("inputs");
        fs::write(&inputs_path, r#"{"operand_stack":["7"]}"#).expect("write input file");

        let inputs = InputFile::read(&None, &program_path).expect("input file should load");

        assert_eq!(inputs.operand_stack, ["7"]);
        fs::remove_file(inputs_path).expect("remove input file");
    }

    #[test]
    fn input_file_read_rejects_oversized_files_before_json_parsing() {
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len(InputFile::MAX_FILE_SIZE as u64 + 1).unwrap();
        let err = InputFile::read(&Some(file.path().to_path_buf()), file.path()).unwrap_err();
        let message = format!("{err:?}");
        assert!(message.contains("size limit of 67108864 bytes"), "{message}");
        assert!(err.to_string().contains(&file.path().display().to_string()), "{message}");

        // The exact limit reaches the JSON parser, which rejects the sparse file's zero bytes.
        file.as_file().set_len(InputFile::MAX_FILE_SIZE as u64).unwrap();
        let err = InputFile::read(&Some(file.path().to_path_buf()), file.path()).unwrap_err();
        assert!(err.to_string().contains("Failed to deserialize input data"));
    }

    #[test]
    fn input_file_read_rejects_invalid_utf8_in_ignored_fields() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), b"{\"operand_stack\":[],\"ignored\":\"\xff\"}").unwrap();
        let err = InputFile::read(&Some(file.path().to_path_buf()), file.path()).unwrap_err();
        assert!(format!("{err:?}").contains("utf-8"));
    }

    #[test]
    fn input_file_read_rejects_non_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let err = InputFile::read(&Some(dir.path().to_path_buf()), dir.path()).unwrap_err();
        assert!(format!("{err:?}").contains("expected a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn input_file_read_accepts_symlinks_to_regular_files_and_rejects_sockets() {
        // The default macOS temporary path can exceed the Unix socket path limit.
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let target = dir.path().join("target.inputs");
        let link = dir.path().join("link.inputs");
        fs::write(&target, br#"{"operand_stack":["7"]}"#).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(InputFile::read(&Some(link), &target).unwrap().operand_stack, ["7"]);

        let socket = dir.path().join("socket.inputs");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let err = InputFile::read(&Some(socket), &target).unwrap_err();
        assert!(format!("{err:?}").contains("expected a regular file"));
    }
}
