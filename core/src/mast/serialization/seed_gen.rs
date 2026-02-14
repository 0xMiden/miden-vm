//! Test helper for generating fuzz corpus seeds.
//!
//! Run with: cargo test -p miden-core generate_fuzz_seeds -- --ignored --nocapture

use alloc::vec::Vec;
use std::println;

use crate::{
    mast::{BasicBlockNodeBuilder, JoinNodeBuilder, MastForest, MastForestContributor},
    operations::Operation,
    serde::Serializable,
};

/// Generates seed corpus files for fuzzing.
/// Run with: cargo test -p miden-core generate_fuzz_seeds -- --ignored --nocapture
#[test]
#[ignore = "run manually to generate fuzz seeds"]
fn generate_fuzz_seeds() {
    let corpus_dir = std::path::Path::new("../miden-core-fuzz/corpus/mast_forest_deserialize");
    std::fs::create_dir_all(corpus_dir).expect("Failed to create corpus directory");

    // Seed 1: Minimal valid forest (single basic block)
    {
        let mut forest = MastForest::new();
        let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut forest)
            .unwrap();
        forest.make_root(block_id);

        let bytes = forest.to_bytes();
        std::fs::write(corpus_dir.join("minimal_block.bin"), &bytes).unwrap();
        println!("Generated minimal_block.bin ({} bytes)", bytes.len());
    }

    // Seed 2: Forest with join node
    {
        let mut forest = MastForest::new();
        let block1 = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut forest)
            .unwrap();
        let block2 = BasicBlockNodeBuilder::new(vec![Operation::Mul], Vec::new())
            .add_to_forest(&mut forest)
            .unwrap();
        let join = JoinNodeBuilder::new([block1, block2]).add_to_forest(&mut forest).unwrap();
        forest.make_root(join);

        let bytes = forest.to_bytes();
        std::fs::write(corpus_dir.join("join_node.bin"), &bytes).unwrap();
        println!("Generated join_node.bin ({} bytes)", bytes.len());
    }

    // Seed 3: Stripped forest (no debug info)
    {
        let mut forest = MastForest::new();
        let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut forest)
            .unwrap();
        forest.make_root(block_id);

        let mut bytes = Vec::new();
        forest.write_stripped(&mut bytes);
        std::fs::write(corpus_dir.join("stripped.bin"), &bytes).unwrap();
        println!("Generated stripped.bin ({} bytes)", bytes.len());
    }

    // Seed 4: Empty header (just magic + flags + version + minimal counts)
    {
        let bytes: &[u8] = b"MAST\x00\x00\x00\x01";
        std::fs::write(corpus_dir.join("header_only.bin"), bytes).unwrap();
        println!("Generated header_only.bin ({} bytes)", bytes.len());
    }

    // Seed 5: Invalid magic
    {
        let bytes: &[u8] = b"XXXX\x00\x00\x00\x01";
        std::fs::write(corpus_dir.join("invalid_magic.bin"), bytes).unwrap();
        println!("Generated invalid_magic.bin ({} bytes)", bytes.len());
    }

    println!("\nSeed corpus generated in {}", corpus_dir.display());
}
