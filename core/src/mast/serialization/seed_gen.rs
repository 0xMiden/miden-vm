//! Test helper for generating fuzz corpus seeds.
//!
//! Run with: cargo test -p miden-core generate_fuzz_seeds -- --ignored --nocapture

use alloc::{sync::Arc, vec::Vec};
use std::println;

use crate::{
    Felt, Word,
    advice::{AdviceInputs, AdviceMap},
    events::EventId,
    mast::{BasicBlockNodeBuilder, JoinNodeBuilder, MastForest, MastForestContributor},
    operations::Operation,
    precompile::PrecompileRequest,
    program::{Kernel, Program, StackInputs, StackOutputs},
    proof::{ExecutionProof, HashFunction},
    serde::{ByteWriter, Serializable},
};

/// Generates seed corpus files for fuzzing.
/// Run with: cargo test -p miden-core generate_fuzz_seeds -- --ignored --nocapture
#[test]
#[ignore = "run manually to generate fuzz seeds"]
fn generate_fuzz_seeds() {
    fn write_seed(target: &str, name: &str, bytes: &[u8]) {
        let corpus_dir = std::path::Path::new("../miden-core-fuzz/corpus").join(target);
        std::fs::create_dir_all(&corpus_dir).expect("Failed to create corpus directory");
        std::fs::write(corpus_dir.join(name), bytes).unwrap();
        println!("Generated {}/{} ({} bytes)", target, name, bytes.len());
    }

    // Seed 1: Minimal valid forest (single basic block)
    {
        let mut forest = MastForest::new();
        let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut forest)
            .unwrap();
        forest.make_root(block_id);

        let bytes = forest.to_bytes();
        write_seed("mast_forest_deserialize", "minimal_block.bin", &bytes);
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
        write_seed("mast_forest_deserialize", "join_node.bin", &bytes);
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
        write_seed("mast_forest_deserialize", "stripped.bin", &bytes);
    }

    // Seed 4: Empty header (just magic + flags + version + minimal counts)
    {
        let bytes: &[u8] = b"MAST\x00\x00\x00\x01";
        write_seed("mast_forest_deserialize", "header_only.bin", bytes);
    }

    // Seed 5: Invalid magic
    {
        let bytes: &[u8] = b"XXXX\x00\x00\x00\x01";
        write_seed("mast_forest_deserialize", "invalid_magic.bin", bytes);
    }

    // Program seed
    {
        let mut forest = MastForest::new();
        let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut forest)
            .unwrap();
        forest.make_root(block_id);
        let program = Program::new(Arc::new(forest), block_id);
        write_seed("program_deserialize", "minimal_program.bin", &program.to_bytes());
    }

    // Program seed with invalid duplicate-kernel payload.
    {
        let mut forest = MastForest::new();
        let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut forest)
            .unwrap();
        forest.make_root(block_id);

        let a: Word = [
            Felt::new_unchecked(9),
            Felt::new_unchecked(10),
            Felt::new_unchecked(11),
            Felt::new_unchecked(12),
        ]
        .into();
        let kernel = Kernel::from_hashes_unchecked(vec![a, a]);
        let program = Program::with_kernel(Arc::new(forest), block_id, kernel);

        write_seed("program_deserialize", "program_with_duplicate_kernel.bin", &program.to_bytes());
    }

    // Kernel seed
    {
        let kernel = Kernel::default();
        write_seed("kernel_deserialize", "empty_kernel.bin", &kernel.to_bytes());

        let a: Word = [
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
        ]
        .into();
        let b: Word = [
            Felt::new_unchecked(5),
            Felt::new_unchecked(6),
            Felt::new_unchecked(7),
            Felt::new_unchecked(8),
        ]
        .into();

        let non_empty = Kernel::new(&[a]).expect("failed to build non-empty kernel");
        write_seed("kernel_deserialize", "single_kernel.bin", &non_empty.to_bytes());

        let max_kernel: Vec<Word> = (0u64..=254)
            .map(|n| {
                [
                    Felt::new_unchecked(n),
                    Felt::new_unchecked(n + 1),
                    Felt::new_unchecked(n + 2),
                    Felt::new_unchecked(n + 3),
                ]
                .into()
            })
            .collect();
        let max_kernel = Kernel::new(&max_kernel).expect("failed to build max-size kernel");
        write_seed("kernel_deserialize", "max_kernel_255.bin", &max_kernel.to_bytes());

        // Invalid seed: duplicate hashes should deserialize to Err (never panic).
        let duplicate_kernel = Kernel::from_hashes_unchecked(vec![b, a, a]);
        write_seed("kernel_deserialize", "duplicate_kernel.bin", &duplicate_kernel.to_bytes());

        // Serde kernel seeds (JSON payloads) used by kernel_serde_deserialize fuzz target.
        write_seed("kernel_serde_deserialize", "empty_kernel.json", b"[]");
        write_seed("kernel_serde_deserialize", "duplicate_kernel.json", b"[[1,2,3,4],[1,2,3,4]]");
        let too_many_hashes: Vec<[u64; 4]> =
            (0u64..=255).map(|n| [n, n + 1, n + 2, n + 3]).collect();
        let too_many_hashes_json =
            serde_json::to_vec(&too_many_hashes).expect("failed to serialize too_many_hashes seed");
        write_seed("kernel_serde_deserialize", "too_many_hashes.json", &too_many_hashes_json);
    }

    // Stack IO seeds
    {
        let inputs = StackInputs::new(&[Felt::new_unchecked(1), Felt::new_unchecked(2)]).unwrap();
        let outputs = StackOutputs::new(&[Felt::new_unchecked(3), Felt::new_unchecked(4)]).unwrap();
        write_seed("stack_io_deserialize", "stack_inputs.bin", &inputs.to_bytes());
        write_seed("stack_io_deserialize", "stack_outputs.bin", &outputs.to_bytes());
    }

    // Advice inputs seed
    {
        let advice = AdviceInputs::default();
        let advice_map = AdviceMap::default();
        write_seed("advice_inputs_deserialize", "advice_inputs.bin", &advice.to_bytes());
        write_seed("advice_inputs_deserialize", "advice_map.bin", &advice_map.to_bytes());
    }

    // Operation seed
    {
        let op = Operation::Add;
        write_seed("operation_deserialize", "op_add.bin", &op.to_bytes());
    }

    // Precompile request seed
    {
        let request = PrecompileRequest::new(EventId::from_u64(1), vec![1, 2, 3, 4]);
        write_seed("precompile_request_deserialize", "precompile_request.bin", &request.to_bytes());
    }

    // Execution proof seed (minimal)
    {
        let request = PrecompileRequest::new(EventId::from_u64(1), vec![1, 2, 3, 4]);
        let proof = ExecutionProof::new(Vec::new(), HashFunction::Rpo256, vec![request]);
        write_seed("execution_proof_deserialize", "minimal_proof.bin", &proof.to_bytes());
    }

    // Execution proof seeds for malicious length-prefix deserialization.
    {
        let mut oversized_proof_len = Vec::new();
        oversized_proof_len.write_usize(usize::MAX);
        write_seed("execution_proof_deserialize", "oversized_proof_len.bin", &oversized_proof_len);

        let mut oversized_pc_requests_len = Vec::new();
        oversized_pc_requests_len.write_usize(0);
        oversized_pc_requests_len.write_u8(HashFunction::Blake3_256 as u8);
        oversized_pc_requests_len.write_usize(usize::MAX);
        write_seed(
            "execution_proof_deserialize",
            "oversized_pc_requests_len.bin",
            &oversized_pc_requests_len,
        );
    }

    // Execution proof seed with many small precompile requests.
    {
        let pc_requests = (0..64)
            .map(|event_id| PrecompileRequest::new(EventId::from_u64(event_id), Vec::new()))
            .collect();
        let proof = ExecutionProof::new(vec![1, 2, 3], HashFunction::Blake3_256, pc_requests);
        write_seed(
            "execution_proof_deserialize",
            "many_minimal_precompile_requests.bin",
            &proof.to_bytes(),
        );
    }

    println!("\nSeed corpus generated in ../miden-core-fuzz/corpus");
}
