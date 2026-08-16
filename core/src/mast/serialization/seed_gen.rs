//! Test helper for generating fuzz corpus seeds.
//!
//! Run with: cargo test -p miden-core --features serde generate_fuzz_seeds -- --ignored --nocapture

use alloc::{sync::Arc, vec::Vec};
use std::println;

use crate::{
    Felt, Word,
    advice::{AdviceInputs, AdviceMap},
    deferred::{DeferredState, DeferredStateWire, Node, TRUE_DIGEST},
    mast::{BasicBlockNodeBuilder, JoinNodeBuilder, MastForest},
    operations::Operation,
    program::{KernelDescriptor, Program, StackInputs, StackOutputs},
    proof::{ExecutionProof, HashFunction, PrecompileProof, StarkProof, VmProof},
    serde::{ByteWriter, Serializable},
};

/// Generates seed corpus files for fuzzing.
/// Run with: cargo test -p miden-core --features serde generate_fuzz_seeds -- --ignored --nocapture
#[test]
#[ignore = "run manually to generate fuzz seeds"]
fn generate_fuzz_seeds() {
    fn write_mast_seed(targets: &[&str], name: &str, bytes: &[u8]) {
        for target in targets {
            write_seed(target, name, bytes);
        }
    }

    fn write_seed(target: &str, name: &str, bytes: &[u8]) {
        let corpus_dir = std::path::Path::new("../tools/miden-core-fuzz/corpus").join(target);
        std::fs::create_dir_all(&corpus_dir).expect("Failed to create corpus directory");
        std::fs::write(corpus_dir.join(name), bytes).unwrap();
        println!("Generated {}/{} ({} bytes)", target, name, bytes.len());
    }

    // Seed 1: Minimal valid forest (single basic block)
    {
        let mut forest = MastForest::new();
        let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut forest)
            .unwrap();
        forest.make_root(block_id);

        let bytes = forest.to_bytes();
        write_mast_seed(
            &[
                "mast_forest_deserialize",
                "mast_forest_validate",
                "mast_node_info",
                "mast_forest_wire_view_new",
                "basic_block_data",
                "debug_info",
            ],
            "minimal_block.bin",
            &bytes,
        );
    }

    // Seed 2: Forest with join node
    {
        let mut forest = MastForest::new();
        let block1 = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut forest)
            .unwrap();
        let block2 = BasicBlockNodeBuilder::new(vec![Operation::Mul])
            .add_to_forest(&mut forest)
            .unwrap();
        let join = JoinNodeBuilder::new([block1, block2]).add_to_forest(&mut forest).unwrap();
        forest.make_root(join);

        let bytes = forest.to_bytes();
        write_mast_seed(
            &[
                "mast_forest_deserialize",
                "mast_forest_validate",
                "mast_node_info",
                "mast_forest_wire_view_new",
                "basic_block_data",
                "debug_info",
            ],
            "join_node.bin",
            &bytes,
        );
    }

    // Seed 3: Normal forest
    {
        let mut forest = MastForest::new();
        let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut forest)
            .unwrap();
        forest.make_root(block_id);

        let mut bytes = Vec::new();
        forest.write_into(&mut bytes);
        write_mast_seed(
            &[
                "mast_forest_deserialize",
                "mast_forest_validate",
                "mast_node_info",
                "mast_forest_wire_view_new",
                "basic_block_data",
            ],
            "normal.bin",
            &bytes,
        );
    }

    // Seed 4: Hashless forest (no internal hash section, no debug info)
    {
        let mut forest = MastForest::new();
        let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut forest)
            .unwrap();
        forest.make_root(block_id);

        let mut bytes = Vec::new();
        forest.write_hashless(&mut bytes);
        write_mast_seed(
            &["mast_forest_validate", "mast_node_info", "mast_forest_wire_view_new"],
            "hashless.bin",
            &bytes,
        );
    }

    // Seed 5: Empty header (just magic + flags + version + minimal counts)
    {
        let bytes: &[u8] = b"MAST\x00\x00\x00\x01";
        write_mast_seed(
            &[
                "mast_forest_deserialize",
                "mast_forest_validate",
                "mast_node_info",
                "mast_forest_wire_view_new",
            ],
            "header_only.bin",
            bytes,
        );
    }

    // Seed 6: Invalid magic
    {
        let bytes: &[u8] = b"XXXX\x00\x00\x00\x01";
        write_mast_seed(
            &[
                "mast_forest_deserialize",
                "mast_forest_validate",
                "mast_node_info",
                "mast_forest_wire_view_new",
            ],
            "invalid_magic.bin",
            bytes,
        );
    }

    // Program seed
    {
        let mut forest = MastForest::new();
        let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut forest)
            .unwrap();
        forest.make_root(block_id);
        let program = Program::new(Arc::new(forest), block_id);
        write_seed("program_deserialize", "minimal_program.bin", &program.to_bytes());
    }

    // Program seed with invalid duplicate-kernel payload.
    {
        let mut forest = MastForest::new();
        let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
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
        let kernel = KernelDescriptor::from_hashes_unchecked(vec![a, a]);
        let program = Program::with_kernel(Arc::new(forest), block_id, kernel);

        write_seed("program_deserialize", "program_with_duplicate_kernel.bin", &program.to_bytes());
    }

    // KernelDescriptor seed
    {
        let kernel = KernelDescriptor::default();
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

        let non_empty = KernelDescriptor::new(&[a]).expect("failed to build non-empty kernel");
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
        let max_kernel =
            KernelDescriptor::new(&max_kernel).expect("failed to build max-size kernel");
        write_seed("kernel_deserialize", "max_kernel_255.bin", &max_kernel.to_bytes());

        // Invalid seed: duplicate hashes should deserialize to Err (never panic).
        let duplicate_kernel = KernelDescriptor::from_hashes_unchecked(vec![b, a, a]);
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

    // Deferred-state wire seeds. A deferred execution proof carries this passive wire so a
    // delegated prover can hydrate it later and produce a precompile STARK proof for its root.
    {
        let empty = DeferredStateWire::default();
        write_seed("deferred_state_wire_deserialize", "empty_wire.bin", &empty.to_bytes());

        let mut state = DeferredState::default();
        let statement = state
            .register(Node::and(TRUE_DIGEST, TRUE_DIGEST))
            .expect("framework statement should register");
        state.log_statement(statement).expect("framework statement should log");
        let wire = state.to_wire().expect("framework state should encode as wire");
        write_seed("deferred_state_wire_deserialize", "all_entries_wire.bin", &wire.to_bytes());

        let mut oversized_entry_count = Vec::new();
        oversized_entry_count.write_usize(usize::MAX);
        write_seed(
            "deferred_state_wire_deserialize",
            "oversized_entry_count.bin",
            &oversized_entry_count,
        );

        #[cfg(feature = "serde")]
        {
            let empty_json =
                serde_json::to_vec(&empty).expect("failed to serialize empty wire seed");
            write_seed("deferred_state_wire_serde_deserialize", "empty_wire.json", &empty_json);
            let wire_json = serde_json::to_vec(&wire).expect("failed to serialize wire seed");
            write_seed(
                "deferred_state_wire_serde_deserialize",
                "all_entries_wire.json",
                &wire_json,
            );

            let vm = |precompile_root, marker| VmProof {
                proof: StarkProof::new(vec![marker], HashFunction::Rpo256),
                precompile_root,
            };
            let precompile = |roots| PrecompileProof {
                proof: StarkProof::new(vec![2], HashFunction::Rpo256),
                roots,
            };
            let deferred = ExecutionProof::Deferred { vm: vm(statement, 1), precompile: wire };
            let complete_without_precompile =
                ExecutionProof::Complete { vm: vm(TRUE_DIGEST, 3), precompile: None };
            let complete_with_precompile = ExecutionProof::Complete {
                vm: vm(statement, 4),
                precompile: Some(precompile(vec![statement])),
            };
            let empty_roots = ExecutionProof::Complete {
                vm: vm(statement, 5),
                precompile: Some(precompile(Vec::new())),
            };
            let duplicate_roots = ExecutionProof::Complete {
                vm: vm(statement, 6),
                precompile: Some(precompile(vec![statement, statement])),
            };
            let true_root = ExecutionProof::Complete {
                vm: vm(statement, 7),
                precompile: Some(precompile(vec![TRUE_DIGEST])),
            };

            for (name, proof) in [
                ("deferred_non_empty_wire.json", &deferred),
                ("complete_without_precompile.json", &complete_without_precompile),
                ("complete_with_precompile.json", &complete_with_precompile),
                ("invalid_empty_roots.json", &empty_roots),
                ("duplicate_roots.json", &duplicate_roots),
                ("invalid_true_root.json", &true_root),
            ] {
                let json = serde_json::to_vec(proof)
                    .expect("failed to serialize synthetic execution proof seed");
                write_seed("execution_proof_serde_deserialize", name, &json);
            }

            let proofs = vec![
                deferred.clone(),
                complete_without_precompile,
                complete_with_precompile,
                empty_roots,
                duplicate_roots,
                true_root,
            ];
            let proofs_json = serde_json::to_vec(&proofs)
                .expect("failed to serialize execution proof vector seed");
            write_seed("execution_proof_serde_deserialize", "proof_vector.json", &proofs_json);
            let option_json = serde_json::to_vec(&Some(deferred))
                .expect("failed to serialize execution proof option seed");
            write_seed("execution_proof_serde_deserialize", "proof_option.json", &option_json);
            write_seed("execution_proof_serde_deserialize", "proof_option_none.json", b"null");
        }
    }

    // Execution proof seed (minimal complete proof with no precompile obligation).
    {
        let stark = StarkProof::new(Vec::new(), HashFunction::Rpo256);
        let vm = VmProof {
            proof: stark,
            precompile_root: TRUE_DIGEST,
        };
        let proof = ExecutionProof::Complete { vm, precompile: None };
        let proof = proof.to_bytes();
        write_seed("execution_proof_deserialize", "minimal_proof.bin", &proof);
    }

    // Execution proof seed for malicious VM STARK length-prefix deserialization.
    {
        let mut oversized_proof_len = Vec::new();
        oversized_proof_len.write_u8(1); // Complete execution proof discriminant.
        oversized_proof_len.write_usize(usize::MAX);
        write_seed("execution_proof_deserialize", "oversized_proof_len.bin", &oversized_proof_len);
    }

    println!("\nSeed corpus generated in ../tools/miden-core-fuzz/corpus");
}
