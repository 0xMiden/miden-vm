use std::{fs, path::Path, process::Command, sync::Arc};

use assert_cmd::prelude::*;
use miden_core::{
    Felt, Word, ZERO,
    deferred::{Node, PrecompileWitnessEntry, deferred_chunks_frame},
};
use miden_precompiles::{UintDomain, UintPrecompile};
use miden_vm::{
    Assembler, DefaultHost, ExecutionProof, HashFunction, PrecompileProof, PrecompileStatus,
    PrecompileWitness, Processor, Program, StarkProof, VmProof,
    default_verification_precompile_limits, serde::Serializable,
};
use predicates::prelude::*;
use tempfile::TempDir;

use super::cli_test::bin_under_test;

fn word_literal(word: Word) -> String {
    format!("[{}, {}, {}, {}]", word[0], word[1], word[2], word[3])
}

/// Duplicate guest requests consume execution work even though the exported uint nodes are shared.
fn precompile_source(requests: usize, rhs: u32) -> String {
    let mut chunk = [ZERO; 8];
    chunk[0] = Felt::from_u32(1);
    let value = Node::value(UintPrecompile::value_frame(UintDomain::U256), chunk)
        .unwrap()
        .digest();
    chunk[0] = Felt::from_u32(rhs);
    let rhs = Node::value(UintPrecompile::value_frame(UintDomain::U256), chunk)
        .unwrap()
        .digest();
    let eq = UintPrecompile::op_frame(UintPrecompile::EQ_OP_ID).initial_chaining_word();
    let request = format!(
        "push.{} push.{} push.{} adv.register_deferred movdnw.2 compress dropw dropw log_deferred dropw\n",
        word_literal(value),
        word_literal(rhs),
        word_literal(eq),
    );
    format!("begin {} end", request.repeat(requests))
}

fn write_program(dir: &Path, source: &str) -> Program {
    let package = Assembler::default().assemble_program("program", source).unwrap();
    fs::write(dir.join("program.masm"), source).unwrap();
    fs::write(dir.join("program.masp"), package.to_bytes()).unwrap();
    fs::write(dir.join("program.inputs"), r#"{"operand_stack":[]}"#).unwrap();
    package.unwrap_program()
}

fn verify_command(dir: &Path, action: &str, program: &Program) -> Command {
    let mut command = bin_under_test(dir);
    let hash: [u8; 32] = program.hash().into();
    command.args([action, "--proof", "program.proof", "--program-hash", &hex::encode(hash)]);
    command
}

fn write_proof(dir: &Path, proof: &ExecutionProof) {
    fs::write(dir.join("program.proof"), proof.to_bytes()).unwrap();
}

fn read_proof(dir: &Path) -> ExecutionProof {
    ExecutionProof::read_from_bytes(&fs::read(dir.join("program.proof")).unwrap()).unwrap()
}

#[test]
fn cli_precompile_policy_errors_precede_input_loading() {
    let dir = TempDir::new().unwrap();
    bin_under_test(dir.path())
        .args(["prove", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("private advice"))
        .stdout(predicate::str::contains("prove-complete"));
    for flag in ["--deferred", "--complete"] {
        bin_under_test(dir.path())
            .args(["prove", "missing.masm", flag])
            .assert()
            .code(2)
            .stderr(predicate::str::contains(flag))
            .stdout(predicate::str::is_empty());
    }
    bin_under_test(dir.path())
        .args(["verify", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--set"))
        .stdout(predicate::str::contains("--require-complete").not());
    let invalid = [
        ("precompiles.max-elements", (u128::from(u64::MAX) + 1).to_string()),
        ("precompiles.hash.max-total-size", format!("{}Gi", u64::MAX)),
        ("precompiles.msm.max-size", (u64::from(u32::MAX) + 1).to_string()),
        ("precompiles.msm.max-total-size", "1Mi".to_owned()),
        ("verification.require-complete", "true".to_owned()),
    ];
    for action in ["run", "prove", "prove-complete", "verify", "verify-complete", "verify-partial"]
    {
        for (key, value) in &invalid {
            let mut command = bin_under_test(dir.path());
            command.arg(action);
            if action.starts_with("verify") {
                command.args(["--proof", "missing.proof", "--program-hash", "00"]);
            } else {
                command.arg("missing.masm");
            }
            command
                .arg("--set")
                .arg(format!("{key}={value}"))
                .assert()
                .failure()
                .stderr(predicate::str::contains(*key))
                .stdout(predicate::str::is_empty());
        }
    }
}

#[test]
fn proving_commands_select_witness_export_or_a_precompile_stark() {
    let dir = TempDir::new().unwrap();
    let value = UintPrecompile::value_frame(UintDomain::U256).initial_chaining_word();
    let eq = UintPrecompile::op_frame(UintPrecompile::EQ_OP_ID).initial_chaining_word();
    // Register the private advice value, then assert its equality with itself. The public
    // program and outputs contain neither the value nor its raw limbs.
    let source = format!(
        "begin adv_pushw adv_pushw push.{} adv.register_deferred movdnw.2 compress dropw dropw \
         dupw push.{} adv.register_deferred movdnw.2 compress dropw dropw log_deferred dropw end",
        word_literal(value),
        word_literal(eq),
    );
    write_program(dir.path(), &source);
    fs::write(
        dir.path().join("program.inputs"),
        r#"{"operand_stack":[],"advice_stack":["42","42","42","42","42","42","42","42"]}"#,
    )
    .unwrap();

    bin_under_test(dir.path())
        .args([
            "prove-complete",
            "program.masm",
            "--set",
            "resources.precompile-prover-memory=0",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("precompile prover memory"))
        .stderr(predicate::str::contains("budget of 0 bytes"));

    bin_under_test(dir.path())
        .args(["prove-complete", "program.masm"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Proof status: complete"))
        .stdout(predicate::str::contains("Precompile witness: exported").not());
    assert!(matches!(read_proof(dir.path()).precompile(), PrecompileStatus::Proven(_)));

    bin_under_test(dir.path())
        .args(["prove", "program.masm", "--set", "resources.precompile-prover-memory=0"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Proof status: deferred"))
        .stdout(predicate::str::contains("may reveal private advice inputs"));
    let proof = read_proof(dir.path());
    let PrecompileStatus::Deferred(witness) = proof.precompile() else {
        panic!("prove must export the deferred witness")
    };
    let private_limbs = [Felt::from_u32(42); 8];
    assert!(witness.entries().iter().any(|entry| matches!(
        entry,
        PrecompileWitnessEntry::Data { chunks, .. } if chunks.contains(&private_limbs)
    )));
}

#[test]
fn cli_precompile_execution_and_export_limits_cover_masm_and_masp() {
    let dir = TempDir::new().unwrap();
    let eq = Node::join(
        UintPrecompile::op_frame(UintPrecompile::EQ_OP_ID),
        Word::default(),
        Word::default(),
    )
    .unwrap();
    let per_request = eq.felt_len() + Node::and(Word::default(), Word::default()).felt_len();
    // Repeated registrations are charged during execution even when export shares the uint nodes.
    for requests in [1, 3] {
        let program = write_program(dir.path(), &precompile_source(requests, 1));
        let (_, portable) = Processor::new(&program)
            .record_witness()
            .run_sync(&mut DefaultHost::default())
            .map(|output| output.witness)
            .unwrap()
            .into_parts();
        let prepared = portable
            .unwrap()
            .prepare(
                Arc::new(miden_precompiles::registry()),
                &default_verification_precompile_limits(),
            )
            .unwrap();
        let execution_elements = u64::try_from(requests * per_request).unwrap();
        let verification_elements = prepared.work().elements();
        let shared = execution_elements.max(verification_elements);
        let (scope, boundary) = if requests == 1 {
            ("verification", verification_elements)
        } else {
            ("execution", execution_elements)
        };
        fs::write(
            dir.path().join("miden-vm.toml"),
            format!("schema-version = 1\n[precompiles]\nmax-elements = {shared}\n"),
        )
        .unwrap();
        for extension in ["masm", "masp"] {
            for action in ["run", "prove"] {
                let mut command = bin_under_test(dir.path());
                command.arg(action).arg(format!("program.{extension}"));
                command.assert().success();
                let mut command = bin_under_test(dir.path());
                command
                    .arg(action)
                    .arg(format!("program.{extension}"))
                    .arg("--set")
                    .arg(format!("{scope}.precompiles.max-elements={}", boundary - 1));
                command
                    .assert()
                    .failure()
                    .stderr(predicate::str::contains(format!("maximum is {}", boundary - 1)));
            }
        }
    }
}

#[test]
fn cli_precompile_verification_status_limits_and_failures() {
    let dir = TempDir::new().unwrap();
    let program = write_program(dir.path(), &precompile_source(1, 1));
    bin_under_test(dir.path())
        .args(["prove", "program.masm"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Proof status: deferred"));
    let deferred = read_proof(dir.path());
    let PrecompileStatus::Deferred(portable) = deferred.precompile() else {
        panic!("expected deferred witness")
    };
    let prepared = portable
        .clone()
        .prepare(
            Arc::new(miden_precompiles::registry()),
            &default_verification_precompile_limits(),
        )
        .unwrap();
    let elements = prepared.work().elements();
    verify_command(dir.path(), "verify-complete", &program)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("verify-complete"))
        .stderr(predicate::str::contains("proof has not been verified"))
        .stdout(predicate::str::contains("Proof status:").not())
        .stdout(predicate::str::contains("validated natively").not());
    for action in ["verify", "verify-partial"] {
        verify_command(dir.path(), action, &program)
            .args(["--set", &format!("verification.precompiles.max-elements={elements}")])
            .assert()
            .success()
            .stdout(predicate::str::contains("Proof status: deferred"))
            .stdout(predicate::str::contains("VM STARK security level:"))
            .stdout(predicate::str::contains("bits conjectured,"))
            .stdout(predicate::str::contains("bits proven"))
            .stdout(predicate::str::contains("Precompile witness: validated natively"))
            .stdout(predicate::str::contains("Precompile STARK: not supplied"))
            .stdout(predicate::str::contains(format!(
                "Outstanding precompile root: {}",
                deferred.vm().precompile_root
            )))
            .stdout(predicate::str::contains("Minimum per-STARK security level:").not());
        verify_command(dir.path(), action, &program)
            .args(["--set", &format!("verification.precompiles.max-elements={}", elements - 1)])
            .assert()
            .failure()
            .stdout(predicate::str::contains("Proof status:").not());
        verify_command(dir.path(), action, &program)
            .args(["--set", "verification.min-security-bits=1000"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("below the required 1000 bits"))
            .stdout(predicate::str::contains("validated natively").not());
    }

    bin_under_test(dir.path())
        .args(["prove-complete", "program.masm"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Proof status: complete"));
    let complete = read_proof(dir.path());
    // Verification consumes the proof, public inputs/outputs and expected hash.
    fs::remove_file(dir.path().join("program.masm")).unwrap();
    fs::remove_file(dir.path().join("program.masp")).unwrap();
    for action in ["verify", "verify-complete"] {
        verify_command(dir.path(), action, &program)
            .args(["--set", "precompiles.max-elements=0"])
            .assert()
            .code(0)
            .stdout(predicate::str::contains("Proof status: complete"))
            .stdout(predicate::str::contains("Minimum per-STARK security level:"))
            .stdout(predicate::str::contains("bits proven"))
            .stdout(predicate::str::contains("validated natively").not());
    }
    verify_command(dir.path(), "verify-partial", &program)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("verify-partial"))
        .stderr(predicate::str::contains("proof has not been verified"))
        .stdout(predicate::str::contains("Proof status:").not());

    let PrecompileStatus::Proven(precompile) = complete.precompile() else {
        panic!("expected precompile STARK")
    };
    let mut bytes = precompile.proof.bytes().to_vec();
    bytes.push(0);
    let invalid_precompile = ExecutionProof::new(
        complete.vm().clone(),
        PrecompileStatus::Proven(PrecompileProof {
            proof: StarkProof::new(bytes, precompile.proof.hash_fn()),
            roots: precompile.roots.clone(),
        }),
    );
    write_proof(dir.path(), &invalid_precompile);
    for action in ["verify", "verify-complete"] {
        verify_command(dir.path(), action, &program)
            .assert()
            .failure()
            .stdout(predicate::str::contains("Proof status:").not());
    }

    let unrelated = PrecompileWitness::from_entries(vec![PrecompileWitnessEntry::Data {
        frame: deferred_chunks_frame(1),
        chunks: vec![[ZERO; 8]],
    }])
    .unwrap();
    let wrong_root =
        ExecutionProof::new(deferred.vm().clone(), PrecompileStatus::Deferred(unrelated));
    write_proof(dir.path(), &wrong_root);
    for action in ["verify", "verify-partial"] {
        verify_command(dir.path(), action, &program)
            .assert()
            .failure()
            .stderr(predicate::str::contains("does not match the VM obligation"))
            .stdout(predicate::str::contains("Proof status:").not());
    }

    let mut bytes = deferred.vm().proof.bytes().to_vec();
    bytes.push(0);
    let invalid_vm = ExecutionProof::new(
        VmProof {
            proof: StarkProof::new(bytes, deferred.vm().proof.hash_fn()),
            precompile_root: deferred.vm().precompile_root,
        },
        deferred.precompile().clone(),
    );
    write_proof(dir.path(), &invalid_vm);
    // The two commands that accept deferred proofs must authenticate the VM STARK.
    for (action, expected_error) in [
        ("verify", "Program failed verification!"),
        ("verify-partial", "Program failed verification!"),
        ("verify-complete", "proof has not been verified"),
    ] {
        verify_command(dir.path(), action, &program)
            .assert()
            .failure()
            .stderr(predicate::str::contains(expected_error))
            .stdout(predicate::str::contains("Proof status:").not())
            .stdout(predicate::str::contains("validated natively").not());
    }

    // Deferring the precompile STARK must not bypass native execution checks in either mode.
    let program = write_program(dir.path(), &precompile_source(1, 2));
    for action in ["prove", "prove-complete"] {
        bin_under_test(dir.path())
            .args([action, "program.masm"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("values disagree"))
            .stdout(predicate::str::contains("Proof status:").not());
    }

    fs::write(dir.path().join("program.proof"), []).unwrap();
    verify_command(dir.path(), "verify", &program)
        .assert()
        .failure()
        .stderr(predicate::str::contains("Failed to decode proof data"))
        .stdout(predicate::str::contains("Proof status:").not());
}

#[test]
fn cli_proves_and_verifies_empty_precompile_work_with_each_hash_schedule() {
    let dir = TempDir::new().unwrap();
    let program = write_program(dir.path(), "begin push.7 swap drop end");
    for (file, hasher) in [
        ("program.masm", HashFunction::Eidos),
        ("program.masp", HashFunction::Blake3_256),
    ] {
        // The first case exercises the default hasher. The second selects BLAKE3 from the file.
        if hasher == HashFunction::Blake3_256 {
            fs::write(
                dir.path().join("miden-vm.toml"),
                "schema-version = 1\n[proving]\nhasher = \"blake3-256\"\n",
            )
            .unwrap();
        }

        let mut eager_proof = None;
        for (action, hash_lde_blocks) in [("prove", false), ("prove-complete", true)] {
            let mut prove = bin_under_test(dir.path());
            // A single worker makes proof-of-work witness selection deterministic across runs.
            prove
                .env("RAYON_NUM_THREADS", "1")
                .args([action, file, "--set", "display.num-outputs=0"])
                .args(["--set", &format!("proving.hash-lde-blocks={hash_lde_blocks}")])
                .assert()
                .success()
                .stdout(predicate::str::contains("Proof status: complete"))
                .stdout(predicate::str::contains("Output: []"));

            let proof = read_proof(dir.path());
            assert_eq!(proof.vm().proof.hash_fn(), hasher);
            assert!(matches!(proof.precompile(), PrecompileStatus::Empty));
            let outputs: serde_json::Value =
                serde_json::from_slice(&fs::read(dir.path().join("program.outputs")).unwrap())
                    .unwrap();
            let stack = outputs["stack"].as_array().unwrap();
            assert_eq!(stack.len(), miden_core::program::MIN_STACK_DEPTH);
            assert_eq!(stack[0], "7");

            for action in ["verify", "verify-complete"] {
                verify_command(dir.path(), action, &program)
                    .assert()
                    .success()
                    .stdout(predicate::str::contains("Proof status: complete"));
            }
            verify_command(dir.path(), "verify-partial", &program)
                .assert()
                .code(1)
                .stderr(predicate::str::contains("verify-partial"))
                .stdout(predicate::str::contains("Proof status:").not());

            if let Some(eager) = eager_proof.as_ref() {
                assert_eq!(&proof, eager, "block scheduling must preserve the proof");
            } else {
                eager_proof = Some(proof);
            }
        }
    }
}
