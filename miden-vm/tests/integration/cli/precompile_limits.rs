use std::{fs, path::Path, process::Command, sync::Arc};

use assert_cmd::prelude::*;
use miden_core::{
    Felt, Word, ZERO,
    deferred::{Node, PrecompileWitnessEntry, deferred_chunks_frame},
};
use miden_precompiles::{UintDomain, UintPrecompile};
use miden_vm::{
    Assembler, DefaultHost, ExecutionProof, FastProcessor, PrecompileProof, PrecompileStatus,
    PrecompileWitness, Program, StackInputs, StarkProof, VmProof,
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

fn verify_command(dir: &Path, program: &Program) -> Command {
    let mut command = bin_under_test(dir);
    let hash: [u8; 32] = program.hash().into();
    command.args(["verify", "--proof", "program.proof", "--program-hash", &hex::encode(hash)]);
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
        .stdout(predicate::str::contains("--complete"))
        .stdout(predicate::str::contains("--deferred"))
        .stdout(predicate::str::contains("private advice"))
        .stdout(predicate::str::contains("when that disclosure is intended"));
    bin_under_test(dir.path())
        .args(["prove", "missing.masm", "--complete", "--deferred"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"))
        .stdout(predicate::str::is_empty());
    bin_under_test(dir.path())
        .args(["verify", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--require-complete"))
        .stdout(predicate::str::contains("By default, accept valid deferred proofs"))
        .stdout(predicate::str::contains("--allow-deferred").not());
    let invalid = [
        ("--max-precompile-elements", (u128::from(u64::MAX) + 1).to_string()),
        ("--max-precompile-hash-bytes", format!("{}Gi", u64::MAX)),
        ("--max-precompile-msm-terms", (u64::from(u32::MAX) + 1).to_string()),
        ("--max-precompile-total-msm-terms", "1Mi".to_owned()),
    ];
    for action in ["run", "prove", "verify"] {
        for args in invalid.iter().map(|(flag, value)| vec![*flag, value.as_str()]).chain([vec![
            "--max-precompile-elements",
            "1",
            "--max-precompile-elements",
            "1",
        ]]) {
            let mut command = bin_under_test(dir.path());
            command.arg(action);
            if action == "verify" {
                command.args(["--proof", "missing.proof", "--program-hash", "00"]);
            } else {
                command.arg("missing.masm");
            }
            command
                .args(&args)
                .assert()
                .code(2)
                .stderr(predicate::str::contains(args[0]))
                .stdout(predicate::str::is_empty());
        }
    }
}

#[test]
fn cli_private_precompile_witness_export_requires_opt_in() {
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
        .args(["prove", "program.masm"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Proof status: complete"))
        .stdout(predicate::str::contains("Precompile witness: exported").not());
    // The default artifact carries a precompile STARK, with no portable witness to disclose.
    assert!(matches!(read_proof(dir.path()).precompile(), PrecompileStatus::Proven(_)));

    bin_under_test(dir.path())
        .args(["prove", "program.masm", "--deferred"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Proof status: deferred"))
        .stdout(predicate::str::contains("may reveal private advice inputs"));
    let proof = read_proof(dir.path());
    let PrecompileStatus::Deferred(witness) = proof.precompile() else {
        panic!("explicit opt-in must export the deferred witness")
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
    // One request reaches the export ceiling first; repeated registrations reach the execution
    // ceiling first because the exported uint nodes are shared. The CLI applies the same ceiling
    // while the library continues to account for both scopes independently.
    for requests in [1, 3] {
        let program = write_program(dir.path(), &precompile_source(requests, 1));
        let (_, portable) = FastProcessor::new(StackInputs::default())
            .execute_for_proving_sync(&program, &mut DefaultHost::default())
            .unwrap()
            .into_parts();
        let prepared = portable
            .unwrap()
            .prepare(
                Arc::new(miden_precompiles::registry()),
                &default_verification_precompile_limits(),
            )
            .unwrap();
        let boundary =
            u64::try_from(requests * per_request).unwrap().max(prepared.work().elements());
        for extension in ["masm", "masp"] {
            for action in ["run", "prove"] {
                let mut command = bin_under_test(dir.path());
                command
                    .arg(action)
                    .arg(format!("program.{extension}"))
                    .arg("--max-precompile-elements")
                    .arg(boundary.to_string());
                if action == "prove" {
                    command.arg("--deferred");
                }
                command.assert().success();
                let mut command = bin_under_test(dir.path());
                command
                    .arg(action)
                    .arg(format!("program.{extension}"))
                    .arg("--max-precompile-elements")
                    .arg((boundary - 1).to_string());
                if action == "prove" {
                    command.arg("--deferred");
                }
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
        .args(["prove", "program.masm", "--deferred"])
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
    verify_command(dir.path(), &program)
        .arg("--require-complete")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("--require-complete rejects deferred proofs"))
        .stderr(predicate::str::contains("proof has not been verified"))
        .stdout(predicate::str::contains("Proof status:").not())
        .stdout(predicate::str::contains("validated natively").not());
    verify_command(dir.path(), &program)
        .assert()
        .code(0)
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
        .stdout(predicate::str::contains("Security level:").not());
    verify_command(dir.path(), &program)
        .args(["--max-precompile-elements", &elements.to_string()])
        .assert()
        .success();
    verify_command(dir.path(), &program)
        .args(["--max-precompile-elements", &(elements - 1).to_string()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("Proof status:").not());

    bin_under_test(dir.path())
        .args(["prove", "program.masm"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Proof status: complete"));
    let complete = read_proof(dir.path());
    for args in [vec![], vec!["--require-complete"]] {
        verify_command(dir.path(), &program)
            .args(args)
            .args(["--max-precompile-elements", "0"])
            .assert()
            .code(0)
            .stdout(predicate::str::contains("Proof status: complete"))
            .stdout(predicate::str::contains("Security level:"))
            .stdout(predicate::str::contains("bits proven"))
            .stdout(predicate::str::contains("validated natively").not());
    }

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
    for args in [vec![], vec!["--require-complete"]] {
        verify_command(dir.path(), &program)
            .args(args)
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
    verify_command(dir.path(), &program)
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not match the VM obligation"))
        .stdout(predicate::str::contains("Proof status:").not());

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
    // Complete-only policy rejects this artifact before cryptographic verification.
    // Default verification must authenticate the VM and reject the invalid STARK.
    for require_complete in [false, true] {
        let mut command = verify_command(dir.path(), &program);
        if require_complete {
            command.arg("--require-complete");
        }
        command
            .assert()
            .failure()
            .stderr(predicate::str::contains(if require_complete {
                "--require-complete rejects deferred proofs; proof has not been verified"
            } else {
                "Program failed verification!"
            }))
            .stdout(predicate::str::contains("Proof status:").not())
            .stdout(predicate::str::contains("validated natively").not());
    }

    // Deferring the precompile STARK must not bypass native execution checks in either mode.
    let program = write_program(dir.path(), &precompile_source(1, 2));
    for args in [vec![], vec!["--complete"], vec!["--deferred"]] {
        bin_under_test(dir.path())
            .args(["prove", "program.masm"])
            .args(args)
            .assert()
            .failure()
            .stderr(predicate::str::contains("values disagree"))
            .stdout(predicate::str::contains("Proof status:").not());
    }

    fs::write(dir.path().join("program.proof"), []).unwrap();
    verify_command(dir.path(), &program)
        .assert()
        .failure()
        .stderr(predicate::str::contains("Failed to decode proof data"))
        .stdout(predicate::str::contains("Proof status:").not());
}

#[test]
fn cli_precompile_empty_proof_is_complete() {
    let dir = TempDir::new().unwrap();
    let program = write_program(dir.path(), "begin push.1 drop end");
    for prove_args in [vec![], vec!["--complete"], vec!["--deferred"]] {
        bin_under_test(dir.path())
            .args(["prove", "program.masm"])
            .args(prove_args)
            .assert()
            .success()
            .stdout(predicate::str::contains("Proof status: complete"));
        assert!(matches!(read_proof(dir.path()).precompile(), PrecompileStatus::Empty));
        for verify_args in [vec![], vec!["--require-complete"]] {
            verify_command(dir.path(), &program)
                .args(verify_args)
                .assert()
                .success()
                .stdout(predicate::str::contains("Proof status: complete"));
        }
    }
}
