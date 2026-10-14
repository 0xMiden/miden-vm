use std::{fs, path::Path, process::Command, sync::Arc};

use assert_cmd::prelude::*;
use miden_core::{
    Felt, Word, ZERO,
    deferred::{Node, PrecompileWitnessEntry, deferred_chunks_frame},
};
use miden_precompiles::{UintDomain, UintPrecompile};
use miden_vm::{
    Assembler, DefaultHost, ExecutionProof, FastProcessor, PrecompileProof, PrecompileStatus,
    PrecompileWitness, Program, Prover, StackInputs, StarkProof, VmProof,
    default_verification_precompile_limits, serde::Serializable,
};
use predicates::prelude::*;
use tempfile::TempDir;

use super::cli_test::bin_under_test;

fn word_literal(word: Word) -> String {
    format!("[{}, {}, {}, {}]", word[0], word[1], word[2], word[3])
}

/// Duplicate guest requests consume execution work even though the exported uint nodes are shared.
fn precompile_source(requests: usize) -> String {
    let mut chunk = [ZERO; 8];
    chunk[0] = Felt::from_u32(1);
    let value = Node::value(UintPrecompile::value_frame(UintDomain::U256), chunk)
        .unwrap()
        .digest();
    let eq = UintPrecompile::op_frame(UintPrecompile::EQ_OP_ID).initial_chaining_word();
    let request = format!(
        "push.{} push.{} push.{} adv.register_deferred movdnw.2 compress dropw dropw log_deferred dropw\n",
        word_literal(value),
        word_literal(value),
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

#[test]
fn cli_precompile_policy_errors_precede_input_loading() {
    let dir = TempDir::new().unwrap();
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
        let program = write_program(dir.path(), &precompile_source(requests));
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
                command.assert().success();
                let mut command = bin_under_test(dir.path());
                command
                    .arg(action)
                    .arg(format!("program.{extension}"))
                    .arg("--max-precompile-elements")
                    .arg((boundary - 1).to_string());
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
    let program = write_program(dir.path(), &precompile_source(1));
    let witness = FastProcessor::new(StackInputs::default())
        .execute_for_proving_sync(&program, &mut DefaultHost::default())
        .unwrap();
    let outputs: Vec<_> = witness.claim().stack_outputs().iter().map(ToString::to_string).collect();
    fs::write(
        dir.path().join("program.outputs"),
        serde_json::to_vec(&serde_json::json!({"stack": outputs})).unwrap(),
    )
    .unwrap();
    let deferred = Prover::new().prove(witness).unwrap();
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
    write_proof(dir.path(), &deferred);
    verify_command(dir.path(), &program)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Proof status: deferred"))
        .stdout(predicate::str::contains("VM STARK security level:"))
        .stdout(predicate::str::contains("Precompile witness: validated natively"))
        .stdout(predicate::str::contains("Precompile STARK: not supplied"))
        .stdout(predicate::str::contains(format!(
            "Outstanding precompile root: {}",
            deferred.vm().precompile_root
        )))
        .stdout(predicate::str::contains("Security level:").not());
    verify_command(dir.path(), &program)
        .arg("--require-complete")
        .assert()
        .code(1)
        .stdout(predicate::str::contains("Proof status: deferred"))
        .stderr(predicate::str::contains("--require-complete requires a precompile STARK"));
    verify_command(dir.path(), &program)
        .args(["--max-precompile-elements", &elements.to_string()])
        .assert()
        .success();
    verify_command(dir.path(), &program)
        .args(["--max-precompile-elements", &(elements - 1).to_string()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("Proof status:").not());

    let precompile = Prover::new().prove_precompiles(vec![portable.clone()]).unwrap();
    let complete = deferred.clone().complete(precompile).unwrap();
    write_proof(dir.path(), &complete);
    verify_command(dir.path(), &program)
        .args(["--require-complete", "--max-precompile-elements", "0"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Proof status: complete"))
        .stdout(predicate::str::contains("Security level:"))
        .stdout(predicate::str::contains("validated natively").not());

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
    verify_command(dir.path(), &program)
        .assert()
        .failure()
        .stdout(predicate::str::contains("Proof status:").not());

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
    verify_command(dir.path(), &program)
        .assert()
        .failure()
        .stdout(predicate::str::contains("Proof status:").not());

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
    bin_under_test(dir.path()).args(["prove", "program.masm"]).assert().success();
    verify_command(dir.path(), &program)
        .arg("--require-complete")
        .assert()
        .success()
        .stdout(predicate::str::contains("Proof status: complete"));
}
