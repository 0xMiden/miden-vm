use miden_assembly::{Assembler, Linkage};
use miden_core::{Felt, Word};
use miden_core_lib::{
    CoreLibrary,
    dsa::leansig_poseidon2::{self, DIMENSION, SecretKey},
};
use miden_processor::{
    DefaultHost, ExecutionError, ExecutionOptions, ExecutionOutput, FastProcessor, StackInputs,
    advice::{AdviceInputs, AdviceStack},
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

const VERIFY_EXPECTED_CYCLES: u64 = 29_383;

#[test]
fn core_leansig_poseidon2_verify_accepts_valid_signature() {
    let fixture = valid_fixture();
    run_verify(&fixture).expect("valid LeanSig signature must verify");
}

#[test]
fn core_leansig_poseidon2_verify_cycle_baseline() {
    let fixture = valid_fixture();
    let source = format!(
        r#"
        begin
            push.{}
            {}
            {}
            clk movdn.9
            exec.::miden::core::crypto::dsa::leansig_poseidon2::verify
            clk swap sub
            swap.15 drop movup.14
        end
        "#,
        fixture.epoch,
        masm_push_word(&fixture.message),
        masm_push_word(&fixture.pk_comm),
    );
    let output = run_program(&source, &fixture.advice).expect("cycle baseline must verify");
    let cycles = output.stack.get_element(0).expect("cycle count").as_canonical_u64();
    assert_eq!(cycles, VERIFY_EXPECTED_CYCLES);
}

#[test]
fn core_leansig_poseidon2_verify_traps_on_wrong_public_key_commitment() {
    let mut fixture = valid_fixture();
    tamper_felt(&mut fixture.pk_comm[0]);
    run_verify(&fixture).expect_err("wrong public key commitment must trap");
}

#[test]
fn core_leansig_poseidon2_verify_traps_on_wrong_message() {
    let mut fixture = valid_fixture();
    tamper_felt(&mut fixture.message[0]);
    run_verify(&fixture).expect_err("wrong message must trap");
}

#[test]
fn core_leansig_poseidon2_verify_traps_on_wrong_epoch() {
    let mut fixture = valid_fixture();
    fixture.epoch ^= 1;
    run_verify(&fixture).expect_err("wrong epoch must trap");
}

#[test]
fn core_leansig_poseidon2_verify_traps_on_non_u32_epoch() {
    let fixture = valid_fixture();
    run_verify_with_epoch(&fixture, 1u64 << 32).expect_err("non-u32 epoch must trap");
}

#[test]
fn core_leansig_poseidon2_verify_traps_on_tampered_chain_hash() {
    let mut fixture = valid_fixture();
    let first_signature_hash = 3 * 4;
    tamper_felt(&mut fixture.advice[first_signature_hash]);
    run_verify(&fixture).expect_err("tampered Winternitz hash must trap");
}

#[test]
fn core_leansig_poseidon2_verify_traps_on_tampered_authentication_path() {
    let mut fixture = valid_fixture();
    let first_path_node = (3 + DIMENSION) * 4;
    tamper_felt(&mut fixture.advice[first_path_node]);
    run_verify(&fixture).expect_err("tampered authentication path must trap");
}

struct Fixture {
    pk_comm: Word,
    message: Word,
    epoch: u32,
    advice: Vec<Felt>,
}

fn valid_fixture() -> Fixture {
    let mut rng = ChaCha20Rng::from_seed([0x51; 32]);
    let epoch = 0x1020_3040;
    let message = Word::new([1u32, 2, 3, 4].map(Felt::from_u32));
    let mut secret_key = SecretKey::with_rng(&mut rng, epoch, 1).expect("LeanSig key generation");
    let public_key = secret_key.public_key();
    let signature = secret_key.sign(epoch, message).expect("LeanSig signing");
    assert!(public_key.verify(epoch, message, &signature));

    let pk_comm = public_key.to_commitment();
    let advice = leansig_poseidon2::encode(&public_key, &signature);

    Fixture { pk_comm, message, epoch, advice }
}

fn run_verify(fixture: &Fixture) -> Result<ExecutionOutput, ExecutionError> {
    run_verify_with_epoch(fixture, u64::from(fixture.epoch))
}

fn run_verify_with_epoch(fixture: &Fixture, epoch: u64) -> Result<ExecutionOutput, ExecutionError> {
    let source = format!(
        r#"
        begin
            push.{}
            {}
            {}
            exec.::miden::core::crypto::dsa::leansig_poseidon2::verify
        end
        "#,
        epoch,
        masm_push_word(&fixture.message),
        masm_push_word(&fixture.pk_comm),
    );

    let output = run_program(&source, &fixture.advice);
    if let Ok(output) = &output {
        assert!(output.advice.stack().is_empty(), "LeanSig verifier must consume its advice");
    }
    output
}

fn run_program(source: &str, advice: &[Felt]) -> Result<ExecutionOutput, ExecutionError> {
    let core_lib = CoreLibrary::default();
    let program = Assembler::default()
        .with_package(core_lib.package(), Linkage::Dynamic)
        .expect("failed to link core library")
        .assemble_program("core_leansig_poseidon2_test", source)
        .expect("failed to assemble LeanSig test program")
        .unwrap_program();

    let mut host = DefaultHost::default()
        .with_library(&core_lib)
        .expect("failed to load CoreLibrary into the host");
    let mut advice_stack = AdviceStack::new();
    advice_stack.append_elements(advice.iter().copied());
    let processor = FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default().with_advice_stack(advice_stack),
        ExecutionOptions::default(),
    )
    .expect("processor construction");

    processor.execute_sync(&program, &mut host)
}

fn masm_push_word(word: &Word) -> String {
    let felts = word
        .iter()
        .rev()
        .map(|felt| felt.as_canonical_u64().to_string())
        .collect::<Vec<_>>()
        .join(".");
    format!("push.{felts}")
}

fn tamper_felt(felt: &mut Felt) {
    *felt = if *felt == Felt::ZERO {
        Felt::ONE
    } else {
        Felt::new_unchecked(felt.as_canonical_u64() - 1)
    };
}
