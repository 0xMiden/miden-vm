use std::sync::Arc;

use miden_assembly::{Assembler, Linkage};
use miden_core::{Felt, Word, deferred::DeferredState};
use miden_core_lib::{CoreLibrary, dsa::ecdsa_k256_keccak};
use miden_crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_processor::{
    DefaultHost, ExecutionError, ExecutionOptions, ExecutionOutput, FastProcessor, StackInputs,
    advice::AdviceInputs,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

const VERIFY_EXPECTED_CYCLES: u64 = 1_697;

#[test]
fn core_ecdsa_k256_keccak_verify_accepts_valid_signature() {
    let fixture = valid_fixture();

    let output = run_verify(&fixture).expect("valid core ECDSA K256/Keccak signature must verify");
    assert_deferred_state_round_trips(&output);
}

#[test]
fn core_ecdsa_k256_keccak_verify_cycle_baseline() {
    let fixture = valid_fixture();

    let output = run_core_program_with_advice(&verify_cycle_source(&fixture), &fixture.advice)
        .expect("valid core ECDSA K256/Keccak signature must verify");
    let cycles = output.stack.get_element(0).expect("cycle count").as_canonical_u64();
    assert_eq!(cycles, VERIFY_EXPECTED_CYCLES);
}

#[test]
fn core_ecdsa_k256_keccak_verify_traps_on_wrong_pk_comm() {
    let mut fixture = valid_fixture();
    tamper_felt(&mut fixture.pk_comm[0]);

    run_verify(&fixture).expect_err("wrong public key commitment must trap");
}

struct Fixture {
    pk_comm: Word,
    message: Word,
    advice: Vec<Felt>,
}

fn valid_fixture() -> Fixture {
    let mut rng = ChaCha20Rng::from_seed([0xe5; 32]);
    let sk = SigningKey::with_rng(&mut rng);
    let message = fixed_message();
    let public_key = sk.public_key();
    let signature = sk.sign(message);

    assert!(
        public_key.verify(message, &signature),
        "Rust fixture signature must verify before passing it to MASM",
    );

    Fixture {
        pk_comm: ecdsa_k256_keccak::public_key_commitment(&public_key),
        message,
        advice: ecdsa_k256_keccak::encode_signature(&public_key, &signature),
    }
}

fn fixed_message() -> Word {
    Word::new([
        Felt::new_unchecked(0x0001_0203_0405_0607),
        Felt::new_unchecked(0x0809_0a0b_0c0d_0e0f),
        Felt::new_unchecked(0x1011_1213_1415_1617),
        Felt::new_unchecked(0x1819_1a1b_1c1d_1e1f),
    ])
}

fn run_verify(fixture: &Fixture) -> Result<ExecutionOutput, ExecutionError> {
    run_core_program_with_advice(&verify_source(fixture), &fixture.advice)
}

fn verify_source(fixture: &Fixture) -> String {
    let setup = verify_setup(fixture);

    format!(
        r#"
        begin
            {setup}
            exec.::miden::core::crypto::dsa::ecdsa_k256_keccak::verify
        end
        "#,
    )
}

fn verify_cycle_source(fixture: &Fixture) -> String {
    let setup = verify_setup(fixture);

    format!(
        r#"
        begin
            {setup}
            clk
            movdn.8
            exec.::miden::core::crypto::dsa::ecdsa_k256_keccak::verify
            clk
            swap sub
            swap drop
        end
        "#,
    )
}

fn verify_setup(fixture: &Fixture) -> String {
    let message = masm_push_word(&fixture.message);
    let pk_comm = masm_push_word(&fixture.pk_comm);

    format!(
        r#"
        {message}
        {pk_comm}
        "#,
    )
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

fn run_core_program_with_advice(
    source: &str,
    advice: &[Felt],
) -> Result<ExecutionOutput, ExecutionError> {
    let core_lib = CoreLibrary::default();
    let program = Assembler::default()
        .with_package(core_lib.package(), Linkage::Dynamic)
        .expect("failed to link core library")
        .assemble_program("core_ecdsa_k256_keccak_test", source)
        .expect("failed to assemble core ECDSA test program")
        .unwrap_program();

    let mut host = DefaultHost::default()
        .with_library(&core_lib)
        .expect("failed to load CoreLibrary into the host");

    let processor = FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default().with_stack(advice.iter().copied()),
        ExecutionOptions::default(),
    )
    .expect("processor construction");

    let output = processor.execute_sync(&program, &mut host);
    if let Ok(output) = &output {
        assert!(output.advice.stack().is_empty(), "core ECDSA wrapper must consume advice");
    }

    output
}

fn assert_deferred_state_round_trips(output: &ExecutionOutput) {
    let registry = Arc::new(miden_precompiles::registry());
    let wire = output.deferred_state.to_wire().expect("deferred state must encode to wire");
    let rehydrated = DeferredState::from_wire(Arc::clone(&registry), &wire, usize::MAX)
        .expect("deferred wire must rehydrate under miden-precompiles registry");
    assert_eq!(
        rehydrated.root(),
        output.deferred_state.root(),
        "wire round-trip must preserve the deferred root",
    );
}

fn tamper_felt(felt: &mut Felt) {
    let value = felt.as_canonical_u64();
    *felt = if value == 0 {
        Felt::from_u32(1)
    } else {
        Felt::new(value - 1).expect("decremented canonical field element must stay canonical")
    };
}
