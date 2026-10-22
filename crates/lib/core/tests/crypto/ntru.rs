use miden_assembly::{Assembler, Linkage};
use miden_core::{
    Felt, Word,
    advice::AdviceInputs,
    program::{Program, StackInputs},
};
use miden_core_lib::{CoreLibrary, kem::ntru_hps509::advice_inputs};
use miden_crypto::{
    ies::{SealedMessage, UnsealingKey, ntru_eidos},
    kem::ntru_hps509::SecretKey,
};
use miden_processor::{ContextId, DefaultHost, ExecutionOutput, FastProcessor};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const SOURCE: u32 = 1024;
const CONTEXT: u32 = 4096;
const DESTINATION: u32 = 8192;

mod packing;

fn assemble(source: &str) -> Program {
    let core = CoreLibrary::default();
    let mut assembler = Assembler::default();
    assembler.link_package(core.package(), Linkage::Dynamic).unwrap();
    assembler.assemble_program("ntru_test", source).unwrap().unwrap_program()
}

fn execute(program: &Program, inputs: &[Felt], advice: AdviceInputs) -> ExecutionOutput {
    let mut host = DefaultHost::default().with_library(&CoreLibrary::default()).unwrap();
    FastProcessor::new(StackInputs::new(inputs).unwrap())
        .with_advice(advice)
        .unwrap()
        .execute_sync(program, &mut host)
        .unwrap()
}

fn memory(output: &ExecutionOutput, start: u32, len: usize) -> Vec<Felt> {
    (0..len)
        .map(|i| {
            output
                .memory
                .read_element(ContextId::root(), Felt::from(start + i as u32))
                .unwrap_or_default()
        })
        .collect()
}

fn seal_source(plaintext: &[Felt], context: &[Felt]) -> String {
    use core::fmt::Write;
    let mut source = String::from("use miden::core::crypto::ies::ntru_eidos\nbegin\n");
    // Sentinels verify that sealing writes only the declared output, even in nonzero memory.
    let envelope_len = (182 + 2 * plaintext.len()).next_multiple_of(4) as u32;
    for address in [SOURCE - 4, CONTEXT - 4, DESTINATION - 4, DESTINATION + envelope_len] {
        writeln!(source, "push.[7,8,9,10] mem_storew_le.{address} dropw").unwrap();
    }
    for address in (DESTINATION..DESTINATION + envelope_len).step_by(4) {
        writeln!(source, "push.[7,8,9,10] mem_storew_le.{address} dropw").unwrap();
    }
    for (ptr, values) in [(SOURCE, plaintext), (CONTEXT, context)] {
        for (i, value) in values.iter().enumerate() {
            writeln!(source, "push.{} mem_store.{}", value.as_canonical_u64(), ptr + i as u32)
                .unwrap();
        }
    }
    // Move five pointer/length arguments below the public-key commitment.
    writeln!(
        source,
        "push.{DESTINATION}.{}.{CONTEXT}.{}.{SOURCE} repeat.5 movdn.8 end \
         exec.ntru_eidos::seal",
        context.len(),
        plaintext.len()
    )
    .unwrap();
    source
}

fn private_advice(values: impl IntoIterator<Item = Felt>) -> AdviceInputs {
    AdviceInputs::default().with_stack(values.into_iter().collect())
}

#[test]
fn ntru_sealing_matches_rust_and_common_ies() {
    let mut rng = ChaCha20Rng::from_seed([47; 32]);
    let key = SecretKey::with_rng(&mut rng);
    for (plaintext_len, context_len) in
        [(0, 0), (1, 1), (2, 2), (3, 3), (7, 4), (8, 5), (9, 6), (32, 7), (513, 1025)]
    {
        let plaintext = vec![-Felt::ONE; plaintext_len];
        let context = vec![Felt::from(31u32); context_len];
        let mut native_rng = rng.clone();
        let expected =
            ntru_eidos::seal_with_rng(key.public_key(), &mut native_rng, &plaintext, &context)
                .unwrap();
        let (_, _, advice) = key.public_key().encapsulate_with_advice(&mut rng);
        let program = assemble(&(seal_source(&plaintext, &context) + "\nend"));
        let mut inputs = key.public_key().to_commitment().into_elements().to_vec();
        inputs.extend([Felt::from(73u32), Felt::from(91u32)]);
        let output = execute(&program, &inputs, advice_inputs(&advice));
        let actual = memory(&output, DESTINATION, expected.to_elements().len());
        assert_eq!(actual, expected.to_elements());
        let envelope = ntru_eidos::Envelope::from_elements(&actual).unwrap();
        assert_eq!(ntru_eidos::open(&key, &context, &envelope).unwrap(), plaintext);
        assert_eq!(memory(&output, SOURCE, plaintext.len()), plaintext);
        assert_eq!(memory(&output, CONTEXT, context.len()), context);
        for address in [SOURCE - 4, CONTEXT - 4, DESTINATION - 4, DESTINATION + actual.len() as u32]
        {
            assert_eq!(memory(&output, address, 4), [7u32, 8, 9, 10].map(Felt::from));
        }
        assert_eq!(output.stack.get_element(0), Some(Felt::from(73u32)));
        assert_eq!(output.stack.get_element(1), Some(Felt::from(91u32)));
        let unsealing =
            UnsealingKey::NtruEidos(SecretKey::from_bytes(key.to_bytes().as_ref()).unwrap());
        assert_eq!(
            unsealing
                .unseal_elements_with_associated_data(SealedMessage::from(envelope), &context)
                .unwrap(),
            plaintext
        );
    }
}

fn expect_failure(program: &Program, key: Word, advice: AdviceInputs, message: &str) {
    use miden_processor::{ExecutionError, operation::OperationError};
    let mut host = DefaultHost::default().with_library(&CoreLibrary::default()).unwrap();
    let failure = FastProcessor::new(StackInputs::new(key.as_elements()).unwrap())
        .with_advice(advice)
        .unwrap()
        .execute_sync(program, &mut host)
        .unwrap_err();
    match failure {
        ExecutionError::OperationError {
            err:
                OperationError::FailedAssertion { err_code, .. }
                | OperationError::U32AssertionFailed { err_code, .. },
            ..
        } => assert_eq!(err_code, miden_core::mast::error_code_from_msg(message), "{failure}"),
        _ => panic!("unexpected failure: {failure}"),
    }
}

#[test]
fn ntru_rejects_malformed_advice_and_wrong_recipient() {
    let mut rng = ChaCha20Rng::from_seed([48; 32]);
    let key = SecretKey::with_rng(&mut rng);
    let (_, _, advice) = key.public_key().encapsulate_with_advice(&mut rng);
    let advice: Vec<_> = advice.elements().collect();
    let program = assemble(&(seal_source(&[Felt::ONE; 8], &[Felt::ONE; 7]) + "\nend"));
    let product = 512 + 52;
    let ciphertext = product + 1024;
    for (offset, value, error) in [
        (0, 2048, "public key coefficient"),
        (509, 1, "polynomial padding"),
        (512, 3u64.pow(20), "packed trits"),
        (537, 3u64.pow(8), "packed trits"),
        (512, (advice[512].as_canonical_u64() + 1) % 3u64.pow(20), "product identity"),
        (
            product + 200,
            advice[product + 200].as_canonical_u64() + 2048,
            "product identity",
        ),
        (product + 1017, 1, "polynomial padding"),
        (ciphertext, advice[ciphertext].as_canonical_u64() + 1, "encapsulation binding"),
        (
            ciphertext + 174,
            advice[ciphertext + 174].as_canonical_u64() + 1,
            "encapsulation binding",
        ),
    ] {
        let mut changed = advice.clone();
        changed[offset] = Felt::new(value).unwrap();
        expect_failure(&program, key.public_key().to_commitment(), private_advice(changed), error);
    }
    let mut changed = advice.clone();
    changed[538..564].fill(Felt::ZERO);
    expect_failure(
        &program,
        key.public_key().to_commitment(),
        private_advice(changed),
        "positive weight",
    );
    let other = SecretKey::with_rng(&mut rng);
    expect_failure(
        &program,
        other.public_key().to_commitment(),
        private_advice(advice),
        "public key commitment",
    );
}

#[test]
fn ntru_sealing_checks_memory_before_reading_advice() {
    let frame = miden_core::FMP_INIT_VALUE.as_canonical_u64();
    for (src, len, context, context_len, dst, error) in [
        (1001, 1, 2000, 1, 3000, "pointer must be word-aligned"),
        (1000, 1, 2001, 1, 3000, "pointer must be word-aligned"),
        (1000, 1, 2000, 1, 3001, "pointer must be word-aligned"),
        (1 << 32, 0, 2000, 0, 3000, "pointer must fit in a u32"),
        (1000, 1_u64 << 32, 2000, 0, 3000, "plaintext length must fit in a u32"),
        (1000, 0, 2000, 1_u64 << 32, 3000, "context length must fit in a u32"),
        (
            1000,
            1 << 27,
            2000,
            0,
            3000,
            "authentication input exceeds its supported length",
        ),
        (
            1000,
            0,
            2000,
            1 << 28,
            3000,
            "authentication input exceeds its supported length",
        ),
        (frame, 1, 2000, 0, 3000, "memory ranges must stay below the local frame"),
        (1000, 0, frame, 1, 3000, "memory ranges must stay below the local frame"),
        (1000, 0, 2000, 0, frame - 180, "memory ranges must stay below the local frame"),
        (
            u32::MAX as u64 - 3,
            8,
            2000,
            0,
            3000,
            "memory range exceeds the u32 address space",
        ),
        (
            1000,
            0,
            u32::MAX as u64 - 3,
            8,
            3000,
            "memory range exceeds the u32 address space",
        ),
        (
            1000,
            0,
            2000,
            0,
            u32::MAX as u64 - 3,
            "memory range exceeds the u32 address space",
        ),
        (1000, 4, 2000, 1, 1000, "destination overlaps an input"),
        (1000, 4, 2000, 1, 996, "destination overlaps an input"),
        (1000, 4, 2000, 1, 2000, "destination overlaps an input"),
        (1000, 4, 2000, 1, 1996, "destination overlaps an input"),
    ] {
        let program = assemble(&format!(
            "use miden::core::crypto::ies::ntru_eidos\nbegin \
             push.{dst}.{context_len}.{context}.{len}.{src} repeat.5 movdn.8 end \
             exec.ntru_eidos::seal end"
        ));
        expect_failure(
            &program,
            Word::default(),
            AdviceInputs::default(),
            &format!("NTRU-Eidos {error}"),
        );
    }
}

#[test]
fn ntru_empty_inputs_allow_unread_addresses_and_an_exact_output_boundary() {
    let mut rng = ChaCha20Rng::from_seed([51; 32]);
    let key = SecretKey::with_rng(&mut rng);
    let expected = ntru_eidos::seal_with_rng(key.public_key(), &mut rng.clone(), &[], &[]).unwrap();
    let (_, _, advice) = key.public_key().encapsulate_with_advice(&mut rng);
    let unread = u32::MAX - 3;
    let dst =
        miden_core::FMP_INIT_VALUE.as_canonical_u64() as u32 - expected.to_elements().len() as u32;
    let program = assemble(&format!(
        "use miden::core::crypto::ies::ntru_eidos\nbegin \
         push.{dst}.0.{unread}.0.{unread} repeat.5 movdn.8 end exec.ntru_eidos::seal end"
    ));
    let output =
        execute(&program, key.public_key().to_commitment().as_elements(), advice_inputs(&advice));
    assert_eq!(memory(&output, dst, expected.to_elements().len()), expected.to_elements());
}

#[test]
fn ntru_repeated_sealing_allows_shared_inputs_at_the_frame_boundary() {
    let mut rng = ChaCha20Rng::from_seed([52; 32]);
    let key = SecretKey::with_rng(&mut rng);
    let values = [Felt::ONE; 4];
    let ptr = miden_core::FMP_INIT_VALUE.as_canonical_u64() - 4;
    let mut expected = Vec::new();
    let mut advice = Vec::new();
    for _ in 0..2 {
        expected.push(
            ntru_eidos::seal_with_rng(key.public_key(), &mut rng.clone(), &values, &values)
                .unwrap(),
        );
        let (_, _, witness) = key.public_key().encapsulate_with_advice(&mut rng);
        advice.extend(witness.elements());
    }
    let program = assemble(&format!(
        "use miden::core::crypto::ies::ntru_eidos
         begin
             mem_storew_le.128 dropw
             push.[1,1,1,1] mem_storew_le.{ptr} dropw
             repeat.2
                 push.{DESTINATION}.4.{ptr}.4.{ptr} padw mem_loadw_le.128
                 exec.ntru_eidos::seal
             end
         end"
    ));
    let output =
        execute(&program, key.public_key().to_commitment().as_elements(), private_advice(advice));
    assert_ne!(expected[0], expected[1]);
    assert_eq!(
        memory(&output, DESTINATION, expected[1].to_elements().len()),
        expected[1].to_elements()
    );
    assert_eq!(memory(&output, ptr as u32, 4), values);
}

#[test]
#[ignore = "generates and verifies one STARK; run explicitly"]
fn ntru_sealing_proof() {
    use miden_crypto::hash::eidos::Eidos;
    let mut rng = ChaCha20Rng::from_seed([49; 32]);
    let key = SecretKey::with_rng(&mut rng);
    let plaintext = [Felt::from(42u32); 8];
    let context = [Felt::from(31u32); 7];
    let expected =
        ntru_eidos::seal_with_rng(key.public_key(), &mut rng.clone(), &plaintext, &context)
            .unwrap();
    let (_, _, advice) = key.public_key().encapsulate_with_advice(&mut rng);
    // Commit the entire output so verification checks more than successful execution.
    let source = format!(
        "use miden::core::crypto::hashes::eidos\n{}\npush.{}.{} exec.eidos::hash_elements \
         repeat.4 movup.4 drop end end",
        seal_source(&plaintext, &context),
        expected.to_elements().len(),
        DESTINATION,
    );
    let program = assemble(&source);
    let mut host = DefaultHost::default().with_library(&CoreLibrary::default()).unwrap();
    let witness = FastProcessor::new(
        StackInputs::new(key.public_key().to_commitment().as_elements()).unwrap(),
    )
    .with_advice(advice_inputs(&advice))
    .unwrap()
    .execute_for_proving_sync(&program, &mut host)
    .unwrap();
    let claim = witness.claim();
    assert_eq!(
        claim.stack_outputs().get_word(0).unwrap(),
        Eidos::hash_elements(&expected.to_elements())
    );
    let proof = miden_prover::Prover::new()
        .with_max_prover_memory_bytes(8 << 30)
        .prove(witness)
        .unwrap();
    assert!(miden_verifier::Verifier::new().verify(&claim, &proof).unwrap().is_complete());
}

#[test]
fn ntru_encapsulation_preserves_caller_stack_and_memory() {
    let mut rng = ChaCha20Rng::from_seed([50; 32]);
    let key = SecretKey::with_rng(&mut rng);
    let (ciphertext, secret, advice) = key.public_key().encapsulate_with_advice(&mut rng);
    // Observe every caller value after it returns from overflow, not only the top sixteen.
    let sentinels = (55..87u32)
        .rev()
        .map(|value| format!("push.{value}"))
        .collect::<Vec<_>>()
        .join(" ");
    let stores = (16400..16432)
        .step_by(4)
        .map(|address| format!("mem_storew_le.{address} dropw"))
        .collect::<Vec<_>>()
        .join("\n");
    let source = format!(
        "use miden::core::crypto::kem::ntru_hps509\nbegin \
         mem_storew_le.128 dropw \
         push.[1,2,3,4] mem_storew_le.1024 dropw \
         {sentinels} padw mem_loadw_le.128 \
         push.{DESTINATION} movdn.4 exec.ntru_hps509::encapsulate \
         mem_storew_le.16384 dropw mem_storew_le.16388 dropw {stores} end"
    );
    let program = assemble(&source);
    let output =
        execute(&program, key.public_key().to_commitment().as_elements(), advice_inputs(&advice));
    assert_eq!(memory(&output, 16384, 4), secret.to_word().as_elements());
    assert_eq!(memory(&output, 16400, 32), (55..87u32).map(Felt::from).collect::<Vec<_>>());
    assert_eq!(memory(&output, 1024, 4), [1u32, 2, 3, 4].map(Felt::from));
    let encoded: Vec<_> = memory(&output, DESTINATION, 175)
        .iter()
        .flat_map(|x| (x.as_canonical_u64() as u32).to_le_bytes())
        .collect();
    assert_eq!(&encoded[..699], ciphertext.as_bytes());
    assert_eq!(encoded[699], 0);
    assert_eq!(memory(&output, DESTINATION + 175, 1), [Felt::ZERO]);
}
