use std::sync::OnceLock;

use miden_core::{Felt, Word, crypto::merkle::MerkleStore};
use miden_core_lib::ecdh::ecgfp5::{
    advice_inputs as direct_advice_inputs, preprocessed_advice_inputs as advice_inputs,
};
use miden_crypto::{
    ecdh::ecgfp5::{PreparedPublicKey, PublicKey, SecretKey},
    hash::eidos::{Eidos, domains::ECGFP5_PUBLIC_KEY},
};
use miden_processor::{ExecutionError, advice::AdviceInputs, operation::OperationError};
use miden_utils_testing::Test;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

const SOURCE: &str = "use miden::core::crypto::ecdh::ecgfp5
begin
    exec.ecgfp5::agree_preprocessed
    repeat.11 movup.15 drop end
end";

const DIRECT_SOURCE: &str = "use miden::core::crypto::ecdh::ecgfp5
begin
    exec.ecgfp5::agree
    repeat.11 movup.15 drop end
end";

const SCALAR_ORDER: [u32; 10] = [
    0x948bffe1, 0xe80fd996, 0xd724a09c, 0xe8885c39, 0xcfb80639, 0x7fffffe6, 0x16, 0x7ffffff1,
    0x80000007, 0x7ffffffd,
];

fn recipient() -> SecretKey {
    let mut bytes = [0; 40];
    bytes[0] = 7;
    SecretKey::from_bytes(&bytes).unwrap()
}

fn prepared() -> &'static PreparedPublicKey {
    static KEY: OnceLock<PreparedPublicKey> = OnceLock::new();
    KEY.get_or_init(|| PreparedPublicKey::new(recipient().public_key()))
}

fn scalar(limbs: [u32; 10]) -> SecretKey {
    let mut bytes = [0; 40];
    for (chunk, limb) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(limbs) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    SecretKey::from_bytes(&bytes).unwrap()
}

fn sample() -> SecretKey {
    // Every digit is nonzero, so malformed-advice tests have a fixed leaf/slope layout.
    scalar([
        2085612185, 3795575787, 3404702886, 1163736064, 4050271405, 2347601655, 329642727,
        1079986156, 12275843, 567828391,
    ])
}

fn agreement(source: &str, commitment: Word, advice: AdviceInputs) -> Test {
    let inputs = commitment.into_elements().map(|x| x.as_canonical_u64());
    let mut test = build_test!(source, &inputs);
    test.advice_inputs = advice;
    test
}

fn expected(secret: &SecretKey, public_key: &PublicKey) -> Vec<u64> {
    secret
        .public_key()
        .to_elements()
        .into_iter()
        .chain(secret.diffie_hellman(public_key).to_elements())
        .chain(public_key.to_elements())
        .map(|x| x.as_canonical_u64())
        .collect()
}

#[test]
fn direct_agreement_matches_native_at_boundaries() {
    let mut maximum = SCALAR_ORDER;
    maximum[0] -= 1;
    let mut rng = ChaCha20Rng::from_seed([85; 32]);
    let recipients = [
        scalar([1, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        recipient(),
        scalar(maximum),
        SecretKey::with_rng(&mut rng),
    ];
    let scalars = [
        scalar([1, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        scalar([2, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        scalar([3, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        scalar([65537, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        scalar([0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 30]),
        scalar(maximum),
        sample(),
        SecretKey::with_rng(&mut rng),
    ];
    let mut minus_two = SCALAR_ORDER;
    minus_two[0] -= 2;
    let mut minus_three = SCALAR_ORDER;
    minus_three[0] -= 3;
    // Negative short numerators make entries inside the joint table cancel, not just the final sum.
    let exceptional = [
        (
            scalar([2, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            // r = -1/2 mod n: 2*S = -Q.
            scalar([
                0x4a45fff0, 0x7407eccb, 0xeb92504e, 0xf4442e1c, 0x67dc031c, 0x3ffffff3, 0x8000000b,
                0xbffffff8, 0xc0000003, 0x3ffffffe,
            ]),
        ),
        (
            scalar([3, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            // r = -2/3 mod n: 3*S = -2*Q.
            scalar([
                0x3183fff5, 0xa2aff332, 0x9d0c3589, 0x4d82c968, 0xefe80213, 0xd555554c, 0x5555555c,
                0xd5555550, 0xd5555557, 0x2aaaaaa9,
            ]),
        ),
        (scalar(maximum), scalar(minus_two)),
        (scalar(maximum), scalar(minus_three)),
    ];
    let cases = recipients
        .iter()
        .flat_map(|recipient| scalars.iter().map(move |secret| (recipient, secret)))
        .chain(exceptional.iter().map(|(recipient, secret)| (recipient, secret)));
    for (recipient, secret) in cases {
        let public_key = recipient.public_key();
        let advice = direct_advice_inputs(&public_key, secret);
        let test = agreement(DIRECT_SOURCE, public_key.to_commitment(), advice);
        let (output, _) = test.execute_for_output().unwrap();
        let mut expected = expected(secret, &public_key);
        expected.resize(16, 0);
        let actual: Vec<_> = output.stack.iter().map(Felt::as_canonical_u64).collect();
        assert_eq!(actual, expected);
    }
}

#[test]
fn direct_agreement_rejects_invalid_points_scalars_and_witnesses() {
    let public_key = recipient().public_key();
    // r=3 uses one generator entry, a=3, b=1, and both doubling and ordinary addition.
    let secret = scalar([3, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let original = direct_advice_inputs(&public_key, &secret);
    let elements: Vec<_> = original.stack().into_elements();
    let fraction = 5 + 10 + 80 + 24; // Public key, scalar, twenty roots, one paired entry.
    let q_root = fraction + 10 * 3 + 1 + 30;
    let s_encoding = q_root + 5 + 2 * 5; // Decode Q, then build 2Q and 3Q.
    let cases = (fraction..fraction + 30)
        .map(|i| (i, "fraction congruence"))
        .chain((fraction + 31..q_root).map(|i| (i, "fraction congruence")))
        .chain((q_root..q_root + 5).map(|i| (i, "public key")))
        .chain((q_root + 5..q_root + 10).map(|i| (i, "doubling slope")))
        .chain((q_root + 10..s_encoding).map(|i| (i, "slope")))
        .chain((s_encoding..s_encoding + 10).map(|i| (i, "public key")))
        .chain((elements.len() - 10..elements.len()).map(|i| (i, "point encoding")))
        .chain((0..5).map(|i| (i, "public key commitment")))
        .chain([(15, "generator roots"), (95, "table binding")]);
    for (index, message) in cases {
        let mut changed = elements.clone();
        changed[index] += Felt::ONE;
        let test = agreement(
            DIRECT_SOURCE,
            public_key.to_commitment(),
            original.clone().with_stack(changed.into()),
        );
        assert_failure(&test, message);
    }
    for (index, value, message) in [
        (fraction, 0, "nonzero denominator"),
        (fraction + 10, 1 << 16, "fraction limb"),
        (fraction + 30, 2, "fraction sign"),
        (fraction + 31, 1 << 21, "fraction carry range"),
    ] {
        let mut changed = elements.clone();
        changed[index] = Felt::from_u32(value);
        let test = agreement(
            DIRECT_SOURCE,
            public_key.to_commitment(),
            original.clone().with_stack(changed.into()),
        );
        assert_failure(&test, message);
    }
    // Keep r=3 and its valid fraction, but use the complete point-check tape for S=2Q.
    // Both scalars need one radix-four window, so no slope is needed after table construction.
    // All supplied additions are correct; the final relation must reject 3Q - S = Q != O.
    let two = scalar([2, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let other = direct_advice_inputs(&public_key, &two).stack().into_elements();
    let mut forged = elements[..q_root].to_vec();
    forged.extend_from_slice(&other[q_root..]);
    assert_failure(
        &agreement(
            DIRECT_SOURCE,
            public_key.to_commitment(),
            original.clone().with_stack(forged.into()),
        ),
        "short scalar product",
    );
    for (limbs, message) in [([0; 10], "nonzero scalar"), (SCALAR_ORDER, "scalar range")] {
        let mut changed = elements.clone();
        for (element, limb) in changed[5..15].iter_mut().zip(limbs) {
            *element = Felt::from_u32(limb);
        }
        let test = agreement(
            DIRECT_SOURCE,
            public_key.to_commitment(),
            original.clone().with_stack(changed.into()),
        );
        assert_failure(&test, message);
    }
    // Invalid encodings from the reference implementation's point-validation vectors.
    let invalid = [
        [
            13557832913345268708,
            15669280705791538619,
            8534654657267986396,
            12533218303838131749,
            5058070698878426028,
        ],
        [
            135036726621282077,
            17283229938160287622,
            13113167081889323961,
            1653240450380825271,
            520025869628727862,
        ],
        [
            6727960962624180771,
            17240764188796091916,
            3954717247028503753,
            1002781561619501488,
            4295357288570643789,
        ],
        [
            4578929270179684956,
            3866930513245945042,
            7662265318638150701,
            9503686272550423634,
            12241691520798116285,
        ],
        [
            16890297404904119082,
            6169724643582733633,
            9725973298012340311,
            5977049210035183790,
            11379332130141664883,
        ],
        [
            13777379982711219130,
            14715168412651470168,
            17942199593791635585,
            6188824164976547520,
            15461469634034461986,
        ],
    ]
    .map(|point| point.map(Felt::new_unchecked));
    for point in invalid {
        assert!(PublicKey::from_elements(point).is_err());
    }
    let points = invalid.into_iter().map(|point| (point, "public key")).chain([
        ([Felt::ZERO; 5], "nonzero public key"),
        (secret.public_key().to_elements(), "public key"),
    ]);
    for (point, message) in points {
        // A matching commitment does not replace point or multiplication-witness validation.
        let commitment = Eidos::hash_elements_in_domain(&point, ECGFP5_PUBLIC_KEY);
        let mut changed = elements.clone();
        changed[..5].copy_from_slice(&point);
        assert_failure(
            &agreement(DIRECT_SOURCE, commitment, original.clone().with_stack(changed.into())),
            message,
        );
    }

    // Either square root identifies the same decoded point.
    let mut opposite_root = elements;
    for coefficient in &mut opposite_root[q_root..q_root + 5] {
        *coefficient = -*coefficient;
    }
    let test = agreement(
        DIRECT_SOURCE,
        public_key.to_commitment(),
        original.with_stack(opposite_root.into()),
    );
    test.expect_stack(&expected(&secret, &public_key));
}

#[test]
fn agreement_and_sealing_reject_a_different_recipient() {
    let secret = sample();
    let other_key = secret.public_key();
    let other_prepared = PreparedPublicKey::new(other_key);
    for (mode, source, commitment, advice, message) in [
        (
            SealMode::Direct,
            DIRECT_SOURCE,
            recipient().public_key().to_commitment(),
            direct_advice_inputs(&other_key, &secret),
            "public key commitment",
        ),
        (
            SealMode::Preprocessed,
            SOURCE,
            prepared().to_commitment(),
            advice_inputs(&other_prepared, &secret),
            "window roots",
        ),
    ] {
        // The advice is internally consistent, but belongs to another valid recipient key.
        assert_failure(&agreement(source, commitment, advice.clone()), message);
        let program = seal_program(&[], &[], mode);
        let mut test = build_test!(&program, &[]);
        test.advice_inputs = advice;
        assert_failure(&test, message);
    }
}

#[test]
fn agreement_rejects_generic_and_other_key_commitments() {
    let secret = sample();
    let public_key = recipient().public_key();
    let direct = direct_advice_inputs(&public_key, &secret);
    let preprocessed = advice_inputs(prepared(), &secret);
    let roots = miden_crypto::SequentialCommit::to_elements(prepared());
    for (source, commitments, advice, message) in [
        (
            DIRECT_SOURCE,
            [Eidos::hash_elements(&public_key.to_elements()), prepared().to_commitment()],
            direct,
            "public key commitment",
        ),
        (
            SOURCE,
            [Eidos::hash_elements(&roots), public_key.to_commitment()],
            preprocessed,
            "window roots",
        ),
    ] {
        for commitment in commitments {
            assert_failure(&agreement(source, commitment, advice.clone()), message);
        }
    }
}

#[test]
fn proves_direct_agreement() {
    let secret = sample();
    let public_key = recipient().public_key();
    // Leave only the public ephemeral point in the proof statement, not the shared secret.
    let source = "use miden::core::crypto::ecdh::ecgfp5
        begin exec.ecgfp5::agree repeat.11 movup.5 drop end end";
    let test =
        agreement(source, public_key.to_commitment(), direct_advice_inputs(&public_key, &secret));
    test.check_constraints();
    let inputs = public_key.to_commitment().iter().map(Felt::as_canonical_u64).collect();
    test.prove_and_verify(inputs, false);
}

#[test]
fn fp5_arithmetic_preserves_overflow_and_matches_convolution() {
    // Reduce the ordinary polynomial convolution by z^5 = 3, independently of the MASM schedule.
    fn product(a: [Felt; 5], b: [Felt; 5]) -> [Felt; 5] {
        let mut result = [Felt::ZERO; 5];
        for (i, a) in a.into_iter().enumerate() {
            for (j, b) in b.into_iter().enumerate() {
                let factor = if i + j >= 5 { Felt::from_u32(3) } else { Felt::ONE };
                result[(i + j) % 5] += a * b * factor;
            }
        }
        result
    }

    let mut pairs = vec![
        ([Felt::ZERO; 5], [Felt::ZERO; 5]),
        ([Felt::ONE; 5], [-Felt::ONE; 5]),
        ([-Felt::ONE; 5], [-Felt::ONE; 5]),
    ];
    // Every monomial pair checks its output lane and whether its degree wraps.
    for i in 0..5 {
        for j in 0..5 {
            let mut a = [Felt::ZERO; 5];
            let mut b = [Felt::ZERO; 5];
            a[i] = Felt::ONE;
            b[j] = Felt::ONE;
            pairs.push((a, b));
        }
    }
    let mut rng = ChaCha20Rng::from_seed([83; 32]);
    for _ in 0..64 {
        let mut element = || Felt::new(rng.next_u64() % Felt::ORDER).unwrap();
        pairs.push((std::array::from_fn(|_| element()), std::array::from_fn(|_| element())));
    }

    let mut advice = Vec::new();
    for (a, b) in &pairs {
        // Scalar advice pushes reverse the operands; the expected coefficients are popped in order.
        advice.extend(a.iter().rev().chain(b.iter().rev()).copied());
        advice.extend(product(*a, *b));
        advice.extend(a.iter().rev().copied());
        advice.extend(product(*a, *a));
        advice.extend(b.iter().rev().chain(a.iter().rev()).copied());
        advice.extend(a.iter().zip(b).map(|(a, b)| *a - *b));
    }

    let module = include_str!("../../asm/crypto/ecdh/ecgfp5/arithmetic.masm");
    let mut push_caller = String::new();
    for value in 1..=32 {
        push_caller.push_str(&format!("push.{value}\n"));
    }
    let mut check_caller = String::new();
    for value in (1..=32).rev() {
        check_caller.push_str(&format!("push.{value} assert_eq\n"));
    }
    // Check every helper return: a later invocation must not conceal an earlier stack corruption.
    let source = format!(
        "use test::fp5_test
        proc check_caller_stack
            {check_caller}
            {push_caller}
        end
        begin
            {push_caller}
            repeat.{}
                repeat.10 adv_push end exec.fp5_test::mul_fp5
                repeat.5 adv_push assert_eq end
                exec.check_caller_stack
                repeat.5 adv_push end exec.fp5_test::square_fp5
                repeat.5 adv_push assert_eq end
                exec.check_caller_stack
                repeat.10 adv_push end exec.fp5_test::sub_fp5
                repeat.5 adv_push assert_eq end
                exec.check_caller_stack
            end
            {check_caller}
        end",
        pairs.len()
    );
    let mut test = build_test!(&source, &[]).with_module("test::fp5_test", module);
    test.advice_inputs = AdviceInputs::default().with_stack(advice.into());
    test.expect_stack(&[]);
}

#[test]
fn scalar_preparation_matches_encoding_and_preserves_caller_state() {
    let mut scalars = vec![sample(), scalar([u32::MAX, 0, 0, 0, 0, 0, 0, 0, 0, 0])];
    for window in 0..20 {
        let mut limbs = [0; 10];
        limbs[window / 2] = 1 << (16 * (window % 2));
        scalars.push(scalar(limbs));
    }
    // A smaller high limb must dominate larger low limbs; the borrow then crosses equal limbs.
    for i in 0..10 {
        let mut limbs = SCALAR_ORDER;
        limbs[..i].fill(u32::MAX);
        limbs[i] -= 1;
        scalars.push(scalar(limbs));
    }
    let mut rng = ChaCha20Rng::from_seed([84; 32]);
    scalars.extend((0..64).map(|_| SecretKey::with_rng(&mut rng)));

    let mut advice = Vec::new();
    for secret in &scalars {
        let bytes = secret.to_bytes();
        advice.extend(
            bytes
                .as_chunks::<4>()
                .0
                .iter()
                .map(|chunk| Felt::from_u32(u32::from_le_bytes(*chunk))),
        );
        // Expected digits come from the canonical byte encoding, not the MASM arithmetic.
        advice.extend(
            bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|chunk| Felt::from_u16(u16::from_le_bytes(*chunk))),
        );
    }
    advice.push(Felt::from_u32(12345));
    let module = include_str!("../../asm/crypto/ecdh/ecgfp5/scalar.masm");
    let mut push_caller = String::new();
    let mut check_caller = String::new();
    for value in 1..=32 {
        push_caller.push_str(&format!("push.{value}\n"));
    }
    for value in (1..=32).rev() {
        check_caller.push_str(&format!("push.{value} assert_eq\n"));
    }
    let mut check_digits = String::new();
    for address in 2048..2068 {
        check_digits.push_str(&format!("mem_load.{address} adv_push assert_eq\n"));
    }
    let source = format!(
        "use test::scalar_test
        begin
            push.111 mem_store.2047 push.222 mem_store.2068
            {push_caller}
            repeat.{}
                exec.scalar_test::prepare
                {check_digits}
                {check_caller}
                {push_caller}
                mem_load.2047 eq.111 assert
                mem_load.2068 eq.222 assert
            end
            {check_caller}
            adv_push eq.12345 assert
        end",
        scalars.len()
    );
    let mut test = build_test!(&source, &[]).with_module("test::scalar_test", module);
    test.advice_inputs = AdviceInputs::default().with_stack(advice.into());
    test.expect_stack(&[]);
}

#[test]
fn agrees_with_native_dh_at_scalar_boundaries() {
    let mut scalars = vec![
        scalar([1, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        scalar([65535, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        scalar([65537, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        scalar([
            0x948bffe0, 0xe80fd996, 0xd724a09c, 0xe8885c39, 0xcfb80639, 0x7fffffe6, 0x16,
            0x7ffffff1, 0x80000007, 0x7ffffffd,
        ]),
    ];
    // One nonzero digit in each window checks both initial zero runs and trailing zero runs.
    for window in 0..20 {
        let mut limbs = [0; 10];
        limbs[window / 2] = 1 << (16 * (window % 2));
        scalars.push(scalar(limbs));
    }
    let mut rng = ChaCha20Rng::from_seed([55; 32]);
    scalars.extend((0..8).map(|_| SecretKey::with_rng(&mut rng)));
    for secret in scalars {
        let test =
            agreement(SOURCE, prepared().to_commitment(), advice_inputs(prepared(), &secret));
        let (output, _) = test.execute_for_output().unwrap();
        let actual: Vec<_> = output.stack.iter().map(Felt::as_canonical_u64).collect();
        let mut expected = expected(&secret, &recipient().public_key());
        expected.resize(16, 0);
        assert_eq!(actual, expected);
    }
}

#[test]
fn agrees_with_generator_and_negated_generator_recipients() {
    // Largest valid top-window digit, with and without a lower-digit prefix to add to it.
    let secrets = [
        sample(),
        scalar([0, 0, 0, 0, 0, 0, 0, 0, 0, 0x7fff0000]),
        scalar([1, 0, 0, 0, 0, 0, 0, 0, 0, 0x7fff0000]),
    ];
    for encoding in [Felt::from_u32(4), -Felt::from_u32(4)] {
        let public_key =
            PublicKey::from_elements([encoding, Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO])
                .unwrap();
        let prepared = PreparedPublicKey::new(public_key);
        for secret in &secrets {
            let test =
                agreement(SOURCE, prepared.to_commitment(), advice_inputs(&prepared, secret));
            let mut expected = expected(secret, &public_key);
            expected.resize(16, 0);
            test.expect_stack(&expected);
        }
    }
}

#[test]
fn callable_from_a_kernel_procedure() {
    use std::sync::Arc;

    use miden_assembly::{
        Assembler, DefaultSourceManager, Linkage, Path,
        ast::{Module, ModuleKind},
    };
    use miden_core::program::{StackInputs, StackOutputs};
    use miden_core_lib::CoreLibrary;
    use miden_processor::{DefaultHost, FastProcessor};

    let secret = sample();
    let public_key = recipient().public_key();
    for (procedure, commitment, advice) in [
        ("agree", public_key.to_commitment(), direct_advice_inputs(&public_key, &secret)),
        (
            "agree_preprocessed",
            prepared().to_commitment(),
            advice_inputs(prepared(), &secret),
        ),
    ] {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let kernel = Module::parser(Some(ModuleKind::Kernel))
            .parse_str(
                Some(Path::KERNEL),
                format!(
                    r#"use miden::core::crypto::ecdh::ecgfp5
                pub proc agree
                    push.123 mem_store.64
                    exec.ecgfp5::{procedure}
                    mem_load.64 eq.123 assert.err="kernel memory"
                    repeat.11 movup.15 drop end
                end"#
                ),
                source_manager.clone(),
            )
            .unwrap();
        let core = CoreLibrary::default();
        let mut assembler = Assembler::new(source_manager.clone());
        assembler.link_package(core.package(), Linkage::Dynamic).unwrap();
        let kernel = Arc::from(assembler.assemble_kernel("kernel", kernel, None).unwrap());
        let program = Assembler::with_kernel(source_manager, Arc::clone(&kernel))
            .unwrap()
            .assemble_program(
                "kernel-dh",
                r#"proc user
                    push.456 mem_store.64
                    syscall.agree
                    mem_load.64 eq.456 assert.err="caller memory"
                end
                begin call.user end"#,
            )
            .unwrap()
            .unwrap_program();
        let inputs = StackInputs::new(commitment.as_elements()).unwrap();
        let mut host = DefaultHost::default().with_library(&core).unwrap();
        host.load_library(kernel.mast_forest()).unwrap();
        let witness = FastProcessor::new(inputs)
            .with_advice(advice)
            .unwrap()
            .execute_for_proving_sync(&program, &mut host)
            .unwrap();
        let expected: Vec<_> =
            expected(&secret, &public_key).into_iter().map(Felt::new_unchecked).collect();
        assert_eq!(witness.claim().stack_outputs(), &StackOutputs::new(&expected).unwrap());
    }
}

#[test]
fn preserves_caller_memory_and_stack_across_repeated_calls() {
    let first = sample();
    let second = scalar([65537, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let public_key = recipient().public_key();
    for (procedure, key, witnesses) in [
        (
            "agree",
            public_key.to_commitment(),
            [
                direct_advice_inputs(&public_key, &first),
                direct_advice_inputs(&public_key, &second),
            ],
        ),
        (
            "agree_preprocessed",
            prepared().to_commitment(),
            [advice_inputs(prepared(), &first), advice_inputs(prepared(), &second)],
        ),
    ] {
        let [mut advice, next] = witnesses;
        advice.extend(next);
        let mut body = String::new();
        for address in [0, 16, 32, 40, 44, 45, 46, 47, 64, 128, 256, 512, 2048] {
            body.push_str(&format!("push.123 mem_store.{address}\n"));
        }
        for value in 1..=20 {
            body.push_str(&format!("push.{value}\n"));
        }
        for secret in [&first, &second] {
            for value in key.iter().rev() {
                body.push_str(&format!("push.{value}\n"));
            }
            body.push_str(&format!("exec.ecgfp5::{procedure}\n"));
            for value in expected(secret, &public_key) {
                body.push_str(&format!("push.{value} assert_eq\n"));
            }
        }
        for value in (1..=20).rev() {
            body.push_str(&format!("push.{value} assert_eq\n"));
        }
        for address in [0, 16, 32, 40, 44, 45, 46, 47, 64, 128, 256, 512, 2048] {
            body.push_str(&format!("mem_load.{address} eq.123 assert\n"));
        }
        let source = format!("use miden::core::crypto::ecdh::ecgfp5\nbegin\n{body}end");
        let mut test = build_test!(&source, &[]);
        test.advice_inputs = advice;
        test.expect_stack(&[]);
    }
}

fn assert_failure(test: &Test, expected_message: &str) {
    let error = match test.execute_for_output() {
        Ok(_) => panic!("execution must fail: {expected_message}"),
        Err(error) => error,
    };
    let err_code = match error {
        ExecutionError::OperationError {
            err:
                OperationError::FailedAssertion { err_code, .. }
                | OperationError::U32AssertionFailed { err_code, .. },
            ..
        } => err_code,
        ExecutionError::OperationError {
            err: OperationError::MerklePathVerificationFailed { inner },
            ..
        } => inner.err_code,
        other => panic!("wrong failure for {expected_message}: {other}"),
    };
    assert_eq!(
        err_code,
        miden_core::mast::error_code_from_msg(expected_message),
        "{expected_message}"
    );
}

#[test]
fn rejects_altered_advice() {
    let original = advice_inputs(prepared(), &sample());
    let elements: Vec<_> = original.stack().into_elements();
    // Root coefficients, every lane of the first leaf, both five-coefficient slopes, and outputs.
    let cases = (10..90)
        .map(|i| (i, "window roots"))
        .chain((90..114).map(|i| (i, "table binding")))
        .chain((138..148).map(|i| (i, "slope")))
        .chain((elements.len() - 39..elements.len() - 29).map(|i| (i, "point encoding")))
        .chain((elements.len() - 29..elements.len() - 5).map(|i| (i, "table binding")))
        .chain((elements.len() - 5..elements.len()).map(|i| (i, "recipient encoding")));
    for (index, message) in cases {
        let mut changed = elements.clone();
        changed[index] += Felt::ONE;
        let advice = original.clone().with_stack(changed.into());
        let test = agreement(SOURCE, prepared().to_commitment(), advice);
        assert_failure(&test, message);
    }
    // Flip the lowest scalar bit: the scalar stays in range and the sibling leaf's path exists.
    // The unchanged leaf must be rejected at the new digit index, not for a missing path.
    let mut changed = elements;
    changed[0] = Felt::new(changed[0].as_canonical_u64() ^ 1).unwrap();
    let advice = original.clone().with_stack(changed.into());
    assert_failure(&agreement(SOURCE, prepared().to_commitment(), advice), "table binding");

    let mut wrong_root = prepared().to_commitment().into_elements();
    wrong_root[0] += Felt::ONE;
    assert_failure(&agreement(SOURCE, Word::new(wrong_root), original), "window roots");
}

#[test]
fn rejects_invalid_scalars_and_missing_paths() {
    let original = advice_inputs(prepared(), &sample());
    let elements: Vec<_> = original.stack().into_elements();
    let mut invalid_scalars = vec![[0; 10], SCALAR_ORDER, [u32::MAX; 10]];
    // A larger high limb must dominate smaller low limbs, clearing an incoming borrow.
    for i in 0..10 {
        let mut limbs = SCALAR_ORDER;
        limbs[..i].fill(0);
        limbs[i] += 1;
        invalid_scalars.push(limbs);
    }
    for value in invalid_scalars {
        let mut changed = elements.clone();
        for (element, limb) in changed.iter_mut().zip(value) {
            *element = Felt::from_u32(limb);
        }
        let message = if value == [0; 10] {
            "nonzero scalar"
        } else {
            "scalar range"
        };
        let test = agreement(
            SOURCE,
            prepared().to_commitment(),
            original.clone().with_stack(changed.into()),
        );
        assert_failure(&test, message);
    }
    for index in 0..10 {
        let mut changed = elements.clone();
        changed[index] = Felt::new_unchecked(1 << 32);
        let test = agreement(
            SOURCE,
            prepared().to_commitment(),
            original.clone().with_stack(changed.into()),
        );
        assert!(matches!(
            test.execute_for_output(),
            Err(ExecutionError::OperationError {
                err: OperationError::U32AssertionFailed { .. }
                    | OperationError::NotU32Values { .. },
                ..
            })
        ));
    }
    let test = agreement(
        SOURCE,
        prepared().to_commitment(),
        original.with_merkle_store(MerkleStore::new()),
    );
    assert!(matches!(
        test.execute_for_output(),
        Err(ExecutionError::AdviceError {
            err: miden_processor::advice::AdviceError::MerkleStoreLookupFailed(_),
            ..
        })
    ));
}

#[test]
fn satisfies_vm_constraints() {
    let test = agreement(SOURCE, prepared().to_commitment(), advice_inputs(prepared(), &sample()));
    test.check_constraints();
}

#[test]
fn proves_native_dh() {
    // Leave only the public ephemeral point in the proof statement, not the shared secret.
    let source = "use miden::core::crypto::ecdh::ecgfp5
        begin exec.ecgfp5::agree_preprocessed repeat.11 movup.5 drop end end";
    let test = agreement(source, prepared().to_commitment(), advice_inputs(prepared(), &sample()));
    let inputs = prepared().to_commitment().iter().map(Felt::as_canonical_u64).collect();
    test.prove_and_verify(inputs, false);
}

#[derive(Clone, Copy)]
enum SealMode {
    Direct,
    Preprocessed,
}

impl SealMode {
    fn call(self) -> String {
        match self {
            Self::Direct => {
                let key = recipient().public_key().to_commitment().into_elements();
                format!("push.{key:?} exec.ecgfp5_eidos::seal")
            },
            Self::Preprocessed => {
                let key = prepared().to_commitment().into_elements();
                format!("push.{key:?} exec.ecgfp5_eidos::seal_preprocessed")
            },
        }
    }

    fn advice(self, secret: &SecretKey) -> AdviceInputs {
        match self {
            Self::Direct => direct_advice_inputs(&recipient().public_key(), secret),
            Self::Preprocessed => advice_inputs(prepared(), secret),
        }
    }
}

fn seal_program(plaintext: &[Felt], context: &[Felt], mode: SealMode) -> String {
    let mut body = String::new();
    for (ptr, elements) in [(1000, plaintext), (2000, context)] {
        for (i, value) in elements.iter().enumerate() {
            body.push_str(&format!("push.{value} mem_store.{}\n", ptr + i));
        }
    }
    // Sentinels make accidental padding reads observable and guard the end of the output.
    for address in [1000 + plaintext.len(), 2000 + context.len(), 3008 + 2 * plaintext.len()] {
        body.push_str(&format!("push.999 mem_store.{address}\n"));
    }
    let seal = mode.call();
    format!(
        "use miden::core::crypto::ies::ecgfp5_eidos
        use miden::core::crypto::hashes::eidos
        begin
            {body}
            push.123.456
            push.3000.{}.2000.{}.1000 {seal}
            push.456 assert_eq push.123 assert_eq
            mem_load.{} eq.999 assert
            push.{}.3000 exec.eidos::hash_elements
            swapw dropw
        end",
        context.len(),
        plaintext.len(),
        3008 + 2 * plaintext.len(),
        8 + 2 * plaintext.len(),
    )
}

#[test]
fn sealing_matches_rust_with_general_associated_data() {
    use miden_crypto::{
        hash::eidos::Eidos,
        ies::{SealedMessage, UnsealingKey, ecgfp5_eidos},
        utils::Deserializable,
    };

    let ephemeral = sample();
    for (pt_len, ad_len) in
        [(0, 0), (0, 9), (1, 0), (1, 1), (7, 3), (8, 2), (8, 4), (8, 6), (9, 7), (32, 17)]
    {
        let plaintext: Vec<_> = (0..pt_len).map(|i| -Felt::from_u32(i)).collect();
        let context: Vec<_> = (0..ad_len).map(|i| Felt::from_u32(i * 17)).collect();
        let expected = ecgfp5_eidos::seal_with_scalar(
            &recipient().public_key(),
            &plaintext,
            &context,
            &ephemeral,
        )
        .unwrap();
        let expected_elements = expected.to_elements();
        let digest = Eidos::hash_elements(&expected_elements);
        for mode in [SealMode::Direct, SealMode::Preprocessed] {
            let source = seal_program(&plaintext, &context, mode);
            let mut test = build_test!(&source, &[]);
            test.advice_inputs = mode.advice(&ephemeral);
            let (output, _) = test.execute_for_output().unwrap();
            assert_eq!(output.stack.get_num_elements(4), digest.as_elements());
            assert_eq!(output.stack.get_num_elements(16)[4..], [Felt::ZERO; 12]);
            let envelope: Vec<_> = (0..expected_elements.len())
                .map(|i| {
                    output
                        .memory
                        .read_element(0_u32.into(), Felt::from_u32(3000 + i as u32))
                        .unwrap()
                })
                .collect();
            assert_eq!(envelope, expected_elements);
            let sealed = ecgfp5_eidos::Envelope::from_elements(&envelope).unwrap();
            let message = SealedMessage::from(sealed);
            let message = SealedMessage::read_from_bytes(&message.to_bytes()).unwrap();
            assert_eq!(
                UnsealingKey::Ecgfp5Eidos(recipient())
                    .unseal_elements_with_associated_data(message, &context)
                    .unwrap(),
                plaintext,
            );
            if (pt_len, ad_len) == (9, 7) {
                test.check_constraints();
            }
        }
    }
}

#[test]
fn sealing_rejects_bad_memory_before_reading_advice() {
    let frame = miden_core::FMP_INIT_VALUE.as_canonical_u64();
    for (src, len, context, context_len, dst, message) in [
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
        (1000, 0, 2000, 0, frame - 4, "memory ranges must stay below the local frame"),
        (
            u32::MAX as u64 - 3,
            8,
            2000,
            0,
            3000,
            "memory range exceeds the u32 address space",
        ),
        (1000, 4, 2000, 1, 1000, "destination overlaps an input"),
        (1000, 4, 2000, 1, 996, "destination overlaps an input"),
        (1000, 4, 2000, 1, 2000, "destination overlaps an input"),
        (1000, 4, 2000, 1, 1996, "destination overlaps an input"),
    ] {
        for mode in [SealMode::Direct, SealMode::Preprocessed] {
            let seal = mode.call();
            let source = format!(
                "use miden::core::crypto::ies::ecgfp5_eidos
                begin push.{dst}.{context_len}.{context}.{len}.{src} {seal} end"
            );
            assert_failure(&build_test!(&source, &[]), &format!("EcGFp5-Eidos {message}"));
        }
    }
}

#[test]
fn proves_in_vm_encryption() {
    for mode in [SealMode::Direct, SealMode::Preprocessed] {
        let source = seal_program(&[Felt::ONE; 9], &[Felt::ONE; 7], mode);
        let mut test = build_test!(&source, &[]);
        test.advice_inputs = mode.advice(&sample());
        // This checks proof validity, not ZK; the program embeds public test plaintext.
        test.prove_and_verify(vec![], false);
    }
}

#[test]
fn sealing_empty_ranges_does_not_read_their_addresses() {
    use miden_crypto::ies::ecgfp5_eidos;

    let ephemeral = sample();
    let sealed =
        ecgfp5_eidos::seal_with_scalar(&recipient().public_key(), &[], &[], &ephemeral).unwrap();
    let unread = u32::MAX - 3;
    let dst = miden_core::FMP_INIT_VALUE.as_canonical_u64() as u32 - 8;
    let expected: Vec<_> = sealed.to_elements().iter().map(Felt::as_canonical_u64).collect();
    for mode in [SealMode::Direct, SealMode::Preprocessed] {
        let seal = mode.call();
        let source = format!(
            "use miden::core::crypto::ies::ecgfp5_eidos
            begin push.{dst}.0.{unread}.0.{unread} {seal} end"
        );
        let mut test = build_test!(&source, &[]);
        test.advice_inputs = mode.advice(&ephemeral);
        test.expect_stack_and_memory(&[], dst, &expected);
    }
}

#[test]
fn repeated_sealing_preserves_caller_state_and_allows_overlapping_read_inputs() {
    use miden_crypto::ies::ecgfp5_eidos;

    let plaintext: Vec<_> = (0..8).map(Felt::from_u32).collect();
    let context = &plaintext[..3];
    let mut body = String::from("push.999 loc_store.0\n");
    for (i, value) in plaintext.iter().enumerate() {
        body.push_str(&format!("push.{value} mem_store.{}\n", 1000 + i));
    }
    for value in 1..=32 {
        body.push_str(&format!("push.{value}\n"));
    }
    let mut advice = AdviceInputs::default();
    for (mode, ephemeral) in [
        (SealMode::Direct, sample()),
        (SealMode::Preprocessed, scalar([65537, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
    ] {
        advice.extend(mode.advice(&ephemeral));
        let seal = mode.call();
        // Both read inputs start at 1000; the output starts immediately after the plaintext.
        body.push_str(&format!("push.1008.3.1000.8.1000 {seal}\n"));
        let sealed = ecgfp5_eidos::seal_with_scalar(
            &recipient().public_key(),
            &plaintext,
            context,
            &ephemeral,
        )
        .unwrap();
        for (i, value) in sealed.to_elements().iter().enumerate() {
            body.push_str(&format!("mem_load.{} push.{value} assert_eq\n", 1008 + i));
        }
        // Observe the entire preserved stack after each call, including its overflow region.
        for value in (1..=32).rev() {
            body.push_str(&format!("push.{value} assert_eq\n"));
        }
        for value in 1..=32 {
            body.push_str(&format!("push.{value}\n"));
        }
    }
    for value in (1..=32).rev() {
        body.push_str(&format!("push.{value} assert_eq\n"));
    }
    for (i, value) in plaintext.iter().enumerate() {
        body.push_str(&format!("mem_load.{} push.{value} assert_eq\n", 1000 + i));
    }
    body.push_str("loc_load.0 eq.999 assert\n");
    let source = format!(
        "use miden::core::crypto::ies::ecgfp5_eidos
        @locals(4)
        proc caller
            {body}
        end
        begin exec.caller end"
    );
    let mut test = build_test!(&source, &[]);
    test.advice_inputs = advice;
    test.expect_stack(&[]);
}
