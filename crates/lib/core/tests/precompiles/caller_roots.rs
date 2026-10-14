use miden_core::{
    Felt, Word,
    deferred::{DEFERRED_AND_FRAME, Node, PrecompileWitness, PrecompileWitnessEntry, TRUE_DIGEST},
    utils::bytes_to_packed_u32_elements,
};
use miden_crypto::hash::{
    keccak::Keccak256,
    sha2::{Sha256, Sha512},
};
use miden_precompiles::{
    CurveId, CurvePrecompile, Keccak256Precompile, ONE_LIMBS, Sha256Precompile, Sha512Precompile,
    UintDomain, UintPrecompile,
};

use super::helpers::{
    masm_store_felts, read_memory_felts, read_stack_felts, run_precompile_program as run_raw,
};
use crate::helpers::{assert_exported_manual_root, masm_push_word};

fn run_precompile_program(
    source: &str,
) -> Result<miden_processor::ExecutionOutput, miden_processor::ExecutionError> {
    let (body, tail) = source.rsplit_once("end").unwrap();
    run_raw(&format!("{body} exec.::miden::core::sys::truncate_stack end {tail}"))
}

fn and_count(witness: &PrecompileWitness) -> usize {
    witness.entries().iter().filter(|entry| {
        matches!(entry, PrecompileWitnessEntry::Join { frame, .. } if *frame == DEFERRED_AND_FRAME)
    }).count()
}

fn uint_module(domain: UintDomain) -> &'static str {
    match domain {
        UintDomain::U256 => "u256",
        UintDomain::K1Base => "fields::k1_base",
        UintDomain::K1Scalar => "fields::k1_scalar",
        UintDomain::Ed25519Base => "fields::ed25519_base",
        UintDomain::Ed25519Scalar => "fields::ed25519_scalar",
        UintDomain::Ed25519Order => "fields::ed25519_order",
        UintDomain::P256Base => "fields::p256_base",
        UintDomain::P256Scalar => "fields::p256_scalar",
    }
}

#[test]
fn manual_uint_evaluation_and_predicates_bind_the_complete_graph() {
    for domain in UintDomain::ALL {
        let module = uint_module(domain);
        let one = UintPrecompile::value_node(domain, ONE_LIMBS).digest();
        let sum =
            Node::join(UintPrecompile::op_frame(UintPrecompile::ADD_OP_ID), one, one).unwrap();
        let two = UintPrecompile::value_node(domain, [2, 0, 0, 0, 0, 0, 0, 0]).digest();
        let binding =
            Node::join(UintPrecompile::op_frame(UintPrecompile::EQ_OP_ID), sum.digest(), two)
                .unwrap();
        let expected = binding.digest();
        let source = format!(
            r#"
            use miden::core::precompiles::{module}
            begin
                push.99.98.97.96
                exec.{leaf}::push_one_digest dupw exec.{leaf}::add
                exec.{leaf}::eval_with_root
                adv.export_deferred_witness
            end
        "#,
            leaf = module.rsplit("::").next().unwrap()
        );
        let output = run_precompile_program(&source).unwrap();
        let witness = assert_exported_manual_root(&output, 0);
        assert_eq!(witness.root_unchecked(), expected);
        assert_eq!(
            &read_stack_felts(&output, 16)[4..12],
            &[2, 0, 0, 0, 0, 0, 0, 0].map(Felt::from_u32)
        );
        assert_eq!(&read_stack_felts(&output, 16)[12..], &[96, 97, 98, 99].map(Felt::from_u32));

        for (name, args, expected_bit, bindings) in [
            ("is_eq", "push_one_digest push_one_digest", 1, 2),
            ("is_eq", "push_one_digest push_two_digest", 0, 2),
            ("is_zero", "push_one_digest", 0, 1),
            ("is_one", "push_one_digest", 1, 1),
            ("is_eq_digest", "push_two_digest push_one_digest", 0, 1),
        ] {
            let leaf = module.rsplit("::").next().unwrap();
            let args = args
                .split_whitespace()
                .map(|p| format!("exec.{leaf}::{p}"))
                .collect::<Vec<_>>()
                .join(" ");
            let source = format!(
                "use miden::core::precompiles::{module}\nbegin push.99.98.97.96 {args} exec.{leaf}::{name}_with_root adv.export_deferred_witness end"
            );
            let output = run_precompile_program(&source).unwrap();
            let witness = assert_exported_manual_root(&output, 0);
            assert_eq!(and_count(&witness), bindings - 1, "{module}::{name}");
            assert_eq!(output.stack.get_element(4).unwrap(), Felt::from_u32(expected_bit));
            assert_eq!(&read_stack_felts(&output, 9)[5..], &[96, 97, 98, 99].map(Felt::from_u32));
        }
    }
}

#[test]
fn manual_uint_equality_preserves_canonical_bindings_and_high_limb_inequality() {
    for domain in UintDomain::ALL {
        let module = uint_module(domain);
        let leaf = module.rsplit("::").next().unwrap();
        let one = UintPrecompile::value_node(domain, ONE_LIMBS).digest();
        let two = UintPrecompile::value_node(domain, [2, 0, 0, 0, 0, 0, 0, 0]).digest();
        let sum = Node::join(UintPrecompile::op_frame(UintPrecompile::ADD_OP_ID), one, one)
            .unwrap()
            .digest();
        let mut cases = vec![(
            format!(
                "exec.{leaf}::push_two_digest exec.{leaf}::push_one_digest dupw exec.{leaf}::add"
            ),
            sum,
            two,
            two,
            two,
            true,
        )];
        for limb in 4..8 {
            let mut high = ONE_LIMBS;
            high[limb] = 1;
            let value = UintPrecompile::value_node(domain, high).digest();
            let words = high
                .map(Felt::from_u32)
                .chunks(4)
                .rev()
                .map(|word| masm_push_word(&Word::new(word.try_into().unwrap())))
                .collect::<Vec<_>>()
                .join(" ");
            cases.push((
                format!("{words} exec.{leaf}::load exec.{leaf}::push_one_digest"),
                one,
                one,
                value,
                value,
                false,
            ));
        }
        for (setup, lhs_expr, lhs_value, rhs_expr, rhs_value, equal) in cases {
            let seed = Node::and(TRUE_DIGEST, TRUE_DIGEST).digest();
            let eq = UintPrecompile::op_frame(UintPrecompile::EQ_OP_ID);
            let lhs_binding = Node::join(eq, lhs_expr, lhs_value).unwrap().digest();
            let rhs_binding = Node::join(eq, rhs_expr, rhs_value).unwrap().digest();
            let comparison = Node::and(lhs_binding, rhs_binding).digest();
            let expected = Node::and(comparison, seed).digest();
            let source = format!(
                "use miden::core::precompiles::{module}\nbegin push.99.98.97.96 padw padw exec.::miden::core::precompiles::append_root {setup} exec.{leaf}::is_eq_with_root adv.export_deferred_witness movup.4 movdn.8 exec.::miden::core::precompiles::append_root adv.export_deferred_witness end"
            );
            let output = run_precompile_program(&source).unwrap();
            let witness = assert_exported_manual_root(&output, 0);
            assert_eq!(witness.root_unchecked(), expected, "{module}: binding order");
            assert!(output.advice.get_mapped_values(&comparison).is_some());
            assert_eq!(and_count(&witness), 3);
            assert_eq!(output.stack.get_element(4), Some(Felt::from_u32(u32::from(equal))));
            assert_eq!(&read_stack_felts(&output, 9)[5..], &[96, 97, 98, 99].map(Felt::from_u32));
        }
    }
}

#[test]
fn independent_inversion_and_division_roots_compose_explicitly() {
    for domain in UintDomain::ALL.into_iter().filter(|d| d.is_prime_field()) {
        let module = uint_module(domain);
        let leaf = module.rsplit("::").next().unwrap();
        let source = format!(
            r#"
            use miden::core::precompiles::{module}
            begin
                push.99.98.97.96
                exec.{leaf}::push_two_digest
                exec.{leaf}::inv_with_root
                swapw
                exec.{leaf}::push_one_digest
                exec.{leaf}::div_with_root
                # => [DIV_ROOT, QUOTIENT, INV_ROOT, ...]
                movupw.2 exec.::miden::core::precompiles::append_root
                swapw
                exec.{leaf}::push_two_digest exec.{leaf}::assert_eq_with_root
                exec.::miden::core::precompiles::append_root
                adv.export_deferred_witness
            end
        "#
        );
        // 1 / (1 / 2) = 2, with two inversion bindings and the final equality.
        let output = run_precompile_program(&source).unwrap();
        assert_eq!(and_count(&assert_exported_manual_root(&output, 0)), 2);
        assert_eq!(&read_stack_felts(&output, 8)[4..], &[96, 97, 98, 99].map(Felt::from_u32));
        let zero = format!(
            "use miden::core::precompiles::{module}\nbegin exec.{leaf}::push_zero_digest exec.{leaf}::inv_with_root end"
        );
        assert!(run_precompile_program(&zero).is_err());
    }
}

#[test]
fn manual_curve_calls_bind_values_and_allow_false_predicates() {
    for (module, curve) in [
        ("secp256k1", CurveId::Secp256k1),
        ("p256", CurveId::P256),
        ("ed25519", CurveId::Ed25519),
    ] {
        for (name, args, bit, count) in [
            ("is_eq", "push_generator push_generator", Some(1), 2),
            ("is_eq", "push_generator push_identity", Some(0), 2),
            ("is_eq_digest", "push_identity push_generator", Some(0), 1),
            ("is_identity", "push_generator", Some(0), 1),
            ("assert_identity", "push_identity", None, 1),
            ("assert_not_identity", "push_generator", None, 1),
            ("assert_eq", "push_generator push_generator", None, 1),
            ("assert_eq_digest", "push_generator push_generator", None, 1),
        ] {
            let args = args
                .split_whitespace()
                .map(|p| format!("exec.{module}::{p}"))
                .collect::<Vec<_>>()
                .join(" ");
            let source = format!(
                "use miden::core::precompiles::curves::{module}\nbegin push.99.98.97.96 {args} exec.{module}::{name}_with_root adv.export_deferred_witness end"
            );
            let output = run_precompile_program(&source).unwrap();
            assert_eq!(and_count(&assert_exported_manual_root(&output, 0)), count - 1);
            if let Some(bit) = bit {
                assert_eq!(output.stack.get_element(4).unwrap(), Felt::from_u32(bit));
            }
            let tail_offset = 4 + usize::from(bit.is_some());
            assert_eq!(
                &read_stack_felts(&output, tail_offset + 4)[tail_offset..],
                &[96, 97, 98, 99].map(Felt::from_u32)
            );
        }
        let source = format!(
            "use miden::core::precompiles::curves::{module}\nbegin push.99.98.97.96 exec.{module}::push_generator exec.{module}::eval_with_root adv.export_deferred_witness push.64 mem_storew_le dropw push.68 mem_storew_le dropw push.72 mem_storew_le dropw push.76 mem_storew_le dropw padw push.64 mem_loadw_le end"
        );
        let output = run_precompile_program(&source).unwrap();
        let witness = assert_exported_manual_root(&output, 0);
        assert_eq!(and_count(&witness), 0);
        let generator = CurvePrecompile::generator_node(curve);
        let (x, y) = generator.payload().as_join().unwrap();
        let binding = Node::join(
            CurvePrecompile::op_frame(CurvePrecompile::EQ_OP_ID),
            generator.digest(),
            generator.digest(),
        )
        .unwrap();
        assert_eq!(witness.root_unchecked(), binding.digest());
        assert_eq!(read_memory_felts(&output, 68, 4), generator.digest().as_elements());
        assert_eq!(read_memory_felts(&output, 72, 4), x.as_elements());
        assert_eq!(read_memory_felts(&output, 76, 4), y.as_elements());
        assert_eq!(&read_stack_felts(&output, 8)[4..], &[96, 97, 98, 99].map(Felt::from_u32));
    }
}

#[test]
fn independent_manual_roots_can_be_composed_without_logging() {
    let source = r#"
        use miden::core::precompiles
        use miden::core::precompiles::u256
        begin
            exec.u256::push_one_digest dupw exec.u256::assert_eq_with_root
            adv.export_deferred_witness push.0 mem_storew_le dropw
            exec.u256::push_two_digest dupw exec.u256::assert_eq_with_root
            adv.export_deferred_witness push.4 mem_storew_le dropw
            padw push.0 mem_loadw_le padw push.4 mem_loadw_le
            exec.precompiles::append_root
            adv.export_deferred_witness
        end
    "#;
    let output = run_precompile_program(source).unwrap();
    let lhs = Word::new(read_memory_felts(&output, 0, 4).try_into().unwrap());
    let rhs = Word::new(read_memory_felts(&output, 4, 4).try_into().unwrap());
    let witness = assert_exported_manual_root(&output, 0);
    assert_eq!(witness.root_unchecked(), Node::and(rhs, lhs).digest());
    assert_eq!(and_count(&witness), 1);
    assert!(output.advice.get_mapped_values(&lhs).is_some());
    assert!(output.advice.get_mapped_values(&rhs).is_some());
}

#[test]
fn stored_roots_compose_in_place_preserving_neighbors_and_tail() {
    let one = UintPrecompile::value_node(UintDomain::U256, ONE_LIMBS).digest();
    let two = UintPrecompile::value_node(UintDomain::U256, [2, 0, 0, 0, 0, 0, 0, 0]).digest();
    let eq = UintPrecompile::op_frame(UintPrecompile::EQ_OP_ID);
    let first = Node::join(eq, one, one).unwrap().digest();
    let second = Node::join(eq, two, two).unwrap().digest();
    let guards = [91, 92, 93, 94].map(Felt::from_u32);
    let stores = format!("{} {}", masm_store_felts(&guards, 60), masm_store_felts(&guards, 68));
    for (seed_setup, seed, seed_ands) in [
        ("padw", TRUE_DIGEST, 0),
        (
            "padw padw exec.precompiles::append_root",
            Node::and(TRUE_DIGEST, TRUE_DIGEST).digest(),
            1,
        ),
    ] {
        let source = format!(
            r#"
            use miden::core::precompiles
            use miden::core::precompiles::u256
            begin
                {stores}
                {seed_setup} push.64 mem_storew_le dropw
                push.99.98.97.96
                exec.u256::push_one_digest dupw exec.u256::assert_eq_with_root
                push.64 exec.precompiles::append_root_ptr
                exec.u256::push_two_digest dupw exec.u256::assert_eq_with_root
                push.64 exec.precompiles::append_root_ptr
                padw push.64 mem_loadw_le adv.export_deferred_witness
            end
        "#
        );
        let output = run_precompile_program(&source).unwrap();
        let witness = assert_exported_manual_root(&output, 0);
        let expected = Node::and(Node::and(seed, first).digest(), second).digest();
        assert_eq!(witness.root_unchecked(), expected);
        assert_eq!(read_memory_felts(&output, 64, 4), expected.as_elements());
        assert_eq!(and_count(&witness), seed_ands + 2);
        assert_eq!(read_memory_felts(&output, 60, 4), guards);
        assert_eq!(read_memory_felts(&output, 68, 4), guards);
        assert_eq!(&read_stack_felts(&output, 8)[4..], &[96, 97, 98, 99].map(Felt::from_u32));
    }
}

#[test]
fn manual_hashes_return_the_exact_assertion_root_and_memory_digest() {
    for module in ["keccak256", "sha256", "sha512"] {
        for len in [0usize, 1, 32, 33, 64, 65] {
            let input: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let expected = match module {
                "keccak256" => Keccak256::hash(&input).as_bytes().to_vec(),
                "sha256" => Sha256::hash(&input).as_bytes().to_vec(),
                _ => Sha512::hash(&input).as_bytes().to_vec(),
            };
            let preimage = Node::chunks_from_bytes(&input).digest();
            let digest = Node::chunks_from_bytes(&expected).digest();
            let assertion = match module {
                "keccak256" => Keccak256Precompile::assert_node(len as u32, preimage, digest),
                "sha256" => Sha256Precompile::assert_node(len as u32, preimage, digest),
                _ => Sha512Precompile::assert_node(len as u32, preimage, digest),
            };
            let mut limbs = bytes_to_packed_u32_elements(&input);
            limbs.resize(len.div_ceil(32).max(1) * 8, Felt::ZERO);
            let stores = masm_store_felts(&limbs, 128);
            let mut names = vec!["hash_bytes_mem"];
            if module == "keccak256" && len <= 32 {
                names.push("hash_1_chunk_mem");
            }
            if module == "keccak256" && (33..=64).contains(&len) {
                names.push("hash_2_chunks_mem");
            }
            for name in names {
                let source = format!(
                    "use miden::core::precompiles::hashes::{module}\nbegin {stores} push.99.98.97.96 push.256 push.{len} push.128 exec.{module}::{name}_with_root adv.export_deferred_witness end"
                );
                let output = run_precompile_program(&source).unwrap();
                let witness = assert_exported_manual_root(&output, 0);
                assert_eq!(witness.root_unchecked(), assertion.digest());
                assert_eq!(and_count(&witness), 0, "hash roots must be bare assertions");
                assert_eq!(
                    &read_stack_felts(&output, 8)[4..],
                    &[96, 97, 98, 99].map(Felt::from_u32)
                );
                let expected = bytes_to_packed_u32_elements(&expected);
                assert_eq!(read_memory_felts(&output, 256, expected.len()), expected);
                let native =
                    source.replace("_with_root", "").replace("adv.export_deferred_witness", "");
                let native = run_precompile_program(&native).unwrap();
                assert_eq!(
                    native.precompile_root(),
                    Node::and(TRUE_DIGEST, witness.root_unchecked()).digest()
                );
                // Explicit composition must retain the exact hash assertion and caller root.
                let composed = source.replace(
                    "adv.export_deferred_witness",
                    "padw exec.::miden::core::precompiles::append_root adv.export_deferred_witness",
                );
                let composed = run_precompile_program(&composed).unwrap();
                assert_eq!(
                    assert_exported_manual_root(&composed, 0).root_unchecked(),
                    native.precompile_root()
                );
                assert_eq!(read_memory_felts(&composed, 256, expected.len()), expected);
            }
        }
    }
}

#[test]
fn returned_hash_roots_compose_with_arithmetic_and_preserve_the_vm_root() {
    let one = UintPrecompile::value_node(UintDomain::U256, ONE_LIMBS).digest();
    let equality =
        Node::join(UintPrecompile::op_frame(UintPrecompile::EQ_OP_ID), one, one).unwrap();
    let seed = equality.digest();
    let preimage = Node::chunks_from_bytes(b"abc").digest();
    let sha256 = Sha256Precompile::assert_node(
        3,
        preimage,
        Node::chunks_from_bytes(Sha256::hash(b"abc").as_bytes()).digest(),
    );
    let sha512 = Sha512Precompile::assert_node(
        3,
        preimage,
        Node::chunks_from_bytes(Sha512::hash(b"abc").as_bytes()).digest(),
    );
    let expected = Node::and(sha512.digest(), Node::and(sha256.digest(), seed).digest()).digest();
    let source = r#"
        use miden::core::precompiles
        use miden::core::precompiles::u256
        use miden::core::precompiles::hashes::sha256
        use miden::core::precompiles::hashes::sha512
        begin
            push.6513249 push.128 mem_store
            push.99.98.97.96
            exec.u256::push_one_digest dupw exec.u256::assert_eq_with_root
            push.256 push.3 push.128 exec.sha256::hash_bytes_mem_with_root
            adv.export_deferred_witness
            exec.precompiles::append_root
            push.256 push.3 push.128 exec.sha512::hash_bytes_mem_with_root
            adv.export_deferred_witness
            exec.precompiles::append_root
            adv.export_deferred_witness
        end
    "#;
    let output = run_precompile_program(source).unwrap();
    let witness = assert_exported_manual_root(&output, 0);
    assert_eq!(witness.root_unchecked(), expected);
    assert_eq!(and_count(&witness), 2);
    assert!(output.advice.get_mapped_values(&sha256.digest()).is_some());
    assert!(output.advice.get_mapped_values(&sha512.digest()).is_some());
    assert_eq!(&read_stack_felts(&output, 8)[4..], &[96, 97, 98, 99].map(Felt::from_u32));

    let logged = source.replacen("begin", "begin padw exec.precompiles::log_deferred", 1);
    let logged = run_precompile_program(&logged).unwrap();
    assert_eq!(logged.precompile_root(), Node::and(TRUE_DIGEST, TRUE_DIGEST).digest());
    assert_eq!(logged.stack, output.stack);
    assert_eq!(
        logged.advice.get_mapped_values(&expected),
        output.advice.get_mapped_values(&expected)
    );
}

#[test]
fn stack_keccak_returns_root_before_limbs_including_full_width_merge() {
    for name in ["hash", "merge", "hash_bytes"] {
        let len = if name == "merge" { 64 } else { 32 };
        let bytes: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let limbs = bytes_to_packed_u32_elements(&bytes);
        let setup = if name == "hash_bytes" {
            format!("{} push.32 push.128", masm_store_felts(&limbs, 128))
        } else {
            limbs
                .chunks(4)
                .rev()
                .map(|word| masm_push_word(&Word::new(word.try_into().unwrap())))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let source = format!(
            "begin push.99.98.97.96 {setup} exec.::miden::core::crypto::hashes::keccak256::{name}_with_root adv.export_deferred_witness end"
        );
        let output = run_precompile_program(&source).unwrap();
        assert_eq!(and_count(&assert_exported_manual_root(&output, 0)), 0);
        assert_eq!(
            &read_stack_felts(&output, 16)[4..12],
            bytes_to_packed_u32_elements(Keccak256::hash(&bytes).as_bytes())
        );
        assert_eq!(&read_stack_felts(&output, 16)[12..], &[96, 97, 98, 99].map(Felt::from_u32));
    }
}

#[test]
fn manual_hashes_reject_forged_digest_advice() {
    use std::sync::Arc;

    use miden_assembly::{Assembler, Linkage};
    use miden_core::deferred::PrecompileError;
    use miden_core_lib::{
        CoreLibrary,
        handlers::precompiles::{
            keccak256::KECCAK256_DIGEST_EVENT_NAME, sha256::SHA256_DIGEST_EVENT_NAME,
            sha512::SHA512_DIGEST_EVENT_NAME,
        },
    };
    use miden_processor::{
        DefaultHost, ExecutionError, ExecutionOptions, FastProcessor, StackInputs,
        advice::{AdviceInputs, AdviceMutation, AdviceStack},
        event::EventHandler,
    };

    for (module, event, digest_felts) in [
        ("keccak256", KECCAK256_DIGEST_EVENT_NAME, 8),
        ("sha256", SHA256_DIGEST_EVENT_NAME, 8),
        ("sha512", SHA512_DIGEST_EVENT_NAME, 16),
    ] {
        let library = CoreLibrary::default();
        let handler: Arc<dyn EventHandler> =
            Arc::new(move |_: &miden_processor::ProcessorState<'_>| {
                let mut advice = AdviceStack::new();
                advice.append_for_adv_pipe(&vec![Felt::ZERO; digest_felts]);
                Ok(vec![AdviceMutation::extend_advice_stack(advice)])
            });
        let source = format!(
            "begin push.6513249 push.128 mem_store push.256 push.3 push.128 exec.::miden::core::precompiles::hashes::{module}::hash_bytes_mem_with_root end"
        );
        let program = Assembler::default()
            .with_package(library.package(), Linkage::Dynamic)
            .unwrap()
            .assemble_program("forged_manual_hash", source)
            .unwrap()
            .unwrap_program();
        let mut host = DefaultHost::default().with_library(&library).unwrap();
        assert!(host.replace_handler(event, handler));
        let error = FastProcessor::new_with_options(
            StackInputs::default(),
            AdviceInputs::default(),
            ExecutionOptions::default(),
        )
        .unwrap()
        .execute_sync(&program, &mut host)
        .unwrap_err();
        assert!(
            matches!(error,ExecutionError::DeferredError { ref err, .. } if matches!(err.root(),PrecompileError::AssertionFailed)),
            "{module}: {error}"
        );
    }
}
