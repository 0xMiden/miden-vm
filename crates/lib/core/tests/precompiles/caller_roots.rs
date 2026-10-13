use miden_core::{
    Felt, Word,
    deferred::{DEFERRED_AND_FRAME, Node, PrecompileWitness, PrecompileWitnessEntry, TRUE_DIGEST},
    utils::bytes_to_packed_u32_elements,
};
use miden_crypto::hash::{
    keccak::Keccak256,
    sha2::{Sha256, Sha512},
};
use miden_precompiles::{CurveId, CurvePrecompile, ONE_LIMBS, UintDomain, UintPrecompile};

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
        let expected = Node::and(TRUE_DIGEST, binding.digest()).digest();
        let source = format!(
            r#"
            use miden::core::precompiles::{module}
            begin
                push.99.98.97.96
                padw
                exec.{leaf}::push_one_digest dupw exec.{leaf}::add
                exec.{leaf}::eval_with_root
                movupw.2 adv.export_deferred_witness
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
                "use miden::core::precompiles::{module}\nbegin padw {args} exec.{leaf}::{name}_with_root movdn.4 adv.export_deferred_witness end"
            );
            let output = run_precompile_program(&source).unwrap();
            let witness = assert_exported_manual_root(&output, 0);
            assert_eq!(and_count(&witness), bindings, "{module}::{name}");
            assert_eq!(output.stack.get_element(4).unwrap(), Felt::from_u32(expected_bit));
        }
    }
}

#[test]
fn manual_inversion_and_division_chain_the_caller_root() {
    for domain in UintDomain::ALL.into_iter().filter(|d| d.is_prime_field()) {
        let module = uint_module(domain);
        let leaf = module.rsplit("::").next().unwrap();
        let source = format!(
            r#"
            use miden::core::precompiles::{module}
            begin
                padw
                exec.{leaf}::push_two_digest
                exec.{leaf}::inv_with_root
                exec.{leaf}::push_one_digest
                exec.{leaf}::div_with_root
                exec.{leaf}::push_two_digest exec.{leaf}::assert_eq_with_root
                adv.export_deferred_witness
            end
        "#
        );
        // 1 / (1 / 2) = 2, with two inversion bindings and the final equality.
        let output = run_precompile_program(&source).unwrap();
        assert_eq!(and_count(&assert_exported_manual_root(&output, 0)), 3);
        let zero = format!(
            "use miden::core::precompiles::{module}\nbegin padw exec.{leaf}::push_zero_digest exec.{leaf}::inv_with_root end"
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
            let adjust = if bit.is_some() { "movdn.4" } else { "" };
            let source = format!(
                "use miden::core::precompiles::curves::{module}\nbegin padw {args} exec.{module}::{name}_with_root {adjust} adv.export_deferred_witness end"
            );
            let output = run_precompile_program(&source).unwrap();
            assert_eq!(and_count(&assert_exported_manual_root(&output, 0)), count);
            if let Some(bit) = bit {
                assert_eq!(output.stack.get_element(4).unwrap(), Felt::from_u32(bit));
            }
        }
        let source = format!(
            "use miden::core::precompiles::curves::{module}\nbegin padw exec.{module}::push_generator exec.{module}::eval_with_root movupw.3 adv.export_deferred_witness end"
        );
        let output = run_precompile_program(&source).unwrap();
        assert_eq!(and_count(&assert_exported_manual_root(&output, 0)), 1);
        assert_eq!(
            &read_stack_felts(&output, 8)[4..],
            CurvePrecompile::generator_node(curve).digest().as_elements()
        );
    }
}

#[test]
fn independent_manual_roots_can_be_composed_without_logging() {
    let source = r#"
        use miden::core::precompiles
        use miden::core::precompiles::u256
        begin
            padw exec.u256::push_one_digest dupw exec.u256::assert_eq_with_root
            dupw adv.export_deferred_witness push.0 mem_storew_le dropw
            padw exec.u256::push_two_digest dupw exec.u256::assert_eq_with_root
            dupw adv.export_deferred_witness push.4 mem_storew_le dropw
            padw push.0 mem_loadw_le padw push.4 mem_loadw_le
            exec.precompiles::append_root
            adv.export_deferred_witness
        end
    "#;
    let output = run_precompile_program(source).unwrap();
    let lhs = Word::new(read_memory_felts(&output, 0, 4).try_into().unwrap());
    let rhs = Word::new(read_memory_felts(&output, 4, 4).try_into().unwrap());
    let witness = assert_exported_manual_root(&output, 0);
    assert_eq!(witness.root_unchecked(), Node::and(lhs, rhs).digest());
    assert_eq!(and_count(&witness), 3);
    assert!(output.advice.get_mapped_values(&lhs).is_some());
    assert!(output.advice.get_mapped_values(&rhs).is_some());
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
                    "use miden::core::precompiles::hashes::{module}\nbegin {stores} padw push.256 push.{len} push.128 exec.{module}::{name}_with_root adv.export_deferred_witness end"
                );
                let output = run_precompile_program(&source).unwrap();
                assert_eq!(and_count(&assert_exported_manual_root(&output, 0)), 1);
                let expected = bytes_to_packed_u32_elements(&expected);
                assert_eq!(read_memory_felts(&output, 256, expected.len()), expected);
                let native = source
                    .replace("padw push.256", "push.256")
                    .replace("_with_root", "")
                    .replace("adv.export_deferred_witness", "");
                let native = run_precompile_program(&native).unwrap();
                assert_eq!(
                    native.precompile_root(),
                    assert_exported_manual_root(&output, 0).root_unchecked()
                );
            }
        }
    }
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
            "begin push.99.98.97.96 padw {setup} exec.::miden::core::crypto::hashes::keccak256::{name}_with_root adv.export_deferred_witness end"
        );
        let output = run_precompile_program(&source).unwrap();
        assert_eq!(and_count(&assert_exported_manual_root(&output, 0)), 1);
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
            "begin push.6513249 push.128 mem_store padw push.256 push.3 push.128 exec.::miden::core::precompiles::hashes::{module}::hash_bytes_mem_with_root end"
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
