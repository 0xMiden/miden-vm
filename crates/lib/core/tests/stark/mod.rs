use std::{fmt::Write as _, sync::Arc};

use miden_air::vm::{MIDEN_AIR_COUNT, MidenAir, config};
use miden_assembly::{Assembler, testing::source_file};
use miden_core::{
    Felt, WORD_SIZE, Word,
    program::{ExecutionClaim, KernelDescriptor, NUM_CLAIM_ELEMENTS},
    proof::{ExecutionProof, HashFunction},
};
use miden_mast_package::Package;
use miden_processor::{DefaultHost, ExecutionOptions, FastProcessor, Program, ProgramInfo};
use miden_utils_testing::{
    AdviceInputs, Prover, Test,
    recursive_verifier::{VerifierData, generate_advice_inputs},
    stack_inputs_from_ints,
};
use rstest::rstest;

mod ace_circuit;
mod ace_read_check;
mod batch_query_gen;
mod deep_queries;
mod isolation;
mod proof_order_maps;
mod pvm_aux_trace;
mod pvm_deep_queries;
mod pvm_public_inputs;
mod pvm_scatter_bench;
mod pvm_settlement;
mod pvm_sigma_scatter;
mod pvm_verifier;
mod pvm_wrapper;
mod random_coin;
mod security;
mod security_math;
mod security_proven;
mod verifier_stack;
mod vm_public_inputs;
mod vm_scatter_bench;
mod vm_sigma_scatter;

use verifier_stack::{CALLER_WORD, VERIFIER_RETURN, VerifierStack};

pub(crate) fn pvm_layout_const(name: &str) -> u32 {
    let source = include_str!("../../asm/sys/pvm/layout.masm");
    let prefix = format!("const {name} = ");
    let region_prefix = format!("### {name}: ");
    let value = source
        .lines()
        .find_map(|line| {
            let line = line.trim();
            let value =
                line.strip_prefix("pub ").unwrap_or(line).strip_prefix(&prefix).or_else(|| {
                    let (_, range) = line.strip_prefix(&region_prefix)?.split_once(" felts at ")?;
                    range.split_once("..").map(|(start, _)| start)
                })?;
            value.parse::<u64>().ok()
        })
        .unwrap_or_else(|| panic!("missing generated PVM layout constant {name}"));
    u32::try_from(value).expect("PVM layout pointer must fit in u32")
}

pub(crate) fn vm_layout_const(name: &str) -> u32 {
    let source = include_str!("../../asm/sys/vm/layout.masm");
    let prefix = format!("const {name} = ");
    let value = source
        .lines()
        .chain(include_str!("../../asm/sys/vm/parameters.masm").lines())
        .find_map(|line| {
            let line = line.trim();
            line.strip_prefix("pub ")
                .unwrap_or(line)
                .strip_prefix(&prefix)?
                .parse::<u64>()
                .ok()
        })
        .unwrap_or_else(|| panic!("missing generated VM layout constant {name}"));
    u32::try_from(value).expect("VM layout pointer must fit in u32")
}

// RECURSIVE VERIFIER TESTS
// ================================================================================================

#[test]
fn stark_verifier_e2f4_small() {
    deep_queries::check_vm_queries(EXAMPLE_FIB_SMALL);
}

#[test]
fn stark_verifier_e2f4_large() {
    deep_queries::check_vm_queries(EXAMPLE_FIB_LARGE);
}

#[rstest]
#[case::even(KERNEL_EVEN_NUM_PROC)]
#[case::odd(KERNEL_ODD_NUM_PROC)]
#[case::single(KERNEL_SINGLE_PROC)]
fn stark_verifier_e2f4_with_kernel(#[case] kernel: &str) {
    let data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        fib_stack_inputs(),
        Some(kernel),
    );
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_with_max_kernel() {
    let kernel = max_kernel_source();
    let data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        fib_stack_inputs(),
        Some(&kernel),
    );
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_with_deferred_root() {
    let data =
        generate_recursive_verifier_data(EXAMPLE_LOG_DEFERRED, log_deferred_stack_inputs(), None);
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_with_kernel_flipped_order() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_LARGE,
        inputs,
        Some(KERNEL_SINGLE_PROC),
    );
    let order = run_recursive_verifier(&data);
    let expected = expected_order_from_shape(&data);

    assert_eq!(order, expected);
    assert_ne!(order, (0..MIDEN_AIR_COUNT).collect::<Vec<_>>());
}

#[test]
fn stark_verifier_e2f4_derives_the_shape_proof_order_for_small_proofs() {
    let equal_height = generate_recursive_verifier_data(EXAMPLE_EQUAL_HEIGHTS, vec![], None);
    let core_heavy = generate_recursive_verifier_data(EXAMPLE_FIB_LARGE, fib_stack_inputs(), None);

    let equal_height_order = run_recursive_verifier(&equal_height);
    let core_heavy_order = run_recursive_verifier(&core_heavy);

    assert_eq!(equal_height_order, expected_order_from_shape(&equal_height));
    assert_eq!(core_heavy_order, expected_order_from_shape(&core_heavy));
}

#[test]
fn stark_verifier_e2f4_rejects_missing_ace_circuit_stream() {
    let mut data = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);
    let circuit_key = recursive_circuit_key();
    data.advice_map.retain(|(key, _)| *key != circuit_key);

    assert_recursive_verifier_rejects(data, "missing ACE circuit stream should fail");
}

#[test]
fn stark_verifier_e2f4_rejects_corrupted_ace_circuit_stream() {
    let mut data = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);
    let circuit_key = recursive_circuit_key();
    let stream = advice_map_value_mut(&mut data, circuit_key);
    stream[0] += Felt::ONE;

    assert_recursive_verifier_rejects(data, "corrupted ACE circuit stream should fail");
}

/// A forged per-AIR log height must be rejected.
///
/// The transcript-bound per-AIR heights are the verifier's authoritative proof-order input.
/// `stage_proof_order_maps` derives both position maps from them once; scatter staging, boundary
/// placement, and fold-coefficient staging read those maps. No standalone order tag is stored.
/// The heights arrive on the advice stack, so
/// `sys/vm/public_inputs.masm` observes them into the Fiat-Shamir transcript: a forged height
/// diverges the transcript, and the proof cannot survive that divergence.
///
/// The non-vacuity guard at the end is what makes this cover *order* binding rather than height
/// binding alone: at least one forgery must land the verifier on a different proof order, which is
/// exactly the case a verifier that took the heights on trust would scatter wrongly for.
#[test]
fn each_air_log_height_is_transcript_bound() {
    /// Proof-stream index of the first advice-supplied log height: 4 security parameters and the
    /// 4-felt deferred root precede it.
    const FIRST_LOG_HEIGHT: usize = 8;
    /// The And8Lookup height is verifier-fixed setup, so only the others come from the proof.
    const ADVICE_SUPPLIED_HEIGHTS: usize = MIDEN_AIR_COUNT - 1;

    let base = generate_recursive_verifier_data(EXAMPLE_FIB_LARGE, fib_stack_inputs(), None);
    let honest_order = expected_order_from_shape(&base);
    let mut reordering_forgeries = 0usize;

    for air in 0..ADVICE_SUPPLIED_HEIGHTS {
        let mut data = base.clone();
        // Raise the height rather than lower it: `assert_shape_log`'s bounds stay satisfied either
        // way, so rejection cannot be explained by the structural check firing first.
        data.proof_stream[FIRST_LOG_HEIGHT + air] += 1;
        if expected_order_from_shape(&data) != honest_order {
            reordering_forgeries += 1;
        }

        assert_recursive_verifier_rejects(
            data,
            &format!("verifier accepted a forged log height for AIR {air}"),
        );
    }

    assert!(
        reordering_forgeries > 0,
        "no forged height moved the proof order, so this fixture cannot cover order binding"
    );
}

/// The negative direction of order binding cannot be explained by transcript divergence alone:
/// `each_air_log_height_is_transcript_bound` above would pass identically against a verifier
/// whose scatter, sigma placement and fold staging were hard-wired to the identity order, since a
/// forged height already diverges the transcript regardless of routing. This builds a mutant
/// `vm::verify_proof` from a fully staged scatter table, exchanging only the equal-width Core and
/// Chiplets auxiliary destinations. A paired control from the same source template accepts the
/// proof with correct routing; the mutant rejects it with only those destinations exchanged,
/// showing that the routing is load-bearing.
#[test]
fn verifier_rejects_a_non_identity_order_when_scatter_destinations_are_swapped() {
    let data = generate_recursive_verifier_data(EXAMPLE_FIB_LARGE, fib_stack_inputs(), None);
    let proof_order = expected_order_from_shape(&data);
    assert_ne!(
        proof_order,
        (0..MIDEN_AIR_COUNT).collect::<Vec<_>>(),
        "fixture must have a non-identity proof order to exercise scatter routing"
    );

    let proof_position = |target| {
        proof_order
            .iter()
            .position(|&air| air == target)
            .expect("each Miden AIR occurs once in the proof order")
    };
    // Dispatch words begin at table offset 4; lane 2 holds the auxiliary destination.
    // Core and Chiplets both use `pipe_2`, so exchanging only these cells keeps every procedure
    // digest and segment length valid while corrupting the routing permutation.
    let core_aux_destination = 6 + 4 * proof_position(MidenAir::CORE.instance_index());
    let chiplets_aux_destination = 6 + 4 * proof_position(MidenAir::CHIPLETS.instance_index());

    let source = |swap_destinations: bool| {
        let routing_mutation = if swap_destinations {
            format!(
                "exec.layout::ood_scatter_table_ptr add.{core_aux_destination} mem_load\n            \
                 exec.layout::ood_scatter_table_ptr add.{chiplets_aux_destination} mem_load\n            \
                 exec.layout::ood_scatter_table_ptr add.{core_aux_destination} mem_store\n            \
                 exec.layout::ood_scatter_table_ptr add.{chiplets_aux_destination} mem_store"
            )
        } else {
            String::new()
        };
        format!(
            "
        use miden::core::mem
        use miden::core::sys
        use miden::core::stark::utils
        use miden::core::stark::verifier

        use miden::core::sys::vm
        use miden::core::sys::vm::claim
        use miden::core::sys::vm::constraints_eval
        use miden::core::sys::vm::deep_queries
        use miden::core::sys::vm::layout
        use miden::core::sys::vm::ood_frames
        use miden::core::sys::vm::public_inputs
        use miden::core::sys::vm::aux_trace

        const KERNEL_COMMITMENT_OFFSET = 4
        const KERNEL_DOMAIN_TAG = 0x01000001
        const FELTS_PER_KERNEL_DIGEST = 4
        const MAX_NUM_KERNEL_PROCEDURES = 255
        # Mirrors the private `vm::materialize_kernel_witness`; any drift fails the control below.
        proc materialize_kernel_witness
            padw exec.layout::claim_ptr add.KERNEL_COMMITMENT_OFFSET mem_loadw_le
            adv.push_mapvaln
            adv_push
            u32assert.err=\"kernel witness length must fit in a u32\"
            dup u32mod.FELTS_PER_KERNEL_DIGEST
            assertz.err=\"kernel witness length must be word-aligned\"
            div.FELTS_PER_KERNEL_DIGEST
            dup u32lte.MAX_NUM_KERNEL_PROCEDURES
            assert.err=\"number of kernel procedures exceeds KernelDescriptor::MAX_NUM_PROCEDURES\"
            dup exec.layout::num_kernel_procedures_ptr mem_store
            exec.layout::kernel_witness_ptr swap
            push.KERNEL_DOMAIN_TAG
            exec.mem::pipe_words_to_memory_in_domain
            movup.4 drop
            assert_eqw.err=\"fetched kernel digests do not hash to the claim's kernel commitment\"
        end

        begin
            exec.layout::claim_commitment_ptr mem_storew_le
            exec.layout::claim_ptr exec.claim::materialize_claim

            exec.utils::load_security_params
            exec.materialize_kernel_witness
            exec.public_inputs::stage_boundary_inputs
            exec.vm::load_air_context
            {routing_mutation}

            procref.deep_queries::compute_deep_composition_polynomial_queries
            procref.constraints_eval::execute_constraint_evaluation_check
            procref.ood_frames::process_row_ood_evaluations
            procref.public_inputs::process_public_inputs
            procref.aux_trace::observe_aux_trace

            exec.verifier::verify
            exec.sys::truncate_stack
        end
    "
        )
    };

    let control_data = data.clone();
    let control_source = source(false);
    let control = build_test!(
        control_source.as_str(),
        &control_data.initial_stack(),
        control_data.advice_stack(),
        control_data.store,
        control_data.advice_map
    );
    control
        .execute_for_output()
        .expect("the paired control with correct scatter destinations must accept the proof");

    let mutated_source = source(true);
    let test = build_test!(
        mutated_source.as_str(),
        &data.initial_stack(),
        data.advice_stack(),
        data.store,
        data.advice_map
    );
    test.execute().expect_err(
        "verifier must reject a non-identity proof order when two scatter destinations are swapped",
    );
}

fn verifier_test(data: VerifierData) -> Test {
    let source = vm_verify_proof_program();
    build_test!(
        source.as_str(),
        &data.initial_stack(),
        data.advice_stack(),
        data.store,
        data.advice_map
    )
}

fn assert_recursive_verifier_rejects(data: VerifierData, message: &str) {
    assert!(verifier_test(data).execute_for_output().is_err(), "{message}");
}

// Helper function for recursive verification
pub fn generate_recursive_verifier_data(
    source: &str,
    stack_inputs: Vec<u64>,
    kernel: Option<&str>,
) -> VerifierData {
    let (proof, claim) = generate_recursive_proof(source, stack_inputs, kernel);
    generate_advice_inputs(vm_verify_proof_root(), &proof, &claim).unwrap()
}

fn generate_recursive_proof(
    source: &str,
    stack_inputs: Vec<u64>,
    kernel: Option<&str>,
) -> (ExecutionProof, ExecutionClaim) {
    let (program, kernel_lib) = {
        match kernel {
            Some(kernel) => {
                let context = miden_assembly::testing::TestContext::new();
                let kernel = context.parse_kernel(source_file!(&context, kernel)).unwrap();
                let kernel_lib = Assembler::new(context.source_manager())
                    .assemble_kernel("kernel", kernel, None)
                    .map(Arc::<Package>::from)
                    .unwrap();
                let assembler =
                    Assembler::with_kernel(context.source_manager(), kernel_lib.clone()).unwrap();
                let program: Program =
                    assembler.assemble_program("program", source).unwrap().unwrap_program();
                (program, Some(kernel_lib))
            },
            None => {
                let program: Program = Assembler::default()
                    .assemble_program("program", source)
                    .unwrap()
                    .unwrap_program();
                (program, None)
            },
        }
    };
    let stack_inputs = stack_inputs_from_ints(stack_inputs);
    let advice_inputs = AdviceInputs::default();
    let mut host = DefaultHost::default();
    if let Some(ref kernel_lib) = kernel_lib {
        host.load_library(kernel_lib.mast_forest()).unwrap();
    }

    let processor =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, ExecutionOptions::default())
            .unwrap();
    let witness = processor.execute_for_proving_sync(&program, &mut host).unwrap();
    let stack_outputs = *witness.claim().stack_outputs();
    let proof = Prover::new().with_hash_fn(HashFunction::Eidos).prove(witness).unwrap();

    let program_info = ProgramInfo::from(program);
    let claim = ExecutionClaim::from_program_info(program_info, stack_inputs, stack_outputs);

    (proof, claim)
}

/// Returns the MAST root used to identify `sys::vm::verify_proof` in proof-request keys.
///
/// Operators obtain it through `CoreLibrary::vm_recursive_verifier_root`. Consumers obtain the
/// same value in MASM with `procref.vm::verify_proof`; the root belongs to the procedure itself and
/// does not depend on the program that calls it.
fn vm_verify_proof_root() -> Word {
    miden_core_lib::CoreLibrary::default().vm_recursive_verifier_root()
}

/// Test helper that copies `count` felts (a multiple of 4) from advice into memory at `dst`.
pub(crate) const COPY_ADVICE_TO_MEM: &str = "
        proc copy_advice_to_mem
            dup.1 push.0 neq
            while.true
                padw adv_loadw
                dup.4 mem_storew_le dropw
                add.4
                swap sub.4 swap
                dup.1 push.0 neq
            end
            drop drop
        end
";

/// Builds the consumer program: stage the claim from the consumer's own inputs, derive its
/// commitment, fetch the proof package registered under
/// `proof_request_key(verifier_root, claim_commitment)`, verify it, compute its security level, and
/// enforce the consumer's threshold. `vm::verify_proof` contains neither the estimator nor the
/// policy.
fn request_consumer_source(bound: &str, target: u32) -> String {
    format!(
        "
        use miden::core::sys
        use miden::core::stark::security
        use miden::core::sys::vm
        use miden::core::sys::vm::claim

        {COPY_ADVICE_TO_MEM}

        begin
            # 1) Fill the canonical claim encoding into VM memory from the consumer's own inputs
            #    (the advice tape) and derive the commitment that names it.
            push.{NUM_CLAIM_ELEMENTS} push.{CONSUMER_CLAIM_PTR}
            exec.copy_advice_to_mem
            push.{CONSUMER_CLAIM_PTR} exec.claim::claim_commitment
            # => [CLAIM_COMMITMENT]

            # 2) Fetch the registered proof package by content: request keys name
            #    vm::verify_proof's root, derived in-VM via procref.
            dupw
            procref.vm::verify_proof exec.sys::build_proof_request_key
            adv.push_mapval dropw
            # => [CLAIM_COMMITMENT]

            # 3) Verify the claim; vm::verify_proof returns the common security descriptor followed
            #    by the deferred obligation.
            exec.vm::verify_proof
            # => [security_descriptor(12), D]

            # 4) Compute the security level and enforce the consumer's threshold.
            exec.security::compute_{bound}_security_level
            # => [level, D]
            u32lt.{target} assertz.err=\"proof security level is below the accepted target\"
            # => [D]
            exec.sys::truncate_stack
        end
        "
    )
}

/// The end-to-end guarantee of fetching by content: a proof fetched via `proof_request_key` and
/// `adv.push_mapval` verifies when it matches the consumer's claim, and is rejected when it
/// does not. No separate binding check is needed for the fetched proof package.
#[test]
fn request_flow_binds_proof_to_claim() {
    use miden_core::program::proof_request_key;

    let intended = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);

    let source = request_consumer_source("conjectured", 96);
    let entry = |proof_stream: &[u64]| -> (Word, Vec<Felt>) {
        let felts: Vec<Felt> = proof_stream.iter().map(|&v| Felt::new_unchecked(v)).collect();
        (proof_request_key(vm_verify_proof_root(), intended.claim_commitment), felts)
    };

    // Control: the intended proof, registered under its key, verifies.
    let (k, v) = entry(&intended.proof_stream);
    let mut advice_map = intended.advice_map.clone();
    advice_map.push((k, v));
    // Both estimators consume the same authenticated descriptor without disturbing the
    // deferred obligation. The proven threshold reflects the weaker proven query bound.
    for consumer in [&source, &request_consumer_source("proven", 56)] {
        let ok = build_test!(
            consumer.as_str(),
            &[],
            &intended.claim_advice,
            intended.store.clone(),
            advice_map.clone()
        );
        ok.execute_for_output()
            .expect("the matching proof must satisfy either security policy");
    }

    // Substitution: a different claim's proof under the same key fails against the consumer's
    // claim — the advice provider cannot pass off another proof. The intended claim's own
    // content-addressed entries stay available so the kernel-witness fetch succeeds and
    // rejection happens in verification, not because of a missing key.
    let other =
        generate_recursive_verifier_data(EXAMPLE_LOG_DEFERRED, log_deferred_stack_inputs(), None);
    let (k, v) = entry(&other.proof_stream);
    let mut advice_map = other.advice_map.clone();
    advice_map.extend(intended.advice_map.iter().cloned());
    advice_map.push((k, v));
    let bad = build_test!(source.as_str(), &[], &intended.claim_advice, other.store, advice_map);
    assert!(
        bad.execute_for_output().is_err(),
        "a proof for a different claim must be rejected by verification"
    );
}

/// Two independently proven executions of one program (distinct stack i/o) verified inside a
/// single consumer program — each proof is registered
/// under `proof_request_key(verifier_root, claim_commitment)` and fetched by content, independent
/// of its position in the advice. The consumer stages each claim from its own inputs and derives
/// the commitment that names the claim and addresses its proof entry, so passing requires the
/// in-VM claim-commitment, kernel-commitment, and request-key derivations to match their native
/// mirrors (a mismatch is a missing advice-map key).
#[test]
fn stark_verifier_e2f4_request_multi_proof() {
    use miden_core::program::proof_request_key;
    use miden_utils_testing::crypto::MerkleStore;

    let mut inputs = fib_stack_inputs();
    let tx0 = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, inputs.clone(), None);
    inputs[13] = 7; // distinct claim: same program, different stack inputs
    let tx1 = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, inputs, None);

    // One advice provider for both proofs: the tape carries the claims from which the consumer
    // derives the commitments. Claim preimages, proof streams, query rows, and kernel witnesses
    // are content-addressed in the advice map.
    let verifier_root = vm_verify_proof_root();
    let mut tape = Vec::new();
    let mut store = MerkleStore::new();
    let mut advice_map = Vec::new();
    for tx in [&tx0, &tx1] {
        tape.extend(tx.claim_advice.iter().copied());
        store.extend(tx.store.inner_nodes());
        advice_map.extend(tx.advice_map.iter().cloned());
        let stream: Vec<Felt> = tx.proof_stream.iter().map(|&v| Felt::new_unchecked(v)).collect();
        advice_map.push((proof_request_key(verifier_root, tx.claim_commitment), stream));
    }

    let source = format!(
        "
        use miden::core::sys
        use miden::core::stark::security
        use miden::core::sys::vm
        use miden::core::sys::vm::claim

        {COPY_ADVICE_TO_MEM}

        proc verify_one_claim
            # Per claim: stage the fields from the consumer's own inputs, derive the
            # commitment that names the claim, fetch and verify the proof package it
            # addresses, then compute the security level and enforce the acceptance threshold.
            push.{NUM_CLAIM_ELEMENTS} push.{CONSUMER_CLAIM_PTR} exec.copy_advice_to_mem
            push.{CONSUMER_CLAIM_PTR} exec.claim::claim_commitment # => [CLAIM_COMMITMENT]
            dupw
            procref.vm::verify_proof exec.sys::build_proof_request_key
            adv.push_mapval dropw                        # => [CLAIM_COMMITMENT]
            exec.vm::verify_proof                        # => [security_descriptor(12), D]
            exec.security::compute_conjectured_security_level # => [level, D]
            u32lt.96 assertz.err=\"proof security level is below the accepted target\"
            # => [D]
        end

        begin
            exec.verify_one_claim dropw
            exec.verify_one_claim dropw
            exec.sys::truncate_stack
        end
        "
    );

    let test = build_test!(source.as_str(), &[], &tape, store, advice_map);
    test.execute_for_output().expect("both content-addressed proofs must verify");
}

fn vm_verify_proof_program() -> String {
    format!(
        "
        use miden::core::sys
        use miden::core::sys::vm

        const VERIFIER_RETURN = event(\"{VERIFIER_RETURN}\")

        begin
            exec.vm::verify_proof
            # => [security_descriptor(12), D, ...]
            trace.VERIFIER_RETURN
            exec.sys::truncate_stack
        end
        "
    )
}

fn run_recursive_verifier(data: &VerifierData) -> Vec<usize> {
    use miden_air::vm::security;

    let source = vm_verify_proof_program();
    let mut initial_stack = data.initial_stack().to_vec();
    initial_stack.extend(CALLER_WORD);
    let verifier_stack = VerifierStack::default();
    let test = build_test!(
        source.as_str(),
        &initial_stack,
        data.advice_stack(),
        data.store.clone(),
        data.advice_map.clone()
    )
    .with_trace_handler(VERIFIER_RETURN, verifier_stack.clone());
    let order = ace_read_check::execute_and_check(&test, &data.proof_stream, &data.claim_advice);

    // Pin the full common descriptor and deferred root so any value or ordering drift is caught
    // across every end-to-end configuration.
    let params = config::pcs_params();
    let height_start = 4 + WORD_SIZE;
    let log_max_height = data.proof_stream[height_start..height_start + MIDEN_AIR_COUNT - 1]
        .iter()
        .copied()
        .chain([u64::from(AND8_LOOKUP_LOG_HEIGHT)])
        .max()
        .expect("the MVM relation has AIR instances");
    let kernel_commitment = claim_kernel_commitment(data);
    let num_kernel_procedures = data
        .advice_map
        .iter()
        .find(|(key, _)| *key == kernel_commitment)
        .map(|(_, values)| values.len() / WORD_SIZE)
        .expect("the authenticated kernel witness must be present");

    let mut expected = vec![
        u64::from(security::LOOKUP_POW_BITS),
        u64::from(security::AIR_SHAPE.num_composed_constraints),
        u64::from(security::AIR_SHAPE.max_constraint_degree),
        u64::from(security::AIR_SHAPE.num_deep_terms.unwrap()),
        u64::from(security::LOOKUP_SHAPE.max_message_width),
        u64::from(security::CORE_BOUNDARY_LOOKUP_TERMS) + num_kernel_procedures as u64,
        u64::from(security::LOOKUP_SHAPE.fractions_per_row),
        log_max_height,
        params.num_queries() as u64,
        params.query_pow_bits() as u64,
        params.deep_pow_bits() as u64,
        params.folding_pow_bits() as u64,
    ];
    expected.extend_from_slice(&data.proof_stream[4..4 + WORD_SIZE]);
    verifier_stack.assert_outputs_and_caller(&expected);
    order
}

/// Derives the expected proof order from the log heights carried in the proof stream.
///
/// Proof-stream layout: 4 security parameters, the 4-felt deferred root, then the three
/// execution-dependent log heights (the And8Lookup height is verifier-fixed).
fn expected_order_from_shape(data: &VerifierData) -> Vec<usize> {
    vm_scatter_bench::proof_order(&[
        data.proof_stream[8],
        data.proof_stream[9],
        data.proof_stream[10],
        u64::from(AND8_LOOKUP_LOG_HEIGHT),
    ])
}

/// Each of the four security parameters (num_queries, query_pow_bits, deep_pow_bits,
/// folding_pow_bits) is absorbed into the Fiat-Shamir transcript, so forging any one of them in
/// the proof stream diverges the transcript and fails verification. They are the first four
/// advice values `vm::verify_proof` reads, i.e. `proof_stream[0..4]`.
#[test]
fn each_security_parameter_is_transcript_bound() {
    let base = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);
    for param in 0usize..4 {
        let mut data = base.clone();
        // Forge the parameter downward. In particular, the proof's original PoW nonces satisfy
        // the weaker targets, so rejection cannot be explained solely by demanding more work;
        // the changed transcript/verification schedule must invalidate the proof.
        data.proof_stream[param] -= 1;
        let test = verifier_test(data);
        expect_assert_error_message!(test);
    }
}

/// The fetched kernel digests must hash to the claim's K before the outer-LogUp fold uses them.
/// Check the explicit authentication failure because the later boundary check also rejects
/// tampered digests.
#[test]
fn tampered_kernel_witness_is_rejected() {
    let mut data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        fib_stack_inputs(),
        Some(KERNEL_EVEN_NUM_PROC),
    );
    let k = claim_kernel_commitment(&data);
    let witness = advice_map_value_mut(&mut data, k);
    // Flip one felt of the first digest while preserving the witness length.
    witness[0] = Felt::new_unchecked(witness[0].as_canonical_u64() ^ 1);

    let test = verifier_test(data);
    expect_assert_error_code_from_msg!(
        test,
        "fetched kernel digests do not hash to the claim's kernel commitment"
    );
}

/// `vm::verify_proof` derives the kernel procedure count from the advice-map value length and
/// rejects a witness containing more than `KernelDescriptor::MAX_NUM_PROCEDURES` digests before
/// copying it.
#[test]
fn vm_verify_proof_rejects_oversized_kernel_witness() {
    let mut data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        fib_stack_inputs(),
        Some(KERNEL_EVEN_NUM_PROC),
    );
    let k = claim_kernel_commitment(&data);
    *advice_map_value_mut(&mut data, k) =
        vec![Felt::ZERO; (KernelDescriptor::MAX_NUM_PROCEDURES + 1) * WORD_SIZE];

    let test = verifier_test(data);
    expect_assert_error_code_from_msg!(
        test,
        "number of kernel procedures exceeds KernelDescriptor::MAX_NUM_PROCEDURES"
    );
}

/// A kernel witness is a list of four-felt procedure digests.
#[test]
fn vm_verify_proof_rejects_misaligned_kernel_witness() {
    let mut data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        fib_stack_inputs(),
        Some(KERNEL_EVEN_NUM_PROC),
    );
    let k = claim_kernel_commitment(&data);
    advice_map_value_mut(&mut data, k).push(Felt::ZERO);

    let test = verifier_test(data);
    expect_assert_error_code_from_msg!(test, "kernel witness length must be word-aligned");
}

/// The claim preimage is untrusted advice and must match the caller-provided commitment.
#[test]
fn tampered_claim_preimage_is_rejected() {
    let mut data = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);
    let claim_commitment = data.claim_commitment;
    let preimage = advice_map_value_mut(&mut data, claim_commitment);
    preimage[0] = Felt::new_unchecked(preimage[0].as_canonical_u64() ^ 1);

    let test = verifier_test(data);
    expect_assert_error_code_from_msg!(test, "claim preimage commitment does not match");
}

/// The advice-map value under the claim commitment must use the canonical 40-felt encoding.
#[rstest]
#[case(NUM_CLAIM_ELEMENTS - 1)]
#[case(NUM_CLAIM_ELEMENTS + 1)]
fn malformed_claim_preimage_length_is_rejected(#[case] len: usize) {
    let mut data = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);
    let claim_commitment = data.claim_commitment;
    let preimage = advice_map_value_mut(&mut data, claim_commitment);
    preimage.resize(len, Felt::ZERO);

    let test = verifier_test(data);
    expect_assert_error_code_from_msg!(test, "claim preimage has a non-canonical length");
}

/// The claim's kernel commitment K, read from felts [4, 8) of the canonical claim encoding.
fn claim_kernel_commitment(data: &VerifierData) -> Word {
    Word::new([
        Felt::new_unchecked(data.claim_advice[4]),
        Felt::new_unchecked(data.claim_advice[5]),
        Felt::new_unchecked(data.claim_advice[6]),
        Felt::new_unchecked(data.claim_advice[7]),
    ])
}

/// Mutable reference to the advice-map value stored under `key`.
fn advice_map_value_mut(data: &mut VerifierData, key: Word) -> &mut Vec<Felt> {
    let entry = data
        .advice_map
        .iter_mut()
        .find(|(k, _)| *k == key)
        .expect("advice map has an entry under the requested key");
    &mut entry.1
}

/// Advice-map key the recursive verifier fetches the ACE circuit stream under.
///
/// One circuit serves every proof order, so this is the canonical circuit's own digest — the
/// same value `build_merkle_data` keys the advice entry with and the loader pins the stream to.
fn recursive_circuit_key() -> Word {
    miden_vm_stark::setup::ace::shared_recursive_circuit().commitment
}

// EXAMPLE PROGRAMS
// ================================================================================================

const EXAMPLE_FIB_SMALL: &str = "begin
        repeat.320
            swap dup.1 add
        end
        u32split drop
    end";

const EXAMPLE_FIB_LARGE: &str = "begin
        repeat.400
            swap dup.1 add
        end
        u32split drop
    end";

/// Tiny program where every AIR lands at its minimum height.
const EXAMPLE_EQUAL_HEIGHTS: &str = "begin push.1 drop end";

/// Like EXAMPLE_FIB_SMALL but with a syscall, for kernel-aware tests.
const EXAMPLE_FIB_KERNEL_SMALL: &str = "begin
        syscall.foo
        repeat.320
            swap dup.1 add
        end
        u32split drop
    end";

/// Like EXAMPLE_FIB_LARGE but with a syscall, for kernel-aware flipped-order tests.
const EXAMPLE_FIB_KERNEL_LARGE: &str = "begin
        syscall.foo
        repeat.400
            swap dup.1 add
        end
        u32split drop
    end";

const EXAMPLE_LOG_DEFERRED: &str = "begin
        log_deferred
        dropw
    end";

fn fib_stack_inputs() -> Vec<u64> {
    let mut inputs = vec![0_u64; 16];
    inputs[15] = 0;
    inputs[14] = 1;
    inputs
}

fn log_deferred_stack_inputs() -> Vec<u64> {
    // TRUE_DIGEST is the zero word and must occupy the top four positions. A nonzero first tail
    // element makes the post-`dropw` output visibly distinct from an empty stack.
    let mut inputs = vec![0_u64; 16];
    inputs[4] = 7;
    inputs
}

fn max_kernel_source() -> String {
    let mut source = KERNEL_SINGLE_PROC.to_owned();
    for i in 1..KernelDescriptor::MAX_NUM_PROCEDURES {
        write!(source, "\npub proc unused_{i}\n    push.{i} drop\nend").unwrap();
    }
    source
}

// CONSTANTS
// ===============================================================================================

/// The verifier-fixed And8Lookup log trace height (the full byte-pair table).
const AND8_LOOKUP_LOG_HEIGHT: u8 = 16;

/// Memory used by test consumers while deriving a claim commitment.
const CONSUMER_CLAIM_PTR: u64 = 4096;

const KERNEL_SINGLE_PROC: &str = r#"
        pub proc foo
            add
        end"#;

const KERNEL_EVEN_NUM_PROC: &str = r#"
        pub proc foo
            add
        end
        pub proc bar
            div
        end"#;

const KERNEL_ODD_NUM_PROC: &str = r#"
        pub proc foo
            add
        end
        pub proc bar
            div
        end
        pub proc baz
            mul
        end"#;
