use super::super::expect_panic;
use super::{proof_order::ProofOrderPlan, *};

fn proof_config(n: usize, word_load: bool, word_store: bool) -> ProofOrderConfig {
    ProofOrderConfig {
        num_airs: n,
        heights: PointerRef::Absolute(2000),
        positions: PointerRef::Absolute(2100),
        ids: PointerRef::Absolute(2120),
        word_load_heights: word_load,
        word_store_ids: word_store,
        procedure_name: "stage_proof_order_maps".into(),
        public: false,
    }
}

#[test]
fn proof_inputs_reject_bad_names_ranges_alignment_and_overlap() {
    let mut c = proof_config(4, true, true);
    c.procedure_name = "stage\nend".into();
    expect_panic(|| render_proof_order(&c));
    c = proof_config(3, true, true);
    expect_panic(|| render_proof_order(&c));
    c = proof_config(4, true, true);
    c.heights = PointerRef::Absolute(2001);
    expect_panic(|| render_proof_order(&c));
    c = proof_config(4, false, true);
    c.ids = PointerRef::Absolute(2121);
    expect_panic(|| render_proof_order(&c));
    c = proof_config(12, false, false);
    c.positions = PointerRef::Absolute(2004);
    expect_panic(|| render_proof_order(&c));
    c = proof_config(12, false, false);
    c.ids = PointerRef::Absolute(u32::MAX - 4);
    expect_panic(|| render_proof_order(&c));
    for n in [0, 1, 13, usize::MAX] {
        expect_panic(|| render_proof_order(&proof_config(n, false, false)));
    }
}

#[test]
fn ood_presentation_keeps_empty_sole_full_cases_and_deduplicates_helpers() {
    let scatter = OodScatterPlan::new(&[0, 0], &[4, 4], &[0, 0], 4);
    let proof = ProofOrderPlan::new(&proof_config(2, false, false));
    let plan = OodPlan::new(
        &scatter,
        MemoryRegion {
            base: 2200,
            len_felts: scatter.table_felts() as u32,
        },
        MemoryRegion { base: 2100, len_felts: 2 },
        MemoryRegion { base: 2120, len_felts: 2 },
        proof,
    );
    assert_eq!(plan.row_felts, 24);
    assert_eq!(plan.helpers.iter().map(|h| h.blocks).collect::<Vec<_>>(), [1]);
    assert_eq!(plan.row_groups.len(), 2);
    assert!(matches!(&plan.row_groups[0], ood::RowGroup::Full { calls } if calls.len() == 2));
    assert!(matches!(
        &plan.row_groups[1],
        ood::RowGroup::Sole { destination: 16, blocks: 1 }
    ));
    assert_eq!(plan.air_dispatch[0].entries[0].destination, 0);
    assert_eq!(plan.air_dispatch[1].entries[0].destination, 8);
}

fn vm_render_input() -> V1RenderInput {
    use super::super::constraints;

    constraints::compile(constraints::accepted_setup_commitments()).masm
}

#[test]
fn fold_slots_cannot_overlap_auxiliary_inputs_or_escape_exact_aligned_tail() {
    let valid = vm_render_input();
    prepare_v1(valid.clone());
    for fold_start in [
        valid.read_layout.alpha,
        valid.read_layout.multi_air_fold_coefficient_0 - 1,
        valid.read_layout.multi_air_fold_coefficient_0 + 1,
    ] {
        let mut malformed = valid.clone();
        malformed.read_layout.multi_air_fold_coefficient_0 = fold_start;
        expect_panic(|| prepare_v1(malformed));
    }
    let total = valid.read_layout.total_slots;
    for total_slots in [total - 3, total - 2, total - 1, total + 1, total + 4, usize::MAX] {
        let mut malformed = valid.clone();
        malformed.read_layout.total_slots = total_slots;
        expect_panic(|| prepare_v1(malformed));
    }
}

#[test]
fn circuit_shape_and_external_read_slots_must_agree() {
    let valid = vm_render_input();
    prepare_v1(valid.clone());
    let mut malformed = valid.clone();
    malformed.circuit.encoded_read_count = 1;
    expect_panic(|| prepare_v1(malformed));
    let mut malformed = valid.clone();
    malformed.circuit.eval_gate_count = 1;
    expect_panic(|| prepare_v1(malformed));
    let mut malformed = valid.clone();
    malformed.circuit.stream_felts += 8;
    expect_panic(|| prepare_v1(malformed));
    let mut malformed = valid.clone();
    malformed.circuit.encoded_read_count += 2;
    expect_panic(|| prepare_v1(malformed));
    let mut malformed = valid;
    malformed.circuit.eval_gate_count += 4;
    expect_panic(|| prepare_v1(malformed));
}

#[test]
fn pvm_glue_keeps_legacy_presentation_and_exact_transcript_counts() {
    use super::super::precompile;
    let compiled = precompile::compile(precompile::accepted_setup_commitment());
    let plan = prepare_v1(compiled.masm);
    let g = plan.pvm_glue.unwrap();
    assert_eq!(
        g.airs.iter().map(|air| air.height).collect::<Vec<_>>(),
        [
            HeightRule::Minimum(5),
            HeightRule::Minimum(5),
            HeightRule::Minimum(7),
            HeightRule::Fixed(16),
            HeightRule::Minimum(1),
            HeightRule::Minimum(3),
            HeightRule::Minimum(1),
            HeightRule::Minimum(1),
            HeightRule::Minimum(2),
            HeightRule::Minimum(1),
            HeightRule::Minimum(7),
            HeightRule::Minimum(7),
        ]
    );
    assert_eq!(
        g.uints.iter().map(|msg| msg.ptr).collect::<Vec<_>>(),
        [1, 2, 3, 4, 5, 6, 14, 15, 8, 9, 10, 11, 12, 13, 16, 17]
    );
    assert_eq!(
        g.uints.iter().map(|msg| msg.repeat_count).collect::<Vec<_>>(),
        [8, 6, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!((g.statement_felts, g.statement_and_shape_felts), (7, 20));
    assert_eq!((g.setup_buffered, g.shape_buffered, g.aux_felts, g.aux_buffered), (4, 0, 28, 4));
}

#[test]
fn pvm_glue_rejects_changed_authored_shapes_and_boundary_slots() {
    use super::super::precompile;
    let compiled = precompile::compile(precompile::accepted_setup_commitment());
    let valid = compiled.masm;
    for case in 0..6 {
        let mut input = valid.clone();
        let RelationInput::Pvm { glue, .. } = &mut input.relation else {
            unreachable!()
        };
        match case {
            0 => glue.airs[1].boundary_slot = glue.airs[0].boundary_slot,
            1 => glue.num_public_values += 1,
            2 => glue.max_aux_inputs = 1,
            3 => {
                glue.airs.pop();
            },
            4 => input.counts.num_aux_boundary += 1,
            _ => glue.max_message_width += 1,
        }
        assert!(
            std::panic::catch_unwind(|| { prepare_v1(input) }).is_err(),
            "authored shape mutation {case} must panic"
        );
    }
}

#[test]
fn trusted_parameters_reject_overlapping_and_overflowing_relation_regions() {
    let mut vm = vm_render_input();
    if let RelationInput::Vm(a) = &mut vm.relation {
        a.read_beta_anchor = PARAMETERS_PTR + 2 * vm.counts.num_public as u32;
    }
    expect_panic(|| prepare_v1(vm));
    let valid =
        super::super::precompile::compile(super::super::precompile::accepted_setup_commitment())
            .masm;
    let mut pvm = valid.clone();
    if let RelationInput::Pvm { abi: a, .. } = &mut pvm.relation {
        a.read_base = PARAMETERS_PTR;
    }
    expect_panic(|| prepare_v1(pvm));
    let mut pvm = valid;
    if let RelationInput::Pvm { abi: a, .. } = &mut pvm.relation {
        a.read_base = u32::MAX - 7;
    }
    expect_panic(|| prepare_v1(pvm));
}

#[test]
fn shared_universe_is_independent_of_relation_render_order() {
    let mut plans = std::vec![prepare_v1(vm_render_input())];
    for variant in miden_core::deferred::PvmAirVariant::ALL_VARIANTS {
        plans.push(prepare_v1(
            super::super::precompile::compile_variant(
                super::super::precompile::accepted_setup_commitment(),
                variant,
            )
            .masm,
        ));
    }
    let forward = shared::render(&plans);
    assert_eq!(forward.len(), 9);
    assert!(forward.iter().all(|file| file.ownership == ArtifactOwnership::Managed));
    plans.reverse();
    assert_eq!(forward, shared::render(&plans));
}

#[test]
fn scatter_plan_rejects_partial_groups_for_both_relations() {
    for n in [4, 12] {
        let scatter = |preprocessed: &[usize]| {
            OodScatterPlan::new(preprocessed, &std::vec![8; n], &std::vec![8; n], 8)
        };
        let mut sole = std::vec![0; n];
        sole[3] = 16;
        scatter(&sole);
        scatter(&std::vec![16; n]);
        sole[0] = 16;
        let error = expect_panic(|| scatter(&sole));
        assert!(
            error.contains(&std::format!("preprocessed commitment group is occupied by 2 of {n}"))
        );
    }
}

#[test]
fn actual_layout_rejects_stream_and_scatter_reservation_overflow() {
    let valid = vm_render_input();
    let layout = prepare_v1(valid.clone()).layout;
    let stream_end = layout.ace_circuit_stream_ptr + valid.circuit.stream_felts;
    for (end, accepted) in [
        (stream_end, true),
        (stream_end - 1, false),
        (layout.ace_circuit_stream_ptr - 1, false),
    ] {
        let mut input = valid.clone();
        if let RelationInput::Vm(a) = &mut input.relation {
            a.next_region_start = end;
        }
        let result = std::panic::catch_unwind(|| prepare_v1(input));
        assert_eq!(result.is_ok(), accepted);
    }
    let mut pvm =
        super::super::precompile::compile(super::super::precompile::accepted_setup_commitment())
            .masm;
    if let RelationInput::Pvm { abi: a, .. } = &mut pvm.relation {
        a.scatter_reserve_felts = 84;
    }
    let error = expect_panic(|| prepare_v1(pvm));
    assert!(error.contains("scatter scratch and proof-order maps overlap"));
}
