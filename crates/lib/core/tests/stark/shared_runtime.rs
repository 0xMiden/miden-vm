//! Same-context lifecycle and independent parameter/assembled identity oracles.
use std::fmt::Write as _;

use miden_air_source::codegen::{constraints, masm_renderer::V1RenderInput, precompile};
use miden_core::{
    deferred::PvmAirVariant,
    serde::{Deserializable, Serializable},
};
use miden_core_lib::CoreLibrary;

// Deliberately independent of RuntimePlan and its descriptor constants/table.
const BASE: u32 = 3_223_324_000;
const LEN: usize = 80;

fn expected(i: &V1RenderInput) -> ([u64; LEN], Vec<(usize, String)>) {
    let vm = i.relation.is_vm();
    let n = i.geometry.main.len() as u32;
    let r = &i.read_layout;
    let read_base = if vm {
        3_225_419_776 - 2 * i.counts.num_public as u32
    } else {
        3_225_432_064
    };
    let ptr = |slot: usize| (read_base + 2 * slot as u32) as u64;
    let row_width = (i.geometry.preprocessed.iter().sum::<usize>()
        + i.geometry.main.iter().sum::<usize>()
        + i.geometry.aux_coordinates.iter().sum::<usize>()
        + i.geometry.quotient_coordinates) as u32;
    let stream = ptr(r.total_slots) as u32;
    let gamma = if vm {
        3_223_322_780
    } else {
        stream + i.circuit.stream_felts
    };
    let total = if vm { 3_223_322_784 } else { gamma + 4 };
    let query = if vm { 3_238_002_688 } else { total + 4 };
    let setup = if vm { 3_223_322_740 } else { query + row_width };
    let scatter = if vm { 3_223_323_864 } else { setup + 4 };
    let positions = if vm { 3_223_323_908 } else { scatter + 96 };
    let ids = if vm {
        3_223_323_912
    } else {
        positions + n.next_multiple_of(4)
    };
    let mut v = [0; LEN];
    v[..20].copy_from_slice(&[
        ptr(r.aux_rand_beta),
        ptr(r.aux_bus_boundary),
        ptr(r.alpha),
        stream as u64,
        (i.circuit.stream_felts / 8) as u64,
        i.circuit.encoded_read_count as u64,
        i.circuit.eval_gate_count as u64,
        i.circuit.max_cycle_log as u64,
        n as u64,
        2 * (r.multi_air_fold_coefficient_0 - r.alpha) as u64,
        scatter as u64,
        positions as u64,
        ids as u64,
        2 * row_width as u64,
        gamma as u64,
        total as u64,
        if vm { 0 } else { ptr(0) },
        setup as u64,
        19,
        (12 + n as u64) % 8,
    ]);
    v[20..24].copy_from_slice(&i.circuit.stream_initial_cv);
    v[24..28].copy_from_slice(&i.circuit.digest);
    v[28..31].copy_from_slice(&[
        i.quotient.shift_ratio,
        i.quotient.first_shift,
        i.quotient.first_weight,
    ]);
    for (k, cv) in i.query_leaf_initial_cvs.iter().enumerate() {
        v[32 + 4 * k..36 + 4 * k].copy_from_slice(cv);
    }
    v[72] = (2 * row_width - 2 * i.geometry.quotient_coordinates as u32) as u64;
    v[73] = ptr(r.multi_air_fold_coefficient_0);
    let widths = [
        i.geometry.preprocessed.iter().sum::<usize>(),
        i.geometry.main.iter().sum(),
        i.geometry.aux_coordinates.iter().sum(),
        i.geometry.quotient_coordinates,
    ];
    let mut refs: Vec<_> = widths
        .iter()
        .enumerate()
        .map(|(k, w)| (48 + 4 * k, format!("base_{}", w / 8)))
        .collect();
    refs.push((64, format!("ext_{}", widths[0] / 4)));
    refs.push((68, format!("ext_{}", widths[3] / 4)));
    refs.push((76, format!("ace_{}", i.circuit.stream_felts / 8)));
    (v, refs)
}

#[test]
fn trusted_parameters_completely_initialize_each_same_context_transition() {
    let core = CoreLibrary::default();
    let mut body = String::new();
    // Include every mask, same-count different-width substitutions, and VM/PVM transitions.
    let transitions = [
        Some(7),
        Some(0),
        None,
        Some(2),
        Some(4),
        Some(1),
        Some(3),
        Some(5),
        Some(6),
        None,
        Some(7),
    ];
    for mask in transitions {
        let input = match mask {
            None => constraints::compile(constraints::accepted_setup_commitments()).masm,
            Some(mask) => {
                precompile::compile_variant(
                    precompile::accepted_setup_commitment(),
                    PvmAirVariant::from_u8(mask).unwrap(),
                )
                .masm
            },
        };
        let path = match mask {
            None => "vm".to_string(),
            Some(7) => "pvm".to_string(),
            Some(m) => format!("pvm::v{m}"),
        };
        // The VM stager derives preprocessed depth from its actual staged And8 height.
        writeln!(body, "push.16 mem_store.3223322747").unwrap();
        for addr in BASE - 1..=BASE + LEN as u32 {
            writeln!(body, "push.999 mem_store.{addr}").unwrap();
        }
        writeln!(body,"push.123 mem_store.3223322767\nexec.::miden::core::sys::{path}::layout::stage_verifier_parameters").unwrap();
        let (mut values, refs) = expected(&input);
        for (offset, name) in refs {
            let root = core
                .package()
                .get_procedure_root_by_path(
                    format!("::miden::core::sys::verifier::pipes::{name}").as_str(),
                )
                .unwrap();
            let limbs: [u64; 4] = root.into();
            values[offset..offset + 4].copy_from_slice(&limbs);
        }
        for (offset, value) in values.into_iter().enumerate() {
            writeln!(body, "mem_load.{} push.{value} assert_eq", BASE + offset as u32).unwrap();
        }
        writeln!(body,"mem_load.{} push.999 assert_eq\nmem_load.{} push.999 assert_eq\nmem_load.3223322767 push.123 assert_eq",BASE-1,BASE+LEN as u32).unwrap();
    }
    let source = format!("begin\n{body}\nend");
    let sentinels = [41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56];
    let (output, _) = build_test!(&source, &sentinels).execute_for_output().unwrap();
    let (control, _) = build_test!("begin nop end", &sentinels).execute_for_output().unwrap();
    assert_eq!(output.stack.get_num_elements(16), control.stack.get_num_elements(16));
}

#[test]
fn assembled_verifier_identity_and_serialized_measures() {
    let core = CoreLibrary::default();
    println!(
        "current VM {:?}; PVM {:?}; package bytes {}; MAST bytes {}",
        core.vm_recursive_verifier_root(),
        core.pvm_recursive_verifier_root(),
        CoreLibrary::SERIALIZED.len(),
        core.mast_forest().to_bytes().len()
    );
    if let Ok(path) = std::env::var("VERIFIER_SHARING_BASELINE") {
        let bytes = std::fs::read(path).unwrap();
        let old = miden_mast_package::Package::read_from_bytes(&bytes).unwrap();
        println!(
            "parent package bytes {}; MAST bytes {}",
            bytes.len(),
            old.mast_forest().to_bytes().len()
        );
    }
    assert_eq!(core.vm_recursive_verifier_root(), miden_core::proof::CURRENT_VM_VERIFIER_ROOT);
    assert_eq!(core.pvm_recursive_verifier_root(), miden_core::proof::CURRENT_PVM_VERIFIER_ROOT);
}

#[test]
fn shared_vm_runtime_cost_is_bounded() {
    let data = super::generate_recursive_verifier_data(
        super::EXAMPLE_FIB_SMALL,
        super::fib_stack_inputs(),
        None,
    );
    let source = "use miden::core::sys::vm\nuse miden::core::sys\nbegin exec.vm::verify_proof exec.sys::truncate_stack end";
    let test = build_test!(
        source,
        &data.initial_stack(),
        data.advice_stack(),
        data.store.clone(),
        data.advice_map
    );
    let trace = test.execute().unwrap();
    let rows = trace.trace_len_summary().core_rows();
    println!("shared VM: {:?}", trace.trace_len_summary());
    assert!(rows < 70_000, "VM recursion must retain a meaningful fixed bound");
    if let Ok(path) = std::env::var("VERIFIER_SHARING_BASELINE") {
        let bytes = std::fs::read(path).unwrap();
        let mut parent = test;
        parent.libraries[0] =
            std::sync::Arc::new(miden_mast_package::Package::read_from_bytes(&bytes).unwrap());
        let old = parent.execute().unwrap();
        let old_rows = old.trace_len_summary().core_rows();
        println!(
            "parent VM on the identical proof: {:?}; added core rows {}",
            old.trace_len_summary(),
            rows as i64 - old_rows as i64
        );
        assert!(rows < old_rows + 4_000, "sharing cost must remain modest on the same proof");
    }
}
