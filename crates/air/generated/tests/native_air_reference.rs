//! Compatibility checks against frozen AIR metadata and independently rebuilt protocol identities.

use miden_ace::RecursiveAceCircuit;
use miden_air_definitions::{precompiles, vm};
use miden_constraint_compiler::testing::constraint_degrees;
use miden_core::{Felt, field::QuadFelt};
use miden_stark::air::{self, DirectKernel, LiftedAir, MultiAir, Statement};

const HISTORICAL: &str = include_str!("fixtures/native_air_reference/reference.txt");
const NEXT_BASELINE: &str = include_str!("fixtures/native_air_reference/next.txt");

type Record = Vec<(&'static str, String)>;

fn metadata<A: LiftedAir<F = Felt>>(air: &A) -> Record {
    let spec = air.spec();
    let periods: Vec<_> = spec.periodic_columns.iter().map(Vec::len).collect();
    let [base, ext] = constraint_degrees(air);
    vec![
        (
            "shape",
            format!(
                "main:{} preprocessed:{} aux:{} public:{} challenges:{} exports:{} preprocessed-log-height:{:?}",
                spec.main_width,
                spec.preprocessed_width(),
                spec.aux_width,
                spec.num_public_values,
                spec.num_challenges,
                spec.num_exports,
                spec.preprocessed.map(|shape| shape.log_height),
            ),
        ),
        ("periods", format!("{periods:?}")),
        ("assertions", format!("base:{} ext:{}", base.len(), ext.len())),
    ]
}

struct AuthoredAirs<A>(Vec<A>);

impl<A: air::AirKernel<F = Felt>> MultiAir<Felt, QuadFelt> for AuthoredAirs<A> {
    type Air = A;

    fn airs(&self) -> &[A] {
        &self.0
    }
}

/// Rebuild setup through source factories, using the existing canonical PCS presets.
fn setup_record<A: LiftedAir<F = Felt>>(
    airs: Vec<A>,
    params: miden_stark::pcs::PcsParams,
    relation: [Felt; 4],
) -> Record {
    let public = airs
        .iter()
        .enumerate()
        .filter(|(_, air)| air.spec().num_public_values != 0)
        .map(|(index, air)| (index, vec![Felt::ZERO; air.spec().num_public_values]))
        .collect();
    let kernels = airs
        .into_iter()
        .map(|air| DirectKernel::new(air).expect("authored source descriptor"))
        .collect();
    let statement = Statement::new(AuthoredAirs(kernels), public, vec![]).unwrap();
    let blake = miden_stark::config::blake3_256_config(params, relation);
    let blake_root: [u8; 32] = miden_stark::Preprocessed::build(&statement, &blake)
        .expect("authored fixed setup is valid")
        .expect("canonical source registry declares a fixed table")
        .commitment()
        .into();
    let eidos = miden_stark::config::eidos_config(
        params,
        relation,
        miden_core::program::domain::STARK_TRANSCRIPT,
    );
    let eidos_root: [u64; 4] = miden_stark::Preprocessed::build(&statement, &eidos)
        .expect("authored fixed setup is valid")
        .expect("canonical source registry declares a fixed table")
        .commitment()
        .into();
    let keccak = miden_stark::config::keccak_config(params, relation);
    let keccak_root: [u64; 4] = miden_stark::Preprocessed::build(&statement, &keccak)
        .expect("authored fixed setup is valid")
        .expect("canonical source registry declares a fixed table")
        .commitment()
        .into();
    vec![
        ("setup-blake3", format!("{blake_root:?}")),
        ("setup-eidos", format!("{eidos_root:?}")),
        ("setup-keccak", format!("{keccak_root:?}")),
    ]
}

fn protocol_record(circuit: &RecursiveAceCircuit, protocol_id: u64) -> Record {
    let relation = miden_stark::config::relation_digest(protocol_id, &circuit.commitment);
    let relation: Vec<_> = relation.iter().map(Felt::as_canonical_u64).collect();
    let ace: Vec<_> = circuit.commitment.iter().map(Felt::as_canonical_u64).collect();
    assert_eq!(circuit.instructions.len(), circuit.stream_len);
    vec![
        ("protocol-id", protocol_id.to_string()),
        ("relation", format!("{relation:?}")),
        ("ace", format!("{ace:?}")),
        (
            "ace-shape",
            format!("{:?}", (circuit.num_inputs, circuit.num_eval_gates, circuit.stream_len)),
        ),
    ]
}

fn protocols() -> [(String, Record); 2] {
    let vm_circuit = miden_air_definitions::compiler::vm::build_recursive_verifier_ace_circuit()
        .expect("authored VM ACE circuit");
    let vm_protocol_id = miden_air::vm::config::PROTOCOL_ID;
    let vm_relation = miden_stark::config::relation_digest(vm_protocol_id, &vm_circuit.commitment);
    let mut vm_record = protocol_record(&vm_circuit, vm_protocol_id);
    vm_record.extend(setup_record(
        vm::AIRS.to_vec(),
        miden_air::vm::config::pcs_params(),
        vm_relation,
    ));

    let pvm_circuit =
        miden_air_definitions::compiler::precompiles::build_pvm_recursive_verifier_ace_circuit()
            .expect("authored precompile ACE circuit");
    let pvm_protocol_id = miden_air::precompiles::policy::PROTOCOL_ID;
    let pvm_relation =
        miden_stark::config::relation_digest(pvm_protocol_id, &pvm_circuit.commitment);
    let mut pvm_record = protocol_record(&pvm_circuit, pvm_protocol_id);
    pvm_record.extend(setup_record(
        precompiles::ChipletAir::all().to_vec(),
        miden_air::precompiles::policy::precompile_pcs_params(),
        pvm_relation,
    ));
    let raw_widths: Vec<_> = precompiles::ChipletAir::all()
        .iter()
        .map(|air| {
            (
                air.spec().preprocessed_width(),
                air.spec().main_width,
                air.spec().aux_width * miden_ace::EXT_DEGREE,
            )
        })
        .collect();
    let max_log_quotient = precompiles::ChipletAir::all()
        .iter()
        .map(|air| {
            miden_stark::log_quotient_degree(
                &DirectKernel::new(air).expect("authored source descriptor"),
            )
            .expect("authored quotient allocation")
        })
        .max()
        .unwrap();
    pvm_record.push(("raw-widths", format!("{raw_widths:?}")));
    pvm_record.push(("quotient-chunks", (1usize << max_log_quotient).to_string()));
    [("vm-protocol".into(), vm_record), ("pvm-protocol".into(), pvm_record)]
}

fn reference_section<'a>(reference: &'a str, name: &str) -> Option<&'a str> {
    let marker = format!("[{name}]\n");
    let (_, rest) = reference.split_once(&marker)?;
    rest.split("\n[").next()
}

fn compare_fields(section: &str, record: &Record) {
    let frozen = reference_section(HISTORICAL, section).expect("known frozen section");
    let upstream = reference_section(NEXT_BASELINE, section);
    for (key, value) in record {
        let prefix = format!("{key}=");
        let expected = upstream
            .and_then(|text| text.lines().find_map(|line| line.strip_prefix(&prefix)))
            .or_else(|| frozen.lines().find_map(|line| line.strip_prefix(&prefix)));
        // The supplied PVM section does not contain a protocol-id line.
        if *key == "protocol-id" && section == "pvm-protocol" {
            assert!(expected.is_none());
            continue;
        }
        assert_eq!(Some(value.as_str()), expected, "{section}/{key}");
    }
}

#[test]
fn authored_sources_match_frozen_explicit_metadata() {
    let expected_registry: Vec<_> = HISTORICAL
        .lines()
        .filter_map(|line| line.strip_prefix('[').and_then(|line| line.strip_suffix(']')))
        .filter(|name| name.starts_with("vm/") || name.starts_with("pvm/"))
        .collect();
    let actual_registry: Vec<_> = vm::AIRS
        .iter()
        .map(|air| format!("vm/{}", air.file_token()))
        .chain(
            precompiles::ChipletAir::all()
                .iter()
                .map(|air| format!("pvm/{}", air.file_token())),
        )
        .collect();
    assert_eq!(vm::AIRS.len(), 4);
    assert_eq!(precompiles::ChipletAir::all().len(), 12);
    assert_eq!(actual_registry, expected_registry, "canonical source registry order");
    for air in vm::AIRS {
        compare_fields(&format!("vm/{}", air.file_token()), &metadata(&air));
    }
    for air in precompiles::ChipletAir::all() {
        compare_fields(&format!("pvm/{}", air.file_token()), &metadata(&air));
    }
}

#[test]
fn rebuilt_protocols_match_frozen_explicit_identities() {
    for (section, record) in protocols() {
        compare_fields(&section, &record);
    }
}
