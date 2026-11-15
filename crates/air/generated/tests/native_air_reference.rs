//! Independently authored observation of the fixed-base relation interfaces.
//!
//! The adjacent fixture FORMAT.md specifies the complete new encoding and the
//! narrower subset comparable to the supplied historical data. No observation
//! here uses a generated evaluator or overwrites an expected fixture.

use std::fmt::Write;

use miden_ace::RecursiveAceCircuit;
use miden_air_definitions::{precompiles, vm};
use miden_constraint_compiler::{
    ir::{NodeId, capture},
    testing::{constraint_degrees, eval_graph},
};
use miden_core::{
    Felt,
    field::{BasedVectorSpace, PrimeCharacteristicRing, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};
use miden_crypto::hash::blake::Blake3_256;
use miden_stark::air::{BaseAir, LiftedAir, MultiAir, Statement};

const BASE: &str = "614c9f3608e6cc0a80397e8aa60315558f3069f7";
const FORMAT: &str = "native-air-base-observation-v1";
const HISTORICAL: &str = include_str!("fixtures/native_air_reference/reference.txt");
const SEEDS: [u64; 4] =
    [0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89];

type Record = Vec<(&'static str, String)>;

/// Explicit framing, independent of Rust Debug representations and historical hashes.
struct Encoding(Vec<u8>);

impl Encoding {
    fn new(tag: &str) -> Self {
        let mut bytes = FORMAT.as_bytes().to_vec();
        bytes.push(0);
        bytes.extend_from_slice(tag.as_bytes());
        bytes.push(0);
        Self(bytes)
    }

    fn count(&mut self, value: usize) {
        self.u64(u64::try_from(value).expect("observation count fits u64"));
    }

    fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn field(&mut self, value: Felt) {
        self.u64(value.as_canonical_u64());
    }

    fn extension(&mut self, value: QuadFelt) {
        for coefficient in value.as_basis_coefficients_slice() {
            self.field(*coefficient);
        }
    }

    fn digest(self) -> String {
        let bytes: [u8; 32] = Blake3_256::hash(&self.0).into();
        let mut text = String::from("0x");
        for byte in bytes {
            write!(text, "{byte:02x}").unwrap();
        }
        text
    }
}

fn quad(coefficients: [u64; 2]) -> QuadFelt {
    QuadFelt::from_basis_coefficients_slice(&coefficients.map(Felt::from_u64)).unwrap()
}

fn coefficients(value: QuadFelt) -> Vec<u64> {
    value.as_basis_coefficients_slice().iter().map(Felt::as_canonical_u64).collect()
}

fn metadata<A: LiftedAir<Felt, QuadFelt>>(air: &A) -> Record {
    let periods: Vec<_> = air.periodic_columns().iter().map(Vec::len).collect();
    let [base, ext] = constraint_degrees(air);
    vec![
        (
            "shape",
            format!(
                "main:{} preprocessed:{} aux:{} public:{} challenges:{} exports:{} preprocessed-log-height:{:?}",
                air.width(),
                air.preprocessed_width(),
                air.aux_width(),
                air.num_public_values(),
                air.num_randomness(),
                air.num_aux_values(),
                air.log_preprocessed_height(),
            ),
        ),
        ("periods", format!("{periods:?}")),
        ("assertions", format!("base:{} ext:{}", base.len(), ext.len())),
    ]
}

/// Collect owned canonical observations of one authored source, including repeated emissions.
fn observe_air<A: LiftedAir<Felt, QuadFelt>>(air: &A) -> Record {
    let mut record = metadata(air);
    let (graph, captured) = capture(air);
    let [base_degrees, ext_degrees] = constraint_degrees(air);
    assert_eq!(captured.base_roots.len(), base_degrees.len());
    assert_eq!(captured.base_global_indices.len(), base_degrees.len());
    assert_eq!(captured.ext_roots.len(), ext_degrees.len());
    assert_eq!(captured.ext_global_indices.len(), ext_degrees.len());
    let mut assertions: Vec<(usize, u8, usize, NodeId)> = captured
        .base_global_indices
        .iter()
        .copied()
        .zip(&base_degrees)
        .zip(&captured.base_roots)
        .map(|((ordinal, degree), root)| (ordinal, 0, *degree, *root))
        .chain(
            captured
                .ext_global_indices
                .iter()
                .copied()
                .zip(&ext_degrees)
                .zip(&captured.ext_roots)
                .map(|((ordinal, degree), root)| (ordinal, 1, *degree, *root)),
        )
        .collect();
    assert_eq!(assertions.len(), base_degrees.len() + ext_degrees.len());
    assertions.sort_by_key(|entry| entry.0);
    let mut layout = Encoding::new("layout");
    layout.count(assertions.len());
    for (expected, &(ordinal, class, degree, _)) in assertions.iter().enumerate() {
        assert_eq!(ordinal, expected, "assertion ordinals must be dense and unique");
        layout.count(ordinal);
        layout.0.push(class);
        layout.count(degree);
    }
    record.push(("ordered-classes-degrees-v1", layout.digest()));

    let periodic = air.periodic_columns();
    let mut periodic_encoding = Encoding::new("periodic");
    periodic_encoding.count(periodic.len());
    for column in periodic.iter() {
        periodic_encoding.count(column.len());
        for &value in column {
            periodic_encoding.field(value);
        }
    }
    record.push(("periodic-v1", periodic_encoding.digest()));

    let fixed = air.preprocessed_trace();
    let mut fixed_encoding = Encoding::new("fixed");
    fixed_encoding.0.push(u8::from(fixed.is_some()));
    if let Some(matrix) = &fixed {
        fixed_encoding.count(matrix.width());
        fixed_encoding.count(matrix.height());
        for &value in &matrix.values {
            fixed_encoding.field(value);
        }
    }
    record.push(("preprocessed-v1", fixed_encoding.digest()));

    for seed in SEEDS {
        let values = eval_graph(&graph, seed);
        let mut encoded = Encoding::new("values");
        encoded.u64(seed);
        encoded.count(assertions.len());
        let mut folded = QuadFelt::ZERO;
        for &(ordinal, class, _, root) in &assertions {
            encoded.count(ordinal);
            encoded.0.push(class);
            let value = values[root.index()];
            encoded.extension(value);
            folded = folded * quad([17, 19]) + value;
        }
        record.push((
            "sample-v1",
            format!(
                "seed={seed:#018x} ordered-values-v1={} horner={:?}",
                encoded.digest(),
                coefficients(folded),
            ),
        ));
    }

    let height = periodic
        .iter()
        .map(Vec::len)
        .chain(fixed.as_ref().map(Matrix::height))
        .chain([2])
        .max()
        .unwrap();
    let main = RowMajorMatrix::new(vec![Felt::ZERO; height * air.width()], air.width());
    let public = vec![Felt::ZERO; air.num_public_values()];
    let challenges: Vec<_> = (0..air.num_randomness())
        .map(|i| {
            let i = u64::try_from(i).unwrap();
            quad([2 * i + 2, 2 * i + 3])
        })
        .collect();
    let (aux, exports) =
        air.build_aux_trace_with_preprocessed(&main, fixed.as_ref(), &public, &[], &challenges);
    assert_eq!(aux.width(), air.aux_width());
    assert_eq!(aux.height(), height);
    assert_eq!(exports.len(), air.num_aux_values());
    let mut aux_encoding = Encoding::new("aux");
    aux_encoding.count(aux.width());
    aux_encoding.count(aux.height());
    for &value in &aux.values {
        aux_encoding.extension(value);
    }
    let mut export_encoding = Encoding::new("exports");
    export_encoding.count(exports.len());
    for &value in &exports {
        export_encoding.extension(value);
    }
    record.push(("aux-height", height.to_string()));
    record.push(("aux-v1", aux_encoding.digest()));
    record.push(("exports-v1", export_encoding.digest()));
    record
}

struct AuthoredAirs<A>(Vec<A>);

impl<A: LiftedAir<Felt, QuadFelt>> MultiAir<Felt, QuadFelt> for AuthoredAirs<A> {
    type Air = A;

    fn airs(&self) -> &[A] {
        &self.0
    }
}

/// Rebuild setup through source factories, using the existing canonical PCS presets.
fn setup_record<A: LiftedAir<Felt, QuadFelt>>(
    airs: Vec<A>,
    params: miden_stark::pcs::PcsParams,
    relation: [Felt; 4],
) -> Record {
    let public = airs
        .iter()
        .enumerate()
        .filter(|(_, air)| air.num_public_values() != 0)
        .map(|(index, air)| (index, vec![Felt::ZERO; air.num_public_values()]))
        .collect();
    let statement = Statement::new(AuthoredAirs(airs), public, vec![]).unwrap();
    let blake = miden_stark::config::blake3_256_config(params, relation);
    let blake_root: [u8; 32] = miden_stark::Preprocessed::build(&statement, &blake)
        .unwrap()
        .commitment()
        .into();
    let eidos = miden_stark::config::eidos_config(
        params,
        relation,
        miden_core::program::domain::STARK_TRANSCRIPT,
    );
    let eidos_root: [u64; 4] = miden_stark::Preprocessed::build(&statement, &eidos)
        .unwrap()
        .commitment()
        .into();
    let keccak = miden_stark::config::keccak_config(params, relation);
    let keccak_root: [u64; 4] = miden_stark::Preprocessed::build(&statement, &keccak)
        .unwrap()
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
    let mut encoded = Encoding::new("ace");
    encoded.count(circuit.num_inputs);
    encoded.count(circuit.num_eval_gates);
    encoded.count(circuit.stream_len);
    for &value in &circuit.instructions {
        encoded.field(value);
    }
    vec![
        ("protocol-id", protocol_id.to_string()),
        ("relation", format!("{relation:?}")),
        ("ace", format!("{ace:?}")),
        (
            "ace-shape",
            format!("{:?}", (circuit.num_inputs, circuit.num_eval_gates, circuit.stream_len)),
        ),
        ("ace-stream-v1", encoded.digest()),
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
        .map(|air| (air.preprocessed_width(), air.width(), air.aux_width() * miden_ace::EXT_DEGREE))
        .collect();
    let max_log_quotient = precompiles::ChipletAir::all()
        .iter()
        .map(miden_stark::log_quotient_degree::<Felt, QuadFelt, _>)
        .max()
        .unwrap();
    pvm_record.push(("raw-widths", format!("{raw_widths:?}")));
    pvm_record.push(("quotient-chunks", (1usize << max_log_quotient).to_string()));
    [("vm-protocol".into(), vm_record), ("pvm-protocol".into(), pvm_record)]
}

fn frozen_section(name: &str) -> &str {
    let marker = format!("[{name}]\n");
    let (_, rest) = HISTORICAL.split_once(&marker).expect("known frozen section");
    rest.split("\n[").next().unwrap()
}

fn compare_fields(section: &str, record: &Record, protocol: bool) {
    let frozen = frozen_section(section);
    for (key, value) in record {
        if key.ends_with("-v1") {
            continue;
        }
        let prefix = format!("{key}=");
        let expected = frozen.lines().find_map(|line| line.strip_prefix(&prefix));
        // The supplied PVM section does not contain a protocol-id line.
        if protocol && *key == "protocol-id" && section == "pvm-protocol" {
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
        compare_fields(&format!("vm/{}", air.file_token()), &metadata(&air), false);
    }
    for air in precompiles::ChipletAir::all() {
        compare_fields(&format!("pvm/{}", air.file_token()), &metadata(&air), false);
    }
}

#[test]
fn rebuilt_protocols_match_frozen_explicit_identities() {
    for (section, record) in protocols() {
        compare_fields(&section, &record, true);
    }
}

/// A print-only base recipe, not a snapshot writer or a migration acceptance test.
#[test]
#[ignore = "base-only observation; execution requires separate user authorization"]
fn print_independent_base_observation() {
    let mut text = format!("{FORMAT}\nbase={BASE}\nalpha=[17, 19]\n");
    let mut append = |name: &str, record: Record| {
        writeln!(text, "\n[{name}]").unwrap();
        for (key, value) in record {
            writeln!(text, "{key}={value}").unwrap();
        }
    };
    for air in vm::AIRS {
        append(&format!("vm/{}", air.file_token()), observe_air(&air));
    }
    for air in precompiles::ChipletAir::all() {
        append(&format!("pvm/{}", air.file_token()), observe_air(&air));
    }
    for (name, record) in protocols() {
        append(&name, record);
    }
    print!("{text}");
}
