use std::{format, fs, string::String, vec::Vec};

use miden_air_source::codegen::{
    constraints::{self, ComputedArtifacts, SHARED_ABI},
    precompile, pvm_variants,
};

use super::*;

const AIR_CONFIG_PATH: &str = "crates/air/generated/src/config.rs";
const RELATION_DIGEST_PATH: &str = "crates/lib/core/asm/sys/vm/mod.masm";
const STARK_CONSTANTS_PATH: &str = "crates/lib/core/asm/stark/constants.masm";
const PVM_PROTECTED_WRAPPER: &str = "crates/lib/core/asm/sys/pvm/mod.masm";
const DELIVERY_MANAGED_PATHS: [&str; 24] = [
    "crates/lib/core/asm/sys/vm/constraints_eval.masm",
    "crates/lib/core/asm/sys/vm/layout.masm",
    "crates/lib/core/asm/sys/vm/ood_frames.masm",
    "crates/lib/core/asm/sys/vm/deep_queries.masm",
    "crates/lib/core/asm/sys/pvm/constraints_eval.masm",
    "crates/lib/core/asm/sys/pvm/layout.masm",
    "crates/lib/core/asm/sys/pvm/ood_frames.masm",
    "crates/lib/core/asm/sys/pvm/deep_queries.masm",
    "crates/lib/core/asm/sys/pvm/aux_trace.masm",
    "crates/lib/core/asm/sys/pvm/public_inputs.masm",
    "crates/air/generated/artifacts/vm-evaluator.rs.zlib",
    "crates/air/generated/artifacts/vm-degrees.rs",
    "crates/air/generated/artifacts/precompile-degrees.rs",
    "crates/air/generated/artifacts/vm-metadata.rs",
    "crates/air/generated/artifacts/precompile-metadata.rs",
    "crates/lib/core/asm/sys/verifier/parameters.masm",
    "crates/lib/core/asm/sys/verifier/pipes.masm",
    "crates/lib/core/asm/sys/verifier/evaluator.masm",
    "crates/lib/core/asm/sys/verifier/proof_order.masm",
    "crates/lib/core/asm/sys/verifier/ood.masm",
    "crates/lib/core/asm/sys/verifier/deep.masm",
    "crates/lib/core/asm/sys/verifier/fixed.masm",
    "crates/lib/core/asm/sys/verifier/pvm_aux.masm",
    "crates/lib/core/asm/sys/verifier/pvm_public.masm",
];

struct DeliveryFixture {
    root: tempfile::TempDir,
}

impl DeliveryFixture {
    fn new(vm: &ComputedArtifacts, pvm: &precompile::GeneratedArtifacts) -> Self {
        let fixture = Self { root: tempfile::tempdir().unwrap() };
        // This fixture exercises delivery behavior, not accepted-identity derivation.
        // Independent pin/golden and live-library tests retain that separate obligation.
        let mut accepted = serde_json::json!({
            "accepted_schema": 1,
            "relations": {
                "vm": {
                    "protocol_id": 1,
                    "accepted_circuit_digest": vm.circuit_digest.map(|felt| felt.as_canonical_u64()),
                    "accepted_relation_digest": vm.relation_digest.map(|felt| felt.as_canonical_u64()),
                },
                "precompile": {
                    "protocol_id": 4,
                    "accepted_circuit_digest": (*pvm.circuit_digest).map(|felt| felt.as_canonical_u64()),
                    "accepted_relation_digest": pvm.relation_digest.map(|felt| felt.as_canonical_u64()),
                },
            },
        });
        assert_eq!((vm.files.len(), pvm.files.len()), (6, 9));
        for relative in &DELIVERY_MANAGED_PATHS[..10] {
            let file = vm
                .files
                .iter()
                .chain(&pvm.files)
                .find(|file| file.relative_path == *relative)
                .unwrap();
            assert_eq!(file.ownership, ArtifactOwnership::Managed);
        }
        for variant in pvm_variants::generate() {
            assert_eq!(variant.files.len(), 2);
            for (name, ownership) in [
                ("layout", ArtifactOwnership::Managed),
                ("mod", ArtifactOwnership::ProtectedCheckOnly),
            ] {
                let path = format!("crates/lib/core/asm/sys/pvm/v{}/{name}.masm", variant.mask);
                assert!(
                    variant
                        .files
                        .iter()
                        .any(|file| file.relative_path == path && file.ownership == ownership)
                );
            }
            accepted["relations"][format!("precompile-{}", variant.mask)] = serde_json::json!({"protocol_id":4,"accepted_circuit_digest":variant.circuit,"accepted_relation_digest":variant.relation});
            for file in variant.files {
                let body = if file.ownership == ArtifactOwnership::ProtectedCheckOnly {
                    file.body
                } else {
                    format!("unchanged reduced sentinel: {}", file.relative_path)
                };
                fixture.write(&file.relative_path, &body);
            }
        }
        fixture.write(
            "crates/air/generated/protocol/accepted.json",
            &serde_json::to_string_pretty(&accepted).unwrap(),
        );
        let shared = format!(
            "pub const LOG_AIR_TRACE_LENGTHS_PTR = {}\n\
             pub const LOG_AIR_TRACE_LENGTHS_CAPACITY = {}\n\
             pub const CONSTRAINT_COMPOSITION_COEFS_PTR = {}\n\
             pub const PUBLIC_INPUTS_ADDRESS_PTR = {}\n",
            SHARED_ABI.heights_ptr,
            SHARED_ABI.heights_capacity,
            SHARED_ABI.composition_coefficients_ptr,
            SHARED_ABI.public_inputs_address_ptr,
        );
        fixture.write(STARK_CONSTANTS_PATH, &shared);
        for relative in [
            AIR_CONFIG_PATH,
            RELATION_DIGEST_PATH,
            "crates/air/generated/src/precompile/ace_constants.rs",
            "crates/air/generated/src/precompile/protocol.rs",
            PVM_PROTECTED_WRAPPER,
        ] {
            let file = vm
                .files
                .iter()
                .chain(&pvm.files)
                .find(|file| file.relative_path == relative)
                .unwrap();
            assert_eq!(file.ownership, ArtifactOwnership::ProtectedCheckOnly);
            fixture.write(relative, &file.body);
        }
        for relative in DELIVERY_MANAGED_PATHS {
            fixture.write(relative, &format!("unchanged managed sentinel: {relative}\n"));
        }
        fixture
    }

    fn validate(&self) {
        codegen::render_and_validate(self.root.path()).expect("valid delivery fixture");
        validate_obsolete(self.root.path()).expect("no obsolete fixture modules");
    }

    fn read(&self, relative: &str) -> String {
        fs::read_to_string(self.root.path().join(relative)).unwrap()
    }

    fn write(&self, relative: &str, body: &str) {
        let path = self.root.path().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    fn managed_contents(&self) -> Vec<Vec<u8>> {
        DELIVERY_MANAGED_PATHS
            .iter()
            .map(|relative| fs::read(self.root.path().join(relative)).unwrap())
            .chain((0..7).map(|mask| {
                fs::read(
                    self.root
                        .path()
                        .join(format!("crates/lib/core/asm/sys/pvm/v{mask}/layout.masm")),
                )
                .unwrap()
            }))
            .collect()
    }
}

fn delivery_artifacts() -> (ComputedArtifacts, precompile::GeneratedArtifacts) {
    let vm = constraints::compile_and_render(constraints::accepted_setup_commitments());
    let pvm = precompile::compile_and_render(precompile::accepted_setup_commitment());
    (vm, pvm)
}

#[test]
fn protected_full_body_drift_is_detected_with_unchanged_numeric_pins() {
    let (vm, pvm) = delivery_artifacts();
    let fixture = DeliveryFixture::new(&vm, &pvm);
    fixture.validate();
    let before = fixture.managed_contents();
    for (relative, suffix) in [
        (AIR_CONFIG_PATH, "// protected body drift\n"),
        (RELATION_DIGEST_PATH, "# protected body drift\n"),
    ] {
        let original = fixture.read(relative);
        let suffix = format!("\n{suffix}");
        let drifted = format!("{original}{suffix}");
        assert_eq!(drifted.strip_suffix(suffix.as_str()), Some(original.as_str()));
        fixture.write(relative, &drifted);
        let error = run(fixture.root.path(), Mode::Write).unwrap_err();
        assert!(
            error.contains(relative) && error.contains("protected template-body drift"),
            "unexpected error: {error}"
        );
        assert_eq!(fixture.managed_contents(), before);
        fixture.write(relative, &original);
    }
}

#[test]
fn rejected_write_delivery_preserves_every_managed_output() {
    let (vm, pvm) = delivery_artifacts();
    DeliveryFixture::new(&vm, &pvm).validate();
    for rejected_input in [
        "accepted identity",
        "VM protected body",
        "PVM protected body",
        "reduced protected body",
        "reduced accepted identity",
        "obsolete module",
    ] {
        let fixture = DeliveryFixture::new(&vm, &pvm);
        let before = fixture.managed_contents();
        let expected = match rejected_input {
            "accepted identity" => {
                let relative = "crates/air/generated/protocol/accepted.json";
                let mut accepted: serde_json::Value =
                    serde_json::from_str(&fixture.read(relative)).unwrap();
                let limb = &mut accepted["relations"]["vm"]["accepted_circuit_digest"][0];
                *limb = serde_json::Value::from(limb.as_u64().unwrap() + 1);
                fixture.write(relative, &serde_json::to_string_pretty(&accepted).unwrap());
                "candidate identity differs"
            },
            "VM protected body" => {
                fixture.write(
                    RELATION_DIGEST_PATH,
                    &format!("{}\n# rejected body drift\n", fixture.read(RELATION_DIGEST_PATH)),
                );
                RELATION_DIGEST_PATH
            },
            "PVM protected body" => {
                fixture.write(
                    PVM_PROTECTED_WRAPPER,
                    &format!("{}\n# rejected body drift\n", fixture.read(PVM_PROTECTED_WRAPPER)),
                );
                PVM_PROTECTED_WRAPPER
            },
            "reduced protected body" => {
                let path = "crates/lib/core/asm/sys/pvm/v2/mod.masm";
                fixture.write(path, &format!("{}\n# rejected reduced drift\n", fixture.read(path)));
                path
            },
            "reduced accepted identity" => {
                let path = "crates/air/generated/protocol/accepted.json";
                let mut accepted: serde_json::Value =
                    serde_json::from_str(&fixture.read(path)).unwrap();
                accepted["relations"]["precompile-2"]["accepted_circuit_digest"][0] = 0.into();
                fixture.write(path, &serde_json::to_string_pretty(&accepted).unwrap());
                "candidate identity differs"
            },
            "obsolete module" => {
                fixture.write("crates/lib/core/asm/sys/pvm/v2/aux_trace.masm", "obsolete sentinel");
                "obsolete variant algorithm"
            },
            _ => unreachable!(),
        };
        let error = run(fixture.root.path(), Mode::Write)
            .expect_err("rejected input must prevent delivery");
        assert!(error.contains(expected), "unexpected {rejected_input} error: {error}");
        assert_eq!(
            fixture.managed_contents(),
            before,
            "rejected {rejected_input} changed a managed output"
        );
    }
}
