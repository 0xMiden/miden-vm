use super::*;

#[test]
fn every_schema_leaf_has_a_typed_runtime_binding() {
    let schema = Schema::load().unwrap();
    let path = Path::new("test.toml");
    // Bind one leaf at a time so a scoped value cannot hide an incorrectly typed shared binding.
    for assignment in schema.sample_assignments() {
        let file = schema.file(path, &assignment).unwrap();
        let overrides = schema.overrides(std::slice::from_ref(&assignment)).unwrap();
        assert_eq!(file, overrides, "{assignment}");
        Settings::resolve(&schema, path, &file, &Layer::new())
            .unwrap_or_else(|err| panic!("binding {assignment}: {err}"));
    }
}

#[test]
fn block_hashing_is_passed_to_the_prover() {
    for enabled in [true, false] {
        let settings =
            Settings::from_overrides(&[format!("proving.hash-lde-blocks={enabled}")]).unwrap();
        assert_eq!(settings.prover, Prover::new().with_hash_lde_blocks(enabled));
    }
}

#[test]
fn shared_values_apply_before_specific_values_in_each_layer() {
    let schema = Schema::load().unwrap();
    let path = Path::new("ci.toml");
    let file = schema
        .file(
            path,
            r#"
        execution.precompiles.hash.max-count = 7
        verification.precompiles.hash.max-total-size = '12MiB'
        resources.vm-prover-memory = '1GiB'
        bundle.release = true
    "#,
        )
        .unwrap();
    let shared = "precompiles.hash.max-total-size=8MiB";
    let specific = "verification.precompiles.hash.max-total-size=2MiB";
    for (assignments, verification_bytes) in [
        (vec![shared], 8 << 20),
        (vec![shared, specific], 2 << 20),
        (vec![specific, shared], 2 << 20),
    ] {
        let assignments = assignments
            .into_iter()
            .chain([
                "resources.max-prover-memory=32MiB",
                "resources.precompile-prover-memory=16MiB",
                "bundle.release=false",
                "display.num-outputs=0",
            ])
            .map(String::from)
            .collect::<Vec<_>>();
        let settings =
            Settings::resolve(&schema, path, &file, &schema.overrides(&assignments).unwrap())
                .unwrap();
        let exec = settings.execution.execution_precompile_limits();
        let verify = settings.execution.verification_precompile_limits();
        assert_eq!(exec.class(&HASH_WORK).unwrap().max_total_size, 8 << 20);
        assert_eq!(exec.class(&HASH_WORK).unwrap().max_count, 7);
        assert_eq!(verify.class(&HASH_WORK).unwrap().max_total_size, verification_bytes);
        assert_eq!(
            verify.class(&MSM_WORK),
            ExecutionOptions::default().verification_precompile_limits().class(&MSM_WORK)
        );
        assert_eq!(settings.prover.max_prover_memory_bytes(), 32 << 20);
        assert_eq!(settings.prover.max_precompile_prover_memory_bytes(), 16 << 20);
        assert!(!settings.release);
        assert_eq!(settings.num_outputs, 0);
    }
}

#[test]
fn validate_cycles_after_combining_layers_and_identify_sources() {
    let schema = Schema::load().unwrap();
    let path = Path::new("ci.toml");
    let file = schema.file(path, "execution.max-cycles=100").unwrap();
    let overrides = schema.overrides(&["execution.expected-cycles=65".into()]).unwrap();
    let err = Settings::resolve(&schema, path, &file, &overrides).err().unwrap().to_string();
    assert!(err.contains("ci.toml: execution.max-cycles"), "{err}");
    assert!(err.contains("--set execution.expected-cycles"), "{err}");
    let overrides = schema
        .overrides(&["execution.expected-cycles=65".into(), "execution.max-cycles=128".into()])
        .unwrap();
    assert_eq!(
        Settings::resolve(&schema, path, &file, &overrides)
            .unwrap()
            .execution
            .expected_cycles(),
        128
    );
}
