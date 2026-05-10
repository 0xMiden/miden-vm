use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use masm_analysis::lint::{LibraryRoot, Workspace, diagnostics_from_workspace};
use miden_debug_types::DefaultSourceManager;

fn temp_module_dir(test_name: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("masm_analysis_{test_name}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp module dir");
    dir
}

fn signature_messages(dir: &Path, module_path: &Path) -> Vec<String> {
    let sources = Arc::new(DefaultSourceManager::default());
    let mut workspace = Workspace::with_source_manager(
        vec![LibraryRoot::new("", dir.to_path_buf())],
        sources.clone(),
    );
    workspace.load_entry(module_path).expect("load MASM module");
    workspace.load_dependencies();

    diagnostics_from_workspace(&workspace, sources, true, false)
        .into_iter()
        .map(|diagnostic| diagnostic.message)
        .collect()
}

fn signature_messages_for_source(test_name: &str, source: &str) -> Vec<String> {
    let dir = temp_module_dir(test_name);
    let module_path = dir.join("test.masm");
    fs::write(&module_path, source).expect("write MASM module");

    let messages = signature_messages(&dir, &module_path);

    fs::remove_dir_all(dir).expect("remove temp module dir");
    messages
}

fn felt_outputs(count: usize) -> String {
    assert!(count > 1, "single-output tests should write `felt` directly");
    format!("({})", vec!["felt"; count].join(", "))
}

fn zero_input_proc_with_outputs(name: &str, outputs: usize, body: &str) -> String {
    format!("pub proc {name}() -> {}\n{body}\nend\n", felt_outputs(outputs))
}

fn declared_zero_inputs_message(inferred_inputs: usize) -> String {
    format!("the definition declares 0 inputs, but the inferred input count is {inferred_inputs}")
}

#[test]
fn declared_zero_input_proc_consuming_stack_value_is_reported() {
    let dir = temp_module_dir("signature_mismatch");
    let module_path = dir.join("bad.masm");
    fs::write(
        &module_path,
        r#"pub proc bad()
    drop
end
"#,
    )
    .expect("write MASM module");

    let messages = signature_messages(&dir, &module_path);

    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0],
        "the definition declares 0 inputs, but the inferred input count is 1"
    );

    fs::remove_dir_all(dir).expect("remove temp module dir");
}

#[test]
fn preserved_hidden_input_checked_in_place_does_not_create_mismatch() {
    let dir = temp_module_dir("preserved_hidden_input");
    let module_path = dir.join("preserved.masm");
    fs::write(
        &module_path,
        r#"pub proc preserved() -> felt
    u32assert
end
"#,
    )
    .expect("write MASM module");

    let messages = signature_messages(&dir, &module_path);

    assert_eq!(messages, Vec::<String>::new());

    fs::remove_dir_all(dir).expect("remove temp module dir");
}

#[test]
fn hidden_input_derived_by_dup_is_reported() {
    let dir = temp_module_dir("derived_hidden_input");
    let module_path = dir.join("derived.masm");
    fs::write(
        &module_path,
        r#"pub proc derived() -> (felt, felt)
    dup.0
end
"#,
    )
    .expect("write MASM module");

    let messages = signature_messages(&dir, &module_path);

    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0],
        "the definition declares 0 inputs, but the inferred input count is 1"
    );

    fs::remove_dir_all(dir).expect("remove temp module dir");
}

#[test]
fn hidden_inputs_derived_by_dup_families_are_reported() {
    for (name, body, outputs, inferred_inputs) in
        [("dup_scalar", "    dup.3", 5, 4), ("dup_word", "    dupw.2", 16, 12)]
    {
        let source = zero_input_proc_with_outputs(name, outputs, body);
        let messages = signature_messages_for_source(name, &source);

        assert_eq!(messages, vec![declared_zero_inputs_message(inferred_inputs)]);
    }
}

#[test]
fn scalar_stack_permutations_report_required_hidden_inputs() {
    for (name, body, outputs, inferred_inputs) in [
        ("swap_scalar", "    swap.4", 5, 5),
        ("movup_scalar", "    movup.5", 6, 6),
        ("movdn_scalar", "    movdn.5", 6, 6),
    ] {
        let source = zero_input_proc_with_outputs(name, outputs, body);
        let messages = signature_messages_for_source(name, &source);

        assert_eq!(messages, vec![declared_zero_inputs_message(inferred_inputs)]);
    }
}

#[test]
fn word_stack_permutations_report_required_hidden_inputs() {
    for (name, body, inferred_inputs) in [
        ("swap_word", "    swapw.3", 16),
        ("movup_word", "    movupw.3", 16),
        ("movdn_word", "    movdnw.3", 16),
    ] {
        let source = zero_input_proc_with_outputs(name, 16, body);
        let messages = signature_messages_for_source(name, &source);

        assert_eq!(messages, vec![declared_zero_inputs_message(inferred_inputs)]);
    }
}

#[test]
fn wrapper_preserves_hidden_input_provenance_from_callee() {
    let dir = temp_module_dir("wrapper_preserved_hidden_input");
    let module_path = dir.join("wrapper.masm");
    fs::write(
        &module_path,
        r#"pub proc callee() -> felt
    u32assert
end

pub proc wrapper() -> felt
    exec.callee
end
"#,
    )
    .expect("write MASM module");

    let messages = signature_messages(&dir, &module_path);

    assert_eq!(messages, Vec::<String>::new());

    fs::remove_dir_all(dir).expect("remove temp module dir");
}

#[test]
fn wrapper_reports_hidden_input_derived_by_callee() {
    let dir = temp_module_dir("wrapper_derived_hidden_input");
    let module_path = dir.join("wrapper.masm");
    fs::write(
        &module_path,
        r#"pub proc callee(x: felt) -> (felt, felt)
    dup.0
end

pub proc wrapper() -> (felt, felt)
    exec.callee
end
"#,
    )
    .expect("write MASM module");

    let messages = signature_messages(&dir, &module_path);

    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0],
        "the definition declares 0 inputs, but the inferred input count is 1"
    );

    fs::remove_dir_all(dir).expect("remove temp module dir");
}

#[test]
fn wrapper_reports_hidden_input_used_by_dropped_callee_output() {
    let dir = temp_module_dir("wrapper_keeps_local_output");
    let module_path = dir.join("wrapper.masm");
    fs::write(
        &module_path,
        r#"pub proc callee(x: felt) -> (felt, felt, felt)
    push.0
    dup.1
end

pub proc wrapper() -> (felt, felt)
    exec.callee
    drop
end
"#,
    )
    .expect("write MASM module");

    let messages = signature_messages(&dir, &module_path);

    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0],
        "the definition declares 0 inputs, but the inferred input count is 1"
    );

    fs::remove_dir_all(dir).expect("remove temp module dir");
}

#[test]
fn hidden_input_used_then_discarded_is_reported() {
    let dir = temp_module_dir("used_hidden_input");
    let module_path = dir.join("used.masm");
    fs::write(
        &module_path,
        r#"pub proc used() -> felt
    dup.0
    emit
    drop
end
"#,
    )
    .expect("write MASM module");

    let messages = signature_messages(&dir, &module_path);

    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0],
        "the definition declares 0 inputs, but the inferred input count is 1"
    );

    fs::remove_dir_all(dir).expect("remove temp module dir");
}

#[test]
fn hidden_input_read_by_zero_effect_store_is_reported() {
    let dir = temp_module_dir("zero_effect_store_hidden_input");
    let module_path = dir.join("stored.masm");
    fs::write(
        &module_path,
        r#"pub proc stored() -> (felt, felt, felt, felt)
    mem_storew_be.0
end
"#,
    )
    .expect("write MASM module");

    let messages = signature_messages(&dir, &module_path);

    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0],
        "the definition declares 0 inputs, but the inferred input count is 4"
    );

    fs::remove_dir_all(dir).expect("remove temp module dir");
}
