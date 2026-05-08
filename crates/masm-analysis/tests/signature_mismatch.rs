use std::{fs, path::PathBuf, sync::Arc};

use masm_analysis::{
    AnalysisSnapshot,
    lint::{LibraryRoot, Workspace},
    signature_mismatch_message, signature_mismatches_from_snapshot,
};
use miden_debug_types::DefaultSourceManager;

fn temp_module_dir(test_name: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("masm_analysis_{test_name}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp module dir");
    dir
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

    let sources = Arc::new(DefaultSourceManager::default());
    let mut workspace =
        Workspace::with_source_manager(vec![LibraryRoot::new("", dir.clone())], sources.clone());
    workspace.load_entry(&module_path).expect("load MASM module");
    workspace.load_dependencies();

    let snapshot = AnalysisSnapshot::from_workspace(&workspace);
    let module = workspace.modules().next().expect("loaded module").module();
    let mismatches = signature_mismatches_from_snapshot(module, sources, &snapshot.signatures);

    assert_eq!(mismatches.len(), 1);
    assert_eq!(
        signature_mismatch_message(&mismatches[0]),
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

    let sources = Arc::new(DefaultSourceManager::default());
    let mut workspace =
        Workspace::with_source_manager(vec![LibraryRoot::new("", dir.clone())], sources.clone());
    workspace.load_entry(&module_path).expect("load MASM module");
    workspace.load_dependencies();

    let snapshot = AnalysisSnapshot::from_workspace(&workspace);
    let module = workspace.modules().next().expect("loaded module").module();
    let mismatches = signature_mismatches_from_snapshot(module, sources, &snapshot.signatures);

    assert_eq!(mismatches, []);

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

    let sources = Arc::new(DefaultSourceManager::default());
    let mut workspace =
        Workspace::with_source_manager(vec![LibraryRoot::new("", dir.clone())], sources.clone());
    workspace.load_entry(&module_path).expect("load MASM module");
    workspace.load_dependencies();

    let snapshot = AnalysisSnapshot::from_workspace(&workspace);
    let module = workspace.modules().next().expect("loaded module").module();
    let mismatches = signature_mismatches_from_snapshot(module, sources, &snapshot.signatures);

    assert_eq!(mismatches.len(), 1);
    assert_eq!(
        signature_mismatch_message(&mismatches[0]),
        "the definition declares 0 inputs, but the inferred input count is 1"
    );

    fs::remove_dir_all(dir).expect("remove temp module dir");
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

    let sources = Arc::new(DefaultSourceManager::default());
    let mut workspace =
        Workspace::with_source_manager(vec![LibraryRoot::new("", dir.clone())], sources.clone());
    workspace.load_entry(&module_path).expect("load MASM module");
    workspace.load_dependencies();

    let snapshot = AnalysisSnapshot::from_workspace(&workspace);
    let module = workspace.modules().next().expect("loaded module").module();
    let mismatches = signature_mismatches_from_snapshot(module, sources, &snapshot.signatures);

    assert_eq!(mismatches, []);

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

    let sources = Arc::new(DefaultSourceManager::default());
    let mut workspace =
        Workspace::with_source_manager(vec![LibraryRoot::new("", dir.clone())], sources.clone());
    workspace.load_entry(&module_path).expect("load MASM module");
    workspace.load_dependencies();

    let snapshot = AnalysisSnapshot::from_workspace(&workspace);
    let module = workspace.modules().next().expect("loaded module").module();
    let mismatches = signature_mismatches_from_snapshot(module, sources, &snapshot.signatures);

    assert_eq!(mismatches.len(), 1);
    assert_eq!(
        signature_mismatch_message(&mismatches[0]),
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

    let sources = Arc::new(DefaultSourceManager::default());
    let mut workspace =
        Workspace::with_source_manager(vec![LibraryRoot::new("", dir.clone())], sources.clone());
    workspace.load_entry(&module_path).expect("load MASM module");
    workspace.load_dependencies();

    let snapshot = AnalysisSnapshot::from_workspace(&workspace);
    let module = workspace.modules().next().expect("loaded module").module();
    let mismatches = signature_mismatches_from_snapshot(module, sources, &snapshot.signatures);

    assert_eq!(mismatches.len(), 1);
    assert_eq!(
        signature_mismatch_message(&mismatches[0]),
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

    let sources = Arc::new(DefaultSourceManager::default());
    let mut workspace =
        Workspace::with_source_manager(vec![LibraryRoot::new("", dir.clone())], sources.clone());
    workspace.load_entry(&module_path).expect("load MASM module");
    workspace.load_dependencies();

    let snapshot = AnalysisSnapshot::from_workspace(&workspace);
    let module = workspace.modules().next().expect("loaded module").module();
    let mismatches = signature_mismatches_from_snapshot(module, sources, &snapshot.signatures);

    assert_eq!(mismatches.len(), 1);
    assert_eq!(
        signature_mismatch_message(&mismatches[0]),
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

    let sources = Arc::new(DefaultSourceManager::default());
    let mut workspace =
        Workspace::with_source_manager(vec![LibraryRoot::new("", dir.clone())], sources.clone());
    workspace.load_entry(&module_path).expect("load MASM module");
    workspace.load_dependencies();

    let snapshot = AnalysisSnapshot::from_workspace(&workspace);
    let module = workspace.modules().next().expect("loaded module").module();
    let mismatches = signature_mismatches_from_snapshot(module, sources, &snapshot.signatures);

    assert_eq!(mismatches.len(), 1);
    assert_eq!(
        signature_mismatch_message(&mismatches[0]),
        "the definition declares 0 inputs, but the inferred input count is 4"
    );

    fs::remove_dir_all(dir).expect("remove temp module dir");
}
