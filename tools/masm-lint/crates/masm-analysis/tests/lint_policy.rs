use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use masm_analysis::lint::{LibraryRoot, LintAnalysisInput, LintDiagnostic, analyze_entries};
use miden_debug_types::DefaultSourceManager;

fn temp_module_dir(test_name: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("masm_analysis_{test_name}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp module dir");
    dir
}

fn diagnostics_for_source(
    test_name: &str,
    source: &str,
    group_by_origin: bool,
) -> Vec<LintDiagnostic> {
    let dir = temp_module_dir(test_name);
    let module_path = dir.join("test.masm");
    fs::write(&module_path, source).expect("write MASM module");

    let diagnostics = diagnostics_for_module(&dir, &module_path, group_by_origin);

    fs::remove_dir_all(dir).expect("remove temp module dir");
    diagnostics
}

fn diagnostics_for_module(
    dir: &Path,
    module_path: &Path,
    group_by_origin: bool,
) -> Vec<LintDiagnostic> {
    let report = analyze_entries(LintAnalysisInput {
        entry_files: vec![module_path.to_path_buf()],
        roots: vec![LibraryRoot::new("", dir.to_path_buf())],
        sources: Arc::new(DefaultSourceManager::default()),
        group_by_origin,
    });

    assert!(
        report.load_errors.is_empty(),
        "failed to load MASM module: {:?}",
        report.load_errors.iter().map(|err| err.message.as_str()).collect::<Vec<_>>()
    );
    assert!(
        report.unresolved_dependencies.is_none(),
        "unexpected unresolved dependencies in lint policy fixture"
    );

    report.diagnostics
}

#[test]
fn allow_marker_suppresses_flat_advice_diagnostic_through_lint_api() {
    let diagnostics = diagnostics_for_source(
        "flat_allow_marker",
        "\
pub proc test
    # masm-lint: allow unconstrained-advice -- test fixture accepts this source.
    adv_push
    mem_load
    drop
end
",
        false,
    );

    assert!(diagnostics.is_empty(), "allowed advice origin emitted diagnostics");
}

#[test]
fn allow_marker_suppresses_grouped_advice_diagnostic_through_lint_api() {
    let diagnostics = diagnostics_for_source(
        "grouped_allow_marker",
        "\
pub proc test
    # masm-lint: allow unconstrained-advice -- test fixture accepts this source.
    adv_push
    mem_load
    drop
end
",
        true,
    );

    assert!(diagnostics.is_empty(), "allowed grouped advice origin emitted diagnostics");
}

#[test]
fn allow_marker_removes_only_marked_origins_for_same_sink() {
    let diagnostics = diagnostics_for_source(
        "partial_allow_marker",
        "\
pub proc test(flag: felt)
    if.true
        # masm-lint: allow unconstrained-advice -- test fixture accepts this source.
        adv_push
    else
        adv_push
    end
    mem_load
    drop
end
",
        false,
    );

    assert_eq!(diagnostics.len(), 1, "expected one unsuppressed diagnostic");
    assert_eq!(
        diagnostics[0].related.len(),
        1,
        "expected only the unmarked advice origin to remain"
    );
}

#[test]
fn lift_failures_are_opaque_without_stopping_lint_diagnostics() {
    let diagnostics = diagnostics_for_source(
        "opaque_lift_failure",
        "\
pub proc opaque_dynamic_call
    dynexec
end

pub proc still_linted
    adv_push
    mem_load
    drop
end
",
        false,
    );

    assert_eq!(diagnostics.len(), 1, "expected diagnostic collection to continue");
    assert_eq!(diagnostics[0].message, "unconstrained advice used as memory address");
}
