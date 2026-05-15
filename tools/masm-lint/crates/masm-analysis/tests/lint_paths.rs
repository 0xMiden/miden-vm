use std::{fs, path::PathBuf, sync::Arc};

use masm_analysis::lint::{LibraryRoot, LintPathAnalysisInput, analyze_paths};
use miden_debug_types::DefaultSourceManager;

fn temp_module_dir(test_name: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("masm_analysis_{test_name}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp module dir");
    dir
}

#[test]
fn relative_library_roots_are_resolved_against_configured_cwd() {
    let cwd = temp_module_dir("relative_library_root");
    fs::create_dir(cwd.join("lib")).expect("create library root");
    fs::write(
        cwd.join("test.masm"),
        "\
pub proc test() -> felt
    push.1
end
",
    )
    .expect("write MASM module");

    let report = analyze_paths(LintPathAnalysisInput {
        inputs: vec![PathBuf::from("test.masm")],
        libraries: vec![LibraryRoot::new("example", PathBuf::from("lib"))],
        cwd: cwd.clone(),
        sources: Arc::new(DefaultSourceManager::default()),
        group_by_origin: false,
    })
    .expect("relative library root should resolve against configured cwd")
    .expect("test module should be discovered");

    assert!(report.load_errors.is_empty(), "unexpected load errors");
    assert!(
        report.unresolved_dependencies.is_none(),
        "unexpected unresolved dependency report"
    );

    fs::remove_dir_all(cwd).expect("remove temp module dir");
}
