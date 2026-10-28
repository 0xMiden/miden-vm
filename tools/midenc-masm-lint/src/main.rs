use std::{env, path::Path, process::ExitCode, rc::Rc};

use miden_project::Project;
use midenc_dialect_hir::analyses::AdviceTaintAnalysis;
use midenc_frontend_masm::{
    DisassemblerConfig, disassemble_project_target_input_for_lint, project::resolve_project_target,
};
use midenc_hir::{
    Context, Op,
    diagnostics::{Report, Severity},
    pass::AnalysisManager,
};
use midenc_hir_analysis::DataFlowConfig;

mod render;

const USAGE: &str = "usage: midenc-masm-lint [--verbose] [--target <name>] <miden-project.toml>";

fn main() -> ExitCode {
    let mut manifest = None;
    let mut verbose = false;
    let mut target = None;
    let mut arguments = env::args_os().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == "--verbose" || argument == "-v" {
            verbose = true;
        } else if argument == "--help" || argument == "-h" {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        } else if argument == "--target" && target.is_none() {
            let Some(name) = arguments.next().and_then(|name| name.into_string().ok()) else {
                eprintln!("expected a target name after --target\n{USAGE}");
                return ExitCode::from(2);
            };
            if name.is_empty() || name.starts_with('-') {
                eprintln!("expected a target name after --target\n{USAGE}");
                return ExitCode::from(2);
            }
            target = Some(name);
        } else if argument.to_string_lossy().starts_with('-') || manifest.is_some() {
            eprintln!("unexpected argument: {}", argument.to_string_lossy());
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        } else {
            manifest = Some(argument);
        }
    }
    let Some(manifest) = manifest else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };

    match analyze(Path::new(&manifest), target.as_deref(), verbose) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            eprintln!("failed to analyze '{}'", Path::new(&manifest).display());
            eprintln!("{error:?}");
            ExitCode::from(2)
        },
    }
}

fn analyze(manifest: &Path, target: Option<&str>, verbose: bool) -> Result<bool, Report> {
    let default_context = Context::default();
    let mut session = default_context.session().clone();
    // Project dependencies supply the external libraries. Importing the default compiled
    // core package would collide with the core source modules under analysis.
    session.options.link_libraries.clear();
    let context = Rc::new(Context::new(Rc::new(session)));
    let project = Project::load(manifest, &context.session().source_manager)?;
    let package = project.package();
    let target_name = target
        .or_else(|| {
            package
                .library_target()
                .or_else(|| package.executable_targets().first())
                .map(|target| target.name.inner().as_ref())
        })
        .ok_or_else(|| Report::msg("project has no build targets"))?;
    let inputs = resolve_project_target(&project, Some(target_name), &context)?;
    let config = DisassemblerConfig { infer_missing_signatures: true };
    let world = disassemble_project_target_input_for_lint(inputs, &config, context.clone())?;
    eprintln!("Analyzing '{}' target '{target_name}'", manifest.display());

    let manager = AnalysisManager::new(world.world.as_operation_ref(), None);
    let mut dataflow = DataFlowConfig::new();
    dataflow.set_interprocedural(true).set_max_worklist_iterations(Some(10_000));
    let result = AdviceTaintAnalysis::run_with_config_allow_partial(
        world.world.borrow().as_operation(),
        manager,
        dataflow,
    )?;
    let source_manager = context.source_manager();
    let root = manifest.parent().unwrap_or(Path::new("."));
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let report_count = render::findings(&result.analysis, source_manager.as_ref(), &root, verbose);
    render::coverage(&world.skipped_procedures);
    if let Some(reason) = &result.incomplete_reason {
        eprintln!("MASM advice taint analysis incomplete: {reason}");
    }
    eprintln!(
        "midenc-masm-lint: {} finding(s), {} skipped procedure(s), analysis {}",
        report_count,
        world.skipped_procedures.len(),
        if result.incomplete_reason.is_some() {
            "incomplete"
        } else {
            "complete"
        },
    );
    eprintln!(
        "midenc-masm-lint: {} operation sink(s), {} public return(s), {} external call(s)",
        result.analysis.findings().len(),
        result.analysis.exit_findings().len(),
        result.analysis.external_call_findings().len(),
    );

    let passed = report_count == 0
        && world.skipped_procedures.is_empty()
        && result.incomplete_reason.is_none();
    eprintln!("Gate {}", if passed { "PASSED" } else { "FAILED" });
    if verbose {
        for skipped in &world.skipped_procedures {
            context
                .diagnostics()
                .diagnostic(Severity::Warning)
                .with_message(format!(
                    "MASM lint skipped procedure '{}': {}",
                    skipped.path, skipped.reason
                ))
                .with_primary_label(skipped.span, "procedure skipped here")
                .emit();
        }
    } else if report_count > 0 || !world.skipped_procedures.is_empty() {
        eprintln!("Use --verbose for individual skips and full source/call context");
    }

    Ok(passed)
}
