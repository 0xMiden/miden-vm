use std::{
    env,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use fs_err as fs;
use miden_assembly::{
    Assembler, Report,
    ast::{self, Module},
    debuginfo::DefaultSourceManager,
    diagnostics::{IntoDiagnostic, reporting::PrintDiagnostic},
};
// CONSTANTS
// ================================================================================================

const ASM_DIR_PATH: &str = "asm";
const PRECOMPILES_ASM_DIR_PATH: &str = "precompiles/asm";
const ASL_DIR_PATH: &str = "assets";
const DOC_DIR_PATH: &str = "docs";
const AGGREGATE_ASM_DIR: &str = "aggregate-masm";

// MARKDOWN RENDERER
// ================================================================================================

pub struct MarkdownRenderer {}

impl MarkdownRenderer {
    fn write_docs_header(mut writer: &fs::File, ns: &str) {
        let header =
            format!("\n## {ns}\n| Procedure | Description |\n| ----------- | ------------- |\n");
        writer.write_all(header.as_bytes()).expect("unable to write header to writer");
    }

    fn write_docs_procedure(mut writer: &fs::File, name: &str, docs: Option<&str>) {
        if let Some(docs) = docs {
            let escaped = docs.replace('|', "\\|").replace('\n', "<br />");
            let line = format!("| {name} | {escaped} |\n");
            writer.write_all(line.as_bytes()).expect("unable to write func to writer");
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn markdown_file_name(ns: &miden_assembly_syntax::Path) -> String {
    use miden_assembly_syntax::Path as MasmPath;

    // Remove the "miden::core::" prefix
    let ns = ns.strip_prefix(MasmPath::new("miden::core")).unwrap_or(ns);
    let mut buf = String::with_capacity(256);
    for (i, part) in ns.components().enumerate() {
        let part = part.unwrap();
        if i > 0 {
            buf.push('/');
        }
        buf.push_str(part.as_str());
    }
    // Handle the root `miden::core` module
    if buf.is_empty() {
        buf.push_str("mod");
    }
    buf.push_str(".md");
    buf
}

// LIBCORE DOCUMENTATION
// ================================================================================================

/// Writes Miden core library modules documentation markdown files based on the available
/// modules and comments.
pub fn build_core_lib_docs(asm_dir: &Path, output_dir: &str) -> io::Result<()> {
    use miden_assembly_syntax::{Path as MasmPath, ast::ModuleKind, parser};
    let output_path = Path::new(output_dir);

    // Try to delete, but ignore “not found” error
    match fs::remove_dir_all(output_path) {
        Ok(()) => {},
        Err(e) if e.kind() == io::ErrorKind::NotFound => {},
        Err(e) => return Err(e),
    }

    // Create docs directory (and parents)
    fs::create_dir_all(output_path)?;

    // Find all .masm
    let namespace = Arc::<MasmPath>::from(MasmPath::new("::miden::core"));
    let source_manager = Arc::new(DefaultSourceManager::default());
    let (root, support) = parser::read_modules_from_root(
        asm_dir.join("mod.masm"),
        Some(namespace),
        Some(ModuleKind::Library),
        source_manager,
        true,
    )
    .unwrap_or_else(|err| panic!("{}", PrintDiagnostic::new(err)));

    // Render the modules into markdown
    for module in core::slice::from_ref(&root).iter().chain(support.iter()) {
        let label = module.path().to_relative();
        let relative = markdown_file_name(label);
        let out = output_path.join(&relative);

        // Create directories if needed
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut f = fs::File::create(&out)?;

        // Parse module using AST-based approach
        let (module_docs, procedures) = extract_docs(module, &support);

        // Write module docs
        if let Some(docs) = module_docs {
            let escaped = docs.replace('|', "\\|").replace('\n', "<br />");
            f.write_all(escaped.as_bytes())?;
            f.write_all(b"\n\n")?;
        }

        // Write header
        MarkdownRenderer::write_docs_header(&f, label.as_str());

        // Write procedures
        for (name, docs) in procedures {
            MarkdownRenderer::write_docs_procedure(&f, &name, docs.as_deref());
        }
    }

    Ok(())
}

// Module doc, procedures doc
type DocPayload = (Option<String>, Vec<(String, Option<String>)>);

/// Parse MASM source using AST-parsing
fn extract_docs(module: &Module, modules: &[Box<Module>]) -> DocPayload {
    // Extract module documentation
    let module_docs = module.docs().map(|d| d.to_string());

    // Extract procedures and their documentation
    let mut procedures = local_procedure_docs(module);
    for import in module.imports() {
        let ast::Import::Item(import) = import else {
            continue;
        };
        if !import.visibility().is_public() {
            continue;
        }
        if let Some(docs) = reexport_target_docs(import, module.path(), modules) {
            procedures.push((import.local_name().to_string(), docs));
        }
    }

    (module_docs, procedures)
}

fn local_procedure_docs(module: &Module) -> Vec<(String, Option<String>)> {
    let mut procedures = Vec::new();
    for (index, name) in module.exported() {
        match &module[index] {
            ast::Item::Procedure(proc) => {
                let docs = proc.docs().map(|d| d.to_string());
                procedures.push((name.name().to_string(), docs));
            },
            // TODO: Update doc format to allow for other item types
            ast::Item::Constant(_) | ast::Item::Type(_) => {},
        }
    }
    procedures
}

fn reexport_target_docs(
    import: &ast::ItemImport,
    current_module_path: &miden_assembly_syntax::Path,
    modules: &[Box<Module>],
) -> Option<Option<String>> {
    use std::borrow::Cow;

    let target_path = import.target_path().into_inner();
    let target_path = if target_path.starts_with("self") {
        let (_, rest) = target_path.split_first()?;
        Cow::Owned(current_module_path.join(rest))
    } else {
        target_path.to_absolute().unwrap()
    };
    let target_module_path = target_path.parent()?;
    let target_module = modules.iter().find(|m| m.path() == target_module_path)?;

    target_module
        .procedures()
        .find(|proc| proc.name().as_str() == import.source_name().as_str())
        .map(|proc| proc.docs().map(|docs| docs.to_string()))
}

// PRE-PROCESSING
// ================================================================================================

fn prepare_aggregate_project(
    build_dir: &Path,
    core_asm_dir: &Path,
    precompiles_asm_dir: &Path,
) -> Result<PathBuf, Report> {
    let aggregate_dir = build_dir.join(AGGREGATE_ASM_DIR);
    match fs::remove_dir_all(&aggregate_dir) {
        Ok(()) => {},
        Err(err) if err.kind() == io::ErrorKind::NotFound => {},
        Err(err) => {
            return Err(Report::msg(format!(
                "failed to clear aggregate MASM directory `{}`: {err}",
                aggregate_dir.display()
            )));
        },
    }

    fs::create_dir_all(&aggregate_dir).into_diagnostic()?;
    fs::write(
        aggregate_dir.join("miden-project.toml"),
        format!(
            r#"[package]
name = "miden-core"
version = "{}"

[lib]
namespace = "miden"
path = "mod.masm"

[profile.release]
# Always produce debug information, as it can be stripped later by the VM
debug = true
# Use workspace-relative file paths in debug info for portability
trim_paths = true
"#,
            env!("CARGO_PKG_VERSION")
        ),
    )
    .into_diagnostic()?;
    fs::write(aggregate_dir.join("mod.masm"), "pub mod core\npub mod precompiles\n")
        .into_diagnostic()?;

    copy_masm_tree(core_asm_dir, &aggregate_dir.join("core"))?;
    copy_masm_tree(precompiles_asm_dir, &aggregate_dir.join("precompiles"))?;
    miden_core_lib_codegen::masm::write_math_masm(aggregate_dir.join("precompiles"))
        .map_err(Report::msg)?;

    Ok(aggregate_dir)
}

fn copy_masm_tree(source_dir: &Path, target_dir: &Path) -> Result<(), Report> {
    fs::create_dir_all(target_dir).into_diagnostic()?;

    for entry in fs::read_dir(source_dir).into_diagnostic()? {
        let entry = entry.into_diagnostic()?;
        let source_path = entry.path();
        let target_path = target_dir.join(entry.file_name());
        let file_type = entry.file_type().into_diagnostic()?;

        if file_type.is_dir() {
            copy_masm_tree(&source_path, &target_path)?;
        } else if file_type.is_file()
            && source_path.extension().and_then(|extension| extension.to_str()) == Some("masm")
        {
            fs::copy(&source_path, &target_path).into_diagnostic()?;
        }
    }

    Ok(())
}

/// Read and parse the aggregate core/precompiles sources into a package, serializing it into the
/// `assets` folder as the `miden-core` package.
fn main() -> Result<(), Report> {
    use miden_assembly::diagnostics::reporting::ReportHandlerOpts;

    // re-build the `[OUT_DIR]/assets/core.masp` file iff core/precompile MASM sources,
    // codegen support, or its builder changed:
    println!("cargo:rerun-if-changed=asm");
    println!("cargo:rerun-if-changed={PRECOMPILES_ASM_DIR_PATH}");
    println!("cargo:rerun-if-changed=codegen");
    println!("cargo:rerun-if-env-changed=MIDEN_BUILD_LIB_DOCS");
    // NOTE: path is relative to the package root (crates/lib/core/), so we need
    // ../../ to reach crates/assembly/src.
    println!("cargo:rerun-if-changed=../../assembly/src");

    miden_assembly::diagnostics::reporting::set_hook(Box::new(|_| {
        Box::new(ReportHandlerOpts::new().build())
    }))
    .unwrap();
    miden_assembly::diagnostics::reporting::set_panic_hook();

    // Enable debug tracing to stderr via the MIDEN_LOG environment variable, if present
    env_logger::Builder::from_env("MIDEN_LOG").format_timestamp(None).init();

    // Build the aggregate core library package.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let asm_dir = Path::new(manifest_dir).join(ASM_DIR_PATH);
    let precompiles_asm_dir = Path::new(manifest_dir).join(PRECOMPILES_ASM_DIR_PATH);
    let build_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let aggregate_dir = prepare_aggregate_project(&build_dir, &asm_dir, &precompiles_asm_dir)?;

    let assembler = Assembler::default();
    let mut registry = miden_package_registry::InMemoryPackageRegistry::default();
    let mut project_assembler =
        assembler.for_project_at_path(aggregate_dir.join("miden-project.toml"), &mut registry)?;

    let package =
        project_assembler.assemble(miden_assembly::ProjectTargetSelector::Library, "release")?;

    // write the masp output
    package.write_masp_file(build_dir.join(ASL_DIR_PATH)).into_diagnostic()?;

    // Generate documentation
    if env::var("MIDEN_BUILD_LIB_DOCS").is_ok() {
        build_core_lib_docs(&asm_dir, DOC_DIR_PATH).into_diagnostic()?;
    }

    Ok(())
}
