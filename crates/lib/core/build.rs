use std::{
    env,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use fs_err as fs;
use miden_assembly::{
    self as masm, Assembler, Library, Parse, ParseOptions, Report,
    ast::{self, ModuleKind},
    debuginfo::DefaultSourceManager,
    diagnostics::IntoDiagnostic,
};

// CONSTANTS
// ================================================================================================

const ASM_DIR_PATH: &str = "asm";
const ASL_DIR_PATH: &str = "assets";
const DOC_DIR_PATH: &str = "docs";

// MARKDOWN RENDERER
// ================================================================================================

pub struct MarkdownRenderer {}

impl MarkdownRenderer {
    fn write_docs_header(mut writer: &fs::File, ns: &str) {
        let header =
            format!("\n## {}\n| Procedure | Description |\n| ----------- | ------------- |\n", ns);
        writer.write_all(header.as_bytes()).expect("unable to write header to writer");
    }

    fn write_docs_procedure(mut writer: &fs::File, name: &str, docs: Option<&str>) {
        if let Some(docs) = docs {
            let escaped = docs.replace('|', "\\|").replace('\n', "<br />");
            let line = format!("| {} | {} |\n", name, escaped);
            writer.write_all(line.as_bytes()).expect("unable to write func to writer");
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn markdown_file_name(ns: &str) -> String {
    let parts: Vec<&str> = ns.split("::").collect();

    // Remove the "miden::core::" prefix
    if parts.len() > 2 && parts[0] == "miden" && parts[1] == "core" {
        // Use the full module path without "miden::core::" prefix, add .md extension
        format!("{}.md", parts[2..].join("/"))
    } else {
        // Fallback for modules without miden::core:: prefix
        format!("{}.md", parts.join("/"))
    }
}

// LIBCORE DOCUMENTATION
// ================================================================================================

/// Writes Miden core library modules documentation markdown files based on the available
/// modules and comments.
pub fn build_core_lib_docs(asm_dir: &Path, output_dir: &str) -> io::Result<()> {
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
    let modules = find_masm_modules(asm_dir, asm_dir)?;

    // Render the modules into markdown
    for (label, file_path) in modules {
        let relative = markdown_file_name(&label);
        let out = output_path.join(&relative);

        // Create directories if needed
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut f = fs::File::create(&out)?;

        // Parse module using AST-based approach
        let (module_docs, procedures) = parse_module_with_ast(&label, &file_path)?;

        // Write module docs
        if let Some(docs) = module_docs {
            let escaped = docs.replace('|', "\\|").replace('\n', "<br />");
            f.write_all(escaped.as_bytes())?;
            f.write_all(b"\n\n")?;
        }

        // Write header
        MarkdownRenderer::write_docs_header(&f, &label);

        // Write procedures
        for (name, docs) in procedures {
            MarkdownRenderer::write_docs_procedure(&f, &name, docs.as_deref());
        }
    }

    Ok(())
}

/// Find all .masm files recursively
fn find_masm_modules(base_dir: &Path, current_dir: &Path) -> io::Result<Vec<(String, PathBuf)>> {
    let mut modules = Vec::new();
    let entries = match fs::read_dir(current_dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Warning: read_dir({}): {e}", current_dir.display());
            return Ok(modules);
        },
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension()
                && ext == "masm"
            {
                // Convert relative path to module path
                let relative_path = path.strip_prefix(base_dir).unwrap();
                let module_path = relative_path
                    .with_extension("")
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("::");

                let label = format!("miden::core::{}", module_path);

                modules.push((label, path));
            }
        } else if path.is_dir() {
            // Recursively scan subdirectories
            modules.extend(find_masm_modules(base_dir, &path)?);
        }
    }

    Ok(modules)
}

// Module doc, procedures doc
type DocPayload = (Option<String>, Vec<(String, Option<String>)>);

/// Parse MASM source using AST-parsing
fn parse_module_with_ast(label: &str, file_path: &Path) -> io::Result<DocPayload> {
    let path = masm::Path::new(label);
    let module = file_path
        .parse_with_options(
            Arc::new(DefaultSourceManager::default()),
            ParseOptions {
                kind: ModuleKind::Library,
                warnings_as_errors: false,
                path: Some(path.into()),
            },
        )
        .map_err(|e| io::Error::other(e.to_string()))?;

    // Extract module documentation
    let module_docs = module.docs().map(|d| d.to_string());

    // Extract procedures and their documentation
    let mut procedures = Vec::new();
    for (index, name) in module.exported() {
        match &module[index] {
            ast::Export::Procedure(proc) => {
                let docs = proc.docs().map(|d| d.to_string());
                procedures.push((name.name().to_string(), docs));
            },
            ast::Export::Alias(alias) => {
                // Ignore undocumented aliases, as they may not be procedure items
                if let Some(docs) = alias.docs() {
                    procedures.push((name.name().to_string(), Some(docs.to_string())));
                }
            },
            // TODO: Update doc format to allow for other item types
            ast::Export::Constant(_) | ast::Export::Type(_) => continue,
        }
    }

    Ok((module_docs, procedures))
}

// PRE-PROCESSING
// ================================================================================================

/// Read and parse the contents from `./asm` into a `LibraryContents` struct, serializing it into
/// `assets` folder under `core` namespace.
fn main() -> Result<(), Report> {
    use miden_assembly::diagnostics::reporting::ReportHandlerOpts;

    // re-build the `[OUT_DIR]/assets/core.masl` file iff something in the `./asm` directory
    // or its builder changed:
    println!("cargo:rerun-if-changed=asm");
    println!("cargo:rerun-if-env-changed=MIDEN_BUILD_LIB_DOCS");
    println!("cargo:rerun-if-changed=../assembly/src");

    miden_assembly::diagnostics::reporting::set_hook(Box::new(|_| {
        Box::new(ReportHandlerOpts::new().build())
    }))
    .unwrap();
    miden_assembly::diagnostics::reporting::set_panic_hook();

    // Enable debug tracing to stderr via the MIDEN_LOG environment variable, if present
    env_logger::Builder::from_env("MIDEN_LOG").format_timestamp(None).init();

    // Build core library
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let asm_dir = Path::new(manifest_dir).join(ASM_DIR_PATH);

    let assembler = Assembler::default();
    let namespace = "::miden::core".parse::<masm::PathBuf>().expect("invalid base namespace");
    let core_lib = assembler.assemble_library_from_dir(&asm_dir, namespace)?;
    // write the masl output
    let build_dir = env::var("OUT_DIR").unwrap();
    let build_dir = Path::new(&build_dir);
    let output_file = build_dir
        .join(ASL_DIR_PATH)
        .join("core")
        .with_extension(Library::LIBRARY_EXTENSION);
    core_lib
        .write_to_file(output_file)
        .map_err(|e| io::Error::other(e.to_string()))
        .into_diagnostic()?;

    // Generate documentation
    if std::env::var("MIDEN_BUILD_LIB_DOCS").is_ok() {
        build_core_lib_docs(&asm_dir, DOC_DIR_PATH).into_diagnostic()?;
    }

    Ok(())
}
