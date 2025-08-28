use std::{
    env, fs,
    io::{self, Write},
    path::Path,
};

use miden_assembly::{
    Assembler, Library, LibraryNamespace, LibraryPath,
    ast::{Module, ModuleKind},
    debuginfo::{DefaultSourceManager, SourceFile, SourceId, SourceLanguage, Uri},
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

    // Remove the "std::" prefix
    if parts.len() > 1 && parts[0] == "std" {
        // Use the full module path without "std::" prefix, add .md extension
        format!("{}.md", parts[1..].join("/"))
    } else {
        // Fallback for modules without std:: prefix
        format!("{}.md", parts.join("/"))
    }
}

// STDLIB DOCUMENTATION
// ================================================================================================

/// Writes Miden standard library modules documentation markdown files based on the available
/// modules and comments.
pub fn build_stdlib_docs(asm_dir: &Path, output_dir: &str) -> io::Result<()> {
    // Remove docs folder to re-generate
    fs::remove_dir_all(output_dir).unwrap();
    fs::create_dir(output_dir).unwrap();

    // Find all .masm files recursively
    let modules = find_masm_modules(asm_dir, asm_dir)?;

    // Create a source manager for parsing
    let source_manager = DefaultSourceManager::default();

    // Render the modules into markdown using AST parsing
    for (label, source) in modules {
        let relative_path = markdown_file_name(&label);
        let file_path = Path::new(output_dir).join(relative_path);

        // Create directories if needed
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut f =
            fs::OpenOptions::new().write(true).create(true).truncate(true).open(file_path)?;

        // Parse module using AST-based approach
        let (module_docs, procedures) = parse_module_with_ast(&label, &source, &source_manager)?;

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
fn find_masm_modules(base_dir: &Path, current_dir: &Path) -> io::Result<Vec<(String, String)>> {
    let mut modules = Vec::new();

    if let Ok(entries) = fs::read_dir(current_dir) {
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

                    let label = format!("std::{}", module_path);
                    let source = fs::read_to_string(&path)?;

                    modules.push((label, source));
                }
            } else if path.is_dir() {
                // Recursively scan subdirectories
                modules.extend(find_masm_modules(base_dir, &path)?);
            }
        }
    }

    Ok(modules)
}

// Module doc, procedures doc
type DocPayload = (Option<String>, Vec<(String, Option<String>)>);

/// Parse MASM source using AST-parsing
fn parse_module_with_ast(
    label: &str,
    source: &str,
    _source_manager: &DefaultSourceManager,
) -> io::Result<DocPayload> {
    // Create source file directly from string
    let source_file = SourceFile::new(
        SourceId::new(1), // Simple ID for build script context
        SourceLanguage::Masm,
        Uri::from(label),
        source.to_string(),
    );

    // Create library path from module label
    let library_path = LibraryPath::new(label)
        .map_err(|e| io::Error::other(format!("Invalid library path: {}", e)))?;

    // Parse the module using AST
    let module = Module::parse(library_path, ModuleKind::Library, source_file.into())
        .map_err(|e| io::Error::other(e.to_string()));

    let module = module?;

    // Extract module documentation
    let module_docs = module.docs().map(|d| d.to_string());

    // Extract procedures and their documentation
    let mut procedures = Vec::new();
    for export in module.procedures() {
        let name = export.name().to_string();
        let docs = export.docs().map(|d| d.to_string());
        procedures.push((name, docs));
    }

    Ok((module_docs, procedures))
}

// PRE-PROCESSING
// ================================================================================================

fn main() -> io::Result<()> {
    // re-build the `[OUT_DIR]/assets/std.masl` file iff something in the `./asm` directory
    // or its builder changed:
    println!("cargo:rerun-if-changed=asm");
    println!("cargo:rerun-if-changed=../assembly/src");

    // Enable debug tracing to stderr via the MIDEN_LOG environment variable, if present
    env_logger::Builder::from_env("MIDEN_LOG").format_timestamp(None).init();

    // Build the stdlib
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let asm_dir = Path::new(manifest_dir).join(ASM_DIR_PATH);

    let assembler = Assembler::default().with_debug_mode(cfg!(feature = "with-debug-info"));
    let namespace = "std".parse::<LibraryNamespace>().expect("invalid base namespace");
    let stdlib = assembler
        .assemble_library_from_dir(&asm_dir, namespace)
        .map_err(|e| io::Error::other(e.to_string()))?;

    // write the masl output
    let build_dir = env::var("OUT_DIR").unwrap();
    let build_dir = Path::new(&build_dir);
    let output_file = build_dir
        .join(ASL_DIR_PATH)
        .join("std")
        .with_extension(Library::LIBRARY_EXTENSION);
    stdlib.write_to_file(output_file).map_err(|e| io::Error::other(e.to_string()))?;

    // Generate documentation
    build_stdlib_docs(&asm_dir, DOC_DIR_PATH)?;

    Ok(())
}
