//! Frontend: parse MASM source into an AST module plus lightweight metadata.

use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    path::{Path as FsPath, PathBuf as FsPathBuf},
    sync::Arc,
};

use miden_assembly_syntax::{
    ModuleParser, Report,
    ast::{Module, ModuleKind, Procedure, path::PathBuf as MasmPathBuf},
    debuginfo::SourceManager,
};

mod workspace;
pub use workspace::Workspace;

/// A library root maps a MASM path prefix (e.g. `miden::core`) to a filesystem directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LibraryRoot {
    /// MASM namespace prefix served by this root.
    pub namespace: String,
    /// Filesystem directory backing this root.
    pub path: FsPathBuf,
    /// Whether this root is trusted to carry stdlib-only semantic refinements.
    pub trusted_stdlib: bool,
}

impl LibraryRoot {
    /// Create a new library root mapping.
    pub fn new(namespace: impl Into<String>, path: FsPathBuf) -> Self {
        Self {
            namespace: normalize_namespace(namespace.into()),
            path,
            trusted_stdlib: false,
        }
    }

    /// Create a trusted stdlib library root mapping.
    pub fn trusted_stdlib(namespace: impl Into<String>, path: FsPathBuf) -> Self {
        Self {
            namespace: normalize_namespace(namespace.into()),
            path,
            trusted_stdlib: true,
        }
    }

    /// Return true if `module_path` is equal to this root's namespace or nested beneath it.
    pub fn matches_module_path(&self, module_path: &str) -> bool {
        self.module_relative_path(module_path).is_some()
    }

    /// Strip this root's namespace prefix from a fully-qualified module path.
    fn module_relative_path<'a>(&self, module_path: &'a str) -> Option<&'a str> {
        let module_path = strip_leading_path_separators(module_path);
        if self.namespace.is_empty() {
            return Some(module_path);
        }
        if module_path == self.namespace {
            return Some("");
        }
        module_path
            .strip_prefix(&self.namespace)
            .and_then(|rest| rest.strip_prefix("::"))
    }
}

/// Parsed MASM module plus its filesystem origin.
#[derive(Debug)]
pub struct Program {
    module: Box<Module>,
    source_path: FsPathBuf,
    module_path: MasmPathBuf,
}

impl Program {
    pub(crate) fn from_path(
        path: impl AsRef<FsPath>,
        roots: &[LibraryRoot],
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Self, Report> {
        let path = path.as_ref();
        // Most MASM files we decompile are library-style modules (no `begin/end` wrapper).
        // Prefer the library parser; fall back to executable if needed.
        let mut parser = ModuleParser::new(ModuleKind::Library);

        let module_name = derive_module_path(path, roots).unwrap_or_else(|_| {
            fallback_module_path(path).unwrap_or_else(|_| MasmPathBuf::absolute(Module::ROOT))
        });

        let module = match parser.parse_file(&module_name, path, source_manager.clone()) {
            Ok(m) => m,
            Err(_e) => {
                // Retry as executable for files that use `begin/end` wrappers.
                let mut exec_parser = ModuleParser::new(ModuleKind::Executable);
                exec_parser.parse_file(&module_name, path, source_manager)?
            },
        };

        Ok(Self {
            module,
            source_path: path.to_path_buf(),
            module_path: module_name,
        })
    }

    pub fn module(&self) -> &Module {
        &self.module
    }

    pub(crate) fn source_path(&self) -> &FsPathBuf {
        &self.source_path
    }

    pub(crate) fn module_path(&self) -> &MasmPathBuf {
        &self.module_path
    }

    pub(crate) fn procedures(&self) -> impl Iterator<Item = &Procedure> {
        self.module.procedures()
    }
}

/// Derive a stable, unique module path for standalone files outside all configured roots.
fn fallback_module_path(file_path: &FsPath) -> Result<MasmPathBuf, String> {
    let normalized_file_path = normalize_path_for_matching(file_path)?;
    let stem = normalized_file_path.file_stem().and_then(|s| s.to_str()).unwrap_or("module");

    let mut component = String::from("file");
    for ch in stem.chars().take(48) {
        if ch.is_ascii_alphanumeric() {
            component.push('_');
            component.push(ch.to_ascii_lowercase());
        } else if ch == '_' {
            component.push('_');
        }
    }

    let mut hasher = DefaultHasher::new();
    normalized_file_path.hash(&mut hasher);
    let path_str = format!("standalone::{component}_{:016x}", hasher.finish());
    MasmPathBuf::new(&path_str).map_err(|e| format!("invalid fallback module path {path_str}: {e}"))
}

/// Derive a MASM module path (e.g. `miden::core::math::u64`) from a filesystem path and library
/// roots.
///
/// Roots are searched in order; the first that contains `file_path` is used. If no root matches,
/// returns an error.
fn derive_module_path(file_path: &FsPath, roots: &[LibraryRoot]) -> Result<MasmPathBuf, String> {
    let normalized_file_path = normalize_path_for_matching(file_path)?;
    let file_name = normalized_file_path
        .file_name()
        .and_then(|f| f.to_str())
        .ok_or_else(|| "module path derivation failed: missing file name".to_string())?;
    let is_mod = file_name == "mod.masm";

    for root in roots {
        let normalized_root_path = normalize_path_for_matching(&root.path)?;
        if let Ok(rel) = normalized_file_path.strip_prefix(&normalized_root_path) {
            let mut comps: Vec<String> = Vec::new();
            if !root.namespace.is_empty() {
                comps.push(root.namespace.clone());
            }

            let mut parts: Vec<String> =
                rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
            if parts.is_empty() {
                continue;
            }

            let file_part = parts.pop().unwrap();
            let stem = if is_mod {
                parts.pop().unwrap_or_else(|| "mod".to_string())
            } else {
                FsPath::new(&file_part)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .map(ToString::to_string)
                    .ok_or_else(|| "invalid file stem".to_string())?
            };

            comps.extend(parts);
            comps.push(stem);

            let path_str = comps.join("::");
            return MasmPathBuf::new(&path_str)
                .map_err(|e| format!("invalid module path {path_str}: {e}"));
        }
    }

    Err("module path derivation failed: file not under any library root".to_string())
}

/// Normalize a filesystem path for prefix matching during module-path derivation.
///
/// Relative paths are made absolute against the process working directory.
fn normalize_path_for_matching(path: &FsPath) -> Result<FsPathBuf, String> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    Ok(cwd.join(path))
}

/// Normalize a MASM namespace prefix used by a library root.
fn normalize_namespace(namespace: String) -> String {
    strip_leading_path_separators(&namespace).to_string()
}

/// Strip leading absolute-path separators from a MASM path string.
fn strip_leading_path_separators(mut path: &str) -> &str {
    while let Some(stripped) = path.strip_prefix("::") {
        path = stripped;
    }
    path
}
