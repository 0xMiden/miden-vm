use std::{
    collections::{HashMap, HashSet},
    path::{Path as FsPath, PathBuf as FsPathBuf},
    sync::Arc,
};

use miden_assembly_syntax::{
    ast::path::PathBuf as MasmPathBuf,
    debuginfo::{DefaultSourceManager, SourceManager},
};

use super::{LibraryRoot, Program};
use crate::symbol::{path::SymbolPath, resolution::create_resolver};

/// In-memory collection of parsed modules plus the search roots used to resolve them.
#[derive(Debug)]
pub struct Workspace {
    roots: Vec<LibraryRoot>,
    source_manager: Arc<dyn SourceManager>,
    modules: Vec<Program>,
    index: HashMap<SymbolPath, usize>,
    pub(crate) proc_index: HashMap<SymbolPath, (usize, usize)>,
    pub(crate) const_index: HashMap<SymbolPath, (usize, usize)>,
}

impl Workspace {
    pub fn new(roots: Vec<LibraryRoot>) -> Self {
        let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
        Self::with_source_manager(roots, source_manager)
    }

    pub fn with_source_manager(
        roots: Vec<LibraryRoot>,
        source_manager: Arc<dyn SourceManager>,
    ) -> Self {
        Self {
            roots,
            source_manager,
            modules: Vec::new(),
            index: HashMap::new(),
            proc_index: HashMap::new(),
            const_index: HashMap::new(),
        }
    }

    /// Load the entry module from a file path. If already loaded, returns its index.
    pub fn load_entry(&mut self, path: &FsPath) -> Result<usize, String> {
        let prog = Program::from_path(path, &self.roots, self.source_manager.clone())
            .map_err(|e| e.to_string())?;
        let key = SymbolPath::new(as_str(prog.module_path()).to_string());
        if let Some(idx) = self.index.get(&key).copied() {
            return Ok(idx);
        }
        let idx = self.modules.len();
        self.modules.push(prog);
        self.index.insert(key, idx);
        self.reindex_symbols(idx);
        Ok(idx)
    }

    /// Insert a program directly (useful for in-memory tests).
    ///
    /// Note: `program` should be parsed using this workspace's source manager to
    /// ensure SourceSpan lookups resolve correctly.
    pub fn add_program(&mut self, program: Program) -> usize {
        let key = SymbolPath::new(as_str(program.module_path()).to_string());
        if let Some(idx) = self.index.get(&key).copied() {
            return idx;
        }
        let idx = self.modules.len();
        self.modules.push(program);
        self.index.insert(key, idx);
        self.reindex_symbols(idx);
        idx
    }

    /// Iteratively load modules referenced by path-based invocations until no new modules can be
    /// found.
    pub fn load_dependencies(&mut self) {
        let mut changed = true;
        while changed {
            changed = false;
            let to_load = self.collect_unloaded_dependency_modules();
            for module_path in to_load {
                if self.index.contains_key(&module_path) {
                    continue;
                }
                if let Some(idx) = self.load_module_by_path(module_path.as_str()) {
                    let _ = idx;
                    changed = true;
                }
            }
        }
    }

    /// Return unresolved module dependencies referenced by loaded modules.
    ///
    /// These are fully-qualified module paths seen in invocation targets that
    /// cannot currently be resolved to loaded modules.
    pub fn unresolved_module_paths(&self) -> Vec<SymbolPath> {
        self.collect_unloaded_dependency_modules()
    }

    /// Load a module by its absolute MASM path (e.g., `miden::core::math::u64`) if it exists on
    /// disk. Returns `None` if no matching file could be found.
    pub fn load_module_by_path(&mut self, module_path: &str) -> Option<usize> {
        let key = SymbolPath::new(module_path);
        if let Some(idx) = self.index.get(&key).copied() {
            return Some(idx);
        }
        let file = find_module_file(key.as_str(), &self.roots)?;
        let prog = Program::from_path(&file, &self.roots, self.source_manager.clone()).ok()?;
        let key = SymbolPath::new(as_str(prog.module_path()).to_string());
        let idx = self.modules.len();
        self.modules.push(prog);
        self.index.insert(key, idx);
        self.reindex_symbols(idx);
        Some(idx)
    }

    pub fn modules(&self) -> impl Iterator<Item = &Program> {
        self.modules.iter()
    }

    pub fn lookup_module(&self, module_path: &SymbolPath) -> Option<&Program> {
        let idx = self.index.get(module_path).copied()?;
        self.modules.get(idx)
    }

    pub fn lookup_proc_entry(
        &self,
        name: &SymbolPath,
    ) -> Option<(&Program, &miden_assembly_syntax::ast::Procedure)> {
        let (m_idx, p_idx) = self.proc_index.get(name).copied()?;
        let program = self.modules.get(m_idx)?;
        let proc = program.procedures().nth(p_idx)?;
        Some((program, proc))
    }

    pub fn lookup_proc(&self, name: &str) -> Option<&miden_assembly_syntax::ast::Procedure> {
        let key = SymbolPath::new(name);
        self.lookup_proc_entry(&key).map(|(_, proc)| proc)
    }

    /// Look up a constant by fully-qualified path.
    pub fn lookup_constant_entry(
        &self,
        name: &SymbolPath,
    ) -> Option<(&Program, &miden_assembly_syntax::ast::Constant)> {
        let (m_idx, c_idx) = self.const_index.get(name).copied()?;
        let program = self.modules.get(m_idx)?;
        let constant = program.constants().nth(c_idx)?;
        Some((program, constant))
    }

    /// Look up a constant by fully-qualified path string.
    pub fn lookup_constant(&self, name: &str) -> Option<&miden_assembly_syntax::ast::Constant> {
        let key = SymbolPath::new(name);
        self.lookup_constant_entry(&key).map(|(_, constant)| constant)
    }

    pub fn roots(&self) -> &[LibraryRoot] {
        &self.roots
    }

    pub fn source_manager(&self) -> Arc<dyn SourceManager> {
        self.source_manager.clone()
    }

    /// Collect referenced module paths that are not currently loaded in the workspace.
    fn collect_unloaded_dependency_modules(&self) -> Vec<SymbolPath> {
        let mut missing = HashSet::new();
        for prog in &self.modules {
            let current_module = SymbolPath::new(as_str(prog.module_path()).to_string());
            let resolver = create_resolver(prog.module(), self.source_manager());
            for proc in prog.procedures() {
                for invoke in proc.invoked() {
                    let Some(target_path) = resolver.resolve_target(&invoke.target).ok().flatten()
                    else {
                        continue;
                    };
                    let Some(module_path) = target_path.module_path() else {
                        continue;
                    };
                    let module_path = SymbolPath::new(module_path);
                    if module_path.as_str() == current_module.as_str() {
                        continue;
                    }
                    if !self.index.contains_key(&module_path) {
                        missing.insert(module_path);
                    }
                }
            }
        }
        let mut missing: Vec<_> = missing.into_iter().collect();
        missing.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        missing
    }
}

fn as_str(path: &MasmPathBuf) -> &str {
    <MasmPathBuf as AsRef<str>>::as_ref(path)
}

/// Given a fully-qualified module path and library roots, locate the corresponding file on disk.
/// Tries `<root>/<components>.masm` and `<root>/<components>/<name>/mod.masm`.
pub fn find_module_file(module_path: &str, roots: &[LibraryRoot]) -> Option<FsPathBuf> {
    for root in roots {
        let Some(relative) = root.module_relative_path(module_path) else {
            continue;
        };
        let rest: Vec<&str> = relative.split("::").filter(|c| !c.is_empty()).collect();
        if rest.is_empty() {
            continue;
        }
        let name = rest.last().unwrap();
        let dir_parts = &rest[..rest.len() - 1];

        let mut direct = FsPathBuf::from(&root.path);
        for part in dir_parts {
            direct.push(part);
        }
        direct.push(format!("{name}.masm"));
        if direct.is_file() {
            return Some(direct);
        }

        let mut mod_path = FsPathBuf::from(&root.path);
        for part in rest {
            mod_path.push(part);
        }
        mod_path.push("mod.masm");
        if mod_path.is_file() {
            return Some(mod_path);
        }
    }
    None
}

fn proc_fq_name(module_path: &str, proc_name: &str) -> SymbolPath {
    SymbolPath::from_module_path_and_name(module_path, proc_name)
}

fn constant_fq_name(module_path: &str, constant_name: &str) -> SymbolPath {
    SymbolPath::from_module_path_and_name(module_path, constant_name)
}

impl Workspace {
    fn reindex_symbols(&mut self, module_idx: usize) {
        if let Some(prog) = self.modules.get(module_idx) {
            let module_path = as_str(prog.module_path());
            for (proc_idx, proc) in prog.procedures().enumerate() {
                let name = proc_fq_name(module_path, proc.name().as_str());
                self.proc_index.insert(name, (module_idx, proc_idx));
            }
            for (const_idx, constant) in prog.constants().enumerate() {
                let name = constant_fq_name(module_path, constant.name().as_str());
                self.const_index.insert(name, (module_idx, const_idx));
            }
        }
    }
}
