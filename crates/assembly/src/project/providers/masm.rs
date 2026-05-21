use alloc::collections::BTreeSet;

use super::*;

pub struct MasmSourceProvider;

impl ProjectSourceProvider for MasmSourceProvider {
    fn file_type(&self) -> &'static str {
        "masm"
    }
    fn provide_sources(
        &self,
        context: &TargetAssemblyContext<'_>,
    ) -> Result<ProjectSourceInputs, Report> {
        load_target_sources(context)
    }
    fn provide_source_provenance(
        &self,
        context: &TargetAssemblyContext<'_>,
    ) -> Result<ProjectSourceProvenanceInputs, Report> {
        resolve_target_source_paths(context)
    }
}

fn load_target_sources(context: &TargetAssemblyContext<'_>) -> Result<ProjectSourceInputs, Report> {
    let ProjectSourceProvenanceInputs { root, support } = resolve_target_source_paths(context)?;

    let TargetAssemblyContext { target, resolved_target_root, .. } = context;

    let root_dir = resolved_target_root.parent().expect("already known to have a parent");
    let root = parse_module_file(
        &root.path,
        target_root_module_kind(target.ty),
        target.namespace.inner().as_ref(),
        context,
    )?;
    let support = support
        .into_iter()
        .map(|source| {
            let relative = source.path.strip_prefix(root_dir).map_err(|error| {
                Report::msg(format!(
                    "failed to derive module path for '{}': {error}",
                    source.path.display()
                ))
            })?;
            let module_path = module_path_from_relative(target.namespace.inner(), relative)?;
            parse_module_file(&source.path, ModuleKind::Library, module_path.as_ref(), context)
        })
        .collect::<Result<Vec<_>, Report>>()?;

    Ok(ProjectSourceInputs { root, support })
}

fn resolve_target_source_paths(
    context: &TargetAssemblyContext<'_>,
) -> Result<ProjectSourceProvenanceInputs, Report> {
    let root_path = context.resolved_target_root;
    let root_dir = root_path.parent().map(FsPath::to_path_buf).ok_or_else(|| {
        Report::msg(format!("target source '{}' has no parent directory", root_path.display()))
    })?;

    let mut excluded = excluded_target_roots(context);
    excluded.insert(root_path.to_path_buf());

    let root = SourceFileProvenance::from_path(root_path.to_path_buf())?;

    let support =
        read_support_module_paths(&root_dir, context.target.namespace.inner().as_ref(), &excluded)?;

    Ok(ProjectSourceProvenanceInputs { root, support })
}

fn parse_module_file(
    source: &FsPath,
    kind: ModuleKind,
    module_path: &MasmPath,
    context: &TargetAssemblyContext<'_>,
) -> Result<Box<Module>, Report> {
    let mut parser = ModuleParser::new(kind);
    parser.set_warnings_as_errors(context.warnings_as_errors);
    parser.parse_file(module_path, source, context.source_manager.clone())
}

fn read_support_module_paths(
    root_dir: &FsPath,
    namespace: &MasmPath,
    excluded: &BTreeSet<PathBuf>,
) -> Result<Vec<SourceFileProvenance>, Report> {
    let mut paths = Vec::new();
    collect_module_files(root_dir, &mut paths)?;
    paths.sort();

    let mut modules = Vec::new();
    for path in paths {
        let canonical = path.canonicalize().map_err(|error| {
            Report::msg(format!("failed to resolve '{}': {error}", path.display()))
        })?;
        if excluded.contains(&canonical) {
            continue;
        }

        let relative = canonical.strip_prefix(root_dir).map_err(|error| {
            Report::msg(format!(
                "failed to derive module path for '{}': {error}",
                canonical.display()
            ))
        })?;

        module_path_from_relative(namespace, relative)?;

        let source = SourceFileProvenance::from_path(canonical)?;

        modules.push(source);
    }

    Ok(modules)
}

fn collect_module_files(dir: &FsPath, paths: &mut Vec<PathBuf>) -> Result<(), Report> {
    for entry in fs::read_dir(dir).map_err(|error| {
        Report::msg(format!("failed to read module directory '{}': {error}", dir.display()))
    })? {
        let entry = entry.map_err(|error| {
            Report::msg(format!("failed to read directory entry in '{}': {error}", dir.display()))
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| {
            Report::msg(format!("failed to read file type for '{}': {error}", path.display()))
        })?;

        if file_type.is_dir() {
            collect_module_files(&path, paths)?;
            continue;
        }

        if path.extension() == Some(AsRef::<std::ffi::OsStr>::as_ref(Module::FILE_EXTENSION)) {
            paths.push(path);
        }
    }

    Ok(())
}

fn excluded_target_roots(context: &TargetAssemblyContext<'_>) -> BTreeSet<PathBuf> {
    let mut excluded = BTreeSet::new();
    if context.target.is_executable()
        && let Some(lib_target) = context.package.library_target()
        && let Some(lib_target_path) = lib_target.path.to_path()
    {
        let joined = context.project_root.join(lib_target_path.as_path());
        if let Ok(canonicalized) = joined.canonicalize() {
            excluded.insert(canonicalized);
        }
    }

    for executable in context.package.executable_targets() {
        let Some(path) = executable.path.to_path() else {
            continue;
        };
        if context.target != executable.inner() {
            let joined = context.project_root.join(path);
            if let Ok(joined) = joined.canonicalize()
                && context.resolved_target_root != joined.as_path()
            {
                excluded.insert(joined);
            }
        }
    }

    excluded
}
