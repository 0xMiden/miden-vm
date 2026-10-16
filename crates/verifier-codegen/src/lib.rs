//! Specialization of the recursive verifier MASM from the AIR definitions.
//!
//! `miden-core-lib`'s build stages its handwritten assembly tree into `OUT_DIR` with
//! [`stage_core_library`], which adds the modules rendered here from the AIR definitions and the
//! templates in `templates/`. The relation identities these modules embed are pinned in
//! `miden-air` and `miden-precompiles-air`, and the resulting verifier roots in `miden-core`.
use std::{
    fmt::Display,
    fs,
    path::{Component, Path, PathBuf},
};

mod family;
mod module_path;
mod protocol;
mod pvm;
mod pvm_ood_frames;
mod vm;

/// Generator named in the header of every rendered module.
const GENERATED_BY: &str = "miden-verifier-codegen";

/// Line of the handwritten `sys/mod.masm` that staging replaces with the verifier module
/// declarations.
const VERIFIER_MODULES_MARKER: &str = "# The `pvm` and `vm` verifier modules are declared when miden-verifier-codegen stages this tree.";

/// File that identifies a directory written by [`stage_core_library`].
const STAGING_STAMP: &str = ".miden-verifier-codegen-stage";

/// One rendered module: its path below the assembly root and its source.
pub type RenderedModule = (PathBuf, String);

/// Render every specialized verifier module from the AIR definitions and the templates.
pub fn render_verifier_masm() -> Result<Vec<RenderedModule>, String> {
    let mut modules = Vec::new();
    vm::render(&mut modules)?;
    pvm::render(&mut modules)?;
    Ok(modules)
}

/// Stage the handwritten core-library assembly tree at `source` into `destination` and add the
/// rendered verifier modules, producing a complete MASM project.
///
/// `destination` must be absent, empty, or an earlier staging output, which is recreated so no
/// module from it survives; any other directory is refused rather than overwritten.
pub fn stage_core_library(source: &Path, destination: &Path) -> Result<(), String> {
    if destination.as_os_str().is_empty() {
        return Err("the staging destination must be a directory path".into());
    }
    let (resolved_source, resolved_destination) = (resolve(source)?, resolve(destination)?);
    if resolved_destination.starts_with(&resolved_source)
        || resolved_source.starts_with(&resolved_destination)
    {
        return Err(format!(
            "the staging destination {} must not contain or lie inside the source {}",
            destination.display(),
            source.display()
        ));
    }
    if destination.exists() {
        let is_empty = fs::read_dir(destination).map_err(io_error(destination))?.next().is_none();
        if !is_empty && !destination.join(STAGING_STAMP).is_file() {
            return Err(format!(
                "{} is not empty and was not written by stage_core_library; refusing to replace it",
                destination.display()
            ));
        }
        fs::remove_dir_all(destination).map_err(io_error(destination))?;
    }
    // Stamp first, so a staging interrupted midway can be replaced by the next one.
    fs::create_dir_all(destination).map_err(io_error(destination))?;
    let stamp = destination.join(STAGING_STAMP);
    fs::write(&stamp, "").map_err(io_error(&stamp))?;
    copy_tree(source, destination)?;
    for (path, source) in render_verifier_masm()? {
        let path = destination.join(path);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(io_error(dir))?;
        }
        fs::write(&path, source).map_err(io_error(&path))?;
    }
    let sys = destination.join("sys").join("mod.masm");
    let module = fs::read_to_string(&sys).map_err(io_error(&sys))?;
    if module.matches(VERIFIER_MODULES_MARKER).count() != 1 {
        return Err(format!("{} must contain the verifier module marker once", sys.display()));
    }
    fs::write(&sys, module.replacen(VERIFIER_MODULES_MARKER, "pub mod pvm\npub mod vm", 1))
        .map_err(io_error(&sys))
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination).map_err(io_error(destination))?;
    for entry in fs::read_dir(source).map_err(io_error(source))? {
        let entry = entry.map_err(io_error(source))?;
        let target = destination.join(entry.file_name());
        if entry.file_type().map_err(io_error(&target))?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), &target).map_err(io_error(&target))?;
        }
    }
    Ok(())
}

/// Absolute form of `path` with its deepest existing ancestor canonicalized, so paths that do not
/// exist yet compare consistently with existing ones.
///
/// Components below that ancestor cannot be resolved, so they must be plain names.
fn resolve(path: &Path) -> Result<PathBuf, String> {
    let absolute = std::path::absolute(path).map_err(io_error(path))?;
    let mut existing = absolute.as_path();
    let mut missing = Vec::new();
    while !existing.exists() {
        match existing.components().next_back() {
            Some(Component::Normal(name)) => missing.push(name.to_owned()),
            _ => {
                return Err(format!(
                    "{} must not use `..` below a directory that does not exist",
                    path.display()
                ));
            },
        }
        existing = existing
            .parent()
            .ok_or_else(|| format!("{} has no existing ancestor", path.display()))?;
    }
    let mut resolved = fs::canonicalize(existing).map_err(io_error(existing))?;
    resolved.extend(missing.iter().rev());
    Ok(resolved)
}

fn io_error(path: &Path) -> impl Fn(std::io::Error) -> String + '_ {
    move |err| format!("{}: {err}", path.display())
}

fn fill(content: &mut String, name: &str, value: impl Display) -> Result<(), String> {
    let token = format!("{{{{{name}}}}}");
    if content.matches(&token).count() != 1 {
        return Err(format!("template must contain exactly one {token}"));
    }
    *content = content.replacen(&token, &value.to_string(), 1);
    Ok(())
}

fn push_module(
    modules: &mut Vec<RenderedModule>,
    relation: &str,
    name: &str,
    content: &str,
) -> Result<(), String> {
    if content.contains("{{") {
        return Err(format!("unexpanded template in {relation}/{name}"));
    }
    let header = format!("# GENERATED by `{GENERATED_BY}` — do not edit by hand.\n");
    let source = if content.starts_with(&header) {
        content.to_string()
    } else {
        format!("{header}{content}")
    };
    modules.push((Path::new("sys").join(relation).join(format!("{name}.masm")), source));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_fail_closed_on_missing_or_duplicate_fields() {
        assert!(fill(&mut "no field".into(), "FIELD", 1).is_err());
        assert!(fill(&mut "{{FIELD}}{{FIELD}}".into(), "FIELD", 1).is_err());
        let mut source = "const X = {{FIELD}} # policy".to_string();
        fill(&mut source, "FIELD", 7).unwrap();
        assert_eq!(source, "const X = 7 # policy");
    }

    #[test]
    fn rendering_expands_every_verifier_module() {
        let modules = render_verifier_masm().unwrap();
        let mut paths: Vec<_> = modules.iter().map(|(path, _)| path.clone()).collect();
        paths.sort();
        let mut expected: Vec<_> = ["vm", "pvm"]
            .into_iter()
            .flat_map(|relation| {
                ["mod", "layout", "ood_frames", "deep_queries", "constraints_eval"]
                    .map(|module| Path::new("sys").join(relation).join(format!("{module}.masm")))
            })
            .chain(
                ["aux_trace", "public_inputs"]
                    .map(|module| Path::new("sys").join("pvm").join(format!("{module}.masm"))),
            )
            .collect();
        expected.sort();
        assert_eq!(paths, expected);
        for (path, source) in &modules {
            assert!(source.starts_with("# GENERATED by"), "{} lacks its header", path.display());
            assert_eq!(
                source.matches("# GENERATED by").count(),
                1,
                "{} must carry exactly one header",
                path.display()
            );
            assert!(!source.contains("{{"), "{} has an unexpanded field", path.display());
        }
    }

    /// Staging the core library adds every rendered module and declares the verifier modules,
    /// leaving the handwritten tree untouched.
    #[test]
    fn staging_completes_the_core_library_project() {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../lib/core/asm");
        let staged = std::env::temp_dir()
            .join(format!("miden-verifier-codegen-stage-{}", std::process::id()));
        stage_core_library(&source, &staged).unwrap();
        for (path, rendered) in render_verifier_masm().unwrap() {
            assert_eq!(fs::read_to_string(staged.join(&path)).unwrap(), rendered);
            assert!(!source.join(&path).exists(), "{} is a build output", path.display());
        }
        let sys = fs::read_to_string(staged.join("sys/mod.masm")).unwrap();
        assert!(sys.contains("pub mod pvm\npub mod vm\n"));
        assert!(!sys.contains(VERIFIER_MODULES_MARKER));

        // Restaging replaces an earlier staging output.
        stage_core_library(&source, &staged).unwrap();
        fs::remove_dir_all(staged).unwrap();
    }

    /// Staging refuses destinations it did not write, so a mistyped path cannot erase them.
    #[test]
    fn staging_refuses_foreign_destinations() {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../lib/core/asm");
        assert!(stage_core_library(&source, Path::new("")).is_err());
        let foreign = std::env::temp_dir()
            .join(format!("miden-verifier-codegen-foreign-{}", std::process::id()));
        fs::create_dir_all(&foreign).unwrap();
        fs::write(foreign.join("keep"), "user data").unwrap();
        assert!(stage_core_library(&source, &foreign).is_err());
        assert_eq!(fs::read_to_string(foreign.join("keep")).unwrap(), "user data");
        assert!(stage_core_library(&source, &source).is_err());
        assert!(stage_core_library(&source, &source.join("nested")).is_err());
        assert!(!source.join("nested").exists());
        let escape = source.join("missing").join("..").join("nested");
        assert!(stage_core_library(&source, &escape).is_err());
        assert!(!source.join("missing").exists() && !source.join("nested").exists());
        assert!(stage_core_library(&source, source.parent().unwrap()).is_err());
        fs::remove_dir_all(foreign).unwrap();
    }
}
