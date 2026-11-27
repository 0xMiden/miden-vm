use std::path::{Component, Path, PathBuf};

use miden_assembly_syntax::debuginfo::Uri;
use miden_mast_package::{PackageId, debug_info::PackageDebugInfo};

const LINKED_PACKAGE_URI_SCHEME: &str = "miden-pkg";

pub(super) fn trim_paths(debug_info: &mut PackageDebugInfo, trimmer: &SourcePathTrimmer) {
    debug_info.trim_file_paths(move |path| {
        let uri = Uri::new(path);
        let trimmed = trimmer.trim_uri(&uri);
        if uri == trimmed { None } else { Some(trimmed.into()) }
    });
}

pub(crate) fn namespace_linked_source_paths(
    debug_info: &mut PackageDebugInfo,
    package: &PackageId,
) {
    debug_info.trim_file_paths(|source| {
        let uri = Uri::new(source);
        let path = uri.to_path()?;
        if path.is_absolute() {
            return None;
        }

        Some(Uri::new(format!("{LINKED_PACKAGE_URI_SCHEME}://{package}/{}", path.display())).into())
    });
}

#[derive(Debug, Clone)]
pub(super) struct SourcePathTrimmer {
    cwd: PathBuf,
}

impl SourcePathTrimmer {
    pub fn new(cwd: PathBuf) -> Self {
        let cwd = cwd.canonicalize().unwrap_or(cwd);
        Self { cwd }
    }

    fn trim_uri(&self, uri: &Uri) -> Uri {
        let Some(path) = uri.to_path() else {
            return uri.clone();
        };

        let trimmed = self.trim_path(&path);
        if trimmed == path {
            return uri.clone();
        }

        Uri::from(trimmed.as_path())
    }

    fn trim_path(&self, path: &Path) -> PathBuf {
        let absolute_path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.cwd.join(path)
        };
        let absolute_path = absolute_path.canonicalize().unwrap_or(absolute_path);
        relative_path(&absolute_path, &self.cwd).unwrap_or_else(|| path.to_path_buf())
    }
}

pub(crate) fn relative_path(path: &Path, base: &Path) -> Option<PathBuf> {
    let mut path_components = path.components().peekable();
    let mut base_components = base.components().peekable();
    while path_components.peek() == base_components.peek() {
        path_components.next();
        base_components.next();
    }

    let mut relative = PathBuf::new();
    for component in base_components {
        match component {
            Component::Normal(_) => relative.push(".."),
            Component::CurDir => {},
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    relative.extend(path_components);
    Some(relative)
}

// HELPER FUNCTIONS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use miden_mast_package::debug_info::PackageDebugInfoBuilder;

    use super::*;
    use crate::Assembler;

    #[cfg(unix)]
    const MISSING_CWD_CHILD_ENV: &str = "MIDEN_MISSING_CWD_TEST_CHILD";
    #[cfg(unix)]
    const MISSING_CWD_MARKER_ENV: &str = "MIDEN_MISSING_CWD_TEST_MARKER";
    #[cfg(unix)]
    const MISSING_CWD_CHILD_TEST: &str =
        "assembler::debuginfo::tests::source_path_trimmer_missing_cwd_child";

    #[cfg(unix)]
    #[test]
    #[ignore = "invoked by source_path_trimmer_reports_missing_cwd"]
    fn source_path_trimmer_missing_cwd_child() {
        let (Some(_), Some(marker_path)) = (
            std::env::var_os(MISSING_CWD_CHILD_ENV),
            std::env::var_os(MISSING_CWD_MARKER_ENV),
        ) else {
            return;
        };

        let cwd = tempfile::tempdir().unwrap();
        std::env::set_current_dir(cwd.path()).unwrap();
        std::fs::remove_dir(cwd.path()).unwrap();
        let current_dir_error = std::env::current_dir().unwrap_err();

        let assembler = Assembler { trim_paths: true, ..Default::default() };
        let err = assembler.source_path_trimmer().unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "failed to get current directory for debug source path trimming: \
                 {current_dir_error}"
            )
        );
        std::fs::write(marker_path, b"verified").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn source_path_trimmer_reports_missing_cwd() {
        let cwd = tempfile::tempdir().unwrap();
        let marker = tempfile::NamedTempFile::new().unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(MISSING_CWD_CHILD_TEST)
            .arg("--ignored")
            .env(MISSING_CWD_CHILD_ENV, "1")
            .env(MISSING_CWD_MARKER_ENV, marker.path())
            .current_dir(cwd.path())
            .status()
            .unwrap();
        assert!(status.success(), "missing-cwd child test failed");
        assert_eq!(std::fs::read(marker.path()).unwrap(), b"verified");
    }

    #[cfg(unix)]
    #[test]
    fn trim_paths_handles_file_uris() {
        let trimmer = SourcePathTrimmer::new(std::env::current_dir().unwrap());
        let source_path = trimmer.cwd.join("nested").join("source.masm");
        let source_uri = Uri::new(format!("file://{}", source_path.display()));

        let mut builder = PackageDebugInfoBuilder::default();
        let file_idx = builder.add_file(source_uri, None);
        let mut debug_info = builder.build();
        trim_paths(&mut debug_info, &trimmer);

        let path = debug_info.get_string(debug_info[file_idx].path_idx).unwrap();
        assert_eq!(Path::new(path.as_ref()), Path::new("nested").join("source.masm"));
    }

    #[test]
    fn trim_paths_preserves_non_file_uris() {
        let trimmer = SourcePathTrimmer::new(std::env::current_dir().unwrap());
        let source_uri = Uri::new("https://example.com/src/source.masm");

        let mut builder = PackageDebugInfoBuilder::default();
        let file_idx = builder.add_file(source_uri.clone(), None);
        let mut debug_info = builder.build();
        trim_paths(&mut debug_info, &trimmer);

        let path = debug_info.get_string(debug_info[file_idx].path_idx).unwrap();
        assert_eq!(path.as_ref(), source_uri.as_str());
    }

    #[cfg(unix)]
    #[test]
    fn trim_paths_handles_case_insensitive_file_scheme() {
        let trimmer = SourcePathTrimmer::new(std::env::current_dir().unwrap());
        let source_path = trimmer.cwd.join("nested").join("source.masm");
        let source_uri = Uri::new(format!("FILE://{}", source_path.display()));

        let mut builder = PackageDebugInfoBuilder::default();
        let file_idx = builder.add_file(source_uri, None);
        let mut debug_info = builder.build();
        trim_paths(&mut debug_info, &trimmer);

        let path = debug_info.get_string(debug_info[file_idx].path_idx).unwrap();
        assert_eq!(Path::new(path.as_ref()), Path::new("nested").join("source.masm"));
    }

    #[cfg(unix)]
    #[test]
    fn trim_paths_preserves_remote_file_authorities() {
        let trimmer = SourcePathTrimmer::new(std::env::current_dir().unwrap());
        let source_uri =
            Uri::new(format!("file://example.com{}/source.masm", trimmer.cwd.display()));

        let mut builder = PackageDebugInfoBuilder::default();
        let file_idx = builder.add_file(source_uri.clone(), None);
        let mut debug_info = builder.build();
        trim_paths(&mut debug_info, &trimmer);

        let path = debug_info.get_string(debug_info[file_idx].path_idx).unwrap();
        assert_eq!(path.as_ref(), source_uri.as_str());
    }
}
