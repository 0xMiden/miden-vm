use alloc::sync::Arc;
use std::{
    path::{Path, PathBuf},
    string::ToString,
};

use miden_assembly_syntax::debuginfo::{FileLineCol, Location, Uri};
use miden_mast_package::debug_info::PackageDebugInfo;

pub(super) fn trim_paths(debug_info: &mut PackageDebugInfo, trimmer: &SourcePathTrimmer) {
    debug_info.trim_file_paths(move |path| {
        let new_path = trimmer.trim_path_string(path);
        if path == new_path.as_ref() {
            None
        } else {
            Some(new_path)
        }
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

    #[allow(unused)]
    pub fn trim_location(&self, mut location: Location) -> Location {
        location.uri = self.trim_uri(&location.uri);
        location
    }

    #[allow(unused)]
    pub fn trim_file_line_col(&self, mut location: FileLineCol) -> FileLineCol {
        location.uri = self.trim_uri(&location.uri);
        location
    }

    fn trim_uri(&self, uri: &Uri) -> Uri {
        let Some(path) = self.filesystem_path(uri) else {
            return uri.clone();
        };

        let trimmed = self.trim_path(path);
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
        absolute_path
            .strip_prefix(&self.cwd)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| path.to_path_buf())
    }

    fn trim_path_string(&self, path: &str) -> Arc<str> {
        Arc::from(self.trim_path(Path::new(path)).display().to_string())
    }

    fn filesystem_path<'a>(&self, uri: &'a Uri) -> Option<&'a Path> {
        match uri.scheme() {
            Some("file") | None => Some(Path::new(uri.path())),
            Some(_) => None,
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================
