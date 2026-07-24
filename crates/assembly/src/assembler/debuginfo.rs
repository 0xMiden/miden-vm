use std::path::{Path, PathBuf};

use miden_assembly_syntax::debuginfo::{FileLineCol, Location, Uri};
use miden_mast_package::debug_info::PackageDebugInfo;

pub(super) fn trim_paths(debug_info: &mut PackageDebugInfo, trimmer: &SourcePathTrimmer) {
    debug_info.trim_file_paths(move |path| {
        let uri = Uri::new(path);
        let trimmed = trimmer.trim_uri(&uri);
        if uri == trimmed { None } else { Some(trimmed.into()) }
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
        absolute_path
            .strip_prefix(&self.cwd)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

// HELPER FUNCTIONS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_mast_package::debug_info::PackageDebugInfoBuilder;

    use super::*;

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
