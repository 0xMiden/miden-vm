use alloc::{boxed::Box, collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::{error::Error, fmt::Debug, num::NonZeroU32};

use miden_diagnostics::{LineColumn, Source as DiagnosticSource};

use super::*;

pub use miden_diagnostics::{SourceId, SourceKey, SourceNamespace, SourceProvider, SourceRevision};

/// The source namespace used by [`DefaultSourceManager::default`] and by the established VM span
/// wire codec, whose representation predates namespaced source identities.
///
/// Callers that combine multiple independent source universes should construct managers with
/// [`DefaultSourceManager::new`] and distinct namespaces instead of relying on this default.
pub const DEFAULT_SOURCE_NAMESPACE: SourceNamespace = SourceNamespace::new(NonZeroU32::MIN);

/// Reconstructs a source identity from the historical wire/serde representation, which stores
/// only the manager-local component.
pub(crate) const fn source_id_from_wire(local: u32) -> SourceId {
    if local == u32::MAX {
        SourceId::UNKNOWN
    } else {
        SourceId::new(DEFAULT_SOURCE_NAMESPACE, local)
    }
}

#[cfg(feature = "serde")]
pub(crate) fn serialize_source_id<S>(id: &SourceId, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serde::Serialize::serialize(&id.local(), serializer)
}

#[cfg(feature = "serde")]
pub(crate) fn deserialize_source_id<'de, D>(deserializer: D) -> Result<SourceId, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let local = <u32 as serde::Deserialize>::deserialize(deserializer)?;
    Ok(source_id_from_wire(local))
}

// SOURCE MANAGER
// ================================================================================================

/// The set of errors which may be raised by a [SourceManager]
#[derive(Debug, thiserror::Error)]
pub enum SourceManagerError {
    /// A [SourceId] was provided to a [SourceManager] which was allocated by a different
    /// [SourceManager]
    #[error("attempted to use an invalid source id")]
    InvalidSourceId,
    /// An attempt was made to read content using invalid byte indices
    #[error("attempted to read content out of bounds")]
    InvalidBounds,
    #[error(transparent)]
    InvalidContentUpdate(#[from] SourceContentUpdateError),
    /// Custom error variant for implementors of the trait.
    #[error("{error_msg}")]
    Custom {
        error_msg: Box<str>,
        // thiserror will return this when calling Error::source on SourceManagerError.
        source: Option<Box<dyn Error + Send + Sync + 'static>>,
    },
}

impl SourceManagerError {
    pub fn custom(message: String) -> Self {
        Self::Custom { error_msg: message.into(), source: None }
    }

    pub fn custom_with_source(message: String, source: impl Error + Send + Sync + 'static) -> Self {
        Self::Custom {
            error_msg: message.into(),
            source: Some(Box::new(source)),
        }
    }
}

pub trait SourceManager: SourceProvider + Debug + Send + Sync {
    /// Returns true if `file` is managed by this source manager
    fn is_manager_of(&self, file: &SourceFile) -> bool {
        match self.get_file(file.id()) {
            Ok(found) => core::ptr::addr_eq(Arc::as_ptr(&found), file),
            Err(_) => false,
        }
    }
    /// Copies `file` into this source manager (if not already managed by this manager).
    ///
    /// The returned source file is guaranteed to be owned by this manager.
    fn copy_into(&self, file: &SourceFile) -> Arc<SourceFile> {
        if let Ok(found) = self.get_file(file.id())
            && core::ptr::addr_eq(Arc::as_ptr(&found), file)
        {
            return found;
        }
        self.load_from_raw_parts(file.uri().clone(), file.content().clone())
    }
    /// Load the given `content` into this [SourceManager] with `name`
    fn load(&self, lang: SourceLanguage, name: Uri, content: String) -> Arc<SourceFile> {
        let content = SourceContent::new(lang, name.clone(), content);
        self.load_from_raw_parts(name, content)
    }
    /// Load the given `content` into this [SourceManager] with a name generated from the hash of
    /// its contents
    fn load_anonymous(&self, lang: SourceLanguage, content: String) -> Arc<SourceFile> {
        use alloc::format;

        use miden_crypto::hash::sha2::Sha256;
        let digest = Sha256::hash(content.as_bytes());
        let name = Uri::new(format!("memory://{}", String::from(digest)));
        let content = SourceContent::new(lang, name.clone(), content);
        self.load_from_raw_parts(name, content)
    }
    /// Load content into this [SourceManager] from raw [SourceFile] components
    fn load_from_raw_parts(&self, name: Uri, content: SourceContent) -> Arc<SourceFile>;
    /// Update the source file corresponding to `id` after being notified of a change event.
    ///
    /// The `version` indicates the new version of the document
    fn update(
        &self,
        id: SourceId,
        text: String,
        range: Option<Selection>,
        version: i32,
    ) -> Result<(), SourceManagerError>;
    /// Get the [SourceFile] corresponding to `id`
    fn get_file(&self, id: SourceId) -> Result<Arc<SourceFile>, SourceManagerError>;
    /// Get the most recent [SourceFile] whose URI is `uri`
    fn get_by_uri(&self, uri: &Uri) -> Option<Arc<SourceFile>> {
        self.find(uri).and_then(|id| self.get_file(id).ok())
    }
    /// Search for a source file whose URI is `uri`, and return its [SourceId] if found.
    fn find(&self, uri: &Uri) -> Option<SourceId>;
    /// Convert a [FileLineCol] to an equivalent [SourceSpan], if the referenced file is available
    fn file_line_col_to_span(&self, loc: FileLineCol) -> Option<SourceSpan>;
    /// Convert a [SourceSpan] to an equivalent [FileLineCol], if the span is valid
    fn file_line_col(&self, span: SourceSpan) -> Result<FileLineCol, SourceManagerError>;
    /// Convert a [Location] to an equivalent [SourceSpan], if the referenced file is available
    fn location_to_span(&self, loc: Location) -> Option<SourceSpan>;
    /// Convert a [SourceSpan] to an equivalent [Location], if the span is valid
    fn location(&self, span: SourceSpan) -> Result<Location, SourceManagerError>;
    /// Get the source associated with `id` as a string slice
    fn source(&self, id: SourceId) -> Result<&str, SourceManagerError>;
    /// Get the source corresponding to `span` as a string slice
    fn source_slice(&self, span: SourceSpan) -> Result<&str, SourceManagerError>;
}

impl<T: ?Sized + SourceManager> SourceManager for Arc<T> {
    #[inline(always)]
    fn is_manager_of(&self, file: &SourceFile) -> bool {
        (**self).is_manager_of(file)
    }
    #[inline(always)]
    fn copy_into(&self, file: &SourceFile) -> Arc<SourceFile> {
        (**self).copy_into(file)
    }
    #[inline(always)]
    fn load(&self, lang: SourceLanguage, uri: Uri, content: String) -> Arc<SourceFile> {
        (**self).load(lang, uri, content)
    }
    #[inline(always)]
    fn load_from_raw_parts(&self, uri: Uri, content: SourceContent) -> Arc<SourceFile> {
        (**self).load_from_raw_parts(uri, content)
    }
    #[inline(always)]
    fn update(
        &self,
        id: SourceId,
        text: String,
        range: Option<Selection>,
        version: i32,
    ) -> Result<(), SourceManagerError> {
        (**self).update(id, text, range, version)
    }
    #[inline(always)]
    fn get_file(&self, id: SourceId) -> Result<Arc<SourceFile>, SourceManagerError> {
        (**self).get_file(id)
    }
    #[inline(always)]
    fn get_by_uri(&self, uri: &Uri) -> Option<Arc<SourceFile>> {
        (**self).get_by_uri(uri)
    }
    #[inline(always)]
    fn find(&self, uri: &Uri) -> Option<SourceId> {
        (**self).find(uri)
    }
    #[inline(always)]
    fn file_line_col_to_span(&self, loc: FileLineCol) -> Option<SourceSpan> {
        (**self).file_line_col_to_span(loc)
    }
    #[inline(always)]
    fn file_line_col(&self, span: SourceSpan) -> Result<FileLineCol, SourceManagerError> {
        (**self).file_line_col(span)
    }
    #[inline(always)]
    fn location_to_span(&self, loc: Location) -> Option<SourceSpan> {
        (**self).location_to_span(loc)
    }
    #[inline(always)]
    fn location(&self, span: SourceSpan) -> Result<Location, SourceManagerError> {
        (**self).location(span)
    }
    #[inline(always)]
    fn source(&self, id: SourceId) -> Result<&str, SourceManagerError> {
        (**self).source(id)
    }
    #[inline(always)]
    fn source_slice(&self, span: SourceSpan) -> Result<&str, SourceManagerError> {
        (**self).source_slice(span)
    }
}

#[cfg(feature = "std")]
pub trait SourceManagerExt: SourceManager {
    /// Load the content of `path` into this [SourceManager]
    fn load_file(&self, path: &std::path::Path) -> Result<Arc<SourceFile>, SourceManagerError> {
        let uri = Uri::from(path);
        let content = std::fs::read_to_string(path).map_err(|source| {
            SourceManagerError::custom_with_source(
                alloc::format!("failed to load file at `{}`", path.display()),
                source,
            )
        })?;

        // Return the already-allocated file if it has already been loaded and with change since
        if let Some(existing) = self.get_by_uri(&uri)
            && existing.as_str() == content.as_str()
        {
            return Ok(existing);
        }

        let lang = match path.extension().and_then(|ext| ext.to_str()) {
            Some("masm") => "masm",
            Some("rs") => "rust",
            Some(ext) => ext,
            None => "unknown",
        };

        let content = std::fs::read_to_string(path)
            .map(|s| SourceContent::new(lang, uri.clone(), s))
            .map_err(|source| {
                SourceManagerError::custom_with_source(
                    alloc::format!("failed to load file at `{}`", path.display()),
                    source,
                )
            })?;

        Ok(self.load_from_raw_parts(uri, content))
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + SourceManager> SourceManagerExt for T {}

// DEFAULT SOURCE MANAGER
// ================================================================================================

use miden_utils_sync::RwLock;

#[derive(Debug)]
pub struct DefaultSourceManager(RwLock<DefaultSourceManagerImpl>);

impl Default for DefaultSourceManager {
    fn default() -> Self {
        Self::new(DEFAULT_SOURCE_NAMESPACE)
    }
}

impl Clone for DefaultSourceManager {
    fn clone(&self) -> Self {
        let manager = self.0.read();
        Self(RwLock::new(manager.clone()))
    }
}

impl Clone for DefaultSourceManagerImpl {
    fn clone(&self) -> Self {
        Self {
            namespace: self.namespace,
            files: self.files.clone(),
            uris: self.uris.clone(),
            retired: self.retired.clone(),
        }
    }
}

#[derive(Debug)]
struct DefaultSourceManagerImpl {
    namespace: SourceNamespace,
    files: Vec<Arc<SourceFile>>,
    uris: BTreeMap<Uri, SourceId>,
    /// Old revisions are retained so references returned from [`SourceManager::source`] and
    /// [`SourceProvider::get`] remain valid after an update.
    retired: Vec<Arc<SourceFile>>,
}

impl DefaultSourceManagerImpl {
    fn new(namespace: SourceNamespace) -> Self {
        assert!(!namespace.is_unknown(), "a source manager requires a valid namespace");
        Self {
            namespace,
            files: Vec::new(),
            uris: BTreeMap::new(),
            retired: Vec::new(),
        }
    }

    fn index_of(&self, id: SourceId) -> Option<usize> {
        if id.namespace() != self.namespace {
            return None;
        }
        usize::try_from(id.local()).ok().filter(|&index| index < self.files.len())
    }

    fn file(&self, id: SourceId) -> Option<&Arc<SourceFile>> {
        self.index_of(id).and_then(|index| self.files.get(index))
    }

    fn insert(&mut self, uri: Uri, content: SourceContent) -> Arc<SourceFile> {
        // If we have previously inserted the same content with `name`, return the previously
        // inserted source id
        if let Some(file) = self.uris.get(&uri).copied().and_then(|id| {
            let file = self.file(id)?;
            if file.as_str() == content.as_str() {
                Some(Arc::clone(file))
            } else {
                None
            }
        }) {
            return file;
        }
        let local = u32::try_from(self.files.len())
            .ok()
            .filter(|local| *local != u32::MAX)
            .expect("system limit: source manager has exhausted its supply of source ids");
        let id = SourceId::new(self.namespace, local);
        let file = Arc::new(SourceFile::from_raw_parts(id, content));
        self.files.push(Arc::clone(&file));
        self.uris.insert(uri, id);
        file
    }

    fn get_file(&self, id: SourceId) -> Result<Arc<SourceFile>, SourceManagerError> {
        self.file(id).cloned().ok_or(SourceManagerError::InvalidSourceId)
    }

    fn get_by_uri(&self, uri: &Uri) -> Option<Arc<SourceFile>> {
        self.find(uri).and_then(|id| self.get_file(id).ok())
    }

    fn find(&self, uri: &Uri) -> Option<SourceId> {
        self.uris.get(uri).copied()
    }

    fn file_line_col_to_span(&self, loc: FileLineCol) -> Option<SourceSpan> {
        let file = self.uris.get(&loc.uri).copied().and_then(|id| self.file(id))?;
        file.line_column_to_span(loc.line, loc.column)
    }

    fn file_line_col(&self, span: SourceSpan) -> Result<FileLineCol, SourceManagerError> {
        let SourceKey::Session(id) = span.source() else {
            return Err(SourceManagerError::InvalidSourceId);
        };
        self.file(id)
            .ok_or(SourceManagerError::InvalidSourceId)
            .map(|file| file.location(span))
    }

    fn location_to_span(&self, loc: Location) -> Option<SourceSpan> {
        let file = self.uris.get(&loc.uri).copied().and_then(|id| self.file(id))?;

        let max_len = ByteIndex::from(file.as_str().len() as u32);
        if loc.start >= max_len || loc.end > max_len {
            return None;
        }

        let range = miden_diagnostics::TextRange::new(loc.start.to_u32(), loc.end.to_u32()).ok()?;
        Some(SourceSpan::session(file.id(), range))
    }

    fn location(&self, span: SourceSpan) -> Result<Location, SourceManagerError> {
        let SourceKey::Session(id) = span.source() else {
            return Err(SourceManagerError::InvalidSourceId);
        };
        self.file(id).ok_or(SourceManagerError::InvalidSourceId).map(|file| {
            let range = span.range();
            Location::new(
                file.uri().clone(),
                ByteIndex::new(range.start()),
                ByteIndex::new(range.end()),
            )
        })
    }
}

impl DefaultSourceManager {
    /// Constructs an empty source manager in `namespace`.
    pub fn new(namespace: SourceNamespace) -> Self {
        Self(RwLock::new(DefaultSourceManagerImpl::new(namespace)))
    }

    /// Returns the namespace allocated to source identities created by this manager.
    pub fn namespace(&self) -> SourceNamespace {
        self.0.read().namespace
    }
}

impl SourceManager for DefaultSourceManager {
    fn load_from_raw_parts(&self, uri: Uri, content: SourceContent) -> Arc<SourceFile> {
        let mut manager = self.0.write();
        manager.insert(uri, content)
    }

    fn update(
        &self,
        id: SourceId,
        text: String,
        range: Option<Selection>,
        version: i32,
    ) -> Result<(), SourceManagerError> {
        let mut manager = self.0.write();
        let index = manager.index_of(id).ok_or(SourceManagerError::InvalidSourceId)?;
        let old = Arc::clone(&manager.files[index]);
        let mut updated = old.as_ref().clone();
        updated
            .content_mut()
            .update(text, range, version)
            .map_err(SourceManagerError::InvalidContentUpdate)?;
        manager.files[index] = Arc::new(updated);
        manager.retired.push(old);
        Ok(())
    }

    fn get_file(&self, id: SourceId) -> Result<Arc<SourceFile>, SourceManagerError> {
        let manager = self.0.read();
        manager.get_file(id)
    }

    fn get_by_uri(&self, uri: &Uri) -> Option<Arc<SourceFile>> {
        let manager = self.0.read();
        manager.get_by_uri(uri)
    }

    fn find(&self, uri: &Uri) -> Option<SourceId> {
        let manager = self.0.read();
        manager.find(uri)
    }

    fn file_line_col_to_span(&self, loc: FileLineCol) -> Option<SourceSpan> {
        let manager = self.0.read();
        manager.file_line_col_to_span(loc)
    }

    fn file_line_col(&self, span: SourceSpan) -> Result<FileLineCol, SourceManagerError> {
        let manager = self.0.read();
        manager.file_line_col(span)
    }

    fn location_to_span(&self, loc: Location) -> Option<SourceSpan> {
        let manager = self.0.read();
        manager.location_to_span(loc)
    }

    fn location(&self, span: SourceSpan) -> Result<Location, SourceManagerError> {
        let manager = self.0.read();
        manager.location(span)
    }

    fn source(&self, id: SourceId) -> Result<&str, SourceManagerError> {
        let manager = self.0.read();
        let ptr = manager
            .file(id)
            .ok_or(SourceManagerError::InvalidSourceId)
            .map(|file| file.as_str() as *const str)?;
        drop(manager);
        // SAFETY: Because the lifetime of the returned reference is bound to the manager, and
        // because we can only ever add files, not modify/remove them, this is safe. Exclusive
        // access to the manager does _not_ mean exclusive access to the contents of previously
        // added source files
        Ok(unsafe { &*ptr })
    }

    fn source_slice(&self, span: SourceSpan) -> Result<&str, SourceManagerError> {
        let SourceKey::Session(id) = span.source() else {
            return Err(SourceManagerError::InvalidSourceId);
        };
        self.source(id)?
            .get(span.range().into_slice_index())
            .ok_or(SourceManagerError::InvalidBounds)
    }
}

impl SourceProvider for DefaultSourceManager {
    fn get(&self, id: SourceId) -> Option<DiagnosticSource<'_>> {
        let manager = self.0.read();
        let file = manager.file(id)?;
        let display_name = file.uri().as_str() as *const str;
        let text = file.as_str() as *const str;
        let revision = (file.content().version() >= 0)
            .then(|| SourceRevision(file.content().version() as u32));
        let byte_len = u32::try_from(file.len()).ok()?;
        drop(manager);

        // SAFETY: source file allocations are immutable. Updates replace the current allocation
        // and retain the old allocation in `retired`; insertions never remove allocations. Both
        // references remain valid for the lifetime borrowed from this manager.
        Some(DiagnosticSource {
            id,
            display_name: unsafe { &*display_name },
            byte_len,
            text: Some(unsafe { &*text }),
            revision,
        })
    }

    fn line_column(&self, id: SourceId, offset: u32) -> Option<LineColumn> {
        let manager = self.0.read();
        let file = manager.file(id)?;
        let location = file.content().location(ByteIndex::new(offset))?;
        LineColumn::new(location.line.to_u32(), location.column.to_u32())
    }
}

#[cfg(test)]
mod error_assertions {
    use super::*;

    /// Asserts at compile time that the passed error has Send + Sync + 'static bounds.
    fn _assert_error_is_send_sync_static<E: Error + Send + Sync + 'static>(_: E) {}

    fn _assert_source_manager_error_bounds(err: SourceManagerError) {
        _assert_error_is_send_sync_static(err);
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU32;

    use super::*;

    #[test]
    fn managers_reject_foreign_namespaced_ids() {
        let first = DefaultSourceManager::new(SourceNamespace::new(NonZeroU32::new(2).unwrap()));
        let second = DefaultSourceManager::new(SourceNamespace::new(NonZeroU32::new(3).unwrap()));
        let first_file = first.load(SourceLanguage::Masm, Uri::new("first.masm"), "a".into());
        let second_file = second.load(SourceLanguage::Masm, Uri::new("second.masm"), "b".into());

        assert_eq!(first_file.id().local(), second_file.id().local());
        assert_ne!(first_file.id(), second_file.id());
        assert!(matches!(
            first.get_file(second_file.id()),
            Err(SourceManagerError::InvalidSourceId)
        ));
        assert!(matches!(
            second.get_file(first_file.id()),
            Err(SourceManagerError::InvalidSourceId)
        ));
    }

    #[test]
    fn source_provider_tracks_revisions_without_invalidating_old_borrows() {
        let manager = DefaultSourceManager::default();
        let file = manager.load(SourceLanguage::Masm, Uri::new("test.masm"), "begin\nend\n".into());

        let before = SourceProvider::get(&manager, file.id()).unwrap();
        assert_eq!(before.text, Some("begin\nend\n"));
        assert_eq!(before.revision, Some(SourceRevision(0)));

        manager.update(file.id(), "push.1\n".into(), None, 4).unwrap();

        // The provider contract permits retaining a resolved source while newer revisions arrive.
        assert_eq!(before.text, Some("begin\nend\n"));
        let after = SourceProvider::get(&manager, file.id()).unwrap();
        assert_eq!(after.text, Some("push.1\n"));
        assert_eq!(after.revision, Some(SourceRevision(4)));
    }
}
