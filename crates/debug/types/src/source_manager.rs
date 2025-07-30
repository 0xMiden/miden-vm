use alloc::{boxed::Box, collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::{error::Error, fmt::Debug};

use super::*;

// SOURCE ID
// ================================================================================================

/// A [SourceId] represents the index/identifier associated with a unique source file in a
/// [SourceManager] implementation.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct SourceId(u32);

impl Default for SourceId {
    fn default() -> Self {
        Self::UNKNOWN
    }
}

impl SourceId {
    pub const UNKNOWN: Self = Self(u32::MAX);

    /// Create a new [SourceId] from a `u32` value, but assert if the value is reserved
    pub fn new(id: u32) -> Self {
        assert_ne!(id, u32::MAX, "u32::MAX is a reserved value for SourceId::default()/UNKNOWN");

        Self(id)
    }

    /// Create a new [SourceId] from a raw `u32` value
    #[inline(always)]
    pub const fn new_unchecked(id: u32) -> Self {
        Self(id)
    }

    #[inline(always)]
    pub const fn to_usize(self) -> usize {
        self.0 as usize
    }

    #[inline(always)]
    pub const fn to_u32(self) -> u32 {
        self.0
    }

    pub const fn is_unknown(&self) -> bool {
        self.0 == u32::MAX
    }
}

impl TryFrom<usize> for SourceId {
    type Error = ();

    #[inline]
    fn try_from(id: usize) -> Result<Self, Self::Error> {
        match u32::try_from(id) {
            Ok(n) if n < u32::MAX => Ok(Self(n)),
            _ => Err(()),
        }
    }
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

pub trait SourceManager: Debug {
    /// Returns true if `file` is managed by this source manager
    fn is_manager_of(&self, file: &SourceFile) -> bool {
        match self.get(file.id()) {
            Ok(found) => core::ptr::addr_eq(Arc::as_ptr(&found), file),
            Err(_) => false,
        }
    }
    /// Copies `file` into this source manager (if not already managed by this manager).
    ///
    /// The returned source file is guaranteed to be owned by this manager.
    fn copy_into(&self, file: &SourceFile) -> Arc<SourceFile> {
        if let Ok(found) = self.get(file.id())
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
    fn get(&self, id: SourceId) -> Result<Arc<SourceFile>, SourceManagerError>;
    /// Get the most recent [SourceFile] whose URI is `uri`
    fn get_by_uri(&self, uri: &Uri) -> Option<Arc<SourceFile>> {
        self.find(uri).and_then(|id| self.get(id).ok())
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
    fn get(&self, id: SourceId) -> Result<Arc<SourceFile>, SourceManagerError> {
        (**self).get(id)
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
        if let Some(existing) = self.get_by_uri(&uri) {
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
                    alloc::format!("failed to load filed at `{}`", path.display()),
                    source,
                )
            })?;

        Ok(self.load_from_raw_parts(uri, content))
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + SourceManager> SourceManagerExt for T {}

/// [SourceManagerSync] is a marker trait for [SourceManager] implementations that are also Send +
/// Sync, and is automatically implemented for any [SourceManager] that meets those requirements.
///
/// [SourceManager] is a supertrait of [SourceManagerSync], so you may use instances of the
/// [SourceManagerSync] where the [SourceManager] is required, either implicitly or via explicit
/// downcasting, e.g. `Arc<dyn SourceManagerSync> as Arc<dyn SourceManager>`.
pub trait SourceManagerSync: SourceManager + Send + Sync {}

impl<T: ?Sized + SourceManager + Send + Sync> SourceManagerSync for T {}

// DEFAULT SOURCE MANAGER
// ================================================================================================

use miden_utils_sync::RwLock;

#[derive(Debug, Default)]
pub struct DefaultSourceManager(RwLock<DefaultSourceManagerImpl>);
impl Clone for DefaultSourceManager {
    fn clone(&self) -> Self {
        let manager = self.0.read();
        Self(RwLock::new(manager.clone()))
    }
}

#[derive(Debug, Default, Clone)]
struct DefaultSourceManagerImpl {
    files: Vec<Arc<SourceFile>>,
    uris: BTreeMap<Uri, SourceId>,
}

impl DefaultSourceManagerImpl {
    fn insert(&mut self, uri: Uri, content: SourceContent) -> Arc<SourceFile> {
        // If we have previously inserted the same content with `name`, return the previously
        // inserted source id
        if let Some(file) = self.uris.get(&uri).copied().and_then(|id| {
            let file = &self.files[id.to_usize()];
            if file.as_str() == content.as_str() {
                Some(Arc::clone(file))
            } else {
                None
            }
        }) {
            return file;
        }
        let id = SourceId::try_from(self.files.len())
            .expect("system limit: source manager has exhausted its supply of source ids");
        let file = Arc::new(SourceFile::from_raw_parts(id, content));
        self.files.push(Arc::clone(&file));
        self.uris.insert(uri.clone(), id);
        file
    }

    fn get(&self, id: SourceId) -> Result<Arc<SourceFile>, SourceManagerError> {
        self.files
            .get(id.to_usize())
            .cloned()
            .ok_or(SourceManagerError::InvalidSourceId)
    }

    fn get_by_uri(&self, uri: &Uri) -> Option<Arc<SourceFile>> {
        self.find(uri).and_then(|id| self.get(id).ok())
    }

    fn find(&self, uri: &Uri) -> Option<SourceId> {
        self.uris.get(uri).copied()
    }

    fn file_line_col_to_span(&self, loc: FileLineCol) -> Option<SourceSpan> {
        let file = self.uris.get(&loc.uri).copied().and_then(|id| self.files.get(id.to_usize()))?;
        file.line_column_to_span(loc.line, loc.column)
    }

    fn file_line_col(&self, span: SourceSpan) -> Result<FileLineCol, SourceManagerError> {
        self.files
            .get(span.source_id().to_usize())
            .ok_or(SourceManagerError::InvalidSourceId)
            .map(|file| file.location(span))
    }

    fn location_to_span(&self, loc: Location) -> Option<SourceSpan> {
        let file = self.uris.get(&loc.uri).copied().and_then(|id| self.files.get(id.to_usize()))?;

        let max_len = ByteIndex::from(file.as_str().len() as u32);
        if loc.start >= max_len || loc.end > max_len {
            return None;
        }

        Some(SourceSpan::new(file.id(), loc.start..loc.end))
    }

    fn location(&self, span: SourceSpan) -> Result<Location, SourceManagerError> {
        self.files
            .get(span.source_id().to_usize())
            .ok_or(SourceManagerError::InvalidSourceId)
            .map(|file| Location::new(file.uri().clone(), span.start(), span.end()))
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
        let source_file = manager
            .files
            .get_mut(id.to_usize())
            .ok_or(SourceManagerError::InvalidSourceId)?;
        let source_file = Arc::make_mut(source_file);
        source_file
            .content_mut()
            .update(text, range, version)
            .map_err(SourceManagerError::InvalidContentUpdate)
    }

    fn get(&self, id: SourceId) -> Result<Arc<SourceFile>, SourceManagerError> {
        let manager = self.0.read();
        manager.get(id)
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
            .files
            .get(id.to_usize())
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
        self.source(span.source_id())?
            .get(span.into_slice_index())
            .ok_or(SourceManagerError::InvalidBounds)
    }
}

#[cfg(test)]
mod error_assertions {
    use super::*;

    /// Asserts at compile time that the passed error has Send + Sync + 'static bounds.
    fn _assert_error_is_send_sync_static<E: core::error::Error + Send + Sync + 'static>(_: E) {}

    fn _assert_source_manager_error_bounds(err: SourceManagerError) {
        _assert_error_is_send_sync_static(err);
    }
}
