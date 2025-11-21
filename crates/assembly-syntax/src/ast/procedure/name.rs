use alloc::{
    string::{String, ToString},
    sync::Arc,
};
use core::{
    fmt,
    hash::{Hash, Hasher},
    ops::Deref,
    str::FromStr,
};

use miden_debug_types::{SourceSpan, Span, Spanned};
use miden_utils_diagnostics::{IntoDiagnostic, Report, miette};

use crate::{
    Path, PathBuf,
    ast::{CaseKindError, Ident, IdentError},
};

// QUALIFIED PROCEDURE NAME
// ================================================================================================

/// Represents a qualified procedure name, e.g. `std::math::u64::add`, parsed into it's
/// constituent [Path] and [ProcedureName] components.
///
/// A qualified procedure name can be context-sensitive, i.e. the module path might refer
/// to an imported
#[derive(Clone)]
#[cfg_attr(feature = "arbitrary", derive(proptest_derive::Arbitrary))]
pub struct QualifiedProcedureName {
    /// The source span associated with this identifier.
    #[cfg_attr(feature = "arbitrary", proptest(value = "SourceSpan::default()"))]
    span: SourceSpan,
    #[cfg_attr(
        feature = "arbitrary",
        proptest(strategy = "crate::arbitrary::path::path_random_length(2)")
    )]
    path: Arc<Path>,
}

impl QualifiedProcedureName {
    /// Create a new [QualifiedProcedureName] with the given fully-qualified module path
    /// and procedure name.
    pub fn new(module: impl AsRef<Path>, name: ProcedureName) -> Self {
        let span = name.span();
        let path = module.as_ref().join(name).into();
        Self { span, path }
    }

    #[inline(always)]
    pub fn with_span(mut self, span: SourceSpan) -> Self {
        self.span = span;
        self
    }

    /// Get the module/namespace of this procedure
    pub fn namespace(&self) -> &Path {
        self.path.parent().unwrap()
    }

    /// Get the name of this procedure as a `str`
    pub fn name(&self) -> &str {
        self.path.last().unwrap()
    }

    /// Get this [QualifiedProcedureName] as a [Path]
    #[inline]
    pub fn as_path(&self) -> &Path {
        &self.path
    }

    /// Get this [QualifiedProcedureName] as a `Span<&Path>`
    #[inline]
    pub fn to_spanned_path(&self) -> Span<&Path> {
        Span::new(self.span, self.as_path())
    }

    #[inline]
    pub fn into_inner(self) -> Arc<Path> {
        self.path
    }
}

impl Deref for QualifiedProcedureName {
    type Target = Path;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

impl From<Arc<Path>> for QualifiedProcedureName {
    fn from(path: Arc<Path>) -> Self {
        assert!(path.parent().is_some());
        Self { span: SourceSpan::default(), path }
    }
}

impl From<PathBuf> for QualifiedProcedureName {
    fn from(path: PathBuf) -> Self {
        assert!(path.parent().is_some());
        Self {
            span: SourceSpan::default(),
            path: path.into(),
        }
    }
}

impl From<&Path> for QualifiedProcedureName {
    fn from(path: &Path) -> Self {
        assert!(path.parent().is_some());
        Self {
            span: SourceSpan::default(),
            path: path.to_path_buf().into(),
        }
    }
}

impl From<QualifiedProcedureName> for Arc<Path> {
    fn from(value: QualifiedProcedureName) -> Self {
        value.path
    }
}

impl FromStr for QualifiedProcedureName {
    type Err = Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let path = PathBuf::new(s).into_diagnostic()?;
        if path.parent().is_none() {
            return Err(Report::msg("invalid procedure path: must be qualified with a namespace"));
        }
        ProcedureName::validate(path.last().unwrap()).into_diagnostic()?;
        Ok(Self {
            span: SourceSpan::default(),
            path: path.into(),
        })
    }
}

impl TryFrom<&str> for QualifiedProcedureName {
    type Error = Report;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        Self::from_str(name)
    }
}

impl TryFrom<String> for QualifiedProcedureName {
    type Error = Report;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        Self::from_str(&name)
    }
}

impl Eq for QualifiedProcedureName {}

impl PartialEq for QualifiedProcedureName {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl Ord for QualifiedProcedureName {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.path.cmp(&other.path)
    }
}

impl PartialOrd for QualifiedProcedureName {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl From<QualifiedProcedureName> for miette::SourceSpan {
    fn from(fqn: QualifiedProcedureName) -> Self {
        fqn.span.into()
    }
}

impl Spanned for QualifiedProcedureName {
    fn span(&self) -> SourceSpan {
        self.span
    }
}

impl fmt::Debug for QualifiedProcedureName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("QualifiedProcedureName").field("path", &self.path).finish()
    }
}

impl crate::prettier::PrettyPrint for QualifiedProcedureName {
    fn render(&self) -> miden_core::prettier::Document {
        use crate::prettier::*;

        display(self)
    }
}

impl fmt::Display for QualifiedProcedureName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.path, f)
    }
}

// PROCEDURE NAME
// ================================================================================================

/// Procedure name.
///
/// The symbol represented by this type must comply with the following rules:
///
/// - It must consist only of alphanumeric characters, or ASCII graphic characters.
/// - If it starts with a non-alphabetic character, it must contain at least one alphanumeric
///   character, e.g. `_`, `$_` are not valid procedure symbols, but `_a` or `$_a` are.
///
/// NOTE: In Miden Assembly source files, a procedure name must be quoted in double-quotes if it
/// contains any characters other than ASCII alphanumerics, or `_`. See examples below.
///
/// ## Examples
///
/// ```masm,ignore
/// # All ASCII alphanumeric, bare identifier
/// proc foo
///   ...
/// end
///
/// # All ASCII alphanumeric, leading underscore
/// proc _foo
///   ...
/// end
///
/// # A symbol which contains `::`, which would be treated as a namespace operator, so requires
/// # quoting
/// proc "std::foo"
///   ...
/// end
///
/// # A complex procedure name representing a monomorphized Rust function, requires quoting
/// proc "alloc::alloc::box_free::<dyn alloc::boxed::FnBox<(), Output = ()>>"
///   ...
/// end
/// ```
#[derive(Debug, Clone)]
pub struct ProcedureName(Ident);

impl ProcedureName {
    /// Reserved name for a main procedure.
    pub const MAIN_PROC_NAME: &'static str = Ident::MAIN;

    /// Creates a [ProcedureName] from `name`.
    pub fn new(name: impl AsRef<str>) -> Result<Self, IdentError> {
        name.as_ref().parse()
    }

    /// Creates a [ProcedureName] from `name`
    pub fn new_with_span(span: SourceSpan, name: impl AsRef<str>) -> Result<Self, IdentError> {
        name.as_ref().parse::<Self>().map(|name| name.with_span(span))
    }

    /// Sets the span for this [ProcedureName].
    pub fn with_span(self, span: SourceSpan) -> Self {
        Self(self.0.with_span(span))
    }

    /// Creates a [ProcedureName] from its raw components.
    ///
    /// It is expected that the caller has already validated that the name meets all validity
    /// criteria for procedure names, for example, the parser only lexes/parses valid identifiers,
    /// so by construction all such identifiers are valid.
    ///
    /// NOTE: This function is perma-unstable, it may be removed or modified at any time.
    pub fn from_raw_parts(name: Ident) -> Self {
        Self(name)
    }

    /// Obtains a procedure name representing the reserved name for the executable entrypoint
    /// (i.e., `main`).
    pub fn main() -> Self {
        let name = Arc::from(Self::MAIN_PROC_NAME.to_string().into_boxed_str());
        Self(Ident::from_raw_parts(Span::unknown(name)))
    }

    /// Is this the reserved name for the executable entrypoint (i.e. `main`)?
    pub fn is_main(&self) -> bool {
        self.0.as_str() == Self::MAIN_PROC_NAME
    }

    /// Returns a string reference for this procedure name.
    pub fn as_str(&self) -> &str {
        self.as_ref()
    }

    /// Returns the underlying [Ident] representation
    pub fn as_ident(&self) -> Ident {
        self.0.clone()
    }
}

impl Eq for ProcedureName {}

impl PartialEq for ProcedureName {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Ord for ProcedureName {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for ProcedureName {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for ProcedureName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Spanned for ProcedureName {
    fn span(&self) -> SourceSpan {
        self.0.span()
    }
}

impl From<ProcedureName> for miette::SourceSpan {
    fn from(name: ProcedureName) -> Self {
        name.span().into()
    }
}

impl core::ops::Deref for ProcedureName {
    type Target = str;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

impl AsRef<Ident> for ProcedureName {
    #[inline(always)]
    fn as_ref(&self) -> &Ident {
        &self.0
    }
}

impl AsRef<str> for ProcedureName {
    #[inline(always)]
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl From<ProcedureName> for Ident {
    #[inline(always)]
    fn from(name: ProcedureName) -> Self {
        name.0
    }
}

impl PartialEq<str> for ProcedureName {
    fn eq(&self, other: &str) -> bool {
        self.0.as_str() == other
    }
}

impl PartialEq<Ident> for ProcedureName {
    fn eq(&self, other: &Ident) -> bool {
        &self.0 == other
    }
}

impl fmt::Display for ProcedureName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Parsing
impl FromStr for ProcedureName {
    type Err = IdentError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let extracted = Self::validate(s)?;

        Ok(Self(Ident::from_raw_parts(Span::unknown(extracted.into()))))
    }
}

impl ProcedureName {
    fn validate(name: &str) -> Result<&str, IdentError> {
        let mut chars = name.char_indices().peekable();

        // peek the first char
        match chars.peek() {
            None => return Err(IdentError::Empty),
            Some((_, '"')) => chars.next(),
            Some((_, c)) if is_valid_unquoted_identifier_char(*c) => {
                // All character for unqouted should be valid
                let all_chars_valid =
                    chars.all(|(_, char)| is_valid_unquoted_identifier_char(char));

                if all_chars_valid {
                    return Ok(name);
                } else {
                    return Err(IdentError::InvalidChars { ident: name.into() });
                }
            },
            Some((_, c)) if c.is_ascii_uppercase() => {
                return Err(IdentError::Casing(CaseKindError::Snake));
            },
            Some(_) => return Err(IdentError::InvalidChars { ident: name.into() }),
        };

        // parsing the qouted identifier
        while let Some((pos, char)) = chars.next() {
            match char {
                '"' => {
                    if chars.next().is_some() {
                        return Err(IdentError::InvalidChars { ident: name.into() });
                    }
                    return Ok(&name[1..pos]);
                },
                c => {
                    // if char is not alphanumeric or asciigraphic then return err
                    if !(c.is_alphanumeric() || c.is_ascii_graphic()) {
                        return Err(IdentError::InvalidChars { ident: name.into() });
                    }
                },
            }
        }

        // if while loop has not returned then the qoute was not closed
        Err(IdentError::InvalidChars { ident: name.into() })
    }
}

// FROM STR HELPER
fn is_valid_unquoted_identifier_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '$' | '.')
}

// ARBITRARY IMPLEMENTATION
// ================================================================================================

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::prelude::Arbitrary for ProcedureName {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        prop_oneof![
            1 => crate::arbitrary::ident::ident_any_random_length(),
            2 => crate::arbitrary::ident::bare_ident_any_random_length(),
        ]
        .prop_map(ProcedureName)
        .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}
