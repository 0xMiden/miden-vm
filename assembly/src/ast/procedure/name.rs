use alloc::{
    string::{String, ToString},
    sync::Arc,
};
use core::{
    fmt,
    hash::{Hash, Hasher},
    str::FromStr,
};

use vm_core::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

use crate::{
    LibraryNamespace, LibraryPath, SourceSpan, Span, Spanned,
    ast::{CaseKindError, Ident, IdentError},
    diagnostics::{IntoDiagnostic, Report},
};

// QUALIFIED PROCEDURE NAME
// ================================================================================================

/// Represents a qualified procedure name, e.g. `std::math::u64::add`, parsed into it's
/// constituent [LibraryPath] and [ProcedureName] components.
///
/// A qualified procedure name can be context-sensitive, i.e. the module path might refer
/// to an imported
#[derive(Clone)]
#[cfg_attr(feature = "testing", derive(proptest_derive::Arbitrary))]
pub struct QualifiedProcedureName {
    /// The source span associated with this identifier.
    #[cfg_attr(feature = "testing", proptest(value = "SourceSpan::default()"))]
    pub span: SourceSpan,
    /// The module path for this procedure.
    pub module: LibraryPath,
    /// The name of the procedure.
    pub name: ProcedureName,
}

impl QualifiedProcedureName {
    /// Create a new [QualifiedProcedureName] with the given fully-qualified module path
    /// and procedure name.
    pub fn new(module: LibraryPath, name: ProcedureName) -> Self {
        Self {
            span: SourceSpan::default(),
            module,
            name,
        }
    }

    /// Returns the namespace of this fully-qualified procedure name.
    pub fn namespace(&self) -> &LibraryNamespace {
        self.module.namespace()
    }
}

impl FromStr for QualifiedProcedureName {
    type Err = Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.rsplit_once("::") {
            None => Err(Report::msg("invalid fully-qualified procedure name, expected namespace")),
            Some((path, name)) => {
                let name = name.parse::<ProcedureName>().into_diagnostic()?;
                let path = path.parse::<LibraryPath>().into_diagnostic()?;
                Ok(Self::new(path, name))
            },
        }
    }
}

impl Eq for QualifiedProcedureName {}

impl PartialEq for QualifiedProcedureName {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.module == other.module
    }
}

impl Ord for QualifiedProcedureName {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.module.cmp(&other.module).then_with(|| self.name.cmp(&other.name))
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
        f.debug_struct("FullyQualifiedProcedureName")
            .field("module", &self.module)
            .field("name", &self.name)
            .finish()
    }
}

impl crate::prettier::PrettyPrint for QualifiedProcedureName {
    fn render(&self) -> vm_core::prettier::Document {
        use crate::prettier::*;

        display(self)
    }
}

impl fmt::Display for QualifiedProcedureName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}::{}", &self.module, &self.name)
    }
}

impl Serializable for QualifiedProcedureName {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.module.write_into(target);
        self.name.write_into(target);
    }
}

impl Deserializable for QualifiedProcedureName {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let module = LibraryPath::read_from(source)?;
        let name = ProcedureName::read_from(source)?;
        Ok(Self::new(module, name))
    }
}

// PROCEDURE NAME
// ================================================================================================

/// Procedure name.
///
/// The symbol represented by this type must comply with the following rules:
///
/// - It must start with an ASCII alphabetic character, or one of: `_`, `.`, or `$`
/// - If it starts with a non-ASCII alphabetic character, it must contain at least one ASCII
///   alphabetic character, e.g. `_`, `$_` are not valid symbols, but `_a` or `$_a` are.
/// - Otherwise, the name may consist of any number of printable ASCII characters, e.g.
///   alphanumerics, punctuation, etc. Control characters and the like are explicitly not allowed.
///
/// NOTE: In Miden Assembly source files, a procedure name must be quoted in double-quotes if it
/// contains any characters other than ASCII alphanumerics, or `_`. See examples below.
///
/// ## Examples
///
/// ```masm,ignore
/// # All ASCII alphanumeric, bare identifier
/// proc.foo
///   ...
/// end
///
/// # All ASCII alphanumeric, leading underscore
/// proc._foo
///   ...
/// end
///
/// # A symbol which contains `::`, which would be treated as a namespace operator, so requires quoting
/// proc."std::foo"
///   ...
/// end
///
/// # A complex procedure name representing a monomorphized Rust function, requires quoting
/// proc."alloc::alloc::box_free::<dyn alloc::boxed::FnBox<(), Output = ()>>"
///   ...
/// end
/// ```
#[derive(Debug, Clone)]
pub struct ProcedureName(Ident);

impl ProcedureName {
    /// Reserved name for a main procedure.
    pub const MAIN_PROC_NAME: &'static str = "#main";

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
    pub fn new_unchecked(name: Ident) -> Self {
        Self(name)
    }

    /// Obtains a procedure name representing the reserved name for the executable entrypoint
    /// (i.e., `main`).
    pub fn main() -> Self {
        let name = Arc::from(Self::MAIN_PROC_NAME.to_string().into_boxed_str());
        Self(Ident::new_unchecked(Span::unknown(name)))
    }

    /// Is this the reserved name for the executable entrypoint (i.e. `main`)?
    pub fn is_main(&self) -> bool {
        self.0.as_str() == Self::MAIN_PROC_NAME
    }

    /// Returns a string reference for this procedure name.
    pub fn as_str(&self) -> &str {
        self.as_ref()
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

impl PartialEq<str> for ProcedureName {
    fn eq(&self, other: &str) -> bool {
        self.0.as_ref() == other
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
        let mut chars = s.char_indices();
        let raw = match chars.next() {
            None => Err(IdentError::Empty),
            Some((_, '"')) => loop {
                if let Some((pos, c)) = chars.next() {
                    match c {
                        '"' => {
                            if chars.next().is_some() {
                                break Err(IdentError::InvalidChars { ident: s.into() });
                            }
                            let tok = &s[1..pos];
                            break Ok(Arc::from(tok.to_string().into_boxed_str()));
                        },
                        c if c.is_alphanumeric() => continue,
                        '_' | '$' | '-' | '!' | '?' | '<' | '>' | ':' | '.' => continue,
                        _ => break Err(IdentError::InvalidChars { ident: s.into() }),
                    }
                } else {
                    break Err(IdentError::InvalidChars { ident: s.into() });
                }
            },
            Some((_, c))
                if c.is_ascii_lowercase() || c == '_' || c == '-' || c == '$' || c == '.' =>
            {
                if chars.as_str().contains(|c| match c {
                    c if c.is_ascii_alphanumeric() => false,
                    '_' | '-' | '$' | '.' => false,
                    _ => true,
                }) {
                    Err(IdentError::InvalidChars { ident: s.into() })
                } else {
                    Ok(Arc::from(s.to_string().into_boxed_str()))
                }
            },
            Some((_, c)) if c.is_ascii_uppercase() => Err(IdentError::Casing(CaseKindError::Snake)),
            Some(_) => Err(IdentError::InvalidChars { ident: s.into() }),
        }?;
        Ok(Self(Ident::new_unchecked(Span::unknown(raw))))
    }
}

impl Serializable for ProcedureName {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.as_str().write_into(target)
    }
}

impl Deserializable for ProcedureName {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let str: String = source.read()?;
        let proc_name = ProcedureName::new(str)
            .map_err(|e| DeserializationError::InvalidValue(e.to_string()))?;
        Ok(proc_name)
    }
}

// ARBITRARY IMPLEMENTATION
// ================================================================================================

#[cfg(feature = "testing")]
impl proptest::prelude::Arbitrary for ProcedureName {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;
        // see https://doc.rust-lang.org/rustc/symbol-mangling/v0.html#symbol-grammar-summary
        let all_possible_chars_in_mangled_name =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.$";
        let mangled_rustc_name = ProcedureName::new(all_possible_chars_in_mangled_name).unwrap();
        let plain = ProcedureName::new("user_func").unwrap();
        let wasm_cm_style = ProcedureName::new("kebab-case-func").unwrap();
        prop_oneof![Just(mangled_rustc_name), Just(plain), Just(wasm_cm_style)].boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

// TESTS
// ================================================================================================

// TODO(Al)
/* 
/// Tests
#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use vm_core::utils::{Deserializable, Serializable};

    use super::ProcedureName;

    proptest! {
        #[test]
        fn procedure_name_serialization_roundtrip(path in any::<ProcedureName>()) {
            let bytes = path.to_bytes();
            let deserialized = ProcedureName::read_from_bytes(&bytes).unwrap();
            assert_eq!(path, deserialized);
        }
    }
}
*/