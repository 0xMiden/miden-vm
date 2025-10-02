use alloc::{
    string::{String, ToString},
    sync::Arc,
};
use core::{
    fmt,
    hash::{Hash, Hasher},
    str::FromStr,
};

use miden_core::utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
use miden_debug_types::{SourceSpan, Span, Spanned};
use miden_utils_diagnostics::{IntoDiagnostic, Report, miette};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    LibraryNamespace, LibraryPath,
    ast::{CaseKindError, Ident, IdentError},
};

// QUALIFIED PROCEDURE NAME
// ================================================================================================

/// Represents a qualified procedure name, e.g. `std::math::u64::add`, parsed into it's
/// constituent [LibraryPath] and [ProcedureName] components.
///
/// A qualified procedure name can be context-sensitive, i.e. the module path might refer
/// to an imported
#[derive(Clone)]
#[cfg_attr(feature = "arbitrary", derive(proptest_derive::Arbitrary))]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_serde_test_macros::serde_test(winter_serde(true))
)]
pub struct QualifiedProcedureName {
    /// The source span associated with this identifier.
    #[cfg_attr(feature = "arbitrary", proptest(value = "SourceSpan::default()"))]
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
    fn render(&self) -> miden_core::prettier::Document {
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

#[cfg(feature = "serde")]
impl serde::Serialize for QualifiedProcedureName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            let name = format!("{}", self);
            serializer.serialize_str(&name)
        } else {
            use serde::ser::SerializeStruct;

            let mut builder = serializer.serialize_struct("QualifiedProcedureName", 2)?;
            builder.serialize_field("module", &self.module)?;
            builder.serialize_field("name", &self.name)?;
            builder.end()
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for QualifiedProcedureName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Visitor;

        if deserializer.is_human_readable() {
            let name = <&'de str as serde::Deserialize>::deserialize(deserializer)?;
            return Self::from_str(name).map_err(serde::de::Error::custom);
        }

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Module,
            Name,
        }

        struct QualifiedProcedureNameVisitor;
        impl<'de> Visitor<'de> for QualifiedProcedureNameVisitor {
            type Value = QualifiedProcedureName;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("struct QualifiedProcedureName")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let module = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let name = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                Ok(QualifiedProcedureName::new(module, name))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut module = None;
                let mut name = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Module => {
                            if module.is_some() {
                                return Err(serde::de::Error::duplicate_field("module"));
                            }
                            module = Some(map.next_value()?);
                        },
                        Field::Name => {
                            if name.is_some() {
                                return Err(serde::de::Error::duplicate_field("name"));
                            }
                            name = Some(map.next_value()?);
                        },
                    }
                }
                let module = module.ok_or_else(|| serde::de::Error::missing_field("module"))?;
                let name = name.ok_or_else(|| serde::de::Error::missing_field("name"))?;
                Ok(QualifiedProcedureName::new(module, name))
            }
        }

        deserializer.deserialize_struct(
            "QualifiedProcedureName",
            &["module", "name"],
            QualifiedProcedureNameVisitor,
        )
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
/// proc.foo
///   ...
/// end
///
/// # All ASCII alphanumeric, leading underscore
/// proc._foo
///   ...
/// end
///
/// # A symbol which contains `::`, which would be treated as a namespace operator, so requires
/// # quoting
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_serde_test_macros::serde_test(winter_serde(true))
)]
pub struct ProcedureName(Ident);

impl ProcedureName {
    /// Reserved name for a main procedure.
    pub const MAIN_PROC_NAME: &'static str = "$main";

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
        let mut chars = s.char_indices().peekable();

        // peek the first char
        match chars.peek() {
            None => return Err(IdentError::Empty),
            Some((_, '"')) => chars.next(),
            Some((_, c)) if is_valid_unquoted_identifier_char(*c) => {
                // All character for unqouted should be valid
                let all_chars_valid =
                    chars.all(|(_, char)| is_valid_unquoted_identifier_char(char));

                if all_chars_valid {
                    return Ok(Self(Ident::from_raw_parts(Span::unknown(s.into()))));
                } else {
                    return Err(IdentError::InvalidChars { ident: s.into() });
                }
            },
            Some((_, c)) if c.is_ascii_uppercase() => {
                return Err(IdentError::Casing(CaseKindError::Snake));
            },
            Some(_) => return Err(IdentError::InvalidChars { ident: s.into() }),
        };

        // parsing the qouted identifier
        while let Some((pos, char)) = chars.next() {
            match char {
                '"' => {
                    if chars.next().is_some() {
                        return Err(IdentError::InvalidChars { ident: s.into() });
                    }
                    let token = &s[0..pos];
                    return Ok(Self(Ident::from_raw_parts(Span::unknown(token.into()))));
                },
                c => {
                    // if char is not alphanumeric or asciigraphic then return err
                    if !(c.is_alphanumeric() || c.is_ascii_graphic()) {
                        return Err(IdentError::InvalidChars { ident: s.into() });
                    }
                },
            }
        }

        // if while loop has not returned then the qoute was not closed
        Err(IdentError::InvalidChars { ident: s.into() })
    }
}

// FROM STR HELPER
fn is_valid_unquoted_identifier_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '$' | '.')
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

#[cfg(any(test, feature = "arbitrary"))]
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
