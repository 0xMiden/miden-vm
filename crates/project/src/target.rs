use alloc::{borrow::Cow, boxed::Box};

use miden_assembly_syntax::Path;

use crate::*;

/// Represents build target configuration
#[derive(Debug, Clone)]
pub struct Target {
    pub ty: TargetType,
    /// The effective name of this target
    ///
    /// If unspecified in the project file, the name is the same as `namespace`
    ///
    /// The name must be unique within a project
    pub name: Span<Arc<str>>,
    /// The namespace root for this target
    pub namespace: Span<Arc<Path>>,
    /// The path from the project manifest to the root source file for this target
    ///
    /// If not provided, it is expected that source modules will be provided to the assembler
    /// through other means. For example, `midenc` will compile Rust code to MASM, and then provide
    /// the MASM modules to an instantiated assembler when assembling this project.
    pub path: Option<Span<Uri>>,
}

impl Target {
    /// Construct a new virtual executable target named `name`
    pub fn executable(name: impl Into<Arc<str>>) -> Self {
        Self::r#virtual(TargetType::Executable, name.into(), Path::exec_path())
    }

    /// Construct a new virtual library target named `name` with namespace `namespace`
    pub fn library(name: impl Into<Arc<str>>, namespace: impl Into<Arc<Path>>) -> Self {
        Self::r#virtual(TargetType::Library, name.into(), namespace.into())
    }

    /// Construct a new virtual target of type `ty`, with the given `name` and `namespace`
    pub fn r#virtual(
        ty: TargetType,
        name: impl Into<Arc<str>>,
        namespace: impl Into<Arc<Path>>,
    ) -> Self {
        Self {
            ty,
            name: Span::unknown(name.into()),
            namespace: Span::unknown(namespace.into()),
            path: None,
        }
    }

    /// Returns true if this target is an executable target
    pub const fn is_executable(&self) -> bool {
        matches!(self.ty, TargetType::Executable)
    }

    /// Returns true if this target is a non-executable target
    pub const fn is_library(&self) -> bool {
        !self.is_executable()
    }
}

/// A [TargetSelector] is used to represent the selection of a project build target.
///
/// This is used in the [Package] API to query targets for assembly, and is defined here so that it
/// may also be used by downstream crates which need to do so as part of their own implementation.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub enum TargetSelector<'a> {
    /// Select the default target
    ///
    /// NOTE: If there are multiple targets, this selector will choose according to the following
    /// criteria:
    ///
    /// 1. If there is a single executable target, it will be chosen first. If there are multiple
    ///    executable targets, then proceed to 3.
    /// 2. If there is a single library target, it will be chosen. If there are multiple library
    ///    targets, and one of them has the default namespace and path, it will be chosen.
    ///    Otherwise, proceed to 3.
    /// 3. The selection is deemed ambiguous, and an error will be raised.
    #[default]
    Default,
    /// Select the target which matches the given target type
    ///
    /// NOTE: If there are multiple targets of the same type, you must use `Name` instead in order
    /// to disambiguate.
    Type(TargetType),
    /// Select the target whose target name matches the given string.
    ///
    /// Target names are required to be unique, so this is the most precise way to request a
    /// specific target when there are many targets of the same type.
    Name(Cow<'a, str>),
}

impl<'a> TargetSelector<'a> {
    pub fn matches(&self, target: &Target) -> bool {
        match self {
            Self::Default => true,
            Self::Type(ty) => &target.ty == ty,
            Self::Name(name) => &**target.name == name,
        }
    }

    pub fn into_owned(self) -> TargetSelector<'static> {
        match self {
            Self::Default => TargetSelector::Default,
            Self::Type(ty) => TargetSelector::Type(ty),
            Self::Name(Cow::Owned(name)) => TargetSelector::Name(Cow::Owned(name)),
            Self::Name(name) => TargetSelector::Name(Cow::Owned(name.into_owned())),
        }
    }
}

impl<'a> From<TargetType> for TargetSelector<'a> {
    fn from(ty: TargetType) -> Self {
        Self::Type(ty)
    }
}

impl<'a> From<&'a str> for TargetSelector<'a> {
    fn from(name: &'a str) -> Self {
        Self::Name(Cow::Borrowed(name))
    }
}

impl From<alloc::string::String> for TargetSelector<'static> {
    fn from(value: alloc::string::String) -> Self {
        Self::Name(Cow::Owned(value))
    }
}

impl<'a> From<&'a Path> for TargetSelector<'a> {
    fn from(path: &'a Path) -> Self {
        Self::Name(Cow::Borrowed(path.as_str()))
    }
}

impl core::fmt::Display for TargetSelector<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Default => f.write_str("default"),
            Self::Type(ty) => write!(f, "type={ty}"),
            Self::Name(name) => write!(f, "name={name}"),
        }
    }
}

/// The error type produced when a [TargetSelector] matches no build targets in a project
#[derive(Debug, thiserror::Error)]
pub enum TargetSelectionError {
    #[error("unable to select a target: project defines no targets")]
    NoTargets,
    #[error("unable to select a target: multiple targets match '{selector}'")]
    Ambiguous { selector: TargetSelector<'static> },
    #[error("unable to select a target: could not find a target with type '{0}'")]
    TypeNotFound(TargetType),
    #[error("unable to select a target: could not find a target named '{0}'")]
    NameNotFound(Box<str>),
}
