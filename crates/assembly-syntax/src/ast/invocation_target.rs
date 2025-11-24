use alloc::sync::Arc;
use core::fmt;

use miden_debug_types::{SourceSpan, Span, Spanned};

use crate::{Path, Word, ast::Ident};

// INVOKE
// ================================================================================================

/// Represents the kind of an invocation
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum InvokeKind {
    Exec = 0,
    Call,
    SysCall,
    ProcRef,
}

impl fmt::Display for InvokeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exec => f.write_str("exec"),
            Self::Call => f.write_str("call"),
            Self::SysCall => f.write_str("syscall"),
            Self::ProcRef => f.write_str("procref"),
        }
    }
}

/// Represents a specific invocation
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Invoke {
    pub kind: InvokeKind,
    pub target: InvocationTarget,
}

impl Spanned for Invoke {
    fn span(&self) -> SourceSpan {
        self.target.span()
    }
}

impl Invoke {
    pub fn new(kind: InvokeKind, target: InvocationTarget) -> Self {
        Self { kind, target }
    }
}

// INVOCATION TARGET
// ================================================================================================

/// Describes targets of `exec`, `call`, and `syscall` instructions.
///
/// A label of an invoked procedure must comply with the following rules:
/// - It can be a hexadecimal string representing a MAST root digest ([Word]). In this case, the
///   label must start with "0x" and must be followed by a valid hexadecimal string representation
///   of an [Word].
/// - It can contain a single procedure name. In this case, the label must comply with procedure
///   name rules.
/// - It can contain module name followed by procedure name (e.g., "module::procedure"). In this
///   case both module and procedure name must comply with relevant name rules.
///
/// All other combinations will result in an error.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum InvocationTarget {
    /// An absolute procedure reference, but opaque in that we do not know where the callee is
    /// defined. However, it does not actually matter, we consider such references to be _a priori_
    /// valid.
    MastRoot(Span<Word>),
    /// A locally-defined procedure.
    Symbol(Ident),
    /// An externally-defined procedure.
    Path(Span<Arc<Path>>),
}

impl InvocationTarget {
    pub fn unwrap_path(&self) -> &Path {
        match self {
            Self::Symbol(name) => name.as_ref(),
            Self::Path(path) => path.inner().as_ref(),
            Self::MastRoot(_) => panic!("expected invocation target to be a path"),
        }
    }
}

impl Spanned for InvocationTarget {
    fn span(&self) -> SourceSpan {
        match self {
            Self::MastRoot(spanned) => spanned.span(),
            Self::Symbol(spanned) => spanned.span(),
            Self::Path(spanned) => spanned.span(),
        }
    }
}

impl crate::prettier::PrettyPrint for InvocationTarget {
    fn render(&self) -> crate::prettier::Document {
        use miden_core::utils::DisplayHex;

        use crate::prettier::*;

        match self {
            Self::MastRoot(digest) => display(DisplayHex(digest.as_bytes().as_slice())),
            Self::Symbol(name) => display(name),
            Self::Path(path) => display(path),
        }
    }
}
impl fmt::Display for InvocationTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use crate::prettier::PrettyPrint;

        self.pretty_print(f)
    }
}
