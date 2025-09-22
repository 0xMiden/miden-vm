use alloc::{collections::BTreeSet, string::String};
use core::fmt;

use miden_debug_types::{SourceSpan, Span, Spanned};

use super::ProcedureName;
use crate::ast::{Attribute, AttributeSet, Block, DocString, FunctionType, Invoke};

// PROCEDURE VISIBILITY
// ================================================================================================

/// Represents the visibility of a procedure globally.
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum Visibility {
    /// The procedure is visible for call/exec.
    Public = 0,
    /// The procedure is visible to syscalls only.
    Syscall = 1,
    /// The procedure is visible only locally to the exec instruction.
    #[default]
    Private = 2,
}

impl fmt::Display for Visibility {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_exported() {
            f.write_str("pub proc")
        } else {
            f.write_str("proc")
        }
    }
}

impl Visibility {
    /// Returns true if the procedure has been explicitly exported
    pub fn is_exported(&self) -> bool {
        matches!(self, Self::Public | Self::Syscall)
    }

    /// Returns true if the procedure is a syscall export
    pub fn is_syscall(&self) -> bool {
        matches!(self, Self::Syscall)
    }
}

// PROCEDURE
// ================================================================================================

/// Represents a concrete procedure definition in Miden Assembly syntax
#[derive(Clone)]
pub struct Procedure {
    /// The source span of the full procedure body
    span: SourceSpan,
    /// The documentation attached to this procedure
    docs: Option<DocString>,
    /// The attributes attached to this procedure
    attrs: AttributeSet,
    /// The local name of this procedure
    name: ProcedureName,
    /// The visibility of this procedure (i.e. whether it is exported or not)
    visibility: Visibility,
    /// The type signature of this procedure, if known
    ty: Option<FunctionType>,
    /// The number of locals to allocate for this procedure
    num_locals: u16,
    /// The body of the procedure
    body: Block,
    /// The set of callees for any call-like instruction in the procedure body.
    pub(super) invoked: BTreeSet<Invoke>,
}

/// Construction
impl Procedure {
    /// Creates a new [Procedure] from the given source span, visibility, name, number of locals,
    /// and code block.
    pub fn new(
        span: SourceSpan,
        visibility: Visibility,
        name: ProcedureName,
        num_locals: u16,
        body: Block,
    ) -> Self {
        Self {
            span,
            docs: None,
            attrs: Default::default(),
            name,
            visibility,
            ty: None,
            num_locals,
            invoked: Default::default(),
            body,
        }
    }

    /// Specify the type signature of this procedure
    pub fn with_signature(mut self, ty: FunctionType) -> Self {
        self.ty = Some(ty);
        self
    }

    /// Adds documentation to this procedure definition
    pub fn with_docs(mut self, docs: Option<Span<String>>) -> Self {
        self.docs = docs.map(DocString::new);
        self
    }

    /// Adds attributes to this procedure definition
    pub fn with_attributes<I>(mut self, attrs: I) -> Self
    where
        I: IntoIterator<Item = Attribute>,
    {
        self.attrs.extend(attrs);
        self
    }

    /// Override the visibility of this procedure.
    pub fn set_visibility(&mut self, visibility: Visibility) {
        self.visibility = visibility;
    }

    /// Override the type signature of this procedure.
    pub fn set_signature(&mut self, signature: FunctionType) {
        self.ty = Some(signature);
    }
}

/// Metadata
impl Procedure {
    /// Returns the name of this procedure within its containing module.
    pub fn name(&self) -> &ProcedureName {
        &self.name
    }

    /// Returns the visibility of this procedure
    pub fn visibility(&self) -> Visibility {
        self.visibility
    }

    /// Get the type signature of this procedure, if known
    pub fn signature(&self) -> Option<&FunctionType> {
        self.ty.as_ref()
    }

    /// Get the type signature of this procedure mutably, if known
    pub fn signature_mut(&mut self) -> Option<&mut FunctionType> {
        self.ty.as_mut()
    }

    /// Returns the number of locals allocated by this procedure.
    pub fn num_locals(&self) -> u16 {
        self.num_locals
    }

    /// Returns true if this procedure corresponds to the `begin`..`end` block of an executable
    /// module.
    pub fn is_entrypoint(&self) -> bool {
        self.name.is_main()
    }

    /// Returns the documentation for this procedure, if present.
    pub fn docs(&self) -> Option<Span<&str>> {
        self.docs.as_ref().map(|docstring| docstring.as_spanned_str())
    }

    /// Get the attributes attached to this procedure
    #[inline]
    pub fn attributes(&self) -> &AttributeSet {
        &self.attrs
    }

    /// Get the attributes attached to this procedure, mutably
    #[inline]
    pub fn attributes_mut(&mut self) -> &mut AttributeSet {
        &mut self.attrs
    }

    /// Returns true if this procedure has an attribute named `name`
    #[inline]
    pub fn has_attribute(&self, name: impl AsRef<str>) -> bool {
        self.attrs.has(name)
    }

    /// Returns the attribute named `name`, if present
    #[inline]
    pub fn get_attribute(&self, name: impl AsRef<str>) -> Option<&Attribute> {
        self.attrs.get(name)
    }

    /// Returns a reference to the [Block] containing the body of this procedure.
    pub fn body(&self) -> &Block {
        &self.body
    }

    /// Returns a mutable reference to the [Block] containing the body of this procedure.
    pub fn body_mut(&mut self) -> &mut Block {
        &mut self.body
    }

    /// Returns an iterator over the operations of the top-level [Block] of this procedure.
    pub fn iter(&self) -> core::slice::Iter<'_, crate::ast::Op> {
        self.body.iter()
    }

    /// Returns an iterator over the set of invocation targets of this procedure, i.e. the callees
    /// of any call instructions in the body of this procedure.
    pub fn invoked<'a, 'b: 'a>(&'b self) -> impl Iterator<Item = &'a Invoke> + 'a {
        if self.invoked.is_empty() {
            InvokedIter::Empty
        } else {
            InvokedIter::NonEmpty(self.invoked.iter())
        }
    }

    /// Extends the set of procedures known to be invoked by this procedure.
    ///
    /// This is for internal use only, and is called during semantic analysis once we've identified
    /// the set of invoked procedures for a given definition.
    pub fn extend_invoked<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = Invoke>,
    {
        self.invoked.extend(iter);
    }
}

#[doc(hidden)]
pub(crate) enum InvokedIter<'a, I: Iterator<Item = &'a Invoke> + 'a> {
    Empty,
    NonEmpty(I),
}

impl<'a, I> Iterator for InvokedIter<'a, I>
where
    I: Iterator<Item = &'a Invoke> + 'a,
{
    type Item = <I as Iterator>::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Empty => None,
            Self::NonEmpty(iter) => {
                let result = iter.next();
                if result.is_none() {
                    *self = Self::Empty;
                }
                result
            },
        }
    }
}

impl Spanned for Procedure {
    fn span(&self) -> SourceSpan {
        self.span
    }
}

impl crate::prettier::PrettyPrint for Procedure {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        let mut doc = self
            .docs
            .as_ref()
            .map(|docstring| docstring.render())
            .unwrap_or(Document::Empty);

        if !self.attrs.is_empty() {
            doc += self
                .attrs
                .iter()
                .map(|attr| attr.render())
                .reduce(|acc, attr| acc + nl() + attr)
                .unwrap_or(Document::Empty);
        }

        if self.is_entrypoint() {
            doc += const_text("begin");
        } else {
            match self.signature() {
                Some(sig) if sig.cc != crate::ast::types::CallConv::Fast => {
                    doc += text(format!("@callconv(\"{}\")", &sig.cc)) + nl();
                },
                _ => (),
            }
            doc += display(self.visibility) + const_text(" ") + display(&self.name);
            if self.num_locals > 0 {
                doc += const_text(".") + display(self.num_locals);
            }
            if let Some(sig) = self.signature() {
                doc += sig.render();
            }
        }

        doc + self.body.render() + const_text("end") + nl()
    }
}

impl fmt::Debug for Procedure {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Procedure")
            .field("docs", &self.docs)
            .field("attrs", &self.attrs)
            .field("name", &self.name)
            .field("visibility", &self.visibility)
            .field("num_locals", &self.num_locals)
            .field("ty", &self.ty)
            .field("body", &self.body)
            .field("invoked", &self.invoked)
            .finish()
    }
}

impl Eq for Procedure {}

impl PartialEq for Procedure {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.visibility == other.visibility
            && self.num_locals == other.num_locals
            && self.ty == other.ty
            && self.body == other.body
            && self.attrs == other.attrs
            && self.docs == other.docs
    }
}
