use miden_debug_types::SourceSpan;

use crate::{ast::ItemIndex, diagnostics::Diagnostic};

/// Additional diagnostic context for a failed symbol resolution.
#[derive(Debug, Clone, Diagnostic)]
pub enum SymbolResolutionRelated {
    /// The referenced path was resolved relative to an item which is not a module.
    #[diagnostic(message = "but this item is not a module", severity = Info)]
    NotAModule {
        #[label("but this item is not a module")]
        span: SourceSpan,
    },
    /// The item to which a symbol of the wrong type resolved.
    #[diagnostic(message = "but the symbol resolved to this item", severity = Info)]
    ResolvedItem {
        #[label("but the symbol resolved to this item")]
        span: SourceSpan,
    },
    /// The definition of a private item referenced from another module.
    #[diagnostic(message = "the referenced item is private", severity = Info)]
    PrivateDefinition {
        #[label("the referenced item is private")]
        span: SourceSpan,
    },
}

/// Represents an error that occurs during symbol resolution
#[derive(Debug, Clone, thiserror::Error, Diagnostic)]
pub enum SymbolResolutionError {
    #[error("undefined symbol reference")]
    #[diagnostic(help = "maybe you are missing an import?")]
    UndefinedSymbol {
        #[label("this symbol path could not be resolved")]
        span: SourceSpan,
    },
    #[error("invalid symbol reference")]
    #[diagnostic(
        help = "references to a subpath of an imported symbol require the imported item to be a module"
    )]
    InvalidAliasTarget {
        #[label("this reference specifies a subpath relative to an import")]
        span: SourceSpan,
        #[related]
        relative_to: Option<SymbolResolutionRelated>,
    },
    #[error("invalid symbol path")]
    #[diagnostic(help = "all ancestors of a path must be modules")]
    InvalidSubPath {
        #[label("this path specifies a subpath relative to another item")]
        span: SourceSpan,
        #[related]
        relative_to: Option<SymbolResolutionRelated>,
    },
    #[error("invalid symbol reference: wrong type")]
    InvalidSymbolType {
        expected: &'static str,
        #[label("expected this symbol to reference a {expected} item")]
        span: SourceSpan,
        #[related]
        actual: Option<SymbolResolutionRelated>,
    },
    #[error("private symbol reference")]
    #[diagnostic(help = "only public items can be referenced from another module")]
    PrivateSymbol {
        #[label("this symbol is private to another module")]
        span: SourceSpan,
        #[related]
        defined: Option<SymbolResolutionRelated>,
    },
    #[error("type expression nesting depth exceeded")]
    #[diagnostic(help = "type expression nesting exceeded the maximum depth of {max_depth}")]
    TypeExpressionDepthExceeded {
        #[label("type expression nesting exceeded the configured depth limit")]
        span: SourceSpan,
        max_depth: usize,
    },
    #[error("alias expansion cycle detected")]
    #[diagnostic(help = "alias expansion encountered a cycle")]
    AliasExpansionCycle {
        #[label("this alias expansion is part of a cycle")]
        span: SourceSpan,
    },
    #[error("alias expansion depth exceeded")]
    #[diagnostic(help = "alias expansion exceeded the maximum depth of {max_depth}")]
    AliasExpansionDepthExceeded {
        #[label("alias expansion exceeded the configured depth limit")]
        span: SourceSpan,
        max_depth: usize,
    },
    #[error("too many items in module")]
    #[diagnostic(help = "break this module up into smaller modules")]
    TooManyItemsInModule {
        #[label("module item count exceeds the supported limit of {max_items}")]
        span: SourceSpan,
        max_items: usize,
    },
}

impl SymbolResolutionError {
    pub fn undefined(span: SourceSpan) -> Self {
        Self::UndefinedSymbol { span }
    }

    pub fn invalid_sub_path(span: SourceSpan, relative_to: SourceSpan) -> Self {
        Self::InvalidSubPath {
            span,
            relative_to: Some(SymbolResolutionRelated::NotAModule { span: relative_to }),
        }
    }

    pub fn invalid_symbol_type(
        span: SourceSpan,
        expected: &'static str,
        actual: SourceSpan,
    ) -> Self {
        Self::InvalidSymbolType {
            expected,
            span,
            actual: Some(SymbolResolutionRelated::ResolvedItem { span: actual }),
        }
    }

    pub fn private_symbol(span: SourceSpan, defined: SourceSpan) -> Self {
        Self::PrivateSymbol {
            span,
            defined: Some(SymbolResolutionRelated::PrivateDefinition { span: defined }),
        }
    }

    pub fn type_expression_depth_exceeded(span: SourceSpan, max_depth: usize) -> Self {
        Self::TypeExpressionDepthExceeded { span, max_depth }
    }

    pub fn alias_expansion_depth_exceeded(span: SourceSpan, max_depth: usize) -> Self {
        Self::AliasExpansionDepthExceeded { span, max_depth }
    }

    pub fn too_many_items_in_module(span: SourceSpan) -> Self {
        Self::TooManyItemsInModule { span, max_items: ItemIndex::MAX_ITEMS }
    }
}
