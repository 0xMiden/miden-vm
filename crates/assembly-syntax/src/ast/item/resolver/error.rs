use alloc::sync::Arc;

use miden_debug_types::{SourceFile, SourceManager, SourceSpan};

use crate::{
    ast::ItemIndex,
    diagnostics::{Diagnostic, DiagnosticDetails, Label, RelatedLabel},
};

/// Represents an error that occurs during symbol resolution
#[derive(Debug, Clone, thiserror::Error)]
pub enum SymbolResolutionError {
    #[error("undefined symbol reference")]
    UndefinedSymbol {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
    },
    #[error("invalid symbol reference")]
    InvalidAliasTarget {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        relative_to: Option<RelatedLabel>,
    },
    #[error("invalid symbol path")]
    InvalidSubPath {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        relative_to: Option<RelatedLabel>,
    },
    #[error("invalid symbol reference: wrong type")]
    InvalidSymbolType {
        expected: &'static str,
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        actual: Option<RelatedLabel>,
    },
    #[error("private symbol reference")]
    PrivateSymbol {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        defined: Option<RelatedLabel>,
    },
    #[error("type expression nesting depth exceeded")]
    TypeExpressionDepthExceeded {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        max_depth: usize,
    },
    #[error("alias expansion cycle detected")]
    AliasExpansionCycle {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
    },
    #[error("alias expansion depth exceeded")]
    AliasExpansionDepthExceeded {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        max_depth: usize,
    },
    #[error("too many items in module")]
    TooManyItemsInModule {
        span: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        max_items: usize,
    },
}

impl Diagnostic for SymbolResolutionError {
    fn details(&self) -> DiagnosticDetails<'_> {
        match self {
            Self::UndefinedSymbol { span, source_file } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(*span, "this symbol path could not be resolved")]
                    .into(),
                help: Some("maybe you are missing an import?".into()),
                ..DiagnosticDetails::default()
            },
            Self::InvalidAliasTarget { span, source_file, relative_to } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(
                    *span,
                    "this reference specifies a subpath relative to an import"
                )]
                .into(),
                help: Some(
                    "references to a subpath of an imported symbol require the imported item to \
                     be a module"
                        .into(),
                ),
                related: relative_to.iter().map(|error| error as &dyn Diagnostic).collect(),
                ..DiagnosticDetails::default()
            },
            Self::InvalidSubPath { span, source_file, relative_to } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(
                    *span,
                    "this path specifies a subpath relative to another item"
                )]
                .into(),
                help: Some("all ancestors of a path must be modules".into()),
                related: relative_to.iter().map(|error| error as &dyn Diagnostic).collect(),
                ..DiagnosticDetails::default()
            },
            Self::InvalidSymbolType { expected, span, source_file, actual } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(
                    *span,
                    format!("expected this symbol to reference a {expected} item")
                )]
                .into(),
                related: actual.iter().map(|error| error as &dyn Diagnostic).collect(),
                ..DiagnosticDetails::default()
            },
            Self::PrivateSymbol { span, source_file, defined } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(*span, "this symbol is private to another module")]
                    .into(),
                help: Some("only public items can be referenced from another module".into()),
                related: defined.iter().map(|error| error as &dyn Diagnostic).collect(),
                ..DiagnosticDetails::default()
            },
            Self::TypeExpressionDepthExceeded { span, source_file, max_depth } => {
                DiagnosticDetails {
                    source: source_file.as_deref(),
                    labels: alloc::vec![Label::new(
                        *span,
                        "type expression nesting exceeded the configured depth limit"
                    )]
                    .into(),
                    help: Some(
                        format!(
                            "type expression nesting exceeded the maximum depth of {max_depth}"
                        )
                        .into(),
                    ),
                    ..DiagnosticDetails::default()
                }
            },
            Self::AliasExpansionCycle { span, source_file } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(*span, "this alias expansion is part of a cycle")]
                    .into(),
                help: Some("alias expansion encountered a cycle".into()),
                ..DiagnosticDetails::default()
            },
            Self::AliasExpansionDepthExceeded { span, source_file, max_depth } => {
                DiagnosticDetails {
                    source: source_file.as_deref(),
                    labels: alloc::vec![Label::new(
                        *span,
                        "alias expansion exceeded the configured depth limit"
                    )]
                    .into(),
                    help: Some(
                        format!("alias expansion exceeded the maximum depth of {max_depth}").into(),
                    ),
                    ..DiagnosticDetails::default()
                }
            },
            Self::TooManyItemsInModule { span, source_file, max_items } => DiagnosticDetails {
                source: source_file.as_deref(),
                labels: alloc::vec![Label::new(
                    *span,
                    format!("module item count exceeds the supported limit of {max_items}")
                )]
                .into(),
                help: Some("break this module up into smaller modules".into()),
                ..DiagnosticDetails::default()
            },
        }
    }
}

impl SymbolResolutionError {
    pub fn undefined(span: SourceSpan, source_manager: &dyn SourceManager) -> Self {
        Self::UndefinedSymbol {
            span,
            source_file: source_manager.get(span.source_id()).ok(),
        }
    }

    pub fn invalid_sub_path(
        span: SourceSpan,
        relative_to: SourceSpan,
        source_manager: &dyn SourceManager,
    ) -> Self {
        let relative_to_source_file = source_manager.get(relative_to.source_id()).ok();
        let source_file = source_manager.get(span.source_id()).ok();
        Self::InvalidSubPath {
            span,
            source_file,
            relative_to: Some(
                RelatedLabel::advice("but this item is not a module")
                    .with_labeled_span(relative_to, "but this item is not a module")
                    .with_source_file(relative_to_source_file),
            ),
        }
    }

    pub fn invalid_symbol_type(
        span: SourceSpan,
        expected: &'static str,
        actual: SourceSpan,
        source_manager: &dyn SourceManager,
    ) -> Self {
        let actual_source_file = source_manager.get(actual.source_id()).ok();
        let source_file = source_manager.get(span.source_id()).ok();
        Self::InvalidSymbolType {
            expected,
            span,
            source_file,
            actual: Some(
                RelatedLabel::advice("but the symbol resolved to this item")
                    .with_labeled_span(actual, "but the symbol resolved to this item")
                    .with_source_file(actual_source_file),
            ),
        }
    }

    pub fn private_symbol(
        span: SourceSpan,
        defined: SourceSpan,
        source_manager: &dyn SourceManager,
    ) -> Self {
        let defined_source_file = source_manager.get(defined.source_id()).ok();
        let source_file = source_manager.get(span.source_id()).ok();
        Self::PrivateSymbol {
            span,
            source_file,
            defined: Some(
                RelatedLabel::advice("the referenced item is private")
                    .with_labeled_span(defined, "the referenced item is private")
                    .with_source_file(defined_source_file),
            ),
        }
    }

    pub fn type_expression_depth_exceeded(
        span: SourceSpan,
        max_depth: usize,
        source_manager: &dyn SourceManager,
    ) -> Self {
        Self::TypeExpressionDepthExceeded {
            span,
            source_file: source_manager.get(span.source_id()).ok(),
            max_depth,
        }
    }

    pub fn alias_expansion_depth_exceeded(
        span: SourceSpan,
        max_depth: usize,
        source_manager: &dyn SourceManager,
    ) -> Self {
        Self::AliasExpansionDepthExceeded {
            span,
            source_file: source_manager.get(span.source_id()).ok(),
            max_depth,
        }
    }

    pub fn too_many_items_in_module(span: SourceSpan, source_manager: &dyn SourceManager) -> Self {
        Self::TooManyItemsInModule {
            span,
            source_file: source_manager.get(span.source_id()).ok(),
            max_items: ItemIndex::MAX_ITEMS,
        }
    }
}
