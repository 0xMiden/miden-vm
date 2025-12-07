use alloc::sync::Arc;

use miden_debug_types::{SourceFile, SourceManager, SourceSpan};

use crate::diagnostics::{Diagnostic, RelatedLabel, miette};

/// Represents an error that occurs during symbol resolution
#[derive(Debug, Clone, thiserror::Error, Diagnostic)]
pub enum SymbolResolutionError {
    #[error("undefined symbol reference")]
    #[diagnostic(help("maybe you are missing an import?"))]
    UndefinedSymbol {
        #[label("this symbol path could not be resolved")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
    },
    #[error("invalid symbol reference")]
    #[diagnostic(help(
        "references to a subpath of an imported symbol require the imported item to be a module"
    ))]
    InvalidAliasTarget {
        #[label("this reference specifies a subpath relative to an import")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        #[related]
        relative_to: Option<RelatedLabel>,
    },
    #[error("invalid symbol path")]
    #[diagnostic(help("all ancestors of a path must be modules"))]
    InvalidSubPath {
        #[label("this path specifies a subpath relative to another item")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        #[related]
        relative_to: Option<RelatedLabel>,
    },
    #[error("invalid symbol reference: wrong type")]
    #[diagnostic()]
    InvalidSymbolType {
        expected: &'static str,
        #[label("expected this symbol to reference a {expected} item")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        #[related]
        actual: Option<RelatedLabel>,
    },
}

impl SymbolResolutionError {
    pub fn undefined(span: SourceSpan, source_manager: &dyn SourceManager) -> Self {
        Self::UndefinedSymbol {
            span,
            source_file: source_manager.get(span.source_id()).ok(),
        }
    }

    pub fn invalid_alias_target(
        span: SourceSpan,
        referrer: SourceSpan,
        source_manager: &dyn SourceManager,
    ) -> Self {
        let referer_source_file = source_manager.get(referrer.source_id()).ok();
        let source_file = source_manager.get(span.source_id()).ok();
        Self::InvalidAliasTarget {
            span,
            source_file,
            relative_to: Some(
                RelatedLabel::advice("this reference specifies a subpath relative to an import")
                    .with_labeled_span(
                        referrer,
                        "this reference specifies a subpath relative to an import",
                    )
                    .with_source_file(referer_source_file),
            ),
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
}
