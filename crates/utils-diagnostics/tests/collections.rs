use std::borrow::Cow;

use miden_debug_types::{SourceId, SourceSpan};
use miden_utils_diagnostics::{Diagnostic, Label};

#[derive(Debug, Diagnostic)]
enum Collections<'a> {
    Slice {
        #[label(collection)]
        labels: &'a [Label],
    },
    Boxed {
        #[label(collection)]
        labels: Box<[Label]>,
    },
    MixedSlice {
        #[label]
        span: SourceSpan,
        #[label(collection)]
        labels: &'a [Label],
    },
    MixedBoxed {
        #[label]
        span: SourceSpan,
        #[label(collection)]
        labels: Box<[Label]>,
    },
}

impl core::fmt::Display for Collections<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("collection diagnostic")
    }
}

impl core::error::Error for Collections<'_> {}

#[test]
fn derive_borrows_slices_and_boxed_slices_and_combines_them_with_other_labels() {
    let span = SourceSpan::new(SourceId::new(1), 0..1);
    let labels = [Label::new(span, "original label").primary()];
    for error in [
        Collections::Slice { labels: &labels },
        Collections::Boxed { labels: labels.clone().into() },
    ] {
        let details = error.details();
        assert!(matches!(details.labels, Cow::Borrowed(_)));
        assert_eq!(details.labels.as_ref(), &labels);
    }
    for error in [
        Collections::MixedSlice { span, labels: &labels },
        Collections::MixedBoxed { span, labels: labels.clone().into() },
    ] {
        let details = error.details();
        assert_eq!(details.labels.len(), 2);
        assert_eq!(details.labels[0].span, span);
        assert_eq!(details.labels[1], labels[0]);
    }
}
