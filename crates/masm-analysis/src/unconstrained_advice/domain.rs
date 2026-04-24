//! Core lattice used by the unconstrained-advice analysis.

use std::{borrow::Borrow, collections::BTreeSet};

use miden_debug_types::SourceSpan;

/// Provenance of unconstrained advice for a value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdviceFact {
    /// Concrete source spans at which unconstrained advice may have been introduced.
    pub source_spans: BTreeSet<SourceSpan>,
    /// Input positions whose unconstrained-advice facts may reach this value.
    pub from_inputs: BTreeSet<usize>,
}

impl AdviceFact {
    /// Return the bottom fact: no known unconstrained advice.
    pub fn bottom() -> Self {
        Self::default()
    }

    /// Return a fact representing locally introduced advice.
    pub fn from_source(span: SourceSpan) -> Self {
        let mut source_spans = BTreeSet::new();
        if span != SourceSpan::UNKNOWN {
            source_spans.insert(span);
        }
        Self {
            source_spans,
            from_inputs: BTreeSet::new(),
        }
    }

    /// Return a fact representing an unconstrained-advice dependency on one input.
    pub fn from_input(index: usize) -> Self {
        let mut from_inputs = BTreeSet::new();
        from_inputs.insert(index);
        Self {
            source_spans: BTreeSet::new(),
            from_inputs,
        }
    }

    /// Return true if the fact carries any unconstrained-advice provenance.
    pub fn is_tainted(&self) -> bool {
        !self.source_spans.is_empty() || !self.from_inputs.is_empty()
    }

    /// Return true if the fact has at least one concrete advice source.
    pub fn has_concrete_sources(&self) -> bool {
        !self.source_spans.is_empty()
    }

    /// Join two facts conservatively.
    pub fn join(&self, other: &Self) -> Self {
        let mut joined = self.clone();
        joined.source_spans.extend(other.source_spans.iter().copied());
        joined.from_inputs.extend(other.from_inputs.iter().copied());
        joined
    }

    /// Join another fact into this one in place.
    pub fn join_assign(&mut self, other: &Self) {
        self.source_spans.extend(other.source_spans.iter().copied());
        self.from_inputs.extend(other.from_inputs.iter().copied());
    }

    /// Join a list of facts conservatively.
    pub fn join_all<T>(facts: impl IntoIterator<Item = T>) -> Self
    where
        T: Borrow<AdviceFact>,
    {
        let mut joined = Self::bottom();
        for fact in facts {
            joined.join_assign(fact.borrow());
        }
        joined
    }
}
