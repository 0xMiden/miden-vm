//! Declared workload accounting for portable precompile witnesses.

use alloc::collections::BTreeMap;

/// Stable process-local identifier for one class of precompile work.
///
/// Returning the same class from multiple tags intentionally combines their accounting. The
/// identifier is not serialized and does not affect deferred commitments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkClass(&'static str);

impl WorkClass {
    /// Creates a work class with the supplied stable display name.
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    /// Returns this class's display name.
    pub const fn name(self) -> &'static str {
        self.0
    }
}

impl core::fmt::Display for WorkClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

/// Work declared by one precompile-owned node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkItem {
    class: WorkClass,
    size: u32,
}

impl WorkItem {
    /// Creates a work item. `size` is the class-specific variable dimension, such as hash input
    /// bytes or MSM terms. Fixed-size operations use one.
    pub const fn new(class: WorkClass, size: u32) -> Self {
        Self { class, size }
    }

    /// Returns the class whose limit and summary receive this item.
    pub const fn class(self) -> WorkClass {
        self.class
    }

    /// Returns the class-specific size of this item.
    pub const fn size(self) -> u32 {
        self.size
    }
}

/// Aggregate work for one class within a witness.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkSummary {
    count: u64,
    total_size: u64,
    max_size: u32,
}

impl WorkSummary {
    /// Returns the number of charged items in this class.
    pub const fn count(self) -> u64 {
        self.count
    }

    /// Returns the checked sum of item sizes in this class.
    pub const fn total_size(self) -> u64 {
        self.total_size
    }

    /// Returns the largest individual item size in this class.
    pub const fn max_size(self) -> u32 {
        self.max_size
    }

    fn checked_with(self, size: u32) -> Result<Self, PrecompileLimitError> {
        Ok(Self {
            count: self.count.checked_add(1).ok_or(PrecompileLimitError::Overflow)?,
            total_size: self
                .total_size
                .checked_add(u64::from(size))
                .ok_or(PrecompileLimitError::Overflow)?,
            max_size: self.max_size.max(size),
        })
    }
}

/// Work computed while preparing one portable witness.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrecompileWork {
    nodes: u64,
    elements: u64,
    classes: BTreeMap<WorkClass, WorkSummary>,
}

impl PrecompileWork {
    /// Returns the number of explicit nodes in the prepared witness.
    pub const fn nodes(&self) -> u64 {
        self.nodes
    }

    /// Returns the canonical field-element footprint of all explicit nodes.
    pub const fn elements(&self) -> u64 {
        self.elements
    }

    /// Returns the summary for `class`, if the witness contains that class.
    pub fn class(&self, class: WorkClass) -> Option<WorkSummary> {
        self.classes.get(&class).copied()
    }

    /// Iterates over the encountered work classes in lexical class-name order.
    pub fn classes(&self) -> impl Iterator<Item = (WorkClass, WorkSummary)> + '_ {
        self.classes.iter().map(|(&class, &summary)| (class, summary))
    }

    pub(crate) fn charge(
        &mut self,
        elements: usize,
        item: Option<WorkItem>,
        limits: &PrecompileLimits,
    ) -> Result<(), PrecompileLimitError> {
        let nodes = self.nodes.checked_add(1).ok_or(PrecompileLimitError::Overflow)?;
        let elements = self
            .elements
            .checked_add(u64::try_from(elements).map_err(|_| PrecompileLimitError::Overflow)?)
            .ok_or(PrecompileLimitError::Overflow)?;
        if elements > limits.max_elements {
            return Err(PrecompileLimitError::Elements {
                actual: elements,
                max: limits.max_elements,
            });
        }

        let next = item
            .map(|item| {
                let limit = limits
                    .classes
                    .get(&item.class)
                    .copied()
                    .ok_or(PrecompileLimitError::MissingClass { class: item.class })?;
                let summary = self
                    .classes
                    .get(&item.class)
                    .copied()
                    .unwrap_or_default()
                    .checked_with(item.size)?;
                limit.check(item.class, summary)?;
                Ok((item.class, summary))
            })
            .transpose()?;

        self.nodes = nodes;
        self.elements = elements;
        if let Some((class, summary)) = next {
            self.classes.insert(class, summary);
        }
        Ok(())
    }
}

/// Bounds for one work class within a single witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkLimit {
    max_count: u64,
    max_total_size: u64,
    max_size: u32,
}

impl WorkLimit {
    /// Creates count, aggregate-size, and individual-size bounds for one work class.
    pub const fn new(max_count: u64, max_total_size: u64, max_size: u32) -> Self {
        Self { max_count, max_total_size, max_size }
    }

    /// Returns the maximum number of items in this class.
    pub const fn max_count(self) -> u64 {
        self.max_count
    }

    /// Returns the maximum aggregate item size in this class.
    pub const fn max_total_size(self) -> u64 {
        self.max_total_size
    }

    /// Returns the maximum size of one item in this class.
    pub const fn max_size(self) -> u32 {
        self.max_size
    }

    fn check(self, class: WorkClass, summary: WorkSummary) -> Result<(), PrecompileLimitError> {
        if summary.count > self.max_count {
            return Err(PrecompileLimitError::Count {
                class,
                actual: summary.count,
                max: self.max_count,
            });
        }
        if summary.total_size > self.max_total_size {
            return Err(PrecompileLimitError::TotalSize {
                class,
                actual: summary.total_size,
                max: self.max_total_size,
            });
        }
        if summary.max_size > self.max_size {
            return Err(PrecompileLimitError::ItemSize {
                class,
                actual: summary.max_size,
                max: self.max_size,
            });
        }
        Ok(())
    }
}

/// Admission policy for one portable precompile witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecompileLimits {
    max_elements: u64,
    classes: BTreeMap<WorkClass, WorkLimit>,
}

impl PrecompileLimits {
    /// Creates a policy with a structural element ceiling and no admitted precompile work classes.
    pub const fn new(max_elements: u64) -> Self {
        Self { max_elements, classes: BTreeMap::new() }
    }

    /// Replaces the structural field-element ceiling.
    #[must_use]
    pub const fn with_max_elements(mut self, max_elements: u64) -> Self {
        self.max_elements = max_elements;
        self
    }

    /// Adds or replaces the bound for `class`.
    #[must_use]
    pub fn with_class(mut self, class: WorkClass, limit: WorkLimit) -> Self {
        self.classes.insert(class, limit);
        self
    }

    /// Returns the structural field-element ceiling.
    pub const fn max_elements(&self) -> u64 {
        self.max_elements
    }

    /// Returns the configured limit for `class`, if that class is admitted.
    pub fn class(&self, class: WorkClass) -> Option<WorkLimit> {
        self.classes.get(&class).copied()
    }

    /// Checks already-computed work against this policy.
    pub fn check(&self, work: &PrecompileWork) -> Result<(), PrecompileLimitError> {
        if work.elements > self.max_elements {
            return Err(PrecompileLimitError::Elements {
                actual: work.elements,
                max: self.max_elements,
            });
        }
        for (&class, &summary) in &work.classes {
            let limit = self
                .classes
                .get(&class)
                .copied()
                .ok_or(PrecompileLimitError::MissingClass { class })?;
            limit.check(class, summary)?;
        }
        Ok(())
    }
}

/// A witness exceeded its configured precompile admission policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PrecompileLimitError {
    #[error("precompile work accounting overflowed")]
    Overflow,
    #[error("precompile witness uses {actual} structural elements, maximum is {max}")]
    Elements { actual: u64, max: u64 },
    #[error("precompile work class `{class}` has no configured limit")]
    MissingClass { class: WorkClass },
    #[error("precompile work class `{class}` occurs {actual} times, maximum is {max}")]
    Count { class: WorkClass, actual: u64, max: u64 },
    #[error("precompile work class `{class}` has total size {actual}, maximum is {max}")]
    TotalSize { class: WorkClass, actual: u64, max: u64 },
    #[error("precompile work class `{class}` has item size {actual}, maximum is {max}")]
    ItemSize { class: WorkClass, actual: u32, max: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST: WorkClass = WorkClass::new("test");

    #[test]
    fn charging_is_checked_before_mutating_the_summary() {
        let limits = PrecompileLimits::new(24).with_class(TEST, WorkLimit::new(2, 7, 4));
        let mut work = PrecompileWork::default();

        work.charge(12, Some(WorkItem::new(TEST, 3)), &limits).unwrap();
        work.charge(12, Some(WorkItem::new(TEST, 4)), &limits).unwrap();
        assert_eq!(work.nodes(), 2);
        assert_eq!(work.elements(), 24);
        assert_eq!(work.class(TEST), Some(WorkSummary { count: 2, total_size: 7, max_size: 4 }));

        assert!(matches!(
            work.charge(1, None, &limits),
            Err(PrecompileLimitError::Elements { actual: 25, max: 24 })
        ));
        assert_eq!(work.nodes(), 2);
        assert_eq!(work.elements(), 24);
    }

    #[test]
    fn unconfigured_and_overflowing_work_is_rejected() {
        let mut work = PrecompileWork::default();
        assert!(matches!(
            work.charge(1, Some(WorkItem::new(TEST, 1)), &PrecompileLimits::new(u64::MAX),),
            Err(PrecompileLimitError::MissingClass { class: TEST })
        ));
        assert_eq!(work, PrecompileWork::default());

        work.nodes = u64::MAX;
        assert!(matches!(
            work.charge(0, None, &PrecompileLimits::new(u64::MAX)),
            Err(PrecompileLimitError::Overflow)
        ));
    }
}
