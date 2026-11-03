//! Declared deferred-precompile workload accounting.

use alloc::{borrow::Cow, collections::BTreeMap, string::String, vec::Vec};

use super::{Node, PrecompileError, PrecompileRegistry, precompile_registry::is_framework_domain};
use crate::serde::{
    BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
    SliceReader, validate_bounded_len,
};

/// Stable identifier for one class of precompile work.
///
/// Returning the same class from multiple frames intentionally combines their accounting. The
/// name is serialized in precompile policies but does not affect deferred commitments. Names are
/// arbitrary UTF-8 and are compared byte for byte.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkClass(Cow<'static, str>);

impl WorkClass {
    /// Creates a work class from a static name. The name is borrowed and not copied.
    pub const fn new(name: &'static str) -> Self {
        Self(Cow::Borrowed(name))
    }

    /// Creates a work class from an owned name.
    ///
    /// Use this for names that are not available as a `&'static str`, such as names decoded from a
    /// serialized policy. Names have no restrictions beyond valid UTF-8.
    pub fn from_string(name: String) -> Self {
        Self(Cow::Owned(name))
    }

    /// Returns the class name.
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

impl core::fmt::Display for WorkClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Work declared by one precompile-owned node.
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

/// Aggregate work for one class within an accounting scope.
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

/// Work accumulated within one execution or verification accounting scope.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrecompileWork {
    nodes: u64,
    elements: u64,
    classes: BTreeMap<WorkClass, WorkSummary>,
}

impl PrecompileWork {
    /// Returns the number of charged nodes in this accounting scope.
    pub const fn nodes(&self) -> u64 {
        self.nodes
    }

    /// Returns the canonical field-element footprint charged in this accounting scope.
    pub const fn elements(&self) -> u64 {
        self.elements
    }

    /// Returns the summary for `class`, if this scope contains that class.
    pub fn class(&self, class: WorkClass) -> Option<WorkSummary> {
        self.classes.get(&class).copied()
    }

    /// Validates already-accumulated work against `limits` without changing it.
    pub(crate) fn validate(&self, limits: &PrecompileLimits) -> Result<(), PrecompileLimitError> {
        limits.check_elements(self.elements)?;
        for (class, &summary) in &self.classes {
            limits.check_class(class, summary)?;
        }
        Ok(())
    }

    /// Charges one node under `limits`.
    ///
    /// Framework nodes contribute structural elements but no precompile work class. Every other
    /// node uses the owning precompile's declared work item.
    pub(crate) fn charge_node(
        &mut self,
        node: &Node,
        registry: &PrecompileRegistry,
        limits: &PrecompileLimits,
    ) -> Result<(), PrecompileError> {
        let item = match node.frame() {
            None => None,
            Some(frame) if is_framework_domain(frame.domain()) => None,
            Some(_) => Some(registry.work(node)?),
        };
        self.charge(node.felt_len(), item, limits)?;
        Ok(())
    }

    fn charge(
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
        limits.check_elements(elements)?;

        let next = item
            .map(|item| {
                let WorkItem { class, size } = item;
                let summary =
                    self.classes.get(&class).copied().unwrap_or_default().checked_with(size)?;
                limits.check_class(&class, summary)?;
                Ok((class, summary))
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

/// Bounds for one work class within a single accounting scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkLimit {
    /// Maximum number of items in this class.
    pub max_count: u64,
    /// Maximum sum of item sizes in this class.
    pub max_total_size: u64,
    /// Maximum size of one item in this class.
    pub max_size: u32,
}

impl WorkLimit {
    fn check(self, class: &WorkClass, summary: WorkSummary) -> Result<(), PrecompileLimitError> {
        if summary.count > self.max_count {
            return Err(PrecompileLimitError::Count {
                class: class.clone(),
                actual: summary.count,
                max: self.max_count,
            });
        }
        if summary.total_size > self.max_total_size {
            return Err(PrecompileLimitError::TotalSize {
                class: class.clone(),
                actual: summary.total_size,
                max: self.max_total_size,
            });
        }
        if summary.max_size > self.max_size {
            return Err(PrecompileLimitError::ItemSize {
                class: class.clone(),
                actual: summary.max_size,
                max: self.max_size,
            });
        }
        Ok(())
    }
}

/// Admission policy for one execution or verification accounting scope.
///
/// # Binary encoding
///
/// The encoding starts with the structural element ceiling as a `u64`. It then writes the class
/// map as a length-prefixed sequence in class-name order. Each entry contains a length-prefixed
/// UTF-8 class name and three work limits. Decoding requires class names in strictly increasing
/// order, rejects duplicates, and requires length prefixes to use the shortest vint64 encoding.
/// The format has no version byte. Both byte entrypoints require the decoded snapshot to consume
/// the entire input.
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

    /// Returns the configured bound for `class`, if the policy admits it.
    pub fn class(&self, class: WorkClass) -> Option<WorkLimit> {
        self.classes.get(&class).copied()
    }

    /// Returns the structural field-element ceiling.
    pub const fn max_elements(&self) -> u64 {
        self.max_elements
    }

    /// Returns the configured class bounds in class-name order.
    pub fn classes(&self) -> impl Iterator<Item = (&WorkClass, &WorkLimit)> + '_ {
        self.classes.iter()
    }

    fn check_elements(&self, actual: u64) -> Result<(), PrecompileLimitError> {
        if actual > self.max_elements {
            return Err(PrecompileLimitError::Elements { actual, max: self.max_elements });
        }
        Ok(())
    }

    fn check_class(
        &self,
        class: &WorkClass,
        summary: WorkSummary,
    ) -> Result<(), PrecompileLimitError> {
        let limit = self
            .classes
            .get(class)
            .copied()
            .ok_or_else(|| PrecompileLimitError::MissingClass { class: class.clone() })?;
        limit.check(class, summary)
    }
}

// SERIALIZATION
// ================================================================================================

fn read_shortest_len<R: ByteReader>(
    source: &mut R,
    label: &str,
    min_element_size: usize,
) -> Result<usize, DeserializationError> {
    let encoded_len = source.peek_u8()?.trailing_zeros() as usize + 1;
    let len = source.read_usize()?;
    if encoded_len != len.get_size_hint() {
        return Err(DeserializationError::InvalidValue(format!("noncanonical {label} length")));
    }
    validate_bounded_len(source, label, len, min_element_size)?;
    Ok(len)
}

impl Serializable for WorkClass {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.as_str().write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.as_str().get_size_hint()
    }
}

impl Deserializable for WorkClass {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let len = read_shortest_len(source, "work class name", 1)?;
        let bytes = source.read_many_iter::<u8>(len)?.collect::<Result<Vec<_>, _>>()?;
        let name = String::from_utf8(bytes)
            .map_err(|err| DeserializationError::InvalidValue(format!("{err}")))?;
        Ok(Self::from_string(name))
    }

    fn min_serialized_size() -> usize {
        1
    }
}

impl Serializable for WorkLimit {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.max_count.write_into(target);
        self.max_total_size.write_into(target);
        self.max_size.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.max_count.get_size_hint()
            + self.max_total_size.get_size_hint()
            + self.max_size.get_size_hint()
    }
}

impl Deserializable for WorkLimit {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let max_count = source.read_u64()?;
        let max_total_size = source.read_u64()?;
        let max_size = source.read_u32()?;
        Ok(Self { max_count, max_total_size, max_size })
    }

    fn min_serialized_size() -> usize {
        u64::min_serialized_size() + u64::min_serialized_size() + u32::min_serialized_size()
    }
}

impl Serializable for PrecompileLimits {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.max_elements.write_into(target);
        self.classes.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.max_elements.get_size_hint() + self.classes.get_size_hint()
    }
}

impl Deserializable for PrecompileLimits {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let max_elements = source.read_u64()?;
        let min_entry_size = WorkClass::min_serialized_size() + WorkLimit::min_serialized_size();
        let class_count = read_shortest_len(source, "precompile limits class", min_entry_size)?;
        let mut classes = BTreeMap::new();
        for entry in source.read_many_iter::<(WorkClass, WorkLimit)>(class_count)? {
            let (class, limit) = entry?;
            if let Some((previous, _)) = classes.last_key_value()
                && class <= *previous
            {
                return Err(DeserializationError::InvalidValue(format!(
                    "precompile limits class names must be strictly increasing: previous `{previous}`, current `{class}`"
                )));
            }
            classes.insert(class, limit);
        }
        Ok(Self { max_elements, classes })
    }

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        Self::read_from_bytes_with_budget(bytes, bytes.len())
    }

    fn read_from_bytes_with_budget(
        bytes: &[u8],
        budget: usize,
    ) -> Result<Self, DeserializationError> {
        let budget = budget.min(bytes.len());
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), budget);
        let limits = Self::read_from(&mut reader)?;
        let consumed = budget.saturating_sub(reader.remaining());
        if consumed != bytes.len() {
            return Err(DeserializationError::InvalidValue(
                "trailing bytes after precompile limits".into(),
            ));
        }
        Ok(limits)
    }

    fn min_serialized_size() -> usize {
        u64::min_serialized_size() + BTreeMap::<WorkClass, WorkLimit>::min_serialized_size()
    }
}

/// Work exceeded its configured precompile admission policy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrecompileLimitError {
    #[error("precompile work accounting overflowed")]
    Overflow,
    #[error("precompile work uses {actual} structural elements, maximum is {max}")]
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
    use alloc::{string::String, vec::Vec};

    use super::*;

    const TEST: WorkClass = WorkClass::new("test");

    #[test]
    fn charging_is_checked_before_mutating_the_summary() {
        let limits = PrecompileLimits::new(24).with_class(
            TEST,
            WorkLimit {
                max_count: 2,
                max_total_size: 7,
                max_size: 4,
            },
        );
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
            Err(PrecompileLimitError::MissingClass { class }) if class == TEST
        ));
        assert_eq!(work, PrecompileWork::default());

        work.nodes = u64::MAX;
        assert!(matches!(
            work.charge(0, None, &PrecompileLimits::new(u64::MAX)),
            Err(PrecompileLimitError::Overflow)
        ));
    }

    #[test]
    fn work_class_roundtrip_preserves_arbitrary_names() {
        let static_class = WorkClass::new("hash");
        let decoded_static = WorkClass::read_from_bytes(&static_class.to_bytes()).unwrap();
        assert_eq!(decoded_static, static_class);
        assert_eq!(decoded_static.as_str(), "hash");
        assert_eq!(format!("{decoded_static}"), "hash");

        for name in ["", "custom class", "custom/λ", "custom\nname"] {
            let class = WorkClass::from_string(String::from(name));
            let bytes = class.to_bytes();
            let decoded = WorkClass::read_from_bytes(&bytes).unwrap();
            assert_eq!(decoded, class);
            assert_eq!(decoded.to_bytes(), bytes);
            assert_eq!(decoded.as_str(), name);
            assert_eq!(format!("{decoded}"), name);
        }
    }

    #[test]
    fn work_class_rejects_invalid_utf8_and_truncated_length() {
        let mut invalid = Vec::new();
        2usize.write_into(&mut invalid);
        invalid.extend_from_slice(&[0xff, 0xfe]);
        assert!(WorkClass::read_from_bytes(&invalid).is_err());

        let mut truncated = Vec::new();
        3usize.write_into(&mut truncated);
        truncated.extend_from_slice(b"ab");
        assert!(WorkClass::read_from_bytes(&truncated).is_err());
    }

    #[test]
    fn precompile_limits_roundtrip_preserves_ceiling_and_multiple_custom_classes() {
        let custom_a = WorkClass::from_string(String::from("custom-a"));
        let custom_b = WorkClass::from_string(String::from("custom class"));
        let hash_limit = WorkLimit {
            max_count: 9,
            max_total_size: 13,
            max_size: 5,
        };
        let limits = PrecompileLimits::new(123)
            .with_class(
                custom_a.clone(),
                WorkLimit {
                    max_count: 7,
                    max_total_size: 11,
                    max_size: 3,
                },
            )
            .with_class(
                custom_b.clone(),
                WorkLimit {
                    max_count: 0,
                    max_total_size: 0,
                    max_size: 0,
                },
            )
            .with_class(WorkClass::new("hash"), hash_limit);

        let bytes = limits.to_bytes();
        let decoded = PrecompileLimits::read_from_bytes(&bytes).unwrap();
        assert_eq!(decoded, limits);
        assert_eq!(decoded.to_bytes(), bytes);
        assert_eq!(decoded.max_elements(), 123);
        assert_eq!(decoded.classes().count(), 3);
        assert!(decoded.classes().any(|(class, _)| class == &custom_a));
        assert!(decoded.classes().any(|(class, _)| class == &custom_b));
        assert_eq!(
            decoded.class(custom_a),
            Some(WorkLimit {
                max_count: 7,
                max_total_size: 11,
                max_size: 3
            })
        );
        assert_eq!(
            decoded.class(custom_b),
            Some(WorkLimit {
                max_count: 0,
                max_total_size: 0,
                max_size: 0
            })
        );
        assert_eq!(decoded.class(WorkClass::new("hash")), Some(hash_limit));
    }

    #[test]
    fn empty_precompile_limits_roundtrip() {
        let limits = PrecompileLimits::new(0);
        let bytes = limits.to_bytes();
        let decoded = PrecompileLimits::read_from_bytes(&bytes).unwrap();
        assert_eq!(decoded, limits);
        assert_eq!(decoded.to_bytes(), bytes);
        assert_eq!(decoded.max_elements(), 0);
        assert_eq!(decoded.classes().count(), 0);
    }

    #[test]
    fn precompile_limits_roundtrip_admission_matches_original() {
        fn assert_same_admission(
            original: &PrecompileLimits,
            decoded: &PrecompileLimits,
            elements: usize,
            item: Option<WorkItem>,
        ) {
            let mut original_work = PrecompileWork::default();
            let original_result = original_work.charge(elements, item.clone(), original);
            let mut decoded_work = PrecompileWork::default();
            let decoded_result = decoded_work.charge(elements, item, decoded);
            assert_eq!(original_result, decoded_result);
            assert_eq!(original_work, decoded_work);
        }

        let custom = WorkClass::from_string(String::from("custom"));
        let allowed = PrecompileLimits::new(4).with_class(
            custom.clone(),
            WorkLimit {
                max_count: 2,
                max_total_size: 5,
                max_size: 3,
            },
        );
        let decoded_allowed = PrecompileLimits::read_from_bytes(&allowed.to_bytes()).unwrap();
        assert_same_admission(
            &allowed,
            &decoded_allowed,
            1,
            Some(WorkItem::new(custom.clone(), 1)),
        );
        assert_same_admission(&allowed, &decoded_allowed, 5, None);

        let missing = PrecompileLimits::new(4);
        let decoded_missing = PrecompileLimits::read_from_bytes(&missing.to_bytes()).unwrap();
        assert_same_admission(
            &missing,
            &decoded_missing,
            1,
            Some(WorkItem::new(custom.clone(), 1)),
        );

        let count = PrecompileLimits::new(4).with_class(
            custom.clone(),
            WorkLimit {
                max_count: 0,
                max_total_size: 5,
                max_size: 3,
            },
        );
        let decoded_count = PrecompileLimits::read_from_bytes(&count.to_bytes()).unwrap();
        assert_same_admission(&count, &decoded_count, 1, Some(WorkItem::new(custom.clone(), 1)));

        let total = PrecompileLimits::new(4).with_class(
            custom.clone(),
            WorkLimit {
                max_count: 2,
                max_total_size: 0,
                max_size: 3,
            },
        );
        let decoded_total = PrecompileLimits::read_from_bytes(&total.to_bytes()).unwrap();
        assert_same_admission(&total, &decoded_total, 1, Some(WorkItem::new(custom.clone(), 1)));

        let item_size = PrecompileLimits::new(4).with_class(
            custom.clone(),
            WorkLimit {
                max_count: 2,
                max_total_size: 5,
                max_size: 0,
            },
        );
        let decoded_item_size = PrecompileLimits::read_from_bytes(&item_size.to_bytes()).unwrap();
        assert_same_admission(&item_size, &decoded_item_size, 1, Some(WorkItem::new(custom, 1)));
    }

    #[test]
    fn owned_custom_name_matches_static_live_class() {
        let live = WorkClass::new("hash");
        let decoded_name = WorkClass::from_string(String::from("hash"));
        assert_eq!(live, decoded_name);
        let limit = WorkLimit {
            max_count: 3,
            max_total_size: 4,
            max_size: 2,
        };
        let limits = PrecompileLimits::new(1).with_class(live, limit);
        let decoded = PrecompileLimits::read_from_bytes(&limits.to_bytes()).unwrap();
        assert_eq!(decoded.class(decoded_name), Some(limit));
    }

    #[test]
    fn precompile_limits_rejects_duplicate_class_keys() {
        let custom = WorkClass::from_string(String::from("custom"));
        let limit = WorkLimit {
            max_count: 1,
            max_total_size: 2,
            max_size: 1,
        };
        let mut bytes = Vec::new();
        42u64.write_into(&mut bytes);
        2usize.write_into(&mut bytes);
        custom.write_into(&mut bytes);
        limit.write_into(&mut bytes);
        custom.write_into(&mut bytes);
        limit.write_into(&mut bytes);
        assert!(PrecompileLimits::read_from_bytes(&bytes).is_err());
    }

    #[test]
    fn precompile_limits_rejects_out_of_order_class_keys() {
        let limit = WorkLimit {
            max_count: 1,
            max_total_size: 2,
            max_size: 1,
        };
        let mut bytes = Vec::new();
        0u64.write_into(&mut bytes);
        2usize.write_into(&mut bytes);
        WorkClass::new("b").write_into(&mut bytes);
        limit.write_into(&mut bytes);
        WorkClass::new("a").write_into(&mut bytes);
        limit.write_into(&mut bytes);
        let error = PrecompileLimits::read_from_bytes(&bytes).unwrap_err();
        assert!(matches!(
            error,
            DeserializationError::InvalidValue(ref message)
                if message.contains("`b`") && message.contains("`a`")
        ));
    }

    #[test]
    fn precompile_limits_fixed_vector_roundtrip() {
        let expected = vec![
            5, 0, 0, 0, 0, 0, 0, 0, // max_elements
            3, // one class
            9, // four-byte name
            b'h', b'a', b's', b'h', 7, 0, 0, 0, 0, 0, 0, 0, // max_count
            9, 0, 0, 0, 0, 0, 0, 0, // max_total_size
            2, 0, 0, 0, // max_size
        ];
        let limits = PrecompileLimits::new(5).with_class(
            WorkClass::new("hash"),
            WorkLimit {
                max_count: 7,
                max_total_size: 9,
                max_size: 2,
            },
        );
        assert_eq!(limits.to_bytes(), expected);
        let decoded = PrecompileLimits::read_from_bytes(&expected).unwrap();
        assert_eq!(decoded, limits);
    }

    #[test]
    fn precompile_limits_rejects_overlong_class_count() {
        let mut bytes = Vec::new();
        0u64.write_into(&mut bytes);
        bytes.extend_from_slice(&[0x02, 0x00]);
        assert!(PrecompileLimits::read_from_bytes(&bytes).is_err());
    }

    #[test]
    fn precompile_limits_rejects_overlong_class_name_length() {
        let mut bytes = Vec::new();
        0u64.write_into(&mut bytes);
        1usize.write_into(&mut bytes);
        bytes.extend_from_slice(&[0x02, 0x00]);
        WorkLimit {
            max_count: 1,
            max_total_size: 2,
            max_size: 1,
        }
        .write_into(&mut bytes);
        assert!(PrecompileLimits::read_from_bytes(&bytes).is_err());
    }

    #[test]
    fn precompile_limits_rejects_oversized_lengths() {
        let mut huge_count = Vec::new();
        0u64.write_into(&mut huge_count);
        usize::MAX.write_into(&mut huge_count);
        assert!(PrecompileLimits::read_from_bytes(&huge_count).is_err());

        let mut huge_name = Vec::new();
        0u64.write_into(&mut huge_name);
        1usize.write_into(&mut huge_name);
        usize::MAX.write_into(&mut huge_name);
        WorkLimit {
            max_count: 1,
            max_total_size: 2,
            max_size: 1,
        }
        .write_into(&mut huge_name);
        assert!(PrecompileLimits::read_from_bytes(&huge_name).is_err());

        let mut valid_name = Vec::new();
        0u64.write_into(&mut valid_name);
        1usize.write_into(&mut valid_name);
        1usize.write_into(&mut valid_name);
        valid_name.push(b'x');
        WorkLimit {
            max_count: 1,
            max_total_size: 2,
            max_size: 1,
        }
        .write_into(&mut valid_name);
        assert!(PrecompileLimits::read_from_bytes(&valid_name).is_ok());
    }

    #[test]
    fn precompile_limits_rejects_truncated_and_trailing_bytes() {
        let limits = PrecompileLimits::new(7).with_class(
            WorkClass::new("hash"),
            WorkLimit {
                max_count: 1,
                max_total_size: 1,
                max_size: 1,
            },
        );
        let bytes = limits.to_bytes();
        for len in 0..bytes.len() {
            assert!(PrecompileLimits::read_from_bytes(&bytes[..len]).is_err());
        }
        assert!(PrecompileLimits::read_from_bytes_with_budget(&bytes, bytes.len()).is_ok());
        assert!(PrecompileLimits::read_from_bytes_with_budget(&bytes, bytes.len() + 1).is_ok());

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(PrecompileLimits::read_from_bytes(&trailing).is_err());
        assert!(PrecompileLimits::read_from_bytes_with_budget(&trailing, trailing.len()).is_err());
        assert!(PrecompileLimits::read_from_bytes_with_budget(&trailing, bytes.len()).is_err());
        assert!(PrecompileLimits::read_from_bytes_with_budget(&bytes, bytes.len() - 1).is_err());
    }
}
