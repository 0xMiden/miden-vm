use alloc::boxed::Box;
use core::{
    fmt::{Display, Formatter},
    ops::{Add, AddAssign, Bound, Index, IndexMut, Mul, RangeBounds, Sub, SubAssign},
};

use miden_core::Felt;

/// Represents the types of errors that can occur when converting from and into [`RowIndex`] and
/// using its operations.
#[derive(Debug, thiserror::Error)]
pub enum RowIndexError {
    // This uses Box<str> rather than String because its stack size is 8 bytes smaller.
    #[error("value {0} is larger than u32::MAX so it cannot be converted into a RowIndex")]
    InvalidSize(Box<str>),
}

// ROW INDEX
// ================================================================================================

/// A newtype wrapper around a usize value representing a step in the execution trace.
#[derive(Debug, Default, Copy, Clone, Eq, Ord, PartialOrd)]
pub struct RowIndex(u32);

impl RowIndex {
    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl Display for RowIndex {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// FROM ROW INDEX
// ================================================================================================

impl From<RowIndex> for u32 {
    fn from(step: RowIndex) -> u32 {
        step.0
    }
}

impl From<RowIndex> for u64 {
    fn from(step: RowIndex) -> u64 {
        step.0 as u64
    }
}

impl From<RowIndex> for usize {
    fn from(step: RowIndex) -> usize {
        step.0 as usize
    }
}

impl From<RowIndex> for Felt {
    fn from(step: RowIndex) -> Felt {
        Felt::from(step.0)
    }
}

// INTO ROW INDEX
// ================================================================================================

/// Converts a usize value into a [`RowIndex`].
///
/// # Panics
///
/// This function will panic if the number represented by the usize is greater than the maximum
/// [`RowIndex`] value, [`u32::MAX`].
impl From<usize> for RowIndex {
    fn from(value: usize) -> Self {
        let value = u32::try_from(value)
            .map_err(|_| RowIndexError::InvalidSize(format!("{value}_usize").into()))
            .unwrap();
        value.into()
    }
}

/// Converts a u64 value into a [`RowIndex`].
///
/// # Errors
///
/// This function returns an error if the number represented by the u64 is greater than the
/// maximum [`RowIndex`] value, [`u32::MAX`].
impl TryFrom<u64> for RowIndex {
    type Error = RowIndexError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let value = u32::try_from(value)
            .map_err(|_| RowIndexError::InvalidSize(format!("{value}_u64").into()))?;
        Ok(RowIndex::from(value))
    }
}

impl From<u32> for RowIndex {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

/// Converts an i32 value into a [`RowIndex`].
///
/// # Panics
///
/// This function will panic if the number represented by the i32 is less than 0.
impl From<i32> for RowIndex {
    fn from(value: i32) -> Self {
        let value = u32::try_from(value)
            .map_err(|_| RowIndexError::InvalidSize(format!("{value}_i32").into()))
            .unwrap();
        RowIndex(value)
    }
}

// ROW INDEX OPS
// ================================================================================================

/// Subtracts a usize from a [`RowIndex`].
///
/// # Panics
///
/// This function will panic if the number represented by the usize is greater than the maximum
/// [`RowIndex`] value, `u32::MAX`.
impl Sub<usize> for RowIndex {
    type Output = RowIndex;

    fn sub(self, rhs: usize) -> Self::Output {
        let rhs = u32::try_from(rhs)
            .map_err(|_| RowIndexError::InvalidSize(format!("{rhs}_usize").into()))
            .unwrap();
        RowIndex(self.0 - rhs)
    }
}

impl SubAssign<u32> for RowIndex {
    fn sub_assign(&mut self, rhs: u32) {
        self.0 -= rhs;
    }
}

impl Sub<RowIndex> for RowIndex {
    type Output = usize;

    fn sub(self, rhs: RowIndex) -> Self::Output {
        (self.0 - rhs.0) as usize
    }
}

impl RowIndex {
    pub fn saturating_sub(self, rhs: u32) -> Self {
        RowIndex(self.0.saturating_sub(rhs))
    }

    pub fn max(self, other: RowIndex) -> Self {
        RowIndex(self.0.max(other.0))
    }
}

/// Adds a usize to a [`RowIndex`].
///
/// # Panics
///
/// This function will panic if the number represented by the usize is greater than the maximum
/// [`RowIndex`] value, `u32::MAX`.
impl Add<usize> for RowIndex {
    type Output = RowIndex;

    fn add(self, rhs: usize) -> Self::Output {
        let rhs = u32::try_from(rhs)
            .map_err(|_| RowIndexError::InvalidSize(format!("{rhs}_usize").into()))
            .unwrap();
        RowIndex(self.0 + rhs)
    }
}

impl Add<RowIndex> for u32 {
    type Output = RowIndex;

    fn add(self, rhs: RowIndex) -> Self::Output {
        RowIndex(self + rhs.0)
    }
}

/// Adds a u32 value to a RowIndex in place.
///
/// # Panics
///
/// This function will panic if the internal value of the [`RowIndex`] would exceed the maximum
/// value `u32::MAX`.
impl AddAssign<u32> for RowIndex {
    fn add_assign(&mut self, rhs: u32) {
        self.0 += rhs;
    }
}

/// Adds a usize value to a RowIndex in place.
///
/// # Panics
///
/// This function will panic if the internal value of the [`RowIndex`] would exceed the maximum
/// value `u32::MAX`.
impl AddAssign<usize> for RowIndex {
    fn add_assign(&mut self, rhs: usize) {
        let rhs = u32::try_from(rhs)
            .map_err(|_| RowIndexError::InvalidSize(format!("{rhs}_usize").into()))
            .unwrap();
        self.0 += rhs;
    }
}

impl Mul<RowIndex> for usize {
    type Output = RowIndex;

    fn mul(self, rhs: RowIndex) -> Self::Output {
        (self * rhs.0 as usize).into()
    }
}

// ROW INDEX EQUALITY AND ORDERING
// ================================================================================================

impl PartialEq<RowIndex> for RowIndex {
    fn eq(&self, rhs: &RowIndex) -> bool {
        self.0 == rhs.0
    }
}

impl PartialEq<usize> for RowIndex {
    fn eq(&self, rhs: &usize) -> bool {
        self.0
            == u32::try_from(*rhs)
                .map_err(|_| RowIndexError::InvalidSize(format!("{}_usize", *rhs).into()))
                .unwrap()
    }
}

impl PartialEq<RowIndex> for i32 {
    fn eq(&self, rhs: &RowIndex) -> bool {
        *self as u32 == u32::from(*rhs)
    }
}

impl PartialOrd<usize> for RowIndex {
    fn partial_cmp(&self, rhs: &usize) -> Option<core::cmp::Ordering> {
        let rhs = u32::try_from(*rhs)
            .map_err(|_| RowIndexError::InvalidSize(format!("{}_usize", *rhs).into()))
            .unwrap();
        self.0.partial_cmp(&rhs)
    }
}

impl<T> Index<RowIndex> for [T] {
    type Output = T;
    fn index(&self, i: RowIndex) -> &Self::Output {
        &self[i.0 as usize]
    }
}

impl<T> IndexMut<RowIndex> for [T] {
    fn index_mut(&mut self, i: RowIndex) -> &mut Self::Output {
        &mut self[i.0 as usize]
    }
}

impl RangeBounds<RowIndex> for RowIndex {
    fn start_bound(&self) -> Bound<&Self> {
        Bound::Included(self)
    }
    fn end_bound(&self) -> Bound<&Self> {
        Bound::Included(self)
    }
}

// TESTS
// ================================================================================================
#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;

    #[test]
    fn row_index_conversions() {
        use super::RowIndex;
        // Into
        let _: RowIndex = 5.into();
        let _: RowIndex = 5u32.into();
        let _: RowIndex = (5usize).into();

        // From
        let _: u32 = RowIndex(5).into();
        let _: u64 = RowIndex(5).into();
        let _: usize = RowIndex(5).into();
    }

    #[test]
    fn row_index_ops() {
        use super::RowIndex;

        // Equality
        assert_eq!(RowIndex(5), 5);
        assert_eq!(RowIndex(5), RowIndex(5));
        assert!(RowIndex(5) == RowIndex(5));
        assert!(RowIndex(5) >= RowIndex(5));
        assert!(RowIndex(6) >= RowIndex(5));
        assert!(RowIndex(5) > RowIndex(4));
        assert!(RowIndex(5) <= RowIndex(5));
        assert!(RowIndex(4) <= RowIndex(5));
        assert!(RowIndex(5) < RowIndex(6));

        // Arithmetic
        assert_eq!(RowIndex(5) + 3, 8);
        assert_eq!(RowIndex(5) - 3, 2);
        assert_eq!(3 + RowIndex(5), 8);
        assert_eq!(2 * RowIndex(5), 10);

        // Add assign
        let mut step = RowIndex(5);
        step += 5_u32;
        assert_eq!(step, 10);
    }

    #[test]
    fn row_index_range() {
        use super::RowIndex;
        let mut tree: BTreeMap<RowIndex, usize> = BTreeMap::new();
        tree.insert(RowIndex(0), 0);
        tree.insert(RowIndex(1), 1);
        tree.insert(RowIndex(2), 2);
        let acc =
            tree.range(RowIndex::from(0)..RowIndex::from(tree.len()))
                .fold(0, |acc, (key, val)| {
                    assert_eq!(*key, RowIndex::from(acc));
                    assert_eq!(*val, acc);
                    acc + 1
                });
        assert_eq!(acc, 3);
    }

    #[test]
    fn row_index_display() {
        assert_eq!(format!("{}", super::RowIndex(5)), "5");
    }
}
