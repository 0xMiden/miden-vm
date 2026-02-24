//! This module is borrowed/modified from [semver-pubgrub](https://github.com/pubgrub-rs/semver-pubgrub/blob/main/src/lib.rs).
use alloc::format;
use core::{
    borrow::Borrow,
    cmp::{max, min},
    fmt::{self, Display},
    num::NonZeroU64,
    ops::Bound,
};

use pubgrub::{Range, VersionSet};

use crate::semver::{BuildMetadata, Comparator, Op, Prerelease, Version, VersionReq};

/// This needs to be bug-for-bug compatible with https://github.com/dtolnay/semver/blob/master/src/eval.rs
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct SemverPubgrub {
    normal: Range<Version>,
    pre: Range<Version>,
}

impl SemverPubgrub {
    /// Returns true if there are no versions in this range
    pub fn is_empty(&self) -> bool {
        self.normal.is_empty() && self.pre.is_empty()
    }

    /// Convert to something that can be used with
    /// [BTreeMap::range](std::collections::BTreeMap::range).
    /// All versions contained in self, will be in the output,
    /// but there may be versions in the output that are not contained in self.
    /// Returns None if the range is empty.
    pub fn bounding_range(&self) -> Option<(Bound<&Version>, Bound<&Version>)> {
        use Bound::*;
        let Some((ns, ne)) = self.normal.bounding_range() else {
            return self.pre.bounding_range();
        };
        let Some((ps, pe)) = self.pre.bounding_range() else {
            return Some((ns, ne));
        };
        let start = match (ns, ps) {
            (Included(n), Included(p)) => Included(min(n, p)),
            (Included(i), Excluded(e)) | (Excluded(e), Included(i)) => {
                if e < i {
                    Excluded(e)
                } else {
                    Included(i)
                }
            },
            (Excluded(n), Excluded(p)) => Excluded(min(n, p)),
            (Unbounded, _) | (_, Unbounded) => Unbounded,
        };
        let end = match (ne, pe) {
            (Included(n), Included(p)) => Included(max(n, p)),
            (Included(i), Excluded(e)) | (Excluded(e), Included(i)) => {
                if i < e {
                    Excluded(e)
                } else {
                    Included(i)
                }
            },
            (Excluded(n), Excluded(p)) => Excluded(max(n, p)),
            (Unbounded, _) | (_, Unbounded) => Unbounded,
        };
        Some((start, end))
    }
}

/// A type that represents when cargo treats two Versions as compatible.
/// Versions `a` and `b` are compatible if their left-most nonzero digit is the
/// same.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug, PartialOrd, Ord)]
pub enum SemverCompatibility {
    Patch(u64),
    Minor(NonZeroU64),
    Major(NonZeroU64),
}

impl SemverCompatibility {
    /// The smallest version that is in this compatibility range.
    pub fn minimum(&self) -> Version {
        match *self {
            Self::Major(new) => Version {
                major: new.into(),
                minor: 0,
                patch: 0,
                pre: Prerelease::new("0").unwrap(),
                build: BuildMetadata::EMPTY,
            },
            Self::Minor(new) => Version {
                major: 0,
                minor: new.into(),
                patch: 0,
                pre: Prerelease::new("0").unwrap(),
                build: BuildMetadata::EMPTY,
            },
            Self::Patch(new) => Version {
                major: 0,
                minor: 0,
                patch: new,
                pre: Prerelease::new("0").unwrap(),
                build: BuildMetadata::EMPTY,
            },
        }
    }

    /// The smallest non pre-release version that is in this compatibility range.
    pub fn canonical(&self) -> Version {
        match *self {
            Self::Major(new) => Version {
                major: new.into(),
                minor: 0,
                patch: 0,
                pre: Prerelease::EMPTY,
                build: BuildMetadata::EMPTY,
            },
            Self::Minor(new) => Version {
                major: 0,
                minor: new.into(),
                patch: 0,
                pre: Prerelease::EMPTY,
                build: BuildMetadata::EMPTY,
            },
            Self::Patch(new) => Version {
                major: 0,
                minor: 0,
                patch: new,
                pre: Prerelease::EMPTY,
                build: BuildMetadata::EMPTY,
            },
        }
    }

    pub fn next(&self) -> Option<SemverCompatibility> {
        let one = NonZeroU64::new(1).unwrap();
        match *self {
            Self::Patch(s) => {
                Some(s.checked_add(1).map(Self::Patch).unwrap_or_else(|| Self::Minor(one)))
            },
            Self::Minor(s) => {
                Some(s.checked_add(1).map(Self::Minor).unwrap_or_else(|| Self::Major(one)))
            },
            Self::Major(s) => s.checked_add(1).map(Self::Major),
        }
    }

    pub fn maximum_bound(&self) -> Bound<Version> {
        if let Some(next) = self.next() {
            Bound::Excluded(next.minimum())
        } else {
            Bound::Unbounded
        }
    }
}

impl From<&Version> for SemverCompatibility {
    fn from(ver: &Version) -> Self {
        if let Some(m) = NonZeroU64::new(ver.major) {
            return Self::Major(m);
        }
        if let Some(m) = NonZeroU64::new(ver.minor) {
            return Self::Minor(m);
        }
        Self::Patch(ver.patch)
    }
}

impl From<&SemverCompatibility> for Range<Version> {
    fn from(compat: &SemverCompatibility) -> Self {
        let low = compat.minimum();
        let hight = {
            match compat {
                SemverCompatibility::Major(_) => bump_major(&low),
                SemverCompatibility::Minor(_) => bump_minor(&low),
                SemverCompatibility::Patch(_) => bump_patch(&low),
            }
        };
        Range::from_range_bounds((Bound::Included(low), hight))
    }
}

impl SemverPubgrub {
    /// Whether cargo would require that only one package matche this range.
    ///
    /// While this crate matches the semantics of `semver`
    /// and implements the traits from `pubgrub`, there is an important difference in semantics.
    /// `pubgrub` assumes that only one version of each package can be selected.
    /// Whereas cargo allows one version per compatibility range to be selected.
    /// In general to lower cargo semantics to `pubgrub`
    /// you need to add synthetic packages to allow this multiplicity.
    /// (Currently look at the `pubgrub` guide for how to do this.
    /// Eventually there will be a crate for this.)
    /// But that's only "in general", in specific most requirements used in the rust ecosystem
    /// can skip these synthetic packages because they
    /// can only match one compatibility range anyway.
    /// This function returns the compatibility range if self can only one.
    pub fn only_one_compatibility_range(&self) -> Option<SemverCompatibility> {
        use Bound::*;
        let normal_bound = self.normal.bounding_range();
        let pre_bound = self.pre.bounding_range();
        if normal_bound.is_none() && pre_bound.is_none() {
            return Some(SemverCompatibility::Patch(0));
        }
        let normal_start = normal_bound.map(|(s, _)| match s {
            Included(v) | Excluded(v) => v.into(),
            Unbounded => SemverCompatibility::Patch(0),
        });
        let pre_start = pre_bound.map(|(s, _)| match s {
            Included(v) | Excluded(v) => v.into(),
            Unbounded => SemverCompatibility::Patch(0),
        });
        if normal_start.is_some() && pre_start.is_some() && normal_start != pre_start {
            return None;
        }
        let start = normal_start.or(pre_start).unwrap();
        if let Some(next) = start.next() {
            if let Some((_, pe)) = pre_bound {
                match (pe, next.minimum()) {
                    (Unbounded, _) => return None,
                    (Included(e), m) => {
                        if e >= &m {
                            return None;
                        }
                    },
                    (Excluded(e), m) => {
                        if e > &m {
                            return None;
                        }
                    },
                }
            }
            if let Some((_, ne)) = normal_bound {
                match (ne, next.canonical()) {
                    (Unbounded, _) => return None,
                    (Included(e), m) => {
                        if e >= &m {
                            return None;
                        }
                    },
                    (Excluded(e), m) => {
                        if e > &m {
                            return None;
                        }
                    },
                }
            }
        }

        Some(start)
    }
}

impl SemverPubgrub {
    /// Returns true if the this Range contains the specified values.
    ///
    /// The `versions` iterator must be sorted.
    /// Functionally equivalent to `versions.map(|v| self.contains(v))`.
    /// Except it runs in `O(size_of_range + len_of_versions)` not `O(size_of_range *
    /// len_of_versions)`
    pub fn contains_many<'s, I, BV>(&'s self, versions: I) -> impl Iterator<Item = bool> + 's
    where
        I: Iterator<Item = BV> + Clone + 's,
        BV: Borrow<Version> + 's,
    {
        let mut n_iter = self
            .normal
            .contains_many(versions.clone().filter(|v| v.borrow().pre.is_empty()));
        let mut p_iter =
            self.pre.contains_many(versions.clone().filter(|v| !v.borrow().pre.is_empty()));
        versions.filter_map(move |v| {
            if v.borrow().pre.is_empty() {
                n_iter.next()
            } else {
                p_iter.next()
            }
        })
    }

    /// Returns a simpler Range that contains the same versions
    ///
    /// For every one of the Versions provided in versions the existing range and
    /// the simplified range will agree on whether it is contained.
    /// The simplified version may include or exclude versions that are not in versions as the
    /// implementation wishes. For example:
    ///  - If all the versions are contained in the original than the range will be simplified to
    ///    `full`.
    ///  - If none of the versions are contained in the original than the range will be simplified
    ///    to `empty`.
    ///
    /// If versions are not sorted the correctness of this function is not guaranteed.
    pub fn simplify<'v, I, BV>(&self, versions: I) -> Self
    where
        I: Iterator<Item = BV> + Clone + 'v,
        BV: Borrow<Version> + 'v,
    {
        Self {
            normal: self.normal.simplify(versions.clone().filter(|v| v.borrow().pre.is_empty())),
            pre: self.pre.simplify(versions.filter(|v| !v.borrow().pre.is_empty())),
        }
    }

    /// If the range was constructed using Singleton, return the version from the constructor.
    /// Otherwise, returns [None].
    pub fn as_singleton(&self) -> Option<&Version> {
        self.normal.as_singleton().xor(self.pre.as_singleton())
    }

    /// Iterate over the parts of the range that can match normal releases.
    pub fn iter_normal(&self) -> impl Iterator<Item = (&Bound<Version>, &Bound<Version>)> {
        self.normal.iter()
    }

    /// Iterate over the parts of the range that can match pre-releases.
    pub fn iter_pre(&self) -> impl Iterator<Item = (&Bound<Version>, &Bound<Version>)> {
        self.pre.iter()
    }

    pub fn empty() -> Self {
        Self {
            normal: Range::empty(),
            pre: Range::empty(),
        }
    }

    pub fn full() -> Self {
        Self {
            normal: Range::full(),
            pre: Range::full(),
        }
    }

    pub fn singleton(v: Version) -> Self {
        let is_pre = !v.pre.is_empty();
        let singleton = Range::singleton(v);
        if !is_pre {
            Self { normal: singleton, pre: Range::empty() }
        } else {
            Self { normal: Range::empty(), pre: singleton }
        }
    }

    pub fn complement(&self) -> Self {
        Self {
            normal: self.normal.complement(),
            pre: self.pre.complement(),
        }
    }

    pub fn intersection(&self, other: &Self) -> Self {
        Self {
            normal: self.normal.intersection(&other.normal),
            pre: self.pre.intersection(&other.pre),
        }
    }

    pub fn contains(&self, v: &Version) -> bool {
        // This needs to be bug-for-bug compatible with matches_req https://github.com/dtolnay/semver/blob/master/src/eval.rs#L3
        if v.pre.is_empty() {
            self.normal.contains(v)
        } else {
            self.pre.contains(v)
        }
    }

    pub fn union(&self, other: &Self) -> Self {
        Self {
            normal: self.normal.union(&other.normal),
            pre: self.pre.union(&other.pre),
        }
    }

    pub fn is_disjoint(&self, other: &Self) -> bool {
        self.normal.is_disjoint(&other.normal) && self.pre.is_disjoint(&other.pre)
    }

    pub fn subset_of(&self, other: &Self) -> bool {
        self.normal.subset_of(&other.normal) && self.pre.subset_of(&other.pre)
    }
}

impl Display for SemverPubgrub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use core::ops::Bound::*;

        fn print_bounds(
            f: &mut fmt::Formatter<'_>,
            unbounded: &str,
            range: (&Bound<Version>, &Bound<Version>),
        ) -> fmt::Result {
            match range {
                (Unbounded, Unbounded) => f.write_str(unbounded),
                (Unbounded, Excluded(end)) => write!(f, "< {end}"),
                (Unbounded, Included(end)) => write!(f, "<= {end}"),
                (Excluded(start), Unbounded) => write!(f, "> {start}"),
                (Excluded(start), Excluded(end)) => write!(f, "> {start} and < {end}"),
                (Excluded(start), Included(end)) => write!(f, "> {start} and <= {end}"),
                (Included(start), Unbounded) => write!(f, ">= {start}"),
                (Included(start), Excluded(end)) => write!(f, ">= {start} and < {end}"),
                (Included(start), Included(end)) => write!(f, ">= {start} and <= {end}"),
            }
        }

        fn print_ranges<'b>(
            f: &mut fmt::Formatter<'_>,
            non_empty_prefix: &str,
            unbounded: &str,
            ranges: impl Iterator<Item = (&'b Bound<Version>, &'b Bound<Version>)>,
        ) -> Result<bool, fmt::Error> {
            let mut is_empty = true;
            for (i, range) in ranges.enumerate() {
                is_empty = false;
                if i > 0 {
                    f.write_str(", or ")?;
                } else if i == 0 && !non_empty_prefix.is_empty() {
                    f.write_str(non_empty_prefix)?;
                }
                print_bounds(f, unbounded, range)?;
            }
            Ok(is_empty)
        }

        if let Some(version) = self.normal.as_singleton() {
            write!(f, "={version}")?;

            print_ranges(f, ", including ", "pre-releases", self.iter_pre())?;

            Ok(())
        } else {
            let is_empty = print_ranges(f, "", "*", self.iter_normal())?;
            let is_empty = if is_empty && let Some(version) = self.pre.as_singleton() {
                return write!(f, "={version}");
            } else if is_empty {
                print_ranges(f, "", "any version including pre-releases", self.iter_pre())?
            } else if let Some(version) = self.pre.as_singleton() {
                return write!(f, ", or ={version}");
            } else {
                print_ranges(f, ", including ", "pre-releases", self.iter_pre())?;
                false
            };

            if is_empty {
                f.write_str("a set with no versions to select from")?;
            }

            Ok(())
        }
    }
}

impl From<&SemverCompatibility> for SemverPubgrub {
    fn from(compat: &SemverCompatibility) -> Self {
        let r = Range::from(compat);
        Self { normal: r.clone(), pre: r }
    }
}

impl VersionSet for SemverPubgrub {
    type V = Version;

    fn empty() -> Self {
        Self::empty()
    }

    fn full() -> Self {
        Self::full()
    }

    fn singleton(v: Self::V) -> Self {
        Self::singleton(v)
    }

    fn complement(&self) -> Self {
        self.complement()
    }

    fn intersection(&self, other: &Self) -> Self {
        self.intersection(other)
    }

    fn contains(&self, v: &Self::V) -> bool {
        self.contains(v)
    }

    fn union(&self, other: &Self) -> Self {
        self.union(other)
    }

    fn is_disjoint(&self, other: &Self) -> bool {
        self.is_disjoint(other)
    }

    fn subset_of(&self, other: &Self) -> bool {
        self.subset_of(other)
    }
}

impl From<&VersionReq> for SemverPubgrub {
    fn from(req: &VersionReq) -> Self {
        let mut out = Self::full();
        // add to normal the intersection of cmps in req
        for cmp in &req.comparators {
            out = out.intersection(&matches_impl(cmp));
        }
        let mut pre = Range::empty();
        // add to pre the union of cmps in req
        for cmp in &req.comparators {
            pre = pre.union(&pre_is_compatible(cmp));
        }
        out.pre = pre.intersection(&out.pre);
        out
    }
}

fn matches_impl(cmp: &Comparator) -> SemverPubgrub {
    // https://github.com/dtolnay/semver/blob/master/src/eval.rs#L30
    match cmp.op {
        Op::Exact | Op::Wildcard => matches_exact(cmp),
        Op::Greater => matches_greater(cmp),
        Op::GreaterEq => matches_exact(cmp).union(&matches_greater(cmp)),
        Op::Less => matches_less(cmp),
        Op::LessEq => matches_exact(cmp).union(&matches_less(cmp)),
        Op::Tilde => matches_tilde(cmp),
        Op::Caret => matches_caret(cmp),
        _ => unreachable!("update to a version that supports this Op"),
    }
}

fn matches_exact(cmp: &Comparator) -> SemverPubgrub {
    // https://github.com/dtolnay/semver/blob/master/src/eval.rs#L44
    let low = Version {
        major: cmp.major,
        minor: cmp.minor.unwrap_or(0),
        patch: cmp.patch.unwrap_or(0),
        pre: cmp.pre.clone(),
        build: BuildMetadata::EMPTY,
    };
    if !cmp.pre.is_empty() {
        return SemverPubgrub {
            normal: Range::empty(),
            pre: between(low, bump_pre),
        };
    }
    let normal = if cmp.patch.is_some() {
        between(low, bump_patch)
    } else if cmp.minor.is_some() {
        between(low, bump_minor)
    } else {
        between(low, bump_major)
    };

    SemverPubgrub {
        normal: simplified_to_normal(&normal),
        pre: Range::empty(),
    }
}

fn matches_greater(cmp: &Comparator) -> SemverPubgrub {
    // https://github.com/dtolnay/semver/blob/master/src/eval.rs#L64
    let low = Version {
        major: cmp.major,
        minor: cmp.minor.unwrap_or(0),
        patch: cmp.patch.unwrap_or(0),
        pre: cmp.pre.clone(),
        build: BuildMetadata::EMPTY,
    };
    let bump = if cmp.patch.is_some() {
        bump_pre(&low)
    } else if cmp.minor.is_some() {
        bump_minor(&low)
    } else {
        bump_major(&low)
    };
    let low_bound = match bump {
        Bound::Included(_) => unreachable!(),
        Bound::Excluded(v) => Bound::Included(v),
        Bound::Unbounded => return SemverPubgrub::empty(),
    };
    let out = Range::from_range_bounds((low_bound, Bound::Unbounded));
    SemverPubgrub {
        normal: simplified_to_normal(&out),
        pre: out,
    }
}

fn matches_less(cmp: &Comparator) -> SemverPubgrub {
    // https://github.com/dtolnay/semver/blob/master/src/eval.rs#L90
    let out = Range::strictly_lower_than(Version {
        major: cmp.major,
        minor: cmp.minor.unwrap_or(0),
        patch: cmp.patch.unwrap_or(0),
        pre: if cmp.patch.is_some() {
            cmp.pre.clone()
        } else {
            Prerelease::new("0").unwrap()
        },
        build: BuildMetadata::EMPTY,
    });
    SemverPubgrub {
        normal: simplified_to_normal(&out),
        pre: out,
    }
}

fn matches_tilde(cmp: &Comparator) -> SemverPubgrub {
    // https://github.com/dtolnay/semver/blob/master/src/eval.rs#L116
    let low = Version {
        major: cmp.major,
        minor: cmp.minor.unwrap_or(0),
        patch: cmp.patch.unwrap_or(0),
        pre: cmp.pre.clone(),
        build: BuildMetadata::EMPTY,
    };
    if cmp.patch.is_some() {
        let out = between(low, bump_minor);
        return SemverPubgrub {
            normal: simplified_to_normal(&out),
            pre: out,
        };
    }
    let normal = if cmp.minor.is_some() {
        between(low, bump_minor)
    } else {
        between(low, bump_major)
    };
    SemverPubgrub {
        normal: simplified_to_normal(&normal),
        pre: Range::empty(),
    }
}

fn matches_caret(cmp: &Comparator) -> SemverPubgrub {
    // https://github.com/dtolnay/semver/blob/master/src/eval.rs#L136
    let low = Version {
        major: cmp.major,
        minor: cmp.minor.unwrap_or(0),
        patch: cmp.patch.unwrap_or(0),
        pre: if cmp.patch.is_some() {
            cmp.pre.clone()
        } else {
            Prerelease::new("0").unwrap()
        },
        build: BuildMetadata::EMPTY,
    };
    let Some(minor) = cmp.minor else {
        let out = between(low, bump_major);
        return SemverPubgrub {
            normal: simplified_to_normal(&out),
            pre: out,
        };
    };

    if cmp.patch.is_none() {
        let out = if cmp.major > 0 {
            between(low, bump_major)
        } else {
            between(low, bump_minor)
        };
        return SemverPubgrub {
            normal: simplified_to_normal(&out),
            pre: out,
        };
    };

    let out = if cmp.major > 0 {
        between(low, bump_major)
    } else if minor > 0 {
        between(low, bump_minor)
    } else {
        between(low, bump_patch)
    };
    SemverPubgrub {
        normal: simplified_to_normal(&out),
        pre: out,
    }
}

fn pre_is_compatible(cmp: &Comparator) -> Range<Version> {
    // https://github.com/dtolnay/semver/blob/master/src/eval.rs#L176
    if cmp.pre.is_empty() {
        return Range::empty();
    }
    let (Some(minor), Some(patch)) = (cmp.minor, cmp.patch) else {
        return Range::empty();
    };

    Range::between(
        Version {
            major: cmp.major,
            minor,
            patch,
            pre: Prerelease::new("0").unwrap(),
            build: BuildMetadata::EMPTY,
        },
        Version::new(cmp.major, minor, patch),
    )
}

fn simplified_to_normal(input: &Range<Version>) -> Range<Version> {
    Range::from_iter(
        input
            .iter()
            .map(|(from, to)| simplified_bounds_to_normal((from.clone(), to.clone()))),
    )
}

pub(crate) fn bump_major(v: &Version) -> Bound<Version> {
    match v.major.checked_add(1) {
        Some(new) => Bound::Excluded(Version {
            major: new,
            minor: 0,
            patch: 0,
            pre: Prerelease::new("0").unwrap(),
            build: BuildMetadata::EMPTY,
        }),
        None => Bound::Unbounded,
    }
}

pub(crate) fn bump_minor(v: &Version) -> Bound<Version> {
    match v.minor.checked_add(1) {
        Some(new) => Bound::Excluded(Version {
            major: v.major,
            minor: new,
            patch: 0,
            pre: Prerelease::new("0").unwrap(),
            build: BuildMetadata::EMPTY,
        }),
        None => bump_major(v),
    }
}

pub(crate) fn bump_patch(v: &Version) -> Bound<Version> {
    match v.patch.checked_add(1) {
        Some(new) => Bound::Excluded(Version {
            major: v.major,
            minor: v.minor,
            patch: new,
            pre: Prerelease::new("0").unwrap(),
            build: BuildMetadata::EMPTY,
        }),
        None => bump_minor(v),
    }
}

pub(crate) fn bump_pre(v: &Version) -> Bound<Version> {
    if !v.pre.is_empty() {
        Bound::Excluded(Version {
            major: v.major,
            minor: v.minor,
            patch: v.patch,
            pre: Prerelease::new(&format!("{}.0", v.pre)).unwrap(),
            build: BuildMetadata::EMPTY,
        })
    } else {
        bump_patch(v)
    }
}

pub(crate) fn between(low: Version, into: impl Fn(&Version) -> Bound<Version>) -> Range<Version> {
    let hight = into(&low);
    Range::from_range_bounds((Bound::Included(low), hight))
}

fn bump_up_to_normal(v: &Version) -> Option<Version> {
    if v.pre.is_empty() {
        None
    } else {
        Some(Version {
            major: v.major,
            minor: v.minor,
            patch: v.patch,
            pre: Prerelease::EMPTY,
            build: BuildMetadata::EMPTY,
        })
    }
}

pub(crate) fn simplified_bounds_to_normal(
    bounds: (Bound<Version>, Bound<Version>),
) -> (Bound<Version>, Bound<Version>) {
    let (mut from, mut to) = bounds;
    if let Bound::Included(f) | Bound::Excluded(f) = &from
        && let Some(n) = bump_up_to_normal(f)
    {
        from = Bound::Included(n)
    };
    if let Bound::Included(f) | Bound::Excluded(f) = &to
        && let Some(n) = bump_up_to_normal(f)
    {
        to = Bound::Excluded(n)
    };
    (from, to)
}

#[cfg(test)]
mod test {
    use std::{collections::HashSet, dbg, eprintln, format, ops::RangeBounds};

    use super::*;
    use crate::semver;

    const OPS: &[&str] = &["^", "~", "=", "<", ">", "<=", ">="];

    #[test]
    fn test_contains_overflow() {
        for op in OPS {
            for psot in [
                "0.0.18446744073709551615",
                "0.18446744073709551615.0",
                "0.18446744073709551615.1",
                "0.18446744073709551615.18446744073709551615",
                "0.18446744073709551615",
                "18446744073709551615",
                "18446744073709551615.0",
                "18446744073709551615.1",
                "18446744073709551615.18446744073709551615",
                "18446744073709551615.18446744073709551615.0",
                "18446744073709551615.18446744073709551615.1",
                "18446744073709551615.18446744073709551615.18446744073709551615",
            ] {
                let raw_req = format!("{op}{psot}");
                let req = semver::VersionReq::parse(&raw_req).unwrap();
                let pver: SemverPubgrub = (&req).into();
                let bounding_range = pver.bounding_range();
                let raw_ver = "18446744073709551615.1.0";
                let ver = semver::Version::parse(raw_ver).unwrap();
                let mat = req.matches(&ver);
                if mat != pver.contains(&ver) {
                    eprintln!("{}", ver);
                    eprintln!("{}", req);
                    dbg!(&pver);
                    assert_eq!(mat, pver.contains(&ver));
                }

                if mat {
                    assert!(bounding_range.unwrap().contains(&ver));
                }
            }
        }
    }

    #[test]
    fn test_contains_pre() {
        for op in OPS {
            for psot in [
                "0, <=0.0.1-z0",
                "0, ^0.0.0-0",
                "0.0, <=0.0.1-z0",
                "0.0.1, <=0.0.1-z0",
                "0.9.8-r",
                "0.9.8-r, >0.8",
                "0.9.8-r, ~0.9.1",
                "1, <=0.0.1-z0",
                "1, <=1.0.1-z0",
                "1.0, <=1.0.1-z0",
                "1.0.1, <=1.0.1-z0",
                "1.1, <=1.0.1-z0",
                "0.0.1-r",
                "0.0.2-r",
                "0.0.2-r, ^0.0.1",
            ] {
                let raw_req = format!("{op}{psot}");
                let req = semver::VersionReq::parse(&raw_req).unwrap();
                let pver: SemverPubgrub = (&req).into();
                let bounding_range = pver.bounding_range();
                for raw_ver in ["0.0.0-0", "0.0.1-z0", "0.0.2-z0", "0.9.8-z", "1.0.1-z0"] {
                    let ver = semver::Version::parse(raw_ver).unwrap();
                    let mat = req.matches(&ver);
                    if mat != pver.contains(&ver) {
                        eprintln!("{}", ver);
                        eprintln!("{}", req);
                        dbg!(&pver);
                        assert_eq!(mat, pver.contains(&ver));
                    }

                    if mat {
                        assert!(bounding_range.unwrap().contains(&ver));
                    }
                }
            }
        }
    }

    #[test]
    fn test_only_one_compatibility_range() {
        let raw_vers = [
            "0.0.0-0", "0.0.0-r", "0.0.0", "0.0.1-0", "0.0.1-r", "0.0.1", "0.0.2-0", "0.0.2-r",
            "0.0.2", "0.1.0-0", "0.1.0-r", "0.1.0", "0.1.1", "0.2.0-0", "0.2.0-r", "0.2.0",
            "1.0.0-0", "1.0.0-r", "1.0.0", "1.1.0", "2.0.0-0", "2.0.0-r", "2.0.0", "3.0.0",
        ];
        let vers = raw_vers.map(|raw_ver| semver::Version::parse(raw_ver).unwrap());
        assert!(vers.is_sorted());
        assert!(vers.is_sorted_by_key(SemverCompatibility::from));
        for op in OPS {
            for psot in [
                "0.0.0-r",
                "0.0.0",
                "0.0.1-r",
                "0.0.1",
                "0.1.0-r",
                "0.1.0",
                "1.0.0-r",
                "1.0.0",
                "0.0.0, <=0.0.1",
                "0.0.0-r, <=0.0.1-0",
                "0.0.1, <=0.0.2",
                "0.0.1-r, <=0.0.2-0",
                "0.1.0, <=0.2.0",
                "0.1.0-r, <=0.2.0-0",
                "1.0.0, <=2.0.0",
                "1.0.0-r, <=2.0.0-0",
            ] {
                let raw_req = format!("{op}{psot}");
                let req = semver::VersionReq::parse(&raw_req).unwrap();
                let pver: SemverPubgrub = (&req).into();
                dbg!(raw_req);

                let set: HashSet<_> = vers
                    .iter()
                    .filter_map(|ver| {
                        let mat = req.matches(ver);
                        if mat != pver.contains(ver) {
                            eprintln!("{}", ver);
                            eprintln!("{}", req);
                            dbg!(&pver);
                            assert_eq!(mat, pver.contains(ver));
                        }
                        let cap: SemverCompatibility = ver.into();
                        mat.then_some(cap)
                    })
                    .collect();

                let bounding_range = pver.only_one_compatibility_range();
                assert_eq!(set.len() <= 1, bounding_range.is_some());
            }
        }
    }

    #[test]
    fn test_only_one_compatibility_range_singletons() {
        let raw_vers = [
            "0.0.0-0", "0.0.0-r", "0.0.0", "0.0.1-0", "0.0.1-r", "0.0.1", "0.0.2-0", "0.0.2-r",
            "0.0.2", "0.1.0-0", "0.1.0-r", "0.1.0", "0.1.1", "0.2.0-0", "0.2.0-r", "0.2.0",
            "1.0.0-0", "1.0.0-r", "1.0.0", "1.1.0", "2.0.0-0", "2.0.0-r", "2.0.0", "3.0.0",
        ];
        let vers = raw_vers.map(|raw_ver| semver::Version::parse(raw_ver).unwrap());
        assert!(vers.is_sorted());
        assert!(vers.is_sorted_by_key(SemverCompatibility::from));
        let reqs = vers.clone().map(|v| SemverPubgrub::singleton(v.clone()));
        for pver in &reqs {
            pver.as_singleton().unwrap();
            // Singletons can only match one thing so they definitely only match one compatibility
            // range.
            pver.only_one_compatibility_range().unwrap();
        }

        let req_unions = reqs
            .iter()
            .flat_map(|req1| reqs.iter().map(|req2: &SemverPubgrub| req1.union(req2)));

        for preq in req_unions {
            let set: HashSet<SemverCompatibility> =
                vers.iter().filter(|ver| preq.contains(ver)).map(|ver| ver.into()).collect();
            let only_one_comp = preq.only_one_compatibility_range();
            dbg!(&preq, &set, only_one_comp);
            assert_eq!(set.len() <= 1, only_one_comp.is_some());
            if only_one_comp.is_none() {
                assert!(preq.as_singleton().is_none());
            }
            if preq.as_singleton().is_some() {
                assert_eq!(set.len(), 1);
            }
        }
    }
}
