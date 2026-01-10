use core::fmt;

#[cfg(feature = "serde")]
use miden_assembly_syntax::debuginfo::SourceId;
use miden_assembly_syntax::debuginfo::Span;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::*;
#[cfg(feature = "serde")]
use crate::ast::parsing::SetSourceId;
use crate::{LexicographicWord, Word};

/// Represents a requirement on a specific version (or versions) of a dependency.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[repr(u8)]
pub enum VersionRequirement {
    /// A semantic versioning constraint, e.g. `~> 0.1`
    ///
    /// In general, this is meant to indicate that any version of a package that satisfies the
    /// version constraint can be used to resolve the dependency.
    ///
    /// This form of constraint also permits us to compile a dependency from source, so long as
    /// the semantic versioning constraint is satisfied.
    Semantic(Span<VersionReq>),
    /// The most precise and onerous form of versioning constraint.
    ///
    /// This requires that the dependency's package digest exactly matches the one provided here.
    ///
    /// Digest constraints also effectively require that the dependency already be compiled to a
    /// Miden package, as digests are derived from the MAST of a compiled package. This means that
    /// when the dependency is resolved, we must be able to find a `.masp` file with the expected
    /// digest.
    Digest(Span<Word>),
}

impl VersionRequirement {
    /// Gets a version requirement that matches any version
    pub fn any() -> Self {
        Self::Semantic(Span::unknown(VersionReq::STAR))
    }

    /// Returns true if this version requirement is a semantic versioning requirement
    pub fn is_semantic_version(&self) -> bool {
        matches!(self, Self::Semantic(_))
    }

    /// Returns true if this version requirement requires an exact digest match
    pub fn is_digest(&self) -> bool {
        matches!(self, Self::Digest(_))
    }
}

#[cfg(feature = "serde")]
impl SetSourceId for VersionRequirement {
    fn set_source_id(&mut self, source_id: SourceId) {
        match self {
            Self::Semantic(version) => version.set_source_id(source_id),
            Self::Digest(digest) => digest.set_source_id(source_id),
        }
    }
}

impl Eq for VersionRequirement {}

impl PartialEq for VersionRequirement {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Semantic(l), Self::Semantic(r)) => l == r,
            (Self::Semantic(_), Self::Digest(_)) | (Self::Digest(_), Self::Semantic(_)) => false,
            (Self::Digest(l), Self::Digest(r)) => {
                LexicographicWord::new(l.into_inner()) == LexicographicWord::new(r.into_inner())
            },
        }
    }
}

impl fmt::Display for VersionRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Semantic(v) => fmt::Display::fmt(v, f),
            Self::Digest(word) => fmt::Display::fmt(word, f),
        }
    }
}

impl From<VersionReq> for VersionRequirement {
    fn from(version: VersionReq) -> Self {
        Self::Semantic(Span::unknown(version))
    }
}

impl From<Word> for VersionRequirement {
    fn from(digest: Word) -> Self {
        Self::Digest(Span::unknown(digest))
    }
}

/// Convert a [VersionReq] to a set of concrete [SemVer] bounds, for used with [BTreeMap::range].
///
/// This takes the semantic versioning constraints of `req` and finds the minimum and maximum
/// versions that can satisfy `req` based on the rules for satisfying those constraints.
///
/// To determine if the resulting range is empty or not, use `Range::contains` on the resulting
/// tuple.
#[cfg(feature = "arbitrary")]
pub(crate) fn bounding_range(
    req: &VersionReq,
) -> (core::ops::Bound<SemVer>, core::ops::Bound<SemVer>) {
    use core::ops::Bound::*;

    use crate::semver::{BuildMetadata, Op, Prerelease};

    let mut min = None;
    let mut max = None;
    let mut min_inclusive = true;
    let mut max_inclusive = false;
    for comparator in &req.comparators {
        let major = comparator.major;
        let minor = comparator.minor.unwrap_or(0);
        let patch = comparator.patch.unwrap_or(0);
        let pre = if comparator.patch.is_some() {
            comparator.pre.clone()
        } else {
            Prerelease::EMPTY
        };
        match comparator.op {
            Op::Exact | Op::Wildcard => {
                match (comparator.minor.is_some(), comparator.patch.is_some()) {
                    (true, true) => {
                        min = Some(SemVer {
                            major,
                            minor,
                            patch,
                            pre,
                            build: BuildMetadata::EMPTY,
                        });
                        max = min.clone();
                        max_inclusive = true;
                    },
                    (true, false) => {
                        let min_version = SemVer {
                            major,
                            minor,
                            patch,
                            pre,
                            build: BuildMetadata::EMPTY,
                        };
                        let max_version = SemVer { minor: minor + 1, ..min_version.clone() };
                        min = Some(min_version);
                        max = Some(max_version);
                    },
                    (false, false) => {
                        let min_version = SemVer {
                            major,
                            minor,
                            patch,
                            pre,
                            build: BuildMetadata::EMPTY,
                        };
                        let max_version = SemVer { major: major + 1, ..min_version.clone() };
                        min = Some(min_version);
                        max = Some(max_version);
                    },
                    _ => unreachable!(),
                }
            },
            Op::Caret => {
                max_inclusive = false;
                match (comparator.minor.is_some(), comparator.patch.is_some()) {
                    (true, true) if major > 0 => {
                        min = Some(SemVer {
                            major,
                            minor,
                            patch,
                            pre,
                            build: BuildMetadata::EMPTY,
                        });
                        max = Some(SemVer {
                            major: major + 1,
                            minor: 0,
                            patch: 0,
                            pre: Prerelease::EMPTY,
                            build: BuildMetadata::EMPTY,
                        });
                    },
                    (true, true) if minor > 0 => {
                        min = Some(SemVer {
                            major,
                            minor,
                            patch,
                            pre,
                            build: BuildMetadata::EMPTY,
                        });
                        max = Some(SemVer {
                            major,
                            minor: minor + 1,
                            patch: 0,
                            pre: Prerelease::EMPTY,
                            build: BuildMetadata::EMPTY,
                        });
                    },
                    (true, true) => {
                        max_inclusive = true;
                        min = Some(SemVer {
                            major,
                            minor,
                            patch,
                            pre,
                            build: BuildMetadata::EMPTY,
                        });
                        max = min.clone();
                    },
                    (true, false) if major > 0 || minor > 0 => {
                        min = Some(SemVer {
                            major,
                            minor,
                            patch,
                            pre,
                            build: BuildMetadata::EMPTY,
                        });
                        max = Some(SemVer {
                            major: major + 1,
                            minor: 0,
                            patch: 0,
                            pre: Prerelease::EMPTY,
                            build: BuildMetadata::EMPTY,
                        });
                    },
                    (true, false) => {
                        min = Some(SemVer {
                            major,
                            minor,
                            patch,
                            pre,
                            build: BuildMetadata::EMPTY,
                        });
                        max = Some(SemVer {
                            major,
                            minor: minor + 1,
                            patch: 0,
                            pre: Prerelease::EMPTY,
                            build: BuildMetadata::EMPTY,
                        });
                    },
                    (false, false) => {
                        min = Some(SemVer {
                            major,
                            minor,
                            patch,
                            pre,
                            build: BuildMetadata::EMPTY,
                        });
                        max = Some(SemVer {
                            major: major + 1,
                            minor: 0,
                            patch: 0,
                            pre: Prerelease::EMPTY,
                            build: BuildMetadata::EMPTY,
                        });
                    },
                    _ => unreachable!(),
                }
            },
            Op::Tilde => {
                max_inclusive = false;

                min = Some(SemVer {
                    major,
                    minor,
                    patch,
                    pre,
                    build: BuildMetadata::EMPTY,
                });
                if comparator.minor.is_some() {
                    max = Some(SemVer {
                        major,
                        minor: minor + 1,
                        patch: 0,
                        pre: Prerelease::EMPTY,
                        build: BuildMetadata::EMPTY,
                    });
                } else {
                    max = Some(SemVer {
                        major: major + 1,
                        minor: 0,
                        patch: 0,
                        pre: Prerelease::EMPTY,
                        build: BuildMetadata::EMPTY,
                    });
                }
            },
            Op::Greater => {
                min_inclusive = false;
                let mut min_version = SemVer {
                    major,
                    minor,
                    patch,
                    pre,
                    build: BuildMetadata::EMPTY,
                };
                if comparator.minor.is_none() {
                    min_version.major += 1;
                } else if comparator.patch.is_none() {
                    min_version.minor += 1;
                }
                min = Some(min_version);
            },
            Op::GreaterEq => {
                min = Some(SemVer {
                    major,
                    minor,
                    patch,
                    pre,
                    build: BuildMetadata::EMPTY,
                });
            },
            Op::Less => {
                max = Some(SemVer {
                    major,
                    minor,
                    patch,
                    pre,
                    build: BuildMetadata::EMPTY,
                });
            },
            Op::LessEq => {
                max_inclusive = true;
                let minor = if comparator.patch.is_some() { minor } else { minor + 1 };
                let major = if comparator.minor.is_some() { major } else { major + 1 };
                max = Some(SemVer {
                    major,
                    minor,
                    patch,
                    pre,
                    build: BuildMetadata::EMPTY,
                });
            },
            op => panic!("unhandled semantic versioning operator: {op:#?}"),
        }
    }

    let min = if let Some(min) = min {
        if min_inclusive { Included(min) } else { Excluded(min) }
    } else {
        Unbounded
    };

    let max = if let Some(max) = max {
        if max_inclusive { Included(max) } else { Excluded(max) }
    } else {
        Unbounded
    };

    (min, max)
}

#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for VersionRequirement {
    type Parameters = ();
    type Strategy = proptest::prelude::BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use miden_core::Felt;
        use proptest::{array, prelude::*};

        let semver_strategy =
            (0u32..3u32, 0u32..10u32, 0u32..10u32).prop_map(|(maj, min, patch)| {
                if maj == 0 && min == 0 && patch == 0 {
                    VersionReq::STAR
                } else if patch == 0 {
                    VersionReq::parse(&format!("^{maj}.{min}")).unwrap()
                } else {
                    VersionReq::parse(&format!("^{maj}.{min}.{patch}")).unwrap()
                }
            });

        prop_oneof![
            array::uniform4(0u64..u64::MAX).prop_map(|word| Self::Digest(Span::unknown(
                [Felt::new(word[0]), Felt::new(word[1]), Felt::new(word[2]), Felt::new(word[3])]
                    .into()
            ))),
            semver_strategy.prop_map(|semver| Self::Semantic(Span::unknown(semver))),
        ]
        .boxed()
    }
}
