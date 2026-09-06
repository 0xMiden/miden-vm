//! Typed output of the deferred transcript's native Eidos chiplet.

use core::cmp::Ordering;

use miden_core::{Felt, deferred::Digest};

/// Output digest of a framed Eidos absorption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct EidosDigest(pub [Felt; 4]);

impl EidosDigest {
    pub fn as_array(&self) -> [Felt; 4] {
        self.0
    }
}

impl PartialOrd for EidosDigest {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EidosDigest {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .map(|felt| felt.as_canonical_u64())
            .cmp(&other.0.map(|felt| felt.as_canonical_u64()))
    }
}

impl From<Digest> for EidosDigest {
    fn from(digest: Digest) -> Self {
        Self(digest.into_elements())
    }
}
