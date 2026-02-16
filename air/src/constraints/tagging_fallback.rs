//! No-op tagging helpers for non-testing builds.
//!
//! This keeps the production/no-std build free of std-only machinery while letting test builds
//! enable full tagging via the real module.

use miden_crypto::stark::air::MidenAirBuilder;

#[path = "tagging/manifest.rs"]
mod manifest;

#[allow(dead_code)]
pub use manifest::{
    CURRENT_MAX_ID, TAG_RANGE_BASE, TAG_RANGE_COUNT, TAG_SYSTEM_BASE, TAG_SYSTEM_COUNT, TOTAL_TAGS,
};

/// No-op tagging extension for non-testing builds.
///
/// The methods call the provided closure directly so they have no runtime overhead beyond
/// the call itself (which the optimizer should inline away).
#[allow(dead_code)]
pub trait TaggingAirBuilderExt: MidenAirBuilder {
    fn tagged<R>(
        &mut self,
        _id: usize,
        _namespace: &'static str,
        f: impl FnOnce(&mut Self) -> R,
    ) -> R {
        f(self)
    }

    fn tagged_list<R, const N: usize>(
        &mut self,
        _ids: [usize; N],
        _namespace: &'static str,
        f: impl FnOnce(&mut Self) -> R,
    ) -> R {
        f(self)
    }
}

impl<T: MidenAirBuilder> TaggingAirBuilderExt for T {}
