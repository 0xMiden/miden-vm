//! No-op tagging helpers for non-testing or no-std builds.

use miden_crypto::stark::air::MidenAirBuilder;

/// No-op tagging extension for non-testing builds.
///
/// The methods call the provided closure directly so they have no runtime overhead beyond
/// the call itself (which the optimizer should inline away).
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
