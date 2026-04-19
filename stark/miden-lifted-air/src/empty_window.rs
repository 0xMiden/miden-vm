//! A zero-width window that prevents access to preprocessed columns.
//!
//! Lifted AIRs have no preprocessed trace. [`EmptyWindow`] encodes this invariant:
//! AIR validation prevents preprocessed access, and the window methods are
//! unreachable as a defence-in-depth measure.

use core::marker::PhantomData;

use p3_air::WindowAccess;

/// A window type for traces that must never be accessed.
///
/// Satisfies the `WindowAccess<T> + Clone` bound required by
/// [`AirBuilder::PreprocessedWindow`](p3_air::AirBuilder::PreprocessedWindow).
/// Lifted AIRs have no preprocessed trace, so these methods should never be
/// called; AIR validation prevents this at a higher level.
#[derive(Debug, Clone, Copy)]
pub struct EmptyWindow<T>(PhantomData<T>);

impl<T> EmptyWindow<T> {
    /// Static reference to an empty window.
    ///
    /// Safe because `EmptyWindow` is a ZST — no actual `T` is stored,
    /// so the `'static` lifetime is always valid.
    pub fn empty_ref() -> &'static Self {
        &EmptyWindow(PhantomData)
    }
}

impl<T> WindowAccess<T> for EmptyWindow<T> {
    fn current_slice(&self) -> &[T] {
        unreachable!("preprocessed trace does not exist in lifted AIRs")
    }

    fn next_slice(&self) -> &[T] {
        unreachable!("preprocessed trace does not exist in lifted AIRs")
    }
}
