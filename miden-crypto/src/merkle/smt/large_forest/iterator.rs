//! This module contains the implementation of the iterator over the entries of an arbitrary tree in
//! the forest.
//!
//! # Performance
//!
//! The performance of this iterator has a significant dependency on the tree that it is running
//! over. Due to the differing performance characteristics of backends, we cannot provide exact
//! performance bounds, but the following general rules apply.
//!
//! - Iterating over the entries of the **latest tree in a lineage** is going to be **the fastest
//!   possible query**. This depends only on the direct iteration performance of the backend in
//!   question.
//! - Iterating over the entries of **a historical tree is going to be slower**. This is because it
//!   has to do work to merge the entries provided by the history with the entries of the full tree
//!   in order to create a coherent picture of the historical tree.
//!
//! We highly recommend benchmarking the iteration behavior on the concrete workload(s) you are
//! concerned about, rather than trying to statically reason about performance of this iterator.

use alloc::boxed::Box;
use core::iter::Peekable;

use miden_field::Word;

use super::Result;
use crate::{
    Set,
    merkle::smt::large_forest::{history::HistoryView, root::TreeEntry},
};

// ENTRIES ITERATOR
// ================================================================================================

/// An iterator over the entries of an arbitrary tree in the forest, yielding entries in an
/// arbitrary order.
///
/// - If any error occurs during iteration, this is signaled to the user by the iterator yielding
///   `Some(Err(...))`. The user should stop on first error, as the iterator will be in an
///   inconsistent state afterward.
/// - `None` is returned if the true end of the iterator is reached successfully, or at any point
///   after an error has been yielded.
///
/// It is split into two variants for performance, as iterating over a full tree is significantly
/// simpler than iterating over a historical tree. While it would be nice to be able to return one
/// of two different iterators depending on the circumstances of construction, Rust's `impl Trait`
/// bounds do not allow for this.
///
/// The iterator **must never transition between variants** during the process of iteration.
///
/// The order in which the results are yielded is undefined.
pub(super) enum EntriesIterator<'forest> {
    /// An iterator over a tree in the forest that is formed from a merger of the full tree and a
    /// historical overlay.
    WithHistory {
        /// The iterator over the entries in the full tree.
        ///
        /// This iterator should never yield any entries where `value == EMPTY_WORD`.
        full_tree_iter:
            Peekable<Box<dyn Iterator<Item = super::backend::Result<TreeEntry>> + 'forest>>,

        /// The view into the history at the correct point.
        history_view: HistoryView<'forest>,

        /// Tracks the keys in the history that have already been "used" by the iterator, either to
        /// skip an entry (a removal), or to change the value of an entry.
        yielded_history_keys: Set<Word>,

        /// The current state of the iteration state machine.
        state: EntriesIteratorState<'forest>,
    },

    /// An iterator over a tree in the forest that is simply an iterator over the full tree.
    WithoutHistory {
        /// The iterator over the entries in the full tree.
        full_tree_iter: Box<dyn Iterator<Item = super::backend::Result<TreeEntry>> + 'forest>,

        /// Whether the iterator has encountered an error and should yield no more items.
        faulted: bool,
    },
}

impl<'forest> EntriesIterator<'forest> {
    /// Constructs a new entries iterator pointing to the first item in the designated `tree` in the
    /// `forest`, formed by combining a historical overlay with the current tree.
    ///
    /// Note that it _does not_ perform checks as to the correctness of the provided iterators.
    pub(super) fn new_with_history(
        full_tree_iter: impl Iterator<Item = super::backend::Result<TreeEntry>> + 'forest,
        history_view: HistoryView<'forest>,
    ) -> Self {
        // This type gymnastics is unfortunately necessary to let us easily store the `Peekable`
        // which we need to avoid carrying additional state in the state machine.
        let full_tree_iter: Box<dyn Iterator<Item = _>> = Box::new(full_tree_iter);

        Self::WithHistory {
            full_tree_iter: full_tree_iter.peekable(),
            history_view,
            yielded_history_keys: Set::new(),
            state: EntriesIteratorState::Initial,
        }
    }

    /// Constructs a new entries iterator pointing to the first item in the designated `tree` in the
    /// `forest` without any associated history.
    ///
    /// Note that it _does not_ check whether `full_tree_iter` is actually an iterator over the
    /// full tree. If it is not, this iterator will yield invalid results.
    pub(super) fn new_without_history(
        full_tree_iter: impl Iterator<Item = super::backend::Result<TreeEntry>> + 'forest,
    ) -> Self {
        let full_tree_iter = Box::new(full_tree_iter);
        Self::WithoutHistory { full_tree_iter, faulted: false }
    }

    /// Advances the iterator and returns the next value in the case where it is iterating over a
    /// historical tree version.
    ///
    /// # Panics
    ///
    /// - If the method is called with a `self` that is not in the [`Self::WithHistory`] variant.
    #[inline(always)] // To help the optimizer eliminate the redundant check in Iterator::next()
    fn next_with_history(&mut self) -> Option<Result<TreeEntry>> {
        let EntriesIterator::WithHistory {
            full_tree_iter,
            history_view,
            yielded_history_keys,
            state,
        } = self
        else {
            panic!("EntriesIterator::next_with_history called without history")
        };

        loop {
            match state {
                EntriesIteratorState::Faulted => return None,
                EntriesIteratorState::Initial => {
                    // In the initial state we need to advance to the appropriate next state.
                    if full_tree_iter.peek().is_none() {
                        // If there is nothing left to read from the full-tree iterator, we move
                        // into the history iteration state.
                        let iterator = Box::new(
                            history_view
                                .changed_keys()
                                .map(|(key, value)| TreeEntry { key, value }),
                        );
                        *state = EntriesIteratorState::ReadingHistory { iterator };
                    } else {
                        // Otherwise we proceed with the full tree.
                        *state = EntriesIteratorState::ReadingFullTree;
                    }
                    continue;
                },
                EntriesIteratorState::ReadingFullTree => {
                    // If we are reading the full tree's iterator, we need to keep advancing as long
                    // as we can, but we have to remove entries using the
                    // history.
                    if full_tree_iter.peek().is_none() {
                        // If we have nothing left to read, we transition into the reading history
                        // state,
                        let iterator = Box::new(
                            history_view
                                .changed_keys()
                                .map(|(key, value)| TreeEntry { key, value }),
                        );
                        *state = EntriesIteratorState::ReadingHistory { iterator };
                        continue;
                    }

                    let Some(entry) = full_tree_iter.next() else {
                        unreachable!("The iterator is known to have another item available");
                    };
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(e) => {
                            *state = EntriesIteratorState::Faulted;
                            return Some(Err(e.into()));
                        },
                    };

                    let value = if let Some(v) = history_view.value(&entry.key) {
                        // If the history has a value for this key, then we need to return that
                        // instead. We also store the key so we do not return it again by accident.
                        yielded_history_keys.insert(entry.key);

                        // If it is an empty value we don't want to return it so we continue the
                        // outer loop.
                        if v.is_empty() {
                            continue;
                        }

                        TreeEntry { key: entry.key, value: v }
                    } else {
                        entry
                    };

                    return Some(Ok(value));
                },
                EntriesIteratorState::ReadingHistory { iterator } => {
                    // This is a terminal state. We cannot transition to any other state from here,
                    // and so the iterator ends when the iterator over the added
                    // history items does.
                    for entry in iterator.by_ref() {
                        if !yielded_history_keys.contains(&entry.key) && !entry.value.is_empty() {
                            return Some(Ok(entry));
                        }

                        // Here we have already returned this entry, or it is empty. In both cases
                        // we want to skip it, so we let the loop continue.
                    }
                    return None;
                },
            }
        }
    }

    /// Advances the iterator and returns the next value in the case where it is iterating over the
    /// current tree version.
    ///
    /// # Panics
    ///
    /// - If the method is called with a `self` that is not the [`Self::WithoutHistory`] variant.
    #[inline(always)] // To help the optimizer eliminate the redundant check in Iterator::next()
    fn next_without_history(&mut self) -> Option<Result<TreeEntry>> {
        // Note that the inner iterator yields items of type `backend::Result` while this one
        // yields the outer result. Conversion happening via the standard `Into::into` conversion
        // for Result.
        let EntriesIterator::WithoutHistory { full_tree_iter, faulted } = self else {
            panic!("EntriesIterator::next_without_history called with history")
        };

        if *faulted {
            return None;
        }

        let result = full_tree_iter.next().map(|e| e.map_err(Into::into));
        if matches!(&result, Some(Err(_))) {
            *faulted = true;
        }
        result
    }
}

// ITERATOR TRAIT
// ================================================================================================

impl Iterator for EntriesIterator<'_> {
    type Item = Result<TreeEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            EntriesIterator::WithHistory { .. } => self.next_with_history(),
            EntriesIterator::WithoutHistory { .. } => self.next_without_history(),
        }
    }
}

// ENTRIES ITERATOR STATE
// ================================================================================================

/// The state machine that is the entries iterator for the forest.
pub(super) enum EntriesIteratorState<'forest> {
    /// The initial state of the iterator, indicating that it has never advanced the underlying
    /// iterator.
    Initial,

    /// Indicates that the iterator is currently reading from the full-tree's iterator, and yielding
    /// results from that.
    ReadingFullTree,

    /// Indicates that the iterator is currently reading from the additional pairs added by the
    /// history delta.
    ReadingHistory {
        /// The iterator over the entries that are _added_ by the history.
        iterator: Box<dyn Iterator<Item = TreeEntry> + 'forest>,
    },

    /// The iterator has encountered an error and will yield no more items.
    Faulted,
}
