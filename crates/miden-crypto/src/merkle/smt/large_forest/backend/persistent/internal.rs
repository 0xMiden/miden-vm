//! Contains internal functionality for interacting with RocksDB that is not exposed in the RocksDB
//! crate or the RocksDB C wrapper.

use crate::merkle::smt::large_forest::backend::persistent::WriteBatch;

/// Merges the provided [`WriteBatch`]es into a single batch using efficient raw-memory operations.
///
/// This is intended to be equivalent to `WriteBatchInternal::Append` in the C++ codebase, but that
/// function is not exposed in the C API or the Rust wrapper for RocksDB.
///
/// **This function must be revisited every time the RocksDB crate is updated to ensure that it
/// operates correctly.**
///
/// # `WriteBatch` Layout
///
/// The basic format of a `WriteBatch` is as follows:
///
/// ```text
/// [sequence: u64le][count: u32le][record0][record1]...
/// ```
///
/// Each record contains:
///
/// - A **type tag** (e.g. `kTypeColumnFamilyValue` or `kTypeColumnFamilyDeletion`) which determines
///   how to read the rest of the underlying data.
/// - A **column family ID** `varint32_cf_id` which identifies the column family into which the
///   record will be written.
/// - A **key** `&[u8]` that is the key in the column.
/// - A **value** `&[u8]` that is the value for the given key in the column.
///
/// # Alternatives
///
/// An alternative to this would be to use a transaction-based RocksDB instance instead, and perform
/// the merging using `Transaction::rebuild_from_writebatch`. This is semantically equivalent, but
/// requires involving the whole transaction machinery. It ends up being significantly more
/// heavyweight than this solution, almost doubling the amount of time the batch forest update takes
/// to run.
///
/// # Panics
///
/// - If the data for either the left or right batch is corrupt, as this indicates a bug in the
///   underlying RocksDB implementation and should not be continued with.
pub fn merge_batches(left: WriteBatch, right: &WriteBatch) -> WriteBatch {
    const SEQUENCE_SIZE: usize = size_of::<u64>();
    const COUNT_SIZE: usize = size_of::<u32>();
    const HEADER_SIZE: usize = SEQUENCE_SIZE + COUNT_SIZE;

    let left_data = left.data();
    let right_data = right.data();

    // We initially check that we have enough data to make this at all sane, returning a corruption
    // error if not.
    if right_data.len() < HEADER_SIZE {
        panic!("Right write batch contained insufficient data of {} bytes", right_data.len());
    }
    if left_data.len() < HEADER_SIZE {
        panic!("Left write batch contained insufficient data of {} bytes", left_data.len());
    }

    // We then parse out the counts, returning an error if they are not valid u32 values.
    let left_count = u32::from_le_bytes(
        left_data[8..12]
            .try_into()
            .unwrap_or_else(|e| panic!("Left's count was not a valid u32: {e}")),
    );
    let right_count = u32::from_le_bytes(
        right_data[8..12]
            .try_into()
            .unwrap_or_else(|e| panic!("Right's count was not a valid u32: {e}")),
    );

    // If that is good, we take `left` as our starting point, update the counts, and then append the
    // records from right.
    let mut new_data = left_data.to_vec();
    new_data[SEQUENCE_SIZE..HEADER_SIZE].copy_from_slice(
        left_count
            .checked_add(right_count)
            .expect("Overflow cannot occur")
            .to_le_bytes()
            .as_ref(),
    );
    new_data.extend_from_slice(&right_data[HEADER_SIZE..]);

    WriteBatch::from_data(&new_data)
}
