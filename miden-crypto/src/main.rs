#[cfg(any(test, feature = "rocksdb"))]
use std::path::Path;
use std::{path::PathBuf, time::Instant};

use clap::{Parser, ValueEnum};
#[cfg(feature = "rocksdb")]
use miden_crypto::merkle::smt::{RocksDbConfig, RocksDbStorage};
use miden_crypto::{
    EMPTY_WORD, Felt, ONE, Word,
    hash::poseidon2::Poseidon2,
    merkle::smt::{LargeSmt, LargeSmtError, MemoryStorage, StorageError},
    rand::test_utils::rand_value,
};
use rand::{RngExt, prelude::IteratorRandom, rng};

#[cfg(feature = "executable")]
mod boxed_storage;
use boxed_storage::{BoxedSmtStorage as Storage, BoxedStorage};

#[derive(Parser, Debug)]
#[command(name = "Benchmark", about = "SMT benchmark", version, rename_all = "kebab-case")]
pub struct BenchmarkCmd {
    /// Size of the tree
    #[arg(short = 's', long = "size", default_value = "1000000")]
    size: usize,
    /// Number of insertions
    #[arg(short = 'i', long = "insertions", default_value = "10000")]
    insertions: usize,
    /// Number of updates
    #[arg(short = 'u', long = "updates", default_value = "10000")]
    updates: usize,
    /// Path for the benchmark database
    #[clap(short = 'p', long = "path")]
    storage_path: Option<PathBuf>,
    /// Open existing database and skip construction
    #[clap(short = 'o', long = "open", default_value = "false")]
    open: bool,
    /// Delete an existing benchmark database path before creating a new one
    #[clap(long = "reset", default_value = "false")]
    reset: bool,
    /// Number of batch operations
    #[clap(short = 'b', long = "batches", default_value = "1")]
    batches: usize,
    /// Storage backend to use at runtime: memory or rocksdb
    #[arg(long = "storage", value_enum, default_value = "memory")]
    storage: StorageKind,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum StorageKind {
    Memory,
    Rocksdb,
}

fn main() -> Result<(), LargeSmtError> {
    benchmark_smt()?;
    println!("Benchmark completed successfully");
    Ok(())
}

/// Run a benchmark for [`Smt`].
pub fn benchmark_smt() -> Result<(), LargeSmtError> {
    let args = BenchmarkCmd::parse();
    let tree_size = args.size;
    let insertions = args.insertions;
    let updates = args.updates;
    let storage_path = args.storage_path;
    let batches = args.batches;
    let reset = args.reset;

    println!(
        "Running benchmark with {} storage",
        match args.storage {
            StorageKind::Memory => "memory",
            StorageKind::Rocksdb => "rocksdb",
        }
    );
    assert!(updates <= tree_size, "Cannot update more than `size`");
    // prepare the `leaves` vector for tree creation
    let mut entries = Vec::new();
    for i in 0..tree_size {
        let key = rand_value::<Word>();
        let value = Word::new([ONE, ONE, ONE, Felt::new_unchecked(i as u64)]);
        entries.push((key, value));
    }

    let mut tree = if args.open {
        open_existing(storage_path, args.storage)?
    } else {
        construction(entries.clone(), tree_size, storage_path, args.storage, reset)?
    };
    insertion(&mut tree, insertions)?;
    for _ in 0..batches {
        batched_insertion(&mut tree, insertions)?;
        batched_update(&mut tree, &entries, updates)?;
    }
    proof_generation(&mut tree)?;

    Ok(())
}

/// Runs the construction benchmark for [`Smt`], returning the constructed tree.
pub fn construction(
    entries: Vec<(Word, Word)>,
    size: usize,
    database_path: Option<PathBuf>,
    storage: StorageKind,
    reset: bool,
) -> Result<LargeSmt<Storage>, LargeSmtError> {
    println!("Running a construction benchmark:");
    let now = Instant::now();
    let storage = get_storage(database_path, false, reset, storage)?;
    let tree = LargeSmt::with_entries(storage, entries)?;
    let elapsed = now.elapsed().as_secs_f32();
    println!("Constructed an SMT with {size} key-value pairs in {elapsed:.1} seconds");
    println!("Number of leaf nodes: {}\n", tree.num_leaves());

    Ok(tree)
}

pub fn open_existing(
    storage_path: Option<PathBuf>,
    storage: StorageKind,
) -> Result<LargeSmt<Storage>, LargeSmtError> {
    println!("Opening an existing database:");
    let now = Instant::now();
    let storage = get_storage(storage_path, true, false, storage)?;
    let tree = LargeSmt::load(storage)?;
    let elapsed = now.elapsed().as_secs_f32();
    println!("Opened an existing database in {elapsed:.1} seconds");
    Ok(tree)
}
/// Runs the insertion benchmark for the [`Smt`].
pub fn insertion(tree: &mut LargeSmt<Storage>, insertions: usize) -> Result<(), LargeSmtError> {
    println!("Running an insertion benchmark:");

    let size = tree.num_leaves();
    let mut insertion_times = Vec::new();

    for i in 0..insertions {
        let test_key = Poseidon2::hash(&rand_value::<u64>().to_be_bytes());
        let test_value = Word::new([ONE, ONE, ONE, Felt::new_unchecked((size + i) as u64)]);

        let now = Instant::now();
        tree.insert(test_key, test_value)?;
        let elapsed = now.elapsed();
        insertion_times.push(elapsed.as_micros());
    }

    println!(
        "The average insertion time measured by {insertions} inserts into an SMT with {size} leaves is {:.0} μs\n",
        // calculate the average
        insertion_times.iter().sum::<u128>() as f64 / (insertions as f64),
    );

    Ok(())
}

pub fn batched_insertion(
    tree: &mut LargeSmt<Storage>,
    insertions: usize,
) -> Result<(), LargeSmtError> {
    println!("Running a batched insertion benchmark:");

    let size = tree.num_leaves();

    let new_pairs: Vec<(Word, Word)> = (0..insertions)
        .map(|i| {
            let key = Poseidon2::hash(&rand_value::<u64>().to_be_bytes());
            let value = Word::new([ONE, ONE, ONE, Felt::new_unchecked((size + i) as u64)]);
            (key, value)
        })
        .collect();

    let now = Instant::now();
    let mutations = tree.compute_mutations(new_pairs)?;
    let compute_elapsed = now.elapsed().as_secs_f64() * 1000_f64; // time in ms

    println!(
        "The average insert-batch computation time measured by a {insertions}-batch into an SMT with {size} leaves over {:.1} ms is {:.0} μs",
        compute_elapsed,
        compute_elapsed * 1000_f64 / insertions as f64, // time in μs
    );

    let now = Instant::now();
    tree.apply_mutations(mutations)?;
    let apply_elapsed = now.elapsed().as_secs_f64() * 1000_f64; // time in ms

    println!(
        "The average insert-batch application time measured by a {insertions}-batch into an SMT with {size} leaves over {:.1} ms is {:.0} μs",
        apply_elapsed,
        apply_elapsed * 1000_f64 / insertions as f64, // time in μs
    );

    println!(
        "The average batch insertion time measured by a {insertions}-batch into an SMT with {size} leaves totals to {:.1} ms",
        (compute_elapsed + apply_elapsed),
    );

    println!();

    Ok(())
}

pub fn batched_update(
    tree: &mut LargeSmt<Storage>,
    entries: &[(Word, Word)],
    updates: usize,
) -> Result<(), LargeSmtError> {
    const REMOVAL_PROBABILITY: f64 = 0.2;

    println!("Running a batched update benchmark:");

    let size = tree.num_leaves();
    let mut rng = rng();

    let new_pairs = entries.iter().sample(&mut rng, updates).into_iter().map(|&(key, _)| {
        let value = if rng.random_bool(REMOVAL_PROBABILITY) {
            EMPTY_WORD
        } else {
            Word::new([ONE, ONE, ONE, Felt::new_unchecked(rng.random())])
        };

        (key, value)
    });

    assert_eq!(new_pairs.len(), updates);

    let now = Instant::now();
    let mutations = tree.compute_mutations(new_pairs)?;
    let compute_elapsed = now.elapsed().as_secs_f64() * 1000_f64; // time in ms

    let now = Instant::now();
    tree.apply_mutations(mutations)?;
    let apply_elapsed = now.elapsed().as_secs_f64() * 1000_f64; // time in ms

    println!(
        "The average update-batch computation time measured by a {updates}-batch into an SMT with {size} leaves over {:.1} ms is {:.0} μs",
        compute_elapsed,
        compute_elapsed * 1000_f64 / updates as f64, // time in μs
    );

    println!(
        "The average update-batch application time measured by a {updates}-batch into an SMT with {size} leaves over {:.1} ms is {:.0} μs",
        apply_elapsed,
        apply_elapsed * 1000_f64 / updates as f64, // time in μs
    );

    println!(
        "The average batch update time measured by a {updates}-batch into an SMT with {size} leaves totals to {:.1} ms",
        (compute_elapsed + apply_elapsed),
    );

    println!();

    Ok(())
}

/// Runs the proof generation benchmark for the [`Smt`].
pub fn proof_generation(tree: &mut LargeSmt<Storage>) -> Result<(), LargeSmtError> {
    const NUM_PROOFS: usize = 100;

    println!("Running a proof generation benchmark:");

    let mut opening_times = Vec::new();
    let size = tree.num_leaves();

    // fetch keys already in the tree to be opened
    let keys = tree
        .leaves()?
        .take(NUM_PROOFS)
        .map(|result| result.map(|(_, leaf)| leaf.entries()[0].0))
        .collect::<Result<Vec<_>, _>>()?;

    for key in keys {
        let now = Instant::now();
        let _proof = tree.open(&key);
        opening_times.push(now.elapsed().as_micros());
    }

    println!(
        "The average proving time measured by {NUM_PROOFS} value proofs in an SMT with {size} leaves in {:.0} μs",
        // calculate the average
        opening_times.iter().sum::<u128>() as f64 / (NUM_PROOFS as f64),
    );

    Ok(())
}

#[allow(unused_variables)]
fn get_storage(
    database_path: Option<PathBuf>,
    open: bool,
    reset: bool,
    kind: StorageKind,
) -> Result<Storage, LargeSmtError> {
    match kind {
        StorageKind::Memory => Ok(Box::new(BoxedStorage(MemoryStorage::new()))),
        StorageKind::Rocksdb => {
            #[cfg(feature = "rocksdb")]
            {
                let path = database_path
                    .unwrap_or_else(|| std::env::temp_dir().join("miden_crypto_benchmark"));
                println!("Using database path: {}", path.display());
                if !open {
                    prepare_database_directory(&path, reset)?;
                }
                let db = RocksDbStorage::open(
                    RocksDbConfig::new(path).with_cache_size(1 << 30).with_max_open_files(2048),
                )?;
                Ok(Box::new(BoxedStorage(db)))
            }
            #[cfg(not(feature = "rocksdb"))]
            {
                Err(StorageError::Unsupported(
                    "rocksdb storage was requested, but the rocksdb feature is not enabled".into(),
                )
                .into())
            }
        },
    }
}

#[cfg(any(test, feature = "rocksdb"))]
fn prepare_database_directory(path: &Path, reset: bool) -> Result<(), LargeSmtError> {
    if path.exists() {
        if !reset {
            return Err(StorageError::Unsupported(format!(
                "database path already exists: {}; pass --reset to delete it before creating a new benchmark database",
                path.display()
            ))
            .into());
        }

        std::fs::remove_dir_all(path).map_err(|err| {
            storage_io_error(format!("failed to reset database path {}", path.display()), err)
        })?;
    }

    std::fs::create_dir_all(path).map_err(|err| {
        storage_io_error(format!("failed to create database path {}", path.display()), err)
    })?;

    Ok(())
}

#[cfg(any(test, feature = "rocksdb"))]
fn storage_io_error(message: String, err: std::io::Error) -> LargeSmtError {
    StorageError::Backend(Box::new(std::io::Error::new(err.kind(), format!("{message}: {err}"))))
        .into()
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser, ValueEnum};

    use super::*;

    #[test]
    fn storage_value_parser_accepts_memory() {
        assert_eq!(StorageKind::from_str("memory", true).unwrap(), StorageKind::Memory);
    }

    #[test]
    fn clap_command_definition_is_valid() {
        BenchmarkCmd::command().debug_assert();
    }

    #[test]
    fn parses_size_short_and_memory_storage() {
        let args = BenchmarkCmd::parse_from(["miden-crypto", "-s", "10", "--storage", "memory"]);

        assert_eq!(args.size, 10);
        assert_eq!(args.storage, StorageKind::Memory);
    }

    #[cfg(not(feature = "rocksdb"))]
    #[test]
    fn rejects_explicit_rocksdb_storage_without_feature() {
        let err = get_storage(None, false, false, StorageKind::Rocksdb).unwrap_err();
        match err {
            LargeSmtError::Storage(StorageError::Unsupported(msg)) => {
                assert!(msg.contains("rocksdb feature"));
            },
            other => panic!("expected unsupported rocksdb storage error, got {other:?}"),
        }
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn storage_value_parser_accepts_rocksdb_with_feature() {
        assert_eq!(StorageKind::from_str("rocksdb", true).unwrap(), StorageKind::Rocksdb);
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn parses_explicit_rocksdb_storage_with_feature() {
        let args =
            BenchmarkCmd::parse_from(["miden-crypto", "--size", "10", "--storage", "rocksdb"]);

        assert_eq!(args.size, 10);
        assert_eq!(args.storage, StorageKind::Rocksdb);
    }

    #[test]
    fn existing_database_path_requires_reset_and_preserves_contents() {
        let temp_dir = tempfile::tempdir().unwrap();
        let sentinel = temp_dir.path().join("sentinel.txt");
        std::fs::write(&sentinel, "keep").unwrap();

        let err = prepare_database_directory(temp_dir.path(), false).unwrap_err();
        match err {
            LargeSmtError::Storage(StorageError::Unsupported(msg)) => {
                assert!(msg.contains("--reset"));
            },
            other => panic!("expected reset-required error, got {other:?}"),
        }

        assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "keep");
    }

    #[test]
    fn reset_database_path_removes_existing_contents() {
        let temp_dir = tempfile::tempdir().unwrap();
        let sentinel = temp_dir.path().join("sentinel.txt");
        std::fs::write(&sentinel, "delete").unwrap();

        prepare_database_directory(temp_dir.path(), true).unwrap();

        assert!(temp_dir.path().is_dir());
        assert!(!sentinel.exists());
    }
}
