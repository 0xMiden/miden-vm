// Shared Criterion benchmark macros.

// Defines a hash benchmark with per-input throughput.
//
// # Usage
// ```no_run
// benchmark_hash_core!(
//     hash_rpo256_elements,
//     "rpo256",
//     "elements",
//     HASH_ELEMENT_COUNTS,
//     |b, count| {
//         let elements = generate_felt_array_sequential(count);
//         b.iter(|| Rpo256::hash_elements(black_box(&elements)))
//     },
//     |count| Some(criterion::Throughput::Elements(count as u64))
// );
// ```
#[macro_export]
macro_rules! benchmark_hash_core {
    (
        $func_name:ident,
        $hasher_name:literal,
        $operation:literal,
        $sizes:expr,
        $closure:expr,
        $throughput:expr
    ) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group(concat!("hash-", $hasher_name, "-", $operation));
            group.sample_size(10);

            for size_ref in $sizes {
                let size_val = *size_ref;
                if size_val > 0 {
                    let throughput_result = $throughput(size_val);
                    if let Some(ref t) = throughput_result {
                        group.throughput(t.clone());
                    }
                }
                group.bench_with_input(
                    criterion::BenchmarkId::new($operation, size_val),
                    &size_val,
                    |b: &mut criterion::Bencher, &size_param: &usize| $closure(b, size_param),
                );
            }

            group.finish();
        }
    };
}

// Creates a benchmark for hash algorithms with common patterns (simplified interface)
//
// # Usage
// ```no_run
// benchmark_hash_simple!(hash_rpo256_single, "rpo256", "single", HASH_INPUT_SIZES, |b, size| {
//     let data = if size <= 64 {
//         generate_byte_array_sequential(size)
//     } else {
//         generate_byte_array_random(size)
//     };
//     b.iter(|| Rpo256::hash(black_box(&data)))
// });
// ```
#[macro_export]
macro_rules! benchmark_hash_simple {
    ($func_name:ident, $hasher_name:literal, $operation:literal, $sizes:expr, $closure:expr) => {
        $crate::benchmark_hash_core! {
            $func_name,
            $hasher_name,
            $operation,
            $sizes,
            $closure,
            |size| Some(criterion::Throughput::Bytes(size as u64))
        }
    };
}

// Creates a benchmark for hash algorithms with backward compatibility
// This macro maintains the original interface for existing code
//
// # Usage
// ```no_run
// benchmark_hash!(hash_rpo256_bytes, "rpo256", "bytes", HASH_INPUT_SIZES, |b, size| {
//     let data = generate_byte_array_sequential(size);
//     b.iter(|| Rpo256::hash(black_box(&data)))
// });
// ```
#[macro_export]
macro_rules! benchmark_hash {
    (
        $func_name:ident,
        $hasher_name:literal,
        $operation:literal,
        $sizes:expr,
        $closure:expr,
        $size_var:ident,
        $throughput:expr
    ) => {
        $crate::benchmark_hash_core! {
            $func_name,
            $hasher_name,
            $operation,
            $sizes,
            $closure,
            $throughput
        }
    };
    ($func_name:ident, $hasher_name:literal, $operation:literal, $sizes:expr, $closure:expr) => {
        $crate::benchmark_hash_core! {
            $func_name,
            $hasher_name,
            $operation,
            $sizes,
            $closure,
            |size| Some(criterion::Throughput::Bytes(size as u64))
        }
    };
}

// Creates a benchmark with automatic data generation for hash operations
//
// # Usage
// ```rust
// benchmark_hash_auto!(hash_rpo256_single, "rpo256", HASH_INPUT_SIZES, |b, data| {
//     b.iter(|| Rpo256::hash(black_box(data)))
// });
// ```
#[macro_export]
macro_rules! benchmark_hash_auto {
    ($func_name:ident, $hasher_name:literal, $sizes:expr, $closure:expr) => {
        $crate::benchmark_hash_simple!($func_name, $hasher_name, "single", $sizes, |b, size| {
            let data = if size <= 64 {
                $crate::common::data::generate_byte_array_sequential(size)
            } else {
                $crate::common::data::generate_byte_array_random(size)
            };
            $closure(b, &data)
        })
    };
}

// Creates a benchmark for hash merge operations
//
// # Usage
// ```no_run
// benchmark_hash_merge!(hash_rpo_merge, "rpo256", &[1, 2, 4, 8, 16], |b, size| {
//     // merge logic here
// });
// ```
#[macro_export]
macro_rules! benchmark_hash_merge {
    // Simple variant without size parameterization - just benchmarks merge operation
    ($func_name:ident, $hasher_name:literal, $closure:expr) => {
        fn $func_name(c: &mut Criterion) {
            c.bench_function(concat!("hash-", $hasher_name, "-merge"), |b| $closure(b));
        }
    };
    // Parameterized variant with multiple sizes (legacy)
    ($func_name:ident, $hasher_name:literal, $sizes:expr, $closure:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group(concat!("hash-", $hasher_name, "-merge"));
            group.sample_size(10);

            for size_ref in $sizes {
                let size = *size_ref;
                group.bench_with_input(
                    criterion::BenchmarkId::new("merge", size),
                    &size,
                    |b: &mut criterion::Bencher, &size_param: &usize| $closure(b, size_param),
                );
            }

            group.finish();
        }
    };
}

// Creates a benchmark for hash felt operations with automatic throughput
//
// # Usage
// ```no_run
// benchmark_hash_felt!(
//     hash_rpo_elements,
//     "rpo256",
//     &[1, 2, 4, 8, 16, 32, 64, 128],
//     |b, count| {
//         let elements = generate_felt_array_sequential(count);
//         b.iter(|| Rpo256::hash_elements(black_box(&elements)))
//     },
//     |count| Some(criterion::Throughput::Elements(count as u64))
// );
// ```
#[macro_export]
macro_rules! benchmark_hash_felt {
    ($func_name:ident, $hasher_name:literal, $counts:expr, $closure:expr, $throughput:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group(concat!("hash-", $hasher_name, "-felt"));
            group.sample_size(10);

            for count_ref in $counts {
                let count = *count_ref;
                let throughput_result = $throughput(count);
                if let Some(ref t) = throughput_result {
                    group.throughput(t.clone());
                }
                group.bench_with_input(
                    criterion::BenchmarkId::new("hash_elements", count),
                    &count,
                    |b: &mut criterion::Bencher, &count_param: &usize| $closure(b, count_param),
                );
            }

            group.finish();
        }
    };
    ($func_name:ident, $hasher_name:literal, $counts:expr, $closure:expr) => {
        $crate::benchmark_hash_felt!($func_name, $hasher_name, $counts, $closure, |count| Some(
            criterion::Throughput::Elements(count as u64)
        ))
    };
}

// Creates a benchmark for hash merge domain operations
#[macro_export]
macro_rules! benchmark_hash_merge_domain {
    ($func_name:ident, $hasher_name:literal, $sizes:expr, $domains:expr, $closure:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group(concat!("hash-", $hasher_name, "-merge-domain"));
            group.sample_size(10);

            for size_ref in $sizes {
                let size = *size_ref;
                for domain_ref in $domains {
                    let domain = *domain_ref;
                    group.bench_with_input(
                        criterion::BenchmarkId::new("merge_in_domain", format!("{size}_{domain}")),
                        &(size, domain),
                        |b: &mut criterion::Bencher, param_ref: &(usize, u64)| {
                            let (size_param, domain_param) = *param_ref;
                            $closure(b, (size_param, domain_param))
                        },
                    );
                }
            }

            group.finish();
        }
    };
}

// Creates a benchmark for hash merge many operations
#[macro_export]
macro_rules! benchmark_hash_merge_many {
    ($func_name:ident, $hasher_name:literal, $digest_counts:expr, $closure:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group(concat!("hash-", $hasher_name, "-merge-many"));
            group.sample_size(10);

            for digest_count_ref in $digest_counts {
                let digest_count = *digest_count_ref;
                group.bench_with_input(
                    criterion::BenchmarkId::new("merge_many", digest_count),
                    &digest_count,
                    |b: &mut criterion::Bencher, &digest_count_param: &usize| {
                        $closure(b, digest_count_param)
                    },
                );
            }

            group.finish();
        }
    };
}

// Creates a benchmark for word conversion operations
//
// # Usage
// ```no_run
// benchmark_word_convert!(convert_bool, bool, TEST_WORDS, |word| { word.try_into() });
// ```
#[macro_export]
macro_rules! benchmark_word_convert {
    ($func_name:ident, $target_type:ty, $test_data:expr, $closure:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group(concat!("word-convert-", stringify!($target_type)));

            group.bench_function(concat!("try_from_to_", stringify!($target_type)), |b| {
                b.iter(|| {
                    for word in $test_data {
                        let _result: Result<$target_type, _> = $closure(word);
                    }
                })
            });

            group.finish();
        }
    };
}

// Creates a benchmark with multiple test cases
//
// # Usage
// ```no_run
// benchmark_multi!(my_bench, "operation", &[1, 2, 3], |b, &value| {
//     // benchmark logic with value
// });
// ```
#[macro_export]
macro_rules! benchmark_multi {
    ($func_name:ident, $operation:literal, $test_cases:expr, $closure:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group(concat!("bench-", $operation));

            for &test_case in $test_cases {
                group.bench_with_input(
                    criterion::BenchmarkId::new($operation, test_case),
                    &test_case,
                    |b, test_case| $closure(b, test_case),
                );
            }

            group.finish();
        }
    };
}

// Creates a benchmark with setup and teardown that uses setup data
//
// # Usage
// ```no_run
// benchmark_with_setup_data!(my_bench, measurement_time, sample_size, group_name, setup_closure, |b, data| { ... });
// ```
#[macro_export]
macro_rules! benchmark_with_setup_data {
    (
        $func_name:ident,
        $measurement_time:expr,
        $sample_size:expr,
        $group_name:literal,
        $setup:expr,
        $closure:expr
    ) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group($group_name);
            group.measurement_time($measurement_time);
            group.sample_size($sample_size);

            let setup_data = $setup();

            group.bench_function("benchmark", |b| $closure(b, &setup_data));

            group.finish();
        }
    };
    (
        $func_name:ident,
        $measurement_time:expr,
        $sample_size:expr,
        $group_name:literal,
        $setup:expr,
        $closure:expr,
    ) => {
        benchmark_with_setup_data!(
            $func_name,
            $measurement_time,
            $sample_size,
            $group_name,
            $setup,
            $closure
        );
    };
}

// Creates a benchmark with setup but ignores setup data
//
// # Usage
// ```no_run
// benchmark_with_setup!(my_bench, measurement_time, sample_size, group_name, setup_closure, |b| { ... });
// ```
#[macro_export]
macro_rules! benchmark_with_setup {
    (
        $func_name:ident,
        $measurement_time:expr,
        $sample_size:expr,
        $group_name:literal,
        $setup:expr,
        $closure:expr
    ) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group($group_name);
            group.measurement_time($measurement_time);
            group.sample_size($sample_size);

            let _setup_data = $setup();

            group.bench_function("benchmark", |b| $closure(b));

            group.finish();
        }
    };
    (
        $func_name:ident,
        $measurement_time:expr,
        $sample_size:expr,
        $group_name:literal,
        $setup:expr,
        $closure:expr,
    ) => {
        benchmark_with_setup!(
            $func_name,
            $measurement_time,
            $sample_size,
            $group_name,
            $setup,
            $closure
        );
    };
}

// Creates a benchmark that uses setup data but doesn't pass it to the closure
//
// # Usage
// ```no_run
// benchmark_with_setup_custom!(my_bench, measurement_time, sample_size, group_name, setup_closure, |b, setup_data| { ... });
// ```
#[macro_export]
macro_rules! benchmark_with_setup_custom {
    (
        $func_name:ident,
        $measurement_time:expr,
        $sample_size:expr,
        $group_name:literal,
        $setup:expr,
        $closure:expr
    ) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group($group_name);
            group.measurement_time($measurement_time);
            group.sample_size($sample_size as usize);

            let setup_data = $setup();

            group.bench_function("benchmark", |b| $closure(b, &setup_data));

            group.finish();
        }
    };
    (
        $func_name:ident,
        $measurement_time:expr,
        $sample_size:expr,
        $group_name:literal,
        $setup:expr,
        $closure:expr,
    ) => {
        benchmark_with_setup_custom!(
            $func_name,
            $measurement_time,
            $sample_size,
            $group_name,
            $setup,
            $closure
        );
    };
}

// Creates a benchmark for batch operations
//
// # Usage
// ```no_run
// benchmark_batch!(
//     batch_operation,
//     SIZES,
//     |b, size| {
//         // batch logic with size
//     },
//     |size| Some(criterion::Throughput::Elements(size as u64))
// );
// ```
#[macro_export]
macro_rules! benchmark_batch {
    ($func_name:ident, $sizes:expr, $closure:expr, $throughput:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group(concat!("batch-", stringify!($func_name)));
            group.measurement_time($crate::common::config::DEFAULT_MEASUREMENT_TIME);
            group.sample_size($crate::common::config::DEFAULT_SAMPLE_SIZE);

            for size_ref in $sizes {
                let size = *size_ref;
                group.bench_with_input(
                    criterion::BenchmarkId::new("batch", size),
                    &size,
                    |b, &size| $closure(b, size),
                );

                let throughput = $throughput(size);
                if let Some(ref t) = throughput {
                    group.throughput(t.clone());
                }
            }

            group.finish();
        }
    };
}

// Creates benchmarks for word type conversions with minimal repetition
//
// This macro generates conversion benchmarks for multiple target types in one call.
// It's useful for benchmarking Word::try_into() for various integer types.
//
// # Usage
// ```no_run
// benchmark_word_conversions!(
//     word_convert_basic,
//     &[bool::default(), u8::default(), u16::default(), u32::default(), u64::default()],
//     TEST_WORDS
// );
// ```
#[macro_export]
macro_rules! benchmark_word_conversions {
    ($func_name:ident, $types:expr, $test_data:expr) => {
        fn $func_name(c: &mut Criterion) {
            let mut group = c.benchmark_group("word-conversions-basic");
            group.measurement_time($crate::common::config::DEFAULT_MEASUREMENT_TIME);
            group.sample_size($crate::common::config::DEFAULT_SAMPLE_SIZE);

            group.bench_function("conversions_batch", |b| {
                b.iter(|| {
                    for word in $test_data {
                        for &type_template in $types {
                            match type_template {
                                // Handle each type conversion
                                0 => {
                                    let _result: Result<[bool; 4], _> = word.try_into();
                                },
                                1 => {
                                    let _result: Result<[u8; 4], _> = word.try_into();
                                },
                                2 => {
                                    let _result: Result<[u16; 4], _> = word.try_into();
                                },
                                3 => {
                                    let _result: Result<[u32; 4], _> = word.try_into();
                                },
                                4 => {
                                    let _result: Result<[u64; 4], _> = word.try_into();
                                },
                                _ => {},
                            }
                        }
                    }
                })
            });

            group.finish();
        }
    };
}

/// Generates comprehensive AEAD benchmarks for bytes operations.
///
/// This macro creates encryption and decryption benchmarks with consistent data generation and
/// throughput measurement.
///
/// # Arguments
/// * `$aead_module` - The AEAD module name
/// * `$group_prefix` - Human-readable prefix for benchmark group names
/// * `$bytes_fn` - The name of the benchmark function to generate for bytes
/// * `$group_ident` - The identifier for the criterion group
///
/// # Generated benchmarks
/// - `$bytes_fn` - Function containing byte array encryption/decryption benchmarks
/// - `$group_ident` - Criterion group for the benchmarks
#[macro_export]
macro_rules! benchmark_aead_bytes {
    ($aead_module:ident, $group_prefix:expr, $bytes_fn:ident, $group_ident:ident) => {
        /// Benchmark AEAD operations on byte arrays
        fn $bytes_fn(c: &mut Criterion) {
            use miden_crypto::aead::$aead_module::{Nonce, SecretKey};
            use rand::SeedableRng;
            use rand_chacha::ChaCha20Rng;

            let group_name = format!("{} - Byte Arrays", $group_prefix);
            let mut group = c.benchmark_group(&group_name);
            let mut rng = ChaCha20Rng::seed_from_u64(42);

            let key = SecretKey::with_rng(&mut rng);
            let associated_data = generate_byte_array_sequential(8);

            for &size in DATA_SIZES {
                let data = generate_byte_array_random(size);
                group.throughput(Throughput::Bytes(size as u64));

                // Encryption benchmark
                group.bench_with_input(BenchmarkId::new("encrypt", size), &data, |b, data| {
                    b.iter_batched(
                        || Nonce::with_rng(&mut rng),
                        |nonce| {
                            black_box(
                                key.encrypt_bytes_with_nonce(
                                    black_box(data),
                                    black_box(&associated_data),
                                    black_box(nonce),
                                )
                                .unwrap(),
                            );
                        },
                        criterion::BatchSize::SmallInput,
                    );
                });

                // Pre-encrypt data for decryption benchmark
                let nonce = Nonce::with_rng(&mut rng);
                let encrypted = key
                    .encrypt_bytes_with_nonce(&data, &associated_data, nonce.clone())
                    .unwrap();

                // Decryption benchmark
                group.bench_with_input(
                    BenchmarkId::new("decrypt", size),
                    &encrypted,
                    |b, encrypted| {
                        b.iter(|| {
                            black_box(
                                key.decrypt_bytes_with_associated_data(
                                    black_box(encrypted),
                                    &associated_data,
                                )
                                .unwrap(),
                            )
                        });
                    },
                );
            }

            group.finish();
        }

        criterion_group!($group_ident, $bytes_fn);
    };
}

/// Generates comprehensive AEAD benchmarks for field elements.
///
/// This macro creates encryption and decryption benchmarks with consistent data generation and
/// throughput measurement.
///
/// # Arguments
/// * `$aead_module` - The AEAD module name
/// * `$group_prefix` - Human-readable prefix for benchmark group names
/// * `$felts_fn` - The name of the benchmark function to generate for Felts
/// * `$group_ident` - The identifier for the criterion group
///
/// # Generated benchmarks
/// - `$felts_fn` - Function containing Felt array encryption/decryption benchmarks
/// - `$group_ident` - Criterion group for the benchmarks
#[macro_export]
macro_rules! benchmark_aead_field {
    ($aead_module:ident, $group_prefix:expr, $felts_fn:ident, $group_ident:ident) => {
        /// Benchmark AEAD operations on field elements
        fn $felts_fn(c: &mut Criterion) {
            use miden_crypto::aead::$aead_module::{Nonce, SecretKey};
            use rand::SeedableRng;
            use rand_chacha::ChaCha20Rng;

            let group_name = format!("{} - Field Elements", $group_prefix);
            let mut group = c.benchmark_group(&group_name);
            let mut rng = ChaCha20Rng::seed_from_u64(42);

            // Setup common test data
            let key = SecretKey::with_rng(&mut rng);
            let associated_data: Vec<Felt> = generate_felt_array_sequential(8);

            for &size in FELT_SIZES {
                let data: Vec<Felt> = generate_felt_array_random(size);
                group.throughput(Throughput::Elements(size as u64));

                // Encryption benchmark
                group.bench_with_input(BenchmarkId::new("encrypt", size), &data, |b, data| {
                    b.iter_batched(
                        || Nonce::with_rng(&mut rng),
                        |nonce| {
                            black_box(
                                key.encrypt_elements_with_nonce(
                                    black_box(data),
                                    black_box(&associated_data),
                                    black_box(nonce),
                                )
                                .unwrap(),
                            );
                        },
                        criterion::BatchSize::SmallInput,
                    );
                });

                // Pre-encrypt data for decryption benchmark
                let nonce = Nonce::with_rng(&mut rng);
                let encrypted = key
                    .encrypt_elements_with_nonce(&data, &associated_data, nonce.clone())
                    .unwrap();

                // Decryption benchmark
                group.bench_with_input(
                    BenchmarkId::new("decrypt", size),
                    &encrypted,
                    |b, encrypted| {
                        b.iter(|| {
                            black_box(
                                key.decrypt_elements_with_associated_data(
                                    black_box(encrypted),
                                    &associated_data,
                                )
                                .unwrap(),
                            )
                        });
                    },
                );
            }

            group.finish();
        }

        criterion_group!($group_ident, $felts_fn);
    };
}
