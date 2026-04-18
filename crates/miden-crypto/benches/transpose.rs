//! Benchmark for transpose_slice comparing unsafe uninit_vector vs safe init_vector.
//!
//! Results at 1024x1024: unsafe=188us, safe=247us (~31% slower with initialization)

use std::hint::black_box;

use criterion::{Bencher, Criterion, criterion_group, criterion_main};
use miden_crypto::Felt;

mod common;

const MATRIX_SIZES: &[usize] = &[64, 256, 1024];

fn generate_felt_matrix(size: usize) -> Vec<Felt> {
    (0..(size * size)).map(|i| Felt::new_unchecked(i as u64)).collect()
}

/// Unsafe transpose using uninit_vector
#[expect(clippy::uninit_vec)]
fn transpose_unsafe<T: Copy + Send + Sync, const N: usize>(source: &[T]) -> Vec<[T; N]> {
    let row_count = source.len() / N;
    assert_eq!(row_count * N, source.len());

    let mut result: Vec<[T; N]> = unsafe {
        let mut vector = Vec::with_capacity(row_count);
        vector.set_len(row_count);
        vector
    };

    result.iter_mut().enumerate().for_each(|(i, element)| {
        for j in 0..N {
            element[j] = source[i + j * row_count]
        }
    });
    result
}

/// Safe transpose using initialized vector
fn transpose_safe<T: Copy + Default + Send + Sync, const N: usize>(source: &[T]) -> Vec<[T; N]> {
    let row_count = source.len() / N;
    assert_eq!(row_count * N, source.len());

    let mut result: Vec<[T; N]> = vec![[T::default(); N]; row_count];

    result.iter_mut().enumerate().for_each(|(i, element)| {
        for j in 0..N {
            element[j] = source[i + j * row_count]
        }
    });
    result
}

benchmark_multi!(
    transpose_unsafe_bench,
    "transpose_unsafe",
    MATRIX_SIZES,
    |b: &mut Bencher<'_>, &size: &usize| {
        let data = generate_felt_matrix(size);
        b.iter(|| {
            let result: Vec<[Felt; 4]> = transpose_unsafe(black_box(&data));
            black_box(result);
        })
    }
);

benchmark_multi!(
    transpose_safe_bench,
    "transpose_safe",
    MATRIX_SIZES,
    |b: &mut Bencher<'_>, &size: &usize| {
        let data = generate_felt_matrix(size);
        b.iter(|| {
            let result: Vec<[Felt; 4]> = transpose_safe(black_box(&data));
            black_box(result);
        })
    }
);

benchmark_multi!(
    transpose_library_bench,
    "transpose_library",
    MATRIX_SIZES,
    |b: &mut Bencher<'_>, &size: &usize| {
        use miden_crypto::utils::transpose_slice;
        let data = generate_felt_matrix(size);
        b.iter(|| {
            let result: Vec<[Felt; 4]> = transpose_slice::<Felt, 4>(black_box(&data));
            black_box(result);
        })
    }
);

criterion_group!(
    transpose_benchmarks,
    transpose_unsafe_bench,
    transpose_safe_bench,
    transpose_library_bench,
);

criterion_main!(transpose_benchmarks);
