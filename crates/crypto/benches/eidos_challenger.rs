use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use miden_crypto::{
    Felt, Word, field::PrimeField64, hash::eidos::EidosChallenger, parallel::*,
    stark::challenger::GrindingChallenger,
};

const CASES: [(usize, usize); 4] = [(4, 0), (12, 0), (17, 0), (12, 7)];

fn challenger_with_buffer(buffer_len: usize) -> EidosChallenger {
    let mut challenger = EidosChallenger::new(Word::new([
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
    ]));
    for value in 0..buffer_len {
        challenger.observe_felt(Felt::new_unchecked(100 + value as u64));
    }
    challenger
}

fn grind_unbatched(challenger: &mut EidosChallenger, bits: usize) -> Felt {
    let witness = (0..Felt::ORDER_U64)
        .into_par_iter()
        .map(Felt::new_unchecked)
        .find_any(|&witness| challenger.clone().check_witness(bits, witness))
        .expect("failed to find proof-of-work witness");

    assert!(challenger.check_witness(bits, witness));
    witness
}

fn eidos_grinding(c: &mut Criterion) {
    let mut group = c.benchmark_group("eidos-grinding");

    for (bits, buffer_len) in CASES {
        let input = format!("bits-{bits}-buffer-{buffer_len}");
        let challenger = challenger_with_buffer(buffer_len);

        group.bench_function(BenchmarkId::new("packed", &input), |b| {
            b.iter_batched(
                || challenger.clone(),
                |mut challenger| black_box(challenger.grind(bits)),
                BatchSize::SmallInput,
            )
        });
        group.bench_function(BenchmarkId::new("unbatched", &input), |b| {
            b.iter_batched(
                || challenger.clone(),
                |mut challenger| black_box(grind_unbatched(&mut challenger, bits)),
                BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

criterion_group!(eidos_challenger_benches, eidos_grinding);
criterion_main!(eidos_challenger_benches);
