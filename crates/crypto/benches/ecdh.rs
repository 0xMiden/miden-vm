//! Native EcGFp5 agreement and per-message VM advice preparation.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use miden_crypto::ecdh::ecgfp5::{PreparedPublicKey, SecretKey};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

mod common;
use common::config::{DEFAULT_MEASUREMENT_TIME, DEFAULT_SAMPLE_SIZE};

fn ecgfp5_agreement(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::from_seed([63; 32]);
    let recipient = SecretKey::with_rng(&mut rng);
    let ephemeral = SecretKey::with_rng(&mut rng);
    let public_key = recipient.public_key();

    let mut group = c.benchmark_group("ecdh_ecgfp5");
    group
        .measurement_time(DEFAULT_MEASUREMENT_TIME)
        .sample_size(DEFAULT_SAMPLE_SIZE);
    group.bench_function("public_key", |b| b.iter(|| black_box(&ephemeral).public_key()));
    group.bench_function("diffie_hellman", |b| {
        b.iter(|| black_box(&ephemeral).diffie_hellman(black_box(&public_key)))
    });
    // Exclude the one-time shared generator-table construction from per-message advice timing.
    drop(public_key.advise(&ephemeral));
    group.bench_function("advice/direct", |b| {
        b.iter(|| black_box(&public_key).advise(black_box(&ephemeral)))
    });

    // Recipients prepare this public cache once; measure only the per-message advice here.
    let prepared = PreparedPublicKey::new(public_key);
    group.bench_function("advice/preprocessed", |b| {
        b.iter(|| black_box(&prepared).advise(black_box(&ephemeral)))
    });
    group.finish();
}

criterion_group!(ecdh_group, ecgfp5_agreement);
criterion_main!(ecdh_group);
