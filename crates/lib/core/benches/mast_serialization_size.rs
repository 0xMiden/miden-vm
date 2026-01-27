use std::{hint::black_box, path::Path, time::Duration};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use miden_assembly::{Assembler, PathBuf as LibraryPath};
use miden_core::utils::Serializable;

fn mast_serialization_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("mast_serialize_core_lib");
    group.measurement_time(Duration::from_secs(10));

    // Assemble the entire core library once and reuse it across iterations.
    let assembler = Assembler::default();
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let asm_dir = Path::new(manifest_dir).join("asm");
    let namespace = LibraryPath::new("::miden::core").expect("invalid base namespace");
    let library = assembler.assemble_library_from_dir(asm_dir, namespace).unwrap();
    let mast_forest = library.mast_forest();

    // Measure the serialized size once for reporting/throughput configuration.
    let initial_bytes = mast_forest.to_bytes();
    let initial_size = initial_bytes.len() as u64;
    group.throughput(Throughput::Bytes(initial_size));

    eprintln!("core-lib MastForest serialized size (bytes): {}", initial_size);

    group.bench_function("full", |bench| {
        bench.iter(|| {
            let bytes = mast_forest.to_bytes();
            black_box(bytes.len());
        });
    });

    group.finish();
}

criterion_group!(mast_serialization_size_group, mast_serialization_size);
criterion_main!(mast_serialization_size_group);
