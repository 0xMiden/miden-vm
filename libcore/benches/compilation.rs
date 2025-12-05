use std::{path::Path, time::Duration};

use criterion::{Criterion, criterion_group, criterion_main};
use miden_assembly::{Assembler, PathBuf as LibraryPath};

fn libcore_compilation(c: &mut Criterion) {
    let mut group = c.benchmark_group("compile_libcore");
    group.measurement_time(Duration::from_secs(10));

    // Compiles the entire core library
    group.bench_function("all", |bench| {
        bench.iter(|| {
            let assembler = Assembler::default();

            let manifest_dir = env!("CARGO_MANIFEST_DIR");
            let asm_dir = Path::new(manifest_dir).join("asm");
            let namespace = LibraryPath::new("std").expect("invalid base namespace");
            assembler.assemble_library_from_dir(asm_dir, namespace).unwrap();
        });
    });

    group.finish();
}

criterion_group!(compilation_group, libcore_compilation);
criterion_main!(compilation_group);
