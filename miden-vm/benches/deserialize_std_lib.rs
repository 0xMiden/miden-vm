use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use miden_assembly::{Library, utils::Deserializable};
use miden_stdlib::StdLibrary;

fn deserialize_std_lib(c: &mut Criterion) {
    let mut group = c.benchmark_group("deserialize_std_lib");
    group.measurement_time(Duration::from_secs(15));
    group.bench_function("read_from_bytes", |bench| {
        bench.iter(|| {
            let _ =
                Library::read_from_bytes(StdLibrary::SERIALIZED).expect("failed to read std masl!");
        });
    });

    group.finish();
}

criterion_group!(std_lib_group, deserialize_std_lib);
criterion_main!(std_lib_group);
