use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use miden_assembly::{Library, utils::Deserializable};
use miden_core_lib::CoreLibrary;

fn deserialize_core_lib(c: &mut Criterion) {
    let mut group = c.benchmark_group("deserialize_core_lib");
    group.measurement_time(Duration::from_secs(15));
    group.bench_function("read_from_bytes", |bench| {
        bench.iter(|| {
            let _ = Library::read_from_bytes(CoreLibrary::SERIALIZED)
                .expect("failed to read std masl!");
        });
    });

    group.finish();
}

criterion_group!(core_lib_group, deserialize_core_lib);
criterion_main!(core_lib_group);
