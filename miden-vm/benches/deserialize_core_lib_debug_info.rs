use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use miden_core_lib::CoreLibrary;

fn deserialize_core_lib_debug_info(c: &mut Criterion) {
    let package = CoreLibrary::default().package();
    let mut group = c.benchmark_group("deserialize_core_lib_debug_info");
    group.measurement_time(Duration::from_secs(15));
    group.bench_function("read_from_bytes", |bench| {
        bench.iter(|| {
            let debug_info = package.debug_info().expect("debug info should be valid");
            assert!(debug_info.is_some(), "expected core lib to be assembled with debug info");
        });
    });

    group.finish();
}

criterion_group!(core_lib_group, deserialize_core_lib_debug_info);
criterion_main!(core_lib_group);
