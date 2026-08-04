use std::{hint::black_box, sync::Arc, time::Duration};

use codspeed_criterion_compat as criterion;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use miden_assembly_syntax::{
    ast::{
        Path as AstPath, PathBuf,
        types::{CallConv, FunctionType, StructType, Type, TypeRepr},
    },
    semver::Version,
};
use miden_core::{
    mast::{BasicBlockNodeBuilder, DenseMastForestBuilder, MastNodeExt, MastNodeId},
    operations::Operation,
    serde::{Deserializable, Serializable},
};
use miden_mast_package::{
    Package, PackageExport, PackageId, ProcedureExport, Section, SectionId, TargetType,
    debug_info::{
        DebugSourceAsmOp, DebugSourceNode, DebugSourceNodeId, PackageDebugInfo,
        PackageDebugInfoBuilder,
    },
};

fn absolute_path(name: &str) -> Arc<AstPath> {
    let path = PathBuf::new(name).expect("benchmark path should be valid");
    let path = path.as_path().to_absolute().unwrap().into_owned();
    Arc::from(path.into_boxed_path())
}

fn package_bytes(with_debug_info: bool) -> Vec<u8> {
    let mut forest_builder = DenseMastForestBuilder::new();
    let node_id = forest_builder
        .push_node(BasicBlockNodeBuilder::new(vec![Operation::Add; 128]))
        .expect("benchmark basic block should be valid");
    forest_builder.mark_root(node_id);
    let (forest, remapping) = forest_builder.build_with_id_map().expect("forest should build");
    let node_id = remapping.get(node_id).expect("benchmark root should be retained");

    let struct_type = StructType::new_with_repr(
        TypeRepr::align(8),
        core::iter::repeat_with(|| Type::Felt).take(16),
    );
    let signature = FunctionType::new(CallConv::Fast, [Type::from(struct_type)], [Type::Felt]);
    let export = ProcedureExport::new(
        absolute_path("bench::deserialize"),
        Some(node_id),
        forest[node_id].digest(),
        Some(signature),
    );
    let mut package = Package::create(
        PackageId::from("benchmark_pkg"),
        Version::new(0, 0, 0),
        TargetType::Library,
        Arc::new(forest),
        vec![PackageExport::Procedure(export)],
        None,
    )
    .expect("benchmark package should be valid");

    if with_debug_info {
        let mut debug_info = PackageDebugInfoBuilder::default();
        let context_name = debug_info.add_string("bench::deserialize");
        let op_names = (0..128)
            .map(|index| debug_info.add_string(format!("operation_{index}")))
            .collect::<Vec<_>>();
        let source_node = debug_info
            .add_node(DebugSourceNode {
                exec_node: node_id,
                children: Vec::new(),
                op_start: 0,
                op_end: 128,
                asm_ops: op_names
                    .into_iter()
                    .enumerate()
                    .map(|(index, op_name)| {
                        DebugSourceAsmOp::new(index as u32, None, context_name, op_name, 1)
                    })
                    .collect(),
                debug_vars: Vec::new(),
                inline_calls: Vec::new(),
            })
            .expect("benchmark debug node should be valid");
        debug_info.add_root(source_node);
        package
            .sections
            .push(Section::new(SectionId::DEBUG_INFO, debug_info.build().to_bytes()));
    }

    package.to_bytes()
}

fn package_deserialization(c: &mut Criterion) {
    let without_debug_info = package_bytes(false);
    let with_debug_info = package_bytes(true);
    let mut group = c.benchmark_group("package_deserialization");
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(100);

    group.throughput(Throughput::Bytes(without_debug_info.len() as u64));
    group.bench_function("untrusted_without_debug_info", |bench| {
        bench.iter(|| Package::read_from_bytes(black_box(&without_debug_info)).unwrap())
    });
    group.bench_function("trusted_without_debug_info", |bench| {
        bench.iter(|| Package::read_from_bytes_trusted(black_box(&without_debug_info)).unwrap())
    });

    group.throughput(Throughput::Bytes(with_debug_info.len() as u64));
    group.bench_function("untrusted_with_debug_info", |bench| {
        bench.iter(|| Package::read_from_bytes(black_box(&with_debug_info)).unwrap())
    });
    group.bench_function("trusted_with_debug_info", |bench| {
        bench.iter(|| Package::read_from_bytes_trusted(black_box(&with_debug_info)).unwrap())
    });
    group.bench_function("trusted_with_debug_info_and_decode", |bench| {
        bench.iter(|| {
            let package = Package::read_from_bytes_trusted(black_box(&with_debug_info)).unwrap();
            black_box(package.debug_info().unwrap())
        })
    });

    group.finish();
}

fn debug_info_with_asm_ops(row_count: usize) -> (Box<PackageDebugInfo>, DebugSourceNodeId) {
    let mut debug_info = PackageDebugInfoBuilder::default();
    let context_name = debug_info.add_string("bench::lookup");
    let op_name = debug_info.add_string("operation");
    let source_node = debug_info
        .add_node(DebugSourceNode {
            exec_node: MastNodeId::new_unchecked(0),
            children: Vec::new(),
            op_start: 0,
            op_end: row_count as u32,
            asm_ops: (0..row_count)
                .map(|index| DebugSourceAsmOp::new(index as u32, None, context_name, op_name, 1))
                .collect(),
            debug_vars: Vec::new(),
            inline_calls: Vec::new(),
        })
        .expect("benchmark debug node should be valid");
    debug_info.add_root(source_node);
    (debug_info.build(), source_node)
}

fn debug_assembly_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("debug_assembly_lookup");
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(100);

    for row_count in [16, 1_024, 65_536] {
        let (debug_info, source_node) = debug_info_with_asm_ops(row_count);

        group.bench_with_input(
            BenchmarkId::new("linear_scan_control", row_count),
            &row_count,
            |bench, _| {
                bench.iter(|| {
                    debug_info.source_node(black_box(source_node)).and_then(|node| {
                        node.asm_ops.iter().rfind(|row| row.op_idx <= black_box(0))
                    })
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("public_binary_lookup", row_count),
            &row_count,
            |bench, _| {
                bench.iter(|| debug_info.asm_op_for_operation(black_box(source_node), black_box(0)))
            },
        );
    }

    group.finish();
}

criterion_group!(benches, package_deserialization, debug_assembly_lookup);
criterion_main!(benches);
