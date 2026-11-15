//! Opt-in generated alternatives for the manual folding comparison.
use std::{env, fmt::Write, fs, path::PathBuf};

use miden_ace::compiler::{
    CapturedAir, CompiledRelation, LayoutKind, ProductSharing, with_product_sharing,
};
use miden_air_definitions::{precompiles::relation, vm};
use miden_constraint_compiler::{
    backend::{
        rust_descriptor::{self, AirDescriptorEmitter},
        rust_eval::{
            AirEvaluator, NativeExperiment, emit_native_optimized_module, with_native_experiment,
        },
    },
    ir::with_sum_folding,
};
use miden_stark::air::symbolic::folding_experiment::{Policy, with_policy};

pub fn generate() {
    println!("cargo:rerun-if-changed=build/folding_experiments.rs");
    println!("cargo:rerun-if-env-changed=MIDEN_FOLD_POLICIES");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let filter = env::var("MIDEN_FOLD_POLICIES").unwrap_or_default();
    let mut modules = String::new();
    let mut runs = String::new();
    for (name, policy, mode, left_only) in [
        ("current", Policy::Current, NativeExperiment::Baseline, false),
        ("strict", Policy::StrictNested, NativeExperiment::Baseline, false),
        ("adjacent", Policy::AdjacentNested, NativeExperiment::Baseline, false),
        ("left", Policy::LeftAppend, NativeExperiment::Baseline, false),
        ("flat", Policy::FullFlatten, NativeExperiment::Baseline, false),
        ("aware", Policy::StrictNested, NativeExperiment::LeftSumFolding, true),
        ("uniform", Policy::StrictNested, NativeExperiment::Uniform, false),
        ("fragments", Policy::StrictNested, NativeExperiment::UniformFragments, false),
        ("prepared", Policy::StrictNested, NativeExperiment::PreparedFragmentsOnly, false),
        ("signed", Policy::StrictNested, NativeExperiment::SignedDots, false),
        (
            "fragmentssigned",
            Policy::StrictNested,
            NativeExperiment::UniformFragmentsSignedDots,
            false,
        ),
        ("combined", Policy::StrictNested, NativeExperiment::UniformFragments, true),
        ("production", Policy::StrictNested, NativeExperiment::Production, true),
        ("products", Policy::StrictNested, NativeExperiment::ProductPairs, true),
        ("productsubsets", Policy::StrictNested, NativeExperiment::ProductSubsets, true),
        (
            "productfrequent",
            Policy::StrictNested,
            NativeExperiment::FrequentProductPairs,
            true,
        ),
        ("cancel", Policy::StrictNested, NativeExperiment::CancelConstOffsets, true),
        ("dotmin2", Policy::StrictNested, NativeExperiment::DotMin2, true),
        ("dotmin3", Policy::StrictNested, NativeExperiment::DotMin3, true),
        ("dotcap6", Policy::StrictNested, NativeExperiment::DotCap6, true),
        ("dotcap8", Policy::StrictNested, NativeExperiment::DotCap8, true),
        ("mixedmin2", Policy::StrictNested, NativeExperiment::MixedDotMin2, true),
        ("mixedmin3", Policy::StrictNested, NativeExperiment::MixedDotMin3, true),
        ("mixedcap6", Policy::StrictNested, NativeExperiment::MixedDotCap6, true),
        ("mixedcap8", Policy::StrictNested, NativeExperiment::MixedDotCap8, true),
        ("factor", Policy::StrictNested, NativeExperiment::FactorRuns, false),
        ("frequent", Policy::StrictNested, NativeExperiment::FrequentFragments, true),
        (
            "veryfrequent",
            Policy::StrictNested,
            NativeExperiment::VeryFrequentFragments,
            true,
        ),
    ] {
        if !filter.is_empty() && !filter.split(',').any(|candidate| candidate == name) {
            continue;
        }
        for pvm in [false, true] {
            let group = if pvm { "pvm" } else { "vm" };
            let capture = || {
                with_policy(policy, || {
                    if pvm {
                        relation::AIRS
                            .iter()
                            .map(CapturedAir::new_native)
                            .collect::<Result<Vec<_>, _>>()
                    } else {
                        vm::AIRS.iter().map(CapturedAir::new_native).collect::<Result<Vec<_>, _>>()
                    }
                })
            };
            let captured = with_sum_folding(left_only, capture).unwrap();
            let tokens: Vec<_> = if pvm {
                relation::AIRS.iter().map(|air| air.file_token()).collect()
            } else {
                vm::AIRS.iter().map(|air| air.file_token()).collect()
            };
            let evals: Vec<_> = captured
                .iter()
                .zip(&tokens)
                .map(|(air, token)| AirEvaluator {
                    name: token,
                    air_label: token,
                    program: air.program(),
                    descriptor: air.descriptor(),
                })
                .collect();
            let mut source =
                with_native_experiment(mode, || emit_native_optimized_module("", &evals));
            let descriptors: Vec<_> = captured
                .iter()
                .zip(&tokens)
                .map(|(air, token)| AirDescriptorEmitter {
                    name: token,
                    air_label: token,
                    descriptor: air.descriptor(),
                })
                .collect();
            writeln!(
                source,
                "mod descriptors {{ {} }}",
                rust_descriptor::emit_module("", &descriptors),
            )
            .unwrap();
            let refs: Vec<_> = captured.iter().collect();
            let product_policy = match name {
                "production" | "productsubsets" => ProductSharing::Subsets,
                "products" | "productfrequent" => ProductSharing::Pairs,
                _ => ProductSharing::Baseline,
            };
            let circuit = with_product_sharing(product_policy, || {
                let relation = CompiledRelation::from_captured(&refs, 8).unwrap();
                relation.build_circuit(LayoutKind::Masm).unwrap()
            });
            let encoded = circuit.to_ace().unwrap();
            writeln!(
                source,
                "pub const ACE: [usize; 5] = {:?};",
                [
                    circuit.num_operations(),
                    circuit.num_constants(),
                    encoded.num_vars(),
                    encoded.num_eval_rows(),
                    encoded.size_in_felt()
                ]
            )
            .unwrap();
            source.push_str("pub enum Prepared<E> {\n");
            for (index, token) in tokens.iter().enumerate() {
                writeln!(source, "Air{index}([E; {}_PREPARED_TERMS]),", token.to_ascii_uppercase())
                    .unwrap();
            }
            source.push_str("}\npub struct Kernel { index: usize, descriptor: miden_stark::air::AirDescriptor<Felt> }\nimpl Kernel { pub fn new(index: usize) -> Self { let descriptor = match index {\n");
            for (index, token) in tokens.iter().enumerate() {
                writeln!(source, "{index} => descriptors::descriptor_{token}(),").unwrap();
            }
            source.push_str("_ => unreachable!(), }; Self { index, descriptor } } }\n");
            source.push_str("impl miden_stark::air::AirKernel for Kernel {\n type F = Felt;\n type Prepared<B: Algebra<Felt>, E: Algebra<B>> = Prepared<E>;\n fn descriptor(&self) -> &miden_stark::air::AirDescriptor<Felt> { &self.descriptor }\n fn prepare<B: Algebra<Felt>, E: Algebra<B>>(&self, inputs: UniformInputs<'_, B, E>) -> Self::Prepared<B,E> { match self.index {\n");
            for (index, token) in tokens.iter().enumerate() {
                writeln!(
                    source,
                    "{index} => Prepared::Air{index}(precompute_{token}::<B,E>(inputs)),"
                )
                .unwrap();
            }
            source.push_str("_ => unreachable!(), } }\n fn eval_row<S: LiftedAirBuilder<F=Felt>>(&self, frame: &Frame<'_, S>, inputs: Inputs<'_, S>, prepared: &Self::Prepared<S::Expr,S::ExtExpr>, sink: &mut S) { match (self.index, prepared) {\n");
            for (index, token) in tokens.iter().enumerate() {
                writeln!(
                    source,
                    "({index}, Prepared::Air{index}(terms)) => eval_{token}(frame, inputs, sink, terms),"
                )
                .unwrap();
            }
            source.push_str("_ => unreachable!(), } }\n}\n");
            let module = format!("{name}_{group}");
            let path = out.join(format!("fold_{module}.rs"));
            fs::write(&path, source).unwrap();
            writeln!(modules, "#[allow(clippy::eq_op)] mod {module} {{ include!({:?}); }}", path)
                .unwrap();
            writeln!(runs, "for index in 0..{} {{ run({name:?}, {group:?}, index, &{module}::Kernel::new(index), repeat, iterations); }}", tokens.len()).unwrap();
            writeln!(
                runs,
                "if repeat == 0 {{ println!(\"ACE,{name}/{group},{{:?}}\", {module}::ACE); }}"
            )
            .unwrap();
        }
    }
    writeln!(modules, "fn run_variants(repeat: usize, iterations: usize) {{ {runs} }}").unwrap();
    fs::write(out.join("folding_experiment_modules.rs"), modules).unwrap();
}
