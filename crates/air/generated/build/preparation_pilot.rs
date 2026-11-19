//! Generate a bounded native fixture without selecting any production AIR or runtime.

use std::{fs, path::Path};

use miden_ace::compiler::CapturedAir;
use miden_constraint_compiler::backend::{
    rust_descriptor::{self, AirDescriptorEmitter},
    rust_eval::{AirEvaluator, emit_native_optimized_module},
};

#[path = "preparation_fixture.rs"]
mod source;

pub fn generate(out: &Path) {
    let captured = [
        (
            "cached",
            "Cached",
            CapturedAir::new_native(&source::PreparationFixture(true))
                .expect("capture cached preparation fixture"),
        ),
        (
            "uncached",
            "Uncached",
            CapturedAir::new_native(&source::PreparationFixture(false))
                .expect("capture uncached preparation fixture"),
        ),
        (
            "renderer",
            "Renderer",
            CapturedAir::new_native(&source::NativeRendererFixture)
                .expect("capture native renderer fixture"),
        ),
    ];
    // Both native outputs use the same canonical authored capture, including its checked
    // descriptor. This only emits Rust: no numerical comparison, proof, observer baseline or
    // test is run here.
    let evaluators: Vec<_> = captured
        .iter()
        .map(|(name, label, captured)| AirEvaluator {
            name,
            air_label: label,
            graph: captured.graph(),
            constraints: captured.constraints(),
            descriptor: captured.descriptor(),
        })
        .collect();
    let descriptors: Vec<_> = captured
        .iter()
        .map(|(name, label, captured)| AirDescriptorEmitter {
            name,
            air_label: label,
            descriptor: captured.descriptor(),
        })
        .collect();
    for (name, contents) in [
        (
            "native_pilot_evaluators.rs",
            emit_native_optimized_module("// Native preparation pilot evaluators.\n", &evaluators),
        ),
        (
            "native_pilot_descriptors.rs",
            rust_descriptor::emit_module(
                "// Native preparation pilot source descriptors.\n",
                &descriptors,
            ),
        ),
    ] {
        let path = out.join(name);
        fs::write(&path, contents)
            .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));
    }
}
