//! Compiled regression fixture for challenge preparation and row-cache substitution.

use miden_constraint_compiler::ir::Graph;
use miden_core::{Felt, field::QuadFelt};
use miden_stark::air::native;
use p3_field::{Algebra, PrimeCharacteristicRing};

#[path = "../build/preparation_fixture.rs"]
mod source;
use source::PreparationFixture;

// These outputs are generated from the shared authored fixture during ordinary compilation.
// They are comparison subjects; neither output is the expected source relation.
mod native_evaluators {
    include!(concat!(env!("OUT_DIR"), "/native_pilot_evaluators.rs"));
}
mod native_descriptors {
    include!(concat!(env!("OUT_DIR"), "/native_pilot_descriptors.rs"));
}

enum Prepared<E> {
    Cached([E; native_evaluators::CACHED_PREPARED_TERMS]),
    Uncached([E; native_evaluators::UNCACHED_PREPARED_TERMS]),
}

struct CompiledFixture {
    cached: bool,
    descriptor: native::AirDescriptor<Felt>,
}

impl CompiledFixture {
    fn new(cached: bool) -> Self {
        let descriptor = if cached {
            native_descriptors::descriptor_cached()
        } else {
            native_descriptors::descriptor_uncached()
        };
        Self { cached, descriptor }
    }
}

impl native::AirKernel for CompiledFixture {
    type F = Felt;
    type Prepared<B: Algebra<Felt>, E: Algebra<B>> = Prepared<E>;

    fn descriptor(&self) -> &native::AirDescriptor<Felt> {
        &self.descriptor
    }

    fn prepare<B: Algebra<Felt>, E: Algebra<B>>(
        &self,
        inputs: native::UniformInputs<'_, B, E>,
    ) -> Prepared<E> {
        if self.cached {
            Prepared::Cached(native_evaluators::precompute_cached(inputs))
        } else {
            Prepared::Uncached(native_evaluators::precompute_uncached(inputs))
        }
    }

    fn eval_row<B: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, B>,
        inputs: native::Inputs<'_, B>,
        prepared: &Prepared<B::ExtExpr>,
        sink: &mut B,
    ) {
        match (self.cached, prepared) {
            (true, Prepared::Cached(terms)) => {
                native_evaluators::eval_cached(frame, inputs, sink, terms)
            },
            (false, Prepared::Uncached(terms)) => {
                native_evaluators::eval_uncached(frame, inputs, sink, terms)
            },
            _ => unreachable!("session retains preparation for the same fixture configuration"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Value {
    Base(Felt),
    Extension(QuadFelt),
}

#[derive(Default)]
struct Collector {
    values: Vec<Value>,
}

impl native::LiftedAirBuilder for Collector {
    type F = Felt;
    type Expr = Felt;
    type ExtExpr = QuadFelt;

    fn emit_base(&mut self, value: Felt, _meta: native::ConstraintMeta<'_>) {
        self.values.push(Value::Base(value));
    }
    fn emit_ext(&mut self, value: QuadFelt, _meta: native::ConstraintMeta<'_>) {
        self.values.push(Value::Extension(value));
    }
}

#[test]
fn native_pilot_uses_exact_schedule_capacity_without_row_challenge_recomputation() {
    assert_eq!(native_evaluators::CACHED_PREPARED_TERMS, 2);
    assert_eq!(native_evaluators::UNCACHED_PREPARED_TERMS, 0);
    let output = include_str!(concat!(env!("OUT_DIR"), "/native_pilot_evaluators.rs"));
    let cached = output
        .split_once("pub fn eval_cached")
        .unwrap()
        .1
        .split("pub const UNCACHED_PREPARED_TERMS")
        .next()
        .unwrap();
    assert!(cached.contains("terms[0]"));
    assert!(cached.contains("terms[1]"));
    assert!(!cached.contains("inputs.challenges"));
}

#[test]
fn compiled_native_descriptor_and_non_copy_symbolic_kernel_match_the_simple_source() {
    use miden_constraint_compiler::ir::{capture_kernel_native_into, capture_native_into};
    use native::AirKernel;

    for cached in [false, true] {
        let source = PreparationFixture(cached);
        let kernel = CompiledFixture::new(cached);
        let mut graph = Graph::builder();
        let (authored, descriptor) = capture_native_into(&source, &mut graph).unwrap();
        assert_eq!(kernel.descriptor().spec(), descriptor.spec());
        assert_eq!(kernel.descriptor().analysis(), descriptor.analysis());
        assert_eq!(kernel.descriptor().fingerprint(), descriptor.fingerprint());
        // This simple cache fixture has no reassociation rewrite. General optimized relations
        // require polynomial-value comparisons; fingerprints need not equal their recapture.
        let (generated, _) = capture_kernel_native_into(&kernel, &mut graph).unwrap();
        assert_eq!(authored.base_roots, generated.base_roots);
        assert_eq!(authored.ext_roots, generated.ext_roots);
        assert_eq!(authored.base_global_indices, generated.base_global_indices);
        assert_eq!(authored.ext_global_indices, generated.ext_global_indices);
    }
}

#[test]
fn compiled_native_sessions_preserve_known_scalar_values_and_assertion_classes() {
    use native::AirKernel;

    let challenges = [
        QuadFelt::new([Felt::from_u32(7), Felt::from_u32(11)]),
        QuadFelt::new([Felt::from_u32(3), Felt::from_u32(5)]),
    ];
    for cached in [false, true] {
        let source = PreparationFixture(cached);
        let kernel = CompiledFixture::new(cached);
        let inputs = native::UniformInputs {
            public_values: &[],
            challenges: &challenges,
            exports: &[],
        };
        let session = kernel.bind(inputs).unwrap();
        for value in [Felt::ZERO, Felt::from_u32(13)] {
            let main = [value];
            let auxiliary = [QuadFelt::ZERO];
            let frame = native::AirFrame {
                main: native::Rows { current: &main, next: &main },
                preprocessed: native::Rows { current: &[], next: &[] },
                aux: native::Rows { current: &auxiliary, next: &auxiliary },
                periodic: &[],
                selectors: native::Selectors {
                    first: Felt::ONE,
                    last: Felt::ZERO,
                    transition: Felt::ONE,
                },
            };
            let mut authored = Collector::default();
            native::LiftedAir::eval(&source, &frame, inputs, &mut authored);
            let mut generated = Collector::default();
            session.eval(&frame, &mut generated);
            let expected = if cached {
                let square = challenges[1] * challenges[1];
                vec![
                    Value::Extension(square * value),
                    Value::Extension(square * challenges[1] + value),
                ]
            } else {
                vec![Value::Base(value)]
            };
            assert_eq!(authored.values, expected);
            assert_eq!(generated.values, expected);
        }
    }
}

#[test]
fn optimized_native_renderer_uses_all_namespaces_and_compiles_typed_arithmetic() {
    use miden_constraint_compiler::{
        ir::{capture_native_into, capture_native_into_with},
        testing::eval_graph,
    };

    let source = source::NativeRendererFixture;
    let mut builder = Graph::builder();
    let (authored, descriptor) = capture_native_into(&source, &mut builder).unwrap();
    let embedded = native_descriptors::descriptor_renderer();
    assert_eq!(embedded.spec(), descriptor.spec());
    assert_eq!(embedded.analysis(), descriptor.analysis());
    assert_eq!(embedded.fingerprint(), descriptor.fingerprint());
    assert_eq!(embedded.label(0), Some("renderer/base-dot"));
    let (generated, _) = capture_native_into_with(&source, &mut builder, |frame, inputs, sink| {
        let terms = native_evaluators::precompute_renderer(inputs);
        assert_eq!(terms.len(), native_evaluators::RENDERER_PREPARED_TERMS);
        native_evaluators::eval_renderer(frame, inputs, sink, &terms);
    })
    .unwrap();
    assert_eq!(authored.base_global_indices, generated.base_global_indices);
    assert_eq!(authored.ext_global_indices, generated.ext_global_indices);
    let graph = builder.freeze();
    // Optimization may change structure. The independently authored roots remain the oracle.
    for seed in [0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89] {
        let values = eval_graph(&graph, seed);
        for (expected, actual) in authored
            .base_roots
            .iter()
            .zip(&generated.base_roots)
            .chain(authored.ext_roots.iter().zip(&generated.ext_roots))
        {
            assert_eq!(values[expected.index()], values[actual.index()]);
        }
    }
    let code = include_str!(concat!(env!("OUT_DIR"), "/native_pilot_evaluators.rs"));
    let renderer = code.split_once("pub fn eval_renderer").unwrap().1;
    assert!(renderer.contains("dot_product"));
}
