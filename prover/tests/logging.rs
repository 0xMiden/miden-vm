use std::sync::{Arc, Mutex};

use miden_assembly::Assembler;
use miden_processor::{DefaultHost, Program};
use miden_prover::{AdviceInputs, ExecutionOptions, Prover, StackInputs, prove_sync};
use tracing::{Event, Level, Metadata, Subscriber, span::Attributes};
use tracing_subscriber::{
    EnvFilter, Layer, Registry, layer::Context, prelude::*, registry::LookupSpan,
};

const EXECUTE: &str = "miden::vm::execute";
const TRACE: &str = "miden::vm::trace";
const PROVE: &str = "miden::vm::prove";

#[derive(Clone, Debug)]
struct Record {
    metadata: &'static Metadata<'static>,
    parent_targets: Vec<&'static str>,
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<Record>>>);

impl<S> Layer<S> for Capture
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &tracing::span::Id, ctx: Context<'_, S>) {
        let parent_targets = ctx
            .span(id)
            .unwrap()
            .scope()
            .skip(1)
            .map(|span| span.metadata().target())
            .collect();
        self.0.lock().unwrap().push(Record {
            metadata: attrs.metadata(),
            parent_targets,
        });
    }

    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        self.0.lock().unwrap().push(Record {
            metadata: event.metadata(),
            parent_targets: Vec::new(),
        });
    }
}

fn capture_proving(program: &Program, overlapped: bool, filter: &str) -> Vec<Record> {
    let capture = Capture::default();
    let subscriber = Registry::default().with(EnvFilter::new(filter)).with(capture.clone());
    tracing::subscriber::with_default(subscriber, || {
        prove_sync(
            &Prover::new(),
            program,
            StackInputs::default(),
            AdviceInputs::default(),
            &mut DefaultHost::default(),
            ExecutionOptions::default().with_overlapped_trace_build(overlapped),
        )
        .unwrap();
    });
    capture.0.lock().unwrap().clone()
}

#[test]
fn proving_tracing_is_opt_in_and_keeps_phase_boundaries() {
    // Exceed the final FRI degree so proving includes at least one folding round.
    let program = Assembler::default()
        .assemble_program("logging", "begin repeat.256 push.1 drop end end")
        .unwrap()
        .unwrap_program();
    let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build().unwrap();

    for overlapped in [false, true] {
        if overlapped && !cfg!(feature = "std") {
            continue;
        }
        for filter in [
            "info",
            "info,miden::vm=trace",
            "info,miden::vm::trace=trace",
            "info,miden::vm::prove=trace",
        ] {
            let records = pool.install(|| capture_proving(&program, overlapped, filter));
            if filter == "info" {
                assert!(records.is_empty(), "{records:?}");
                continue;
            }
            assert!(records.iter().all(|record| *record.metadata.level() == Level::TRACE));

            if filter == "info,miden::vm=trace" {
                assert!(
                    records.iter().any(|record| {
                        record.metadata.name() == "prove_program"
                            && record.metadata.target() == "miden::vm"
                    }),
                    "{records:?}"
                );
                assert!(records.iter().any(|record| record.metadata.target() == EXECUTE));
                if overlapped {
                    assert!(
                        records.iter().any(|record| {
                            record.metadata.name() == "build_streamed_hasher"
                                && record.metadata.target() == TRACE
                        }),
                        "{records:?}"
                    );
                }
            }

            if filter != "info,miden::vm::prove=trace" {
                let builds: Vec<_> = records
                    .iter()
                    .filter(|record| record.metadata.name() == "build_vm_trace")
                    .collect();
                assert_eq!(builds.len(), 1, "overlapped={overlapped}: {records:?}");
                assert_eq!(builds[0].metadata.target(), TRACE);
                assert!(!builds[0].parent_targets.contains(&EXECUTE), "{records:?}");
                assert!(
                    records.iter().any(|record| {
                        record.metadata.name() == "vm_trace_ready"
                            && record.metadata.target() == TRACE
                    }),
                    "{records:?}"
                );
            }

            if filter == "info,miden::vm::trace=trace" {
                assert!(records.iter().all(|record| record.metadata.target() == TRACE));
            } else {
                for name in ["prove_stark", "open_polynomials", "fold_fri_round"] {
                    assert!(
                        records.iter().any(|record| {
                            record.metadata.name() == name && record.metadata.target() == PROVE
                        }),
                        "missing {name}: {records:?}"
                    );
                }
            }
            if filter == "info,miden::vm::prove=trace" {
                assert!(records.iter().all(|record| record.metadata.target() == PROVE));
                assert!(!records.iter().any(|record| record.metadata.name() == "prove_program"));
            }
        }
    }
}
