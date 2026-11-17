use std::sync::{Arc, Mutex};

use miden_assembly::Assembler;
use miden_processor::{DefaultHost, Program};
use miden_prover::{AdviceInputs, ExecutionOptions, Prover, StackInputs, prove_sync};
use tracing::{Event, Subscriber, span::Attributes};
use tracing_subscriber::{
    EnvFilter, Layer, Registry, layer::Context, prelude::*, registry::LookupSpan,
};

const EXECUTE: &str = "miden::vm::execute";
const TRACE: &str = "miden::vm::trace";

#[derive(Clone, Debug)]
struct Record {
    name: &'static str,
    target: &'static str,
    in_execution: bool,
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<Record>>>);

impl<S> Layer<S> for Capture
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &tracing::span::Id, ctx: Context<'_, S>) {
        let in_execution = ctx
            .span(id)
            .unwrap()
            .scope()
            .skip(1)
            .any(|span| span.metadata().target() == EXECUTE);
        self.0.lock().unwrap().push(Record {
            name: attrs.metadata().name(),
            target: attrs.metadata().target(),
            in_execution,
        });
    }

    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        self.0.lock().unwrap().push(Record {
            name: event.metadata().name(),
            target: event.metadata().target(),
            in_execution: false,
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
fn proving_is_quiet_at_info_and_separates_trace_building() {
    let program = Assembler::default()
        .assemble_program("logging", "begin push.1 drop end")
        .unwrap()
        .unwrap_program();
    let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build().unwrap();

    for overlapped in [false, true] {
        if overlapped && !cfg!(feature = "std") {
            continue;
        }
        let info = pool.install(|| capture_proving(&program, overlapped, "info"));
        assert!(info.is_empty(), "{info:?}");

        let records =
            pool.install(|| capture_proving(&program, overlapped, "info,miden::vm=trace"));
        let pipeline = records.iter().find(|record| record.name == "prove_program").unwrap();
        assert_eq!(pipeline.target, "miden::vm");

        let streamed_hasher = records.iter().find(|record| record.name == "build_streamed_hasher");
        assert_eq!(streamed_hasher.is_some(), overlapped, "{records:?}");
        if let Some(hasher) = streamed_hasher {
            assert_eq!(hasher.target, TRACE);
        }

        let builds: Vec<_> =
            records.iter().filter(|record| record.name == "build_vm_trace").collect();
        assert_eq!(builds.len(), 1, "overlapped={overlapped}: {records:?}");
        assert_eq!(builds[0].target, TRACE);
        assert!(!builds[0].in_execution, "{records:?}");
    }
}
