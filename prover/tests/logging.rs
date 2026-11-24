use std::sync::{Arc, Mutex};

use miden_assembly::Assembler;
use miden_processor::{DefaultHost, Processor, Program};
use miden_prover::Prover;
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

fn capture_proving(program: &Program, filter: &str) -> Vec<Record> {
    let capture = Capture::default();
    let subscriber = Registry::default().with(EnvFilter::new(filter)).with(capture.clone());
    tracing::subscriber::with_default(subscriber, || {
        let prover = Prover::new();
        let output = Processor::new(program)
            .record_witness()
            .run_sync(&mut DefaultHost::default())
            .unwrap();
        prover.prove_full(output.witness).unwrap();
    });
    capture.0.lock().unwrap().clone()
}

#[test]
fn proving_is_quiet_at_info_and_separates_trace_building() {
    let program = Assembler::default()
        .assemble_program("logging", "begin push.1 drop end")
        .unwrap()
        .unwrap_program();
    let info = capture_proving(&program, "info");
    assert!(info.is_empty(), "{info:?}");

    let records = capture_proving(&program, "info,miden::vm=trace");
    let execution = records.iter().find(|record| record.name == "execute_program").unwrap();
    assert_eq!(execution.target, EXECUTE);

    let builds: Vec<_> = records.iter().filter(|record| record.name == "build_vm_trace").collect();
    assert_eq!(builds.len(), 1, "{records:?}");
    assert_eq!(builds[0].target, TRACE);
    assert!(!builds[0].in_execution, "{records:?}");
}
