use std::sync::{Arc, Mutex};

use miden_vm::{Assembler, DefaultHost, ExecutionOptions, Processor, Prover};
use tracing::{
    Level, Subscriber,
    instrument::WithSubscriber,
    span::{Attributes, Id},
};
use tracing_subscriber::{
    EnvFilter, Layer, Registry,
    layer::{Context, SubscriberExt},
    registry::LookupSpan,
};

const PROVING_SPAN: &str = "prove_program";

#[derive(Clone, Default)]
struct ProvingPhases(Arc<Mutex<Vec<&'static str>>>);

impl<S: Subscriber + for<'lookup> LookupSpan<'lookup>> Layer<S> for ProvingPhases {
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let span = ctx.span(id).unwrap();
        if span.scope().skip(1).any(|parent| {
            let metadata = parent.metadata();
            metadata.name() == PROVING_SPAN
                && metadata.target() == "miden::vm"
                && *metadata.level() == Level::TRACE
        }) {
            self.0.lock().unwrap().push(attrs.metadata().name());
        }
    }
}

#[tokio::test]
async fn combined_proving_spans_cover_execution_trace_building_and_vm_proving() {
    let program = Assembler::default()
        .assemble_program("logging", "begin push.1 drop end")
        .unwrap()
        .unwrap_program();
    let prover = Prover::new();
    let request = || {
        Processor::new(&program)
            .with_options(ExecutionOptions::default().with_overlapped_trace_build(false))
    };

    for synchronous in [true, false] {
        let phases = ProvingPhases::default();
        let subscriber = Registry::default()
            .with(EnvFilter::new("info,miden::vm=trace"))
            .with(phases.clone());
        async {
            let mut host = DefaultHost::default();
            if synchronous {
                request().prove_complete(&prover).run_sync(&mut host).unwrap();
            } else {
                request().prove_deferred(&prover).run(&mut host).await.unwrap();
            }
        }
        .with_subscriber(subscriber)
        .await;

        let phases = phases.0.lock().unwrap();
        for phase in ["execute_program", "build_vm_trace", "prove_vm"] {
            assert!(
                phases.contains(&phase),
                "missing {phase} with synchronous={synchronous}: {phases:?}"
            );
        }
    }
}
