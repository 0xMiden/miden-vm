//! The overlapped execute-and-build path must produce exactly the trace the
//! buffered path produces: same values, byte for byte, in every segment.

use miden_assembly::Assembler;
use miden_processor::{
    DefaultHost, ExecutionOptions, FastProcessor, StackInputs, advice::AdviceInputs,
    trace::build_trace,
};

/// A program mixing basic blocks (including repeats, which exercise the
/// hasher's memoized-trace path), control blocks, and an `hperm` (a streamed
/// `Permute` request). The test processor uses a small fragment size so the
/// run spans multiple trace fragments.
const PROGRAM: &str = "
begin
    push.1 push.2
    repeat.8
        u32wrapping_add dup.1 swap
        push.3 u32and drop
    end
    if.true
        push.5 mul
    else
        push.7 add
    end
    padw padw padw hperm dropw dropw dropw
    repeat.4
        push.11 u32wrapping_add
    end
    drop
end
";

fn processor() -> FastProcessor {
    FastProcessor::new_with_options(
        StackInputs::new(&[miden_processor::Felt::new_unchecked(1)]).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default()
            .with_core_trace_fragment_size(64)
            .expect("valid fragment size"),
    )
    .unwrap()
}

#[test]
fn overlapped_build_matches_buffered() {
    let program = Assembler::default().assemble_program("test", PROGRAM).unwrap().unwrap_program();

    let buffered = {
        let mut host = DefaultHost::default();
        let inputs = processor().execute_trace_inputs_sync(&program, &mut host).unwrap();
        build_trace(inputs).unwrap()
    };

    let streamed = {
        let mut host = DefaultHost::default();
        processor().execute_and_build_trace_sync(&program, &mut host).unwrap()
    };

    assert_eq!(buffered.program_hash(), streamed.program_hash());
    let (b_core, b_chiplets, b_p2) = buffered.main_trace().to_air_matrices();
    let (s_core, s_chiplets, s_p2) = streamed.main_trace().to_air_matrices();
    assert_eq!(b_core, s_core, "core segment diverged");
    assert_eq!(b_chiplets, s_chiplets, "chiplets segment diverged");
    assert_eq!(b_p2, s_p2, "poseidon2 segment diverged");
}

/// The overlap path spawns the hasher builder on its own thread; span context is
/// thread-local, so the builder re-enters the `execute_and_build_trace_sync` span
/// to stay attributed under it. This asserts the span is entered on both threads:
/// once by `#[instrument]` on the caller and once by the builder.
#[test]
fn overlap_builder_thread_enters_the_instrument_span() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use tracing::span::{Attributes, Id};
    use tracing_subscriber::{Registry, layer::SubscriberExt};

    #[derive(Default)]
    struct EnterCounter {
        target: std::sync::Mutex<Option<Id>>,
        enters: Arc<AtomicUsize>,
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for EnterCounter {
        fn on_new_span(
            &self,
            attrs: &Attributes<'_>,
            id: &Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if attrs.metadata().name() == "execute_and_build_trace_sync" {
                *self.target.lock().unwrap() = Some(id.clone());
            }
        }

        fn on_enter(&self, id: &Id, _ctx: tracing_subscriber::layer::Context<'_, S>) {
            if self.target.lock().unwrap().as_ref() == Some(id) {
                self.enters.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    let enters = Arc::new(AtomicUsize::new(0));
    let layer = EnterCounter {
        target: std::sync::Mutex::new(None),
        enters: Arc::clone(&enters),
    };
    let subscriber = Registry::default().with(layer);

    let program = Assembler::default().assemble_program("test", PROGRAM).unwrap().unwrap_program();
    tracing::subscriber::with_default(subscriber, || {
        let mut host = DefaultHost::default();
        processor().execute_and_build_trace_sync(&program, &mut host).unwrap();
    });

    assert_eq!(
        enters.load(Ordering::SeqCst),
        2,
        "span must be entered by the caller and re-entered by the builder thread"
    );
}
