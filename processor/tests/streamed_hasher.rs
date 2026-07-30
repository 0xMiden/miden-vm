//! The overlapped execute-and-build path must produce exactly the trace the
//! buffered path produces: same values, byte for byte, in every segment.

use miden_assembly::Assembler;
use miden_processor::{
    DefaultHost, ExecutionOptions, FastProcessor, Felt, StackInputs, advice::AdviceInputs,
    trace::build_trace,
};
use miden_utils_testing::crypto::{MerkleTree, init_merkle_leaf, init_merkle_store};

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

fn processor(stack: &[u64], advice: AdviceInputs) -> FastProcessor {
    let stack: Vec<Felt> = stack.iter().map(|&v| Felt::new(v).unwrap()).collect();
    FastProcessor::new_with_options(
        StackInputs::new(&stack).unwrap(),
        advice,
        ExecutionOptions::default()
            .with_core_trace_fragment_size(64)
            .expect("valid fragment size"),
    )
    .unwrap()
}

/// Runs `program_src` through both trace-build paths and asserts byte-for-byte
/// equality of every trace segment.
fn assert_overlapped_matches_buffered(program_src: &str, stack: &[u64], advice: &AdviceInputs) {
    let program = Assembler::default()
        .assemble_program("test", program_src)
        .unwrap()
        .unwrap_program();

    let buffered = {
        let mut host = DefaultHost::default();
        let inputs = processor(stack, advice.clone())
            .execute_trace_inputs_sync(&program, &mut host)
            .unwrap();
        build_trace(inputs).unwrap()
    };

    let streamed = {
        let mut host = DefaultHost::default();
        processor(stack, advice.clone())
            .execute_and_build_trace_sync(&program, &mut host)
            .unwrap()
    };

    assert_eq!(buffered.program_hash(), streamed.program_hash());
    let (b_core, b_chiplets, b_p2) = buffered.main_trace().to_air_matrices();
    let (s_core, s_chiplets, s_p2) = streamed.main_trace().to_air_matrices();
    assert_eq!(b_core, s_core, "core segment diverged");
    assert_eq!(b_chiplets, s_chiplets, "chiplets segment diverged");
    assert_eq!(b_p2, s_p2, "poseidon2 segment diverged");
}

#[test]
fn overlapped_build_matches_buffered() {
    assert_overlapped_matches_buffered(PROGRAM, &[1], &AdviceInputs::default());
}

/// Covers the two Merkle op kinds in the streamed replay (`BuildMerkleRoot`
/// from `mtree_get`, `UpdateMerkleRoot` from `mtree_set`), which the main
/// program cannot exercise without a Merkle store in the advice inputs.
#[test]
fn overlapped_build_matches_buffered_merkle() {
    let index = 3usize;
    let (leaves, store) = init_merkle_store(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let tree = MerkleTree::new(leaves).unwrap();
    let root = tree.root();
    let advice = AdviceInputs::default().with_merkle_store(store);

    // mtree_get consumes [d, i, R, ...] with depth on top.
    let get_stack = [
        tree.depth() as u64,
        index as u64,
        root[0].as_canonical_u64(),
        root[1].as_canonical_u64(),
        root[2].as_canonical_u64(),
        root[3].as_canonical_u64(),
    ];
    assert_overlapped_matches_buffered("begin mtree_get dropw end", &get_stack, &advice);

    // mtree_set consumes [d, i, R, V_new] with depth on top.
    let new_node = init_merkle_leaf(9);
    let set_stack = [
        tree.depth() as u64,
        index as u64,
        root[0].as_canonical_u64(),
        root[1].as_canonical_u64(),
        root[2].as_canonical_u64(),
        root[3].as_canonical_u64(),
        new_node[0].as_canonical_u64(),
        new_node[1].as_canonical_u64(),
        new_node[2].as_canonical_u64(),
        new_node[3].as_canonical_u64(),
    ];
    assert_overlapped_matches_buffered("begin mtree_set end", &set_stack, &advice);
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
        processor(&[1], AdviceInputs::default())
            .execute_and_build_trace_sync(&program, &mut host)
            .unwrap();
    });

    assert_eq!(
        enters.load(Ordering::SeqCst),
        2,
        "span must be entered by the caller and re-entered by the builder thread"
    );
}
