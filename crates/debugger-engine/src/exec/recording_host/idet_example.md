## Recording a host with a loader capability

Wrap the host before passing it to a diagnostic executor. Forests returned by its
loader are recorded for replay, and storage errors keep their original type.

```rust
use std::sync::Arc;
use miden_assembly::Assembler;
use miden_debug_engine::exec::{DiagnosticExecutor, MastForestRecorder, RecordingHost};
use miden_debug_types::{Location, SourceFile, SourceSpan};
use miden_processor::{
    BaseHost, ExecutionError, ExecutionOptions, LoadedMastForest, MastForestLoadResult,
    ProcessorState, StackInputs, SyncForestLoader, SyncHost, Word,
    advice::{AdviceInputs, AdviceMutation}, event::EventError,
    mast::{ExternalNodeBuilder, MastForest},
};

struct StoreHost {
    forest: LoadedMastForest,
    fail: bool,
}

impl BaseHost for StoreHost {
    fn get_label_and_source_file(&self, _: &Location) -> (SourceSpan, Option<Arc<SourceFile>>) {
        (SourceSpan::UNKNOWN, None)
    }
}

impl SyncHost for StoreHost {
    fn forest_loader(&self) -> Option<&dyn SyncForestLoader> { Some(self) }

    fn get_mast_forest(&self, _: &Word) -> Option<LoadedMastForest> {
        unreachable!("use the advertised loader")
    }

    fn on_event(&mut self, _: &ProcessorState<'_>) -> Result<Vec<AdviceMutation>, EventError> {
        Ok(Vec::new())
    }
}

impl SyncForestLoader for StoreHost {
    fn load_sync(&self, _: &Word) -> MastForestLoadResult {
        if self.fail {
            Err(std::io::Error::other("store unavailable").into())
        } else {
            Ok(Some(self.forest.clone()))
        }
    }
}

# fn ready<T>(future: impl core::future::Future<Output = T>) -> T {
#     use core::task::{Context, Poll, Waker};
#     let mut future = core::pin::pin!(future);
#     match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
#         Poll::Ready(output) => output,
#         Poll::Pending => panic!("the synchronous store must complete immediately"),
#     }
# }
let callee = Assembler::default()
    .assemble_program("callee", "begin add.1 end").unwrap().unwrap_program();
let mut caller = MastForest::new();
let root = ExternalNodeBuilder::new(callee.hash()).add_to_forest(&mut caller).unwrap();
caller.make_root(root);
let program = miden_processor::Program::new(caller.into(), root);
let loaded = LoadedMastForest::new(callee.mast_forest().clone());
let mut host = StoreHost { forest: loaded.clone(), fail: false };
let forests = MastForestRecorder::new();
{
    let mut recording = RecordingHost::new(&mut host, None, Some(forests.clone()));
    let executor = DiagnosticExecutor::new(
        StackInputs::default(), AdviceInputs::default(), ExecutionOptions::default(),
    );
    let output = ready(executor.execute_async(&program, &mut recording)).unwrap();
    assert_eq!(output.stack.get_element(0), Some(miden_processor::Felt::from_u32(1)));
}
assert_eq!(forests.snapshot().len(), 1);
assert!(Arc::ptr_eq(forests.snapshot()[0].mast_forest(), loaded.mast_forest()));

host.fail = true;
let failed_forests = MastForestRecorder::new();
let mut recording = RecordingHost::new(&mut host, None, Some(failed_forests.clone()));
let executor = DiagnosticExecutor::new(
    StackInputs::default(), AdviceInputs::default(), ExecutionOptions::default(),
);
let error = ready(executor.execute_async(&program, &mut recording)).unwrap_err();
let ExecutionError::MastForestError { error, .. } = error else {
    panic!("expected the store error");
};
assert_eq!(error.downcast_ref::<std::io::Error>().unwrap().to_string(), "store unavailable");
assert!(failed_forests.snapshot().is_empty());
```
