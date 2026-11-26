use std::sync::Arc;

use miden_assembly::Assembler;
use miden_debug_engine::exec::{DiagnosticExecutor, MastForestRecorder, RecordingHost};
use miden_debug_types::{Location, SourceFile, SourceSpan};
use miden_processor::{
    BaseHost, ExecutionOptions, LoadedMastForest, MastForestLoadError, ProcessorError,
    ProcessorState, StackInputs, SyncHost, Word,
    advice::{AdviceInputs, AdviceMutation},
    event::EventError,
    mast::{DenseMastForestBuilder, ExternalNodeBuilder},
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
    fn get_mast_forest(&self, _: &Word) -> Result<Option<LoadedMastForest>, MastForestLoadError> {
        if self.fail {
            Err(std::io::Error::other("store unavailable").into())
        } else {
            Ok(Some(self.forest.clone()))
        }
    }

    fn on_event(&mut self, _: &ProcessorState<'_>) -> Result<Vec<AdviceMutation>, EventError> {
        Ok(Vec::new())
    }
}

fn ready<T>(future: impl Future<Output = T>) -> T {
    use core::task::{Context, Poll, Waker};
    let mut future = core::pin::pin!(future);
    match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the synchronous store must complete immediately"),
    }
}

#[test]
fn diagnostic_recording_preserves_lookup_results() {
    let callee = Assembler::default()
        .assemble_program("callee", "begin add.1 end")
        .unwrap()
        .unwrap_program();
    let mut caller = DenseMastForestBuilder::new();
    let root = caller.push_node(ExternalNodeBuilder::new(callee.hash())).unwrap();
    caller.mark_root(root);
    let caller = caller.build().unwrap();
    let root = caller.procedure_roots()[0];
    let program = miden_processor::Program::new(caller.into(), root);
    let loaded = LoadedMastForest::new(callee.mast_forest().clone());
    let mut host = StoreHost { forest: loaded.clone(), fail: false };
    let forests = MastForestRecorder::new();
    {
        let mut recording = RecordingHost::new(&mut host, None, Some(forests.clone()));
        let executor = DiagnosticExecutor::new(
            StackInputs::default(),
            AdviceInputs::default(),
            ExecutionOptions::default(),
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
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    );
    let error = ready(executor.execute_async(&program, &mut recording)).unwrap_err();
    let ProcessorError::MastForestLoad { source, .. } = error.kind() else {
        panic!("expected the store error");
    };
    assert_eq!(
        source.downcast_ref::<std::io::Error>().unwrap().to_string(),
        "store unavailable"
    );
    assert!(failed_forests.snapshot().is_empty());
}
