use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use miden_assembly::Assembler;
use miden_debug_types::{Location, SourceFile, SourceSpan};
use miden_processor::{
    BaseHost, ExecutionError, ExecutionRequest, FastProcessor, FutureMaybeSend, Host,
    LoadedMastForest, MastForestLoadError, ProcessorState, Program, StackInputs, Word,
    advice::AdviceMutation,
    event::EventError,
    mast::{DenseMastForestBuilder, ExternalNodeBuilder, JoinNodeBuilder},
};

struct StoreHost {
    result: Result<Option<LoadedMastForest>, std::io::ErrorKind>,
    calls: AtomicUsize,
}

impl BaseHost for StoreHost {
    fn get_label_and_source_file(&self, _: &Location) -> (SourceSpan, Option<Arc<SourceFile>>) {
        (SourceSpan::UNKNOWN, None)
    }
}

impl Host for StoreHost {
    fn get_mast_forest(
        &self,
        _: &Word,
    ) -> impl FutureMaybeSend<Result<Option<LoadedMastForest>, MastForestLoadError>> {
        async move {
            tokio::task::yield_now().await;
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.result.clone().map_err(|kind| Box::new(std::io::Error::from(kind)) as _)
        }
    }

    fn on_event(
        &mut self,
        _: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
        async { Ok(Vec::new()) }
    }
}

fn fixture() -> (Program, StoreHost) {
    let callee = Assembler::default()
        .assemble_program("callee", "begin add.1 end")
        .unwrap()
        .unwrap_program();
    let mut forest = DenseMastForestBuilder::new();
    let external = forest.push_node(ExternalNodeBuilder::new(callee.hash())).unwrap();
    let root = forest.push_node(JoinNodeBuilder::new([external; 2])).unwrap();
    forest.mark_root(root);
    let forest = forest.build().unwrap();
    let root = forest.procedure_roots()[0];
    let host = StoreHost {
        result: Ok(Some(LoadedMastForest::new(callee.mast_forest().clone()))),
        calls: AtomicUsize::new(0),
    };
    (Program::new(forest.into(), root), host)
}

#[tokio::test]
async fn async_lookup_loads_once_and_reuses_the_forest() {
    let (program, mut host) = fixture();
    // Native callers retain the ability to move the execution future between threads.
    #[cfg(not(target_family = "wasm"))]
    fn assert_send<T: Send>(future: T) -> T {
        future
    }
    #[cfg(target_family = "wasm")]
    fn assert_send<T>(future: T) -> T {
        future
    }
    let output = assert_send(ExecutionRequest::new(&program).execute().run(&mut host))
        .await
        .unwrap();
    assert_eq!(output.stack.get_element(0), Some(miden_processor::Felt::from_u32(2)));
    assert_eq!(host.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn async_lookup_preserves_storage_errors() {
    let (program, mut host) = fixture();
    host.result = Err(std::io::ErrorKind::PermissionDenied);
    let error = ExecutionRequest::new(&program)
        .record_witness()
        .run(&mut host)
        .await
        .unwrap_err();
    let ExecutionError::MastForestError { error, .. } = error else {
        panic!("expected a storage error");
    };
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::PermissionDenied
    );
}

#[tokio::test]
async fn absent_forest_reports_procedure_not_found() {
    let (program, mut host) = fixture();
    host.result = Ok(None);
    let error = ExecutionRequest::new(&program).execute().run(&mut host).await.unwrap_err();
    assert!(matches!(error, ExecutionError::ProcedureNotFound { .. }));
    assert_eq!(host.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn stepped_execution_uses_the_same_lookup() {
    let (program, mut host) = fixture();
    let mut processor = FastProcessor::new(StackInputs::default());
    let mut context = Some(processor.get_initial_resume_context(&program).unwrap());
    while let Some(current) = context {
        context = processor.step(&mut host, current).await.unwrap();
    }
    assert_eq!(processor.stack_get(0), miden_processor::Felt::from_u32(2));
    assert_eq!(host.calls.load(Ordering::SeqCst), 1);
}
