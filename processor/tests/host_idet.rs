use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use miden_assembly::Assembler;
use miden_debug_types::{Location, SourceFile, SourceSpan};
use miden_processor::{
    AsyncForestLoader, BaseHost, ExecutionError, FastProcessor, FutureMaybeSend, Host,
    LoadedMastForest, MastForestLoadFuture, ProcessorState, Program, StackInputs, Word,
    advice::AdviceMutation,
    event::EventError,
    mast::{DenseMastForestBuilder, ExternalNodeBuilder, JoinNodeBuilder},
};

struct Store {
    result: Result<Option<LoadedMastForest>, std::io::ErrorKind>,
    calls: AtomicUsize,
}

impl AsyncForestLoader for Store {
    fn load<'a>(&'a self, _: &'a Word) -> MastForestLoadFuture<'a> {
        Box::pin(async move {
            tokio::task::yield_now().await;
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.result.clone().map_err(|kind| Box::new(std::io::Error::from(kind)) as _)
        })
    }
}

struct StoreHost {
    store: Store,
    enabled: bool,
    legacy_calls: AtomicUsize,
}

impl BaseHost for StoreHost {
    fn get_label_and_source_file(&self, _: &Location) -> (SourceSpan, Option<Arc<SourceFile>>) {
        (SourceSpan::UNKNOWN, None)
    }
}

impl Host for StoreHost {
    fn forest_loader(&self) -> Option<&dyn AsyncForestLoader> {
        self.enabled.then_some(&self.store)
    }

    fn get_mast_forest(&self, _: &Word) -> impl FutureMaybeSend<Option<LoadedMastForest>> {
        self.legacy_calls.fetch_add(1, Ordering::SeqCst);
        async { None }
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
        store: Store {
            result: Ok(Some(LoadedMastForest::new(callee.mast_forest().clone()))),
            calls: AtomicUsize::new(0),
        },
        enabled: true,
        legacy_calls: AtomicUsize::new(0),
    };
    (Program::new(forest.into(), root), host)
}

#[tokio::test]
async fn async_extension_loads_once_and_reuses_the_forest() {
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
    let output =
        assert_send(FastProcessor::new(StackInputs::default()).execute(&program, &mut host))
            .await
            .unwrap();
    assert_eq!(output.stack.get_element(0), Some(miden_processor::Felt::from_u32(2)));
    assert_eq!(host.store.calls.load(Ordering::SeqCst), 1);
    assert_eq!(host.legacy_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn extension_error_is_preserved_without_legacy_retry() {
    let (program, mut host) = fixture();
    host.store.result = Err(std::io::ErrorKind::PermissionDenied);
    let error = FastProcessor::new(StackInputs::default())
        .execute_for_proving(&program, &mut host)
        .await
        .unwrap_err();
    let ExecutionError::MastForestError { error, .. } = error else {
        panic!("expected a storage error");
    };
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(host.legacy_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn extension_absence_is_distinct_from_an_absent_forest() {
    for enabled in [false, true] {
        let (program, mut host) = fixture();
        host.enabled = enabled;
        host.store.result = Ok(None);
        let error = FastProcessor::new(StackInputs::default())
            .execute(&program, &mut host)
            .await
            .unwrap_err();
        assert!(matches!(error, ExecutionError::ProcedureNotFound { .. }));
        assert_eq!(host.store.calls.load(Ordering::SeqCst), usize::from(enabled));
        assert_eq!(host.legacy_calls.load(Ordering::SeqCst), usize::from(!enabled));
    }
}

#[tokio::test]
async fn stepped_execution_uses_the_same_extension() {
    let (program, mut host) = fixture();
    let mut processor = FastProcessor::new(StackInputs::default());
    let mut context = Some(processor.get_initial_resume_context(&program).unwrap());
    while let Some(current) = context {
        context = processor.step(&mut host, current).await.unwrap();
    }
    assert_eq!(processor.stack_get(0), miden_processor::Felt::from_u32(2));
    assert_eq!(host.store.calls.load(Ordering::SeqCst), 1);
    assert_eq!(host.legacy_calls.load(Ordering::SeqCst), 0);
}
