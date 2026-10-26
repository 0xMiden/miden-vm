use std::{
    future::Future,
    sync::{Arc, Mutex as DispatchMutex},
};

use miden_processor::ExecutionWitness;
use miden_prover::Prover;
use tokio::{
    sync::{Mutex, Semaphore, TryAcquireError},
    time::{Instant, sleep_until, timeout_at},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tonic::{Request, Response, Status};

use crate::{
    InputPolicy, PROTOCOL_VERSION, ProvingService, ServerConfig,
    failure::{prover_error, status},
    protocol::{
        ErrorCode, ProveRequest, ProveResponse, prover_service_server::ProverService as Rpc,
    },
};

#[cfg(test)]
type TestProver = Arc<dyn Fn(ExecutionWitness) -> Result<Vec<u8>, Status> + Send + Sync>;

pub(crate) struct State {
    pub config: ServerConfig,
    prover: Prover,
    admission: Arc<Semaphore>,
    ingress: Arc<Semaphore>,
    health_ingress: Arc<Semaphore>,
    worker: Arc<Mutex<()>>,
    // Serializes only shutdown and dispatch; never held while proving or awaiting.
    dispatch: DispatchMutex<()>,
    shutdown: CancellationToken,
    pub tasks: TaskTracker,
    pub response_tasks: TaskTracker,
    #[cfg(test)]
    test_prover: Option<TestProver>,
}

impl State {
    pub fn new(config: ServerConfig) -> Self {
        let mut prover = Prover::new()
            .with_max_prover_memory_bytes(config.vm_memory_bytes())
            .with_max_precompile_prover_memory_bytes(config.precompile_memory_bytes());
        if let Some(limits) = config.verification_precompile_limits() {
            prover = prover.with_verification_precompile_limits(limits.clone());
        }
        Self {
            admission: Arc::new(Semaphore::new(config.capacity().get())),
            ingress: Arc::new(Semaphore::new(config.capacity().get())),
            health_ingress: Arc::new(Semaphore::new(config.capacity().get())),
            config,
            prover,
            worker: Arc::new(Mutex::new(())),
            dispatch: DispatchMutex::new(()),
            shutdown: CancellationToken::new(),
            tasks: TaskTracker::new(),
            response_tasks: TaskTracker::new(),
            #[cfg(test)]
            test_prover: None,
        }
    }

    pub fn begin_shutdown(&self) {
        let _dispatch = self.dispatch.lock().expect("dispatch lock poisoned");
        self.admission.close();
        self.shutdown.cancel();
        self.tasks.close();
        self.response_tasks.close();
    }

    pub fn track_response(&self, future: impl Future<Output = ()> + Send + 'static) {
        let _dispatch = self.dispatch.lock().expect("dispatch lock poisoned");
        // Shutdown's connection grace already bounds draining. Serialize this
        // check with shutdown so no timer can appear after its tracker is joined.
        if !self.shutdown.is_cancelled() {
            self.response_tasks.spawn(future);
        }
    }

    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    pub fn ingress_semaphore(&self) -> Arc<Semaphore> {
        Arc::clone(&self.ingress)
    }

    pub fn health_ingress_semaphore(&self) -> Arc<Semaphore> {
        Arc::clone(&self.health_ingress)
    }

    fn prove<P: InputPolicy>(&self, bytes: &[u8]) -> Result<ProveResponse, Status> {
        let witness = P::read(bytes).map_err(|_| status(ErrorCode::InvalidWitness))?;
        let proof = self.prove_witness(witness)?;
        if proof.len() > self.config.max_proof_bytes() {
            return Err(status(ErrorCode::ResponseTooLarge));
        }
        Ok(ProveResponse { execution_proof: proof })
    }

    fn prove_witness(&self, witness: ExecutionWitness) -> Result<Vec<u8>, Status> {
        #[cfg(test)]
        if let Some(prove) = &self.test_prover {
            return prove(witness);
        }
        Ok(self.prover.prove_full(witness).map_err(prover_error)?.to_bytes())
    }
}

#[tonic::async_trait]
impl<P: InputPolicy> Rpc for ProvingService<P> {
    #[tracing::instrument(name = "prover_service.prove", skip_all)]
    async fn prove(
        &self,
        request: Request<ProveRequest>,
    ) -> Result<Response<ProveResponse>, Status> {
        let deadline = Instant::now()
            .checked_add(self.config().request_timeout())
            .ok_or_else(|| status(ErrorCode::Internal))?;
        let request = request.into_inner();
        if request.protocol_version != PROTOCOL_VERSION {
            return Err(status(ErrorCode::UnsupportedVersion));
        }
        if request.execution_witness.is_empty() {
            return Err(status(ErrorCode::InvalidWitness));
        }
        if request.execution_witness.len() > self.config().max_witness_bytes() {
            return Err(status(ErrorCode::RequestTooLarge));
        }

        let permit = Arc::clone(&self.state.admission).try_acquire_owned().map_err(|error| {
            status(match error {
                TryAcquireError::Closed => ErrorCode::ShuttingDown,
                TryAcquireError::NoPermits => ErrorCode::QueueFull,
            })
        })?;
        tracing::debug!("proof request admitted");
        // Tokio's mutex serves accepted waiters in FIFO order. Waiting retains
        // serialized bytes; no blocking task or expanded witness exists yet.
        let worker = tokio::select! {
            biased;
            _ = self.state.shutdown.cancelled() => return Err(status(ErrorCode::ShuttingDown)),
            _ = sleep_until(deadline) => return Err(status(ErrorCode::DeadlineExceeded)),
            guard = Arc::clone(&self.state.worker).lock_owned() => guard,
        };
        let task = {
            let _dispatch = self.state.dispatch.lock().expect("dispatch lock poisoned");
            if self.state.shutdown.is_cancelled() {
                return Err(status(ErrorCode::ShuttingDown));
            }
            if Instant::now() >= deadline {
                return Err(status(ErrorCode::DeadlineExceeded));
            }
            let state = Arc::clone(&self.state);
            let span = tracing::Span::current();
            self.state.tasks.spawn_blocking(move || {
                // These guards belong to the actual blocking operation, even
                // after the RPC future drops or times out. Unwinding drops them.
                let _worker = worker;
                let _permit = permit;
                span.in_scope(|| {
                    tracing::debug!("proof job started");
                    let result = state.prove::<P>(&request.execution_witness);
                    tracing::debug!("proof job finished");
                    result
                })
            })
        };
        let result = timeout_at(deadline, task)
            .await
            .map_err(|_| status(ErrorCode::DeadlineExceeded))?
            .map_err(|_| status(ErrorCode::Internal))??;
        Ok(Response::new(result))
    }
}

#[cfg(test)]
mod tests;
