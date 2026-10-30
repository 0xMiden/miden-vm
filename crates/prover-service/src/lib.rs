//! Typed gRPC handlers for remote Miden VM execution-witness proving.
//!
//! Trust belongs to the service type. Ordinary construction selects [`Untrusted`],
//! and [`Trusted`] requires the explicitly named constructor.

use std::{fmt, marker::PhantomData, sync::Arc};

mod config;
mod failure;
mod service;
mod transport;

pub use config::{ConfigError, ServerConfig};
use service::State;
pub use transport::ServerError;

/// Generated client and server bindings for the versioned proving protocol.
// Tonic deliberately qualifies prelude types in its generated bindings.
#[allow(unused_qualifications)]
pub mod protocol {
    tonic::include_proto!("miden.prover.v1");
}

/// The request protocol version accepted by this service.
pub const PROTOCOL_VERSION: u32 = 1;

mod sealed {
    use miden_core::serde::DeserializationError;
    use miden_processor::ExecutionWitness;

    pub trait Sealed {
        fn read(bytes: &[u8]) -> Result<ExecutionWitness, DeserializationError>;
    }
}

/// A service input policy implemented only by [`Untrusted`] and [`Trusted`].
pub trait InputPolicy: sealed::Sealed + Send + Sync + 'static {}

/// A service that uses the bounded reader for externally supplied witness bytes.
#[derive(Clone, Copy, Debug, Default)]
pub struct Untrusted;

/// A service that accepts witness bytes retained inside a trusted proving system.
#[derive(Clone, Copy, Debug, Default)]
pub struct Trusted;

impl sealed::Sealed for Untrusted {
    fn read(
        bytes: &[u8],
    ) -> Result<miden_processor::ExecutionWitness, miden_core::serde::DeserializationError> {
        miden_processor::ExecutionWitness::read_from_bytes(bytes)
    }
}
impl sealed::Sealed for Trusted {
    fn read(
        bytes: &[u8],
    ) -> Result<miden_processor::ExecutionWitness, miden_core::serde::DeserializationError> {
        miden_processor::ExecutionWitness::read_from_bytes_trusted(bytes)
    }
}
impl InputPolicy for Untrusted {}
impl InputPolicy for Trusted {}

/// A proving service whose input policy is fixed by its type.
///
/// Each instance owns immutable resource configuration. Cloning an instance retains
/// its input policy and shares its worker, admission capacity, and shutdown state.
pub struct ProvingService<P: InputPolicy = Untrusted> {
    state: Arc<State>,
    policy: PhantomData<P>,
}

impl<P: InputPolicy> Clone for ProvingService<P> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            policy: PhantomData,
        }
    }
}

impl ProvingService<Untrusted> {
    /// Creates the default service for externally supplied witness bytes.
    pub fn new(config: ServerConfig) -> Self {
        Self {
            state: Arc::new(State::new(config)),
            policy: PhantomData,
        }
    }
}

impl ProvingService<Trusted> {
    /// Creates a service for witness bytes from trusted producers.
    pub fn new_trusted(config: ServerConfig) -> Self {
        Self {
            state: Arc::new(State::new(config)),
            policy: PhantomData,
        }
    }
}

impl<P: InputPolicy> ProvingService<P> {
    /// Returns the resource settings shared by this instance and its clones.
    pub fn config(&self) -> &ServerConfig {
        &self.state.config
    }

    /// Stops admission and queued jobs, then waits for any running proof to exit.
    ///
    /// Synchronous proving cannot be interrupted. A disconnected or timed-out job
    /// retains its worker and admission slot until the blocking operation exits.
    ///
    /// # Cancel safety
    ///
    /// Shutdown is requested when this future is first polled. Dropping it before
    /// then has no effect. Once polled, admission remains closed and queued jobs
    /// remain cancelled even if this future is dropped. Active proof jobs continue.
    /// Call `shutdown().await` again on this instance or a clone to finish joining
    /// them. Also retain and await the serving future to finish graceful health
    /// and connection cleanup.
    pub async fn shutdown(&self) {
        self.state.begin_shutdown();
        self.state.tasks.wait().await;
    }
}

impl<P: InputPolicy> fmt::Debug for ProvingService<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvingService")
            .field("config", self.config())
            .finish_non_exhaustive()
    }
}
