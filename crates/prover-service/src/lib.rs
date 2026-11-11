//! gRPC bindings for remote Miden VM execution-witness proving.
//!
//! The default `server` feature also enables typed proving handlers. Their input
//! policy defaults to `Untrusted`; `Trusted` requires an explicit constructor.

#[cfg(feature = "server")]
mod config;
#[cfg(feature = "server")]
mod failure;
#[cfg(feature = "server")]
mod service;
#[cfg(feature = "server")]
mod transport;

#[cfg(feature = "server")]
pub use config::{ConfigError, ProofMode, ServerConfig};
#[cfg(feature = "server")]
pub use service::{InputPolicy, ProvingService, Trusted, Untrusted};
#[cfg(feature = "server")]
pub use transport::ServerError;

/// Generated bindings for the versioned proving protocol.
// Tonic deliberately qualifies prelude types in its generated bindings.
#[allow(unused_qualifications)]
pub mod protocol {
    tonic::include_proto!("miden.prover.v1");
}

/// The request protocol version accepted by this service.
pub const PROTOCOL_VERSION: u32 = 1;
