use std::{
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    time::{Duration, Instant},
};

use miden_core::deferred::PrecompileLimits;
use tokio::sync::Semaphore;

// The version field takes at most six bytes and the bytes field another six.
const REQUEST_ENVELOPE_BYTES: usize = 12;
const RESPONSE_ENVELOPE_BYTES: usize = 6;

/// Resource settings for either service input policy.
///
/// Message limits apply to the serialized witness and proof. The service adds
/// protobuf-envelope space when configuring its transport limits.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    listen_addr: SocketAddr,
    capacity: NonZeroUsize,
    max_witness_bytes: usize,
    max_proof_bytes: usize,
    request_timeout: Duration,
    vm_memory_bytes: u64,
    precompile_memory_bytes: u64,
    verification_precompile_limits: Option<PrecompileLimits>,
}

impl ServerConfig {
    /// Creates resource settings with a capacity of one and a loopback listener.
    ///
    /// Every supplied limit must be nonzero. Witness and proof limits must leave
    /// room for protobuf framing inside gRPC's 32-bit message length.
    pub fn new(
        max_witness_bytes: usize,
        max_proof_bytes: usize,
        request_timeout: Duration,
        vm_memory_bytes: u64,
        precompile_memory_bytes: u64,
    ) -> Result<Self, ConfigError> {
        message_limit(max_witness_bytes, REQUEST_ENVELOPE_BYTES, "max_witness_bytes")?;
        message_limit(max_proof_bytes, RESPONSE_ENVELOPE_BYTES, "max_proof_bytes")?;
        if request_timeout.is_zero() {
            return Err(ConfigError::ZeroLimit("request_timeout"));
        }
        if Instant::now().checked_add(request_timeout).is_none() {
            return Err(ConfigError::TimeoutTooLarge(request_timeout));
        }
        if vm_memory_bytes == 0 {
            return Err(ConfigError::ZeroLimit("vm_memory_bytes"));
        }
        if precompile_memory_bytes == 0 {
            return Err(ConfigError::ZeroLimit("precompile_memory_bytes"));
        }

        Ok(Self {
            listen_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 50051)),
            capacity: NonZeroUsize::MIN,
            max_witness_bytes,
            max_proof_bytes,
            request_timeout,
            vm_memory_bytes,
            precompile_memory_bytes,
            verification_precompile_limits: None,
        })
    }

    /// Sets the address used when the service binds its listener.
    #[must_use]
    pub const fn with_listen_addr(mut self, listen_addr: SocketAddr) -> Self {
        self.listen_addr = listen_addr;
        self
    }

    /// Sets the maximum number of active and queued requests for this instance.
    pub fn with_capacity(mut self, capacity: usize) -> Result<Self, ConfigError> {
        let capacity = NonZeroUsize::new(capacity).ok_or(ConfigError::ZeroLimit("capacity"))?;
        if capacity.get() > Semaphore::MAX_PERMITS {
            return Err(ConfigError::CapacityTooLarge {
                capacity: capacity.get(),
                maximum: Semaphore::MAX_PERMITS,
            });
        }
        self.capacity = capacity;
        Ok(self)
    }

    /// Replaces the prover's default precompile verification-work policy.
    #[must_use]
    pub fn with_verification_precompile_limits(mut self, limits: PrecompileLimits) -> Self {
        self.verification_precompile_limits = Some(limits);
        self
    }

    /// Returns the address to bind when no listener is supplied by the caller.
    pub const fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Returns the maximum number of active and queued requests.
    pub const fn capacity(&self) -> NonZeroUsize {
        self.capacity
    }

    /// Returns the serialized witness byte limit, excluding its protobuf envelope.
    pub const fn max_witness_bytes(&self) -> usize {
        self.max_witness_bytes
    }

    /// Returns the serialized proof byte limit, excluding its protobuf envelope.
    pub const fn max_proof_bytes(&self) -> usize {
        self.max_proof_bytes
    }

    /// Returns the transport request limit, including its protobuf envelope.
    pub const fn request_message_limit(&self) -> usize {
        self.max_witness_bytes + REQUEST_ENVELOPE_BYTES
    }

    /// Returns the transport response limit, including its protobuf envelope.
    pub const fn response_message_limit(&self) -> usize {
        self.max_proof_bytes + RESPONSE_ENVELOPE_BYTES
    }

    /// Returns the request timeout and the network grace period on shutdown.
    pub const fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// Returns the modeled VM prover-memory budget in bytes.
    pub const fn vm_memory_bytes(&self) -> u64 {
        self.vm_memory_bytes
    }

    /// Returns the precompile prover-memory budget in bytes.
    pub const fn precompile_memory_bytes(&self) -> u64 {
        self.precompile_memory_bytes
    }

    /// Returns an explicit precompile policy, or `None` to retain the prover default.
    pub const fn verification_precompile_limits(&self) -> Option<&PrecompileLimits> {
        self.verification_precompile_limits.as_ref()
    }
}

fn message_limit(bytes: usize, envelope: usize, name: &'static str) -> Result<usize, ConfigError> {
    if bytes == 0 {
        return Err(ConfigError::ZeroLimit(name));
    }
    bytes.checked_add(envelope).filter(|&limit| u32::try_from(limit).is_ok()).ok_or(
        ConfigError::MessageTooLarge {
            name,
            bytes,
            maximum: u32::MAX as usize - envelope,
        },
    )
}

/// Invalid service resource configuration.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("{0} must be nonzero")]
    ZeroLimit(&'static str),
    #[error("{name} is {bytes} bytes, maximum is {maximum} bytes including room for framing")]
    MessageTooLarge {
        name: &'static str,
        bytes: usize,
        maximum: usize,
    },
    #[error("capacity is {capacity}, maximum is {maximum}")]
    CapacityTooLarge { capacity: usize, maximum: usize },
    #[error("request_timeout of {0:?} cannot be represented as a deadline")]
    TimeoutTooLarge(Duration),
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::*;
    use crate::protocol::{ProveRequest, ProveResponse};

    fn config() -> ServerConfig {
        ServerConfig::new(1024, 2048, Duration::from_secs(60), 4096, 8192).unwrap()
    }

    #[test]
    fn generated_messages_fit_the_configured_transport_bounds() {
        for length in [1, 127, 128, 16_383, 16_384] {
            let config = ServerConfig::new(length, length, Duration::from_secs(1), 1, 1).unwrap();
            let request = ProveRequest {
                protocol_version: u32::MAX,
                execution_witness: vec![0; length],
            };
            let response = ProveResponse { execution_proof: vec![0; length] };
            assert!(request.encoded_len() <= config.request_message_limit());
            assert!(response.encoded_len() <= config.response_message_limit());
        }
    }

    #[test]
    fn rejects_zero_resource_limits() {
        let valid = (1024, 2048, Duration::from_secs(60), 4096, 8192);
        for (witness, proof, timeout, vm, precompile, name) in [
            (0, valid.1, valid.2, valid.3, valid.4, "max_witness_bytes"),
            (valid.0, 0, valid.2, valid.3, valid.4, "max_proof_bytes"),
            (valid.0, valid.1, Duration::ZERO, valid.3, valid.4, "request_timeout"),
            (valid.0, valid.1, valid.2, 0, valid.4, "vm_memory_bytes"),
            (valid.0, valid.1, valid.2, valid.3, 0, "precompile_memory_bytes"),
        ] {
            assert_eq!(
                ServerConfig::new(witness, proof, timeout, vm, precompile).unwrap_err(),
                ConfigError::ZeroLimit(name)
            );
        }
    }

    #[test]
    fn message_limits_respect_the_grpc_length_boundary() {
        let maximum = u32::MAX as usize;
        assert!(
            ServerConfig::new(
                maximum - REQUEST_ENVELOPE_BYTES,
                maximum - RESPONSE_ENVELOPE_BYTES,
                Duration::from_secs(1),
                1,
                1,
            )
            .is_ok()
        );
        assert_eq!(
            ServerConfig::new(
                maximum - REQUEST_ENVELOPE_BYTES + 1,
                1,
                Duration::from_secs(1),
                1,
                1
            )
            .unwrap_err(),
            ConfigError::MessageTooLarge {
                name: "max_witness_bytes",
                bytes: maximum - REQUEST_ENVELOPE_BYTES + 1,
                maximum: maximum - REQUEST_ENVELOPE_BYTES,
            }
        );
        assert_eq!(
            ServerConfig::new(1, usize::MAX, Duration::from_secs(1), 1, 1).unwrap_err(),
            ConfigError::MessageTooLarge {
                name: "max_proof_bytes",
                bytes: usize::MAX,
                maximum: maximum - RESPONSE_ENVELOPE_BYTES,
            }
        );
    }

    #[test]
    fn capacity_fits_the_runtime_semaphore() {
        assert_eq!(config().capacity().get(), 1);
        assert_eq!(config().with_capacity(0).unwrap_err(), ConfigError::ZeroLimit("capacity"));
        assert_eq!(
            config().with_capacity(Semaphore::MAX_PERMITS + 1).unwrap_err(),
            ConfigError::CapacityTooLarge {
                capacity: Semaphore::MAX_PERMITS + 1,
                maximum: Semaphore::MAX_PERMITS,
            }
        );
        assert_eq!(config().with_capacity(3).unwrap().capacity().get(), 3);
    }

    #[test]
    fn timeout_fits_the_clock() {
        assert_eq!(
            ServerConfig::new(1, 1, Duration::MAX, 1, 1).unwrap_err(),
            ConfigError::TimeoutTooLarge(Duration::MAX)
        );
    }
}
