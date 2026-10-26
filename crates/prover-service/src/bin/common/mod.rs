use std::{
    collections::BTreeSet,
    env::{self, VarError},
    io,
    net::SocketAddr,
    time::Duration,
};

use clap::Parser;
use miden_core::deferred::{WorkClass, WorkLimit};
use miden_precompiles::{
    CURVE_WORK, HASH_WORK, MSM_WORK, UINT_WORK, default_verification_precompile_limits,
};
use miden_prover_service::{InputPolicy, ProvingService, ServerConfig};
use tracing_subscriber::EnvFilter;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

pub fn exit(result: Result<(), Error>) -> std::process::ExitCode {
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        },
    }
}

#[derive(Parser)]
#[command(
    name = env!("CARGO_BIN_NAME"),
    version,
    about = "Serve complete proofs for serialized Miden VM execution witnesses"
)]
pub struct Options {
    /// Listener address. Restrict the trusted binary to trusted producers.
    #[arg(long, default_value = "127.0.0.1:50051")]
    listen: SocketAddr,

    /// Maximum number of active and queued proof requests.
    #[arg(long, default_value_t = 1)]
    capacity: usize,

    /// Maximum serialized witness bytes, excluding protobuf framing.
    #[arg(long)]
    max_witness_bytes: usize,

    /// Maximum serialized proof bytes, excluding protobuf framing.
    #[arg(long)]
    max_proof_bytes: usize,

    /// RPC deadline and shutdown network grace period in milliseconds.
    #[arg(long)]
    request_timeout_ms: u64,

    /// Modeled VM prover memory budget in bytes.
    #[arg(long)]
    vm_memory_bytes: u64,

    /// Precompile prover memory budget in bytes.
    #[arg(long)]
    precompile_memory_bytes: u64,

    /// Override the canonical precompile structural element limit. Zero denies all elements.
    #[arg(long)]
    precompile_max_elements: Option<u64>,

    /// Override a canonical work class: hash, uint, curve, or msm. Zero denies work.
    #[arg(long, value_name = "CLASS:COUNT:TOTAL_SIZE:ITEM_SIZE", value_parser = parse_work_limit)]
    precompile_work_limit: Vec<(WorkClass, WorkLimit)>,
}

impl Options {
    pub fn config(self) -> Result<ServerConfig, Error> {
        let mut config = ServerConfig::new(
            self.max_witness_bytes,
            self.max_proof_bytes,
            Duration::from_millis(self.request_timeout_ms),
            self.vm_memory_bytes,
            self.precompile_memory_bytes,
        )?
        .with_listen_addr(self.listen)
        .with_capacity(self.capacity)?;

        if self.precompile_max_elements.is_some() || !self.precompile_work_limit.is_empty() {
            let mut limits = default_verification_precompile_limits();
            if let Some(elements) = self.precompile_max_elements {
                limits = limits.with_max_elements(elements);
            }
            let mut seen = BTreeSet::new();
            for (class, limit) in self.precompile_work_limit {
                if !seen.insert(class) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("duplicate precompile work class: {class}"),
                    )
                    .into());
                }
                limits = limits.with_class(class, limit);
            }
            config = config.with_verification_precompile_limits(limits);
        }
        Ok(config)
    }
}

fn parse_work_limit(value: &str) -> Result<(WorkClass, WorkLimit), String> {
    let mut fields = value.split(':');
    let (Some(class), Some(count), Some(total), Some(size), None) =
        (fields.next(), fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err("expected CLASS:COUNT:TOTAL_SIZE:ITEM_SIZE".into());
    };
    let class = match class {
        "hash" => HASH_WORK,
        "uint" => UINT_WORK,
        "curve" => CURVE_WORK,
        "msm" => MSM_WORK,
        _ => return Err("work class must be hash, uint, curve, or msm".into()),
    };
    let limit = WorkLimit {
        max_count: count.parse().map_err(|_| "COUNT must be a u64")?,
        max_total_size: total.parse().map_err(|_| "TOTAL_SIZE must be a u64")?,
        max_size: size.parse().map_err(|_| "ITEM_SIZE must be a u32")?,
    };
    Ok((class, limit))
}

pub fn init_tracing() -> Result<(), Error> {
    let filter = match env::var("RUST_LOG") {
        Ok(value) => EnvFilter::try_new(value).map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("invalid RUST_LOG: {error}"))
        })?,
        Err(VarError::NotPresent) => EnvFilter::new("info"),
        Err(VarError::NotUnicode(_)) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "RUST_LOG must contain Unicode text",
            )
            .into());
        },
    };
    tracing_subscriber::fmt().with_env_filter(filter).with_target(false).try_init()
}

pub async fn run<P: InputPolicy>(service: ProvingService<P>) -> Result<(), Error> {
    // Install Unix signal handlers before binding the listener.
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    #[cfg(unix)]
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let signal = async {
        #[cfg(unix)]
        {
            tokio::select! {
                received = interrupt.recv() => received.ok_or_else(|| io::Error::other("SIGINT stream closed")),
                received = terminate.recv() => received.ok_or_else(|| io::Error::other("SIGTERM stream closed")),
            }
        }
        #[cfg(not(unix))]
        tokio::signal::ctrl_c().await
    };
    tracing::info!(address = %service.config().listen_addr(), capacity = service.config().capacity().get(), "starting listener");
    let serving = service.clone().serve();
    tokio::pin!(serving);
    tokio::select! {
        result = &mut serving => result?,
        result = signal => {
            tracing::info!("shutdown requested; waiting for proof work and connections");
            let (_, served) = tokio::join!(service.shutdown(), &mut serving);
            served?;
            result?;
        }
    }
    Ok(())
}
