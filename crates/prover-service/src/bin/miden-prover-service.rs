use clap::Parser;
use miden_prover_service::ProvingService;

mod common;

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    common::exit(start().await)
}

async fn start() -> Result<(), common::Error> {
    let config = common::Options::parse().config()?;
    common::init_tracing()?;
    tracing::info!("starting untrusted-input proving service");
    common::run(ProvingService::new(config)).await
}
