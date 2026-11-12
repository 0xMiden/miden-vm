use clap::Parser;
use miden_prover_service::{ProvingService, Trusted};

mod common;

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    common::exit(start().await)
}

async fn start() -> Result<(), common::Error> {
    let config = common::Options::parse().config()?;
    common::init_tracing()?;
    tracing::info!("starting trusted-input proving service");
    common::run(ProvingService::<Trusted>::new_trusted(config)).await
}
