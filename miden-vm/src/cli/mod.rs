mod bundle;
mod compile;
pub(crate) mod config;
pub mod data;

mod prove;
mod run;
pub mod utils;
mod verify;

pub use bundle::BundleCmd;
pub use compile::CompileCmd;
pub use prove::ProveCmd;
pub use run::RunCmd;
pub use verify::VerifyCmd;

/// Whether precompile work is carried as a witness or proved with a STARK.
pub(crate) enum ProofMode {
    Deferred,
    Complete,
}
