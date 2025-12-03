use std::path::PathBuf;

use clap::Parser;
use miden_assembly::diagnostics::Report;

use crate::repl::start_repl;

#[derive(Debug, Clone, Parser)]
#[command(about = "Launch the Miden REPL")]
pub struct ReplCmd {
    /// Paths to .masl library files
    #[arg(short = 'l', long = "libraries", value_parser)]
    library_paths: Vec<PathBuf>,

    /// Link in the core library
    #[arg(short = 'c', long = "libcore")]
    use_libcore: bool,
}

impl ReplCmd {
    pub fn execute(&self) -> Result<(), Report> {
        // initiates repl tool.
        start_repl(&self.library_paths, self.use_libcore);
        Ok(())
    }
}
