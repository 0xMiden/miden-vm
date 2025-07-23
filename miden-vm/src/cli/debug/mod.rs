use std::{path::PathBuf, sync::Arc};

use clap::Parser;
use miden_assembly::{DefaultSourceManager, diagnostics::Report};
use miden_vm::internal::InputFile;
use rustyline::{Config, DefaultEditor, EditMode, error::ReadlineError};

use super::data::Libraries;

mod command;
use command::DebugCommand;

mod executor;
use executor::DebugExecutor;

use crate::cli::utils::{get_masm_program, get_masp_program};

#[derive(Debug, Clone, Parser)]
#[command(about = "Debug a miden program")]
pub struct DebugCmd {
    /// Path to a .masm assembly file or a .masp package file
    #[arg(value_parser)]
    pub program_file: PathBuf,

    /// Path to input file
    #[arg(short = 'i', long = "input", value_parser)]
    input_file: Option<PathBuf>,

    /// Enable vi edit mode
    #[arg(long = "vi", long = "vim_edit_mode")]
    vim_edit_mode: Option<String>,

    /// Paths to .masl library files
    #[arg(short = 'l', long = "libraries", value_parser)]
    library_paths: Vec<PathBuf>,
}

impl DebugCmd {
    pub fn execute(&self) -> Result<(), Report> {
        println!("============================================================");
        println!("Debug program");
        println!("============================================================");

        // load libraries from files
        let libraries = Libraries::new(&self.library_paths)?;

        // Determine file type based on extension.
        let ext = self
            .program_file
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        // Use a single match expression to load the program.
        let (program, source_manager) = match ext.as_str() {
            "masp" => {
                (get_masp_program(&self.program_file)?, Arc::new(DefaultSourceManager::default()))
            },
            "masm" => get_masm_program(&self.program_file, &libraries, true)?,
            _ => return Err(Report::msg("The provided file must have a .masm or .masp extension")),
        };
        let program_hash: [u8; 32] = program.hash().into();

        println!("Debugging program with hash {}...", hex::encode(program_hash));

        // load input data from file
        let input_data = InputFile::read(&self.input_file, &self.program_file)?;

        // fetch the stack and program inputs from the arguments
        let stack_inputs = input_data.parse_stack_inputs().map_err(Report::msg)?;
        let advice_inputs = input_data.parse_advice_inputs().map_err(Report::msg)?;

        // instantiate DebugExecutor
        let mut debug_executor =
            DebugExecutor::new(program, stack_inputs, advice_inputs, source_manager)
                .map_err(Report::msg)?;

        // build readline config
        let mut rl_config = Config::builder().auto_add_history(true);
        if self.vim_edit_mode.is_some() {
            rl_config = rl_config.edit_mode(EditMode::Vi);
        }
        let rl_config = rl_config.build();

        // initialize readline
        let mut rl =
            DefaultEditor::with_config(rl_config).expect("Readline couldn't be initialized");

        println!("Welcome! Enter `h` for help.");

        loop {
            match rl.readline(">> ") {
                Ok(command) => match DebugCommand::parse(&command) {
                    Ok(Some(command)) => {
                        if !debug_executor.execute(command) {
                            println!("Debugging complete");
                            break;
                        }
                    },
                    Ok(None) => (),
                    Err(err) => eprintln!("{err}"),
                },
                Err(ReadlineError::Interrupted) => {
                    // ctrl+c is a transparent interruption and should provide not feedback or
                    // action.
                },
                Err(ReadlineError::Eof) => {
                    eprintln!("CTRL-D");
                    break;
                },
                Err(err) => eprintln!("malformed command - failed to read user input: {err}"),
            }
        }

        Ok(())
    }
}
