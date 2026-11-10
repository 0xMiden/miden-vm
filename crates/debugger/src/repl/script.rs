use std::{boxed::Box, io::Write, path::Path};

use miden_assembly_syntax::diagnostics::Report;

use super::engine::Outcome;
use crate::{config::DebuggerConfig, script::ScriptDebugger};

/// Run a script of debugger commands non-interactively, then return.
///
/// This is the batch / "source a command file" mode, analogous to
/// `gdb -x <file> -batch` or `lldb -s <file>`. The program to debug is loaded
/// from `config` exactly as for an interactive session.
///
/// Each line of the file is one REPL command, using the same syntax as the
/// interactive prompt. Blank lines and lines beginning with `#` are ignored, so
/// scripts can be commented — and a script can double as a lit/FileCheck test
/// input, where the `# RUN:` and `# CHECK:` lines are skipped here and consumed
/// by the test runner instead. A `quit` command, or end of file, ends the run.
///
/// Command output goes to stdout; command/parse errors go to stderr and do not
/// abort the script.
pub fn run_commands(config: Box<DebuggerConfig>, script_path: &Path) -> Result<(), Report> {
    let script = std::fs::read_to_string(script_path).map_err(|e| {
        Report::msg(format!("failed to read command file {}: {e}", script_path.display()))
    })?;

    #[cfg(feature = "python")]
    let python_init_file = super::python::project_init_file(&config);
    let debugger = ScriptDebugger::from_config(config)?;
    #[cfg(feature = "python")]
    let mut python = {
        let python = crate::script::PythonScriptSession::new(debugger.clone())
            .map_err(|e| Report::msg(format!("failed to initialize Python scripting: {e}")))?;
        if let Some(path) = python_init_file {
            python.import_file(&path).map_err(|e| {
                Report::msg(format!("failed to load Python init file {}: {e}", path.display()))
            })?;
        }
        python
    };
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    #[cfg(feature = "python")]
    run_lines(&debugger, Some(&mut python), &script, &mut out);
    #[cfg(not(feature = "python"))]
    run_lines(&debugger, &script, &mut out);
    Ok(())
}

#[cfg(feature = "python")]
fn run_lines(
    debugger: &ScriptDebugger,
    mut python: Option<&mut crate::script::PythonScriptSession>,
    script: &str,
    out: &mut dyn Write,
) {
    for line in script.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let outcome = match python.as_deref_mut() {
            Some(python) => super::python::execute_line(debugger, python, line, out),
            None => debugger.execute_repl_line(line, out),
        };

        match outcome {
            Ok(Outcome::Quit) => break,
            Ok(Outcome::Continue) => {}
            Err(e) => eprintln!("error: {e}"),
        }
    }
}

#[cfg(not(feature = "python"))]
fn run_lines(debugger: &ScriptDebugger, script: &str, out: &mut dyn Write) {
    for line in script.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        match debugger.execute_repl_line(line, out) {
            Ok(Outcome::Quit) => break,
            Ok(Outcome::Continue) => {}
            Err(e) => eprintln!("error: {e}"),
        }
    }
}

#[cfg(test)]
mod tests;
