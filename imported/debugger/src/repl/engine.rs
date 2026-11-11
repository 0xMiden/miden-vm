use std::{
    boxed::Box,
    io::Write,
    string::{String, ToString},
};

use miden_assembly_syntax::diagnostics::Report;

use super::commands::ReplCommand;
use crate::{config::DebuggerConfig, debug::BreakpointType, ui::state::State};

/// The result of executing a single REPL line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Continue reading commands.
    Continue,
    /// The user requested to quit the session.
    Quit,
}

/// The core debugger REPL logic, decoupled from any particular I/O frontend.
///
/// Command output is written to a caller-provided [`Write`] sink rather than
/// directly to stdout. This lets the same command set drive both the
/// interactive session (writing to stdout, see [`super::session::ReplSession`])
/// and the scriptable test harness (writing to an in-memory buffer, see
/// [`super::script::run_script`]).
pub struct ReplEngine {
    state: State,
}

impl ReplEngine {
    /// Create an engine from a debugger configuration (loads a program package).
    pub fn new(config: Box<DebuggerConfig>) -> Result<Self, Report> {
        Ok(Self {
            state: State::new(config)?,
        })
    }

    /// Create an engine from a debugger configuration.
    pub fn from_config(config: Box<DebuggerConfig>) -> Result<Self, Report> {
        Self::new(config)
    }

    /// Borrow the current debugger state.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Mutably borrow the current debugger state.
    pub fn state_mut(&mut self) -> &mut State {
        &mut self.state
    }

    /// Render the prompt for the current execution state.
    ///
    /// When `color` is true, ANSI escape codes are emitted (for interactive
    /// use). When false, the prompt is plain text, which keeps scripted
    /// transcripts stable and matchable.
    #[cfg(feature = "repl")]
    pub fn make_prompt(&self, color: bool) -> String {
        let cycle = self.state.executor().cycle;

        let (status, fg) = if self.state.executor().stopped {
            if self.state.execution_failed().is_some() {
                ("ERR", "1;31")
            } else {
                ("END", "1;32")
            }
        } else if self.state.stopped {
            ("STOP", "1;33")
        } else {
            ("", "")
        };

        if !color {
            return if status.is_empty() {
                format!("[cycle {cycle}] > ")
            } else {
                format!("[cycle {cycle} {status}] > ")
            };
        }

        if status.is_empty() {
            format!("\x1b[36m[\x1b[0mcycle {cycle}\x1b[36m]\x1b[0m > ")
        } else {
            format!("\x1b[36m[\x1b[0mcycle {cycle} \x1b[{fg}m{status}\x1b[0m\x1b[36m]\x1b[0m > ")
        }
    }

    /// Print the current source location / procedure to `out`.
    pub fn print_location(&self, out: &mut dyn Write) {
        let frames = self.state.executor().callstack.logical_frames("");
        if let Some(frame) = frames.iter().rev().nth(self.state.selected_stack_frame()) {
            let name = frame.display_name();
            if let Some(resolved) = frame.resolved(&*self.state.source_manager) {
                let _ = writeln!(out, "at {} in {}", resolved, name);
            } else {
                let _ = writeln!(out, "in {}", name);
            }
        }
    }

    /// Parse and execute a single command line, writing any output to `out`.
    ///
    /// Returns [`Outcome::Quit`] when the user asked to exit. Parse errors and
    /// command errors are returned as `Err` for the caller to surface.
    pub fn execute_line(&mut self, line: &str, out: &mut dyn Write) -> Result<Outcome, String> {
        let cmd = line.parse::<ReplCommand>()?;
        if matches!(cmd, ReplCommand::Quit) {
            return Ok(Outcome::Quit);
        }
        self.execute_command(cmd, out)?;
        Ok(Outcome::Continue)
    }

    fn execute_command(&mut self, cmd: ReplCommand, out: &mut dyn Write) -> Result<(), String> {
        match cmd {
            ReplCommand::Step => self.cmd_step(1, out),
            ReplCommand::StepN(n) => self.cmd_step(n, out),
            ReplCommand::Next => self.cmd_next(out),
            ReplCommand::NextLine => self.cmd_next_line(out),
            ReplCommand::Continue => self.cmd_continue(out),
            ReplCommand::Finish => self.cmd_finish(out),
            ReplCommand::Break(bp_type) => self.cmd_break(bp_type, out),
            ReplCommand::Breakpoints => self.cmd_breakpoints(out),
            ReplCommand::Delete(id) => self.cmd_delete(id, out),
            ReplCommand::Stack => self.cmd_stack(out),
            ReplCommand::Memory(expr) => self.cmd_memory(&expr, out),
            ReplCommand::Locals => self.cmd_locals(out),
            ReplCommand::Vars(show_all) => self.cmd_vars(show_all, out),
            ReplCommand::Where => self.cmd_where(out),
            ReplCommand::List => self.cmd_list(out),
            ReplCommand::Backtrace => self.cmd_backtrace(out),
            ReplCommand::Frame(index) => self.cmd_frame(index, out),
            ReplCommand::Reload => self.cmd_reload(out),
            ReplCommand::Help => self.cmd_help(out),
            ReplCommand::Quit => unreachable!("quit handled in execute_line"),
        }
    }

    fn cmd_step(&mut self, n: usize, out: &mut dyn Write) -> Result<(), String> {
        if self.state.executor().stopped {
            return Err("program has terminated, cannot step".into());
        }

        for _ in 0..n {
            if self.state.executor().stopped {
                break;
            }
            match self.state.executor_mut().step() {
                Ok(_) => {}
                Err(err) => {
                    self.state.set_execution_failed(err);
                    break;
                }
            }
        }

        self.state.reset_stack_selection();
        self.report_execution_state(out);
        Ok(())
    }

    fn cmd_next(&mut self, out: &mut dyn Write) -> Result<(), String> {
        self.cmd_resume_with_breakpoint(BreakpointType::Next, out)
    }

    fn cmd_next_line(&mut self, out: &mut dyn Write) -> Result<(), String> {
        self.cmd_resume_with_breakpoint(BreakpointType::NextLine, out)
    }

    fn cmd_continue(&mut self, out: &mut dyn Write) -> Result<(), String> {
        self.ensure_can_continue()?;

        self.state.run_until_stopped();
        self.state.reset_stack_selection();

        self.report_execution_state(out);

        Ok(())
    }

    fn cmd_finish(&mut self, out: &mut dyn Write) -> Result<(), String> {
        self.cmd_resume_with_breakpoint(BreakpointType::Finish, out)
    }

    fn cmd_resume_with_breakpoint(
        &mut self,
        bp_type: BreakpointType,
        out: &mut dyn Write,
    ) -> Result<(), String> {
        self.ensure_can_continue()?;

        self.state.create_breakpoint(bp_type);
        self.state.run_until_stopped();
        self.state.reset_stack_selection();
        self.report_execution_state(out);
        Ok(())
    }

    fn report_execution_state(&self, out: &mut dyn Write) {
        if !self.state.executor().stopped {
            self.print_location(out);
            return;
        }

        if let Some(err) = self.state.execution_failed() {
            let _ = writeln!(out, "Program terminated with error: {}", err);
            return;
        }

        let _ = writeln!(out, "Program terminated successfully");
        match self.state.typed_result() {
            Ok(Some(result)) => {
                let _ = writeln!(out, "Result: {result}");
            }
            Ok(None) => {}
            Err(err) => {
                let _ = writeln!(out, "Result unavailable: {err}");
            }
        }
    }

    fn ensure_can_continue(&self) -> Result<(), String> {
        if self.state.executor().stopped {
            return Err("program has terminated, cannot continue".into());
        }

        Ok(())
    }

    fn cmd_break(&mut self, bp_type: BreakpointType, out: &mut dyn Write) -> Result<(), String> {
        self.state.create_breakpoint(bp_type.clone());
        let id = self.state.breakpoints.last().map(|bp| bp.id).unwrap_or(0);
        let _ = writeln!(out, "Breakpoint {} set: {}", id, format_bp_type(&bp_type));
        Ok(())
    }

    fn cmd_breakpoints(&mut self, out: &mut dyn Write) -> Result<(), String> {
        if self.state.breakpoints.is_empty() {
            let _ = writeln!(out, "No breakpoints set");
            return Ok(());
        }

        let _ = writeln!(out, "Breakpoints:");
        for bp in &self.state.breakpoints {
            if !bp.is_internal() {
                let _ = writeln!(out, "  [{}] {}", bp.id, format_bp_type(&bp.ty));
            }
        }
        Ok(())
    }

    fn cmd_delete(&mut self, id: Option<u8>, out: &mut dyn Write) -> Result<(), String> {
        match id {
            Some(id) => {
                let count_before = self.state.breakpoints.len();
                self.state.breakpoints.retain(|bp| bp.id != id);
                if self.state.breakpoints.len() < count_before {
                    let _ = writeln!(out, "Deleted breakpoint {}", id);
                } else {
                    return Err(format!("no breakpoint with id {}", id));
                }
            }
            None => {
                // Delete only user-created (non-internal) breakpoints
                self.state.breakpoints.retain(|bp| bp.is_internal());
                let _ = writeln!(out, "Deleted all breakpoints");
            }
        }
        Ok(())
    }

    fn cmd_stack(&mut self, out: &mut dyn Write) -> Result<(), String> {
        let stack = &self.state.executor().current_stack;

        if stack.is_empty() {
            let _ = writeln!(out, "Stack is empty");
            return Ok(());
        }

        let _ = writeln!(out, "Operand Stack ({} elements):", stack.len());
        for (i, elem) in stack.iter().enumerate() {
            let val = elem.as_canonical_u64();
            let marker = if i == 0 { ">" } else { " " };
            let _ = writeln!(out, "  {} [{}] {} (0x{:x})", marker, i, val, val);
        }
        Ok(())
    }

    fn cmd_memory(
        &mut self,
        expr: &crate::debug::ReadMemoryExpr,
        out: &mut dyn Write,
    ) -> Result<(), String> {
        let result = self.state.read_memory(expr)?;
        let _ = writeln!(out, "{}", result);
        Ok(())
    }

    fn cmd_locals(&mut self, out: &mut dyn Write) -> Result<(), String> {
        let output = self.state.format_variables(false);
        let _ = writeln!(out, "{}", output);
        Ok(())
    }

    fn cmd_vars(&mut self, show_all: bool, out: &mut dyn Write) -> Result<(), String> {
        let output = self.state.format_variables(show_all);
        let _ = writeln!(out, "{}", output);
        Ok(())
    }

    fn cmd_where(&mut self, out: &mut dyn Write) -> Result<(), String> {
        let frames = self.state.executor().callstack.logical_frames("");
        if let Some(frame) = frames.iter().rev().nth(self.state.selected_stack_frame()) {
            let name = frame.display_name();
            if let Some(resolved) = frame.resolved(&*self.state.source_manager) {
                let _ = writeln!(
                    out,
                    "{}:{}:{} in {}",
                    resolved.source_file.uri().as_str(),
                    resolved.line,
                    resolved.col,
                    name
                );
            } else {
                let _ = writeln!(out, "in {} (no source location available)", name);
            }
        } else {
            let _ = writeln!(out, "No current frame");
        }
        Ok(())
    }

    fn cmd_list(&mut self, out: &mut dyn Write) -> Result<(), String> {
        if let Some(frame) = self.state.executor().callstack.current_frame() {
            let recent = frame.recent();
            if recent.is_empty() {
                let _ = writeln!(out, "No recent instructions");
                return Ok(());
            }

            let _ = writeln!(out, "Recent instructions:");
            for (i, op) in recent.iter().enumerate() {
                let marker = if i == recent.len() - 1 { ">" } else { " " };
                let _ = writeln!(out, "  {} {}", marker, op.display());
            }
        } else {
            let _ = writeln!(out, "No current frame");
        }
        Ok(())
    }

    fn cmd_backtrace(&mut self, out: &mut dyn Write) -> Result<(), String> {
        let frames = self.state.executor().callstack.logical_frames("");
        if frames.is_empty() {
            let _ = writeln!(out, "No call stack");
            return Ok(());
        }

        let _ = writeln!(out, "Backtrace ({} frames):", frames.len());
        for (i, frame) in frames.iter().rev().enumerate() {
            let loc_str = frame
                .resolved(&*self.state.source_manager)
                .map(|r| format!(" at {}", r))
                .unwrap_or_default();
            let marker = if i == self.state.selected_stack_frame() {
                "*"
            } else {
                " "
            };

            let _ = writeln!(out, "{} #{} {}{}", marker, i, frame.display_name(), loc_str);
        }
        Ok(())
    }

    fn cmd_frame(&mut self, index: usize, out: &mut dyn Write) -> Result<(), String> {
        self.state.select_stack_frame(index)?;
        self.print_location(out);
        Ok(())
    }

    fn cmd_reload(&mut self, out: &mut dyn Write) -> Result<(), String> {
        self.state.reload().map_err(|e| format!("reload failed: {e}"))?;
        self.state.reset_stack_selection();
        let _ = writeln!(out, "Program reloaded");
        self.report_execution_state(out);
        Ok(())
    }

    fn cmd_help(&mut self, out: &mut dyn Write) -> Result<(), String> {
        let _ = writeln!(out, "{}", ReplCommand::help_text());
        Ok(())
    }
}

pub(crate) fn format_bp_type(ty: &BreakpointType) -> String {
    match ty {
        BreakpointType::Step => "next cycle".into(),
        BreakpointType::StepN(n) => format!("after {} cycles", n),
        BreakpointType::StepTo(c) => format!("at cycle {}", c),
        BreakpointType::Next => "next instruction".into(),
        BreakpointType::NextLine => "next source line".into(),
        BreakpointType::Finish => "function return".into(),
        BreakpointType::File(pattern) => pattern.glob().to_string(),
        BreakpointType::Line { pattern, line } => format!("{}:{}", pattern.glob(), line),
        BreakpointType::Opcode(matcher) => format!("opcode {matcher}"),
        BreakpointType::Called(pat) => format!("call {}", pat.glob()),
        BreakpointType::Event(event) => format!("event {event:?}"),
    }
}

#[cfg(all(test, feature = "repl"))]
mod tests;
