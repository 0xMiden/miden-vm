use std::{string::ToString, vec::Vec};

use super::*;
use crate::program_loader::test_package_input;

#[test]
fn command_files_skip_comments_continue_after_errors_and_stop_at_quit() {
    let debugger = ScriptDebugger::new(Box::new(DebuggerConfig {
        input: Some(test_package_input()),
        ..Default::default()
    }))
    .unwrap();
    let mut output = Vec::new();
    let commands = "\n # comment\nunknown-command\nstack\nquit\nhelp\n";
    #[cfg(feature = "python")]
    run_lines(&debugger, None, commands, &mut output);
    #[cfg(not(feature = "python"))]
    run_lines(&debugger, commands, &mut output);
    let output = std::string::String::from_utf8(output).unwrap();
    assert_eq!(output.trim(), "Stack is empty");
    let path = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(path.path(), "# comment\nquit\n").unwrap();
    run_commands(
        Box::new(DebuggerConfig {
            input: Some(test_package_input()),
            ..Default::default()
        }),
        path.path(),
    )
    .unwrap();
    let missing = path.path().with_extension("missing");
    assert!(
        run_commands(Box::default(), &missing)
            .unwrap_err()
            .to_string()
            .contains("failed to read command file")
    );
}
