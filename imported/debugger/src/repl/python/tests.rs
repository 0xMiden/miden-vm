use super::*;

fn test_debugger() -> ScriptDebugger {
    crate::script::test_debugger()
}

#[test]
fn parses_script_commands_only() {
    assert!(matches!(
        parse_script_command("script"),
        Some(ScriptCommand::InteractiveConsole)
    ));
    assert!(matches!(
        parse_script_command("script 1 + 1"),
        Some(ScriptCommand::Snippet("1 + 1"))
    ));
    assert!(matches!(
        parse_script_command("command script import /tmp/demo.py"),
        Some(ScriptCommand::Import("/tmp/demo.py"))
    ));
    assert!(parse_script_command("scripts").is_none());
    assert!(parse_script_command("step").is_none());
}

#[test]
fn executes_script_snippets_through_repl_route() {
    let _guard = crate::script::python::python_test_lock();
    let debugger = test_debugger();
    let mut python = PythonScriptSession::new(debugger.clone()).unwrap();
    let mut output = Vec::new();

    execute_line(&debugger, &mut python, "script x = 1", &mut output).unwrap();
    execute_line(&debugger, &mut python, "script x + 1", &mut output).unwrap();

    assert_eq!(String::from_utf8(output).unwrap(), "2\n");
}

#[test]
fn imports_script_and_runs_initializer() {
    let _guard = crate::script::python::python_test_lock();
    let debugger = test_debugger();
    let mut python = PythonScriptSession::new(debugger.clone()).unwrap();
    let temp_path = std::env::temp_dir().join(format!(
        "miden-debug-python-import-{}-{}.py",
        std::process::id(),
        0
    ));
    std::fs::write(
        &temp_path,
        r#"
def __miden_init_module(debugger, internal_dict):
    internal_dict["loaded_cycle"] = debugger.get_cycle()
"#,
    )
    .unwrap();

    let mut output = Vec::new();
    execute_line(
        &debugger,
        &mut python,
        &format!("command script import {}", temp_path.display()),
        &mut output,
    )
    .unwrap();
    execute_line(&debugger, &mut python, "script internal_dict['loaded_cycle']", &mut output)
        .unwrap();

    let _ = std::fs::remove_file(&temp_path);
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("Imported Python script:"));
    assert!(output.ends_with("0\n"));
}

#[test]
fn registers_and_executes_custom_python_command() {
    let _guard = crate::script::python::python_test_lock();
    let debugger = test_debugger();
    let mut python = PythonScriptSession::new(debugger.clone()).unwrap();
    let temp_path =
        std::env::temp_dir().join(format!("miden_debug_python_command_{}.py", std::process::id()));
    std::fs::write(
        &temp_path,
        r#"
def cycle(debugger, command, exe_ctx, result, internal_dict):
    print(f"{debugger.get_cycle()}:{command}", file=result)
"#,
    )
    .unwrap();

    let mut output = Vec::new();
    execute_line(
        &debugger,
        &mut python,
        &format!("command script import {}", temp_path.display()),
        &mut output,
    )
    .unwrap();
    execute_line(
        &debugger,
        &mut python,
        &format!(
            "command script add py-cycle -f {}.cycle",
            temp_path.file_stem().unwrap().to_str().unwrap()
        ),
        &mut output,
    )
    .unwrap();
    execute_line(&debugger, &mut python, "py-cycle hello", &mut output).unwrap();
    execute_line(&debugger, &mut python, "command script list", &mut output).unwrap();
    execute_line(&debugger, &mut python, "command script delete py-cycle", &mut output).unwrap();

    let _ = std::fs::remove_file(&temp_path);
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("Added Python command: py-cycle"));
    assert!(output.contains("0:hello\n"));
    assert!(output.contains("Python commands:\n  py-cycle\n"));
    assert!(output.contains("Deleted Python command: py-cycle"));
}

#[test]
fn breakpoint_callback_false_continues_execution() {
    let _guard = crate::script::python::python_test_lock();
    let debugger = test_debugger();
    let mut python = PythonScriptSession::new(debugger.clone()).unwrap();
    let temp_path =
        std::env::temp_dir().join(format!("miden_debug_bp_callback_{}.py", std::process::id()));
    std::fs::write(
        &temp_path,
        r#"
def never_stop(frame, breakpoint, internal_dict):
    internal_dict["called"] = internal_dict.get("called", 0) + 1
    return False
"#,
    )
    .unwrap();

    let mut output = Vec::new();
    execute_line(&debugger, &mut python, "b after 1", &mut output).unwrap();
    execute_line(
        &debugger,
        &mut python,
        &format!("command script import {}", temp_path.display()),
        &mut output,
    )
    .unwrap();
    execute_line(
        &debugger,
        &mut python,
        &format!(
            "breakpoint command add 0 -f {}.never_stop",
            temp_path.file_stem().unwrap().to_str().unwrap()
        ),
        &mut output,
    )
    .unwrap();
    execute_line(&debugger, &mut python, "continue", &mut output).unwrap();
    execute_line(&debugger, &mut python, "script internal_dict['called']", &mut output).unwrap();

    let _ = std::fs::remove_file(&temp_path);
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("Added Python callback for breakpoint 0"), "output:\n{output}");
    assert!(output.contains("Program terminated successfully"), "output:\n{output}");
    assert!(output.ends_with("1\n"), "output:\n{output}");
}
