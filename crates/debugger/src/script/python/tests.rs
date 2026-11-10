use super::*;

fn test_debugger() -> ScriptDebugger {
    crate::script::test_debugger()
}

#[test]
fn embedded_module_exposes_debugger_globals() {
    let _guard = python_test_lock();
    let session = PythonScriptSession::new(test_debugger()).unwrap();

    Python::attach(|py| {
        let module = py.import("miden_debugger").unwrap();
        let cycle: usize = module
            .getattr("debugger")
            .unwrap()
            .call_method0("get_cycle")
            .unwrap()
            .extract()
            .unwrap();
        assert_eq!(cycle, 0);

        session
            .with_globals(py, |globals| {
                let debugger = globals.get_item("debugger")?.unwrap();
                let cycle: usize = debugger.call_method0("get_cycle")?.extract()?;
                assert_eq!(cycle, 0);
                Ok(())
            })
            .unwrap();
    });
}

#[test]
fn thread_frames_capture_each_invocations_locals() {
    let _guard = python_test_lock();
    let debugger = crate::script::invocation_debugger();
    let thread = PyThread::new(Rc::new(RefCell::new(debugger.clone())));
    let frames = thread.frames();
    assert_eq!(frames.len(), 3);
    Python::attach(|py| {
        let caller = frames[1].variables(py, Some(true)).unwrap();
        let value: u64 = caller
            .bind(py)
            .get_item("n")
            .unwrap()
            .unwrap()
            .getattr("value")
            .unwrap()
            .extract()
            .unwrap();
        assert_eq!(value, 11);
    });
    debugger.handle_command("frame 1").unwrap();
    assert!(thread.selected_frame().function_name().unwrap().ends_with("::outer"));
    debugger.finish().unwrap();
    // Enumerated frames are snapshots, so they cannot silently retarget after a resume.
    assert!(frames[0].function_name().unwrap().ends_with("::inner"));
}

#[test]
fn python_debugger_can_drive_commands() {
    let _guard = python_test_lock();
    let session = PythonScriptSession::new(test_debugger()).unwrap();

    Python::attach(|py| {
        session
            .with_globals(py, |globals| {
                let debugger = globals.get_item("debugger")?.unwrap();
                let output: String =
                    debugger.call_method1("handle_command", ("step",))?.extract()?;
                assert!(output.contains("in") || output.is_empty());
                let cycle: usize = debugger.call_method0("get_cycle")?.extract()?;
                assert_eq!(cycle, 1);
                Ok(())
            })
            .unwrap();
    });
}

#[test]
fn python_snippets_preserve_globals_and_print_expression_values() {
    let _guard = python_test_lock();
    let session = PythonScriptSession::new(test_debugger()).unwrap();

    assert_eq!(session.execute_snippet("x = 1").unwrap(), "");
    assert_eq!(session.execute_snippet("x + 1").unwrap(), "2\n");
}

pub(crate) fn python_test_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};

    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
