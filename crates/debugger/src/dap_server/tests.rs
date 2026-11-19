use alloc::string::ToString;
use std::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
    thread,
    time::Duration,
};

use miden_assembly::Assembler;

use super::*;

#[test]
fn standalone_server_runs_with_remote_state_client() {
    let directory = tempfile::tempdir().unwrap();
    let package_path = directory.path().join("standalone.masp");
    let source_manager = Arc::new(DefaultSourceManager::default());
    let package = Assembler::new(source_manager)
        .assemble_program("standalone", "begin push.3 push.4 add add end")
        .unwrap();
    package.write_to_file(&package_path).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let timeout = Duration::from_secs(5);

    let config = Box::new(DebuggerConfig {
        input: Some(crate::InputFile::from_path(&package_path)),
        start_debug_adapter: Some(address.to_string()),
        ..Default::default()
    });
    let (completed, completion) = mpsc::channel();
    let server = thread::spawn(move || {
        completed.send(run_on_listener(config, listener)).unwrap();
    });

    let stream = TcpStream::connect_timeout(&address, timeout).unwrap();
    stream.set_read_timeout(Some(timeout)).unwrap();
    stream.set_write_timeout(Some(timeout)).unwrap();
    let client = crate::exec::DapClient::from_stream(stream).unwrap();
    let mut state = crate::State::from_dap_client(&address.to_string(), client).unwrap();
    assert_eq!(state.debug_mode, crate::DebugMode::Remote);
    assert_eq!(state.executor().cycle, 0);
    assert!(matches!(state.step_remote().unwrap(), crate::exec::DapStopReason::Terminated));
    drop(state);
    completion.recv_timeout(timeout).expect("DAP server did not finish").unwrap();
    server.join().unwrap();
}

#[test]
fn remote_frame_selection_and_return_inspect_the_owning_invocations_locals() {
    use miden_assembly_syntax::ast::types::{ArrayType, Type};

    let directory = tempfile::tempdir().unwrap();
    let package_path = directory.path().join("invocations.masp");
    crate::program_loader::invocation_test_package(Some(Type::Array(Arc::new(ArrayType::new(
        Type::Felt,
        1,
    )))))
    .write_to_file(&package_path)
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let timeout = Duration::from_secs(5);
    let config = Box::new(DebuggerConfig {
        input: Some(crate::InputFile::from_path(&package_path)),
        start_debug_adapter: Some(address.to_string()),
        ..Default::default()
    });
    let (completed, completion) = mpsc::channel();
    let server = thread::spawn(move || {
        completed.send(run_on_listener(config, listener)).unwrap();
    });
    let stream = TcpStream::connect_timeout(&address, timeout).unwrap();
    stream.set_read_timeout(Some(timeout)).unwrap();
    stream.set_write_timeout(Some(timeout)).unwrap();
    let client = crate::exec::DapClient::from_stream(stream).unwrap();
    let mut state = crate::State::from_dap_client(&address.to_string(), client).unwrap();
    for _ in 0..100 {
        state.create_breakpoint(crate::BreakpointType::Step);
        assert!(matches!(state.step_remote().unwrap(), crate::exec::DapStopReason::Stopped(_)));
        if state.current_variables(true).iter().any(|variable| {
            variable.name == "n" && variable.display_value.as_deref() == Some("[22]")
        }) {
            break;
        }
    }
    assert_eq!(state.format_variables(true), "n=[22]");
    assert_eq!(state.current_variables(true)[0].value, Some(miden_core::Felt::from_u32(22)));
    state.select_stack_frame(1).unwrap();
    assert_eq!(state.format_variables(true), "n=[11]");
    assert_eq!(
        state.variables_for_frame(1, true)[0].value,
        Some(miden_core::Felt::from_u32(11))
    );
    state.breakpoints.clear();
    state.create_breakpoint(crate::BreakpointType::Finish);
    state.step_remote().unwrap();
    assert_eq!(state.selected_stack_frame(), 0);
    assert_eq!(state.format_variables(true), "n=[11]");
    assert!(matches!(state.step_remote().unwrap(), crate::exec::DapStopReason::Terminated));
    assert!(state.current_variables(true).is_empty());
    assert!(state.format_variables(true).contains("terminated"));
    drop(state);
    completion.recv_timeout(timeout).expect("DAP server did not finish").unwrap();
    server.join().unwrap();
}
