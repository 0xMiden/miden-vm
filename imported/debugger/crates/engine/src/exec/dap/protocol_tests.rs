use std::{
    fs,
    io::{BufRead, Read, Write},
    net::Shutdown,
    thread,
    time::Duration,
};

use miden_assembly::{Assembler, DefaultSourceManager, ast::Module};
use miden_core::Felt;
use serde_json::{Value, json};

use super::*;
use crate::exec::DebuggerHost;

struct Session {
    reader: BufReader<std::net::TcpStream>,
    writer: BufWriter<std::net::TcpStream>,
    server: Option<thread::JoinHandle<Result<ExecutionOutput, ExecutionError>>>,
    sequence: i64,
    breakpoint_events: Vec<Value>,
}

impl Session {
    fn start(source: &str, config: DapConfig) -> Self {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let package: Arc<Package> = Assembler::new(source_manager.clone())
            .assemble_program("protocol-test", source)
            .unwrap()
            .into();
        Self::start_package(package, source_manager, config)
    }

    fn start_module(module: Module, source_manager: Arc<DefaultSourceManager>) -> Self {
        let package: Arc<Package> = Assembler::new(source_manager.clone())
            .assemble_program("protocol-test", module)
            .unwrap()
            .into();
        Self::start_package(package, source_manager, DapConfig::new("127.0.0.1:0"))
    }

    fn start_package(
        package: Arc<Package>,
        source_manager: Arc<DefaultSourceManager>,
        config: DapConfig,
    ) -> Self {
        Self::start_with_packages(package, source_manager, config, Vec::new())
    }

    fn start_with_packages(
        package: Arc<Package>,
        source_manager: Arc<DefaultSourceManager>,
        config: DapConfig,
        dependencies: Vec<Arc<Package>>,
    ) -> Self {
        let listener = DapExecutor::bind_listener("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut executor = DapExecutor::new(
            StackInputs::default(),
            AdviceInputs::default(),
            ExecutionOptions::default(),
        );
        executor.config = config;
        executor.event_recorder = Some(EventMutationRecorder::new());
        executor.forest_recorder = Some(MastForestRecorder::new());
        let server = thread::spawn(move || {
            let mut host = DebuggerHost::new(source_manager);
            for dependency in dependencies {
                host.load_package(dependency);
            }
            executor.execute_on_listener(package, &mut host, listener)
        });
        let stream = std::net::TcpStream::connect(address).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        Self {
            reader: BufReader::new(stream.try_clone().unwrap()),
            writer: BufWriter::new(stream),
            server: Some(server),
            sequence: 0,
            breakpoint_events: Vec::new(),
        }
    }

    fn read(&mut self) -> Value {
        let mut length = None;
        loop {
            let mut line = String::new();
            assert_ne!(
                self.reader.read_line(&mut line).unwrap(),
                0,
                "server closed before sending a message"
            );
            if let Some(value) = line.trim().strip_prefix("Content-Length:") {
                length = Some(value.trim().parse::<usize>().unwrap());
            } else if line.trim().is_empty() && length.is_some() {
                break;
            }
        }
        let mut bytes = vec![0; length.unwrap()];
        self.reader.read_exact(&mut bytes).unwrap();
        let message: Value = serde_json::from_slice(&bytes).unwrap();
        if message["event"] == "breakpoint" {
            self.breakpoint_events.push(message["body"].clone());
        }
        message
    }

    fn request(&mut self, command: &str, arguments: Value) -> Value {
        self.sequence += 1;
        let payload = json!({"seq": self.sequence, "type": "request", "command": command, "arguments": arguments}).to_string();
        write!(self.writer, "Content-Length: {}\r\n\r\n{payload}", payload.len()).unwrap();
        self.writer.flush().unwrap();
        loop {
            let message = self.read();
            if message["type"] == "response" {
                assert_eq!(message["request_seq"], self.sequence);
                return message;
            }
        }
    }

    fn stop(&mut self) -> (Value, Option<Value>) {
        let mut snapshot = None;
        loop {
            let message = self.read();
            match message["event"].as_str() {
                Some("miden/uiState") => snapshot = Some(message["body"].clone()),
                Some("stopped" | "terminated") => return (message, snapshot),
                _ => {}
            }
        }
    }

    fn handshake(&mut self, command: &str) {
        let response = self.request("initialize", json!({"adapterID": "test-client"}));
        assert_eq!(response["body"]["supportsRestartRequest"], true);
        assert_eq!(self.request(command, json!({}))["success"], true);
        let (event, snapshot) = self.stop();
        assert_eq!(event["body"]["reason"], "entry");
        assert_eq!(snapshot.unwrap()["cycle"], 0);
        assert_eq!(self.request("configurationDone", json!({}))["success"], true);
    }

    fn current_scopes(&mut self) -> Value {
        let trace = self.request("stackTrace", json!({"threadId": 1}));
        let frame = trace["body"]["stackFrames"][0]["id"].clone();
        self.request("scopes", json!({"frameId": frame}))
    }

    fn scope_reference(&mut self, name: &str) -> Value {
        self.current_scopes()["body"]["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|scope| scope["name"] == name)
            .unwrap()["variablesReference"]
            .clone()
    }

    fn join(&mut self) -> Result<ExecutionOutput, ExecutionError> {
        self.server.take().unwrap().join().unwrap()
    }

    fn disconnect(mut self) -> ExecutionOutput {
        assert_eq!(self.request("disconnect", json!({}))["success"], true);
        self.join().unwrap()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.writer.get_ref().shutdown(Shutdown::Both);
    }
}

fn session_with_dynamic_source(path: &std::path::Path) -> Session {
    use miden_assembly_syntax::ast::{ModuleKind, Path as AssemblyPath};

    let source_manager = Arc::new(DefaultSourceManager::default());
    let module = Module::parser(Some(ModuleKind::Library))
        .parse_file(Some(AssemblyPath::new("fixture::lazy")), path, source_manager.clone())
        .unwrap();
    let library: Arc<Package> = Assembler::new(source_manager.clone())
        .assemble_library("lazy", module, None::<&str>)
        .unwrap()
        .into();
    let mut assembler = Assembler::new(source_manager);
    assembler
        .link_package(library.clone(), miden_assembly::Linkage::Dynamic)
        .unwrap();
    let package: Arc<Package> = assembler
        .assemble_program("root", "use fixture::lazy\nbegin exec.lazy::run drop end")
        .unwrap()
        .into();
    Session::start_with_packages(
        package,
        Arc::new(DefaultSourceManager::default()),
        DapConfig::new("127.0.0.1:0"),
        vec![library],
    )
}

#[test]
fn source_breakpoint_is_verified_when_a_dynamic_package_loads() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("lazy.masm");
    fs::write(&path, "pub proc run\n\n    push.7\n    push.5\n    add\nend\n").unwrap();
    let path = path.canonicalize().unwrap();
    let mut session = session_with_dynamic_source(&path);
    session.handshake("launch");
    let response = session.request(
        "setBreakpoints",
        json!({
            "source": {"path": path}, "breakpoints": [{"line": 2}]
        }),
    );
    let breakpoint = &response["body"]["breakpoints"][0];
    assert_eq!(breakpoint["verified"], false);
    assert!(breakpoint["message"].as_str().unwrap().contains("Pending"));
    let id = breakpoint["id"].clone();
    session.request("continue", json!({"threadId": 1}));
    let (stop, _) = session.stop();
    assert_eq!(stop["body"]["reason"], "breakpoint", "{stop:?}");
    session.request("threads", json!({}));
    assert_eq!(session.breakpoint_events.len(), 1);
    let update = &session.breakpoint_events[0];
    assert_eq!(update["reason"], "changed");
    assert_eq!(update["breakpoint"]["id"], id);
    assert_eq!(update["breakpoint"]["verified"], true);
    assert_eq!(update["breakpoint"]["line"], 3);
    let stack_reference = session.scope_reference("Operand Stack");
    let values = session.request("variables", json!({"variablesReference": stack_reference}));
    assert_eq!(values["body"]["variables"][0]["value"], "7");
    let response = session.request(
        "setBreakpoints",
        json!({
            "source": {"path": path}, "breakpoints": [{"line": 4}]
        }),
    );
    assert_eq!(response["body"]["breakpoints"][0]["verified"], true);
    session.request("restart", json!({}));
    session.stop();
    session.request("continue", json!({"threadId": 1}));
    assert_eq!(session.stop().0["body"]["reason"], "breakpoint");
    session.request("threads", json!({}));
    assert_eq!(session.breakpoint_events.len(), 1);
    session.disconnect();
}

#[test]
fn removed_pending_source_breakpoints_do_not_stop_in_loaded_packages() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("lazy.masm");
    fs::write(&path, "pub proc run\n    push.7\nend\n").unwrap();
    let path = path.canonicalize().unwrap();
    let mut session = session_with_dynamic_source(&path);
    session.handshake("attach");
    session.request(
        "setBreakpoints",
        json!({"source": {"path": path}, "breakpoints": [{"line": 2}]}),
    );
    session.request("setBreakpoints", json!({"source": {"path": path}, "breakpoints": []}));
    session.request("continue", json!({"threadId": 1}));
    assert_eq!(session.stop().0["event"], "terminated");
    session.request("threads", json!({}));
    assert!(session.breakpoint_events.is_empty());
    session.disconnect();
}

#[test]
fn relocated_source_breakpoint_moves_when_another_package_loads_the_requested_line() {
    use miden_assembly_syntax::ast::{ModuleKind, Path as AssemblyPath};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("shared.masm");
    fs::write(&path, "pub proc foo\n    push.11\nend\n\npub proc bar\n    push.22\nend\n").unwrap();
    let path = path.canonicalize().unwrap();
    let manager = Arc::new(DefaultSourceManager::default());
    let module = Module::parser(Some(ModuleKind::Library))
        .parse_file(Some(AssemblyPath::new("fixture::shared")), &path, manager.clone())
        .unwrap();
    let shared: Arc<Package> = Assembler::new(manager.clone())
        .assemble_library("shared", module, None::<&str>)
        .unwrap()
        .into();
    let dependency: Arc<Package> = Assembler::new(manager.clone())
        .with_package(shared.clone(), miden_assembly::Linkage::Static)
        .unwrap()
        .assemble_library(
            "dependency",
            "namespace fixture::dependency use fixture::shared pub proc run exec.shared::bar \
             push.1 add end",
            None::<&str>,
        )
        .unwrap()
        .into();
    let package: Arc<Package> = Assembler::new(manager)
        .with_package(shared, miden_assembly::Linkage::Static)
        .unwrap()
        .with_package(dependency.clone(), miden_assembly::Linkage::Dynamic)
        .unwrap()
        .assemble_program(
            "root",
            "use fixture::shared use fixture::dependency begin exec.shared::foo \
             exec.dependency::run add drop end",
        )
        .unwrap()
        .into();
    let mut session = Session::start_with_packages(
        package,
        Arc::new(DefaultSourceManager::default()),
        DapConfig::new("127.0.0.1:0"),
        vec![dependency],
    );
    session.handshake("launch");
    let response = session.request(
        "setBreakpoints",
        json!({"source": {"path": path}, "breakpoints": [{"line": 6}]}),
    );
    let breakpoint = &response["body"]["breakpoints"][0];
    assert_eq!(breakpoint["verified"], true);
    assert_eq!(breakpoint["line"], 2);
    let id = breakpoint["id"].clone();

    session.request("continue", json!({"threadId": 1}));
    let (stop, snapshot) = session.stop();
    assert_eq!(stop["body"]["reason"], "breakpoint", "{stop:?}");
    assert_eq!(snapshot.unwrap()["current_stack"][0], 11);

    let mut stopped_in_bar = false;
    for _ in 0..8 {
        session.request("continue", json!({"threadId": 1}));
        let (stop, snapshot) = session.stop();
        assert_eq!(stop["body"]["reason"], "breakpoint", "{stop:?}");
        if snapshot.unwrap()["current_stack"][0] == 22 {
            stopped_in_bar = true;
            break;
        }
    }
    assert!(stopped_in_bar, "the newly loaded executable line must be hit");
    session.request("threads", json!({}));
    assert_eq!(session.breakpoint_events.len(), 1);
    let update = &session.breakpoint_events[0];
    assert_eq!(update["reason"], "changed");
    assert_eq!(update["breakpoint"]["id"], id);
    assert_eq!(update["breakpoint"]["verified"], true);
    assert_eq!(update["breakpoint"]["line"], 6);

    let response = session.request(
        "setBreakpoints",
        json!({"source": {"path": path}, "breakpoints": [{"line": 6}]}),
    );
    assert_eq!(response["body"]["breakpoints"][0]["line"], 6);
    assert_eq!(response["body"]["breakpoints"][0]["verified"], true);
    assert_eq!(session.breakpoint_events.len(), 1);
    session.disconnect();
}

#[test]
fn instruction_stepping_verifies_pending_source_breakpoints_once() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("lazy.masm");
    fs::write(&path, "pub proc run\n    push.7\nend\n").unwrap();
    let path = path.canonicalize().unwrap();
    let mut session = session_with_dynamic_source(&path);
    session.handshake("launch");
    let response = session.request(
        "setBreakpoints",
        json!({
            "source": {"path": path}, "breakpoints": [{"line": 2}]
        }),
    );
    assert_eq!(response["body"]["breakpoints"][0]["verified"], false);
    for _ in 0..20 {
        session.request("stepIn", json!({"threadId": 1, "granularity": "instruction"}));
        let (event, _) = session.stop();
        session.request("threads", json!({}));
        if event["event"] == "terminated" {
            break;
        }
    }
    assert_eq!(session.breakpoint_events.len(), 1);
    assert_eq!(session.breakpoint_events[0]["breakpoint"]["verified"], true);
    let response = session.request(
        "setBreakpoints",
        json!({
            "source": {"path": path}, "breakpoints": [{"line": 2}, {"line": 0}]
        }),
    );
    assert_eq!(response["body"]["breakpoints"][0]["verified"], true);
    assert_eq!(response["body"]["breakpoints"][1]["verified"], false);
    session.disconnect();
}

#[test]
fn pending_breakpoint_hits_a_single_operation_dynamic_procedure() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("lazy.masm");
    fs::write(&path, "pub proc run\n    add\nend\n").unwrap();
    let path = path.canonicalize().unwrap();
    let mut session = session_with_dynamic_source(&path);
    session.handshake("launch");
    let response = session.request(
        "setBreakpoints",
        json!({
            "source": {"path": path}, "breakpoints": [{"line": 2}]
        }),
    );
    assert_eq!(response["body"]["breakpoints"][0]["verified"], false);
    session.request("continue", json!({"threadId": 1}));
    let (stop, _) = session.stop();
    assert_eq!(stop["body"]["reason"], "breakpoint", "{stop:?}");
    assert_eq!(session.breakpoint_events.len(), 1);
    session.disconnect();
}

#[test]
fn dap_session_inspects_initial_state_and_evaluations() {
    let mut session = Session::start(
        "proc increment push.1 add end\nbegin push.7 dup.0 mem_store.0 exec.increment add end",
        DapConfig::new("127.0.0.1:0"),
    );
    session.handshake("attach");
    let threads = session.request("threads", json!({}));
    assert_eq!(threads["body"]["threads"][0]["name"], "main");
    let scopes = session.current_scopes();
    assert_eq!(scopes["body"]["scopes"].as_array().unwrap().len(), 3);
    assert_eq!(scopes["body"]["scopes"][0]["name"], "Local Variables");
    for scope in scopes["body"]["scopes"].as_array().unwrap() {
        let reference = scope["variablesReference"].clone();
        let variables = session.request("variables", json!({"variablesReference": reference}));
        let values = variables["body"]["variables"].as_array().unwrap();
        if scope["name"] == "Operand Stack" {
            assert_eq!(values.len(), 16);
            assert_eq!(values[0]["value"], "0");
        } else {
            assert!(values.is_empty());
        }
    }
    for (expression, expected) in [
        ("__miden_read_memory 0 -t u32", "0"),
        ("vars all", "No debug variables tracked"),
        ("vars", "No source-level variables (use 'vars all' to show compiler locals)"),
    ] {
        let response = session.request("evaluate", json!({"expression": expression}));
        assert_eq!(response["body"]["result"], expected);
    }
    let state = session.request("evaluate", json!({"expression": "__miden_ui_state"}));
    let state: Value = serde_json::from_str(state["body"]["result"].as_str().unwrap()).unwrap();
    assert_eq!(state["cycle"], 0);
    for expression in
        ["missing_variable", "__miden_read_memory invalid", "__miden_read_memory 0 -c 2"]
    {
        assert_eq!(
            session.request("evaluate", json!({"expression": expression}))["success"],
            false
        );
    }
    assert_eq!(
        session.request("pause", json!({"threadId": 1}))["message"],
        "Unsupported command"
    );
    session.disconnect();
}

#[test]
fn dap_session_steps_breaks_restarts_and_records_a_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("replay.bin");
    let mut config = DapConfig::new("127.0.0.1:0");
    let recorder = config.record_snapshot(path.clone());
    let mut session = Session::start(
        "proc increment push.1 add end\nbegin push.7 dup.0 mem_store.0 exec.increment add end",
        config,
    );
    session.handshake("attach");
    let breakpoints = session.request(
        "setBreakpoints",
        json!({"source": {"path": "missing.rs"}, "breakpoints": [{"line": 10}]}),
    );
    assert_eq!(breakpoints["body"]["breakpoints"][0]["verified"], false);
    let functions = session.request(
        "setFunctionBreakpoints",
        json!({"breakpoints": [{"name": "increment"}, {"name": "[invalid"}]}),
    );
    assert_eq!(functions["body"]["breakpoints"][0]["verified"], true);
    assert_eq!(functions["body"]["breakpoints"][1]["verified"], false);
    assert_eq!(session.request("continue", json!({"threadId": 1}))["success"], true);
    let (event, snapshot) = session.stop();
    assert_eq!(event["body"]["reason"], "breakpoint");
    assert!(snapshot.unwrap()["cycle"].as_u64().unwrap() > 0);
    let trace = session.request("stackTrace", json!({"threadId": 1}));
    assert!(trace["body"]["totalFrames"].as_u64().unwrap() > 0);
    let reference = session.scope_reference("Memory");
    let memory = session.request("variables", json!({"variablesReference": reference}));
    assert!(
        memory["body"]["variables"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value["value"] == "7")
    );
    assert_eq!(
        session.request("setFunctionBreakpoints", json!({"breakpoints": []}))["success"],
        true
    );
    for command in ["stepIn", "next", "stepOut"] {
        assert_eq!(
            session.request(command, json!({"threadId": 1, "granularity": "instruction"}))
                ["success"],
            true
        );
        let (event, _) = session.stop();
        assert!(matches!(event["event"].as_str(), Some("stopped" | "terminated")));
    }
    assert_eq!(session.request("restart", json!({}))["success"], true);
    let (_, snapshot) = session.stop();
    assert_eq!(snapshot.unwrap()["cycle"], 0);
    assert_eq!(
        session.request("next", json!({"threadId": 1, "granularity": "statement"}))["success"],
        true
    );
    session.stop();
    let output = session.disconnect();
    assert_eq!(output.stack[0], Felt::from_u32(8));
    let snapshot = crate::exec::ReplaySnapshot::read_from_file(&path).unwrap();
    assert!(snapshot.event_log.is_empty());
    assert_eq!(recorder.take().unwrap().unwrap().path, Uri::from(path.as_path()));
}

#[test]
fn dap_locals_scope_reports_a_live_debug_variable() {
    use miden_assembly_syntax::{
        Parse,
        ast::{Instruction, Op},
        debuginfo::{SourceSpan, Span},
    };

    let source_manager = Arc::new(DefaultSourceManager::default());
    let mut module =
        Parse::parse("begin push.5 nop push.1 add add end", false, source_manager.clone()).unwrap();
    let entrypoint = module.procedures_mut().find(|procedure| procedure.is_entrypoint()).unwrap();
    for operation in entrypoint.body_mut().iter_mut() {
        if let Op::Inst(instruction) = operation
            && matches!(instruction.inner(), Instruction::Nop)
        {
            *instruction = Span::new(
                SourceSpan::default(),
                Instruction::DebugVar(DebugVarInfo::new("answer", DebugVarLocation::Stack(0))),
            );
        }
    }

    let mut session = Session::start_module(*module, source_manager);
    session.handshake("launch");
    let mut variable = None;
    for _ in 0..20 {
        assert_eq!(
            session.request("stepIn", json!({"threadId": 1, "granularity": "instruction"}))
                ["success"],
            true
        );
        let (event, _) = session.stop();
        assert_eq!(event["event"], "stopped");
        let reference = session.scope_reference("Local Variables");
        let response = session.request("variables", json!({"variablesReference": reference}));
        variable = response["body"]["variables"]
            .as_array()
            .unwrap()
            .iter()
            .find(|variable| variable["name"] == "answer")
            .cloned();
        if variable.is_some() {
            break;
        }
    }
    let variable = variable.expect("live DAP local was not reported");
    assert_eq!(variable["value"], "5");
    assert_eq!(variable["type"], "Felt");
    session.disconnect();
}

#[test]
fn dap_phase_two_restart_sets_and_resets_the_restart_flag() {
    let config = DapConfig::new("127.0.0.1:0");
    let handle = config.clone();
    let mut session = Session::start("begin push.1 end", config);
    session.handshake("launch");
    assert_eq!(session.request("restart", json!({"arguments": {}}))["success"], true);
    let (event, _) = session.stop();
    assert_eq!(event["event"], "terminated");
    assert_eq!(event["body"]["restart"], true);
    session.join().unwrap();
    assert!(handle.restart_requested());
    handle.reset_restart();
    assert!(!handle.restart_requested());
}

#[test]
fn dap_reports_execution_failure_and_writes_the_failed_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("failed.bin");
    let mut config = DapConfig::new("127.0.0.1:0");
    config.record_snapshot(path.clone());
    let mut session = Session::start("begin push.0 assert end", config);
    session.handshake("launch");
    assert_eq!(session.request("continue", json!({"threadId": 1}))["success"], true);
    assert_eq!(session.stop().0["event"], "terminated");
    assert!(session.join().is_err());
    assert!(crate::exec::ReplaySnapshot::read_from_file(&path).is_ok());
}

fn session_with_stack_local(source: &str, name: &str) -> Session {
    use miden_assembly_syntax::{
        Parse,
        ast::{Instruction, Op},
        debuginfo::{SourceSpan, Span},
    };
    let source_manager = Arc::new(DefaultSourceManager::default());
    let mut module = Parse::parse(source, false, source_manager.clone()).unwrap();
    for procedure in module.procedures_mut() {
        for operation in procedure.body_mut().iter_mut() {
            if let Op::Inst(instruction) = operation
                && matches!(instruction.inner(), Instruction::Nop)
            {
                *instruction = Span::new(
                    SourceSpan::default(),
                    Instruction::DebugVar(DebugVarInfo::new(name, DebugVarLocation::Stack(0))),
                );
            }
        }
    }
    Session::start_module(*module, source_manager)
}

fn invocation_locals_session() -> (Session, Value, Value) {
    invocation_locals_session_with_call("exec.inner")
}

fn invocation_locals_session_with_call(call: &str) -> (Session, Value, Value) {
    let source = format!(
        "proc inner push.9 nop dup drop drop end begin procref.inner mem_storew_le.100 dropw \
         push.5 nop dup drop drop {call} push.8 drop end"
    );
    let mut session = session_with_stack_local(&source, "x");
    session.handshake("launch");
    for _ in 0..60 {
        session.request("stepIn", json!({"threadId": 1}));
        assert_eq!(session.stop().0["event"], "stopped");
        if session.request("evaluate", json!({"expression": "x"}))["body"]["result"] == "9" {
            let trace = session.request("stackTrace", json!({"threadId": 1}));
            let frames = trace["body"]["stackFrames"].as_array().unwrap();
            assert_eq!(frames.len(), 2);
            return (session, frames[0]["id"].clone(), frames[1]["id"].clone());
        }
    }
    panic!("callee variable was never observed");
}

#[test]
fn dap_scopes_distinguish_suspended_caller_locals() {
    let (mut session, callee, caller) = invocation_locals_session();
    let callee_scopes = session.request("scopes", json!({"frameId": callee}));
    let caller_scopes = session.request("scopes", json!({"frameId": caller}));
    let callee_locals = callee_scopes["body"]["scopes"][0]["variablesReference"].clone();
    let caller_locals = caller_scopes["body"]["scopes"][0]["variablesReference"].clone();
    assert_ne!(callee_locals, caller_locals);
    for (reference, expected) in [(callee_locals, "9"), (caller_locals, "5")] {
        let variables = session.request("variables", json!({"variablesReference": reference}));
        assert_eq!(variables["body"]["variables"][0]["value"], expected);
    }
    session.disconnect();
}

#[test]
fn dap_evaluation_selects_the_requested_invocation() {
    for call in ["exec.inner", "call.inner", "push.100 dynexec", "push.100 dyncall"] {
        let (mut session, callee, caller) = invocation_locals_session_with_call(call);
        for (frame, expected) in [(callee, "9"), (caller, "5")] {
            let result = session.request("evaluate", json!({"expression": "x", "frameId": frame}));
            assert_eq!(result["body"]["result"], expected);
            let bundle = session
                .request("evaluate", json!({"expression": "__miden_variables", "frameId": frame}));
            let variables: Value =
                serde_json::from_str(bundle["body"]["result"].as_str().unwrap()).unwrap();
            assert_eq!(variables[0]["value"], expected);
            assert_eq!(variables[0]["raw"], expected.parse::<u64>().unwrap());
        }
        session.request("stepOut", json!({"threadId": 1}));
        assert_eq!(session.stop().0["event"], "stopped");
        assert_eq!(session.request("evaluate", json!({"expression": "x"}))["body"]["result"], "5");
        assert_eq!(
            session.request("evaluate", json!({"expression": "vars all"}))["body"]["result"],
            "x=5"
        );
        session.disconnect();
    }
}

#[test]
fn dap_frame_and_scope_handles_expire_on_resume_and_restart() {
    let (mut session, callee, _) = invocation_locals_session();
    let scope = session.request("scopes", json!({"frameId": callee}))["body"]["scopes"][0]
        ["variablesReference"]
        .clone();
    session.request("stepIn", json!({"threadId": 1}));
    assert_eq!(session.stop().0["event"], "stopped");
    assert_eq!(session.request("scopes", json!({"frameId": callee}))["success"], false);
    assert_eq!(
        session.request("variables", json!({"variablesReference": scope}))["success"],
        false
    );
    assert_eq!(
        session.request("evaluate", json!({"expression": "x", "frameId": callee}))["success"],
        false
    );
    let trace = session.request("stackTrace", json!({"threadId": 1}));
    let new_frame = trace["body"]["stackFrames"][0]["id"].clone();
    assert_ne!(new_frame, callee);
    session.request("restart", json!({}));
    assert_eq!(session.stop().0["event"], "stopped");
    session.request("stackTrace", json!({"threadId": 1}));
    assert_eq!(session.request("scopes", json!({"frameId": new_frame}))["success"], false);
    session.request("continue", json!({"threadId": 1}));
    assert_eq!(session.stop().0["event"], "terminated");
    assert_eq!(session.request("evaluate", json!({"expression": "x"}))["success"], false);
    assert!(
        session.current_scopes()["body"]["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|scope| scope["name"] != "Local Variables")
    );
    session.disconnect();
}

#[test]
fn dap_recursive_invocations_keep_distinct_locals() {
    let mut session = session_with_stack_local(
        "proc inner nop dup neq.0 if.true sub.1 push.100 dynexec else push.7 drop end push.8 drop \
         end begin procref.inner mem_storew_le.100 dropw push.3 push.100 dynexec drop push.9 drop \
         end",
        "x",
    );
    session.handshake("launch");
    let mut reached_base = false;
    for _ in 0..150 {
        session.request("stepIn", json!({"threadId": 1}));
        assert_eq!(session.stop().0["event"], "stopped");
        if session.request("evaluate", json!({"expression": "x"}))["body"]["result"] == "0" {
            reached_base = true;
            break;
        }
    }
    assert!(reached_base);
    let trace = session.request("stackTrace", json!({"threadId": 1}));
    let frames = trace["body"]["stackFrames"].as_array().unwrap();
    assert_eq!(frames.len(), 5);
    for (depth, frame) in frames.iter().take(4).enumerate() {
        let result =
            session.request("evaluate", json!({"expression": "x", "frameId": frame["id"]}));
        assert_eq!(result["body"]["result"], depth.to_string());
    }
    for expected in 1..=3 {
        session.request("stepOut", json!({"threadId": 1}));
        assert_eq!(session.stop().0["event"], "stopped");
        assert_eq!(
            session.request("evaluate", json!({"expression": "x"}))["body"]["result"],
            expected.to_string()
        );
    }
    session.disconnect();
}

#[test]
fn dap_other_locals_scope_preserves_compiler_variables() {
    let mut session = session_with_stack_local("begin push.5 nop dup drop drop end", "local0");
    session.handshake("launch");
    for _ in 0..15 {
        session.request("stepIn", json!({"threadId": 1}));
        assert_eq!(session.stop().0["event"], "stopped");
        if session.request("evaluate", json!({"expression": "vars all"}))["body"]["result"]
            == "local0=5"
        {
            let scopes = session.current_scopes();
            assert_eq!(scopes["body"]["scopes"][0]["namedVariables"], 0);
            assert_eq!(scopes["body"]["scopes"][1]["name"], "Other Locals");
            let visible = session.request("evaluate", json!({"expression": "__miden_variables"}));
            assert_eq!(visible["body"]["result"], "[]");
            let all = session.request("evaluate", json!({"expression": "__miden_variables all"}));
            let all: Value = serde_json::from_str(all["body"]["result"].as_str().unwrap()).unwrap();
            assert_eq!(all[0], json!({"name": "local0", "value": "5", "raw": 5}));
            let reference = scopes["body"]["scopes"][1]["variablesReference"].clone();
            assert_eq!(
                session.request("variables", json!({"variablesReference": reference}))["body"]
                    ["variables"][0]["value"],
                "5"
            );
            session.disconnect();
            return;
        }
    }
    panic!("compiler local was never observed");
}

#[test]
fn dap_inline_frames_do_not_claim_invocation_locals() {
    use miden_assembly_syntax::{
        Parse,
        ast::{DebugInlineCallInfo, Instruction, Op},
        debuginfo::{SourceManager, Span},
    };
    let manager = Arc::new(DefaultSourceManager::default());
    let mut module = Parse::parse(
        "proc inner push.9 nop dup drop nop push.1 drop drop end begin exec.inner end",
        false,
        manager.clone(),
    )
    .unwrap();
    let mut decorated = false;
    for procedure in module.procedures_mut() {
        for operation in procedure.body_mut().iter_mut() {
            if let Op::Inst(instruction) = operation
                && matches!(instruction.inner(), Instruction::Nop)
            {
                let span = instruction.span();
                let replacement = if decorated {
                    let location = manager.file_line_col(span).unwrap();
                    Instruction::DebugInlineCall(DebugInlineCallInfo::new(
                        "source::inlined",
                        location.clone(),
                        location,
                    ))
                } else {
                    decorated = true;
                    Instruction::DebugVar(DebugVarInfo::new("x", DebugVarLocation::Stack(0)))
                };
                *instruction = Span::new(span, replacement);
            }
        }
    }
    let mut session = Session::start_module(*module, manager);
    session.handshake("launch");
    for _ in 0..40 {
        session.request("stepIn", json!({"threadId": 1}));
        assert_eq!(session.stop().0["event"], "stopped");
        let trace = session.request("stackTrace", json!({"threadId": 1}));
        let frames = trace["body"]["stackFrames"].as_array().unwrap();
        if let Some(inline) = frames.iter().find(|frame| frame["presentationHint"] == "subtle") {
            let scopes = session.request("scopes", json!({"frameId": inline["id"]}));
            assert!(scopes["body"]["scopes"].as_array().unwrap().is_empty());
            assert_eq!(
                session.request("evaluate", json!({"expression": "x", "frameId": inline["id"]}))
                    ["success"],
                false
            );
            assert_eq!(
                session.request("evaluate", json!({"expression": "x"}))["body"]["result"],
                "9"
            );
            session.disconnect();
            return;
        }
    }
    panic!("inline frame was never observed");
}

#[test]
fn dap_bundled_variables_preserve_typed_display_and_raw_felts() {
    use miden_assembly_syntax::{
        Parse,
        ast::{
            Instruction, Op,
            types::{ArrayType, Type},
        },
        debuginfo::Span,
    };

    let manager = Arc::new(DefaultSourceManager::default());
    let mut module = Parse::parse(
        "begin push.1 nop drop push.4294967295 nop drop push.7.8 nop drop drop push.9 drop end",
        false,
        manager.clone(),
    )
    .unwrap();
    let mut declarations = [
        ("boolean", Type::I1),
        ("signed", Type::I32),
        ("array", Type::Array(Arc::new(ArrayType::new(Type::U32, 2)))),
    ]
    .into_iter();
    for procedure in module.procedures_mut() {
        for operation in procedure.body_mut().iter_mut() {
            if let Op::Inst(instruction) = operation
                && matches!(instruction.inner(), Instruction::Nop)
            {
                let (name, ty) = declarations.next().unwrap();
                let mut variable = DebugVarInfo::new(name, DebugVarLocation::Stack(0));
                variable.set_ty(ty, None);
                *instruction = Span::new(instruction.span(), Instruction::DebugVar(variable));
            }
        }
    }
    let mut session = Session::start_module(*module, manager);
    session.handshake("launch");
    for _ in 0..40 {
        session.request("stepIn", json!({"threadId": 1}));
        assert_eq!(session.stop().0["event"], "stopped");
        if session.request("evaluate", json!({"expression": "array"}))["success"] == true {
            let trace = session.request("stackTrace", json!({"threadId": 1}));
            let frame = trace["body"]["stackFrames"][0]["id"].clone();
            let response = session
                .request("evaluate", json!({"expression": "__miden_variables", "frameId": frame}));
            assert_eq!(response["success"], true);
            let variables: Value =
                serde_json::from_str(response["body"]["result"].as_str().unwrap()).unwrap();
            for (name, value, raw) in [
                ("boolean", "true", 1u64),
                ("signed", "-1i32", 4_294_967_295),
                ("array", "[8, 7]", 8),
            ] {
                let variable = variables
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|variable| variable["name"] == name)
                    .unwrap();
                assert_eq!(variable["value"], value);
                assert_eq!(variable["raw"], raw);
            }
            session.disconnect();
            return;
        }
    }
    panic!("typed declarations were never observed");
}
