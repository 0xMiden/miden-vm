use miden_vm::{DefaultHost, Processor, Program, processor::ExecutionRequest};

fn invalid(program: &Program) {
    let _ = Processor::new(program).run_sync(&mut DefaultHost::default());
}

fn invalid_native(program: &Program) {
    let _ = ExecutionRequest::new(program).run_sync(&mut DefaultHost::default());
}

fn main() {}
