use miden_vm::{CompletedExecution, Execute};

fn invalid(task: Execute, completed: CompletedExecution<Execute>) {
    let _ = CompletedExecution { task, ..completed };
}

fn main() {}
