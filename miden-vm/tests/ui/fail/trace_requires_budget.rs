use miden_vm::{Processor, Program};

fn invalid(program: &Program) {
    let _ = Processor::new(program).build_trace();
}

fn main() {}
