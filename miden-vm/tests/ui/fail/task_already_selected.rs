use miden_vm::{Processor, Program};

fn invalid(program: &Program) {
    let _ = Processor::new(program).execute().record_witness();
}

fn main() {}
