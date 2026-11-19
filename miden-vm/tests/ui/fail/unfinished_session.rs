use miden_vm::{Processor, Program};

fn invalid(program: &Program) {
    let session = Processor::new(program).record_witness().start().unwrap();
    let _ = session.finish();
}

fn main() {}
