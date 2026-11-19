use miden_vm::{Host, Processor, Program};

fn invalid<H: Host>(program: &Program, host: &mut H) {
    let _ = Processor::new(program).execute().run_sync(host);
}

fn main() {}
