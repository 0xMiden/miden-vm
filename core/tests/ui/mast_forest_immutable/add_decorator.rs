use miden_core::{mast::MastForest, operations::Decorator};

fn main() {
    let mut forest = MastForest::new();
    let _decorator_id = forest.add_decorator(Decorator::Trace(0)).unwrap();
}
