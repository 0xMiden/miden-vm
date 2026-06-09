use miden_core::mast::{MastForest, MastNodeId};

fn main() {
    let forest = MastForest::new();
    let node_id = MastNodeId::new_unchecked(0);

    forest[node_id] = forest[node_id].clone();
}
