use miden_core::{
    mast::MastForest,
    operations::{DebugVarInfo, DebugVarLocation},
};

fn main() {
    let mut forest = MastForest::new();
    let _debug_var_id =
        forest.add_debug_var(DebugVarInfo::new("x", DebugVarLocation::Stack(0))).unwrap();
}
