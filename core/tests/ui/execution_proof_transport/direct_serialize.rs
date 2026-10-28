use miden_core::{
    proof::ExecutionProof,
    serde::{Deserializable, Serializable},
};

fn assert_serializable<T: Serializable>() {}
fn assert_deserializable<T: Deserializable>() {}

fn main() {
    assert_serializable::<ExecutionProof>();
    assert_deserializable::<ExecutionProof>();
}
