extern crate alloc;

use alloc::{string::String, vec::Vec};

use miden_assembly::ast::ConstantValue;
use miden_core::{Felt, Word};
use miden_core_lib::CoreLibrary;
use miden_mast_package::PackageExport;
use miden_processor::{ContextId, ExecutionOutput};

/// Returns the value of the public integer constant `name` exported by
/// `miden::core::stark::constants` in the compiled core library.
pub fn stark_constant(name: &str) -> u32 {
    let path = format!("::miden::core::stark::constants::{name}");
    let package = CoreLibrary::default().package();
    let Some(PackageExport::Constant(constant)) = package.manifest.get_export(path.as_str()) else {
        panic!("{path} is not an exported constant");
    };
    let ConstantValue::Int(value) = &constant.value else {
        panic!("{path} is not an integer constant");
    };
    let value = value.inner().as_int();
    u32::try_from(value).unwrap_or_else(|_| panic!("{path} does not fit in u32"))
}

/// Reads an initialized felt from root-context memory.
pub fn read_memory_felt(output: &ExecutionOutput, addr: u32) -> Felt {
    output
        .memory
        .read_element(ContextId::root(), Felt::from_u32(addr))
        .unwrap_or_else(|_| panic!("memory address {addr} was not written"))
}

/// Generates MASM code to store field elements sequentially in memory starting at `base_addr`.
pub fn masm_store_felts(felts: &[Felt], base_addr: u32) -> String {
    felts
        .iter()
        .enumerate()
        .map(|(i, felt)| {
            let value = felt.as_canonical_u64();
            let offset = u32::try_from(i).unwrap_or_else(|_| {
                panic!("too many felts to store from base address {base_addr}")
            });
            let addr = base_addr.checked_add(offset).unwrap_or_else(|| {
                panic!("memory address overflow storing felt {i} from base address {base_addr}")
            });
            format!("push.{value} push.{addr} mem_store")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Generates MASM code to push field elements onto the stack while preserving their original order.
pub fn masm_push_felts(felts: &[Felt]) -> String {
    felts
        .iter()
        .rev()
        .map(|felt| format!("push.{}", felt.as_canonical_u64()))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Generates one MASM instruction that pushes a word in its original element order.
pub fn masm_push_word(word: &Word) -> String {
    let elements = word
        .iter()
        .rev()
        .map(|felt| felt.as_canonical_u64().to_string())
        .collect::<Vec<_>>()
        .join(".");
    format!("push.{elements}")
}

/// Portable transport preserves the execution's complete precompile obligation.
pub fn assert_precompile_witness_round_trips(output: &ExecutionOutput) {
    use miden_core::{
        deferred::{PrecompileWitness, TRUE_DIGEST},
        serde::{Deserializable, Serializable},
    };

    let decoded =
        Option::<PrecompileWitness>::read_from_bytes(&output.precompile_witness.to_bytes())
            .expect("portable precompile witness must round-trip");
    assert_eq!(decoded, output.precompile_witness);
    assert_eq!(
        decoded.as_ref().map(PrecompileWitness::root_unchecked).unwrap_or(TRUE_DIGEST),
        output.precompile_root(),
    );
}

/// Reads an explicitly exported caller root and checks its portable graph without a PVM proof.
pub fn assert_exported_manual_root(
    output: &ExecutionOutput,
    root_offset: usize,
) -> miden_core::deferred::PrecompileWitness {
    let root = Word::new(core::array::from_fn(|i| {
        output.stack.get_element(root_offset + i).expect("root element")
    }));
    assert_manual_graph(output, root)
}

fn assert_manual_graph(
    output: &ExecutionOutput,
    root: Word,
) -> miden_core::deferred::PrecompileWitness {
    use std::sync::Arc;

    use miden_core::{
        deferred::{PrecompileWitness, TRUE_DIGEST},
        serde::Deserializable,
        utils::packed_u32_elements_to_bytes,
    };

    assert_eq!(output.precompile_root(), TRUE_DIGEST, "manual calls must not log");
    assert!(output.precompile_witness.is_none());
    assert!(output.advice.stack().is_empty());
    let value = output.advice.get_mapped_values(&root).expect("root must be exported");
    let byte_len = usize::try_from(value[0].as_canonical_u64()).unwrap();
    let mut bytes = packed_u32_elements_to_bytes(&value[1..]);
    bytes.truncate(byte_len);
    let witness = PrecompileWitness::read_from_bytes(&bytes).expect("exported witness must decode");
    assert_eq!(witness.root_unchecked(), root);
    assert_eq!(witness.compute_root(Arc::new(miden_precompiles::registry())).unwrap(), root);
    witness
}

/// Exports the operation's root, optionally composing it with an independent caller root.
/// Both paths consume the root-first return while preserving the native result layout.
pub fn manual_signature_source(
    source: &str,
    module: &str,
    procedure: &str,
    composed: bool,
) -> String {
    let start = if composed {
        "begin padw padw exec.::miden::core::precompiles::append_root push.64 mem_storew_le dropw"
    } else {
        "begin"
    };
    let finish = if composed {
        // Save the returned root above the ordinary results, including all sixteen recovery
        // limbs, then load both roots above those results for explicit caller composition.
        "adv.export_deferred_witness push.68 mem_storew_le dropw \
         padw push.64 mem_loadw_le padw push.68 mem_loadw_le \
         exec.::miden::core::precompiles::append_root adv.export_deferred_witness dropw"
    } else {
        "adv.export_deferred_witness dropw"
    };
    source.replacen("begin", start, 1).replace(
        &format!("exec.::miden::core::crypto::dsa::{module}::{procedure}"),
        &format!("exec.::miden::core::crypto::dsa::{module}::{procedure}_with_root {finish}"),
    )
}

pub fn assert_manual_signature_matches_native(
    native: &ExecutionOutput,
    manual: &ExecutionOutput,
    obligations: usize,
    root_ands: usize,
    composed: bool,
) {
    use miden_core::deferred::{DEFERRED_AND_FRAME, Node, PrecompileWitnessEntry, TRUE_DIGEST};

    assert_eq!(manual.advice.map().len(), 1 + usize::from(composed));
    let root = if composed {
        Word::new(core::array::from_fn(|i| read_memory_felt(manual, 68 + i as u32)))
    } else {
        *manual.advice.map().iter().next().unwrap().0
    };
    let witness = assert_manual_graph(manual, root);
    assert_eq!(native.precompile_root(), Node::and(TRUE_DIGEST, root).digest());
    if composed {
        let expected = Node::and(Node::and(TRUE_DIGEST, TRUE_DIGEST).digest(), root).digest();
        let combined = assert_manual_graph(manual, expected);
        assert_eq!(combined.entries().iter().filter(|entry| {
            matches!(entry, PrecompileWitnessEntry::Join { frame, .. } if *frame == DEFERRED_AND_FRAME)
        }).count(), root_ands + 2, "composition must retain both independent subgraphs");
    }
    assert_eq!(native.stack, manual.stack, "ordinary results and tail must match");
    assert_eq!(witness.entries().iter().filter(|entry| {
        matches!(entry, PrecompileWitnessEntry::Join { frame, .. } if *frame == DEFERRED_AND_FRAME)
    }).count(), root_ands, "the returned root must use the expected grouping");
    let uint_eq =
        miden_precompiles::UintPrecompile::op_frame(miden_precompiles::UintPrecompile::EQ_OP_ID);
    let curve_eq =
        miden_precompiles::CurvePrecompile::op_frame(miden_precompiles::CurvePrecompile::EQ_OP_ID);
    assert_eq!(witness.entries().iter().filter(|entry| {
        matches!(entry, PrecompileWitnessEntry::Join { frame, .. } if *frame == uint_eq || *frame == curve_eq)
    }).count(), obligations - 1, "all arithmetic/curve bindings must be present alongside the hash assertion");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masm_store_felts_accepts_last_u32_address() {
        let source = masm_store_felts(&[Felt::new_unchecked(7)], u32::MAX);

        assert_eq!(source, format!("push.7 push.{} mem_store", u32::MAX));
    }

    #[test]
    #[should_panic(
        expected = "memory address overflow storing felt 1 from base address 4294967295"
    )]
    fn masm_store_felts_panics_clearly_on_address_overflow() {
        masm_store_felts(&[Felt::new_unchecked(7), Felt::new_unchecked(11)], u32::MAX);
    }
}
