//! Manual operation and constant counts for symbolic folding experiments.
use miden_ace::compiler::{CapturedAir, CompiledRelation, LayoutKind};
use miden_stark::air::symbolic::folding_experiment::{Policy, with_policy};

fn main() {
    for (policy, aware) in Policy::ALL
        .into_iter()
        .map(|policy| (policy, false))
        .chain(core::iter::once((Policy::StrictNested, true)))
    {
        for pvm in [false, true] {
            let capture = || {
                with_policy(policy, || {
                    if pvm {
                        miden_air_definitions::precompiles::relation::AIRS
                            .iter()
                            .map(CapturedAir::new_native)
                            .collect::<Result<Vec<_>, _>>()
                    } else {
                        miden_air_definitions::vm::AIRS
                            .iter()
                            .map(CapturedAir::new_native)
                            .collect::<Result<Vec<_>, _>>()
                    }
                })
            };
            let captured = miden_constraint_compiler::ir::with_sum_folding(aware, capture).unwrap();
            let refs: Vec<_> = captured.iter().collect();
            let relation = CompiledRelation::from_captured(&refs, 8).unwrap();
            let circuit = relation.build_circuit(LayoutKind::Masm).unwrap();
            let encoded = circuit.to_ace().unwrap();
            println!(
                "ACE,{}/{},{},{},{},{},{}",
                if aware { "aware" } else { policy.name() },
                if pvm { "pvm" } else { "vm" },
                circuit.num_operations(),
                circuit.num_constants(),
                encoded.num_vars(),
                encoded.num_eval_rows(),
                encoded.size_in_felt()
            );
        }
    }
}
