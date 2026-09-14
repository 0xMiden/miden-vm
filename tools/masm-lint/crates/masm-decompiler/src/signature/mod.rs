//! Stack-signature inference.

mod analysis;
mod domain;
mod effects;

pub use analysis::infer_signatures;
pub use domain::{ProcSignature, SignatureMap};
pub(crate) use effects::StackEffect;

use crate::{frontend::Workspace, symbol::path::SymbolPath};

/// Refine the public input arity for zero-input procedures with exact declared signatures.
///
/// This keeps the internal lifting depth unchanged while allowing linting and
/// rendered diagnostics to ignore preserved-stack scaffolding that is not part
/// of the procedure's semantic input surface. Mixed public/hidden input
/// signatures are left unrefined until lifting and advice analysis share a
/// canonical input ordering for that case.
pub fn refine_public_signature_inputs(workspace: &Workspace, signatures: &mut SignatureMap) {
    for module in workspace.modules() {
        let module_path = module.module_path().to_string();
        for proc in module.procedures() {
            let proc_path = SymbolPath::new(format!("{}::{}", module_path, proc.name()));
            let Some(signature @ ProcSignature::Known { inputs, outputs, .. }) =
                signatures.get(&proc_path).cloned()
            else {
                continue;
            };
            let Some(declared) = crate::types::declared_summary_for_proc(module, proc) else {
                continue;
            };
            let declared_inputs = declared.inputs.len();
            let declared_outputs = declared.outputs.len();
            if declared_inputs != 0 {
                continue;
            }
            if declared_outputs != outputs || declared_inputs >= inputs {
                continue;
            }
            if !signature.preserves_input_depths_from(declared_inputs) {
                continue;
            }
            signatures.insert(proc_path, signature.with_public_inputs(declared_inputs));
        }
    }
}
