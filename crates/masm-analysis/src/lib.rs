//! Reusable analysis passes for MASM LSP.

use std::{collections::HashMap, sync::Arc};

use masm_decompiler::{ProcSignature, SignatureMap, SymbolPath, Workspace};
use miden_assembly_syntax::ast::{
    FunctionType, Module, SymbolResolutionError, TypeResolver, types::Type as AstType,
};
use miden_debug_types::{DefaultSourceManager, SourceSpan, Spanned};

pub mod abstract_interp;
pub mod lint;
mod prepared;
mod unconstrained_advice;

use prepared::PreparedAnalysis;
use unconstrained_advice::{AdviceDiagnostic, infer_unconstrained_advice};

/// Results of running all analysis passes on a workspace.
#[derive(Debug)]
pub struct AnalysisSnapshot {
    /// Inferred procedure signatures.
    pub signatures: SignatureMap,
    /// Unconstrained advice flow diagnostics.
    pub advice_diagnostics: HashMap<SymbolPath, Vec<AdviceDiagnostic>>,
}

impl AnalysisSnapshot {
    /// Run all analysis passes on a workspace and return the combined results.
    pub fn from_workspace(workspace: &Workspace) -> Self {
        let prepared = PreparedAnalysis::new(workspace);
        let advice_diagnostics = infer_unconstrained_advice(&prepared);

        Self {
            signatures: prepared.signatures,
            advice_diagnostics,
        }
    }
}

/// Stack-effect counts extracted from a procedure signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StackSignature {
    /// Number of inputs.
    inputs: usize,
    /// Number of outputs.
    outputs: usize,
}

/// Mismatch between declared and inferred stack signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureMismatch {
    /// Procedure name without module path.
    pub proc_name: String,
    /// Source span associated with the mismatch.
    pub span: SourceSpan,
    /// Declared stack signature.
    declared: StackSignature,
    /// Inferred stack signature.
    inferred: StackSignature,
}

/// Generate a human-readable message describing a signature mismatch.
pub fn signature_mismatch_message(mismatch: &SignatureMismatch) -> String {
    let inputs_diff = mismatch.declared.inputs != mismatch.inferred.inputs;
    let outputs_diff = mismatch.declared.outputs != mismatch.inferred.outputs;
    match (inputs_diff, outputs_diff) {
        (true, true) => format!(
            "the definition declares {} inputs and {} outputs, but the inferred counts are {} and {} respectively",
            mismatch.declared.inputs,
            mismatch.declared.outputs,
            mismatch.inferred.inputs,
            mismatch.inferred.outputs
        ),
        (true, false) => format!(
            "the definition declares {} inputs, but the inferred input count is {}",
            mismatch.declared.inputs, mismatch.inferred.inputs
        ),
        (false, true) => format!(
            "the definition declares {} outputs, but the inferred output count is {}",
            mismatch.declared.outputs, mismatch.inferred.outputs
        ),
        (false, false) => String::new(),
    }
}

/// Compute signature mismatches using a pre-computed signature map.
///
/// This avoids rebuilding the call graph and signatures from scratch. Use this
/// when an [`AnalysisSnapshot`] is already available.
pub fn signature_mismatches_from_snapshot(
    module: &Module,
    sources: Arc<DefaultSourceManager>,
    signatures: &SignatureMap,
) -> Vec<SignatureMismatch> {
    let mut findings = Vec::new();
    let Ok(mut resolver) = module.type_resolver(sources) else {
        return findings;
    };
    for proc in module.procedures() {
        let Some(signature) = proc.signature() else {
            continue;
        };
        let Some(declared) = signature_stack_signature(signature, &mut resolver) else {
            continue;
        };

        let symbol_path = SymbolPath::from_module_and_name(module, proc.name().as_str());
        let Some(inferred) = signatures.get(&symbol_path) else {
            continue;
        };
        let Some(StackSignature { inputs, outputs }) = inferred_stack_signature(inferred) else {
            continue;
        };

        if declared.inputs != inputs || declared.outputs != outputs {
            let span = {
                let sig_span = signature.span();
                if sig_span == SourceSpan::UNKNOWN {
                    proc.name().span()
                } else {
                    sig_span
                }
            };
            findings.push(SignatureMismatch {
                proc_name: proc.name().as_str().to_string(),
                span,
                declared,
                inferred: StackSignature { inputs, outputs },
            });
        }
    }

    findings
}

fn signature_stack_signature<R>(
    signature: &FunctionType,
    resolver: &mut R,
) -> Option<StackSignature>
where
    R: TypeResolver<SymbolResolutionError>,
{
    let mut inputs = 0usize;
    for arg in signature.args.iter() {
        let ty = arg.resolve_type(resolver).ok().flatten()?;
        let felts = type_felts(&ty)?;
        inputs = inputs.checked_add(felts)?;
    }

    let mut outputs = 0usize;
    for result in signature.results.iter() {
        let ty = result.resolve_type(resolver).ok().flatten()?;
        let felts = type_felts(&ty)?;
        outputs = outputs.checked_add(felts)?;
    }

    Some(StackSignature { inputs, outputs })
}

fn inferred_stack_signature(signature: &ProcSignature) -> Option<StackSignature> {
    match signature {
        ProcSignature::Known { public_inputs, outputs, .. } => Some(StackSignature {
            inputs: *public_inputs,
            outputs: *outputs,
        }),
        ProcSignature::Unknown => None,
    }
}

fn type_felts(ty: &AstType) -> Option<usize> {
    match ty {
        AstType::Unknown | AstType::Never | AstType::List(_) => None,
        _ => Some(ty.size_in_felts()),
    }
}
