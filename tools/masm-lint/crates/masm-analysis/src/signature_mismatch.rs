//! Declared-vs-inferred signature mismatch capability.

use std::sync::Arc;

use masm_decompiler::analysis::{ProcSignature, SymbolPath, Workspace};
use miden_assembly_syntax::ast::{
    FunctionType, GlobalItemIndex, ItemIndex, LocalSymbolResolver, Module, SymbolResolution,
    SymbolResolutionError, TypeResolver, types::Type as AstType,
};
use miden_debug_types::{DefaultSourceManager, SourceManager, SourceSpan, Span, Spanned};

use crate::prepared::PreparedAnalysis;

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
pub(crate) struct SignatureMismatch {
    /// Procedure name without module path.
    pub(crate) proc_name: String,
    /// Source span associated with the mismatch.
    pub(crate) span: SourceSpan,
    /// Declared stack signature.
    declared: StackSignature,
    /// Inferred stack signature.
    inferred: StackSignature,
}

/// Generate a human-readable message describing a signature mismatch.
pub(crate) fn signature_mismatch_message(mismatch: &SignatureMismatch) -> String {
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

/// Analysis capability for declared-vs-inferred signature mismatches.
pub(crate) struct SignatureMismatchCapability<'a> {
    workspace: &'a Workspace,
    sources: Arc<DefaultSourceManager>,
}

impl<'a> SignatureMismatchCapability<'a> {
    /// Construct the signature mismatch capability.
    pub(crate) fn new(workspace: &'a Workspace, sources: Arc<DefaultSourceManager>) -> Self {
        Self { workspace, sources }
    }
}

impl SignatureMismatchCapability<'_> {
    pub(crate) fn analyze(&self, prepared: &PreparedAnalysis) -> Vec<SignatureMismatch> {
        self.workspace
            .modules()
            .flat_map(|program| {
                signature_mismatches_for_module(program.module(), self.sources.clone(), prepared)
            })
            .collect()
    }
}

/// Compute signature mismatches for a single module using prepared signatures.
fn signature_mismatches_for_module(
    module: &Module,
    sources: Arc<DefaultSourceManager>,
    prepared: &PreparedAnalysis,
) -> Vec<SignatureMismatch> {
    let mut findings = Vec::new();
    let Some(mut resolver) = ModuleLocalTypeResolver::new(module, sources) else {
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
        let Some(inferred) = prepared.signature(&symbol_path) else {
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

struct ModuleLocalTypeResolver<'a> {
    module: &'a Module,
    resolver: LocalSymbolResolver,
}

impl<'a> ModuleLocalTypeResolver<'a> {
    fn new(module: &'a Module, sources: Arc<DefaultSourceManager>) -> Option<Self> {
        let resolver = LocalSymbolResolver::new(module, sources).ok()?;
        Some(Self { module, resolver })
    }

    fn undefined(&self, span: SourceSpan) -> SymbolResolutionError {
        let sources = self.resolver.source_manager();
        SymbolResolutionError::undefined(span, sources.as_ref())
    }
}

impl TypeResolver<SymbolResolutionError> for ModuleLocalTypeResolver<'_> {
    fn source_manager(&self) -> Arc<dyn SourceManager> {
        self.resolver.source_manager()
    }

    fn resolve_local_failed(&self, err: SymbolResolutionError) -> SymbolResolutionError {
        err
    }

    fn get_type(
        &mut self,
        context: SourceSpan,
        _gid: GlobalItemIndex,
    ) -> Result<AstType, SymbolResolutionError> {
        Err(self.undefined(context))
    }

    fn get_local_type(
        &mut self,
        context: SourceSpan,
        id: ItemIndex,
    ) -> Result<Option<AstType>, SymbolResolutionError> {
        let item_name = self.resolver.get_item_name(id);
        let Some(type_decl) = self
            .module
            .types()
            .find(|type_decl| type_decl.name().as_str() == item_name.as_str())
        else {
            return Err(self.undefined(context));
        };
        type_decl.ty().resolve_type(self)
    }

    fn resolve_type_ref(
        &mut self,
        ty: Span<&miden_assembly_syntax::ast::Path>,
    ) -> Result<SymbolResolution, SymbolResolutionError> {
        self.resolver.resolve_path(ty)
    }
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
