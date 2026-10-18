//! Statically checked Askama bindings; no text surgery or MASM string fragments.

use std::{string::String, vec, vec::Vec};

use askama::Template;

use super::{
    ArtifactOwnership, HeightRule, RenderedArtifact, V1RenderPlan,
    proof_order::{PointerRef, ProofOrderPlan, SortStep},
    pvm_glue::PvmGluePlan,
};

#[derive(Template)]
#[template(path = "verifier/evaluator.masm", escape = "none")]
struct EvaluatorTemplate<'a> {
    p: &'a V1RenderPlan,
}

#[derive(Template)]
#[template(path = "verifier/ood.masm", escape = "none")]
struct OodTemplate<'a> {
    p: &'a V1RenderPlan,
}

#[derive(Template)]
#[template(path = "verifier/proof_order.masm", escape = "none")]
struct ProofOrderTemplate<'a> {
    proof: &'a ProofOrderPlan,
}

#[derive(Template)]
#[template(path = "verifier/vm_layout.masm", escape = "none")]
struct VmLayoutTemplate<'a> {
    p: &'a V1RenderPlan,
}

#[derive(Template)]
#[template(path = "verifier/pvm_layout.masm", escape = "none")]
struct PvmLayoutTemplate<'a> {
    p: &'a V1RenderPlan,
}

#[derive(Template)]
#[template(path = "verifier/deep_adapter.masm", escape = "none")]
struct DeepTemplate<'a> {
    p: &'a V1RenderPlan,
}

#[derive(Template)]
#[template(path = "verifier/vm_wrapper.masm", escape = "none")]
struct VmWrapperTemplate<'a> {
    p: &'a V1RenderPlan,
}

#[derive(Template)]
#[template(path = "verifier/pvm_wrapper.masm", escape = "none")]
struct PvmWrapperTemplate<'a> {
    p: &'a V1RenderPlan,
    g: &'a PvmGluePlan,
}

#[derive(Template)]
#[template(path = "verifier/pvm_aux_trace.masm", escape = "none")]
struct PvmAuxTemplate<'a> {
    p: &'a V1RenderPlan,
}

#[derive(Template)]
#[template(path = "verifier/pvm_public_inputs.masm", escape = "none")]
struct PvmPublicTemplate<'a> {
    p: &'a V1RenderPlan,
    g: &'a PvmGluePlan,
}

pub(crate) fn render_proof_order(proof: &ProofOrderPlan) -> String {
    ProofOrderTemplate { proof }
        .render()
        .expect("packaged verifier template must render")
}

pub(crate) fn render(p: &V1RenderPlan) -> Vec<RenderedArtifact> {
    let (evaluator_path, ood_path, layout_path, deep_path, wrapper_path) = match &p.input.relation {
        super::RelationInput::Vm(_) => (
            "crates/lib/core/asm/sys/vm/constraints_eval.masm",
            "crates/lib/core/asm/sys/vm/ood_frames.masm",
            "crates/lib/core/asm/sys/vm/layout.masm",
            "crates/lib/core/asm/sys/vm/deep_queries.masm",
            "crates/lib/core/asm/sys/vm/mod.masm",
        ),
        super::RelationInput::Pvm { .. } => (
            "crates/lib/core/asm/sys/pvm/constraints_eval.masm",
            "crates/lib/core/asm/sys/pvm/ood_frames.masm",
            "crates/lib/core/asm/sys/pvm/layout.masm",
            "crates/lib/core/asm/sys/pvm/deep_queries.masm",
            "crates/lib/core/asm/sys/pvm/mod.masm",
        ),
    };
    let layout = match &p.input.relation {
        super::RelationInput::Vm(_) => VmLayoutTemplate { p }.render(),
        super::RelationInput::Pvm { .. } => PvmLayoutTemplate { p }.render(),
    }
    .expect("packaged verifier template must render");
    let deep = DeepTemplate { p }.render().expect("packaged verifier template must render");
    let wrapper = match &p.input.relation {
        super::RelationInput::Vm(_) => VmWrapperTemplate { p }.render(),
        super::RelationInput::Pvm { .. } => PvmWrapperTemplate {
            p,
            g: p.pvm_glue.as_ref().expect("validated PVM glue"),
        }
        .render(),
    }
    .expect("packaged verifier template must render");
    let mut artifacts = vec![
        RenderedArtifact {
            relative_path: evaluator_path.into(),
            body: EvaluatorTemplate { p }
                .render()
                .expect("packaged verifier template must render"),
            ownership: ArtifactOwnership::Managed,
        },
        RenderedArtifact {
            relative_path: ood_path.into(),
            body: OodTemplate { p }.render().expect("packaged verifier template must render"),
            ownership: ArtifactOwnership::Managed,
        },
        RenderedArtifact {
            relative_path: layout_path.into(),
            body: layout,
            ownership: ArtifactOwnership::Managed,
        },
        RenderedArtifact {
            relative_path: deep_path.into(),
            body: deep,
            ownership: ArtifactOwnership::Managed,
        },
        RenderedArtifact {
            relative_path: wrapper_path.into(),
            body: wrapper,
            ownership: ArtifactOwnership::ProtectedCheckOnly,
        },
    ];
    if let Some(g) = &p.pvm_glue {
        let aux_path = "crates/lib/core/asm/sys/pvm/aux_trace.masm";
        let public_path = "crates/lib/core/asm/sys/pvm/public_inputs.masm";
        artifacts.push(RenderedArtifact {
            relative_path: aux_path.into(),
            body: PvmAuxTemplate { p }.render().expect("packaged verifier template must render"),
            ownership: ArtifactOwnership::Managed,
        });
        artifacts.push(RenderedArtifact {
            relative_path: public_path.into(),
            body: PvmPublicTemplate { p, g }
                .render()
                .expect("packaged verifier template must render"),
            ownership: ArtifactOwnership::Managed,
        });
    }
    artifacts
}
