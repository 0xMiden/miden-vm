//! Deterministic shared runtime universe, emitted once outside relation projections.
use std::{collections::BTreeSet, string::String, vec::Vec};

use askama::Template;

use super::{
    ood::RowGroup,
    proof_order::{ProofOrderPlan, SortStep},
    *,
};
#[derive(Template)]
#[template(path = "verifier/shared_parameters.masm", escape = "none")]
struct Parameters {
    abi: &'static [runtime::ParameterField],
}
#[derive(Template)]
#[template(path = "verifier/shared_pipes.masm", escape = "none")]
struct Pipes {
    base_blocks: BTreeSet<u32>,
    ext_blocks: BTreeSet<u32>,
    ace_blocks: BTreeSet<u32>,
}
#[derive(Template)]
#[template(path = "verifier/shared_evaluator.masm", escape = "none")]
struct Evaluator<'a> {
    abi: &'static [runtime::ParameterField],
    counts: &'a [&'a V1RenderPlan],
}
#[derive(Template)]
#[template(path = "verifier/shared_ood.masm", escape = "none")]
struct Ood<'a> {
    abi: &'static [runtime::ParameterField],
    counts: &'a [&'a V1RenderPlan],
}
#[derive(Template)]
#[template(path = "verifier/shared_proof_order.masm", escape = "none")]
struct ProofOrder {
    proofs: Vec<ProofOrderPlan>,
}
#[derive(Template)]
#[template(path = "verifier/shared_deep.masm", escape = "none")]
struct Deep {
    abi: &'static [runtime::ParameterField],
}
#[derive(Template)]
#[template(path = "verifier/shared_fixed.masm", escape = "none")]
struct Fixed<'a> {
    g: &'a pvm_glue::PvmGluePlan,
}
#[derive(Template)]
#[template(path = "verifier/shared_aux.masm", escape = "none")]
struct Aux<'a> {
    pvm_counts: &'a [&'a V1RenderPlan],
}
#[derive(Template)]
#[template(path = "verifier/shared_public.masm", escape = "none")]
struct Public<'a> {
    abi: &'static [runtime::ParameterField],
    g: &'a pvm_glue::PvmGluePlan,
}
fn rendered(result: askama::Result<String>) -> String {
    result.expect("packaged shared verifier template must render")
}
pub fn render(plans: &[V1RenderPlan]) -> Vec<RenderedArtifact> {
    assert_eq!(plans.len(), 9, "shared universe requires VM and all eight masks");
    let mut masks: Vec<_> = plans
        .iter()
        .filter_map(|p| p.pvm_glue.as_ref().map(|g| g.variant_mask))
        .collect();
    masks.sort();
    assert_eq!(
        masks,
        [0, 1, 2, 3, 4, 5, 6, 7],
        "shared universe binds every full mask, not just AIR counts"
    );
    let mut counts: Vec<_> = plans.iter().collect();
    counts.sort_by_key(|p| p.num_airs);
    counts.dedup_by_key(|p| p.num_airs);
    assert_eq!(counts.iter().map(|p| p.num_airs).collect::<Vec<_>>(), [4, 8, 9, 10, 11, 12]);
    let mut pipes = Pipes {
        base_blocks: BTreeSet::new(),
        ext_blocks: BTreeSet::new(),
        ace_blocks: BTreeSet::new(),
    };
    for p in plans {
        assert_eq!(p.ood.row_felts, 2 * p.layout.query_row_felts);
        pipes.ace_blocks.insert(p.stream_blocks);
        for g in &p.deep.groups {
            pipes.base_blocks.insert(g.blocks);
        }
        for h in &p.ood.helpers {
            pipes.ext_blocks.insert(h.blocks);
        }
        for g in [&p.deep.groups[0], &p.deep.groups[3]] {
            pipes.ext_blocks.insert(2 * g.blocks);
        }
    }
    let proofs = counts
        .iter()
        .map(|p| {
            let mut c = p.ood.proof_order.config.clone();
            c.procedure_name = std::format!("stage_proof_order_maps_{}", p.num_airs);
            ProofOrderPlan::new(&c)
        })
        .collect();
    let g = plans.iter().find(|p| p.num_airs == 12).unwrap().pvm_glue.as_ref().unwrap();
    for p in plans {
        if let Some(candidate) = &p.pvm_glue {
            assert_eq!(candidate.uints, g.uints, "fixed uint environment differs by mask");
            assert_eq!(candidate.groups, g.groups, "fixed curve environment differs by mask");
            assert_eq!(
                (candidate.uint_bus_scale, candidate.ec_bus_scale, candidate.max_message_width),
                (g.uint_bus_scale, g.ec_bus_scale, g.max_message_width)
            );
        }
        let representative = counts.iter().find(|q| q.num_airs == p.num_airs).unwrap();
        assert_eq!(p.ood.row_groups.len(), 4);
        for (index, (actual, common)) in
            p.ood.row_groups.iter().zip(&representative.ood.row_groups).enumerate()
        {
            match (actual, common) {
                (RowGroup::Sole { destination, .. }, RowGroup::Sole { .. }) => {
                    assert!(if index == 0 {
                        *destination == 0
                    } else {
                        index == 3 && *destination > 0
                    })
                },
                (RowGroup::Full { calls: a }, RowGroup::Full { calls: b }) => {
                    assert_eq!(a, b, "same-count OOD dispatch differs")
                },
                _ => panic!("incompatible shared OOD profile"),
            }
        }
    }
    let bodies = [
        (
            "crates/lib/core/asm/sys/verifier/parameters.masm",
            rendered(Parameters { abi: runtime::FIELDS }.render()),
        ),
        ("crates/lib/core/asm/sys/verifier/pipes.masm", rendered(pipes.render())),
        (
            "crates/lib/core/asm/sys/verifier/evaluator.masm",
            rendered(Evaluator { counts: &counts, abi: runtime::FIELDS }.render()),
        ),
        (
            "crates/lib/core/asm/sys/verifier/ood.masm",
            rendered(Ood { counts: &counts, abi: runtime::FIELDS }.render()),
        ),
        (
            "crates/lib/core/asm/sys/verifier/proof_order.masm",
            rendered(ProofOrder { proofs }.render()),
        ),
        (
            "crates/lib/core/asm/sys/verifier/deep.masm",
            rendered(Deep { abi: runtime::FIELDS }.render()),
        ),
        ("crates/lib/core/asm/sys/verifier/fixed.masm", rendered(Fixed { g }.render())),
        (
            "crates/lib/core/asm/sys/verifier/pvm_aux.masm",
            rendered(Aux { pvm_counts: &counts[1..] }.render()),
        ),
        (
            "crates/lib/core/asm/sys/verifier/pvm_public.masm",
            rendered(Public { g, abi: runtime::FIELDS }.render()),
        ),
    ];
    bodies
        .into_iter()
        .map(|(relative_path, body)| RenderedArtifact {
            relative_path: relative_path.into(),
            body,
            ownership: ArtifactOwnership::Managed,
        })
        .collect()
}
