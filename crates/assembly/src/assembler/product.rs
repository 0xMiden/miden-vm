use miden_mast_package::{
    Dependency,
    debug_info::{
        DebugSourceAsmOp, DebugSourceGraphSection, DebugSourceMapSection, DebugSourceMastNode,
        DebugSourceMastNodeId, DebugSourceVar,
    },
};

use super::*;
use crate::mast_forest_builder::SourceDebugGraph;

pub struct AssemblyProduct {
    package: Box<Package>,
    kernel_package: Option<Arc<Package>>,
    debug_info: Option<DebugInfoSections>,
    source_graph: Option<SourceDebugGraph>,
}

impl AssemblyProduct {
    pub(super) fn new(
        package: Box<Package>,
        kernel: Option<Arc<Package>>,
        debug_info: Option<DebugInfoSections>,
        source_graph: Option<SourceDebugGraph>,
    ) -> Self {
        assert!(
            kernel.is_none() || !package.is_kernel(),
            "kernels cannot depend on another kernel"
        );
        Self {
            package,
            kernel_package: kernel,
            debug_info,
            source_graph,
        }
    }

    #[cfg_attr(not(feature = "std"), expect(unused))]
    pub fn extend_dependencies(
        &mut self,
        deps: impl IntoIterator<Item = Dependency>,
    ) -> Result<(), Report> {
        for dep in deps {
            self.package.manifest.add_dependency(dep).map_err(Report::msg)?;
        }

        Ok(())
    }

    pub fn into_artifact(self) -> Result<Box<Package>, Report> {
        let Self {
            mut package,
            kernel_package,
            debug_info,
            source_graph,
        } = self;
        // Section: embedded kernel package
        if package.is_program()
            && let Some(kernel_package) = kernel_package
        {
            package.sections.push(linked_kernel_package_section(kernel_package.as_ref()));
            if let Some(kernel_dep) =
                package.manifest.dependencies().find(|dep| dep.id() == &kernel_package.name)
            {
                if kernel_dep.digest != kernel_package.digest()
                    || kernel_dep.kind != kernel_package.kind
                    || kernel_dep.version() != &kernel_package.version
                {
                    return Err(Report::msg(format!(
                        "unable to register kernel dependency: '{}' already exists as a dependency, but with different metadata than the actual kernel package",
                        kernel_package.name
                    )));
                }
            } else {
                package
                    .manifest
                    .add_dependency(Dependency {
                        name: kernel_package.name.clone(),
                        kind: kernel_package.kind,
                        version: kernel_package.version.clone(),
                        digest: kernel_package.digest(),
                    })
                    .map_err(|err| {
                        Report::msg(format!("unable to register kernel dependency: {err}"))
                    })?;
            }
        }

        // Section: debug info
        if let Some(DebugInfoSections {
            debug_sources_section,
            debug_functions_section,
            debug_types_section,
        }) = debug_info
        {
            package
                .sections
                .push(Section::new(SectionId::DEBUG_SOURCES, debug_sources_section.to_bytes()));
            package
                .sections
                .push(Section::new(SectionId::DEBUG_FUNCTIONS, debug_functions_section.to_bytes()));
            package
                .sections
                .push(Section::new(SectionId::DEBUG_TYPES, debug_types_section.to_bytes()));
        }
        if let Some(source_graph) = source_graph {
            package.sections.push(Section::new(
                SectionId::DEBUG_SOURCE_GRAPH,
                source_graph_section(&source_graph)?.to_bytes(),
            ));
            package.sections.push(Section::new(
                SectionId::DEBUG_SOURCE_MAP,
                source_map_section(&source_graph)?.to_bytes(),
            ));
        }
        Ok(package)
    }
}

fn linked_kernel_package_section(package: &Package) -> Section {
    Section::new(SectionId::KERNEL, package.to_bytes())
}

fn source_graph_section(
    source_graph: &SourceDebugGraph,
) -> Result<DebugSourceGraphSection, Report> {
    Ok(DebugSourceGraphSection::from_parts(
        source_graph
            .nodes()
            .as_slice()
            .iter()
            .map(|source_node| {
                Ok(DebugSourceMastNode::new(
                    source_node.exec_node(),
                    source_node
                        .children()
                        .iter()
                        .map(|child| DebugSourceMastNodeId::from(u32::from(*child)))
                        .collect(),
                    source_node.op_start().try_into().map_err(|_| {
                        Report::msg("source node start operation index exceeds u32")
                    })?,
                    source_node
                        .op_end()
                        .try_into()
                        .map_err(|_| Report::msg("source node end operation index exceeds u32"))?,
                ))
            })
            .collect::<Result<_, Report>>()?,
        source_graph
            .roots()
            .iter()
            .map(|root| DebugSourceMastNodeId::from(u32::from(*root)))
            .collect(),
    ))
}

fn source_map_section(source_graph: &SourceDebugGraph) -> Result<DebugSourceMapSection, Report> {
    let mut asm_ops = Vec::new();
    let mut debug_vars = Vec::new();

    for (source_index, source_node) in source_graph.nodes().as_slice().iter().enumerate() {
        let source_node_id = DebugSourceMastNodeId::from(source_index as u32);
        for (op_idx, asm_op) in source_node.asm_ops() {
            asm_ops.push(DebugSourceAsmOp::new(
                source_node_id,
                (*op_idx)
                    .try_into()
                    .map_err(|_| Report::msg("source asm-op index exceeds u32"))?,
                asm_op.location().cloned(),
                asm_op.context_name().to_string(),
                asm_op.op().to_string(),
                asm_op.num_cycles(),
            ));
        }
        for (op_idx, debug_var) in source_node.debug_vars() {
            debug_vars.push(DebugSourceVar::new(
                source_node_id,
                (*op_idx)
                    .try_into()
                    .map_err(|_| Report::msg("source debug-var index exceeds u32"))?,
                debug_var.clone(),
            ));
        }
    }

    Ok(DebugSourceMapSection::from_parts(asm_ops, debug_vars))
}
