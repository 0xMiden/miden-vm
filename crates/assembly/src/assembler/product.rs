use miden_mast_package::{
    Dependency,
    debug_info::{
        DebugErrorMessage, DebugErrorMessagesSection, DebugSourceAsmOp, DebugSourceGraphSection,
        DebugSourceMapSection, DebugSourceNode, DebugSourceNodeId, DebugSourceVar,
    },
};

use super::*;
use crate::mast_forest_builder::SourceDebugGraph;

pub struct AssemblyProduct {
    package: Box<Package>,
    kernel_package: Option<Arc<Package>>,
    debug_info: DebugInfoSections,
    source_graph: SourceDebugGraph,
    source_id_by_ref: BTreeMap<SourceNodeRef, SourceNodeId>,
    node_id_by_ref: BTreeMap<MastNodeRef, MastNodeId>,
}

impl AssemblyProduct {
    pub(super) fn new(
        package: Box<Package>,
        kernel: Option<Arc<Package>>,
        debug_info: DebugInfoSections,
        source_graph: SourceDebugGraph,
        source_id_by_ref: BTreeMap<SourceNodeRef, SourceNodeId>,
        node_id_by_ref: BTreeMap<MastNodeRef, MastNodeId>,
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
            source_id_by_ref,
            node_id_by_ref,
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

    pub fn into_artifact(self, emit_debug_info: bool) -> Result<Box<Package>, Report> {
        let Self {
            mut package,
            kernel_package,
            debug_info,
            source_graph,
            source_id_by_ref,
            node_id_by_ref,
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

        if !emit_debug_info {
            return Ok(package);
        }

        // Section: debug info
        let DebugInfoSections {
            debug_sources_section,
            debug_function_infos,
            debug_function_strings,
            debug_types_section,
        } = debug_info;
        {
            let mut debug_functions_section =
                miden_mast_package::debug_info::DebugFunctionsSection::new();
            debug_functions_section.strings = debug_function_strings;
            debug_functions_section.functions.reserve_exact(debug_function_infos.len());
            debug_functions_section
                .functions
                .extend(debug_function_infos.into_iter().map(|pfi| {
                    let node = node_id_by_ref[&pfi.node];
                    let source_node = pfi
                        .source_node
                        .map(|sn| u32::from(source_id_by_ref[&sn]))
                        .map(DebugSourceNodeId::from);
                    miden_mast_package::debug_info::DebugFunctionInfo {
                        node,
                        source_node,
                        name_idx: pfi.name_idx,
                        linkage_name_idx: pfi.linkage_name_idx,
                        file_idx: pfi.file_idx,
                        line: pfi.line,
                        column: pfi.column,
                        type_idx: pfi.type_idx,
                    }
                }));
            package
                .sections
                .push(Section::new(SectionId::DEBUG_FUNCTIONS, debug_functions_section.to_bytes()));
            package
                .sections
                .push(Section::new(SectionId::DEBUG_SOURCES, debug_sources_section.to_bytes()));
            package
                .sections
                .push(Section::new(SectionId::DEBUG_TYPES, debug_types_section.to_bytes()));
        }

        package.sections.push(Section::new(
            SectionId::DEBUG_SOURCE_GRAPH,
            source_graph_section(&source_graph)?.to_bytes(),
        ));
        package.sections.push(Section::new(
            SectionId::DEBUG_SOURCE_MAP,
            source_map_section(&source_graph)?.to_bytes(),
        ));

        let error_messages = error_messages_section(&source_graph);
        if !error_messages.is_empty() {
            package
                .sections
                .push(Section::new(SectionId::DEBUG_ERROR_MESSAGES, error_messages.to_bytes()));
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
                Ok(DebugSourceNode::new(
                    source_node.exec_node(),
                    source_node
                        .children()
                        .iter()
                        .map(|child| DebugSourceNodeId::from(u32::from(*child)))
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
            .map(|root| DebugSourceNodeId::from(u32::from(*root)))
            .collect(),
    ))
}

fn source_map_section(source_graph: &SourceDebugGraph) -> Result<DebugSourceMapSection, Report> {
    let mut asm_ops = Vec::new();
    let mut debug_vars = Vec::new();

    for (source_index, source_node) in source_graph.nodes().as_slice().iter().enumerate() {
        let source_node_id = DebugSourceNodeId::from(source_index as u32);
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

fn error_messages_section(source_graph: &SourceDebugGraph) -> DebugErrorMessagesSection {
    DebugErrorMessagesSection::from_parts(
        source_graph
            .error_messages()
            .iter()
            .map(|(err_code, message)| DebugErrorMessage::new(*err_code, message.clone()))
            .collect(),
    )
}
