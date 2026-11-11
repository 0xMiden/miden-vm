//! Private package builder for lit fixtures.

use std::{
    env, io,
    path::{Path, PathBuf},
    sync::Arc,
};

use miden_assembly::{Assembler, DefaultSourceManager, SourceManager};
use miden_assembly_syntax::Parse;
use miden_debug_types::{ColumnNumber, FileLineCol, LineNumber, Uri};
use miden_mast_package::{
    Package, Section, SectionId,
    debug_info::{
        DebugFunctionInfo, DebugSourceInlineCall, DebugSourceNodeId, PackageDebugInfoBuilder,
    },
};

struct InlineCallSpec {
    name: String,
    line: LineNumber,
    column: ColumnNumber,
}

struct CompileOptions {
    input_path: PathBuf,
    output_path: PathBuf,
    inject_frame_base_test_vars: bool,
    inline_calls: Vec<InlineCallSpec>,
}

const USAGE: &str = "Usage: compile-masm <file.masm> [-o <file.masp>] \
                     [--inject-frame-base-test-vars] [--inline-call <name,line,column>]...";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let CompileOptions {
        input_path,
        output_path,
        inject_frame_base_test_vars,
        inline_calls,
    } = parse_args()?;
    let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
    let assembler = Assembler::new(source_manager.clone());
    let mut package = if inject_frame_base_test_vars {
        let mut module = input_path.as_path().parse(false, source_manager.clone())?;
        inject_frame_base_test_vars_into(&mut module)?;
        assembler.assemble_program("program", module)?
    } else {
        assembler.assemble_program("program", input_path.as_path())?
    };
    if !inline_calls.is_empty() {
        add_inline_calls(&mut package, &input_path, &inline_calls, source_manager.as_ref())?;
    }
    package.write_to_file(&output_path)?;
    Ok(())
}

fn inject_frame_base_test_vars_into(
    module: &mut miden_assembly::ast::Module,
) -> Result<(), Box<dyn std::error::Error>> {
    use miden_assembly_syntax::{
        ast::{DebugFrameBase, DebugVarInfo, DebugVarLocation, Instruction, Op},
        debuginfo::{SourceSpan, Span},
    };

    let procedure = module
        .procedures_mut()
        .find(|procedure| !procedure.is_entrypoint() && procedure.num_locals() == 1)
        .ok_or("frame-base test fixture requires a non-entrypoint procedure with one local")?;

    for (name, base) in [
        ("local_frame", DebugFrameBase::Local(-4)),
        ("memory_frame", DebugFrameBase::Memory(100)),
    ] {
        let location = DebugVarLocation::ResolvedFrameBase {
            base,
            byte_offset: 4,
        };
        let debug_var = DebugVarInfo::new(name, location);
        procedure
            .body_mut()
            .push(Op::Inst(Span::new(SourceSpan::default(), Instruction::DebugVar(debug_var))));
    }
    procedure
        .body_mut()
        .push(Op::Inst(Span::new(SourceSpan::default(), Instruction::LocLoad(0u16.into()))));
    procedure
        .body_mut()
        .push(Op::Inst(Span::new(SourceSpan::default(), Instruction::Drop)));

    Ok(())
}

fn parse_args() -> Result<CompileOptions, Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let input_path = args.next().map(PathBuf::from).ok_or_else(|| invalid_argument(USAGE))?;
    let mut output_path = None;
    let mut inject_frame_base_test_vars = false;
    let mut inline_calls = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-o" | "--output" => {
                let output = args
                    .next()
                    .ok_or_else(|| invalid_argument(format!("{arg} requires a path")))?;
                output_path = Some(PathBuf::from(output));
            }
            "--inline-call" => {
                let spec = args
                    .next()
                    .ok_or_else(|| invalid_argument("--inline-call requires name,line,column"))?;
                inline_calls.push(parse_inline_call(&spec)?);
            }
            "--inject-frame-base-test-vars" => inject_frame_base_test_vars = true,
            _ => return Err(invalid_argument(format!("unrecognized argument '{arg}'")).into()),
        }
    }

    let output_path = output_path.unwrap_or_else(|| input_path.with_extension(Package::EXTENSION));
    Ok(CompileOptions {
        input_path,
        output_path,
        inject_frame_base_test_vars,
        inline_calls,
    })
}

fn parse_inline_call(spec: &str) -> Result<InlineCallSpec, Box<dyn std::error::Error>> {
    let mut parts = spec.rsplitn(3, ',');
    let column = parts
        .next()
        .ok_or_else(|| invalid_argument("inline call is missing a column"))?
        .parse::<u32>()?;
    let line = parts
        .next()
        .ok_or_else(|| invalid_argument("inline call is missing a line"))?
        .parse::<u32>()?;
    let name = parts
        .next()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| invalid_argument("inline call is missing a name"))?;

    Ok(InlineCallSpec {
        name: name.to_string(),
        line: LineNumber::new(line)
            .ok_or_else(|| invalid_argument("inline call line must be greater than zero"))?,
        column: ColumnNumber::new(column)
            .ok_or_else(|| invalid_argument("inline call column must be greater than zero"))?,
    })
}

fn add_inline_calls(
    package: &mut Package,
    input_path: &Path,
    specs: &[InlineCallSpec],
    source_manager: &dyn SourceManager,
) -> Result<(), Box<dyn std::error::Error>> {
    let debug_info = package
        .debug_info()?
        .ok_or_else(|| io::Error::other("assembled package has no debug information"))?;
    let mut debug_info = PackageDebugInfoBuilder::from(Box::new(debug_info));
    let source_uri = Uri::from(input_path);
    let mut callees = Vec::with_capacity(specs.len());
    for spec in specs {
        let call_site = FileLineCol::new(source_uri.clone(), spec.line, spec.column);
        let call_site_span = source_manager.file_line_col_to_span(call_site).ok_or_else(|| {
            invalid_argument(format!(
                "inline call location {}:{} is outside {}",
                spec.line,
                spec.column,
                input_path.display()
            ))
        })?;
        let call_site_idx = debug_info.add_location(source_manager.location(call_site_span)?);
        let file_idx = debug_info.debug_info().locations()[call_site_idx].file_idx;
        let name_idx = debug_info.add_string(Arc::from(spec.name.as_str()));
        let callee_idx = debug_info.add_function(DebugFunctionInfo::new(
            None,
            name_idx,
            file_idx,
            spec.line,
            spec.column,
            Default::default(),
        ));
        callees.push((callee_idx, call_site_idx));
    }

    let source_nodes = debug_info
        .debug_info()
        .nodes()
        .iter()
        .enumerate()
        .map(|(source_index, source_node)| {
            let source_node_id = u32::try_from(source_index)
                .map(DebugSourceNodeId::from)
                .map_err(|_| io::Error::other("too many debug source nodes"))?;
            Ok((source_node_id, source_node.op_start..source_node.op_end))
        })
        .collect::<Result<Vec<_>, io::Error>>()?;
    for (source_node_id, operation_range) in source_nodes {
        // Inject source-level frames inside the assembler's enclosing exec frames.
        debug_info[source_node_id].inline_calls.splice(
            0..0,
            callees
                .iter()
                .copied()
                .map(|(callee_idx, call_site_idx)| DebugSourceInlineCall {
                    op_idx: operation_range.start,
                    op_end: operation_range.end,
                    callee_idx,
                    loc_idx: call_site_idx,
                }),
        );
    }

    replace_section(
        package,
        SectionId::DEBUG_INFO,
        debug_info.build().to_bytes_with_standard_limits()?,
    );
    Ok(())
}

fn replace_section(package: &mut Package, id: SectionId, data: Vec<u8>) {
    package.sections.retain(|section| section.id != id);
    package.sections.push(Section::new(id, data));
}

fn invalid_argument(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
