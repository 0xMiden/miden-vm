//! Private typed ABI package builder for lit fixtures.

use std::{env, io, path::PathBuf, sync::Arc};

use miden_assembly::{Assembler, DefaultSourceManager, SourceManager};
use miden_assembly_syntax::{
    Parse,
    ast::{
        DebugLocationExpression, DebugLocationExpressionOp, DebugVarInfo, DebugVarLocation,
        Instruction, Module, Op,
        types::{ArrayType, CallConv, FunctionType, StructType, Type},
    },
    debuginfo::{Span, Spanned},
};
use miden_mast_package::{Package, PackageExport};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (input_path, output_path) = parse_args()?;
    let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
    let mut module = input_path.as_path().parse(false, source_manager.clone())?;
    add_abi_debug_vars(&mut module)?;

    let package = Assembler::new(source_manager).assemble_program("abi-types", module)?;
    let package = with_typed_entrypoint(*package)?;
    package.write_to_file(&output_path)?;
    Ok(())
}

fn parse_args() -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    match args.as_slice() {
        [_, input, flag, output] if flag == "-o" || flag == "--output" => {
            Ok((PathBuf::from(input), PathBuf::from(output)))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: compile-abi-fixture <file.masm> -o <file.masp>",
        )
        .into()),
    }
}

fn add_abi_debug_vars(module: &mut Module) -> Result<(), Box<dyn std::error::Error>> {
    let entrypoint = module
        .procedures_mut()
        .find(|procedure| procedure.is_entrypoint())
        .ok_or_else(|| io::Error::other("ABI fixture has no entrypoint"))?;
    let mut variables = abi_debug_vars()?.into_iter();

    for op in entrypoint.body_mut().iter_mut() {
        if !matches!(op, Op::Inst(instruction) if matches!(**instruction.as_ref(), Instruction::Nop))
        {
            continue;
        }
        let Some(variable) = variables.next() else {
            break;
        };
        *op = Op::Inst(Span::new(op.span(), Instruction::DebugVar(variable)));
    }

    if variables.next().is_some() {
        return Err(io::Error::other("ABI fixture is missing debug variable markers").into());
    }
    Ok(())
}

fn with_typed_entrypoint(package: Package) -> Result<Package, Box<dyn std::error::Error>> {
    let entrypoint = package.entrypoint().ok_or_else(|| io::Error::other("missing entrypoint"))?;
    let mut export = package
        .manifest
        .get_export(entrypoint.as_ref())
        .and_then(PackageExport::as_procedure)
        .cloned()
        .ok_or_else(|| io::Error::other("missing entrypoint export"))?;
    export.signature = Some(FunctionType::new(CallConv::ComponentModel, [Type::U64], [Type::U64]));
    let dependencies = package.manifest.dependencies().cloned().collect::<Vec<_>>();
    let mut typed = Package::create(
        package.name.clone(),
        package.version.clone(),
        package.kind,
        package.mast_forest().clone(),
        [PackageExport::Procedure(export)],
        dependencies,
    )?;
    typed.description = package.description;
    typed.sections = package.sections;
    Ok(typed)
}

fn abi_debug_vars() -> Result<Vec<DebugVarInfo>, Box<dyn std::error::Error>> {
    let account_ty = Type::from(StructType::named(
        Arc::from("miden:base/core-types@1.0.0/account-id"),
        [(Arc::from("prefix"), Type::Felt), (Arc::from("suffix"), Type::Felt)],
    ));
    let array_ty = Type::Array(Arc::new(ArrayType::new(Type::U32, 3)));
    let point_ty =
        Type::from(StructType::new([(Arc::from("x"), Type::Felt), (Arc::from("y"), Type::Felt)]));
    let record_ty = Type::from(StructType::new([
        (Arc::from("tiny"), Type::U8),
        (Arc::from("half"), Type::U16),
    ]));

    Ok(vec![
        typed_memory_var("account", 130, account_ty),
        typed_memory_var("array", 110, array_ty),
        typed_memory_var("enabled", 150, Type::I1),
        typed_expression_var(
            "record",
            vec![DebugLocationExpressionOp::ConstU64(641), DebugLocationExpressionOp::DerefBytes],
            record_ty,
        )?,
        typed_memory_var("point", 100, point_ty),
        typed_stack_var("snapshot", 0, Type::U64),
        typed_expression_var(
            "wide",
            vec![DebugLocationExpressionOp::ConstU64(643), DebugLocationExpressionOp::DerefBytes],
            Type::U64,
        )?,
    ])
}

fn typed_memory_var(name: &str, address: u32, ty: Type) -> DebugVarInfo {
    let mut variable = DebugVarInfo::new(name, DebugVarLocation::Memory(address));
    variable.set_ty(ty, None);
    variable
}

fn typed_stack_var(name: &str, position: u8, ty: Type) -> DebugVarInfo {
    let mut variable = DebugVarInfo::new(name, DebugVarLocation::Stack(position));
    variable.set_ty(ty, None);
    variable
}

fn typed_expression_var(
    name: &str,
    operations: Vec<DebugLocationExpressionOp>,
    ty: Type,
) -> Result<DebugVarInfo, Box<dyn std::error::Error>> {
    let expression = DebugLocationExpression::new(operations)?;
    let mut variable = DebugVarInfo::new(name, DebugVarLocation::Expression(expression));
    variable.set_ty(ty, None);
    Ok(variable)
}
