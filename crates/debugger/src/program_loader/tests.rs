use miden_assembly_syntax::ast::types::{CallConv, FunctionType, Type};
use miden_core::Felt;

use super::*;

#[test]
fn typed_arguments_use_the_entrypoint_abi() {
    let config = DebuggerConfig {
        args: vec!["4294967303".into(), "true".into()],
        ..Default::default()
    };
    let procedure = TypedProcedure::new(
        "entrypoint",
        FunctionType::new(CallConv::ComponentModel, [Type::U64, Type::I1], []),
    )
    .unwrap();

    let inputs = execution_inputs(&config, Some(&procedure)).unwrap();

    assert_eq!(
        &inputs.inputs.as_ref()[..3],
        [Felt::from_u32(7), Felt::from_u32(1), Felt::from_u32(1)]
    );
}

#[test]
fn untyped_arguments_keep_sequential_push_order() {
    let config = DebuggerConfig {
        args: vec!["3".into(), "4".into()],
        ..Default::default()
    };

    let inputs = execution_inputs(&config, None).unwrap();

    assert_eq!(&inputs.inputs.as_ref()[..2], [Felt::from_u32(4), Felt::from_u32(3)]);
}

pub(crate) fn test_package_input() -> crate::InputFile {
    use miden_assembly::{Assembler, DefaultSourceManager};
    use miden_core::serde::Serializable;

    let package = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .assemble_program("test", "begin push.3 push.4 add add end")
        .expect("test package should assemble");
    crate::InputFile::new("stdin://", Some(package.to_bytes().into_boxed_slice()))
}

#[cfg(any(feature = "script", feature = "dap"))]
pub(crate) fn invocation_test_package(
    ty: Option<miden_assembly_syntax::ast::types::Type>,
) -> Arc<miden_mast_package::Package> {
    use miden_assembly::{Assembler, DefaultSourceManager};
    use miden_assembly_syntax::{
        Parse,
        ast::{DebugVarInfo, DebugVarLocation, Instruction, Op},
    };
    use miden_debug_types::{SourceSpan, Span};
    let manager = Arc::new(DefaultSourceManager::default());
    let mut module = Parse::parse(
        "proc inner push.22 nop drop push.3 drop end proc outer push.11 nop drop exec.inner \
         push.4 drop end begin exec.outer push.5 drop end",
        false,
        manager.clone(),
    )
    .unwrap();
    for procedure in module.procedures_mut() {
        for operation in procedure.body_mut().iter_mut() {
            if let Op::Inst(instruction) = operation
                && matches!(instruction.inner(), Instruction::Nop)
            {
                let mut variable = DebugVarInfo::new("n", DebugVarLocation::Stack(0));
                if let Some(ty) = &ty {
                    variable.set_ty(ty.clone(), None);
                }
                *instruction = Span::new(SourceSpan::default(), Instruction::DebugVar(variable));
            }
        }
    }
    Assembler::new(manager).assemble_program("invocations", module).unwrap().into()
}
