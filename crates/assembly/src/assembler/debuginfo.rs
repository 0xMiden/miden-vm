use alloc::sync::Arc;

use miden_mast_package::debug_info::{
    DebugFieldInfo, DebugFunctionsSection, DebugPrimitiveType, DebugSourcesSection, DebugTypeIdx,
    DebugTypeInfo, DebugTypesSection,
};

use crate::{
    Procedure,
    ast::{
        TypeExpr,
        types::{StructType, Type},
    },
    debuginfo::SourceManager,
    diagnostics::Report,
};

// DEBUG INFO SECTIONS
// ================================================================================================

#[derive(Default, Clone)]
pub struct DebugInfoSections {
    /// The debug function section maintained by the assembler during assembly
    pub debug_functions_section: DebugFunctionsSection,
    /// The debug type section maintained by the assembler during assembly
    pub debug_types_section: DebugTypesSection,
    /// The debug sources section maintained by the assembler during assembly
    pub debug_sources_section: DebugSourcesSection,
}

impl DebugInfoSections {
    pub fn register_procedure_debug_info(
        &mut self,
        procedure: &Procedure,
        source_manager: &dyn SourceManager,
    ) -> Result<(), Report> {
        if let Ok(file_line_col) = source_manager.file_line_col(*procedure.span()) {
            let path_id =
                self.debug_sources_section.add_string(Arc::from(file_line_col.uri.path()));
            let file_id = self
                .debug_sources_section
                .add_file(miden_mast_package::debug_info::DebugFileInfo::new(path_id));
            let name = Arc::<str>::from(procedure.path().as_str());
            let name_id = self.debug_functions_section.add_string(name.clone());
            let type_index = if let Some(signature) = procedure.signature() {
                Some(register_debug_type(
                    &mut self.debug_types_section,
                    Some(name),
                    None,
                    &Type::Function(signature),
                )?)
            } else {
                None
            };
            let func_info = miden_mast_package::debug_info::DebugFunctionInfo::new(
                name_id,
                file_id,
                file_line_col.line,
                file_line_col.column,
            )
            .with_mast_root(procedure.mast_root());
            let func_info = if let Some(type_index) = type_index {
                func_info.with_type(type_index)
            } else {
                func_info
            };
            self.debug_functions_section.add_function(func_info);
        }

        Ok(())
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// This visits a type exported or used in a procedure signature, and emits records to the
/// provided debug types section corresponding to it.
///
/// The declared name and type expression can be optionally provided to give additional useful
/// context to the debug info type produced, e.g. type name, field names, etc.
fn register_debug_type(
    debug_types_section: &mut DebugTypesSection,
    declared_name: Option<Arc<str>>,
    declared_ty: Option<&TypeExpr>,
    ty: &Type,
) -> Result<DebugTypeIdx, Report> {
    Ok(match ty {
        Type::I1 => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Bool))
        },
        Type::I8 => debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::I8)),
        Type::U8 => debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U8)),
        Type::I16 => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::I16))
        },
        Type::U16 => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U16))
        },
        Type::I32 => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::I32))
        },
        Type::U32 => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U32))
        },
        Type::I64 => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::I64))
        },
        Type::U64 => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U64))
        },
        Type::I128 => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::I128))
        },
        Type::U128 => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U128))
        },
        Type::Felt => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Felt))
        },
        Type::F64 => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::F64))
        },
        Type::U256 | Type::Unknown => debug_types_section.add_type(DebugTypeInfo::Unknown),
        Type::Never => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Void))
        },
        Type::Ptr(ptr) => {
            let pointee_name = declared_ty.and_then(|t| match t {
                TypeExpr::Ptr(p) => match p.pointee.as_ref() {
                    TypeExpr::Ref(p) => Some(Arc::from(p.inner().as_str())),
                    _ => None,
                },
                _ => None,
            });
            let pointee_decl = declared_ty.and_then(|t| match t {
                TypeExpr::Ptr(p) => Some(p.pointee.as_ref()),
                _ => None,
            });
            let pointee_type_idx = register_debug_type(
                debug_types_section,
                pointee_name,
                pointee_decl,
                ptr.pointee(),
            )?;
            debug_types_section.add_type(DebugTypeInfo::Pointer { pointee_type_idx })
        },
        Type::Array(array) => {
            let element_name = declared_ty.and_then(|t| match t {
                TypeExpr::Array(array) => match array.elem.as_ref() {
                    TypeExpr::Ref(t) => Some(Arc::from(t.inner().as_str())),
                    _ => None,
                },
                _ => None,
            });
            let element_decl = declared_ty.and_then(|t| match t {
                TypeExpr::Ptr(p) => Some(p.pointee.as_ref()),
                _ => None,
            });
            let element_type_idx = register_debug_type(
                debug_types_section,
                element_name,
                element_decl,
                array.element_type(),
            )?;
            let count =
                u32::try_from(array.len()).map_err(|_| Report::msg("array type is too large"))?;
            debug_types_section
                .add_type(DebugTypeInfo::Array { element_type_idx, count: Some(count) })
        },
        Type::List(ty) => {
            let pointee_name = declared_ty.and_then(|t| match t {
                TypeExpr::Ptr(p) => match p.pointee.as_ref() {
                    TypeExpr::Ref(p) => Some(Arc::from(p.inner().as_str())),
                    _ => None,
                },
                _ => None,
            });
            let pointee_decl = declared_ty.and_then(|t| match t {
                TypeExpr::Ptr(p) => Some(p.pointee.as_ref()),
                _ => None,
            });
            let pointee_ty =
                register_debug_type(debug_types_section, pointee_name, pointee_decl, ty)?;
            let usize_ty =
                debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U32));
            let pointer_ty = debug_types_section
                .add_type(DebugTypeInfo::Pointer { pointee_type_idx: pointee_ty });
            let name_idx = debug_types_section
                .add_string(declared_name.unwrap_or_else(|| format!("list<{ty}>").into()));
            let ptr = DebugFieldInfo {
                name_idx: debug_types_section.add_string("ptr".into()),
                type_idx: pointer_ty,
                offset: 0,
            };
            let len = DebugFieldInfo {
                name_idx: debug_types_section.add_string("len".into()),
                type_idx: usize_ty,
                offset: 4,
            };
            debug_types_section.add_type(DebugTypeInfo::Struct {
                name_idx,
                size: 8,
                fields: vec![ptr, len],
            })
        },
        Type::Struct(struct_ty) => {
            let declared_field_tys = declared_ty.and_then(|t| match t {
                TypeExpr::Struct(t) => Some(&t.fields),
                _ => None,
            });
            let mut fields = vec![];
            for (i, field) in struct_ty.fields().iter().enumerate() {
                let decl = declared_field_tys.and_then(|fields| fields.get(i));
                let declared_name = decl.map(|decl| decl.name.clone().into_inner());
                let declared_ty = decl.map(|decl| &decl.ty);
                let type_idx = register_debug_type(
                    debug_types_section,
                    declared_name.clone(),
                    declared_ty,
                    &field.ty,
                )?;
                let name_idx = debug_types_section
                    .add_string(declared_name.unwrap_or_else(|| format!("{i}").into()));
                fields.push(DebugFieldInfo { name_idx, type_idx, offset: field.offset });
            }
            let name_idx = debug_types_section
                .add_string(declared_name.clone().unwrap_or_else(|| "<anon>".into()));
            let size = u32::try_from(struct_ty.size()).map_err(|_| {
                if let Some(declared_name) = declared_name.as_ref() {
                    Report::msg(format!(
                        "invalid struct type '{declared_name}': struct is too large"
                    ))
                } else {
                    Report::msg("invalid struct type: struct is too large")
                }
            })?;
            debug_types_section.add_type(DebugTypeInfo::Struct { name_idx, size, fields })
        },
        Type::Enum(enum_ty) => {
            let discrim_ty =
                register_debug_type(debug_types_section, None, None, enum_ty.discriminant())?;
            if enum_ty.is_c_like() {
                discrim_ty
            } else {
                // TODO(pauls): We need to figure out how best to represent this in terms of DWARF
                // debug info
                debug_types_section.add_type(DebugTypeInfo::Unknown)
            }
        },
        Type::Function(fty) => {
            let return_type_index = match fty.results() {
                [] => {
                    debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Void))
                },
                [ty] => register_debug_type(debug_types_section, None, None, ty)?,
                types => {
                    let ty = StructType::new(types.iter().cloned());
                    let size = u32::try_from(ty.size()).map_err(|_| {
                        if let Some(declared_name) = declared_name.as_ref() {
                            Report::msg(format!(
                                "invalid signature for '{declared_name}': return type is too big"
                            ))
                        } else {
                            Report::msg("invalid signature: return type is too big")
                        }
                    })?;
                    let mut fields = vec![];
                    for (i, field) in ty.fields().iter().enumerate() {
                        let name_idx = debug_types_section.add_string(format!("{i}").into());
                        let type_idx =
                            register_debug_type(debug_types_section, None, None, &field.ty)?;
                        fields.push(DebugFieldInfo { name_idx, type_idx, offset: field.offset });
                    }
                    let name_idx = debug_types_section.add_string("<anon>".into());
                    debug_types_section.add_type(DebugTypeInfo::Struct { name_idx, size, fields })
                },
            };
            let mut param_type_indices = vec![];
            for param in fty.params() {
                param_type_indices.push(register_debug_type(
                    debug_types_section,
                    None,
                    None,
                    param,
                )?);
            }
            debug_types_section.add_type(DebugTypeInfo::Function {
                return_type_idx: Some(return_type_index),
                param_type_indices,
            })
        },
    })
}
