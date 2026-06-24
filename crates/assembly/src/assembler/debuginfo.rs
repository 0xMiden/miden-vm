use alloc::sync::Arc;
#[cfg(feature = "std")]
use std::{
    path::{Path, PathBuf},
    string::ToString,
};

#[cfg(feature = "std")]
use miden_assembly_syntax::debuginfo::{FileLineCol, Location, Uri};
use miden_mast_package::debug_info::{
    DebugFieldInfo, DebugFunctionsSection, DebugPrimitiveType, DebugSourcesSection, DebugTypeIdx,
    DebugTypeInfo, DebugTypesSection, DebugVariantInfo,
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

#[derive(Clone)]
pub struct DebugInfoSections {
    /// The debug function section maintained by the assembler during assembly
    pub debug_functions_section: DebugFunctionsSection,
    /// The debug type section maintained by the assembler during assembly
    pub debug_types_section: DebugTypesSection,
    /// The debug sources section maintained by the assembler during assembly
    pub debug_sources_section: DebugSourcesSection,
}

impl Default for DebugInfoSections {
    fn default() -> Self {
        Self {
            debug_functions_section: DebugFunctionsSection::new(),
            debug_types_section: DebugTypesSection::new(),
            debug_sources_section: DebugSourcesSection::new(),
        }
    }
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

    #[cfg(feature = "std")]
    pub(super) fn trim_paths(&mut self, trimmer: &SourcePathTrimmer) {
        for path in self.debug_sources_section.strings.iter_mut() {
            *path = trimmer.trim_path_string(path.as_ref());
        }
    }
}

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub(super) struct SourcePathTrimmer {
    cwd: PathBuf,
}

#[cfg(feature = "std")]
impl SourcePathTrimmer {
    pub fn new(cwd: PathBuf) -> Self {
        let cwd = cwd.canonicalize().unwrap_or(cwd);
        Self { cwd }
    }

    pub fn trim_location(&self, mut location: Location) -> Location {
        location.uri = self.trim_uri(&location.uri);
        location
    }

    pub fn trim_file_line_col(&self, mut location: FileLineCol) -> FileLineCol {
        location.uri = self.trim_uri(&location.uri);
        location
    }

    fn trim_uri(&self, uri: &Uri) -> Uri {
        let Some(path) = self.filesystem_path(uri) else {
            return uri.clone();
        };

        let trimmed = self.trim_path(path);
        if trimmed == path {
            return uri.clone();
        }

        Uri::from(trimmed.as_path())
    }

    fn trim_path(&self, path: &Path) -> PathBuf {
        let absolute_path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.cwd.join(path)
        };
        let absolute_path = absolute_path.canonicalize().unwrap_or(absolute_path);
        absolute_path
            .strip_prefix(&self.cwd)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| path.to_path_buf())
    }

    fn trim_path_string(&self, path: &str) -> Arc<str> {
        Arc::from(self.trim_path(Path::new(path)).display().to_string())
    }

    fn filesystem_path<'a>(&self, uri: &'a Uri) -> Option<&'a Path> {
        match uri.scheme() {
            Some("file") | None => Some(Path::new(uri.path())),
            Some(_) => None,
        }
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
        Type::U256 => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U256))
        },
        Type::Unknown => debug_types_section.add_type(DebugTypeInfo::Unknown),
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
                let field_name =
                    decl.map(|decl| decl.name.clone().into_inner()).or_else(|| field.name.clone());
                let declared_ty = decl.map(|decl| &decl.ty);
                let field_type_name = declared_type_name(declared_ty);
                let type_idx = register_debug_type(
                    debug_types_section,
                    field_type_name,
                    declared_ty,
                    &field.ty,
                )?;
                let name_idx = debug_types_section
                    .add_string(field_name.unwrap_or_else(|| format!("{i}").into()));
                fields.push(DebugFieldInfo { name_idx, type_idx, offset: field.offset });
            }
            let struct_name = declared_name.or_else(|| struct_ty.name());
            let name_idx = debug_types_section
                .add_string(struct_name.clone().unwrap_or_else(|| "<anon>".into()));
            let size = u32::try_from(struct_ty.size()).map_err(|_| {
                if let Some(declared_name) = struct_name.as_ref() {
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
            let name_idx = debug_types_section.add_string(enum_ty.name().clone());
            let size = u32::try_from(enum_ty.size_in_bytes()).map_err(|_| {
                Report::msg(format!("invalid enum type '{}': enum is too large", enum_ty.name()))
            })?;
            let variants = enum_ty
                .variant_offsets()
                .zip(enum_ty.discriminant_values())
                .map(|((payload_offset, variant), discriminant)| {
                    let name_idx = debug_types_section.add_string(variant.name.clone());
                    let type_idx = variant
                        .value
                        .as_ref()
                        .map(|ty| register_debug_type(debug_types_section, None, None, ty))
                        .transpose()?;
                    let payload_offset = variant.value.as_ref().map(|_| payload_offset);
                    Ok(DebugVariantInfo {
                        name_idx,
                        type_idx,
                        payload_offset,
                        discriminant,
                    })
                })
                .collect::<Result<_, Report>>()?;
            debug_types_section.add_type(DebugTypeInfo::Enum {
                name_idx,
                size,
                discriminant_type_idx: discrim_ty,
                variants,
            })
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

fn declared_type_name(declared_ty: Option<&TypeExpr>) -> Option<Arc<str>> {
    match declared_ty? {
        TypeExpr::Ref(path) => Some(Arc::from(path.inner().as_str())),
        TypeExpr::Struct(ty) => ty.name.as_ref().map(|name| name.clone().into_inner()),
        TypeExpr::Primitive(_) | TypeExpr::Ptr(_) | TypeExpr::Array(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use super::*;
    use crate::ast::types::{CallConv, EnumType, FunctionType, Variant};

    #[test]
    fn registers_c_like_enum_debug_type() {
        let mut section = DebugTypesSection::new();
        let enum_ty = EnumType::new(
            Arc::from("Status"),
            Type::U16,
            [
                Variant::c_like(Arc::from("Ok"), Some(200)),
                Variant::c_like(Arc::from("NotFound"), Some(404)),
            ],
        )
        .unwrap();
        let ty = Type::Enum(Arc::new(enum_ty));

        let type_idx = register_debug_type(&mut section, None, None, &ty).unwrap();

        let DebugTypeInfo::Enum {
            name_idx,
            size,
            discriminant_type_idx,
            variants,
        } = section.get_type(type_idx).unwrap()
        else {
            panic!("expected enum debug type");
        };
        assert_eq!(section.get_string(*name_idx).as_deref(), Some("Status"));
        assert_eq!(*size, 2);
        assert_eq!(
            section.get_type(*discriminant_type_idx),
            Some(&DebugTypeInfo::Primitive(DebugPrimitiveType::U16))
        );
        assert_eq!(variants.len(), 2);
        assert_eq!(section.get_string(variants[0].name_idx).as_deref(), Some("Ok"));
        assert_eq!(variants[0].type_idx, None);
        assert_eq!(variants[0].payload_offset, None);
        assert_eq!(variants[0].discriminant, 200);
        assert_eq!(section.get_string(variants[1].name_idx).as_deref(), Some("NotFound"));
        assert_eq!(variants[1].type_idx, None);
        assert_eq!(variants[1].payload_offset, None);
        assert_eq!(variants[1].discriminant, 404);
    }

    #[test]
    fn registers_payload_enum_debug_type() {
        let mut section = DebugTypesSection::new();
        let enum_ty = EnumType::new(
            Arc::from("OptionU32"),
            Type::U8,
            [
                Variant::c_like(Arc::from("None"), Some(0)),
                Variant::new(Arc::from("Some"), Type::U32, Some(1)),
            ],
        )
        .unwrap();
        let ty = Type::Enum(Arc::new(enum_ty));

        let type_idx = register_debug_type(&mut section, None, None, &ty).unwrap();

        let DebugTypeInfo::Enum { variants, .. } = section.get_type(type_idx).unwrap() else {
            panic!("expected enum debug type");
        };
        assert_eq!(variants.len(), 2);
        assert_eq!(variants[0].type_idx, None);
        let payload_type_idx = variants[1].type_idx.expect("Some variant should have payload");
        assert_eq!(
            section.get_type(payload_type_idx),
            Some(&DebugTypeInfo::Primitive(DebugPrimitiveType::U32))
        );
        assert_eq!(variants[1].payload_offset, Some(4));
        assert_eq!(variants[1].discriminant, 1);
    }

    #[test]
    fn function_debug_types_preserve_resolved_struct_metadata() {
        let felt_wrapper = Type::Struct(Arc::new(StructType::named(
            "felt-wrapper".into(),
            [(Arc::from("inner"), Type::Felt)],
        )));
        let account_id = Type::Struct(Arc::new(StructType::named(
            "account-id".into(),
            [(Arc::from("prefix"), felt_wrapper.clone()), (Arc::from("suffix"), felt_wrapper)],
        )));
        let function = Type::Function(Arc::new(FunctionType::new(
            CallConv::ComponentModel,
            [account_id.clone()],
            [account_id],
        )));
        let mut section = DebugTypesSection::new();

        let function_idx =
            register_debug_type(&mut section, Some(Arc::from("take-account-id")), None, &function)
                .expect("function type should register");

        let (return_type_idx, param_type_idx) = match section.get_type(function_idx).unwrap() {
            DebugTypeInfo::Function {
                return_type_idx: Some(return_type_idx),
                param_type_indices,
            } => {
                assert_eq!(param_type_indices.len(), 1);
                (*return_type_idx, param_type_indices[0])
            },
            other => panic!("expected function debug type, got {other:?}"),
        };

        assert_struct_debug_type(
            &section,
            param_type_idx,
            "account-id",
            &[("prefix", "felt-wrapper"), ("suffix", "felt-wrapper")],
        );
        assert_struct_debug_type(
            &section,
            return_type_idx,
            "account-id",
            &[("prefix", "felt-wrapper"), ("suffix", "felt-wrapper")],
        );
    }

    fn assert_struct_debug_type(
        section: &DebugTypesSection,
        type_idx: DebugTypeIdx,
        expected_name: &str,
        expected_fields: &[(&str, &str)],
    ) {
        let DebugTypeInfo::Struct { name_idx, fields, .. } = section.get_type(type_idx).unwrap()
        else {
            panic!("expected struct debug type");
        };

        assert_eq!(section.get_string(*name_idx).as_deref(), Some(expected_name));
        assert_eq!(fields.len(), expected_fields.len());
        for (field, (expected_name, expected_type_name)) in fields.iter().zip(expected_fields) {
            assert_eq!(section.get_string(field.name_idx).as_deref(), Some(*expected_name));

            let DebugTypeInfo::Struct { name_idx, .. } = section.get_type(field.type_idx).unwrap()
            else {
                panic!("expected struct field type");
            };
            assert_eq!(section.get_string(*name_idx).as_deref(), Some(*expected_type_name));
        }
    }
}
