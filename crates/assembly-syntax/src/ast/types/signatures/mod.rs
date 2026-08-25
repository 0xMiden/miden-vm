//! A typed view of a procedure signature.
//!
//! A procedure carries a high-level (WIT) signature; the VM stack only holds felts.
//! [`TypedProcInfo`] joins the two: it prints the signature, turns argument text into stack felts,
//! and result felts back into text.
//!
//! The felts follow the canonical ABI: one stack slot per leaf field, so `struct { u8, u8 }` is
//! two felts. This is the layout of a component export, the kind a caller reaches with `call`, and
//! the only convention this module takes.
//!
//! Types that take one token, like `word` and `felt`, go through a [`WitScalarCodec`]. Those two
//! are built in; the caller adds others with [`TypedProcInfo::with_scalar_codec`].

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

use miden_core::Felt;
use midenc_hir_type::{CallConv, FunctionType, Type};

use self::{
    arity::{felt_count, token_count},
    codec::{StructShape, codec_for_struct, field_name, struct_shape, type_leaf_name},
    decode::decode_type,
    encode::encode_type,
};

mod arity;
mod codec;
mod decode;
mod encode;
mod errors;
#[cfg(test)]
mod tests;

pub use self::{
    codec::{FeltCodec, MIDEN_CORE_TYPES, WitScalarCodec, WordCodec},
    errors::TypedError,
};

// TYPED PROCEDURE INFO
// ================================================================================================

/// The typed signature of one exported procedure.
///
/// Build it with [`Self::new`], then use [`Self::encode_args`] for arguments and
/// [`Self::decode_result`] for results. [`fmt::Display`] prints the signature, like
/// `add-points(point, point) -> point`.
pub struct TypedProcInfo {
    /// The name we show, like `add-points`.
    name: String,
    /// The signature we encode arguments and decode results against.
    signature: FunctionType,
    /// Codecs the user added. We match them by type name when we encode and decode.
    codecs: Vec<Box<dyn WitScalarCodec>>,
}

impl TypedProcInfo {
    /// Builds the typed view of the procedure `name`, with the signature `signature`.
    ///
    /// The caller picks the procedure. It knows which one it wants, and it keeps the signature and
    /// anything else it reads about it, like its digest, on the same procedure.
    ///
    /// The signature has to be `component-model`. Another convention puts the same value on the
    /// stack in another shape, and we would read and write felts the procedure never sees.
    ///
    /// The result has [`WordCodec`] and [`FeltCodec`]. Add more with [`Self::with_scalar_codec`].
    pub fn new(name: impl Into<String>, signature: FunctionType) -> Result<Self, TypedError> {
        let name = name.into();
        if signature.abi != CallConv::ComponentModel {
            return Err(TypedError::UnsupportedCallConv {
                procedure: name,
                abi: signature.abi.to_string(),
            });
        }
        Ok(Self {
            name,
            signature,
            codecs: alloc::vec![
                Box::new(WordCodec) as Box<dyn WitScalarCodec>,
                Box::new(FeltCodec),
            ],
        })
    }

    /// Adds a [`WitScalarCodec`]. The codec then handles its own WIT type, instead of the normal
    /// field by field way.
    ///
    /// We match a codec by name and by interface, so the built-in ones only take the core types.
    /// If two codecs want the same type, the first one wins. So you cannot replace a built-in
    /// codec, you can only add new ones.
    #[must_use]
    pub fn with_scalar_codec(mut self, codec: Box<dyn WitScalarCodec>) -> Self {
        self.codecs.push(codec);
        self
    }

    /// How many argument tokens the procedure needs, for all parameters together. A type with a
    /// codec, like `word`, takes one token. Other structs take one token per field.
    ///
    /// Returns `None` if a parameter has no fixed token count. This crate cannot encode pointers,
    /// functions, enums, lists or unknown types. Then the caller skips this check and lets
    /// [`Self::encode_args`] say what is wrong.
    fn expected_token_count(&self) -> Option<usize> {
        self.signature
            .params
            .iter()
            .try_fold(0usize, |total, param| total.checked_add(token_count(param, &self.codecs)?))
    }

    /// Turns `tokens` into the felts the procedure needs on the stack, in parameter order.
    ///
    /// The first felt goes on top of the stack, because the first argument sits on top:
    /// `f(1u32, 2u32)` gives `[1, 2]`. A caller that pushes them one by one starts at the back.
    /// See `docs/external/src/appendix/calling-conventions.md` in the compiler.
    ///
    /// We check the count first. So if the caller passes the wrong number of arguments, the error
    /// gives the procedure name and both counts.
    pub fn encode_args<T: AsRef<str>>(&self, tokens: &[T]) -> Result<Vec<Felt>, TypedError> {
        let expected = self
            .expected_token_count()
            .ok_or_else(|| TypedError::UnsupportedParameter { procedure: self.name.clone() })?;
        if tokens.len() != expected {
            return Err(TypedError::ArgumentCount {
                procedure: self.name.clone(),
                expected,
                actual: tokens.len(),
            });
        }

        let mut tokens = tokens.iter();
        let mut felts = Vec::new();
        for param in &self.signature.params {
            felts.extend(encode_type(&mut tokens, param, &self.codecs)?);
        }
        if tokens.next().is_some() {
            return Err(TypedError::TokenCountMismatch);
        }
        Ok(felts)
    }

    /// Whether the procedure have a result.
    pub fn returns_value(&self) -> bool {
        !self.signature.results.is_empty()
    }

    /// How many felts the procedure leaves on the stack, or `None` if a result type has no
    /// place on the stack.
    pub fn output_felt_count(&self) -> Option<usize> {
        self.signature
            .results
            .iter()
            .try_fold(0usize, |total, result| total.checked_add(felt_count(result)?))
    }

    /// Turns the result felts at the start of `stack` into text. `stack[0]` is the top of the
    /// stack. The first result sits there, and so does the first field of a struct.
    ///
    /// `Ok(None)` means the procedure returns nothing. That is the only case that is not a
    /// problem. Everything else is an error the caller can show: a result type we cannot decode,
    /// a stack that is too short, or felts that are not a valid value of the type. A value that a
    /// codec says is bad is also an error. The user should hear about that, not see raw felts.
    pub fn decode_result(&self, stack: &[Felt]) -> Result<Option<String>, TypedError> {
        // A result can take no felts and still be a result: an empty struct, or an array of
        // length zero.
        if !self.returns_value() {
            return Ok(None);
        }
        let total = self
            .output_felt_count()
            .ok_or_else(|| TypedError::UnsupportedResult { procedure: self.name.clone() })?;
        if total > stack.len() {
            return Err(TypedError::ResultStackTooShort {
                procedure: self.name.clone(),
                expected: total,
                actual: stack.len(),
            });
        }

        let mut cursor = &stack[..total];
        let mut rendered = Vec::with_capacity(self.signature.results.len());
        for result in &self.signature.results {
            let (mut value, rest) = decode_type(cursor, result, &self.codecs)?;
            // A primitive gets its type after it, like `42u32`. Not a bool, which reads as `true`
            // or `false`, and not a struct or an array, which already show their own name.
            if !matches!(result, Type::Struct(_) | Type::Array(_) | Type::I1) {
                value.push_str(&result.to_string());
            }
            rendered.push(value);
            cursor = rest;
        }
        if !cursor.is_empty() {
            return Err(TypedError::FeltCountMismatch);
        }

        Ok(Some(match rendered.len() {
            1 => rendered.pop().expect("just checked there is one"),
            _ => format!("({})", rendered.join(", ")),
        }))
    }
}

/// Prints the signature, like `add-points(point, point) -> point`.
impl fmt::Display for TypedProcInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format_signature(&self.name, &self.signature, &self.codecs))
    }
}

// HELPERS
// ================================================================================================

/// Prints `ty` the way it looks in the source. A struct with a name shows its plain name. A
/// struct with no name shows its fields. Every other type prints itself.
///
/// Only the struct branch really belongs to us: a struct name in a signature is a full WIT path,
/// and we show its last part. We walk the types that hold other types so a struct inside one gets
/// the same treatment, and we print them the way [`Type`] itself does, so a signature reads like
/// the source it came from.
/// `printing` holds the recursive definitions whose bodies are being written out.
///
/// A named recursive struct stops at its name below, but an anonymous one has no name to stop at,
/// so without this its body is unfolded forever.
fn format_type_inner(
    ty: &Type,
    codecs: &[Box<dyn WitScalarCodec>],
    printing: &mut Vec<midenc_hir_type::RecTypeRef>,
) -> String {
    match ty {
        Type::Struct(struct_ty) => {
            // A codec reads one token for the whole struct, not one per field, the same way
            // `token_count` and `decode_type` treat it. So the signature shows the codec's name
            // for it, not a field list that would wrongly ask the user for one token per field.
            if let Some(rec) = struct_ty.as_recursive() {
                if printing.contains(rec) {
                    // Back at a definition already being written out. A named one never gets
                    // here, because its name is its whole rendering below.
                    return rec.name().map_or_else(|| "_".to_string(), |name| name.to_string());
                }
                printing.push(rec.clone());
            }
            let is_recursive = struct_ty.is_recursive();
            let struct_ty = struct_ty.get();
            if let Some(codec) = codec_for_struct(codecs, &struct_ty) {
                if is_recursive {
                    printing.pop();
                }
                return codec.wit_name().to_string();
            }

            let fields = struct_ty.fields();
            // A struct with mixed field names has no shape, and `Display` cannot show an error, so
            // the signature says so instead of looking correct. `decode_type` is where it becomes
            // an error.
            let rendered = match struct_shape(&struct_ty) {
                // A struct with a name is its name. Its fields are not part of the signature.
                Some(
                    StructShape::Tuple { name: Some(name) }
                    | StructShape::Record { name: Some(name) },
                ) => name,
                Some(StructShape::Tuple { name: None }) => {
                    let fields: Vec<String> = fields
                        .iter()
                        .map(|field| format_type_inner(&field.ty, codecs, printing))
                        .collect();
                    format!("({})", fields.join(", "))
                },
                // A record has a name on every field, so `?` only shows up for a struct whose
                // fields are partly named. It stands for a field `field_name` reads as
                // positional: no name, an empty name, or the position itself, like `"0"`.
                Some(StructShape::Record { name: None }) | None => {
                    let rendered: Vec<String> = fields
                        .iter()
                        .enumerate()
                        .map(|(i, field)| {
                            let name = field_name(field, i).unwrap_or("?");
                            format!("{name}: {}", format_type_inner(&field.ty, codecs, printing))
                        })
                        .collect();
                    let body = rendered.join(", ");
                    // The name too, so the reader knows which type is bad, not only that one is.
                    let name = struct_ty.name();
                    match name.as_deref().and_then(type_leaf_name) {
                        Some(name) => format!("{name} {{ {body} }}"),
                        None => format!("{{ {body} }}"),
                    }
                },
            };
            if is_recursive {
                printing.pop();
            }
            rendered
        },
        Type::Array(array_ty) => {
            format!("[{}; {}]", format_type_inner(&array_ty.ty, codecs, printing), array_ty.len)
        },
        Type::List(element_ty) => {
            format!("list<{}>", format_type_inner(element_ty, codecs, printing))
        },
        Type::Ptr(ptr_ty) => {
            format!(
                "ptr<{}, {}>",
                ptr_ty.addrspace,
                format_type_inner(&ptr_ty.pointee, codecs, printing)
            )
        },
        Type::Function(sig) => format_signature_inner("fn", sig, codecs, printing),
        primitive => primitive.to_string(),
    }
}

/// Prints `name(a, b) -> c`. With no results there is no arrow. With more than one result they
/// go in a tuple.
fn format_signature(name: &str, sig: &FunctionType, codecs: &[Box<dyn WitScalarCodec>]) -> String {
    format_signature_inner(name, sig, codecs, &mut Vec::new())
}

fn format_signature_inner(
    name: &str,
    sig: &FunctionType,
    codecs: &[Box<dyn WitScalarCodec>],
    printing: &mut Vec<midenc_hir_type::RecTypeRef>,
) -> String {
    let params: Vec<String> =
        sig.params.iter().map(|ty| format_type_inner(ty, codecs, printing)).collect();
    let results: Vec<String> =
        sig.results.iter().map(|ty| format_type_inner(ty, codecs, printing)).collect();

    let ret = match results.as_slice() {
        [] => String::new(),
        [single] => format!(" -> {single}"),
        many => format!(" -> ({})", many.join(", ")),
    };

    format!("{name}({}){ret}", params.join(", "))
}
