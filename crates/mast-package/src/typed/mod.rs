//! A typed view of a procedure signature.
//!
//! The manifest keeps the high-level (WIT) signature of each export; the VM stack only holds
//! felts. [`TypedProcInfo`] joins the two: it prints the signature, turns argument text into stack
//! felts, and result felts back into text.
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

use miden_assembly_syntax::ast::types::{FunctionType, Type};
use miden_core::Felt;

use self::{
    arity::{felt_count, token_count},
    codec::type_leaf_name,
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
    /// The signature from the package manifest.
    signature: FunctionType,
    /// Codecs the user added. We match them by type name when we encode and decode.
    codecs: Vec<Box<dyn WitScalarCodec>>,
}

impl TypedProcInfo {
    /// Builds the typed view of the procedure `name`, with the signature its package manifest
    /// carries.
    ///
    /// The caller picks the export. It knows which one it wants, and it keeps the signature and
    /// anything else it reads from that export, like its digest, on the same procedure.
    ///
    /// The result has [`WordCodec`] and [`FeltCodec`]. Add more with [`Self::with_scalar_codec`].
    pub fn new(name: impl Into<String>, signature: FunctionType) -> Self {
        Self {
            name: name.into(),
            signature,
            codecs: alloc::vec![
                Box::new(WordCodec) as Box<dyn WitScalarCodec>,
                Box::new(FeltCodec),
            ],
        }
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

    /// How many felts the procedure leaves on the stack. `Some(0)` if it returns nothing, `None`
    /// if a result type has no place on the stack.
    pub fn output_felt_count(&self) -> Option<usize> {
        self.signature
            .results
            .iter()
            .try_fold(0usize, |total, result| total.checked_add(felt_count(result)?))
    }

    /// Turns the result felts at the start of `stack` into text.
    ///
    /// `Ok(None)` means the procedure returns nothing. That is the only case that is not a
    /// problem. Everything else is an error the caller can show: a result type we cannot decode,
    /// a stack that is too short, or felts that are not a valid value of the type. A value that a
    /// codec says is bad is also an error. The user should hear about that, not see raw felts.
    pub fn decode_result(&self, stack: &[Felt]) -> Result<Option<String>, TypedError> {
        let total = self
            .output_felt_count()
            .ok_or_else(|| TypedError::UnsupportedResult { procedure: self.name.clone() })?;
        if total == 0 {
            return Ok(None);
        }
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
        f.write_str(&format_signature(&self.name, &self.signature))
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
fn format_type(ty: &Type) -> String {
    match ty {
        Type::Struct(struct_ty) => {
            // `name` outlives the borrow `type_leaf_name` returns.
            let name = struct_ty.name();
            match name.as_deref().and_then(type_leaf_name) {
                Some(leaf) => leaf.into(),
                None => {
                    let fields: Vec<String> =
                        struct_ty.fields().iter().map(|field| format_type(&field.ty)).collect();
                    format!("({})", fields.join(", "))
                },
            }
        },
        Type::Array(array_ty) => format!("[{}; {}]", format_type(&array_ty.ty), array_ty.len),
        Type::List(element_ty) => format!("list<{}>", format_type(element_ty)),
        Type::Ptr(ptr_ty) => {
            format!("ptr<{}, {}>", ptr_ty.addrspace, format_type(&ptr_ty.pointee))
        },
        Type::Function(sig) => format_signature("fn", sig),
        primitive => primitive.to_string(),
    }
}

/// Prints `name(a, b) -> c`. With no results there is no arrow. With more than one result they
/// go in a tuple.
fn format_signature(name: &str, sig: &FunctionType) -> String {
    let params: Vec<String> = sig.params.iter().map(format_type).collect();
    let results: Vec<String> = sig.results.iter().map(format_type).collect();

    let ret = match results.as_slice() {
        [] => String::new(),
        [single] => format!(" -> {single}"),
        many => format!(" -> ({})", many.join(", ")),
    };

    format!("{name}({}){ret}", params.join(", "))
}
