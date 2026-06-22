use alloc::string::{String, ToString};
use core::{fmt, str::FromStr};

/// Represents the calling convention of a function.
///
/// Calling conventions are part of a program's ABI (Application Binary Interface), and defines the
/// contract between caller and callee, by specifying the architecture-specific details of how
/// arguments are passed, results are returned, what effects may/will occur (e.g. context switches),
/// etc.
///
/// Additionally, calling conventions define the set of allowed types for function arguments and
/// results, and how those types are represented in the target ABI. It may impose additional
/// restrictions on callers, such as only allowing calls under specific conditions.
///
/// It is not required that callers be functions of the same convention as the callee, it is
/// perfectly acceptable to mix conventions in a program. The only requirement is that the
/// convention used at a given call site, matches the convention of the callee, i.e. it must
/// be the case that caller and callee agree on the convention used for that call.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr)
)]
#[repr(u8)]
pub enum CallConv {
    /// This convention passes all arguments and results by value, and thus requires that the types
    /// of its arguments and results be valid immediates in the Miden ABI. The representation of
    /// those types on the operand stack is specified by the Miden ABI.
    ///
    /// Additional properties of this convention:
    ///
    /// * It is always executed in the caller's context
    /// * May only be the target of a `exec` or `dynexec` instruction
    /// * Must not require more than 16 elements of the operand stack for arguments or results
    /// * Callees are expected to preserve the state of the operand stack following the function
    ///   arguments, such that from the caller's perspective, the effect of the call on the operand
    ///   stack is as if the function arguments had been popped, and the function results were
    ///   pushed.
    ///
    /// This convention is optimal when both caller and callee are in the same language, no context
    /// switching is required, and the arguments and results can be passed on the operand stack
    /// without the potential for overflow.
    Fast,
    /// The C calling convention, as specified for WebAssembly, adapted to Miden's ABI.
    ///
    /// The purpose of this convention is to support cross-language interop via a foreign function
    /// interface (FFI) based on the C data layout rules. It is specifically designed for interop
    /// occurring _within_ the same context. For cross-language, cross-context interop, we require
    /// the use of the Wasm Component Model, see the `ComponentModel` convention for more.
    ///
    /// Notable properties of this convention:
    ///
    /// * It is always executed in the caller's context
    /// * May only be the target of a `exec` or `dynexec` instruction
    /// * Supports any IR type that corresponds to a valid C type (i.e. structs, arrays, etc.)
    /// * Aggregates (structs and arrays) must be returned by reference, where the caller is
    ///   responsible for allocating the memory to which the return value will be written. The
    ///   caller passes the pointer to that memory as the first parameter of the function, which
    ///   must be of matching pointer type, and marked with the `sret` attribute. When the "struct
    ///   return" protocol is in use, the function does not return any values directly.
    /// * Aggregates up to 64 bits may be passed by value, all other structs must be passed by
    ///   reference.
    /// * Integer types up to 128 bits are supported, and are passed by value
    /// * Floating-point types are not supported
    /// * Callees must preserve the state of the operand stack following the function arguments
    /// * If the function arguments require more than 16 elements of the operand stack to represent,
    ///   then arguments will be spilled to the caller's stack frame, such that no more than 15
    ///   elements are required. The caller must then obtain the value of the stack pointer on
    ///   entry, and offset it to access spilled arguments as desired. The arguments are spilled
    ///   in reverse order, i.e. the last argument in the argument list has the greatest offset,
    ///   while the first argument of the argument list to be spilled starts at `sp` (the value
    ///   of the stack pointer on entry).
    ///
    /// NOTE: This convention may be non-optimal if not being used for cross-language interop.
    ///
    #[default]
    C,
    /// This convention is used to represent function signatures in WebAssembly.
    ///
    /// WebAssembly has only the following types relevant for us:
    ///
    /// * `i32`
    /// * `i64`
    /// * `f32` (used to represent field elements here)
    /// * `f64` (not supported here)
    /// * Reference types (i.e. handles that act like pointers)
    ///
    /// It has the following properties:
    ///
    /// * It is always executed in the caller's context
    /// * May only be the target of a `exec` or `dynexec` instruction
    /// * Only supports IR types which correspond to a valid WebAssembly type. Notably this does
    ///   not include aggregates (except via reference types).
    /// * Floating-point types are not allowed, except `f32` which is used to represent field
    ///   elements in the WebAssembly type system.
    /// * Callees must preserve the state of the operand stack following the function arguments
    /// * Uses the same argument spilling strategy as the `C` convention
    Wasm,
    /// This convention corresponds to the Canonical ABI of the Wasm Component Model.
    ///
    /// This convention must be used for all exports of a component, in order for those exports to
    /// be callable from other components and across Miden contexts.
    ///
    /// NOTE: This calling convention corresponds specifically to the functions synthesized from a
    /// `(canon lift)` declaration in a Wasm component, which acts as a wrapper for some internal
    /// function with another calling convention (i.e. `Wasm`) "lifting" it into the Canonical ABI.
    /// Specifically, lifting here refers to the act of "lowering" the function arguments out of the
    /// Canonical ABI and into the underlying convention of the wrapped function, and "lifting" the
    /// results from the underlying convention into the Canonical ABI. While exports might have been
    /// synthesized by a compiler, the details of this ABI can also be implemented by hand for
    /// procedures written in Miden Assembly.
    ///
    /// NOTE: Some important details of this calling convention are described by the Canonical ABI
    /// spec covering the `canon lift` primitive, as well as how types are lifted/lowered from/to
    /// the "flattened" core Wasm type representation. See
    /// [this document](https://github.com/WebAssembly/component-model/blob/main/design/mvp/CanonicalABI.md#lifting-and-lowering-values)
    /// for those details, and other useful information about the Canonical ABI.
    ///
    /// This convention has the following properties:
    ///
    /// * It is always executed in a new context
    /// * May only be the target of a `call` or `dyncall` instruction
    /// * Only supports IR types which correspond to a valid Canonical ABI type. Notably this does
    ///   not include pointer types. No support for `resource` types exists at this time due to
    ///   limitations of the Miden VM.
    /// * Callers must ensure that sensitive data is removed from the first 16 elements of the
    ///   operand stack when lowering calls to `ComponentModel` functions. This compiler will zero-
    ///   pad the unused portions of the operand stack where applicable.
    /// * If the function arguments require more than 16 elements of the operand stack to represent,
    ///   then arguments will be spilled to the advice provider, as a block of memory (in words)
    ///   sufficiently large to hold all of the spilled arguments. The block will be hashed and
    ///   the digest used as the key in the advice map under which the block will be stored. The
    ///   digest will then be passed by-value to the callee as the first argument. This requires
    ///   a word (4 elements) of operand stack to be unused, so when spilling arguments, the first
    ///   12 elements are preserved, while the rest are spilled. The callee is expected to, as part
    ///   of its prologue, immediately fetch the spilled arguments from the advice map using the
    ///   provided digest on top of the operand stack, and write them into the current stack frame.
    ///   The spilled arguments can then be accessed by computing the offset from the stack pointer
    ///   to the desired argument. Note that, like the spill strategy for `C`, the spilled
    ///   arguments will be written into memory in reverse order (the closer to the front of the
    ///   argument list, the smaller the offset).
    ComponentModel,
}

impl CallConv {
    /// Returns true if this convention corresponds to the Canonical ABI convention
    pub fn is_wasm_canonical_abi(&self) -> bool {
        matches!(self, Self::ComponentModel)
    }

    /// Get the string representation of this calling convention
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::C => "C",
            Self::Wasm => "wasm",
            Self::ComponentModel => "component-model",
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown calling convention '{0}'")]
pub struct UnknownCallingConventionError(String);

impl FromStr for CallConv {
    type Err = UnknownCallingConventionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "fast" => Ok(Self::Fast),
            "C" => Ok(Self::C),
            "wasm" | "Wasm" => Ok(Self::Wasm),
            "canon-lift" | "component-model" => Ok(Self::ComponentModel),
            other => Err(UnknownCallingConventionError(other.to_string())),
        }
    }
}

impl fmt::Display for CallConv {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl miden_formatting::prettier::PrettyPrint for CallConv {
    fn render(&self) -> miden_formatting::prettier::Document {
        use miden_formatting::prettier::const_text;

        const_text(self.as_str())
    }
}
