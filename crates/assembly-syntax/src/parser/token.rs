use alloc::string::String;
use core::fmt;

use miden_core::{
    Felt, FieldElement, StarkField,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// DOCUMENTATION TYPE
// ================================================================================================

/// Represents the scope of a given documentation comment
#[derive(Debug, Clone)]
pub enum DocumentationType {
    Module(String),
    Form(String),
}

impl From<DocumentationType> for String {
    fn from(doc: DocumentationType) -> Self {
        match doc {
            DocumentationType::Module(s) => s,
            DocumentationType::Form(s) => s,
        }
    }
}

impl core::ops::Deref for DocumentationType {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Module(s) => s,
            Self::Form(s) => s,
        }
    }
}

// PUSH VALUE
// ================================================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushValue {
    Int(IntValue),
    Word(WordValue),
}

impl From<u8> for PushValue {
    fn from(value: u8) -> Self {
        Self::Int(value.into())
    }
}

impl From<u16> for PushValue {
    fn from(value: u16) -> Self {
        Self::Int(value.into())
    }
}

impl From<u32> for PushValue {
    fn from(value: u32) -> Self {
        Self::Int(value.into())
    }
}

impl From<Felt> for PushValue {
    fn from(value: Felt) -> Self {
        Self::Int(value.into())
    }
}

impl From<IntValue> for PushValue {
    fn from(value: IntValue) -> Self {
        Self::Int(value)
    }
}

impl From<WordValue> for PushValue {
    fn from(value: WordValue) -> Self {
        Self::Word(value)
    }
}

impl fmt::Display for PushValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(value) => fmt::Display::fmt(value, f),
            Self::Word(value) => fmt::Display::fmt(value, f),
        }
    }
}

impl crate::prettier::PrettyPrint for PushValue {
    fn render(&self) -> crate::prettier::Document {
        match self {
            Self::Int(value) => value.render(),
            Self::Word(value) => value.render(),
        }
    }
}

// WORD VALUE
// ================================================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_serde_test_macros::serde_test(winter_serde(true))
)]
pub struct WordValue(pub [Felt; 4]);

impl fmt::Display for WordValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#08x}{:08x}{:08x}{:08x}",
            &self.0[0].as_int(),
            &self.0[1].as_int(),
            &self.0[2].as_int(),
            &self.0[3].as_int(),
        )
    }
}

impl crate::prettier::PrettyPrint for WordValue {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        const_text("[")
            + self
                .0
                .iter()
                .copied()
                .map(display)
                .reduce(|acc, doc| acc + const_text(",") + doc)
                .unwrap_or_default()
            + const_text("]")
    }
}

impl PartialOrd for WordValue {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for WordValue {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        let (WordValue([l0, l1, l2, l3]), WordValue([r0, r1, r2, r3])) = (self, other);
        l0.as_int()
            .cmp(&r0.as_int())
            .then_with(|| l1.as_int().cmp(&r1.as_int()))
            .then_with(|| l2.as_int().cmp(&r2.as_int()))
            .then_with(|| l3.as_int().cmp(&r3.as_int()))
    }
}

impl core::hash::Hash for WordValue {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        let WordValue([a, b, c, d]) = self;
        [a.as_int(), b.as_int(), c.as_int(), d.as_int()].hash(state)
    }
}

#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for WordValue {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::{array::uniform4, strategy::Strategy};
        uniform4((0..=crate::FIELD_MODULUS).prop_map(Felt::new))
            .prop_map(WordValue)
            .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

impl Serializable for WordValue {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0[0].write_into(target);
        self.0[1].write_into(target);
        self.0[2].write_into(target);
        self.0[3].write_into(target);
    }
}

impl Deserializable for WordValue {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let a = Felt::read_from(source)?;
        let b = Felt::read_from(source)?;
        let c = Felt::read_from(source)?;
        let d = Felt::read_from(source)?;
        Ok(Self([a, b, c, d]))
    }
}

// INT VALUE
// ================================================================================================

/// Represents one of the various types of values that have a hex-encoded representation in Miden
/// Assembly source files.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_serde_test_macros::serde_test(winter_serde(true))
)]
pub enum IntValue {
    /// A tiny value
    U8(u8),
    /// A small value
    U16(u16),
    /// A u32 constant, typically represents a memory address
    U32(u32),
    /// A single field element, 8 bytes, encoded as 16 hex digits
    Felt(Felt),
}

impl From<u8> for IntValue {
    fn from(value: u8) -> Self {
        Self::U8(value)
    }
}

impl From<u16> for IntValue {
    fn from(value: u16) -> Self {
        Self::U16(value)
    }
}

impl From<u32> for IntValue {
    fn from(value: u32) -> Self {
        Self::U32(value)
    }
}

impl From<Felt> for IntValue {
    fn from(value: Felt) -> Self {
        Self::Felt(value)
    }
}

impl IntValue {
    pub fn as_int(&self) -> u64 {
        match self {
            Self::U8(value) => *value as u64,
            Self::U16(value) => *value as u64,
            Self::U32(value) => *value as u64,
            Self::Felt(value) => value.as_int(),
        }
    }
}

impl core::ops::Add<IntValue> for IntValue {
    type Output = IntValue;

    fn add(self, rhs: IntValue) -> Self::Output {
        super::lexer::shrink_u64_hex(self.as_int() + rhs.as_int())
    }
}

impl core::ops::Sub<IntValue> for IntValue {
    type Output = IntValue;

    fn sub(self, rhs: IntValue) -> Self::Output {
        super::lexer::shrink_u64_hex(self.as_int() - rhs.as_int())
    }
}

impl core::ops::Mul<IntValue> for IntValue {
    type Output = IntValue;

    fn mul(self, rhs: IntValue) -> Self::Output {
        super::lexer::shrink_u64_hex(self.as_int() * rhs.as_int())
    }
}

impl core::ops::Div<IntValue> for IntValue {
    type Output = IntValue;

    fn div(self, rhs: IntValue) -> Self::Output {
        super::lexer::shrink_u64_hex(self.as_int() / rhs.as_int())
    }
}

impl PartialEq<Felt> for IntValue {
    fn eq(&self, other: &Felt) -> bool {
        match self {
            Self::U8(lhs) => (*lhs as u64) == other.as_int(),
            Self::U16(lhs) => (*lhs as u64) == other.as_int(),
            Self::U32(lhs) => (*lhs as u64) == other.as_int(),
            Self::Felt(lhs) => lhs == other,
        }
    }
}

impl fmt::Display for IntValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::U8(value) => write!(f, "{value}"),
            Self::U16(value) => write!(f, "{value}"),
            Self::U32(value) => write!(f, "{value:#04x}"),
            Self::Felt(value) => write!(f, "{:#08x}", &value.as_int().to_be()),
        }
    }
}

impl crate::prettier::PrettyPrint for IntValue {
    fn render(&self) -> crate::prettier::Document {
        match self {
            Self::U8(v) => v.render(),
            Self::U16(v) => v.render(),
            Self::U32(v) => v.render(),
            Self::Felt(v) => u64::from(*v).render(),
        }
    }
}

impl PartialOrd for IntValue {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for IntValue {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        use core::cmp::Ordering;
        match (self, other) {
            (Self::U8(l), Self::U8(r)) => l.cmp(r),
            (Self::U8(_), _) => Ordering::Less,
            (Self::U16(_), Self::U8(_)) => Ordering::Greater,
            (Self::U16(l), Self::U16(r)) => l.cmp(r),
            (Self::U16(_), _) => Ordering::Less,
            (Self::U32(_), Self::U8(_) | Self::U16(_)) => Ordering::Greater,
            (Self::U32(l), Self::U32(r)) => l.cmp(r),
            (Self::U32(_), _) => Ordering::Less,
            (Self::Felt(_), Self::U8(_) | Self::U16(_) | Self::U32(_)) => Ordering::Greater,
            (Self::Felt(l), Self::Felt(r)) => l.as_int().cmp(&r.as_int()),
        }
    }
}

impl core::hash::Hash for IntValue {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
        match self {
            Self::U8(value) => value.hash(state),
            Self::U16(value) => value.hash(state),
            Self::U32(value) => value.hash(state),
            Self::Felt(value) => value.as_int().hash(state),
        }
    }
}

impl Serializable for IntValue {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.as_int().write_into(target)
    }
}

impl Deserializable for IntValue {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let raw = source.read_u64()?;
        if raw >= Felt::MODULUS {
            Err(DeserializationError::InvalidValue(
                "int value is greater than field modulus".into(),
            ))
        } else {
            Ok(super::lexer::shrink_u64_hex(raw))
        }
    }
}

#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for IntValue {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::{num, prop_oneof, strategy::Strategy};
        prop_oneof![
            num::u8::ANY.prop_map(IntValue::U8),
            ((u8::MAX as u16 + 1)..=u16::MAX).prop_map(IntValue::U16),
            ((u16::MAX as u32 + 1)..=u32::MAX).prop_map(IntValue::U32),
            ((u32::MAX as u64 + 1)..=crate::FIELD_MODULUS)
                .prop_map(|n| IntValue::Felt(Felt::new(n))),
        ]
        .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

// BINARY ENCODED VALUE
// ================================================================================================

/// Represents one of the various types of values that have a hex-encoded representation in Miden
/// Assembly source files.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BinEncodedValue {
    /// A tiny value
    U8(u8),
    /// A small value
    U16(u16),
    /// A u32 constant, typically represents a memory address
    U32(u32),
}

// TOKEN
// ================================================================================================

/// The token type produced by [crate::parser::Lexer], and consumed by the parser.
#[derive(Debug, Clone)]
pub enum Token<'input> {
    Add,
    Addrspace,
    Adv,
    AdvMap,
    InsertHdword,
    InsertHdwordWithDomain,
    InsertHqword,
    InsertHperm,
    InsertMem,
    AdvLoadw,
    AdvPipe,
    AdvPush,
    AdvStack,
    PushMapval,
    PushMapvaln,
    PushMtnode,
    And,
    Assert,
    Assertz,
    AssertEq,
    AssertEqw,
    EvalCircuit,
    Begin,
    Breakpoint,
    Byte,
    Caller,
    Call,
    Cdrop,
    Cdropw,
    Clk,
    Const,
    Cswap,
    Cswapw,
    Debug,
    Div,
    Drop,
    Dropw,
    Dup,
    Dupw,
    Dynexec,
    Dyncall,
    Else,
    Emit,
    End,
    Enum,
    Eq,
    Eqw,
    Ext2Add,
    Ext2Div,
    Ext2Inv,
    Ext2Mul,
    Ext2Neg,
    Ext2Sub,
    Err,
    Exec,
    Export,
    Exp,
    ExpU,
    False,
    Felt,
    FriExt2Fold4,
    Gt,
    Gte,
    Hash,
    HasMapkey,
    HornerBase,
    HornerExt,
    Hperm,
    Hmerge,
    I1,
    I8,
    I16,
    I32,
    I64,
    I128,
    If,
    ILog2,
    Inv,
    IsOdd,
    Local,
    Locaddr,
    LocLoad,
    LocLoadw,
    LocStore,
    LocStorew,
    Lt,
    Lte,
    Mem,
    MemLoad,
    MemLoadw,
    MemLoadwBe,
    MemLoadwLe,
    MemStore,
    MemStorew,
    MemStorewBe,
    MemStorewLe,
    MemStream,
    Movdn,
    Movdnw,
    Movup,
    Movupw,
    MtreeGet,
    MtreeMerge,
    MtreeSet,
    MtreeVerify,
    Mul,
    Neg,
    Neq,
    Not,
    Nop,
    Or,
    Padw,
    Pow2,
    Proc,
    Procref,
    Ptr,
    Pub,
    Push,
    Repeat,
    Reversew,
    Reversedw,
    Range,
    Sdepth,
    Stack,
    Struct,
    Sub,
    Swap,
    Swapw,
    Swapdw,
    Syscall,
    Trace,
    True,
    Type,
    Use,
    U8,
    U16,
    U32,
    U32And,
    U32Assert,
    U32Assert2,
    U32Assertw,
    U32Cast,
    U32Div,
    U32Divmod,
    U32Gt,
    U32Gte,
    U32Lt,
    U32Lte,
    U32Max,
    U32Min,
    U32Mod,
    U32Not,
    U32Or,
    U32OverflowingAdd,
    U32OverflowingAdd3,
    U32OverflowingMadd,
    U32OverflowingMul,
    U32OverflowingSub,
    U32Popcnt,
    U32Clz,
    U32Ctz,
    U32Clo,
    U32Cto,
    U32Rotl,
    U32Rotr,
    U32Shl,
    U32Shr,
    U32Split,
    U32Test,
    U32Testw,
    U32WrappingAdd,
    U32WrappingAdd3,
    U32WrappingMadd,
    U32WrappingMul,
    U32WrappingSub,
    U32Xor,
    U64,
    U128,
    While,
    Word,
    Event,
    Xor,
    At,
    Bang,
    Colon,
    ColonColon,
    Dot,
    Comma,
    Equal,
    Langle,
    Lparen,
    Lbrace,
    Lbracket,
    Minus,
    Plus,
    Semicolon,
    SlashSlash,
    Slash,
    Star,
    Rangle,
    Rparen,
    Rbrace,
    Rbracket,
    Rstab,
    DocComment(DocumentationType),
    HexValue(IntValue),
    HexWord(WordValue),
    BinValue(BinEncodedValue),
    Int(u64),
    Ident(&'input str),
    ConstantIdent(&'input str),
    QuotedIdent(&'input str),
    QuotedString(&'input str),
    Comment,
    Eof,
}

impl fmt::Display for Token<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Token::Add => write!(f, "add"),
            Token::Addrspace => write!(f, "addrspace"),
            Token::Adv => write!(f, "adv"),
            Token::AdvMap => write!(f, "adv_map"),
            Token::AdvStack => write!(f, "adv_stack"),
            Token::InsertHdword => write!(f, "insert_hdword"),
            Token::InsertHdwordWithDomain => write!(f, "insert_hdword_d"),
            Token::InsertHqword => write!(f, "insert_hqword"),
            Token::InsertHperm => write!(f, "insert_hperm"),
            Token::InsertMem => write!(f, "insert_mem"),
            Token::AdvLoadw => write!(f, "adv_loadw"),
            Token::AdvPipe => write!(f, "adv_pipe"),
            Token::AdvPush => write!(f, "adv_push"),
            Token::PushMapval => write!(f, "push_mapval"),
            Token::PushMapvaln => write!(f, "push_mapvaln"),
            Token::PushMtnode => write!(f, "push_mtnode"),
            Token::And => write!(f, "and"),
            Token::Assert => write!(f, "assert"),
            Token::Assertz => write!(f, "assertz"),
            Token::AssertEq => write!(f, "assert_eq"),
            Token::AssertEqw => write!(f, "assert_eqw"),
            Token::EvalCircuit => write!(f, "eval_circuit"),
            Token::Begin => write!(f, "begin"),
            Token::Breakpoint => write!(f, "breakpoint"),
            Token::Byte => write!(f, "byte"),
            Token::Caller => write!(f, "caller"),
            Token::Call => write!(f, "call"),
            Token::Cdrop => write!(f, "cdrop"),
            Token::Cdropw => write!(f, "cdropw"),
            Token::Clk => write!(f, "clk"),
            Token::Const => write!(f, "const"),
            Token::Cswap => write!(f, "cswap"),
            Token::Cswapw => write!(f, "cswapw"),
            Token::Debug => write!(f, "debug"),
            Token::Div => write!(f, "div"),
            Token::Drop => write!(f, "drop"),
            Token::Dropw => write!(f, "dropw"),
            Token::Dup => write!(f, "dup"),
            Token::Dupw => write!(f, "dupw"),
            Token::Dynexec => write!(f, "dynexec"),
            Token::Dyncall => write!(f, "dyncall"),
            Token::Else => write!(f, "else"),
            Token::Emit => write!(f, "emit"),
            Token::End => write!(f, "end"),
            Token::Enum => write!(f, "enum"),
            Token::Eq => write!(f, "eq"),
            Token::Eqw => write!(f, "eqw"),
            Token::Ext2Add => write!(f, "ext2add"),
            Token::Ext2Div => write!(f, "ext2div"),
            Token::Ext2Inv => write!(f, "ext2inv"),
            Token::Ext2Mul => write!(f, "ext2mul"),
            Token::Ext2Neg => write!(f, "ext2neg"),
            Token::Ext2Sub => write!(f, "ext2sub"),
            Token::Err => write!(f, "err"),
            Token::Exec => write!(f, "exec"),
            Token::Exp => write!(f, "exp"),
            Token::ExpU => write!(f, "exp.u"),
            Token::Export => write!(f, "export"),
            Token::False => write!(f, "false"),
            Token::Felt => write!(f, "felt"),
            Token::FriExt2Fold4 => write!(f, "fri_ext2fold4"),
            Token::Gt => write!(f, "gt"),
            Token::Gte => write!(f, "gte"),
            Token::Hash => write!(f, "hash"),
            Token::HasMapkey => write!(f, "has_mapkey"),
            Token::Hperm => write!(f, "hperm"),
            Token::Hmerge => write!(f, "hmerge"),
            Token::I1 => write!(f, "i1"),
            Token::I8 => write!(f, "i8"),
            Token::I16 => write!(f, "i16"),
            Token::I32 => write!(f, "i32"),
            Token::I64 => write!(f, "i64"),
            Token::I128 => write!(f, "i128"),
            Token::If => write!(f, "if"),
            Token::ILog2 => write!(f, "ilog2"),
            Token::Inv => write!(f, "inv"),
            Token::IsOdd => write!(f, "is_odd"),
            Token::Local => write!(f, "local"),
            Token::Locaddr => write!(f, "locaddr"),
            Token::LocLoad => write!(f, "loc_load"),
            Token::LocLoadw => write!(f, "loc_loadw"),
            Token::LocStore => write!(f, "loc_store"),
            Token::LocStorew => write!(f, "loc_storew"),
            Token::Lt => write!(f, "lt"),
            Token::Lte => write!(f, "lte"),
            Token::Mem => write!(f, "mem"),
            Token::MemLoad => write!(f, "mem_load"),
            Token::MemLoadw => write!(f, "mem_loadw"),
            Token::MemLoadwBe => write!(f, "mem_loadw_be"),
            Token::MemLoadwLe => write!(f, "mem_loadw_le"),
            Token::MemStore => write!(f, "mem_store"),
            Token::MemStorew => write!(f, "mem_storew"),
            Token::MemStorewBe => write!(f, "mem_storew_be"),
            Token::MemStorewLe => write!(f, "mem_storew_le"),
            Token::MemStream => write!(f, "mem_stream"),
            Token::Movdn => write!(f, "movdn"),
            Token::Movdnw => write!(f, "movdnw"),
            Token::Movup => write!(f, "movup"),
            Token::Movupw => write!(f, "movupw"),
            Token::MtreeGet => write!(f, "mtree_get"),
            Token::MtreeMerge => write!(f, "mtree_merge"),
            Token::MtreeSet => write!(f, "mtree_set"),
            Token::MtreeVerify => write!(f, "mtree_verify"),
            Token::Mul => write!(f, "mul"),
            Token::Neg => write!(f, "neg"),
            Token::Neq => write!(f, "neq"),
            Token::Not => write!(f, "not"),
            Token::Nop => write!(f, "nop"),
            Token::Or => write!(f, "or"),
            Token::Padw => write!(f, "padw"),
            Token::Pow2 => write!(f, "pow2"),
            Token::Proc => write!(f, "proc"),
            Token::Procref => write!(f, "procref"),
            Token::Ptr => write!(f, "ptr"),
            Token::Pub => write!(f, "pub"),
            Token::Push => write!(f, "push"),
            Token::HornerBase => write!(f, "horner_eval_base"),
            Token::HornerExt => write!(f, "horner_eval_ext"),
            Token::Repeat => write!(f, "repeat"),
            Token::Reversew => write!(f, "reversew"),
            Token::Reversedw => write!(f, "reversedw"),
            Token::Sdepth => write!(f, "sdepth"),
            Token::Stack => write!(f, "stack"),
            Token::Struct => write!(f, "struct"),
            Token::Sub => write!(f, "sub"),
            Token::Swap => write!(f, "swap"),
            Token::Swapw => write!(f, "swapw"),
            Token::Swapdw => write!(f, "swapdw"),
            Token::Syscall => write!(f, "syscall"),
            Token::Trace => write!(f, "trace"),
            Token::True => write!(f, "true"),
            Token::Type => write!(f, "type"),
            Token::Use => write!(f, "use"),
            Token::U8 => write!(f, "u8"),
            Token::U16 => write!(f, "u16"),
            Token::U32 => write!(f, "u32"),
            Token::U32And => write!(f, "u32and"),
            Token::U32Assert => write!(f, "u32assert"),
            Token::U32Assert2 => write!(f, "u32assert2"),
            Token::U32Assertw => write!(f, "u32assertw"),
            Token::U32Cast => write!(f, "u32cast"),
            Token::U32Div => write!(f, "u32div"),
            Token::U32Divmod => write!(f, "u32divmod"),
            Token::U32Gt => write!(f, "u32gt"),
            Token::U32Gte => write!(f, "u32gte"),
            Token::U32Lt => write!(f, "u32lt"),
            Token::U32Lte => write!(f, "u32lte"),
            Token::U32Max => write!(f, "u32max"),
            Token::U32Min => write!(f, "u32min"),
            Token::U32Mod => write!(f, "u32mod"),
            Token::U32Not => write!(f, "u32not"),
            Token::U32Or => write!(f, "u32or"),
            Token::U32OverflowingAdd => write!(f, "u32overflowing_add"),
            Token::U32OverflowingAdd3 => write!(f, "u32overflowing_add3"),
            Token::U32OverflowingMadd => write!(f, "u32overflowing_madd"),
            Token::U32OverflowingMul => write!(f, "u32overflowing_mul"),
            Token::U32OverflowingSub => write!(f, "u32overflowing_sub"),
            Token::U32Popcnt => write!(f, "u32popcnt"),
            Token::U32Clz => write!(f, "u32clz"),
            Token::U32Ctz => write!(f, "u32ctz"),
            Token::U32Clo => write!(f, "u32clo"),
            Token::U32Cto => write!(f, "u32cto"),
            Token::U32Rotl => write!(f, "u32rotl"),
            Token::U32Rotr => write!(f, "u32rotr"),
            Token::U32Shl => write!(f, "u32shl"),
            Token::U32Shr => write!(f, "u32shr"),
            Token::U32Split => write!(f, "u32split"),
            Token::U32Test => write!(f, "u32test"),
            Token::U32Testw => write!(f, "u32testw"),
            Token::U32WrappingAdd => write!(f, "u32wrapping_add"),
            Token::U32WrappingAdd3 => write!(f, "u32wrapping_add3"),
            Token::U32WrappingMadd => write!(f, "u32wrapping_madd"),
            Token::U32WrappingMul => write!(f, "u32wrapping_mul"),
            Token::U32WrappingSub => write!(f, "u32wrapping_sub"),
            Token::U32Xor => write!(f, "u32xor"),
            Token::U64 => write!(f, "u64"),
            Token::U128 => write!(f, "u128"),
            Token::While => write!(f, "while"),
            Token::Word => write!(f, "word"),
            Token::Event => write!(f, "event"),
            Token::Xor => write!(f, "xor"),
            Token::At => write!(f, "@"),
            Token::Bang => write!(f, "!"),
            Token::Colon => write!(f, ":"),
            Token::ColonColon => write!(f, "::"),
            Token::Dot => write!(f, "."),
            Token::Comma => write!(f, ","),
            Token::Equal => write!(f, "="),
            Token::Langle => write!(f, "<"),
            Token::Lparen => write!(f, "("),
            Token::Lbrace => write!(f, "{{"),
            Token::Lbracket => write!(f, "["),
            Token::Minus => write!(f, "-"),
            Token::Plus => write!(f, "+"),
            Token::Semicolon => write!(f, ";"),
            Token::SlashSlash => write!(f, "//"),
            Token::Slash => write!(f, "/"),
            Token::Star => write!(f, "*"),
            Token::Rangle => write!(f, ">"),
            Token::Rparen => write!(f, ")"),
            Token::Rbrace => write!(f, "}}"),
            Token::Rbracket => write!(f, "]"),
            Token::Rstab => write!(f, "->"),
            Token::Range => write!(f, ".."),
            Token::DocComment(DocumentationType::Module(_)) => f.write_str("module doc"),
            Token::DocComment(DocumentationType::Form(_)) => f.write_str("doc comment"),
            Token::HexValue(_) => f.write_str("hex-encoded value"),
            Token::HexWord(_) => f.write_str("hex-encoded word"),
            Token::BinValue(_) => f.write_str("bin-encoded value"),
            Token::Int(_) => f.write_str("integer"),
            Token::Ident(_) => f.write_str("identifier"),
            Token::ConstantIdent(_) => f.write_str("constant identifier"),
            Token::QuotedIdent(_) => f.write_str("quoted identifier"),
            Token::QuotedString(_) => f.write_str("quoted string"),
            Token::Comment => f.write_str("comment"),
            Token::Eof => write!(f, "end of file"),
        }
    }
}

impl<'input> Token<'input> {
    /// Returns true if this token represents the name of an instruction.
    ///
    /// This is used to simplify diagnostic output related to expected tokens so as not to
    /// overwhelm the user with a ton of possible expected instruction variants.
    pub fn is_instruction(&self) -> bool {
        matches!(
            self,
            Token::Add
                | Token::Adv
                | Token::InsertHdword
                | Token::InsertHdwordWithDomain
                | Token::InsertHqword
                | Token::InsertHperm
                | Token::InsertMem
                | Token::AdvLoadw
                | Token::AdvPipe
                | Token::AdvPush
                | Token::AdvStack
                | Token::PushMapval
                | Token::PushMapvaln
                | Token::PushMtnode
                | Token::And
                | Token::Assert
                | Token::Assertz
                | Token::AssertEq
                | Token::AssertEqw
                | Token::EvalCircuit
                | Token::Breakpoint
                | Token::Caller
                | Token::Call
                | Token::Cdrop
                | Token::Cdropw
                | Token::Clk
                | Token::Cswap
                | Token::Cswapw
                | Token::Debug
                | Token::Div
                | Token::Drop
                | Token::Dropw
                | Token::Dup
                | Token::Dupw
                | Token::Dynexec
                | Token::Dyncall
                | Token::Emit
                | Token::Eq
                | Token::Eqw
                | Token::Ext2Add
                | Token::Ext2Div
                | Token::Ext2Inv
                | Token::Ext2Mul
                | Token::Ext2Neg
                | Token::Ext2Sub
                | Token::Exec
                | Token::Exp
                | Token::ExpU
                | Token::FriExt2Fold4
                | Token::Gt
                | Token::Gte
                | Token::Hash
                | Token::Hperm
                | Token::Hmerge
                | Token::HornerBase
                | Token::HornerExt
                | Token::ILog2
                | Token::Inv
                | Token::IsOdd
                | Token::Local
                | Token::Locaddr
                | Token::LocLoad
                | Token::LocLoadw
                | Token::LocStore
                | Token::LocStorew
                | Token::Lt
                | Token::Lte
                | Token::Mem
                | Token::MemLoad
                | Token::MemLoadw
                | Token::MemLoadwBe
                | Token::MemLoadwLe
                | Token::MemStore
                | Token::MemStorew
                | Token::MemStorewBe
                | Token::MemStorewLe
                | Token::MemStream
                | Token::Movdn
                | Token::Movdnw
                | Token::Movup
                | Token::Movupw
                | Token::MtreeGet
                | Token::MtreeMerge
                | Token::MtreeSet
                | Token::MtreeVerify
                | Token::Mul
                | Token::Neg
                | Token::Neq
                | Token::Not
                | Token::Nop
                | Token::Or
                | Token::Padw
                | Token::Pow2
                | Token::Procref
                | Token::Push
                | Token::Repeat
                | Token::Reversew
                | Token::Reversedw
                | Token::Sdepth
                | Token::Stack
                | Token::Sub
                | Token::Swap
                | Token::Swapw
                | Token::Swapdw
                | Token::Syscall
                | Token::Trace
                | Token::U32And
                | Token::U32Assert
                | Token::U32Assert2
                | Token::U32Assertw
                | Token::U32Cast
                | Token::U32Div
                | Token::U32Divmod
                | Token::U32Gt
                | Token::U32Gte
                | Token::U32Lt
                | Token::U32Lte
                | Token::U32Max
                | Token::U32Min
                | Token::U32Mod
                | Token::U32Not
                | Token::U32Or
                | Token::U32OverflowingAdd
                | Token::U32OverflowingAdd3
                | Token::U32OverflowingMadd
                | Token::U32OverflowingMul
                | Token::U32OverflowingSub
                | Token::U32Popcnt
                | Token::U32Clz
                | Token::U32Ctz
                | Token::U32Clo
                | Token::U32Cto
                | Token::U32Rotl
                | Token::U32Rotr
                | Token::U32Shl
                | Token::U32Shr
                | Token::U32Split
                | Token::U32Test
                | Token::U32Testw
                | Token::U32WrappingAdd
                | Token::U32WrappingAdd3
                | Token::U32WrappingMadd
                | Token::U32WrappingMul
                | Token::U32WrappingSub
                | Token::U32Xor
                | Token::Xor
        )
    }

    /// Returns true if this token represents the name of an type or a type-related keyword.
    ///
    /// This is used to simplify diagnostic output related to expected tokens so as not to
    /// overwhelm the user with a ton of possible expected tokens.
    pub fn is_type_keyword(&self) -> bool {
        matches!(
            self,
            Token::Addrspace
                | Token::Ptr
                | Token::I1
                | Token::I8
                | Token::I16
                | Token::I32
                | Token::I64
                | Token::I128
                | Token::U8
                | Token::U16
                | Token::U32
                | Token::U64
                | Token::U128
                | Token::Struct
        )
    }

    const KEYWORDS: &'static [(&'static str, Token<'static>)] = &[
        ("add", Token::Add),
        ("addrspace", Token::Addrspace),
        ("adv", Token::Adv),
        ("adv_map", Token::AdvMap),
        ("eval_circuit", Token::EvalCircuit),
        ("insert_hdword", Token::InsertHdword),
        ("insert_hdword_d", Token::InsertHdwordWithDomain),
        ("insert_hqword", Token::InsertHqword),
        ("insert_hperm", Token::InsertHperm),
        ("insert_mem", Token::InsertMem),
        ("adv_loadw", Token::AdvLoadw),
        ("adv_pipe", Token::AdvPipe),
        ("adv_push", Token::AdvPush),
        ("adv_stack", Token::AdvStack),
        ("push_mapval", Token::PushMapval),
        ("push_mapvaln", Token::PushMapvaln),
        ("push_mtnode", Token::PushMtnode),
        ("and", Token::And),
        ("assert", Token::Assert),
        ("assertz", Token::Assertz),
        ("assert_eq", Token::AssertEq),
        ("assert_eqw", Token::AssertEqw),
        ("begin", Token::Begin),
        ("breakpoint", Token::Breakpoint),
        ("byte", Token::Byte),
        ("caller", Token::Caller),
        ("call", Token::Call),
        ("cdrop", Token::Cdrop),
        ("cdropw", Token::Cdropw),
        ("clk", Token::Clk),
        ("const", Token::Const),
        ("cswap", Token::Cswap),
        ("cswapw", Token::Cswapw),
        ("debug", Token::Debug),
        ("div", Token::Div),
        ("drop", Token::Drop),
        ("dropw", Token::Dropw),
        ("dup", Token::Dup),
        ("dupw", Token::Dupw),
        ("dynexec", Token::Dynexec),
        ("dyncall", Token::Dyncall),
        ("else", Token::Else),
        ("emit", Token::Emit),
        ("end", Token::End),
        ("enum", Token::Enum),
        ("eq", Token::Eq),
        ("eqw", Token::Eqw),
        ("ext2add", Token::Ext2Add),
        ("ext2div", Token::Ext2Div),
        ("ext2inv", Token::Ext2Inv),
        ("ext2mul", Token::Ext2Mul),
        ("ext2neg", Token::Ext2Neg),
        ("ext2sub", Token::Ext2Sub),
        ("err", Token::Err),
        ("exec", Token::Exec),
        ("exp", Token::Exp),
        ("exp.u", Token::ExpU),
        ("export", Token::Export),
        ("false", Token::False),
        ("felt", Token::Felt),
        ("fri_ext2fold4", Token::FriExt2Fold4),
        ("gt", Token::Gt),
        ("gte", Token::Gte),
        ("hash", Token::Hash),
        ("has_mapkey", Token::HasMapkey),
        ("hperm", Token::Hperm),
        ("hmerge", Token::Hmerge),
        ("i1", Token::I1),
        ("i8", Token::I8),
        ("i16", Token::I16),
        ("i32", Token::I32),
        ("i64", Token::I64),
        ("i128", Token::I128),
        ("if", Token::If),
        ("ilog2", Token::ILog2),
        ("inv", Token::Inv),
        ("is_odd", Token::IsOdd),
        ("local", Token::Local),
        ("locaddr", Token::Locaddr),
        ("loc_load", Token::LocLoad),
        ("loc_loadw", Token::LocLoadw),
        ("loc_store", Token::LocStore),
        ("loc_storew", Token::LocStorew),
        ("lt", Token::Lt),
        ("lte", Token::Lte),
        ("mem", Token::Mem),
        ("mem_load", Token::MemLoad),
        ("mem_loadw", Token::MemLoadw),
        ("mem_loadw_be", Token::MemLoadwBe),
        ("mem_loadw_le", Token::MemLoadwLe),
        ("mem_store", Token::MemStore),
        ("mem_storew", Token::MemStorew),
        ("mem_storew_be", Token::MemStorewBe),
        ("mem_storew_le", Token::MemStorewLe),
        ("mem_stream", Token::MemStream),
        ("movdn", Token::Movdn),
        ("movdnw", Token::Movdnw),
        ("movup", Token::Movup),
        ("movupw", Token::Movupw),
        ("mtree_get", Token::MtreeGet),
        ("mtree_merge", Token::MtreeMerge),
        ("mtree_set", Token::MtreeSet),
        ("mtree_verify", Token::MtreeVerify),
        ("mul", Token::Mul),
        ("neg", Token::Neg),
        ("neq", Token::Neq),
        ("not", Token::Not),
        ("nop", Token::Nop),
        ("or", Token::Or),
        ("padw", Token::Padw),
        ("pow2", Token::Pow2),
        ("proc", Token::Proc),
        ("procref", Token::Procref),
        ("ptr", Token::Ptr),
        ("push", Token::Push),
        ("pub", Token::Pub),
        ("horner_eval_base", Token::HornerBase),
        ("horner_eval_ext", Token::HornerExt),
        ("repeat", Token::Repeat),
        ("reversew", Token::Reversew),
        ("reversedw", Token::Reversedw),
        ("sdepth", Token::Sdepth),
        ("stack", Token::Stack),
        ("struct", Token::Struct),
        ("sub", Token::Sub),
        ("swap", Token::Swap),
        ("swapw", Token::Swapw),
        ("swapdw", Token::Swapdw),
        ("syscall", Token::Syscall),
        ("trace", Token::Trace),
        ("true", Token::True),
        ("type", Token::Type),
        ("use", Token::Use),
        ("u8", Token::U8),
        ("u16", Token::U16),
        ("u32", Token::U32),
        ("u32and", Token::U32And),
        ("u32assert", Token::U32Assert),
        ("u32assert2", Token::U32Assert2),
        ("u32assertw", Token::U32Assertw),
        ("u32cast", Token::U32Cast),
        ("u32div", Token::U32Div),
        ("u32divmod", Token::U32Divmod),
        ("u32gt", Token::U32Gt),
        ("u32gte", Token::U32Gte),
        ("u32lt", Token::U32Lt),
        ("u32lte", Token::U32Lte),
        ("u32max", Token::U32Max),
        ("u32min", Token::U32Min),
        ("u32mod", Token::U32Mod),
        ("u32not", Token::U32Not),
        ("u32or", Token::U32Or),
        ("u32overflowing_add", Token::U32OverflowingAdd),
        ("u32overflowing_add3", Token::U32OverflowingAdd3),
        ("u32overflowing_madd", Token::U32OverflowingMadd),
        ("u32overflowing_mul", Token::U32OverflowingMul),
        ("u32overflowing_sub", Token::U32OverflowingSub),
        ("u32popcnt", Token::U32Popcnt),
        ("u32clz", Token::U32Clz),
        ("u32ctz", Token::U32Ctz),
        ("u32clo", Token::U32Clo),
        ("u32cto", Token::U32Cto),
        ("u32rotl", Token::U32Rotl),
        ("u32rotr", Token::U32Rotr),
        ("u32shl", Token::U32Shl),
        ("u32shr", Token::U32Shr),
        ("u32split", Token::U32Split),
        ("u32test", Token::U32Test),
        ("u32testw", Token::U32Testw),
        ("u32wrapping_add", Token::U32WrappingAdd),
        ("u32wrapping_add3", Token::U32WrappingAdd3),
        ("u32wrapping_madd", Token::U32WrappingMadd),
        ("u32wrapping_mul", Token::U32WrappingMul),
        ("u32wrapping_sub", Token::U32WrappingSub),
        ("u32xor", Token::U32Xor),
        ("u64", Token::U64),
        ("u128", Token::U128),
        ("while", Token::While),
        ("word", Token::Word),
        ("event", Token::Event),
        ("xor", Token::Xor),
    ];

    /// Constructs a DFA capable of recognizing Miden Assembly keywords.
    ///
    /// Constructing the state machine is expensive, so it should not be done in hot code. Instead,
    /// prefer to construct it once and reuse it many times.
    ///
    /// Currently we construct an instance of this searcher in the lexer, which is then used to
    /// select a keyword token or construct an identifier token depending on whether a given string
    /// is a known keyword.
    pub fn keyword_searcher() -> aho_corasick::AhoCorasick {
        use aho_corasick::AhoCorasick;

        // Execute a search for any of the keywords above, matching longest first, and requiring
        // the match to cover the entire input.
        AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::LeftmostLongest)
            .start_kind(aho_corasick::StartKind::Anchored)
            .build(Self::KEYWORDS.iter().map(|(kw, _)| kw).copied())
            .expect("unable to build aho-corasick searcher for token")
    }

    /// Returns an appropriate [Token] depending on whether the given string is a keyword or an
    /// identifier.
    ///
    /// NOTE: This constructs and throws away an expensive-to-construct Aho-Corasick state machine.
    /// You should not call this from any code on a hot path. Instead, construct the state machine
    /// once using [Token::keyword_searcher], and reuse it for all searches using
    /// [Token::from_keyword_or_ident_with_searcher].
    ///
    /// Currently, this function is only called along one code path, which is when we are
    /// constructing a parser error in which we wish to determine which, if any, of the expected
    /// tokens are instruction opcode keywords, so we can collapse them into a more user-friendly
    /// error message. This is not on a hot path, so we don't care if it is a bit slow.
    pub fn from_keyword_or_ident(s: &'input str) -> Self {
        let searcher = Self::keyword_searcher();
        Self::from_keyword_or_ident_with_searcher(s, &searcher)
    }

    /// This is the primary function you should use when you wish to get an appropriate token for
    /// a given input string, depending on whether it is a keyword or an identifier.
    ///
    /// See [Token::keyword_searcher] for additional information on how this is meant to be used.
    pub fn from_keyword_or_ident_with_searcher(
        s: &'input str,
        searcher: &aho_corasick::AhoCorasick,
    ) -> Self {
        let input = aho_corasick::Input::new(s).anchored(aho_corasick::Anchored::Yes);
        match searcher.find(input) {
            // No match, it's an ident
            None => Token::Ident(s),
            // If the match is not exact, it's an ident
            Some(matched) if matched.len() != s.len() => Token::Ident(s),
            // Otherwise clone the Token corresponding to the keyword that was matched
            Some(matched) => Self::KEYWORDS[matched.pattern().as_usize()].1.clone(),
        }
    }

    /// Parses a [Token] from a string corresponding to that token.
    ///
    /// This solely exists to aid in constructing more user-friendly error messages in certain
    /// scenarios, and is otherwise not used (nor should it be). It is quite expensive to call due
    /// to invoking [Token::keyword_searcher] under the covers. See the documentation for that
    /// function for more details.
    pub fn parse(s: &'input str) -> Option<Token<'input>> {
        match Token::from_keyword_or_ident(s) {
            Token::Ident(_) => {
                // Nope, try again
                match s {
                    "@" => Some(Token::At),
                    "!" => Some(Token::Bang),
                    ":" => Some(Token::Colon),
                    "::" => Some(Token::ColonColon),
                    "." => Some(Token::Dot),
                    "," => Some(Token::Comma),
                    "=" => Some(Token::Equal),
                    "<" => Some(Token::Langle),
                    "(" => Some(Token::Lparen),
                    "{" => Some(Token::Lbrace),
                    "[" => Some(Token::Lbracket),
                    "-" => Some(Token::Minus),
                    "+" => Some(Token::Plus),
                    ";" => Some(Token::Semicolon),
                    "//" => Some(Token::SlashSlash),
                    "/" => Some(Token::Slash),
                    "*" => Some(Token::Star),
                    ">" => Some(Token::Rangle),
                    ")" => Some(Token::Rparen),
                    "}" => Some(Token::Rbrace),
                    "]" => Some(Token::Rbracket),
                    "->" => Some(Token::Rstab),
                    ".." => Some(Token::Range),
                    "end of file" => Some(Token::Eof),
                    "module doc" => {
                        Some(Token::DocComment(DocumentationType::Module(String::new())))
                    },
                    "doc comment" => {
                        Some(Token::DocComment(DocumentationType::Form(String::new())))
                    },
                    "comment" => Some(Token::Comment),
                    "hex-encoded value" => Some(Token::HexValue(IntValue::U8(0))),
                    "hex-encoded word" => Some(Token::HexWord(WordValue([Felt::ZERO; 4]))),
                    "bin-encoded value" => Some(Token::BinValue(BinEncodedValue::U8(0))),
                    "integer" => Some(Token::Int(0)),
                    "identifier" => Some(Token::Ident("")),
                    "constant identifier" => Some(Token::ConstantIdent("")),
                    "quoted identifier" => Some(Token::QuotedIdent("")),
                    "quoted string" => Some(Token::QuotedString("")),
                    _ => None,
                }
            },
            // We matched a keyword
            token => Some(token),
        }
    }
}
