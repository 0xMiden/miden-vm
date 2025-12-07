//! This module provides an implementation of the visitor pattern for the AST of Miden Assembly.
//!
//! The pattern is implemented in terms of two traits, `Visit` and `VisitMut`, corresponding to
//! whether or not the visitor has mutable access to each AST node.
//!
//! In addition to the visitor traits, there are a number of free functions that correspond to the
//! methods of those traits. For example, the visit methods for a [Procedure] are
//! [Visit::visit_procedure] and [VisitMut::visit_mut_procedure]. There are two free functions that
//! are used in conjunction with these methods: [visit_procedure], and [visit_mut_procedure], which
//! are typically not imported directly, but are referenced through the `visit` module, e.g.
//! `visit::visit_procedure`. These free functions implement the default visitor for the AST node
//! they correspond to. By default, all methods of the `Visit` and `VisitMut` traits delegate to
//! these functions. As a result, `impl Visit for MyVisitor {}` is technically a valid visitor, and
//! will traverse the entire AST if invoked.
//!
//! Obviously, that visitor wouldn't be very useful, but in practice, the free functions are called
//! to resume traversal of the AST either before or after executing the desired behavior for a given
//! AST node. Doing so essentially corresponds to either a post- or preorder traversal of the AST
//! respectively.
//!
//! How do you choose between performing a postorder vs preorder visit? It depends on the semantics
//! of the visitor, but here are some examples:
//!
//! 1. When implementing a visitor that performs constant folding/propagation, you need to visit the
//!    operands of an expression before the operator, in order to determine whether it is possible
//!    to fold, and if so, what the actual values of the operands are. As a result, this is
//!    implemented as a postorder visitor, so that the AST node corresponding to the expression is
//!    rewritten after all of it's children.
//!
//! 2. When implementing an analysis based on lexical scope, it is necessary to "push down" context
//!    from the root to the leaves of the AST - the context being the contents of each AST nodes
//!    inherited scope. As a result, this is implemented as a preorder traversal, so that the
//!    context at each node can be computed before visiting the children of that node.
//!
//! In both cases, the implementor must call the free function corresponding to the _current_ AST
//! node at the appropriate point (i.e. before/after executing the logic for the node), so that the
//! visitor will resume its traversal of the tree correctly. Put another way, failing to do so will
//! cause the traversal to stop at that node (it will continue visiting sibling nodes, if
//! applicable, but it will go no deeper in the tree).
//!
//! # FAQs
//!
//! * Why are the free `visit` functions needed?
//!
//! Technically they aren't - you could reimplement the visit pattern for every AST node, in each
//! visitor, independently. However, this is a lot of boilerplate (as you can see below), and would
//! represent a major maintenance burden if the AST changes shape at all. By implementing the
//! default pattern in those free functions, they can be reused everywhere, and a visitor need only
//! override the methods of those nodes it cares about. Changes to the AST only require modifying
//! the code in this module, with the exception of visitors whose logic must be updated to reflect
//! modifications to specific nodes they care about.
use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_debug_types::Span;

use super::immediate::ErrorMsg;
use crate::{
    Felt,
    ast::*,
    parser::{PushValue, WordValue},
};

/// Represents an immutable AST visitor, whose "early return" type is `T` (by default `()`).
///
/// Immutable visitors are primarily used for analysis, or to search the AST for something specific.
///
/// Unless explicitly overridden, all methods of this trait will perform a default depth-first
/// traversal of the AST. When a node is overridden, you must ensure that the corresponding free
/// function in this module is called at an appropriate point if you wish to visit all of the
/// children of that node. For example, if visiting procedures, you must call
/// `visit::visit_procedure` either before you do your analysis for that procedure, or after,
/// corresponding to whether you are pushing information up the tree, or down. If you do not do
/// this, none of the children of the [Procedure] node will be visited. This is perfectly valid!
/// Sometimes you don't want/need to waste time on the children of a node if you can obtain all the
/// information you need at the parent. It is just important to be aware that this is one of the
/// elements placed in the hands of the visitor implementation.
///
/// The methods of this trait all return [core::ops::ControlFlow], which can be used to break out
/// of the traversal early via `ControlFlow::Break`. The `T` type parameter of this trait controls
/// what the value associated with an early return will be. In most cases, the default of `()` is
/// all you need - but in some cases it can be useful to return an error or other value, that
/// indicates why the traversal ended early.
pub trait Visit<T = ()> {
    fn visit_module(&mut self, module: &Module) -> ControlFlow<T> {
        visit_module(self, module)
    }
    fn visit_export(&mut self, export: &Export) -> ControlFlow<T> {
        visit_export(self, export)
    }
    fn visit_procedure(&mut self, procedure: &Procedure) -> ControlFlow<T> {
        visit_procedure(self, procedure)
    }
    fn visit_constant(&mut self, constant: &Constant) -> ControlFlow<T> {
        visit_constant(self, constant)
    }
    fn visit_constant_expr(&mut self, expr: &ConstantExpr) -> ControlFlow<T> {
        visit_constant_expr(self, expr)
    }
    fn visit_constant_ref(&mut self, path: &Span<Arc<Path>>) -> ControlFlow<T> {
        visit_constant_ref(self, path)
    }
    fn visit_type_decl(&mut self, ty: &TypeDecl) -> ControlFlow<T> {
        visit_type_decl(self, ty)
    }
    fn visit_type_alias(&mut self, ty: &TypeAlias) -> ControlFlow<T> {
        visit_type_alias(self, ty)
    }
    fn visit_type_expr(&mut self, ty: &TypeExpr) -> ControlFlow<T> {
        visit_type_expr(self, ty)
    }
    fn visit_type_ref(&mut self, path: &Span<Arc<Path>>) -> ControlFlow<T> {
        visit_type_ref(self, path)
    }
    fn visit_enum(&mut self, ty: &EnumType) -> ControlFlow<T> {
        visit_enum(self, ty)
    }
    fn visit_enum_variant(&mut self, variant: &Variant) -> ControlFlow<T> {
        visit_enum_variant(self, variant)
    }
    fn visit_alias(&mut self, alias: &Alias) -> ControlFlow<T> {
        visit_alias(self, alias)
    }
    fn visit_block(&mut self, block: &Block) -> ControlFlow<T> {
        visit_block(self, block)
    }
    fn visit_op(&mut self, op: &Op) -> ControlFlow<T> {
        visit_op(self, op)
    }
    fn visit_inst(&mut self, inst: &Span<Instruction>) -> ControlFlow<T> {
        visit_inst(self, inst)
    }
    fn visit_system_event(&mut self, sys_event: Span<&SystemEventNode>) -> ControlFlow<T> {
        visit_system_event(self, sys_event)
    }
    fn visit_debug_options(&mut self, options: Span<&DebugOptions>) -> ControlFlow<T> {
        visit_debug_options(self, options)
    }
    fn visit_exec(&mut self, target: &InvocationTarget) -> ControlFlow<T> {
        visit_exec(self, target)
    }
    fn visit_call(&mut self, target: &InvocationTarget) -> ControlFlow<T> {
        visit_call(self, target)
    }
    fn visit_syscall(&mut self, target: &InvocationTarget) -> ControlFlow<T> {
        visit_syscall(self, target)
    }
    fn visit_procref(&mut self, target: &InvocationTarget) -> ControlFlow<T> {
        visit_procref(self, target)
    }
    fn visit_invoke_target(&mut self, target: &InvocationTarget) -> ControlFlow<T> {
        visit_invoke_target(self, target)
    }
    fn visit_alias_target(&mut self, target: &AliasTarget) -> ControlFlow<T> {
        visit_alias_target(self, target)
    }
    fn visit_immediate_u8(&mut self, imm: &Immediate<u8>) -> ControlFlow<T> {
        visit_immediate_u8(self, imm)
    }
    fn visit_immediate_u16(&mut self, imm: &Immediate<u16>) -> ControlFlow<T> {
        visit_immediate_u16(self, imm)
    }
    fn visit_immediate_u32(&mut self, imm: &Immediate<u32>) -> ControlFlow<T> {
        visit_immediate_u32(self, imm)
    }
    fn visit_immediate_felt(&mut self, imm: &Immediate<Felt>) -> ControlFlow<T> {
        visit_immediate_felt(self, imm)
    }
    fn visit_immediate_word_value(&mut self, code: &Immediate<WordValue>) -> ControlFlow<T> {
        visit_immediate_word_value(self, code)
    }
    fn visit_immediate_push_value(&mut self, code: &Immediate<PushValue>) -> ControlFlow<T> {
        visit_immediate_push_value(self, code)
    }
    fn visit_immediate_error_message(&mut self, code: &ErrorMsg) -> ControlFlow<T> {
        visit_immediate_error_message(self, code)
    }
}

impl<V, T> Visit<T> for &mut V
where
    V: ?Sized + Visit<T>,
{
    fn visit_module(&mut self, module: &Module) -> ControlFlow<T> {
        (**self).visit_module(module)
    }
    fn visit_export(&mut self, export: &Export) -> ControlFlow<T> {
        (**self).visit_export(export)
    }
    fn visit_procedure(&mut self, procedure: &Procedure) -> ControlFlow<T> {
        (**self).visit_procedure(procedure)
    }
    fn visit_constant(&mut self, constant: &Constant) -> ControlFlow<T> {
        (**self).visit_constant(constant)
    }
    fn visit_constant_expr(&mut self, expr: &ConstantExpr) -> ControlFlow<T> {
        (**self).visit_constant_expr(expr)
    }
    fn visit_constant_ref(&mut self, path: &Span<Arc<Path>>) -> ControlFlow<T> {
        (**self).visit_constant_ref(path)
    }
    fn visit_type_decl(&mut self, ty: &TypeDecl) -> ControlFlow<T> {
        (**self).visit_type_decl(ty)
    }
    fn visit_type_alias(&mut self, ty: &TypeAlias) -> ControlFlow<T> {
        (**self).visit_type_alias(ty)
    }
    fn visit_type_expr(&mut self, ty: &TypeExpr) -> ControlFlow<T> {
        (**self).visit_type_expr(ty)
    }
    fn visit_type_ref(&mut self, path: &Span<Arc<Path>>) -> ControlFlow<T> {
        (**self).visit_type_ref(path)
    }
    fn visit_enum(&mut self, ty: &EnumType) -> ControlFlow<T> {
        (**self).visit_enum(ty)
    }
    fn visit_enum_variant(&mut self, variant: &Variant) -> ControlFlow<T> {
        (**self).visit_enum_variant(variant)
    }
    fn visit_alias(&mut self, alias: &Alias) -> ControlFlow<T> {
        (**self).visit_alias(alias)
    }
    fn visit_block(&mut self, block: &Block) -> ControlFlow<T> {
        (**self).visit_block(block)
    }
    fn visit_op(&mut self, op: &Op) -> ControlFlow<T> {
        (**self).visit_op(op)
    }
    fn visit_inst(&mut self, inst: &Span<Instruction>) -> ControlFlow<T> {
        (**self).visit_inst(inst)
    }
    fn visit_system_event(&mut self, sys_event: Span<&SystemEventNode>) -> ControlFlow<T> {
        (**self).visit_system_event(sys_event)
    }
    fn visit_debug_options(&mut self, options: Span<&DebugOptions>) -> ControlFlow<T> {
        (**self).visit_debug_options(options)
    }
    fn visit_exec(&mut self, target: &InvocationTarget) -> ControlFlow<T> {
        (**self).visit_exec(target)
    }
    fn visit_call(&mut self, target: &InvocationTarget) -> ControlFlow<T> {
        (**self).visit_call(target)
    }
    fn visit_syscall(&mut self, target: &InvocationTarget) -> ControlFlow<T> {
        (**self).visit_syscall(target)
    }
    fn visit_procref(&mut self, target: &InvocationTarget) -> ControlFlow<T> {
        (**self).visit_procref(target)
    }
    fn visit_invoke_target(&mut self, target: &InvocationTarget) -> ControlFlow<T> {
        (**self).visit_invoke_target(target)
    }
    fn visit_alias_target(&mut self, target: &AliasTarget) -> ControlFlow<T> {
        (**self).visit_alias_target(target)
    }
    fn visit_immediate_u8(&mut self, imm: &Immediate<u8>) -> ControlFlow<T> {
        (**self).visit_immediate_u8(imm)
    }
    fn visit_immediate_u16(&mut self, imm: &Immediate<u16>) -> ControlFlow<T> {
        (**self).visit_immediate_u16(imm)
    }
    fn visit_immediate_u32(&mut self, imm: &Immediate<u32>) -> ControlFlow<T> {
        (**self).visit_immediate_u32(imm)
    }
    fn visit_immediate_felt(&mut self, imm: &Immediate<Felt>) -> ControlFlow<T> {
        (**self).visit_immediate_felt(imm)
    }
    fn visit_immediate_word_value(&mut self, imm: &Immediate<WordValue>) -> ControlFlow<T> {
        (**self).visit_immediate_word_value(imm)
    }
    fn visit_immediate_push_value(&mut self, imm: &Immediate<PushValue>) -> ControlFlow<T> {
        (**self).visit_immediate_push_value(imm)
    }
    fn visit_immediate_error_message(&mut self, code: &ErrorMsg) -> ControlFlow<T> {
        (**self).visit_immediate_error_message(code)
    }
}

pub fn visit_module<V, T>(visitor: &mut V, module: &Module) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    for export in module.items() {
        visitor.visit_export(export)?;
    }

    ControlFlow::Continue(())
}

pub fn visit_export<V, T>(visitor: &mut V, export: &Export) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    match export {
        Export::Procedure(item) => visitor.visit_procedure(item),
        Export::Constant(item) => visitor.visit_constant(item),
        Export::Type(item) => visitor.visit_type_decl(item),
        Export::Alias(item) => visitor.visit_alias(item),
    }
}

pub fn visit_procedure<V, T>(visitor: &mut V, procedure: &Procedure) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    visitor.visit_block(procedure.body())
}

#[inline(always)]
pub fn visit_constant<V, T>(visitor: &mut V, constant: &Constant) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    visitor.visit_constant_expr(&constant.value)
}

pub fn visit_constant_expr<V, T>(visitor: &mut V, expr: &ConstantExpr) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    match expr {
        ConstantExpr::Var(path) => visitor.visit_constant_ref(path),
        ConstantExpr::BinaryOp { lhs, rhs, .. } => {
            visitor.visit_constant_expr(lhs)?;
            visitor.visit_constant_expr(rhs)
        },
        ConstantExpr::Hash(..)
        | ConstantExpr::Int(_)
        | ConstantExpr::String(_)
        | ConstantExpr::Word(_) => ControlFlow::Continue(()),
    }
}

#[inline(always)]
pub fn visit_constant_ref<V, T>(_visitor: &mut V, _path: &Span<Arc<Path>>) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    ControlFlow::Continue(())
}

pub fn visit_type_decl<V, T>(visitor: &mut V, ty: &TypeDecl) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    match ty {
        TypeDecl::Alias(ty) => visitor.visit_type_alias(ty),
        TypeDecl::Enum(ty) => visitor.visit_enum(ty),
    }
}

pub fn visit_type_alias<V, T>(visitor: &mut V, ty: &TypeAlias) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    visitor.visit_type_expr(&ty.ty)
}

pub fn visit_type_expr<V, T>(visitor: &mut V, ty: &TypeExpr) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    match ty {
        TypeExpr::Ref(path) => visitor.visit_type_ref(path),
        TypeExpr::Primitive(_) => ControlFlow::Continue(()),
        TypeExpr::Array(ty) => visitor.visit_type_expr(&ty.elem),
        TypeExpr::Ptr(ty) => visitor.visit_type_expr(&ty.pointee),
        TypeExpr::Struct(ty) => {
            for field in ty.fields.iter() {
                visitor.visit_type_expr(&field.ty)?;
            }
            ControlFlow::Continue(())
        },
    }
}

#[inline(always)]
pub fn visit_type_ref<V, T>(_visitor: &mut V, _path: &Span<Arc<Path>>) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    ControlFlow::Continue(())
}

pub fn visit_enum<V, T>(visitor: &mut V, ty: &EnumType) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    for variant in ty.variants() {
        visitor.visit_enum_variant(variant)?;
    }
    ControlFlow::Continue(())
}

#[inline(always)]
pub fn visit_enum_variant<V, T>(_visitor: &mut V, _variant: &Variant) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    ControlFlow::Continue(())
}

#[inline(always)]
pub fn visit_alias<V, T>(visitor: &mut V, alias: &Alias) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    visitor.visit_alias_target(alias.target())
}

pub fn visit_block<V, T>(visitor: &mut V, block: &Block) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    for op in block.iter() {
        visitor.visit_op(op)?;
    }
    ControlFlow::Continue(())
}

pub fn visit_op<V, T>(visitor: &mut V, op: &Op) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    match op {
        Op::If { then_blk, else_blk, .. } => {
            visitor.visit_block(then_blk)?;
            visitor.visit_block(else_blk)
        },
        Op::While { body, .. } | Op::Repeat { body, .. } => visitor.visit_block(body),
        Op::Inst(inst) => visitor.visit_inst(inst),
    }
}

pub fn visit_inst<V, T>(visitor: &mut V, inst: &Span<Instruction>) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    use Instruction::*;
    let span = inst.span();
    match &**inst {
        U32ShrImm(imm) | U32ShlImm(imm) | U32RotrImm(imm) | U32RotlImm(imm) | AdvPush(imm) => {
            visitor.visit_immediate_u8(imm)
        },
        Locaddr(imm) | LocLoad(imm) | LocLoadWBe(imm) | LocLoadWLe(imm) | LocStore(imm)
        | LocStoreWBe(imm) | LocStoreWLe(imm) => visitor.visit_immediate_u16(imm),
        AssertWithError(code)
        | AssertEqWithError(code)
        | AssertEqwWithError(code)
        | AssertzWithError(code)
        | U32AssertWithError(code)
        | U32Assert2WithError(code)
        | U32AssertWWithError(code)
        | MTreeVerifyWithError(code) => visitor.visit_immediate_error_message(code),
        AddImm(imm) | SubImm(imm) | MulImm(imm) | DivImm(imm) | ExpImm(imm) | EqImm(imm)
        | NeqImm(imm) => visitor.visit_immediate_felt(imm),
        Push(imm) => visitor.visit_immediate_push_value(imm),
        PushSlice(imm, _) => visitor.visit_immediate_word_value(imm),
        U32WrappingAddImm(imm)
        | U32OverflowingAddImm(imm)
        | U32WrappingSubImm(imm)
        | U32OverflowingSubImm(imm)
        | U32WrappingMulImm(imm)
        | U32OverflowingMulImm(imm)
        | U32DivImm(imm)
        | U32ModImm(imm)
        | U32DivModImm(imm)
        | MemLoadImm(imm)
        | MemLoadWBeImm(imm)
        | MemLoadWLeImm(imm)
        | MemStoreImm(imm)
        | MemStoreWBeImm(imm)
        | MemStoreWLeImm(imm)
        | Trace(imm) => visitor.visit_immediate_u32(imm),
        EmitImm(imm) => visitor.visit_immediate_felt(imm),
        SysEvent(sys_event) => visitor.visit_system_event(Span::new(span, sys_event)),
        Exec(target) => visitor.visit_exec(target),
        Call(target) => visitor.visit_call(target),
        SysCall(target) => visitor.visit_syscall(target),
        ProcRef(target) => visitor.visit_procref(target),
        Debug(options) => visitor.visit_debug_options(Span::new(span, options)),
        Nop | Assert | AssertEq | AssertEqw | Assertz | Add | Sub | Mul | Div | Neg | ILog2
        | Inv | Incr | Pow2 | Exp | ExpBitLength(_) | Not | And | Or | Xor | Eq | Neq | Eqw
        | Lt | Lte | Gt | Gte | IsOdd | Ext2Add | Ext2Sub | Ext2Mul | Ext2Div | Ext2Neg
        | Ext2Inv | U32Test | U32TestW | U32Assert | U32Assert2 | U32AssertW | U32Split
        | U32Cast | U32WrappingAdd | U32OverflowingAdd | U32OverflowingAdd3 | U32WrappingAdd3
        | U32WrappingSub | U32OverflowingSub | U32WrappingMul | U32OverflowingMul
        | U32OverflowingMadd | U32WrappingMadd | U32Div | U32Mod | U32DivMod | U32And | U32Or
        | U32Xor | U32Not | U32Shr | U32Shl | U32Rotr | U32Rotl | U32Popcnt | U32Clz | U32Ctz
        | U32Clo | U32Cto | U32Lt | U32Lte | U32Gt | U32Gte | U32Min | U32Max | Drop | DropW
        | PadW | Dup0 | Dup1 | Dup2 | Dup3 | Dup4 | Dup5 | Dup6 | Dup7 | Dup8 | Dup9 | Dup10
        | Dup11 | Dup12 | Dup13 | Dup14 | Dup15 | DupW0 | DupW1 | DupW2 | DupW3 | Swap1 | Swap2
        | Swap3 | Swap4 | Swap5 | Swap6 | Swap7 | Swap8 | Swap9 | Swap10 | Swap11 | Swap12
        | Swap13 | Swap14 | Swap15 | SwapW1 | SwapW2 | SwapW3 | SwapDw | MovUp2 | MovUp3
        | MovUp4 | MovUp5 | MovUp6 | MovUp7 | MovUp8 | MovUp9 | MovUp10 | MovUp11 | MovUp12
        | MovUp13 | MovUp14 | MovUp15 | MovUpW2 | MovUpW3 | MovDn2 | MovDn3 | MovDn4 | MovDn5
        | MovDn6 | MovDn7 | MovDn8 | MovDn9 | MovDn10 | MovDn11 | MovDn12 | MovDn13 | MovDn14
        | MovDn15 | MovDnW2 | MovDnW3 | Reversew | Reversedw | CSwap | CSwapW | CDrop | CDropW
        | PushFeltList(_) | Sdepth | Caller | Clk | MemLoad | MemLoadWBe | MemLoadWLe
        | MemStore | MemStoreWBe | MemStoreWLe | MemStream | AdvPipe | AdvLoadW | Hash | HMerge
        | HPerm | MTreeGet | MTreeSet | MTreeMerge | MTreeVerify | FriExt2Fold4 | DynExec
        | DynCall | Breakpoint | HornerBase | HornerExt | CryptoStream | EvalCircuit
        | LogPrecompile | Emit => ControlFlow::Continue(()),
    }
}

pub fn visit_system_event<V, T>(_visitor: &mut V, _node: Span<&SystemEventNode>) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    ControlFlow::Continue(())
}

pub fn visit_debug_options<V, T>(visitor: &mut V, options: Span<&DebugOptions>) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    match options.into_inner() {
        DebugOptions::StackTop(imm) => visitor.visit_immediate_u8(imm),
        DebugOptions::AdvStackTop(imm) => visitor.visit_immediate_u16(imm),
        DebugOptions::LocalRangeFrom(imm) => visitor.visit_immediate_u16(imm),
        DebugOptions::MemInterval(imm1, imm2) => {
            visitor.visit_immediate_u32(imm1)?;
            visitor.visit_immediate_u32(imm2)
        },
        DebugOptions::LocalInterval(imm1, imm2) => {
            visitor.visit_immediate_u16(imm1)?;
            visitor.visit_immediate_u16(imm2)
        },
        DebugOptions::StackAll | DebugOptions::MemAll | DebugOptions::LocalAll => {
            ControlFlow::Continue(())
        },
    }
}

#[inline]
pub fn visit_exec<V, T>(visitor: &mut V, target: &InvocationTarget) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    visitor.visit_invoke_target(target)
}

#[inline]
pub fn visit_call<V, T>(visitor: &mut V, target: &InvocationTarget) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    visitor.visit_invoke_target(target)
}

#[inline]
pub fn visit_syscall<V, T>(visitor: &mut V, target: &InvocationTarget) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    visitor.visit_invoke_target(target)
}

#[inline]
pub fn visit_procref<V, T>(visitor: &mut V, target: &InvocationTarget) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    visitor.visit_invoke_target(target)
}

#[inline(always)]
pub fn visit_invoke_target<V, T>(_visitor: &mut V, _target: &InvocationTarget) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    ControlFlow::Continue(())
}

#[inline(always)]
pub fn visit_alias_target<V, T>(_visitor: &mut V, _target: &AliasTarget) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    ControlFlow::Continue(())
}

#[inline(always)]
pub fn visit_immediate_u8<V, T>(_visitor: &mut V, _imm: &Immediate<u8>) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    ControlFlow::Continue(())
}

#[inline(always)]
pub fn visit_immediate_u16<V, T>(_visitor: &mut V, _imm: &Immediate<u16>) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    ControlFlow::Continue(())
}

#[inline(always)]
pub fn visit_immediate_u32<V, T>(_visitor: &mut V, _imm: &Immediate<u32>) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    ControlFlow::Continue(())
}

#[inline(always)]
pub fn visit_immediate_felt<V, T>(_visitor: &mut V, _imm: &Immediate<Felt>) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    ControlFlow::Continue(())
}

#[inline(always)]
pub fn visit_immediate_word_value<V, T>(
    _visitor: &mut V,
    _imm: &Immediate<WordValue>,
) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    ControlFlow::Continue(())
}

#[inline(always)]
pub fn visit_immediate_push_value<V, T>(
    _visitor: &mut V,
    _imm: &Immediate<PushValue>,
) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    ControlFlow::Continue(())
}

#[inline(always)]
pub fn visit_immediate_error_message<V, T>(_visitor: &mut V, _imm: &ErrorMsg) -> ControlFlow<T>
where
    V: ?Sized + Visit<T>,
{
    ControlFlow::Continue(())
}

/// Represents a mutable AST visitor, whose "early return" type is `T` (by default `()`).
///
/// Mutable visitors are primarily used to perform rewrites of the AST, either for desugaring
/// purposes, optimization purposes, or to iteratively flesh out details in the AST as more
/// information is discovered during compilation (such as the absolute path to a procedure that
/// is imported from another module).
///
/// Unless explicitly overridden, all methods of this trait will perform a default depth-first
/// traversal of the AST. When a node is overridden, you must ensure that the corresponding free
/// function in this module is called at an appropriate point if you wish to visit all of the
/// children of that node. For example, if visiting procedures, you must call
/// `visit::visit_mut_procedure` either before you do your analysis for that procedure, or after,
/// corresponding to whether you are rewriting top-down, or bottom-up. If you do not do this, none
/// of the children of the [Procedure] node will be visited. This is perfectly valid! Sometimes you
/// only need to rewrite specific nodes that cannot appear further down the tree, in which case you
/// do not need to visit any of the children. It is just important to be aware that this is one of
/// the elements placed in the hands of the visitor implementation.
///
/// The methods of this trait all return [core::ops::ControlFlow], which can be used to break out
/// of the traversal early via `ControlFlow::Break`. The `T` type parameter of this trait controls
/// what the value associated with an early return will be. In most cases, the default of `()` is
/// all you need - but in some cases it can be useful to return an error or other value, that
/// indicates why the traversal ended early.
pub trait VisitMut<T = ()> {
    fn visit_mut_module(&mut self, module: &mut Module) -> ControlFlow<T> {
        visit_mut_module(self, module)
    }
    fn visit_mut_export(&mut self, export: &mut Export) -> ControlFlow<T> {
        visit_mut_export(self, export)
    }
    fn visit_mut_procedure(&mut self, procedure: &mut Procedure) -> ControlFlow<T> {
        visit_mut_procedure(self, procedure)
    }
    fn visit_mut_constant(&mut self, constant: &mut Constant) -> ControlFlow<T> {
        visit_mut_constant(self, constant)
    }
    fn visit_mut_constant_expr(&mut self, expr: &mut ConstantExpr) -> ControlFlow<T> {
        visit_mut_constant_expr(self, expr)
    }
    fn visit_mut_constant_ref(&mut self, path: &mut Span<Arc<Path>>) -> ControlFlow<T> {
        visit_mut_constant_ref(self, path)
    }
    fn visit_mut_type_decl(&mut self, ty: &mut TypeDecl) -> ControlFlow<T> {
        visit_mut_type_decl(self, ty)
    }
    fn visit_mut_type_alias(&mut self, ty: &mut TypeAlias) -> ControlFlow<T> {
        visit_mut_type_alias(self, ty)
    }
    fn visit_mut_type_expr(&mut self, ty: &mut TypeExpr) -> ControlFlow<T> {
        visit_mut_type_expr(self, ty)
    }
    fn visit_mut_type_ref(&mut self, path: &mut Span<Arc<Path>>) -> ControlFlow<T> {
        visit_mut_type_ref(self, path)
    }
    fn visit_mut_enum(&mut self, ty: &mut EnumType) -> ControlFlow<T> {
        visit_mut_enum(self, ty)
    }
    fn visit_mut_enum_variant(&mut self, variant: &mut Variant) -> ControlFlow<T> {
        visit_mut_enum_variant(self, variant)
    }
    fn visit_mut_alias(&mut self, alias: &mut Alias) -> ControlFlow<T> {
        visit_mut_alias(self, alias)
    }
    fn visit_mut_block(&mut self, block: &mut Block) -> ControlFlow<T> {
        visit_mut_block(self, block)
    }
    fn visit_mut_op(&mut self, op: &mut Op) -> ControlFlow<T> {
        visit_mut_op(self, op)
    }
    fn visit_mut_inst(&mut self, inst: &mut Span<Instruction>) -> ControlFlow<T> {
        visit_mut_inst(self, inst)
    }
    fn visit_mut_system_event(&mut self, sys_event: Span<&mut SystemEventNode>) -> ControlFlow<T> {
        visit_mut_system_event(self, sys_event)
    }
    fn visit_mut_debug_options(&mut self, options: Span<&mut DebugOptions>) -> ControlFlow<T> {
        visit_mut_debug_options(self, options)
    }
    fn visit_mut_exec(&mut self, target: &mut InvocationTarget) -> ControlFlow<T> {
        visit_mut_exec(self, target)
    }
    fn visit_mut_call(&mut self, target: &mut InvocationTarget) -> ControlFlow<T> {
        visit_mut_call(self, target)
    }
    fn visit_mut_syscall(&mut self, target: &mut InvocationTarget) -> ControlFlow<T> {
        visit_mut_syscall(self, target)
    }
    fn visit_mut_procref(&mut self, target: &mut InvocationTarget) -> ControlFlow<T> {
        visit_mut_procref(self, target)
    }
    fn visit_mut_invoke_target(&mut self, target: &mut InvocationTarget) -> ControlFlow<T> {
        visit_mut_invoke_target(self, target)
    }
    fn visit_mut_alias_target(&mut self, target: &mut AliasTarget) -> ControlFlow<T> {
        visit_mut_alias_target(self, target)
    }
    fn visit_mut_immediate_u8(&mut self, imm: &mut Immediate<u8>) -> ControlFlow<T> {
        visit_mut_immediate_u8(self, imm)
    }
    fn visit_mut_immediate_u16(&mut self, imm: &mut Immediate<u16>) -> ControlFlow<T> {
        visit_mut_immediate_u16(self, imm)
    }
    fn visit_mut_immediate_u32(&mut self, imm: &mut Immediate<u32>) -> ControlFlow<T> {
        visit_mut_immediate_u32(self, imm)
    }
    fn visit_mut_immediate_felt(&mut self, imm: &mut Immediate<Felt>) -> ControlFlow<T> {
        visit_mut_immediate_felt(self, imm)
    }
    fn visit_mut_immediate_word_value(&mut self, imm: &mut Immediate<WordValue>) -> ControlFlow<T> {
        visit_mut_immediate_word_value(self, imm)
    }
    fn visit_mut_immediate_push_value(&mut self, imm: &mut Immediate<PushValue>) -> ControlFlow<T> {
        visit_mut_immediate_push_value(self, imm)
    }
    fn visit_mut_immediate_error_message(&mut self, code: &mut ErrorMsg) -> ControlFlow<T> {
        visit_mut_immediate_error_message(self, code)
    }
}

impl<V, T> VisitMut<T> for &mut V
where
    V: ?Sized + VisitMut<T>,
{
    fn visit_mut_module(&mut self, module: &mut Module) -> ControlFlow<T> {
        (**self).visit_mut_module(module)
    }
    fn visit_mut_export(&mut self, export: &mut Export) -> ControlFlow<T> {
        (**self).visit_mut_export(export)
    }
    fn visit_mut_procedure(&mut self, procedure: &mut Procedure) -> ControlFlow<T> {
        (**self).visit_mut_procedure(procedure)
    }
    fn visit_mut_constant(&mut self, constant: &mut Constant) -> ControlFlow<T> {
        (**self).visit_mut_constant(constant)
    }
    fn visit_mut_constant_expr(&mut self, expr: &mut ConstantExpr) -> ControlFlow<T> {
        (**self).visit_mut_constant_expr(expr)
    }
    fn visit_mut_constant_ref(&mut self, path: &mut Span<Arc<Path>>) -> ControlFlow<T> {
        (**self).visit_mut_constant_ref(path)
    }
    fn visit_mut_type_decl(&mut self, ty: &mut TypeDecl) -> ControlFlow<T> {
        (**self).visit_mut_type_decl(ty)
    }
    fn visit_mut_type_alias(&mut self, ty: &mut TypeAlias) -> ControlFlow<T> {
        (**self).visit_mut_type_alias(ty)
    }
    fn visit_mut_type_expr(&mut self, ty: &mut TypeExpr) -> ControlFlow<T> {
        (**self).visit_mut_type_expr(ty)
    }
    fn visit_mut_type_ref(&mut self, path: &mut Span<Arc<Path>>) -> ControlFlow<T> {
        (**self).visit_mut_type_ref(path)
    }
    fn visit_mut_enum(&mut self, ty: &mut EnumType) -> ControlFlow<T> {
        (**self).visit_mut_enum(ty)
    }
    fn visit_mut_enum_variant(&mut self, variant: &mut Variant) -> ControlFlow<T> {
        (**self).visit_mut_enum_variant(variant)
    }
    fn visit_mut_alias(&mut self, alias: &mut Alias) -> ControlFlow<T> {
        (**self).visit_mut_alias(alias)
    }
    fn visit_mut_block(&mut self, block: &mut Block) -> ControlFlow<T> {
        (**self).visit_mut_block(block)
    }
    fn visit_mut_op(&mut self, op: &mut Op) -> ControlFlow<T> {
        (**self).visit_mut_op(op)
    }
    fn visit_mut_inst(&mut self, inst: &mut Span<Instruction>) -> ControlFlow<T> {
        (**self).visit_mut_inst(inst)
    }
    fn visit_mut_system_event(&mut self, sys_event: Span<&mut SystemEventNode>) -> ControlFlow<T> {
        (**self).visit_mut_system_event(sys_event)
    }
    fn visit_mut_debug_options(&mut self, options: Span<&mut DebugOptions>) -> ControlFlow<T> {
        (**self).visit_mut_debug_options(options)
    }
    fn visit_mut_exec(&mut self, target: &mut InvocationTarget) -> ControlFlow<T> {
        (**self).visit_mut_exec(target)
    }
    fn visit_mut_call(&mut self, target: &mut InvocationTarget) -> ControlFlow<T> {
        (**self).visit_mut_call(target)
    }
    fn visit_mut_syscall(&mut self, target: &mut InvocationTarget) -> ControlFlow<T> {
        (**self).visit_mut_syscall(target)
    }
    fn visit_mut_procref(&mut self, target: &mut InvocationTarget) -> ControlFlow<T> {
        (**self).visit_mut_procref(target)
    }
    fn visit_mut_invoke_target(&mut self, target: &mut InvocationTarget) -> ControlFlow<T> {
        (**self).visit_mut_invoke_target(target)
    }
    fn visit_mut_alias_target(&mut self, target: &mut AliasTarget) -> ControlFlow<T> {
        (**self).visit_mut_alias_target(target)
    }
    fn visit_mut_immediate_u8(&mut self, imm: &mut Immediate<u8>) -> ControlFlow<T> {
        (**self).visit_mut_immediate_u8(imm)
    }
    fn visit_mut_immediate_u16(&mut self, imm: &mut Immediate<u16>) -> ControlFlow<T> {
        (**self).visit_mut_immediate_u16(imm)
    }
    fn visit_mut_immediate_u32(&mut self, imm: &mut Immediate<u32>) -> ControlFlow<T> {
        (**self).visit_mut_immediate_u32(imm)
    }
    fn visit_mut_immediate_felt(&mut self, imm: &mut Immediate<Felt>) -> ControlFlow<T> {
        (**self).visit_mut_immediate_felt(imm)
    }
    fn visit_mut_immediate_word_value(&mut self, imm: &mut Immediate<WordValue>) -> ControlFlow<T> {
        (**self).visit_mut_immediate_word_value(imm)
    }
    fn visit_mut_immediate_push_value(&mut self, imm: &mut Immediate<PushValue>) -> ControlFlow<T> {
        (**self).visit_mut_immediate_push_value(imm)
    }
    fn visit_mut_immediate_error_message(&mut self, code: &mut ErrorMsg) -> ControlFlow<T> {
        (**self).visit_mut_immediate_error_message(code)
    }
}

pub fn visit_mut_module<V, T>(visitor: &mut V, module: &mut Module) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    for export in module.items_mut() {
        visitor.visit_mut_export(export)?;
    }

    ControlFlow::Continue(())
}

pub fn visit_mut_export<V, T>(visitor: &mut V, export: &mut Export) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    match export {
        Export::Procedure(item) => visitor.visit_mut_procedure(item),
        Export::Constant(item) => visitor.visit_mut_constant(item),
        Export::Type(item) => visitor.visit_mut_type_decl(item),
        Export::Alias(item) => visitor.visit_mut_alias(item),
    }
}

pub fn visit_mut_procedure<V, T>(visitor: &mut V, procedure: &mut Procedure) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    visitor.visit_mut_block(procedure.body_mut())
}

#[inline(always)]
pub fn visit_mut_constant<V, T>(visitor: &mut V, constant: &mut Constant) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    visitor.visit_mut_constant_expr(&mut constant.value)
}

pub fn visit_mut_constant_expr<V, T>(visitor: &mut V, expr: &mut ConstantExpr) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    match expr {
        ConstantExpr::Var(path) => visitor.visit_mut_constant_ref(path),
        ConstantExpr::BinaryOp { lhs, rhs, .. } => {
            visitor.visit_mut_constant_expr(lhs)?;
            visitor.visit_mut_constant_expr(rhs)
        },
        ConstantExpr::Hash(..)
        | ConstantExpr::Int(_)
        | ConstantExpr::String(_)
        | ConstantExpr::Word(_) => ControlFlow::Continue(()),
    }
}

#[inline(always)]
pub fn visit_mut_constant_ref<V, T>(_visitor: &mut V, _path: &mut Span<Arc<Path>>) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    ControlFlow::Continue(())
}

pub fn visit_mut_type_decl<V, T>(visitor: &mut V, ty: &mut TypeDecl) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    match ty {
        TypeDecl::Alias(ty) => visitor.visit_mut_type_alias(ty),
        TypeDecl::Enum(ty) => visitor.visit_mut_enum(ty),
    }
}

pub fn visit_mut_type_alias<V, T>(visitor: &mut V, ty: &mut TypeAlias) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    visitor.visit_mut_type_expr(&mut ty.ty)
}

pub fn visit_mut_type_expr<V, T>(visitor: &mut V, ty: &mut TypeExpr) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    match ty {
        TypeExpr::Ref(path) => visitor.visit_mut_type_ref(path),
        TypeExpr::Primitive(_) => ControlFlow::Continue(()),
        TypeExpr::Array(ty) => visitor.visit_mut_type_expr(&mut ty.elem),
        TypeExpr::Ptr(ty) => visitor.visit_mut_type_expr(&mut ty.pointee),
        TypeExpr::Struct(ty) => {
            for field in ty.fields.iter_mut() {
                visitor.visit_mut_type_expr(&mut field.ty)?;
            }
            ControlFlow::Continue(())
        },
    }
}

#[inline(always)]
pub fn visit_mut_type_ref<V, T>(_visitor: &mut V, _path: &mut Span<Arc<Path>>) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    ControlFlow::Continue(())
}

pub fn visit_mut_enum<V, T>(visitor: &mut V, ty: &mut EnumType) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    for variant in ty.variants_mut() {
        visitor.visit_mut_enum_variant(variant)?;
    }
    ControlFlow::Continue(())
}

#[inline(always)]
pub fn visit_mut_enum_variant<V, T>(_visitor: &mut V, _variant: &mut Variant) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    ControlFlow::Continue(())
}

#[inline(always)]
pub fn visit_mut_alias<V, T>(visitor: &mut V, alias: &mut Alias) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    visitor.visit_mut_alias_target(alias.target_mut())
}

pub fn visit_mut_block<V, T>(visitor: &mut V, block: &mut Block) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    for op in block.iter_mut() {
        visitor.visit_mut_op(op)?;
    }
    ControlFlow::Continue(())
}

pub fn visit_mut_op<V, T>(visitor: &mut V, op: &mut Op) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    match op {
        Op::If { then_blk, else_blk, .. } => {
            visitor.visit_mut_block(then_blk)?;
            visitor.visit_mut_block(else_blk)
        },
        Op::While { body, .. } | Op::Repeat { body, .. } => visitor.visit_mut_block(body),
        Op::Inst(inst) => visitor.visit_mut_inst(inst),
    }
}

pub fn visit_mut_inst<V, T>(visitor: &mut V, inst: &mut Span<Instruction>) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    use Instruction::*;
    let span = inst.span();
    match &mut **inst {
        U32ShrImm(imm) | U32ShlImm(imm) | U32RotrImm(imm) | U32RotlImm(imm) | AdvPush(imm) => {
            visitor.visit_mut_immediate_u8(imm)
        },
        Locaddr(imm) | LocLoad(imm) | LocLoadWBe(imm) | LocLoadWLe(imm) | LocStore(imm)
        | LocStoreWBe(imm) | LocStoreWLe(imm) => visitor.visit_mut_immediate_u16(imm),
        AssertWithError(code)
        | AssertEqWithError(code)
        | AssertEqwWithError(code)
        | AssertzWithError(code)
        | U32AssertWithError(code)
        | U32Assert2WithError(code)
        | U32AssertWWithError(code)
        | MTreeVerifyWithError(code) => visitor.visit_mut_immediate_error_message(code),
        AddImm(imm) | SubImm(imm) | MulImm(imm) | DivImm(imm) | ExpImm(imm) | EqImm(imm)
        | NeqImm(imm) => visitor.visit_mut_immediate_felt(imm),
        Push(imm) => visitor.visit_mut_immediate_push_value(imm),
        PushSlice(imm, _) => visitor.visit_mut_immediate_word_value(imm),
        U32WrappingAddImm(imm)
        | U32OverflowingAddImm(imm)
        | U32WrappingSubImm(imm)
        | U32OverflowingSubImm(imm)
        | U32WrappingMulImm(imm)
        | U32OverflowingMulImm(imm)
        | U32DivImm(imm)
        | U32ModImm(imm)
        | U32DivModImm(imm)
        | MemLoadImm(imm)
        | MemLoadWBeImm(imm)
        | MemLoadWLeImm(imm)
        | MemStoreImm(imm)
        | MemStoreWBeImm(imm)
        | MemStoreWLeImm(imm)
        | Trace(imm) => visitor.visit_mut_immediate_u32(imm),
        EmitImm(imm) => visitor.visit_mut_immediate_felt(imm),
        SysEvent(sys_event) => visitor.visit_mut_system_event(Span::new(span, sys_event)),
        Exec(target) => visitor.visit_mut_exec(target),
        Call(target) => visitor.visit_mut_call(target),
        SysCall(target) => visitor.visit_mut_syscall(target),
        ProcRef(target) => visitor.visit_mut_procref(target),
        Debug(options) => visitor.visit_mut_debug_options(Span::new(span, options)),
        Nop | Assert | AssertEq | AssertEqw | Assertz | Add | Sub | Mul | Div | Neg | ILog2
        | Inv | Incr | Pow2 | Exp | ExpBitLength(_) | Not | And | Or | Xor | Eq | Neq | Eqw
        | Lt | Lte | Gt | Gte | IsOdd | Ext2Add | Ext2Sub | Ext2Mul | Ext2Div | Ext2Neg
        | Ext2Inv | U32Test | U32TestW | U32Assert | U32Assert2 | U32AssertW | U32Split
        | U32Cast | U32WrappingAdd | U32OverflowingAdd | U32OverflowingAdd3 | U32WrappingAdd3
        | U32WrappingSub | U32OverflowingSub | U32WrappingMul | U32OverflowingMul
        | U32OverflowingMadd | U32WrappingMadd | U32Div | U32Mod | U32DivMod | U32And | U32Or
        | U32Xor | U32Not | U32Shr | U32Shl | U32Rotr | U32Rotl | U32Popcnt | U32Clz | U32Ctz
        | U32Clo | U32Cto | U32Lt | U32Lte | U32Gt | U32Gte | U32Min | U32Max | Drop | DropW
        | PadW | Dup0 | Dup1 | Dup2 | Dup3 | Dup4 | Dup5 | Dup6 | Dup7 | Dup8 | Dup9 | Dup10
        | Dup11 | Dup12 | Dup13 | Dup14 | Dup15 | DupW0 | DupW1 | DupW2 | DupW3 | Swap1 | Swap2
        | Swap3 | Swap4 | Swap5 | Swap6 | Swap7 | Swap8 | Swap9 | Swap10 | Swap11 | Swap12
        | Swap13 | Swap14 | Swap15 | SwapW1 | SwapW2 | SwapW3 | SwapDw | MovUp2 | MovUp3
        | MovUp4 | MovUp5 | MovUp6 | MovUp7 | MovUp8 | MovUp9 | MovUp10 | MovUp11 | MovUp12
        | MovUp13 | MovUp14 | MovUp15 | MovUpW2 | MovUpW3 | MovDn2 | MovDn3 | MovDn4 | MovDn5
        | MovDn6 | MovDn7 | MovDn8 | MovDn9 | MovDn10 | MovDn11 | MovDn12 | MovDn13 | MovDn14
        | MovDn15 | MovDnW2 | MovDnW3 | Reversew | Reversedw | CSwap | CSwapW | CDrop | CDropW
        | PushFeltList(_) | Sdepth | Caller | Clk | MemLoad | MemLoadWBe | MemLoadWLe
        | MemStore | MemStoreWBe | MemStoreWLe | MemStream | AdvPipe | AdvLoadW | Hash | HMerge
        | HPerm | MTreeGet | MTreeSet | MTreeMerge | MTreeVerify | FriExt2Fold4 | DynExec
        | DynCall | Breakpoint | HornerBase | HornerExt | EvalCircuit | CryptoStream
        | LogPrecompile | Emit => ControlFlow::Continue(()),
    }
}

pub fn visit_mut_system_event<V, T>(
    _visitor: &mut V,
    _node: Span<&mut SystemEventNode>,
) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    ControlFlow::Continue(())
}

pub fn visit_mut_debug_options<V, T>(
    visitor: &mut V,
    options: Span<&mut DebugOptions>,
) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    match options.into_inner() {
        DebugOptions::StackTop(imm) => visitor.visit_mut_immediate_u8(imm),
        DebugOptions::AdvStackTop(imm) => visitor.visit_mut_immediate_u16(imm),
        DebugOptions::LocalRangeFrom(imm) => visitor.visit_mut_immediate_u16(imm),
        DebugOptions::MemInterval(imm1, imm2) => {
            visitor.visit_mut_immediate_u32(imm1)?;
            visitor.visit_mut_immediate_u32(imm2)
        },
        DebugOptions::LocalInterval(imm1, imm2) => {
            visitor.visit_mut_immediate_u16(imm1)?;
            visitor.visit_mut_immediate_u16(imm2)
        },
        DebugOptions::StackAll | DebugOptions::MemAll | DebugOptions::LocalAll => {
            ControlFlow::Continue(())
        },
    }
}

#[inline]
pub fn visit_mut_exec<V, T>(visitor: &mut V, target: &mut InvocationTarget) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    visitor.visit_mut_invoke_target(target)
}

#[inline]
pub fn visit_mut_call<V, T>(visitor: &mut V, target: &mut InvocationTarget) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    visitor.visit_mut_invoke_target(target)
}

#[inline]
pub fn visit_mut_syscall<V, T>(visitor: &mut V, target: &mut InvocationTarget) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    visitor.visit_mut_invoke_target(target)
}

#[inline]
pub fn visit_mut_procref<V, T>(visitor: &mut V, target: &mut InvocationTarget) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    visitor.visit_mut_invoke_target(target)
}

#[inline(always)]
pub fn visit_mut_invoke_target<V, T>(
    _visitor: &mut V,
    _target: &mut InvocationTarget,
) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    ControlFlow::Continue(())
}

#[inline(always)]
pub fn visit_mut_alias_target<V, T>(_visitor: &mut V, _target: &mut AliasTarget) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    ControlFlow::Continue(())
}

#[inline(always)]
pub fn visit_mut_immediate_u8<V, T>(_visitor: &mut V, _imm: &mut Immediate<u8>) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    ControlFlow::Continue(())
}

#[inline(always)]
pub fn visit_mut_immediate_u16<V, T>(_visitor: &mut V, _imm: &mut Immediate<u16>) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    ControlFlow::Continue(())
}

#[inline(always)]
pub fn visit_mut_immediate_u32<V, T>(_visitor: &mut V, _imm: &mut Immediate<u32>) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    ControlFlow::Continue(())
}

#[inline(always)]
pub fn visit_mut_immediate_felt<V, T>(
    _visitor: &mut V,
    _imm: &mut Immediate<Felt>,
) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    ControlFlow::Continue(())
}

#[inline(always)]
pub fn visit_mut_immediate_word_value<V, T>(
    _visitor: &mut V,
    _imm: &mut Immediate<WordValue>,
) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    ControlFlow::Continue(())
}

#[inline(always)]
pub fn visit_mut_immediate_push_value<V, T>(
    _visitor: &mut V,
    _imm: &mut Immediate<PushValue>,
) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    ControlFlow::Continue(())
}

#[inline(always)]
pub fn visit_mut_immediate_error_message<V, T>(
    _visitor: &mut V,
    _imm: &mut ErrorMsg,
) -> ControlFlow<T>
where
    V: ?Sized + VisitMut<T>,
{
    ControlFlow::Continue(())
}
