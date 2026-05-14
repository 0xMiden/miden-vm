use miden_assembly_syntax::{
    ast::{Immediate, Instruction},
    parser::PushValue,
};

use crate::semantics::{StackFamily, stack_family};

/// Describes the local stack effect of a single instruction or operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StackEffect {
    Known {
        /// The number of elements popped from the stack.
        pops: usize,
        /// The number of new elements pushed onto the stack.
        pushes: usize,
        /// The stack depth required to execute the instruction or operation.
        /// Guaranteed to be greater than or equal to `pops`.
        required_depth: usize,
    },
    Unknown,
}

impl StackEffect {
    const fn known(pops: usize, pushes: usize) -> Self {
        StackEffect::Known { pops, pushes, required_depth: pops }
    }

    const fn with_required_depth(self, required_depth: usize) -> Self {
        match self {
            StackEffect::Known { pops, pushes, .. } => {
                StackEffect::Known { pops, pushes, required_depth }
            },
            StackEffect::Unknown => StackEffect::Unknown,
        }
    }
}

impl From<&Instruction> for StackEffect {
    fn from(inst: &Instruction) -> Self {
        use Instruction::*;

        if let Some(effect) = stack_family(inst).map(StackFamily::effect) {
            return StackEffect::Known {
                pops: effect.pops,
                pushes: effect.pushes,
                required_depth: effect.required_depth,
            };
        }

        // Unary instructions
        let unary = matches!(
            inst,
            ExpImm(_)
                | ILog2
                | Inv
                | Incr
                | IsOdd
                | Pow2
                | Neg
                | Not
                | EqImm(_)
                | NeqImm(_)
                | AddImm(_)
                | SubImm(_)
                | MulImm(_)
                | U32Cast
                | U32Clz
                | U32Clo
                | U32Cto
                | U32Ctz
                | U32Not
                | U32Popcnt
                | U32WrappingAddImm(_)
                | U32WrappingSubImm(_)
                | U32WrappingMulImm(_)
                | U32ShlImm(_)
                | U32ShrImm(_)
                | U32DivImm(_)
                | U32ModImm(_)
                | U32RotlImm(_)
                | U32RotrImm(_)
        );
        if unary {
            return StackEffect::known(1, 1);
        }

        let binary = matches!(
            inst,
            Add | Sub
                | Mul
                | Div
                | Exp
                | ExpBitLength(_)
                | And
                | Or
                | Xor
                | Eq
                | Neq
                | Lt
                | Lte
                | Gt
                | Gte
                | U32WrappingAdd
                | U32WrappingSub
                | U32WrappingMul
                | U32Div
                | U32Mod
                | U32And
                | U32Or
                | U32Xor
                | U32Shl
                | U32Shr
                | U32Rotl
                | U32Rotr
                | U32Lt
                | U32Lte
                | U32Gt
                | U32Gte
                | U32Min
                | U32Max
        );

        if binary {
            return StackEffect::known(2, 1);
        }

        match inst {
            // Nop
            Nop => StackEffect::known(0, 0),

            // Assertions
            Assert | AssertWithError(_) | Assertz | AssertzWithError(_) => {
                StackEffect::known(1, 0).with_required_depth(1)
            },
            AssertEq | AssertEqWithError(_) => StackEffect::known(2, 0).with_required_depth(2),
            AssertEqw | AssertEqwWithError(_) => StackEffect::known(8, 0).with_required_depth(8),

            // Stack operations
            Drop => StackEffect::known(1, 0),
            DropW => StackEffect::known(4, 0),
            PadW => StackEffect::known(0, 4),

            CSwap => StackEffect::known(3, 2),
            CSwapW => StackEffect::known(9, 8),
            CDrop => StackEffect::known(3, 1),
            CDropW => StackEffect::known(9, 4),
            Reversew => StackEffect::known(4, 4),

            // Remaining U32 operations
            U32OverflowingAdd => StackEffect::known(2, 2),
            U32OverflowingAddImm(_) => StackEffect::known(1, 2),
            U32WideningAdd => StackEffect::known(2, 2),
            U32WideningAddImm(_) => StackEffect::known(1, 2),
            U32OverflowingSub => StackEffect::known(2, 2),
            U32OverflowingSubImm(_) => StackEffect::known(1, 2),
            U32WideningMul => StackEffect::known(2, 2),
            U32WideningMulImm(_) => StackEffect::known(1, 2),
            U32WideningMadd => StackEffect::known(3, 2),
            U32WideningAdd3 => StackEffect::known(3, 2),
            U32OverflowingAdd3 => StackEffect::known(3, 2),
            U32WrappingAdd3 => StackEffect::known(3, 1),
            U32WrappingMadd => StackEffect::known(3, 1),
            U32DivMod => StackEffect::known(2, 2),
            U32DivModImm(_) => StackEffect::known(1, 2),
            U32Test => StackEffect::known(0, 1).with_required_depth(1),
            U32TestW => StackEffect::known(0, 1).with_required_depth(4),
            U32Assert | U32AssertWithError(_) => StackEffect::known(0, 0).with_required_depth(1),
            U32Assert2 | U32Assert2WithError(_) => StackEffect::known(0, 0).with_required_depth(2),
            U32AssertW | U32AssertWWithError(_) => StackEffect::known(0, 0).with_required_depth(4),
            U32Split => StackEffect::known(1, 2),

            // Remaining word-size operations.
            Eqw => StackEffect::known(0, 1).with_required_depth(8),

            // Extension field operations.
            Ext2Add | Ext2Sub | Ext2Mul | Ext2Div => StackEffect::known(4, 2),
            Ext2Neg | Ext2Inv => StackEffect::known(2, 2),

            // Cryptographic operations
            Hash => StackEffect::known(4, 4),
            HMerge => StackEffect::known(8, 4),
            HPerm => StackEffect::known(12, 12),
            MTreeGet => StackEffect::known(2, 4).with_required_depth(6),
            MTreeSet => StackEffect::known(10, 8),
            MTreeMerge => StackEffect::known(8, 4),
            MTreeVerify => StackEffect::known(0, 0).with_required_depth(10),
            MTreeVerifyWithError(_) => StackEffect::known(0, 0).with_required_depth(10),

            // Polynomial/circuit operations
            EvalCircuit => StackEffect::known(0, 0).with_required_depth(3),
            HornerBase => StackEffect::known(16, 16),
            HornerExt => StackEffect::known(16, 16),
            LogPrecompile => StackEffect::known(12, 12).with_required_depth(12),

            // FRI folding
            FriExt2Fold4 => StackEffect::known(0, 0).with_required_depth(17),

            // Memory loads/stores
            MemLoad => StackEffect::known(1, 1).with_required_depth(1),
            MemLoadImm(_) => StackEffect::known(0, 1),
            MemLoadWBe => StackEffect::known(5, 4).with_required_depth(5),
            MemLoadWBeImm(_) => StackEffect::known(4, 4).with_required_depth(4),
            MemLoadWLe => StackEffect::known(5, 4).with_required_depth(5),
            MemLoadWLeImm(_) => StackEffect::known(4, 4).with_required_depth(4),

            LocLoad(_) => StackEffect::known(0, 1),
            LocLoadWBe(_) => StackEffect::known(4, 4).with_required_depth(4),
            LocLoadWLe(_) => StackEffect::known(4, 4).with_required_depth(4),

            MemStore => StackEffect::known(2, 0).with_required_depth(2),
            MemStoreImm(_) => StackEffect::known(1, 0).with_required_depth(1),
            MemStoreWBe => StackEffect::known(1, 0).with_required_depth(5),
            MemStoreWBeImm(_) => StackEffect::known(0, 0).with_required_depth(4),
            MemStoreWLe => StackEffect::known(1, 0).with_required_depth(5),
            MemStoreWLeImm(_) => StackEffect::known(0, 0).with_required_depth(4),

            LocStore(_) => StackEffect::known(1, 0).with_required_depth(1),
            LocStoreWBe(_) => StackEffect::known(0, 0).with_required_depth(4),
            LocStoreWLe(_) => StackEffect::known(0, 0).with_required_depth(4),

            MemStream => StackEffect::known(13, 13).with_required_depth(13),

            Push(Immediate::Value(spanned)) => match spanned.inner() {
                PushValue::Word(_) => StackEffect::known(0, 4),
                PushValue::Int(_) => StackEffect::known(0, 1),
            },
            Push(Immediate::Constant(_)) | Locaddr(_) | Sdepth => StackEffect::known(0, 1),
            PushSlice(_, range) => StackEffect::known(0, range.len()),
            PushFeltList(values) => StackEffect::known(0, values.len()),

            AdvLoadW => StackEffect::known(4, 4).with_required_depth(4),
            AdvPipe => StackEffect::known(13, 13).with_required_depth(13),
            AdvPush => StackEffect::known(0, 1),
            AdvPushW => StackEffect::known(0, 4),

            SysEvent(_) => StackEffect::known(0, 0),

            // Stack effects from calls are handled manually during analysis.
            Exec(_) | Call(_) | SysCall(_) | DynExec | DynCall => StackEffect::Unknown,

            Debug(_) => StackEffect::known(0, 0),

            Emit => StackEffect::known(0, 0).with_required_depth(1),
            EmitImm(_) => StackEffect::known(0, 0),
            Trace(_) => StackEffect::known(0, 0),
            _ => StackEffect::Unknown,
        }
    }
}
