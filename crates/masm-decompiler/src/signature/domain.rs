use std::collections::{HashMap, VecDeque};

use crate::{signature::StackEffect, symbol::path::SymbolPath};

/// A procedures signature, as determined during signature inference.
///
/// The number of inputs are determined by tracking the provenance of each stack
/// slot. Stack slots pushed during execution of the procedure are marked as
/// local. Stack slots below the entry stack depth that are read by the
/// procedure are marked as inputs.
///
/// When execution has completed, the stack has the following layout if the net
/// effect is > 0:
///
///   ┌────────────────────┬─────────────────────┐
///   │  Remaining inputs  │  Procedure outputs  │ → Stack grows this way
///   └────────────────────┴─────────────────────┘
///                            ↑                 ↑
///                      Depth on entry    Depth on exit
///   ╰────────────┬───────────┴────────┬────────╯
///         Required depth        Net effect > 0
///
/// If the net effect is < 0, we have the following stack layout:
///
///   ┌────────────────────┬─────────────────────┐ - - - - - - - - ┐
///   │  Remaining inputs  │  Procedure outputs  │                 │ → Stack grows this way
///   └────────────────────┴─────────────────────┘ - - - - - - - - ┘
///                                              ↑                 ↑
///                                        Depth on exit     Depth on entry
///   ╰────────────┬─────────────────────────────┴────────┬────────╯
///         Required depth                          Net effect < 0
///
/// When the procedure exits, the number of inputs are given by the required
/// depth. The number of outputs are determined by the full final stack shape,
/// including any preserved inputs that remain semantically visible to callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcSignature {
    Known {
        /// The number of inputs to the procedure
        inputs: usize,
        /// The number of public inputs rendered in the decompiled header.
        ///
        /// This may be smaller than `inputs` when lifting requires hidden
        /// preserved-stack scaffolding that should not be exposed as part of
        /// the procedure's public semantic surface.
        public_inputs: usize,
        /// The number of outputs from the procedure
        outputs: usize,
        /// Net stack effect of the procedure
        net_effect: isize,
    },
    Unknown,
}

impl ProcSignature {
    /// Return a copy with a refined public input arity.
    pub(crate) fn with_public_inputs(self, public_inputs: usize) -> Self {
        match self {
            ProcSignature::Known { inputs, outputs, net_effect, .. } => ProcSignature::Known {
                inputs,
                public_inputs,
                outputs,
                net_effect,
            },
            ProcSignature::Unknown => ProcSignature::Unknown,
        }
    }
}

/// Convert a [ProcSignature] to the stack effect of a corresponding `exec`
/// call.
///
/// To convert the signature to the corresponding stack effect, we make use of
/// the following relationships (see above):
///
///   1. pops = number of outputs - net effect
///   2. pushes = number of outputs
///   3. required depth = number of inputs
impl From<&ProcSignature> for StackEffect {
    fn from(signature: &ProcSignature) -> Self {
        match *signature {
            ProcSignature::Known { inputs, outputs, net_effect, .. } => {
                assert!(net_effect <= (outputs as isize));
                StackEffect::Known {
                    pops: ((outputs as isize) - net_effect) as usize,
                    pushes: outputs,
                    required_depth: inputs,
                }
            },
            ProcSignature::Unknown => StackEffect::Unknown,
        }
    }
}

impl From<&ProvenanceStack> for ProcSignature {
    fn from(stack: &ProvenanceStack) -> Self {
        ProcSignature::Known {
            inputs: stack.inputs(),
            public_inputs: stack.inputs(),
            outputs: stack.outputs(),
            net_effect: stack.net_effect(),
        }
    }
}

/// Provenance of a stack slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provenance {
    /// An input to the procedure.
    Input,
    /// A locally computed value.
    Local,
}

impl Provenance {
    /// Merge two individual stack slot values from two different branches.
    ///
    /// If either branch writes to the slot, the slot is marked as local.
    fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Provenance::Input, Provenance::Input) => Provenance::Input,
            _ => Provenance::Local,
        }
    }
}

/// A map from proc names to signatures
pub type SignatureMap = HashMap<SymbolPath, ProcSignature>;

/// Symbolic stack to track stack slot provenance.
///
/// Required depth tracks the required stack depth compared to the depth at
/// procedure entry. This is the number of inputs to the procedure. The number
/// of outputs is given by the full stack height on exit, including preserved
/// inputs that remain visible to the caller.
///
/// If the procedure contains branches with different stack effects, non-neutral
/// while loops, or calls to procedures with unknown stack effects, the analysis
/// fails.
#[derive(Debug, Default, Clone)]
pub(super) struct ProvenanceStack {
    stack: VecDeque<Provenance>,
    current_depth: isize,
    required_depth: usize,
}

impl ProvenanceStack {
    /// Ensure that the stack depth is at least `required_depth` by pushing
    /// additional inputs to the stack. Must be called before popping values
    /// from the stack.
    pub(super) fn ensure_depth(&mut self, required_depth: usize) {
        while self.stack.len() < required_depth {
            self.stack.push_front(Provenance::Input);
            self.required_depth += 1;
        }
    }

    /// Pop a single value from the stack.
    pub(super) fn pop(&mut self) {
        assert!(!self.stack.is_empty());
        self.stack.pop_back();
        self.current_depth -= 1;
    }

    /// Push a single local value onto the stack.
    fn push(&mut self) {
        self.stack.push_back(Provenance::Local);
        self.current_depth += 1;
    }

    /// Apply the known stack effects of a single instruction.
    pub(super) fn apply(&mut self, pops: usize, pushes: usize, required_depth: usize) {
        self.ensure_depth(required_depth);
        for _ in 0..pops {
            self.pop();
        }
        for _ in 0..pushes {
            self.push()
        }
    }

    /// Returns the number of inputs to the procedure.
    fn inputs(&self) -> usize {
        self.required_depth
    }

    /// Returns the number of outputs from the procedure.
    fn outputs(&self) -> usize {
        self.stack.len()
    }

    /// Returns the net stack effect of the procedure on exit.
    fn net_effect(&self) -> isize {
        self.current_depth
    }

    pub(super) fn current_depth(&self) -> isize {
        self.current_depth
    }

    // Merge stack effects of two branches. This assumes that the stack depth is
    // the same for both versions of the stack. The required depth of the merged
    // stack is the maximum depth across the two inputs. Individual slots are
    // marked as local if either of the inputs has marked the slot as local.
    pub(super) fn merge(&self, other: &Self) -> Self {
        assert!(self.current_depth == other.current_depth);

        let mut self_stack = self.stack.clone();
        let mut other_stack = other.stack.clone();

        let mut stack = VecDeque::new();
        loop {
            let value = match (self_stack.pop_back(), other_stack.pop_back()) {
                (Some(self_value), Some(other_value)) => self_value.merge(other_value),
                (Some(self_value), None) => self_value,
                (None, Some(other_value)) => other_value,
                (None, None) => break,
            };
            stack.push_front(value);
        }

        let current_depth = self.current_depth;
        let required_depth = self.required_depth.max(other.required_depth);
        ProvenanceStack { stack, current_depth, required_depth }
    }
}
