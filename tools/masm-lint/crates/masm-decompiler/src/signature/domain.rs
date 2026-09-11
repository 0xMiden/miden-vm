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
        /// Entry stack depths that are still present in the final stack.
        preserved_inputs: Vec<usize>,
        /// Per-output provenance as an entry input depth, or `None` for local outputs.
        output_input_depths: Vec<Option<usize>>,
        /// Per-output entry input depths that feed non-pass-through outputs.
        output_dependency_depths: Vec<Vec<usize>>,
        /// Entry input depths read by non-pass-through operations.
        used_input_depths: Vec<usize>,
    },
    Unknown,
}

impl ProcSignature {
    /// Return a copy with a refined public input arity.
    pub(crate) fn with_public_inputs(self, public_inputs: usize) -> Self {
        match self {
            ProcSignature::Known {
                inputs,
                outputs,
                net_effect,
                preserved_inputs,
                output_input_depths,
                output_dependency_depths,
                used_input_depths,
                ..
            } => ProcSignature::Known {
                inputs,
                public_inputs,
                outputs,
                net_effect,
                preserved_inputs,
                output_input_depths,
                output_dependency_depths,
                used_input_depths,
            },
            ProcSignature::Unknown => ProcSignature::Unknown,
        }
    }

    /// Return whether all inputs hidden below `public_inputs` are preserved.
    pub(crate) fn preserves_input_depths_from(&self, public_inputs: usize) -> bool {
        let ProcSignature::Known {
            inputs,
            preserved_inputs,
            output_dependency_depths,
            used_input_depths,
            ..
        } = self
        else {
            return false;
        };
        (public_inputs..*inputs).all(|depth| preserved_inputs.contains(&depth))
            && !output_dependency_depths
                .iter()
                .flatten()
                .any(|depth| (public_inputs..*inputs).contains(depth))
            && !used_input_depths.iter().any(|depth| (public_inputs..*inputs).contains(depth))
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
            preserved_inputs: stack.preserved_inputs(),
            output_input_depths: stack.output_input_depths(),
            output_dependency_depths: stack.output_dependency_depths(),
            used_input_depths: stack.used_input_depths(),
        }
    }
}

/// Provenance of a stack slot.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Provenance {
    /// An input to the procedure.
    Input(usize),
    /// A value derived from one or more entry inputs.
    Derived(Vec<usize>),
    /// A locally computed value.
    Local,
}

impl Provenance {
    /// Merge two individual stack slot values from two different branches.
    ///
    /// If either branch writes to the slot, the slot is marked as local.
    fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Provenance::Input(lhs), Provenance::Input(rhs)) if lhs == rhs => {
                Provenance::Input(lhs)
            },
            (lhs, rhs) => {
                let deps = joined_dependency_depths(
                    lhs.dependencies_including_pass_through()
                        .into_iter()
                        .chain(rhs.dependencies_including_pass_through()),
                );
                if deps.is_empty() {
                    Provenance::Local
                } else {
                    Provenance::Derived(deps)
                }
            },
        }
    }

    fn dependencies(&self) -> Vec<usize> {
        match self {
            Provenance::Input(_) | Provenance::Local => Vec::new(),
            Provenance::Derived(depths) => depths.clone(),
        }
    }

    fn dependencies_including_pass_through(&self) -> Vec<usize> {
        match self {
            Provenance::Input(depth) => vec![*depth],
            Provenance::Derived(depths) => depths.clone(),
            Provenance::Local => Vec::new(),
        }
    }

    fn from_dependencies(dependencies: &[usize]) -> Self {
        if dependencies.is_empty() {
            Provenance::Local
        } else {
            Provenance::Derived(dependencies.to_vec())
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
    used_input_depths: Vec<usize>,
}

impl ProvenanceStack {
    /// Ensure that the stack depth is at least `required_depth` by pushing
    /// additional inputs to the stack. Must be called before popping values
    /// from the stack.
    pub(super) fn ensure_depth(&mut self, required_depth: usize) {
        while self.stack.len() < required_depth {
            self.stack.push_front(Provenance::Input(self.required_depth));
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
        let pushed_dependencies = self.read_dependency_depths(required_depth);
        if pops > 0 || pushes > 0 {
            self.record_used_dependencies(&pushed_dependencies);
        }
        for _ in 0..pops {
            self.pop();
        }
        for _ in 0..pushes {
            self.push_with_dependencies(&pushed_dependencies)
        }
    }

    /// Apply an in-place stack read that constrains values but does not consume
    /// them or produce a derived value.
    pub(super) fn apply_preserving_read(&mut self, required_depth: usize) {
        self.ensure_depth(required_depth);
    }

    /// Apply an in-place read whose result escapes through side effects.
    pub(super) fn apply_side_effecting_read(&mut self, required_depth: usize) {
        self.ensure_depth(required_depth);
        let dependencies = self.read_dependency_depths(required_depth);
        self.record_used_dependencies(&dependencies);
    }

    fn push_with_dependencies(&mut self, dependencies: &[usize]) {
        if dependencies.is_empty() {
            self.push();
        } else {
            self.stack.push_back(Provenance::Derived(dependencies.to_vec()));
            self.current_depth += 1;
        }
    }

    /// Apply a callee signature while preserving known input provenance in outputs.
    pub(super) fn apply_signature(&mut self, signature: &ProcSignature) -> bool {
        let ProcSignature::Known {
            inputs,
            outputs,
            net_effect,
            output_input_depths,
            output_dependency_depths,
            used_input_depths,
            ..
        } = signature
        else {
            return false;
        };
        assert!(net_effect <= &(*outputs as isize));

        self.ensure_depth(*inputs);
        let input_provenance: Vec<_> = (0..*inputs)
            .map(|depth| self.stack.get(self.stack.len() - 1 - depth).cloned())
            .collect();
        let used_dependencies = joined_dependency_depths(
            used_input_depths
                .iter()
                .filter_map(|depth| input_provenance.get(*depth).cloned().flatten())
                .flat_map(|provenance| provenance.dependencies_including_pass_through()),
        );
        self.record_used_dependencies(&used_dependencies);
        let pops = ((*outputs as isize) - net_effect) as usize;
        for _ in 0..pops {
            self.pop();
        }
        for (exit_depth, output_depth) in output_input_depths.iter().take(*outputs).enumerate() {
            let output_dependencies = joined_dependency_depths(
                output_dependency_depths
                    .get(exit_depth)
                    .into_iter()
                    .flatten()
                    .filter_map(|depth| input_provenance.get(*depth).cloned().flatten())
                    .flat_map(|provenance| provenance.dependencies_including_pass_through()),
            );
            let provenance = output_depth
                .and_then(|depth| input_provenance.get(depth).cloned().flatten())
                .unwrap_or_else(|| Provenance::from_dependencies(&output_dependencies));
            self.stack.push_back(provenance);
            self.current_depth += 1;
        }
        true
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

    fn preserved_inputs(&self) -> Vec<usize> {
        let mut depths: Vec<_> = self.output_input_depths().into_iter().flatten().collect();
        depths.sort_unstable();
        depths.dedup();
        depths
    }

    fn output_input_depths(&self) -> Vec<Option<usize>> {
        self.stack
            .iter()
            .map(|provenance| match provenance {
                Provenance::Input(depth) => Some(*depth),
                Provenance::Derived(_) | Provenance::Local => None,
            })
            .collect()
    }

    fn output_dependency_depths(&self) -> Vec<Vec<usize>> {
        self.stack.iter().map(Provenance::dependencies).collect()
    }

    fn used_input_depths(&self) -> Vec<usize> {
        self.used_input_depths.clone()
    }

    fn read_dependency_depths(&self, required_depth: usize) -> Vec<usize> {
        joined_dependency_depths(
            self.stack
                .iter()
                .rev()
                .take(required_depth)
                .flat_map(Provenance::dependencies_including_pass_through),
        )
    }

    fn record_used_dependencies(&mut self, dependencies: &[usize]) {
        self.used_input_depths.extend(dependencies);
        self.used_input_depths.sort_unstable();
        self.used_input_depths.dedup();
    }

    pub(super) fn current_depth(&self) -> isize {
        self.current_depth
    }

    // Merge stack effects of two branches. This assumes that the stack depth is
    // the same for both versions of the stack. The required depth of the merged
    // stack is the maximum depth across the two inputs. Individual slots that
    // differ across branches retain any entry-input dependencies they may carry.
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
        let used_input_depths = joined_dependency_depths(
            self.used_input_depths
                .iter()
                .copied()
                .chain(other.used_input_depths.iter().copied()),
        );
        ProvenanceStack {
            stack,
            current_depth,
            required_depth,
            used_input_depths,
        }
    }
}

fn joined_dependency_depths(depths: impl IntoIterator<Item = usize>) -> Vec<usize> {
    let mut depths: Vec<_> = depths.into_iter().collect();
    depths.sort_unstable();
    depths.dedup();
    depths
}
