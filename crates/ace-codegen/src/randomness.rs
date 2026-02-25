//! Randomness input plan for ACE layouts and DAG lowering.
//!
//! This keeps the mapping between AIR challenges and layout inputs centralized,
//! so layout building and DAG lowering cannot drift.
//!
//! Example (internal use):
//! ```ignore
//! use miden_ace_codegen::layout::InputLayout;
//! use miden_ace_codegen::randomness::RandomnessPlan;
//!
//! let plan = RandomnessPlan::from_layout(&layout)?;
//! let node = plan.lower_challenge(&mut builder, 0)?;
//! ```

use core::hash::Hash;

use p3_field::PrimeCharacteristicRing;

use crate::{
    AceError,
    dag::{DagBuilder, NodeId},
    layout::{InputCounts, InputKey, InputLayout, InputRegion},
};

/// Randomness provisioning strategy for the ACE layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RandomnessPlan {
    /// All randomness values are supplied directly.
    Direct { num: usize },
    /// Randomness is expanded from alpha/beta seeds.
    AlphaBeta {
        num: usize,
        alpha: InputKey,
        beta: InputKey,
    },
}

impl RandomnessPlan {
    /// Derive the plan from counts and the randomness input region.
    ///
    /// Returns the plan plus the aux alpha/beta input indices (if any).
    /// Invalid configurations are handled during layout validation.
    pub(crate) fn from_counts(
        counts: &InputCounts,
        randomness: InputRegion,
    ) -> (Self, Option<usize>, Option<usize>) {
        let num = counts.num_randomness;
        let num_inputs = counts.num_randomness_inputs;

        if num == 0 {
            return (RandomnessPlan::Direct { num }, None, None);
        }

        if num_inputs == num {
            return (RandomnessPlan::Direct { num }, None, None);
        }

        if num_inputs == 2 {
            // Stored as [beta, alpha] in memory words.
            let beta_idx = randomness.index(0);
            let alpha_idx = randomness.index(1);
            return (
                RandomnessPlan::AlphaBeta {
                    num,
                    alpha: InputKey::AuxRandAlpha,
                    beta: InputKey::AuxRandBeta,
                },
                alpha_idx,
                beta_idx,
            );
        }

        (RandomnessPlan::Direct { num }, None, None)
    }

    /// Build the plan from a concrete input layout.
    pub(crate) fn from_layout(layout: &InputLayout) -> Result<Self, AceError> {
        let num = layout.counts.num_randomness;
        let num_inputs = layout.counts.num_randomness_inputs;

        if num == 0 {
            return Err(AceError::InvalidRandomnessInputs {
                num_randomness: num,
                num_randomness_inputs: num_inputs,
            });
        }

        if num_inputs == num {
            return Ok(RandomnessPlan::Direct { num });
        }

        if num_inputs == 2 {
            if layout.index(InputKey::AuxRandAlpha).is_none()
                || layout.index(InputKey::AuxRandBeta).is_none()
            {
                return Err(AceError::InvalidRandomnessInputs {
                    num_randomness: num,
                    num_randomness_inputs: num_inputs,
                });
            }
            return Ok(RandomnessPlan::AlphaBeta {
                num,
                alpha: InputKey::AuxRandAlpha,
                beta: InputKey::AuxRandBeta,
            });
        }

        Err(AceError::InvalidRandomnessInputs {
            num_randomness: num,
            num_randomness_inputs: num_inputs,
        })
    }

    /// Lower a challenge index into DAG nodes.
    pub(crate) fn lower_challenge<EF>(
        &self,
        builder: &mut DagBuilder<EF>,
        index: usize,
    ) -> Result<NodeId, AceError>
    where
        EF: PrimeCharacteristicRing + Copy + Eq + Hash,
    {
        let num = self.num_randomness();
        if num == 0 || index >= num {
            return Err(AceError::InvalidRandomnessInputs {
                num_randomness: num,
                num_randomness_inputs: 0,
            });
        }

        match *self {
            RandomnessPlan::Direct { .. } => Ok(builder.input(InputKey::Randomness(index))),
            RandomnessPlan::AlphaBeta { alpha, beta, .. } => {
                if index == 0 {
                    return Ok(builder.input(alpha));
                }
                if index == 1 {
                    return Ok(builder.constant(EF::ONE));
                }
                let beta_node = builder.input(beta);
                let mut power = beta_node;
                for _ in 2..index {
                    power = builder.mul(power, beta_node);
                }
                Ok(power)
            },
        }
    }

    fn num_randomness(&self) -> usize {
        match *self {
            RandomnessPlan::Direct { num } => num,
            RandomnessPlan::AlphaBeta { num, .. } => num,
        }
    }
}
