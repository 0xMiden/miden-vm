//! Canonical declaration and protocol policy of the precompile relation family.

use alloc::{format, string::String, vec::Vec};

use miden_ace_codegen::{
    AceError, AirDeclaration, CapturedAir, CompiledRelation, Inclusion, RelationFamily,
};
use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::Matrix,
};
use miden_lifted_air::{BaseAir, LiftedAir, ReductionError};

use crate::{ChipletAir, NUM_CHIPLETS, fixed, policy};

/// Declaration order is the stable AIR identity order, including across family members.
/// Optional AIRs belonging to the same feature use the same single-bit inclusion mask.
pub const AIR_DECLARATIONS: [AirDeclaration<ChipletAir>; NUM_CHIPLETS] = [
    AirDeclaration {
        air: ChipletAir::ChunkNodeSponge,
        inclusion: Inclusion::Required,
    },
    AirDeclaration {
        air: ChipletAir::EidosCompression,
        inclusion: Inclusion::Required,
    },
    AirDeclaration {
        air: ChipletAir::KeccakRound,
        inclusion: Inclusion::Required,
    },
    AirDeclaration {
        air: ChipletAir::BytePairLut,
        inclusion: Inclusion::Required,
    },
    AirDeclaration {
        air: ChipletAir::TranscriptEval,
        inclusion: Inclusion::Required,
    },
    AirDeclaration {
        air: ChipletAir::UintStoreMul,
        inclusion: Inclusion::Required,
    },
    AirDeclaration {
        air: ChipletAir::UintAdd,
        inclusion: Inclusion::Required,
    },
    AirDeclaration {
        air: ChipletAir::EcPointStoreGroups,
        inclusion: Inclusion::Required,
    },
    AirDeclaration {
        air: ChipletAir::EcGroupAdd,
        inclusion: Inclusion::Required,
    },
    AirDeclaration {
        air: ChipletAir::EcMsm,
        inclusion: Inclusion::Required,
    },
    AirDeclaration {
        air: ChipletAir::Sha512,
        inclusion: Inclusion::Required,
    },
    AirDeclaration {
        air: ChipletAir::Sha256,
        inclusion: Inclusion::Required,
    },
];

const fn supported_mask() -> u32 {
    let mut mask = 0;
    let mut index = 0;
    while index < AIR_DECLARATIONS.len() {
        if let Inclusion::Optional(bit) = AIR_DECLARATIONS[index].inclusion {
            mask |= bit;
        }
        index += 1;
    }
    mask
}

fn family() -> RelationFamily<'static, ChipletAir> {
    RelationFamily::new(&AIR_DECLARATIONS).expect("valid precompile relation declaration")
}

/// A validated member of the declared precompile relation family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelationSelection(u32);

impl RelationSelection {
    pub const FULL: Self = Self(supported_mask());

    pub fn from_mask(mask: u32) -> Result<Self, AceError> {
        family().select(mask)?;
        Ok(Self(mask))
    }

    pub const fn mask(self) -> u32 {
        self.0
    }

    pub const fn recursive_selector(self) -> u32 {
        self.mask()
    }

    pub fn airs(self) -> Vec<ChipletAir> {
        family().select(self.0).expect("validated relation selection")
    }

    /// Stable declaration indices corresponding to the compact selected AIR order.
    pub fn canonical_indices(self) -> Vec<usize> {
        AIR_DECLARATIONS
            .iter()
            .enumerate()
            .filter_map(|(index, declaration)| match declaration.inclusion {
                Inclusion::Required => Some(index),
                Inclusion::Optional(bit) => (self.0 & bit != 0).then_some(index),
            })
            .collect()
    }

    pub fn all() -> Vec<Self> {
        let supported = supported_mask();
        let mut mask = supported;
        let mut selections = Vec::new();
        loop {
            if family().select(mask).is_ok() {
                selections.push(Self(mask));
            }
            if mask == 0 {
                break;
            }
            mask = (mask - 1) & supported;
        }
        selections.reverse();
        selections
    }

    pub fn module_name(self) -> String {
        if self == Self::FULL {
            "pvm".into()
        } else {
            format!("pvm_{}", self.0)
        }
    }

    pub fn protocol(self) -> RelationProtocol {
        let airs = self.airs();
        let num_public_values = airs[0].num_public_values();
        assert!(airs.iter().all(|air| air.num_public_values() == num_public_values));
        RelationProtocol {
            protocol_id: policy::PROTOCOL_ID,
            num_public_values,
            max_aux_inputs: 0,
            num_aux_inputs: 0,
            heights: airs
                .iter()
                .map(|air| {
                    air.fixed_log_height().map(HeightRule::Fixed).unwrap_or_else(|| {
                        let preprocessed_height =
                            air.preprocessed_trace().map_or(0, |trace| trace.height());
                        HeightRule::Minimum(
                            air.max_periodic_length().max(preprocessed_height).max(2).ilog2(),
                        )
                    })
                })
                .collect(),
            max_periodic_log: airs
                .iter()
                .map(|air| air.max_periodic_length().max(1).ilog2())
                .max()
                .unwrap_or(0),
            boundary: AuxBoundaryPlan::for_airs(&airs),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeightRule {
    Minimum(u32),
    Fixed(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuxBoundaryReduction {
    TraceLengthWeightedSum,
}

#[derive(Clone, Debug)]
pub struct AuxBoundaryPlan {
    pub values_per_air: Vec<usize>,
    pub reduction: AuxBoundaryReduction,
    pub fixed_boundary_terms: usize,
}

impl AuxBoundaryPlan {
    pub fn for_airs(airs: &[ChipletAir]) -> Self {
        Self {
            values_per_air: airs.iter().map(LiftedAir::<Felt, QuadFelt>::num_aux_values).collect(),
            reduction: AuxBoundaryReduction::TraceLengthWeightedSum,
            fixed_boundary_terms: fixed::fixed_uintval_msgs().count()
                + fixed::fixed_ecgroup_msgs().count(),
        }
    }

    /// Reduce normalized committed LogUp residues using their committed trace lengths.
    pub fn reduce(
        &self,
        values: &[&[QuadFelt]],
        log_heights: &[u8],
    ) -> Result<QuadFelt, ReductionError> {
        if values.len() != self.values_per_air.len() || log_heights.len() != values.len() {
            return Err("auxiliary boundary AIR count mismatch".into());
        }
        let mut sum = QuadFelt::ZERO;
        for (index, ((values, &expected), &log_height)) in
            values.iter().zip(&self.values_per_air).zip(log_heights).enumerate()
        {
            if values.len() != expected {
                return Err(format!(
                    "AIR {index} expects {expected} auxiliary boundary values, got {}",
                    values.len()
                )
                .into());
            }
            let length = 1u64.checked_shl(u32::from(log_height)).ok_or_else(|| {
                ReductionError::from(format!(
                    "AIR {index} log trace height {log_height} does not fit in u64"
                ))
            })?;
            match self.reduction {
                AuxBoundaryReduction::TraceLengthWeightedSum => {
                    sum += values.iter().copied().sum::<QuadFelt>() * Felt::new_unchecked(length);
                },
            }
        }
        Ok(sum)
    }
}

#[derive(Clone, Debug)]
pub struct RelationProtocol {
    pub protocol_id: u64,
    pub num_public_values: usize,
    pub max_aux_inputs: usize,
    pub num_aux_inputs: usize,
    pub heights: Vec<HeightRule>,
    pub max_periodic_log: u32,
    pub boundary: AuxBoundaryPlan,
}

/// One symbolic capture of each declaration, shared by all selected compiler backends.
pub struct CapturedPvmRelation {
    airs: Vec<CapturedAir>,
}

impl CapturedPvmRelation {
    pub fn airs(&self) -> &[CapturedAir] {
        &self.airs
    }

    pub fn new() -> Result<Self, AceError> {
        Ok(Self {
            airs: AIR_DECLARATIONS
                .iter()
                .map(|declaration| CapturedAir::new(&declaration.air))
                .collect::<Result<_, _>>()?,
        })
    }

    pub fn compile(&self, selection: RelationSelection) -> Result<CompiledRelation<'_>, AceError> {
        let airs: Vec<_> = selection
            .canonical_indices()
            .into_iter()
            .map(|index| &self.airs[index])
            .collect();
        CompiledRelation::from_captured(&airs, crate::ace::LMCS_ALIGNMENT)
    }
}
