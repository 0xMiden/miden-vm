//! Checked planning for the proof-order permutation.

use std::{string::String, vec::Vec};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayoutAccessor {
    ProofOrderPositions,
    ProofOrderIds,
}

impl LayoutAccessor {
    pub fn name(self) -> &'static str {
        match self {
            Self::ProofOrderPositions => "proof_order_positions_ptr",
            Self::ProofOrderIds => "proof_order_ids_ptr",
        }
    }
}

/// An address is supplied for validation even when emitted through a symbol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PointerRef {
    Absolute(u32),
    SharedHeights { address: u32 },
    Layout { accessor: LayoutAccessor, address: u32 },
}

impl PointerRef {
    pub fn address(self) -> u32 {
        match self {
            Self::Absolute(address)
            | Self::SharedHeights { address }
            | Self::Layout { address, .. } => address,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProofOrderConfig {
    pub num_airs: usize,
    pub heights: PointerRef,
    pub positions: PointerRef,
    pub ids: PointerRef,
    pub word_load_heights: bool,
    pub word_store_ids: bool,
    pub procedure_name: String,
    pub public: bool,
}

/// A comparator uses canonical stack positions before either operand is lifted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Comparator {
    pub lo: u8,
    pub hi: u8,
}

/// Only the movements calculated by the sorting network are variable.
/// The comparison itself is written literally in the template.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SortStep {
    Swap,
    MoveUp(u8),
    MoveDown(u8),
    CompareExchange,
}

#[derive(Clone, Debug)]
pub(crate) struct KeyRead {
    pub id: usize,
    pub pointer_depth: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct IdStore {
    pub position: usize,
    pub key_depth: usize,
    pub positions_pointer_depth: usize,
    pub ids_pointer_depth: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct WordStore {
    pub offset: usize,
    pub entries: Vec<IdStore>,
}

#[derive(Clone, Debug)]
pub(crate) struct ProofOrderPlan {
    pub config: ProofOrderConfig,
    pub num_airs: usize,
    pub key_stride: u32,
    pub key_id_mask: u32,
    pub word_load_heights: bool,
    pub scalar_key_reads: Vec<KeyRead>,
    pub word_key_ids: Vec<usize>,
    pub sort_steps: Vec<SortStep>,
    pub word_stores: Vec<WordStore>,
    pub scalar_stores: Vec<IdStore>,
}

impl ProofOrderPlan {
    pub fn new(config: &ProofOrderConfig) -> Self {
        let ProofOrderConfig {
            num_airs,
            word_load_heights,
            word_store_ids,
            ..
        } = *config;
        let heights_base = config.heights.address();
        let ids_base = config.ids.address();
        let comparators = comparator_network(num_airs);
        let name = &config.procedure_name;
        assert!(
            !name.is_empty()
                && name.bytes().enumerate().all(|(i, b)| b == b'_'
                    || b.is_ascii_alphabetic()
                    || (i > 0 && b.is_ascii_digit())),
            "proof order: procedure name must be a MASM identifier"
        );
        let positions_base = config.positions.address();
        // The comparator schedule already bounds the AIR count to 2..=12.
        let n = num_airs as u32;
        for base in [heights_base, positions_base, ids_base] {
            assert!(base.checked_add(n).is_some(), "proof-order address overflow");
        }
        assert!(
            (heights_base >= positions_base + n || positions_base >= heights_base + n)
                && (heights_base >= ids_base + n || ids_base >= heights_base + n)
                && (positions_base >= ids_base + n || ids_base >= positions_base + n),
            "proof order: height and map regions overlap"
        );
        assert!(
            !word_load_heights || (num_airs == 4 && heights_base.is_multiple_of(4)),
            "proof order: word height loads require exactly four AIRs and an aligned base"
        );
        assert!(
            !word_store_ids || ids_base.is_multiple_of(4),
            "proof order: word ID stores require an aligned base"
        );
        let mut sort_steps = Vec::new();
        for &Comparator { lo, hi } in &comparators {
            assert!(
                lo < hi && usize::from(hi) < num_airs,
                "proof order: invalid comparator positions"
            );
            Self::movement(&mut sort_steps, hi, true);
            Self::movement(&mut sort_steps, lo + 1, true);
            sort_steps.push(SortStep::CompareExchange);
            Self::movement(&mut sort_steps, lo + 1, false);
            Self::movement(&mut sort_steps, hi, false);
        }
        let scalar_key_reads = if word_load_heights {
            Vec::new()
        } else {
            (0..num_airs)
                .rev()
                .enumerate()
                .map(|(pointer_depth, id)| KeyRead { id, pointer_depth })
                .collect()
        };
        let mut word_stores = Vec::new();
        let mut scalar_stores = Vec::new();
        let mut position = 0;
        if word_store_ids {
            while position + 4 <= num_airs {
                let entries = (position..position + 4)
                    .rev()
                    .enumerate()
                    .map(|(within, position)| IdStore {
                        position,
                        key_depth: if word_load_heights { 3 } else { 5 },
                        positions_pointer_depth: if word_load_heights { 6 } else { 3 + within },
                        ids_pointer_depth: 5,
                    })
                    .collect();
                word_stores.push(WordStore { offset: position, entries });
                position += 4;
            }
        }
        for position in (position..num_airs).rev() {
            scalar_stores.push(IdStore {
                position,
                key_depth: num_airs - (position + 1) + 2,
                positions_pointer_depth: 3,
                ids_pointer_depth: 2,
            });
        }
        // Scalar tails select the highest remaining key, then consume it. Its
        // depth decreases with every store because the two table pointers stay
        // above the keys.
        let tail_len = scalar_stores.len();
        for (i, store) in scalar_stores.iter_mut().enumerate() {
            let remaining = tail_len - i;
            store.key_depth = if word_load_heights {
                remaining - 1
            } else {
                remaining + 1
            };
            if word_load_heights {
                store.positions_pointer_depth = remaining + 2;
                store.ids_pointer_depth = remaining + 1;
            }
        }
        for store in word_stores.iter().flat_map(|w| &w.entries).chain(&scalar_stores) {
            assert!(
                store.key_depth < 16 && store.positions_pointer_depth < 16,
                "proof order: stack movement exceeds sixteen slots"
            );
        }
        let key_stride = u32::try_from(miden_ace::PROOF_ORDER_KEY_STRIDE)
            .unwrap_or_else(|_| panic!("proof order: key stride exceeds u32"));
        assert!(key_stride == 16, "proof order: v1 requires key stride sixteen");
        Self {
            config: config.clone(),
            num_airs,
            key_stride,
            key_id_mask: key_stride - 1,
            word_load_heights,
            scalar_key_reads,
            word_key_ids: if word_load_heights {
                (0..num_airs).collect()
            } else {
                Vec::new()
            },
            sort_steps,
            word_stores,
            scalar_stores,
        }
    }

    fn movement(steps: &mut Vec<SortStep>, depth: u8, up: bool) {
        assert!(depth < 16, "proof order: direct stack index must be below sixteen");
        if depth == 0 {
            return;
        }
        if depth == 1 {
            if steps.last() == Some(&SortStep::Swap) {
                steps.pop();
            } else {
                steps.push(SortStep::Swap);
            }
        } else {
            steps.push(if up {
                SortStep::MoveUp(depth)
            } else {
                SortStep::MoveDown(depth)
            });
        }
    }
}

/// Generic ACE owns the portable comparator schedule. Rendering owns only its
/// checked stack choreography and MASM presentation.
pub(crate) fn comparator_network(num_airs: usize) -> Vec<Comparator> {
    assert!((2..=12).contains(&num_airs), "proof order: AIR count must be in 2..=12");
    miden_ace::proof_order_comparators(num_airs)
        .into_iter()
        .map(|(lo, hi)| Comparator { lo: lo as u8, hi: hi as u8 })
        .collect()
}
