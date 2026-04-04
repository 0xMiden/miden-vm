//! Chiplets bus constraint (b_chiplets).
//!
//! This module enforces the running product constraint for the main chiplets bus.
//! The chiplets bus handles communication between the VM components (stack, decoder)
//! and the specialized chiplets (hasher, bitwise, memory, ACE, kernel ROM).
//!
//! ## Running Product Protocol
//!
//! The bus accumulator uses a multiset running product:
//! - Boundary: b_chiplets[0] = 1, b_chiplets[last] = reduced_kernel_digests (via aux_finals)
//! - Transition: b_chiplets' * requests = b_chiplets * responses
//!
//! Request values are computed in [`requests`], response values in [`responses`].

mod requests;
mod responses;

use miden_crypto::stark::air::{ExtensionBuilder, WindowAccess};

use crate::{
    Felt, MainCols, MidenAirBuilder,
    constraints::{
        bus::indices::B_CHIPLETS, chiplets::selectors::ChipletSelectors, op_flags::OpFlags,
    },
    trace::{
        Challenges,
        chiplets::hasher::{
            HASH_CYCLE_LEN, LINEAR_HASH_LABEL, MP_VERIFY_LABEL, MR_UPDATE_NEW_LABEL,
            MR_UPDATE_OLD_LABEL, RETURN_HASH_LABEL, RETURN_STATE_LABEL,
        },
    },
};

// LABEL CONSTANTS
// ================================================================================================

/// Transition label for linear hash init / control block requests.
const TRANSITION_LINEAR_HASH: Felt = Felt::new(LINEAR_HASH_LABEL as u64 + 16);
/// Transition label for absorb (respan).
const TRANSITION_LINEAR_HASH_ABP: Felt = Felt::new(LINEAR_HASH_LABEL as u64 + 32);
/// Transition label for Merkle path verification input.
const TRANSITION_MP_VERIFY: Felt = Felt::new(MP_VERIFY_LABEL as u64 + 16);
/// Transition label for Merkle root update (old path) input.
const TRANSITION_MR_UPDATE_OLD: Felt = Felt::new(MR_UPDATE_OLD_LABEL as u64 + 16);
/// Transition label for Merkle root update (new path) input.
const TRANSITION_MR_UPDATE_NEW: Felt = Felt::new(MR_UPDATE_NEW_LABEL as u64 + 16);
/// Transition label for return hash output.
const TRANSITION_RETURN_HASH: Felt = Felt::new(RETURN_HASH_LABEL as u64 + 32);
/// Transition label for return state output.
const TRANSITION_RETURN_STATE: Felt = Felt::new(RETURN_STATE_LABEL as u64 + 32);
/// Hasher cycle offset (HASH_CYCLE_LEN - 1 = 31).
const HASH_CYCLE_OFFSET: Felt = Felt::new((HASH_CYCLE_LEN - 1) as u64);

// ENTRY POINT
// ================================================================================================

/// Enforces the chiplets bus constraint: `b_chiplets' * requests = b_chiplets * responses`.
pub fn enforce_chiplets_bus_constraint<AB>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    challenges: &Challenges<AB::ExprEF>,
    selectors: &ChipletSelectors<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let (b_local_val, b_next_val) = {
        let aux = builder.permutation();
        let aux_local = aux.current_slice();
        let aux_next = aux.next_slice();
        (aux_local[B_CHIPLETS], aux_next[B_CHIPLETS])
    };

    let requests = requests::compute_request_multiplier::<AB>(local, next, op_flags, challenges);
    let responses =
        responses::compute_response_multiplier::<AB>(builder, local, next, challenges, selectors);

    let lhs: AB::ExprEF = Into::<AB::ExprEF>::into(b_next_val) * requests;
    let rhs: AB::ExprEF = Into::<AB::ExprEF>::into(b_local_val) * responses;
    builder.when_transition().assert_eq_ext(lhs, rhs);
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use crate::{
        Felt,
        trace::chiplets::{
            ace::ACE_INIT_LABEL,
            bitwise::{BITWISE_AND_LABEL, BITWISE_XOR_LABEL},
            kernel_rom::{KERNEL_PROC_CALL_LABEL, KERNEL_PROC_INIT_LABEL},
            memory::{
                MEMORY_READ_ELEMENT_LABEL, MEMORY_READ_WORD_LABEL, MEMORY_WRITE_ELEMENT_LABEL,
                MEMORY_WRITE_WORD_LABEL,
            },
        },
    };

    #[test]
    fn test_operation_labels() {
        assert_eq!(BITWISE_AND_LABEL, Felt::new(2));
        assert_eq!(BITWISE_XOR_LABEL, Felt::new(6));
        assert_eq!(MEMORY_WRITE_ELEMENT_LABEL, 4);
        assert_eq!(MEMORY_READ_ELEMENT_LABEL, 12);
        assert_eq!(MEMORY_WRITE_WORD_LABEL, 20);
        assert_eq!(MEMORY_READ_WORD_LABEL, 28);
    }

    #[test]
    fn test_memory_label_formula() {
        fn label(is_read: u64, is_word: u64) -> u64 {
            4 + 8 * is_read + 16 * is_word
        }
        assert_eq!(label(0, 0), MEMORY_WRITE_ELEMENT_LABEL as u64);
        assert_eq!(label(1, 0), MEMORY_READ_ELEMENT_LABEL as u64);
        assert_eq!(label(0, 1), MEMORY_WRITE_WORD_LABEL as u64);
        assert_eq!(label(1, 1), MEMORY_READ_WORD_LABEL as u64);
    }

    #[test]
    fn test_ace_label() {
        assert_eq!(ACE_INIT_LABEL, Felt::new(8));
    }

    #[test]
    fn test_kernel_rom_labels() {
        assert_eq!(KERNEL_PROC_CALL_LABEL, Felt::new(16));
        assert_eq!(KERNEL_PROC_INIT_LABEL, Felt::new(48));
    }
}
