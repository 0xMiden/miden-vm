use miden_air::trace::RowIndex;
use miden_core::{
    OPCODE_CALL, OPCODE_DYN, OPCODE_DYNCALL, OPCODE_END, OPCODE_HALT, OPCODE_JOIN, OPCODE_LOOP,
    OPCODE_REPEAT, OPCODE_SPLIT, OPCODE_SYSCALL, Word, ZERO, field::ExtensionField,
};

use super::{AuxColumnBuilder, Felt, MainTrace, ONE};
use crate::{PrimeField64, debug::BusDebugger};

// BLOCK HASH TABLE COLUMN BUILDER
// ================================================================================================

/// Builds the execution trace of the decoder's `p2` column which describes the state of the block
/// hash table via multiset checks.
///
/// At any point in time, the block hash table contains the hashes of the blocks whose parents have
/// been visited, and that remain to be executed. For example, when we encounter the beginning of a
/// JOIN block, we add both children to the table, since both will be executed at some point in the
/// future. However, when we encounter the beginning of a SPLIT block, we only push the left or the
/// right child, depending on the current value on the stack (since only one child gets executed in
/// a SPLIT block). When we encounter an `END` operation, we remove the block from the table that
/// corresponds to the block that just ended. The table is initialized with the root block's hash,
/// since it doesn't have a parent, and so would never be added to the table otherwise.
#[derive(Default)]
pub struct BlockHashTableColumnBuilder {}

impl<E: ExtensionField<Felt>> AuxColumnBuilder<E> for BlockHashTableColumnBuilder {
    fn init_responses(
        &self,
        main_trace: &MainTrace,
        alphas: &[E],
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        BlockHashTableRow::table_init(main_trace).collapse(alphas)
    }

    /// Removes a row from the block hash table.
    fn get_requests_at(
        &self,
        main_trace: &MainTrace,
        alphas: &[E],
        row: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let op_code = main_trace.get_op_code(row).as_canonical_u64() as u8;

        match op_code {
            OPCODE_END => BlockHashTableRow::from_end(main_trace, row).collapse(alphas),
            _ => E::ONE,
        }
    }

    /// Adds a row to the block hash table.
    fn get_responses_at(
        &self,
        main_trace: &MainTrace,
        alphas: &[E],
        row: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let op_code = main_trace.get_op_code(row).as_canonical_u64() as u8;

        match op_code {
            OPCODE_JOIN => {
                let left_child_row = BlockHashTableRow::from_join(main_trace, row, true);
                let right_child_row = BlockHashTableRow::from_join(main_trace, row, false);

                // Note: this adds the 2 rows separately to the block hash table.
                left_child_row.collapse(alphas) * right_child_row.collapse(alphas)
            },
            OPCODE_SPLIT => BlockHashTableRow::from_split(main_trace, row).collapse(alphas),
            OPCODE_LOOP => BlockHashTableRow::from_loop(main_trace, row)
                .map(|row| row.collapse(alphas))
                .unwrap_or(E::ONE),
            OPCODE_REPEAT => BlockHashTableRow::from_repeat(main_trace, row).collapse(alphas),
            OPCODE_DYN | OPCODE_DYNCALL | OPCODE_CALL | OPCODE_SYSCALL => {
                BlockHashTableRow::from_dyn_dyncall_call_syscall(main_trace, row).collapse(alphas)
            },
            _ => E::ONE,
        }
    }
}

// BLOCK HASH TABLE ROW
// ================================================================================================

/// Describes a single entry in the block hash table. An entry in the block hash table is a tuple
/// (parent_id, block_hash, is_first_child, is_loop_body), where each column is defined as follows:
/// - parent_block_id: contains the ID of the current block. Note: the current block's ID is the
///   parent block's ID from the perspective of the block being added to the table.
/// - block_hash: these 4 columns hold the hash of the current block's child which will be executed
///   at some point in time in the future.
/// - is_first_child: set to true if the table row being added represents the first child of the
///   current block. If the current block has only one child, set to false.
/// - is_loop_body: Set to true when the current block block is a LOOP code block (and hence, the
///   current block's child being added to the table is the body of a loop).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHashTableRow {
    parent_block_id: Felt,
    child_block_hash: Word,
    is_first_child: bool,
    is_loop_body: bool,
}

impl BlockHashTableRow {
    // CONSTRUCTORS
    // ----------------------------------------------------------------------------------------------

    // Instantiates the initial row in the block hash table.
    pub fn table_init(main_trace: &MainTrace) -> Self {
        let program_hash =
            main_trace.decoder_hasher_state_first_half(main_trace.last_program_row());
        Self {
            parent_block_id: ZERO,
            child_block_hash: program_hash,
            is_first_child: false,
            is_loop_body: false,
        }
    }

    /// Computes the row to be removed from the block hash table when encountering an `END`
    /// operation.
    pub fn from_end(main_trace: &MainTrace, row: RowIndex) -> Self {
        let op_code_next = main_trace.get_op_code(row + 1).as_canonical_u64() as u8;
        let parent_block_id = main_trace.addr(row + 1);
        let child_block_hash = main_trace.decoder_hasher_state_first_half(row);

        // A block can only be a first child of a JOIN block; every other control block only
        // executes one child. Hence, it is easier to identify the conditions that only a
        // "second child" (i.e. a JOIN block's second child, as well as all other control
        // block's child) can find itself in. That is, when the opcode of the next row is:
        // - END: this marks the end of the parent block, which only a second child can be in
        // - REPEAT: this means that the current block is the child of a LOOP block, and hence a
        //   "second child"
        // - HALT: The end of the program, which a first child can't find itself in (since the
        //   second child needs to execute first)
        let is_first_child = op_code_next != OPCODE_END
            && op_code_next != OPCODE_REPEAT
            && op_code_next != OPCODE_HALT;

        let is_loop_body = match main_trace.is_loop_body_flag(row).as_canonical_u64() {
            0 => false,
            1 => true,
            other => panic!("expected loop body flag to be 0 or 1, got {other}"),
        };

        Self {
            parent_block_id,
            child_block_hash,
            is_first_child,
            is_loop_body,
        }
    }

    /// Computes the row corresponding to the left or right child to add to the block hash table
    /// when encountering a `JOIN` operation.
    pub fn from_join(main_trace: &MainTrace, row: RowIndex, is_first_child: bool) -> Self {
        let child_block_hash = if is_first_child {
            main_trace.decoder_hasher_state_first_half(row)
        } else {
            main_trace.decoder_hasher_state_second_half(row)
        };

        Self {
            parent_block_id: main_trace.addr(row + 1),
            child_block_hash,
            is_first_child,
            is_loop_body: false,
        }
    }

    /// Computes the row to add to the block hash table when encountering a `SPLIT` operation.
    pub fn from_split(main_trace: &MainTrace, row: RowIndex) -> Self {
        let stack_top = main_trace.stack_element(0, row);
        let parent_block_id = main_trace.addr(row + 1);
        // Note: only one child of a split block is executed. Hence, `is_first_child` is always
        // false.
        let is_first_child = false;
        let is_loop_body = false;

        if stack_top == ONE {
            let left_child_block_hash = main_trace.decoder_hasher_state_first_half(row);
            Self {
                parent_block_id,
                child_block_hash: left_child_block_hash,
                is_first_child,
                is_loop_body,
            }
        } else {
            let right_child_block_hash = main_trace.decoder_hasher_state_second_half(row);

            Self {
                parent_block_id,
                child_block_hash: right_child_block_hash,
                is_first_child,
                is_loop_body,
            }
        }
    }

    /// Computes the row (optionally) to add to the block hash table when encountering a `LOOP`
    /// operation. That is, a loop will have a child to execute when the top of the stack is 1.
    pub fn from_loop(main_trace: &MainTrace, row: RowIndex) -> Option<Self> {
        let stack_top = main_trace.stack_element(0, row);

        if stack_top == ONE {
            Some(Self {
                parent_block_id: main_trace.addr(row + 1),
                child_block_hash: main_trace.decoder_hasher_state_first_half(row),
                is_first_child: false,
                is_loop_body: true,
            })
        } else {
            None
        }
    }

    /// Computes the row to add to the block hash table when encountering a `REPEAT` operation. A
    /// `REPEAT` marks the start of a new loop iteration, and hence the loop's child block needs to
    /// be added to the block hash table once again (since it was removed in the previous `END`
    /// instruction).
    pub fn from_repeat(main_trace: &MainTrace, row: RowIndex) -> Self {
        Self {
            parent_block_id: main_trace.addr(row + 1),
            child_block_hash: main_trace.decoder_hasher_state_first_half(row),
            is_first_child: false,
            is_loop_body: true,
        }
    }

    /// Computes the row to add to the block hash table when encountering a `DYN`, `DYNCALL`, `CALL`
    /// or `SYSCALL` operation.
    ///
    /// The hash of the child node being called is expected to be in the first half of the decoder
    /// hasher state.
    pub fn from_dyn_dyncall_call_syscall(main_trace: &MainTrace, row: RowIndex) -> Self {
        Self {
            parent_block_id: main_trace.addr(row + 1),
            child_block_hash: main_trace.decoder_hasher_state_first_half(row),
            is_first_child: false,
            is_loop_body: false,
        }
    }

    // COLLAPSE
    // ----------------------------------------------------------------------------------------------

    /// Collapses this row to a single field element in the field specified by E by taking a random
    /// linear combination of all the columns. This requires 8 alpha values, which are assumed to
    /// have been drawn randomly.
    pub fn collapse<E: ExtensionField<Felt>>(&self, alphas: &[E]) -> E {
        let is_first_child = if self.is_first_child { ONE } else { ZERO };
        let is_loop_body = if self.is_loop_body { ONE } else { ZERO };
        alphas[0]
            + alphas[1] * self.parent_block_id
            + alphas[2] * self.child_block_hash[0]
            + alphas[3] * self.child_block_hash[1]
            + alphas[4] * self.child_block_hash[2]
            + alphas[5] * self.child_block_hash[3]
            + alphas[6] * is_first_child
            + alphas[7] * is_loop_body
    }

    // TEST
    // ----------------------------------------------------------------------------------------------

    /// Returns a new [BlockHashTableRow] instantiated with the specified parameters. This is
    /// used for test purpose only.
    #[cfg(test)]
    pub fn new_test(
        parent_id: Felt,
        block_hash: Word,
        is_first_child: bool,
        is_loop_body: bool,
    ) -> Self {
        Self {
            parent_block_id: parent_id,
            child_block_hash: block_hash,
            is_first_child,
            is_loop_body,
        }
    }
}
