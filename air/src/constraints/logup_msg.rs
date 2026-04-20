//! Message structs for LogUp bus interactions.
//!
//! Each struct represents a reduced denominator encoding: `α + Σ βⁱ · field_i`.
//! Fields are named for readability; the [`super::lookup::LookupMessage`] trait
//! (implemented further down in this file) provides the `encode` method that
//! produces the extension-field value.
//!
//! Chiplet messages (hasher, memory, bitwise) use a **header-as-builder** pattern:
//! construct a header with the shared context, then call a named method that bakes in
//! the operation label and produces the final message. The label enums are internal.
//!
//! All structs are generic over `E` (base-field expression type, typically `AB::Expr`).

use miden_core::field::{Algebra, PrimeCharacteristicRing};

use crate::lookup::Challenges;

// HASHER MESSAGES
// ================================================================================================

/// Hasher chiplet message. Variants differ by payload size.
///
/// Constructed via associated functions — the label is baked in by each constructor.
/// Encodes as `[label, addr, node_index, ...payload]`.
#[derive(Clone, Debug)]
pub enum HasherMsg<E> {
    /// 15-element message: addr + node_index + 12-lane sponge state.
    State {
        label_value: u16,
        addr: E,
        node_index: E,
        state: [E; 12],
    },
    /// 11-element message: addr + node_index + 8-lane rate.
    Rate {
        label_value: u16,
        addr: E,
        node_index: E,
        rate: [E; 8],
    },
    /// 7-element message: addr + node_index + 4-element word/digest.
    Word {
        label_value: u16,
        addr: E,
        node_index: E,
        word: [E; 4],
    },
}

impl<E: PrimeCharacteristicRing + Clone> HasherMsg<E> {
    // --- State messages (15 elements) ---

    /// Linear hash / control block init: full 12-lane sponge state.
    ///
    /// Used by: HPERM input, LOGPRECOMPILE input.
    pub fn linear_hash_init(addr: E, state: [E; 12]) -> Self {
        use crate::trace::chiplets::hasher::LINEAR_HASH_LABEL;
        Self::State {
            label_value: LINEAR_HASH_LABEL as u16 + 16,
            addr,
            node_index: E::ZERO,
            state,
        }
    }

    /// Control block init: 8 rate lanes + opcode at `capacity[1]`, zeros elsewhere.
    ///
    /// Used by: JOIN, SPLIT, LOOP, SPAN, CALL, SYSCALL, DYN, DYNCALL.
    pub fn control_block(addr: E, rate: &[E; 8], opcode: u8) -> Self {
        use crate::trace::chiplets::hasher::LINEAR_HASH_LABEL;
        Self::State {
            label_value: LINEAR_HASH_LABEL as u16 + 16,
            addr,
            node_index: E::ZERO,
            state: [
                rate[0].clone(),
                rate[1].clone(),
                rate[2].clone(),
                rate[3].clone(),
                rate[4].clone(),
                rate[5].clone(),
                rate[6].clone(),
                rate[7].clone(),
                E::ZERO,
                E::from_u16(opcode as u16),
                E::ZERO,
                E::ZERO,
            ],
        }
    }

    /// Return full sponge state after permutation.
    ///
    /// Used by: HPERM output, LOGPRECOMPILE output.
    pub fn return_state(addr: E, state: [E; 12]) -> Self {
        use crate::trace::chiplets::hasher::RETURN_STATE_LABEL;
        Self::State {
            label_value: RETURN_STATE_LABEL as u16 + 32,
            addr,
            node_index: E::ZERO,
            state,
        }
    }

    // --- Rate messages (11 elements) ---

    /// Absorb new rate into running hash.
    ///
    /// Used by: RESPAN.
    pub fn absorption(addr: E, rate: [E; 8]) -> Self {
        use crate::trace::chiplets::hasher::LINEAR_HASH_LABEL;
        Self::Rate {
            label_value: LINEAR_HASH_LABEL as u16 + 32,
            addr,
            node_index: E::ZERO,
            rate,
        }
    }

    // --- Word messages (7 elements) ---

    /// Return digest only (node_index = 0).
    ///
    /// Used by: END, MPVERIFY output, MRUPDATE output.
    pub fn return_hash(addr: E, word: [E; 4]) -> Self {
        use crate::trace::chiplets::hasher::RETURN_HASH_LABEL;
        Self::Word {
            label_value: RETURN_HASH_LABEL as u16 + 32,
            addr,
            node_index: E::ZERO,
            word,
        }
    }

    /// Start Merkle path verification (with explicit node_index).
    ///
    /// Used by: MPVERIFY input.
    pub fn merkle_verify_init(addr: E, node_index: E, word: [E; 4]) -> Self {
        use crate::trace::chiplets::hasher::MP_VERIFY_LABEL;
        Self::Word {
            label_value: MP_VERIFY_LABEL as u16 + 16,
            addr,
            node_index,
            word,
        }
    }

    /// Start Merkle update, old path (with explicit node_index).
    ///
    /// Used by: MRUPDATE old input.
    pub fn merkle_old_init(addr: E, node_index: E, word: [E; 4]) -> Self {
        use crate::trace::chiplets::hasher::MR_UPDATE_OLD_LABEL;
        Self::Word {
            label_value: MR_UPDATE_OLD_LABEL as u16 + 16,
            addr,
            node_index,
            word,
        }
    }

    /// Start Merkle update, new path (with explicit node_index).
    ///
    /// Used by: MRUPDATE new input.
    pub fn merkle_new_init(addr: E, node_index: E, word: [E; 4]) -> Self {
        use crate::trace::chiplets::hasher::MR_UPDATE_NEW_LABEL;
        Self::Word {
            label_value: MR_UPDATE_NEW_LABEL as u16 + 16,
            addr,
            node_index,
            word,
        }
    }
}

// MEMORY MESSAGES
// ================================================================================================

/// Common header for all memory messages: `[ctx, addr, clk]`.
///
/// Call a named method to produce a [`MemoryMsg`] with the correct operation label baked in.
#[derive(Clone, Debug)]
pub struct MemoryHeader<E> {
    pub ctx: E,
    pub addr: E,
    pub clk: E,
}

impl<E: PrimeCharacteristicRing + Clone> MemoryHeader<E> {
    /// Read a single element from memory.
    pub fn read_element(&self, element: E) -> MemoryMsg<E> {
        use crate::trace::chiplets::memory::MEMORY_READ_ELEMENT_LABEL;
        MemoryMsg::Element {
            op_value: MEMORY_READ_ELEMENT_LABEL as u16,
            header: self.clone(),
            element,
        }
    }

    /// Write a single element to memory.
    pub fn write_element(&self, element: E) -> MemoryMsg<E> {
        use crate::trace::chiplets::memory::MEMORY_WRITE_ELEMENT_LABEL;
        MemoryMsg::Element {
            op_value: MEMORY_WRITE_ELEMENT_LABEL as u16,
            header: self.clone(),
            element,
        }
    }

    /// Read a 4-element word from memory.
    pub fn read_word(&self, word: [E; 4]) -> MemoryMsg<E> {
        use crate::trace::chiplets::memory::MEMORY_READ_WORD_LABEL;
        MemoryMsg::Word {
            op_value: MEMORY_READ_WORD_LABEL as u16,
            header: self.clone(),
            word,
        }
    }

    /// Write a 4-element word to memory.
    pub fn write_word(&self, word: [E; 4]) -> MemoryMsg<E> {
        use crate::trace::chiplets::memory::MEMORY_WRITE_WORD_LABEL;
        MemoryMsg::Word {
            op_value: MEMORY_WRITE_WORD_LABEL as u16,
            header: self.clone(),
            word,
        }
    }
}

/// Memory chiplet message. Variants differ by payload size.
///
/// Constructed via methods on [`MemoryHeader`] — the operation label is baked in.
/// Encodes as `[op_label, ctx, addr, clk, ...payload]`.
#[derive(Clone, Debug)]
pub enum MemoryMsg<E> {
    /// 5-element message: header + one field element.
    Element {
        op_value: u16,
        header: MemoryHeader<E>,
        element: E,
    },
    /// 8-element message: header + 4-element word.
    Word {
        op_value: u16,
        header: MemoryHeader<E>,
        word: [E; 4],
    },
}

impl<E: PrimeCharacteristicRing + Clone> MemoryMsg<E> {}

// BITWISE MESSAGE
// ================================================================================================

/// Bitwise chiplet message (4 elements): `[label, a, b, result]`.
///
/// Constructed via [`BitwiseMsg::and`] or [`BitwiseMsg::xor`].
#[derive(Clone, Debug)]
pub struct BitwiseMsg<E> {
    op_value: u16,
    pub a: E,
    pub b: E,
    pub result: E,
}

impl<E: PrimeCharacteristicRing> BitwiseMsg<E> {
    /// Bitwise AND message (label = 2).
    pub fn and(a: E, b: E, result: E) -> Self {
        Self { op_value: 2, a, b, result }
    }

    /// Bitwise XOR message (label = 6).
    pub fn xor(a: E, b: E, result: E) -> Self {
        Self { op_value: 6, a, b, result }
    }
}

impl<E: PrimeCharacteristicRing + Clone> BitwiseMsg<E> {}

// DECODER MESSAGES
// ================================================================================================

/// Block stack message: `[block_id, parent_id, is_loop, ctx, fmp, depth, fn_hash[4]]`.
///
/// `Simple` — for blocks that don't save context (JOIN/SPLIT/SPAN/DYN/LOOP/RESPAN/END-simple).
/// Context fields are encoded as zeros.
///
/// `Full` — for blocks that save/restore the caller's execution context
/// (CALL/SYSCALL/DYNCALL/END-call).
#[derive(Clone, Debug)]
pub enum BlockStackMsg<E> {
    Simple {
        block_id: E,
        parent_id: E,
        is_loop: E,
    },
    Full {
        block_id: E,
        parent_id: E,
        is_loop: E,
        ctx: E,
        fmp: E,
        depth: E,
        fn_hash: [E; 4],
    },
}

impl<E: PrimeCharacteristicRing + Clone> BlockStackMsg<E> {}

/// Block hash queue message (7 elements):
/// `[parent, child_hash[4], is_first_child, is_loop_body]`.
///
/// `FirstChild` — first child of a JOIN (is_first_child = 1, is_loop_body = 0).
/// `Child` — non-first, non-loop child (is_first_child = 0, is_loop_body = 0).
/// `LoopBody` — loop body entry (is_first_child = 0, is_loop_body = 1).
/// `End` — removal at END; both flags are computed expressions.
#[derive(Clone, Debug)]
pub enum BlockHashMsg<E> {
    FirstChild {
        parent: E,
        child_hash: [E; 4],
    },
    Child {
        parent: E,
        child_hash: [E; 4],
    },
    LoopBody {
        parent: E,
        child_hash: [E; 4],
    },
    End {
        parent: E,
        child_hash: [E; 4],
        is_first_child: E,
        is_loop_body: E,
    },
}

impl<E: PrimeCharacteristicRing + Clone> BlockHashMsg<E> {}

/// Op group table message (3 elements): `[batch_id, group_pos, group_value]`.
#[derive(Clone, Debug)]
pub struct OpGroupMsg<E> {
    pub batch_id: E,
    pub group_pos: E,
    pub group_value: E,
}

impl<E: PrimeCharacteristicRing + Clone> OpGroupMsg<E> {
    /// Create an op group message. Computes `group_pos = group_count - offset`.
    pub fn new<V>(batch_id: &E, group_count: V, offset: u16, group_value: E) -> Self
    where
        V: core::ops::Sub<E, Output = E> + Clone,
    {
        Self {
            batch_id: batch_id.clone(),
            group_pos: group_count - E::from_u16(offset),
            group_value,
        }
    }
}

// STACK MESSAGE
// ================================================================================================

/// Stack overflow table message (3 elements): `[clk, val, prev]`.
///
/// `clk` is the cycle at which the value spilled past `stack[15]`, `val` is the spilled element,
/// and `prev` links to the previous overflow entry (the prior `b1`).
#[derive(Clone, Debug)]
pub struct StackOverflowMsg<E> {
    pub clk: E,
    pub val: E,
    pub prev: E,
}

// HASHER PERM-LINK MESSAGE
// ================================================================================================

/// Hasher perm-link message (13 elements): `[label, state[0..12]]`.
///
/// Binds hasher controller rows to permutation sub-chiplet rows on `BUS_HASHER_PERM_LINK`.
/// `label = 0` on input pairings (controller-input row ↔ perm-cycle row 0); `label = 1` on
/// output pairings (controller-output row ↔ perm-cycle row 15). `state` carries all 12 sponge
/// lanes (rate_0, rate_1, capacity).
#[derive(Clone, Debug)]
pub struct HasherPermLinkMsg<E> {
    pub label: E,
    pub state: [E; 12],
}

// KERNEL ROM MESSAGE
// ================================================================================================

/// Kernel ROM message (5 elements): `[label, digest[4]]`.
///
/// Constructed via [`KernelRomMsg::call`] (KERNEL_PROC_CALL_LABEL = 16) or
/// [`KernelRomMsg::init`] (KERNEL_PROC_INIT_LABEL = 48). The chiplet emits an INIT
/// `remove` (multiplicity 1) and a CALL `add` (with syscall multiplicity). The boundary
/// correction adds once per INIT; the decoder removes once per SYSCALL for CALL.
#[derive(Clone, Debug)]
pub struct KernelRomMsg<E> {
    label: u16,
    pub digest: [E; 4],
}

impl<E: PrimeCharacteristicRing + Clone> KernelRomMsg<E> {
    // KERNEL_PROC_CALL_LABEL = Felt::new(0b001111 + 1) = 16.
    const CALL_LABEL: u16 = 16;
    // KERNEL_PROC_INIT_LABEL = Felt::new(0b101111 + 1) = 48.
    const INIT_LABEL: u16 = 48;

    /// Kernel procedure call message (SYSCALL request side + chiplet-side CALL response).
    pub fn call(digest: [E; 4]) -> Self {
        Self { label: Self::CALL_LABEL, digest }
    }

    /// Kernel procedure init message (public-input request side + chiplet-side INIT response).
    pub fn init(digest: [E; 4]) -> Self {
        Self { label: Self::INIT_LABEL, digest }
    }
}

// ACE MESSAGE
// ================================================================================================

/// ACE circuit evaluation init message (6 elements): `[label, clk, ctx, ptr, num_read, num_eval]`.
#[derive(Clone, Debug)]
pub struct AceInitMsg<E> {
    pub clk: E,
    pub ctx: E,
    pub ptr: E,
    pub num_read: E,
    pub num_eval: E,
}

impl<E: PrimeCharacteristicRing + Clone> AceInitMsg<E> {
    /// ACE_INIT_LABEL = Felt(0b0111 + 1) = 8.
    const LABEL: u16 = 8;
}

// RANGE CHECK MESSAGE
// ================================================================================================

/// Range check message (1 element): `[value]`.
///
/// The denominator is `α + β⁰ · value`.
#[derive(Clone, Debug)]
pub struct RangeMsg<E> {
    pub value: E,
}

impl<E: PrimeCharacteristicRing + Clone> RangeMsg<E> {}

// LOG-PRECOMPILE CAPACITY MESSAGE
// ================================================================================================

/// Log-precompile capacity state message (5 elements): `[label, cap[4]]`.
#[derive(Clone, Debug)]
pub struct LogCapacityMsg<E> {
    pub capacity: [E; 4],
}

impl<E: PrimeCharacteristicRing + Clone> LogCapacityMsg<E> {
    /// LOG_PRECOMPILE_LABEL = 14.
    const LABEL: u16 = crate::trace::LOG_PRECOMPILE_LABEL as u16;
}

// SIBLING TABLE MESSAGE
// ================================================================================================

// Sibling table message for Merkle path operations (sparse encoding).

// ACE WIRING MESSAGE
// ================================================================================================

/// ACE wiring bus message (5 elements): `[clk, ctx, id, v0, v1]`.
///
/// Encodes a single wire entry for the ACE wiring bus (C3). Each wire carries
/// an identifier and a two-coefficient extension-field value.
#[derive(Clone, Debug)]
pub struct AceWireMsg<E> {
    pub clk: E,
    pub ctx: E,
    pub id: E,
    pub v0: E,
    pub v1: E,
}

impl<E: PrimeCharacteristicRing + Clone> AceWireMsg<E> {}

// CHIPLET RESPONSE MESSAGES
// ================================================================================================

/// Memory chiplet response message with conditional element/word encoding.
///
/// The chiplet-side memory response must select between element access (5 fields) and
/// word access (8 fields) based on `is_word`. The label, address, and element are all
/// pre-computed from the chiplet columns (including the idx0/idx1 element mux).
#[derive(Clone, Debug)]
pub struct MemoryResponseMsg<E> {
    pub label: E,
    pub ctx: E,
    pub addr: E,
    pub clk: E,
    pub is_word: E,
    pub element: E,
    pub word: [E; 4],
}

impl<E: PrimeCharacteristicRing + Clone> MemoryResponseMsg<E> {}

/// Bitwise chiplet response message with a pre-computed (conditional) label expression.
///
/// The chiplet-side label is `(1-sel)*AND_LABEL + sel*XOR_LABEL`. Unlike [`BitwiseMsg`]
/// which bakes in a fixed label, this carries the label as an expression.
#[derive(Clone, Debug)]
pub struct BitwiseResponseMsg<E> {
    pub label: E,
    pub a: E,
    pub b: E,
    pub z: E,
}

impl<E: PrimeCharacteristicRing + Clone> BitwiseResponseMsg<E> {}

// LOOKUP MESSAGE IMPLEMENTATIONS
// ================================================================================================

use crate::lookup::message::LookupMessage;

// --- HasherMsg (BUS_CHIPLETS; label_value at β⁰) -------------------------------------------------

impl<E, EF> LookupMessage<E, EF> for HasherMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        use super::lookup::bus_id::BUS_CHIPLETS;
        let bp = &challenges.beta_powers;
        let mut acc = challenges.bus_prefix[BUS_CHIPLETS].clone();
        match self {
            Self::State { label_value, addr, node_index, state } => {
                acc += bp[0].clone() * E::from_u16(*label_value);
                acc += bp[1].clone() * addr.clone();
                acc += bp[2].clone() * node_index.clone();
                for i in 0..12 {
                    acc += bp[i + 3].clone() * state[i].clone();
                }
            },
            Self::Rate { label_value, addr, node_index, rate } => {
                acc += bp[0].clone() * E::from_u16(*label_value);
                acc += bp[1].clone() * addr.clone();
                acc += bp[2].clone() * node_index.clone();
                for i in 0..8 {
                    acc += bp[i + 3].clone() * rate[i].clone();
                }
            },
            Self::Word { label_value, addr, node_index, word } => {
                acc += bp[0].clone() * E::from_u16(*label_value);
                acc += bp[1].clone() * addr.clone();
                acc += bp[2].clone() * node_index.clone();
                for i in 0..4 {
                    acc += bp[i + 3].clone() * word[i].clone();
                }
            },
        }
        acc
    }
}

// --- MemoryMsg (BUS_CHIPLETS; op_value at β⁰) ----------------------------------------------------

impl<E, EF> LookupMessage<E, EF> for MemoryMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        use super::lookup::bus_id::BUS_CHIPLETS;
        let bp = &challenges.beta_powers;
        let mut acc = challenges.bus_prefix[BUS_CHIPLETS].clone();
        match self {
            Self::Element { op_value, header, element } => {
                acc += bp[0].clone() * E::from_u16(*op_value);
                acc += bp[1].clone() * header.ctx.clone();
                acc += bp[2].clone() * header.addr.clone();
                acc += bp[3].clone() * header.clk.clone();
                acc += bp[4].clone() * element.clone();
            },
            Self::Word { op_value, header, word } => {
                acc += bp[0].clone() * E::from_u16(*op_value);
                acc += bp[1].clone() * header.ctx.clone();
                acc += bp[2].clone() * header.addr.clone();
                acc += bp[3].clone() * header.clk.clone();
                for i in 0..4 {
                    acc += bp[i + 4].clone() * word[i].clone();
                }
            },
        }
        acc
    }
}

// --- BitwiseMsg (BUS_CHIPLETS; op_value at β⁰) ---------------------------------------------------

impl<E, EF> LookupMessage<E, EF> for BitwiseMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        use super::lookup::bus_id::BUS_CHIPLETS;
        let bp = &challenges.beta_powers;
        let mut acc = challenges.bus_prefix[BUS_CHIPLETS].clone();
        acc += bp[0].clone() * E::from_u16(self.op_value);
        acc += bp[1].clone() * self.a.clone();
        acc += bp[2].clone() * self.b.clone();
        acc += bp[3].clone() * self.result.clone();
        acc
    }
}

// --- BlockStackMsg (BUS_BLOCK_STACK_TABLE; no label) ---------------------------------------------

impl<E, EF> LookupMessage<E, EF> for BlockStackMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        use super::lookup::bus_id::BUS_BLOCK_STACK_TABLE;
        let bp = &challenges.beta_powers;
        let mut acc = challenges.bus_prefix[BUS_BLOCK_STACK_TABLE].clone();
        match self {
            // `Simple` zero-pads to 10 slots in the legacy encoding. Slots `3..10`
            // contribute `β^k · 0 = 0` so they are elided from the loop.
            Self::Simple { block_id, parent_id, is_loop } => {
                acc += bp[0].clone() * block_id.clone();
                acc += bp[1].clone() * parent_id.clone();
                acc += bp[2].clone() * is_loop.clone();
            },
            Self::Full {
                block_id,
                parent_id,
                is_loop,
                ctx,
                fmp,
                depth,
                fn_hash,
            } => {
                acc += bp[0].clone() * block_id.clone();
                acc += bp[1].clone() * parent_id.clone();
                acc += bp[2].clone() * is_loop.clone();
                acc += bp[3].clone() * ctx.clone();
                acc += bp[4].clone() * fmp.clone();
                acc += bp[5].clone() * depth.clone();
                acc += bp[6].clone() * fn_hash[0].clone();
                acc += bp[7].clone() * fn_hash[1].clone();
                acc += bp[8].clone() * fn_hash[2].clone();
                acc += bp[9].clone() * fn_hash[3].clone();
            },
        }
        acc
    }
}

// --- BlockHashMsg (BUS_BLOCK_HASH_TABLE; no label) -----------------------------------------------

impl<E, EF> LookupMessage<E, EF> for BlockHashMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        use super::lookup::bus_id::BUS_BLOCK_HASH_TABLE;
        let bp = &challenges.beta_powers;
        // Per-variant fan-in: produce the (parent, child_hash, is_first_child, is_loop_body)
        // tuple, then emit a flat 7-slot payload. Mirrors the legacy `encode` ordering.
        let (parent, child_hash, is_first_child, is_loop_body) = match self {
            Self::FirstChild { parent, child_hash } => (parent, child_hash, E::ONE, E::ZERO),
            Self::Child { parent, child_hash } => (parent, child_hash, E::ZERO, E::ZERO),
            Self::LoopBody { parent, child_hash } => (parent, child_hash, E::ZERO, E::ONE),
            Self::End {
                parent,
                child_hash,
                is_first_child,
                is_loop_body,
            } => (parent, child_hash, is_first_child.clone(), is_loop_body.clone()),
        };
        let mut acc = challenges.bus_prefix[BUS_BLOCK_HASH_TABLE].clone();
        acc += bp[0].clone() * parent.clone();
        acc += bp[1].clone() * child_hash[0].clone();
        acc += bp[2].clone() * child_hash[1].clone();
        acc += bp[3].clone() * child_hash[2].clone();
        acc += bp[4].clone() * child_hash[3].clone();
        acc += bp[5].clone() * is_first_child;
        acc += bp[6].clone() * is_loop_body;
        acc
    }
}

// --- OpGroupMsg (BUS_OP_GROUP_TABLE; no label) ---------------------------------------------------

impl<E, EF> LookupMessage<E, EF> for OpGroupMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        use super::lookup::bus_id::BUS_OP_GROUP_TABLE;
        let bp = &challenges.beta_powers;
        let mut acc = challenges.bus_prefix[BUS_OP_GROUP_TABLE].clone();
        acc += bp[0].clone() * self.batch_id.clone();
        acc += bp[1].clone() * self.group_pos.clone();
        acc += bp[2].clone() * self.group_value.clone();
        acc
    }
}

// --- StackOverflowMsg (BUS_STACK_OVERFLOW_TABLE; no label) ---------------------------------------

impl<E, EF> LookupMessage<E, EF> for StackOverflowMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        use super::lookup::bus_id::BUS_STACK_OVERFLOW_TABLE;
        let bp = &challenges.beta_powers;
        let mut acc = challenges.bus_prefix[BUS_STACK_OVERFLOW_TABLE].clone();
        acc += bp[0].clone() * self.clk.clone();
        acc += bp[1].clone() * self.val.clone();
        acc += bp[2].clone() * self.prev.clone();
        acc
    }
}

// --- KernelRomMsg (BUS_CHIPLETS; `self.label` at β⁰) ---------------------------------------------

impl<E, EF> LookupMessage<E, EF> for KernelRomMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        use super::lookup::bus_id::BUS_CHIPLETS;
        let bp = &challenges.beta_powers;
        let mut acc = challenges.bus_prefix[BUS_CHIPLETS].clone();
        acc += bp[0].clone() * E::from_u16(self.label);
        for i in 0..4 {
            acc += bp[i + 1].clone() * self.digest[i].clone();
        }
        acc
    }
}

// --- AceInitMsg (BUS_CHIPLETS; constant `LABEL` at β⁰) -------------------------------------------

impl<E, EF> LookupMessage<E, EF> for AceInitMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        use super::lookup::bus_id::BUS_CHIPLETS;
        let bp = &challenges.beta_powers;
        let mut acc = challenges.bus_prefix[BUS_CHIPLETS].clone();
        acc += bp[0].clone() * E::from_u16(Self::LABEL);
        acc += bp[1].clone() * self.clk.clone();
        acc += bp[2].clone() * self.ctx.clone();
        acc += bp[3].clone() * self.ptr.clone();
        acc += bp[4].clone() * self.num_read.clone();
        acc += bp[5].clone() * self.num_eval.clone();
        acc
    }
}

// --- RangeMsg (BUS_RANGE_CHECK; no label) --------------------------------------------------------

impl<E, EF> LookupMessage<E, EF> for RangeMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        use super::lookup::bus_id::BUS_RANGE_CHECK;
        let bp = &challenges.beta_powers;
        let mut acc = challenges.bus_prefix[BUS_RANGE_CHECK].clone();
        acc += bp[0].clone() * self.value.clone();
        acc
    }
}

// --- LogCapacityMsg (BUS_LOG_PRECOMPILE_TRANSCRIPT; constant `LABEL` at β⁰) ----------------------

impl<E, EF> LookupMessage<E, EF> for LogCapacityMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        use super::lookup::bus_id::BUS_LOG_PRECOMPILE_TRANSCRIPT;
        let bp = &challenges.beta_powers;
        let mut acc = challenges.bus_prefix[BUS_LOG_PRECOMPILE_TRANSCRIPT].clone();
        acc += bp[0].clone() * E::from_u16(Self::LABEL);
        for i in 0..4 {
            acc += bp[i + 1].clone() * self.capacity[i].clone();
        }
        acc
    }
}

// --- HasherPermLinkMsg (BUS_HASHER_PERM_LINK; `label` at β⁰) -------------------------------------

impl<E, EF> LookupMessage<E, EF> for HasherPermLinkMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        use super::lookup::bus_id::BUS_HASHER_PERM_LINK;
        let bp = &challenges.beta_powers;
        let mut acc = challenges.bus_prefix[BUS_HASHER_PERM_LINK].clone();
        acc += bp[0].clone() * self.label.clone();
        for i in 0..12 {
            acc += bp[i + 1].clone() * self.state[i].clone();
        }
        acc
    }
}

// --- AceWireMsg (BUS_ACE_WIRING; no label) -------------------------------------------------------

impl<E, EF> LookupMessage<E, EF> for AceWireMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        use super::lookup::bus_id::BUS_ACE_WIRING;
        let bp = &challenges.beta_powers;
        let mut acc = challenges.bus_prefix[BUS_ACE_WIRING].clone();
        acc += bp[0].clone() * self.clk.clone();
        acc += bp[1].clone() * self.ctx.clone();
        acc += bp[2].clone() * self.id.clone();
        acc += bp[3].clone() * self.v0.clone();
        acc += bp[4].clone() * self.v1.clone();
        acc
    }
}

// LookupMessage impls for the response + sibling structs
// ================================================================================================
//
// The three `*ResponseMsg` structs below carry `LookupMessage<E, EF>` impls used by the
// `lookup/buses/chiplet_responses.rs` port. The runtime-muxed encoding (label at β⁰ taken
// from a chiplet column) keeps the C1 transition at degree 8; a per-variant split would
// bump it to 9. The per-variant split structs further down (one per distinct runtime label)
// are also live; bus authors can pick whichever variant best fits the algebraic shape of
// their port.

impl<E, EF> LookupMessage<E, EF> for MemoryResponseMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        use super::lookup::bus_id::BUS_CHIPLETS;
        let bp = &challenges.beta_powers;
        let prefix = challenges.bus_prefix[BUS_CHIPLETS].clone();

        // Element-case denominator: [label, ctx, addr, clk, element] at β⁰..β⁴.
        let mut element_msg = prefix.clone();
        element_msg += bp[0].clone() * self.label.clone();
        element_msg += bp[1].clone() * self.ctx.clone();
        element_msg += bp[2].clone() * self.addr.clone();
        element_msg += bp[3].clone() * self.clk.clone();
        element_msg += bp[4].clone() * self.element.clone();

        // Word-case denominator: [label, ctx, addr, clk, word[0..4]] at β⁰..β⁷.
        let mut word_msg = prefix;
        word_msg += bp[0].clone() * self.label.clone();
        word_msg += bp[1].clone() * self.ctx.clone();
        word_msg += bp[2].clone() * self.addr.clone();
        word_msg += bp[3].clone() * self.clk.clone();
        for i in 0..4 {
            word_msg += bp[i + 4].clone() * self.word[i].clone();
        }

        // Runtime mux mirrors the legacy `encode`.
        let is_element: E = E::ONE - self.is_word.clone();
        element_msg * is_element + word_msg * self.is_word.clone()
    }
}

impl<E, EF> LookupMessage<E, EF> for BitwiseResponseMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        use super::lookup::bus_id::BUS_CHIPLETS;
        let bp = &challenges.beta_powers;
        let mut acc = challenges.bus_prefix[BUS_CHIPLETS].clone();
        acc += bp[0].clone() * self.label.clone();
        acc += bp[1].clone() * self.a.clone();
        acc += bp[2].clone() * self.b.clone();
        acc += bp[3].clone() * self.z.clone();
        acc
    }
}

// PER-VARIANT RESPONSE + SIBLING MESSAGES
// ================================================================================================
//
// These structs let the chiplet-response bus (C1) and the hash-kernel bus (C2) encode through
// the `LookupMessage<E, EF>::encode` trait. Each implements `LookupMessage<E, EF>::encode` and
// nothing else.
//
// The response structs each fan their per-label cases out into dedicated structs rather than
// keeping a runtime `label: E` mux: the trait needs to resolve the label into a compile-time
// `u16` at `encode`-time. Each variant hard-wires its label via a `const LABEL: u16`, and the
// caller gates four mutually-exclusive flags (memory) or two ME flags (kernel ROM / bitwise)
// so the running-sum contribution matches the unified single-interaction hybrid exactly.
//
// `SiblingMsg` is split into `SiblingMsgBitZero<E>` / `SiblingMsgBitOne<E>`, each carrying
// the relevant hasher half, and encodes against the **sparse β layouts** (`[2, 7, 8, 9, 10]`
// and `[2, 3, 4, 5, 6]`) that the responder-side hasher chiplet algebra requires. The trait
// is permissive about *which* β positions an `encode` body touches; only the contiguous
// convention is a suggestion, not a requirement. Preserving the non-contiguous layout keeps
// the responder-side hasher chiplet algebra intact without touching the chiplet-side response
// encoding.

// --- MemoryResponseElementMsg (BUS_CHIPLETS) -----------------------------------------------------

// Chiplet-side memory response for a **read-element** operation.

// --- KernelRomResponse{Call,Init}Msg (BUS_CHIPLETS) ----------------------------------------------

// --- BitwiseResponse{And,Xor}Msg (BUS_CHIPLETS) --------------------------------------------------

// --- SiblingMsgBit{Zero,One} (BUS_SIBLING_TABLE, sparse β layouts) -------------------------------

/// Sibling-table message when `bit = 0` — sibling lives at h[4..8] and the payload goes into
/// β positions `[1, 2, 7, 8, 9, 10]`, matching the 2856 running-product layout
/// (mrupdate_id at β¹, node_index at β², sibling rate1 at β⁷..β¹⁰).
#[derive(Clone, Debug)]
pub struct SiblingMsgBitZero<E> {
    pub mrupdate_id: E,
    pub node_index: E,
    pub h_hi: [E; 4],
}

/// Sibling-table message when `bit = 1` — sibling lives at h[0..4] and the payload goes into
/// β positions `[1, 2, 3, 4, 5, 6]`.
#[derive(Clone, Debug)]
pub struct SiblingMsgBitOne<E> {
    pub mrupdate_id: E,
    pub node_index: E,
    pub h_lo: [E; 4],
}

impl<E, EF> LookupMessage<E, EF> for SiblingMsgBitZero<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        use super::lookup::bus_id::BUS_SIBLING_TABLE;
        let bp = &challenges.beta_powers;
        let mut acc = challenges.bus_prefix[BUS_SIBLING_TABLE].clone();
        acc += bp[1].clone() * self.mrupdate_id.clone();
        acc += bp[2].clone() * self.node_index.clone();
        acc += bp[7].clone() * self.h_hi[0].clone();
        acc += bp[8].clone() * self.h_hi[1].clone();
        acc += bp[9].clone() * self.h_hi[2].clone();
        acc += bp[10].clone() * self.h_hi[3].clone();
        acc
    }
}

impl<E, EF> LookupMessage<E, EF> for SiblingMsgBitOne<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        use super::lookup::bus_id::BUS_SIBLING_TABLE;
        let bp = &challenges.beta_powers;
        let mut acc = challenges.bus_prefix[BUS_SIBLING_TABLE].clone();
        acc += bp[1].clone() * self.mrupdate_id.clone();
        acc += bp[2].clone() * self.node_index.clone();
        acc += bp[3].clone() * self.h_lo[0].clone();
        acc += bp[4].clone() * self.h_lo[1].clone();
        acc += bp[5].clone() * self.h_lo[2].clone();
        acc += bp[6].clone() * self.h_lo[3].clone();
        acc
    }
}
