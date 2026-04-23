//! Message structs for LogUp bus interactions.
//!
//! Each struct represents a reduced denominator encoding: `α + Σ βⁱ · field_i`.
//! Fields are named for readability; the [`super::lookup::LookupMessage`] trait
//! (implemented further down in this file) provides the `encode` method that
//! produces the extension-field value.
//!
//! Chiplet messages are addressed by interaction-specific bus domains (one [`BusId`]
//! variant per semantic message kind). Constructors pick the interaction domain; payloads
//! start directly with the semantic fields (addr, ctx, etc.).
//!
//! All structs are generic over `E` (base-field expression type, typically `AB::Expr`).

use miden_core::field::{Algebra, PrimeCharacteristicRing};

use crate::lookup::Challenges;

// BUS IDENTIFIERS
// ================================================================================================

/// Width of the `beta_powers` table `Challenges` precomputes for Miden's bus
/// messages, i.e. the exponent of `gamma = beta^MIDEN_MAX_MESSAGE_WIDTH` used in
/// `bus_prefix[i] = alpha + (i + 1) * gamma`.
///
/// Must match the Poseidon2 absorption loop in `crates/lib/core/asm/stark/` which
/// reads the same β-power table during recursive verification.
pub const MIDEN_MAX_MESSAGE_WIDTH: usize = 16;

/// Domain-separated bus interaction identifier.
///
/// Each variant identifies a distinct bus interaction type. When encoding a message,
/// the bus is cast to `usize` and indexes into
/// [`Challenges::bus_prefix`](crate::lookup::Challenges) to obtain the additive base
/// `bus_prefix[bus] = alpha + (bus + 1) * gamma`.
#[repr(usize)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BusId {
    // --- Out-of-circuit (boundary correction / reduced_aux_values) ---
    /// Kernel ROM init: kernel procedure digests from variable-length public inputs.
    KernelRomInit = 0,
    /// Block hash table (decoder p2): root program hash boundary correction.
    BlockHashTable = 1,
    /// Log-precompile transcript: initial/final capacity state boundary correction.
    LogPrecompileTranscript = 2,

    // --- In-circuit buses ---
    KernelRomCall = 3,
    HasherLinearHashInit = 4,
    HasherReturnState = 5,
    HasherAbsorption = 6,
    HasherReturnHash = 7,
    HasherMerkleVerifyInit = 8,
    HasherMerkleOldInit = 9,
    HasherMerkleNewInit = 10,
    MemoryReadElement = 11,
    MemoryWriteElement = 12,
    MemoryReadWord = 13,
    MemoryWriteWord = 14,
    Bitwise = 15,
    AceInit = 16,
    /// Block stack table (decoder p1): tracks control flow block nesting.
    BlockStackTable = 17,
    /// Op group table (decoder p3): tracks operation batch consumption.
    OpGroupTable = 18,
    /// Stack overflow table.
    StackOverflowTable = 19,
    /// Sibling table: shares Merkle tree sibling nodes between old/new root computations.
    SiblingTable = 20,
    /// Range checker bus (LogUp).
    RangeCheck = 21,
    /// ACE wiring bus (LogUp).
    AceWiring = 22,
    /// Hasher perm-link input bus: pairs controller-input rows with perm-cycle row 0.
    HasherPermLinkInput = 23,
    /// Hasher perm-link output bus: pairs controller-output rows with perm-cycle row 15.
    HasherPermLinkOutput = 24,
}

impl BusId {
    /// Last variant discriminant. Paired with the static assertion below, `COUNT` stays
    /// in lockstep with the enum: adding a new variant with a higher discriminant bumps
    /// `COUNT` automatically (and the assertion flags a missed update if the new variant's
    /// discriminant isn't contiguous).
    pub const COUNT: usize = Self::HasherPermLinkOutput as usize + 1;
}

// Guard against an enum-update that skips a discriminant: any gap would inflate `COUNT`
// relative to the real variant count and silently resize the bus-prefix table. If this
// fires, either fill the gap or extend the check.
const _: () = assert!(BusId::HasherPermLinkOutput as usize == 24);

// HASHER MESSAGES
// ================================================================================================

/// Hasher chiplet message: a [`BusId`] tag plus a variable-width payload.
///
/// All hasher messages encode as `bus_prefix[kind] + [addr, node_index, ...payload]`; only
/// the payload width differs between variants.
#[derive(Clone, Debug)]
pub struct HasherMsg<E> {
    pub kind: BusId,
    pub addr: E,
    pub node_index: E,
    pub payload: HasherPayload<E>,
}

/// Payload for a [`HasherMsg`]; width varies per interaction kind.
#[derive(Clone, Debug)]
pub enum HasherPayload<E> {
    /// 12-lane sponge state.
    State([E; 12]),
    /// 8-lane rate.
    Rate([E; 8]),
    /// 4-element word/digest.
    Word([E; 4]),
}

impl<E: PrimeCharacteristicRing + Clone> HasherMsg<E> {
    // --- State messages (14 payload elements: [addr, node_index, state[12]]) ---

    /// Linear hash / control block init: full 12-lane sponge state.
    ///
    /// Used by: HPERM input, LOGPRECOMPILE input.
    pub fn linear_hash_init(addr: E, state: [E; 12]) -> Self {
        Self {
            kind: BusId::HasherLinearHashInit,
            addr,
            node_index: E::ZERO,
            payload: HasherPayload::State(state),
        }
    }

    /// Control block init: 8 rate lanes + opcode at `capacity[1]`, zeros elsewhere.
    ///
    /// Used by: JOIN, SPLIT, LOOP, SPAN, CALL, SYSCALL, DYN, DYNCALL.
    pub fn control_block(addr: E, rate: &[E; 8], opcode: u8) -> Self {
        let state = [
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
        ];
        Self {
            kind: BusId::HasherLinearHashInit,
            addr,
            node_index: E::ZERO,
            payload: HasherPayload::State(state),
        }
    }

    /// Return full sponge state after permutation.
    ///
    /// Used by: HPERM output, LOGPRECOMPILE output.
    pub fn return_state(addr: E, state: [E; 12]) -> Self {
        Self {
            kind: BusId::HasherReturnState,
            addr,
            node_index: E::ZERO,
            payload: HasherPayload::State(state),
        }
    }

    // --- Rate messages (10 payload elements: [addr, node_index, rate[8]]) ---

    /// Absorb new rate into running hash.
    ///
    /// Used by: RESPAN.
    pub fn absorption(addr: E, rate: [E; 8]) -> Self {
        Self {
            kind: BusId::HasherAbsorption,
            addr,
            node_index: E::ZERO,
            payload: HasherPayload::Rate(rate),
        }
    }

    // --- Word messages (6 payload elements: [addr, node_index, word[4]]) ---

    /// Return digest only (node_index = 0).
    ///
    /// Used by: END, MPVERIFY output, MRUPDATE output.
    pub fn return_hash(addr: E, word: [E; 4]) -> Self {
        Self {
            kind: BusId::HasherReturnHash,
            addr,
            node_index: E::ZERO,
            payload: HasherPayload::Word(word),
        }
    }

    /// Start Merkle path verification (with explicit node_index).
    ///
    /// Used by: MPVERIFY input.
    pub fn merkle_verify_init(addr: E, node_index: E, word: [E; 4]) -> Self {
        Self {
            kind: BusId::HasherMerkleVerifyInit,
            addr,
            node_index,
            payload: HasherPayload::Word(word),
        }
    }

    /// Start Merkle update, old path (with explicit node_index).
    ///
    /// Used by: MRUPDATE old input.
    pub fn merkle_old_init(addr: E, node_index: E, word: [E; 4]) -> Self {
        Self {
            kind: BusId::HasherMerkleOldInit,
            addr,
            node_index,
            payload: HasherPayload::Word(word),
        }
    }

    /// Start Merkle update, new path (with explicit node_index).
    ///
    /// Used by: MRUPDATE new input.
    pub fn merkle_new_init(addr: E, node_index: E, word: [E; 4]) -> Self {
        Self {
            kind: BusId::HasherMerkleNewInit,
            addr,
            node_index,
            payload: HasherPayload::Word(word),
        }
    }
}

// MEMORY MESSAGES
// ================================================================================================

/// Memory chiplet message. Variants differ by payload size.
///
/// Encodes as `bus_prefix[bus] + [ctx, addr, clk, ...payload]`. Use the [`MemoryMsg`]
/// associated functions (`read_element`, `write_element`, `read_word`, `write_word`) to
/// build messages with the correct interaction kind.
#[derive(Clone, Debug)]
pub enum MemoryMsg<E> {
    /// 5-element message: `[ctx, addr, clk, element]`.
    Element {
        bus: BusId,
        ctx: E,
        addr: E,
        clk: E,
        element: E,
    },
    /// 8-element message: `[ctx, addr, clk, word[0..4]]`.
    Word {
        bus: BusId,
        ctx: E,
        addr: E,
        clk: E,
        word: [E; 4],
    },
}

impl<E> MemoryMsg<E> {
    /// Read a single element from memory.
    pub fn read_element(ctx: E, addr: E, clk: E, element: E) -> Self {
        Self::Element {
            bus: BusId::MemoryReadElement,
            ctx,
            addr,
            clk,
            element,
        }
    }

    /// Write a single element to memory.
    pub fn write_element(ctx: E, addr: E, clk: E, element: E) -> Self {
        Self::Element {
            bus: BusId::MemoryWriteElement,
            ctx,
            addr,
            clk,
            element,
        }
    }

    /// Read a 4-element word from memory.
    pub fn read_word(ctx: E, addr: E, clk: E, word: [E; 4]) -> Self {
        Self::Word {
            bus: BusId::MemoryReadWord,
            ctx,
            addr,
            clk,
            word,
        }
    }

    /// Write a 4-element word to memory.
    pub fn write_word(ctx: E, addr: E, clk: E, word: [E; 4]) -> Self {
        Self::Word {
            bus: BusId::MemoryWriteWord,
            ctx,
            addr,
            clk,
            word,
        }
    }
}

// BITWISE MESSAGE
// ================================================================================================

/// Bitwise chiplet message (4 elements): `[op, a, b, result]`.
#[derive(Clone, Debug)]
pub struct BitwiseMsg<E> {
    pub op: E,
    pub a: E,
    pub b: E,
    pub result: E,
}

impl<E: PrimeCharacteristicRing> BitwiseMsg<E> {
    const AND_SELECTOR: u32 = 0;
    const XOR_SELECTOR: u32 = 1;

    /// Bitwise AND message (op selector = 0).
    pub fn and(a: E, b: E, result: E) -> Self {
        Self {
            op: E::from_u32(Self::AND_SELECTOR),
            a,
            b,
            result,
        }
    }

    /// Bitwise XOR message (op selector = 1).
    pub fn xor(a: E, b: E, result: E) -> Self {
        Self {
            op: E::from_u32(Self::XOR_SELECTOR),
            a,
            b,
            result,
        }
    }
}

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

/// Block hash queue message (7 elements):
/// `[child_hash[4], parent, is_first_child, is_loop_body]`.
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

/// Hasher perm-link message (12 elements): `state[0..12]`.
///
/// Binds hasher controller rows to permutation sub-chiplet rows. The `Input` variant pairs a
/// controller-input row with perm-cycle row 0 on `BusId::HasherPermLinkInput`; the `Output`
/// variant pairs a controller-output row with perm-cycle row 15 on
/// `BusId::HasherPermLinkOutput`. `state` carries all 12 sponge lanes (rate_0, rate_1, capacity).
#[derive(Clone, Debug)]
pub enum HasherPermLinkMsg<E> {
    Input { state: [E; 12] },
    Output { state: [E; 12] },
}

// KERNEL ROM MESSAGE
// ================================================================================================

/// Kernel ROM message (4 elements): `bus_prefix[bus] + [digest[4]]`.
///
/// Two bus domains: INIT (one remove per declared procedure, balanced by the boundary
/// correction from public inputs) and CALL (one insert per SYSCALL, carrying the
/// multiplicity from kernel ROM column 0; balanced by decoder-emitted SYSCALL removes).
#[derive(Clone, Debug)]
pub struct KernelRomMsg<E> {
    bus: BusId,
    pub digest: [E; 4],
}

impl<E: PrimeCharacteristicRing + Clone> KernelRomMsg<E> {
    /// Kernel procedure call message (SYSCALL request side + chiplet CALL response).
    pub fn call(digest: [E; 4]) -> Self {
        Self { bus: BusId::KernelRomCall, digest }
    }

    /// Kernel procedure init message (public-input boundary + chiplet INIT response).
    pub fn init(digest: [E; 4]) -> Self {
        Self { bus: BusId::KernelRomInit, digest }
    }
}

// ACE MESSAGE
// ================================================================================================

/// ACE circuit evaluation init message (5 elements): `[clk, ctx, ptr, num_read, num_eval]`.
#[derive(Clone, Debug)]
pub struct AceInitMsg<E> {
    pub clk: E,
    pub ctx: E,
    pub ptr: E,
    pub num_read: E,
    pub num_eval: E,
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

// LOG-PRECOMPILE CAPACITY MESSAGE
// ================================================================================================

/// Log-precompile capacity state message (4 elements): `cap[4]`.
#[derive(Clone, Debug)]
pub struct LogCapacityMsg<E> {
    pub capacity: [E; 4],
}

// SIBLING TABLE MESSAGE
// ================================================================================================

// Sibling table message for Merkle path operations (sparse encoding).

// ACE WIRING MESSAGE
// ================================================================================================

/// ACE wiring bus message (5 elements): `[clk, ctx, id, v0, v1]`.
///
/// Encodes a single wire entry for the ACE wiring bus. Each wire carries
/// an identifier and a two-coefficient extension-field value.
#[derive(Clone, Debug)]
pub struct AceWireMsg<E> {
    pub clk: E,
    pub ctx: E,
    pub id: E,
    pub v0: E,
    pub v1: E,
}

// CHIPLET RESPONSE MESSAGES
// ================================================================================================

/// Memory chiplet response message with conditional element/word encoding.
///
/// The chiplet-side memory response must select between element access (4 payload
/// elements: `[ctx, addr, clk, element]`) and word access (7 payload elements:
/// `[ctx, addr, clk, word[4]]`) based on `is_word`. The label, address, and element are
/// all pre-computed from the chiplet columns (including the idx0/idx1 element mux).
#[derive(Clone, Debug)]
pub struct MemoryResponseMsg<E> {
    pub is_read: E,
    pub ctx: E,
    pub addr: E,
    pub clk: E,
    pub is_word: E,
    pub element: E,
    pub word: [E; 4],
}

// LOOKUP MESSAGE IMPLEMENTATIONS
// ================================================================================================

use crate::lookup::message::LookupMessage;

// --- HasherMsg (interaction-specific bus ids; payload starts at β⁰) ------------------------------

impl<E, EF> LookupMessage<E, EF> for HasherMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        let bp = &challenges.beta_powers;
        let mut acc = challenges.bus_prefix[self.kind as usize].clone();
        acc += bp[0].clone() * self.addr.clone();
        acc += bp[1].clone() * self.node_index.clone();
        match &self.payload {
            HasherPayload::State(state) => {
                for i in 0..12 {
                    acc += bp[i + 2].clone() * state[i].clone();
                }
            },
            HasherPayload::Rate(rate) => {
                for i in 0..8 {
                    acc += bp[i + 2].clone() * rate[i].clone();
                }
            },
            HasherPayload::Word(word) => {
                for i in 0..4 {
                    acc += bp[i + 2].clone() * word[i].clone();
                }
            },
        }
        acc
    }
}

// --- MemoryMsg (interaction-specific bus ids; payload starts at β⁰) ------------------------------

impl<E, EF> LookupMessage<E, EF> for MemoryMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        let bp = &challenges.beta_powers;
        let bus = match self {
            Self::Element { bus, .. } | Self::Word { bus, .. } => *bus as usize,
        };
        let mut acc = challenges.bus_prefix[bus].clone();
        match self {
            Self::Element { ctx, addr, clk, element, .. } => {
                acc += bp[0].clone() * ctx.clone();
                acc += bp[1].clone() * addr.clone();
                acc += bp[2].clone() * clk.clone();
                acc += bp[3].clone() * element.clone();
            },
            Self::Word { ctx, addr, clk, word, .. } => {
                acc += bp[0].clone() * ctx.clone();
                acc += bp[1].clone() * addr.clone();
                acc += bp[2].clone() * clk.clone();
                for i in 0..4 {
                    acc += bp[i + 3].clone() * word[i].clone();
                }
            },
        }
        acc
    }
}

// --- BitwiseMsg (BusId::Bitwise; op at β⁰)
// ----------------------------------------------------------

impl<E, EF> LookupMessage<E, EF> for BitwiseMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(
            BusId::Bitwise as usize,
            [self.op.clone(), self.a.clone(), self.b.clone(), self.result.clone()],
        )
    }
}

// --- BlockStackMsg (BusId::BlockStackTable) ---------------------------------------------

impl<E, EF> LookupMessage<E, EF> for BlockStackMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        let bp = &challenges.beta_powers;
        let mut acc = challenges.bus_prefix[BusId::BlockStackTable as usize].clone();
        match self {
            // `Simple` zero-pads to 10 slots; slots `3..10` contribute `β^k · 0 = 0` so
            // they are elided from the loop.
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

// --- BlockHashMsg (BusId::BlockHashTable) -----------------------------------------------

impl<E, EF> LookupMessage<E, EF> for BlockHashMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        // Per-variant fan-in: produce the (parent, child_hash, is_first_child, is_loop_body)
        // tuple, then emit a flat 7-slot payload laid out as
        // `[child_hash[4], parent, is_first_child, is_loop_body]`.
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
        challenges.encode(
            BusId::BlockHashTable as usize,
            [
                child_hash[0].clone(),
                child_hash[1].clone(),
                child_hash[2].clone(),
                child_hash[3].clone(),
                parent.clone(),
                is_first_child,
                is_loop_body,
            ],
        )
    }
}

// --- OpGroupMsg (BusId::OpGroupTable) ---------------------------------------------------

impl<E, EF> LookupMessage<E, EF> for OpGroupMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(
            BusId::OpGroupTable as usize,
            [self.batch_id.clone(), self.group_pos.clone(), self.group_value.clone()],
        )
    }
}

// --- StackOverflowMsg (BusId::StackOverflowTable) ---------------------------------------

impl<E, EF> LookupMessage<E, EF> for StackOverflowMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(
            BusId::StackOverflowTable as usize,
            [self.clk.clone(), self.val.clone(), self.prev.clone()],
        )
    }
}

// --- KernelRomMsg (BusId::KernelRomInit / BusId::KernelRomCall)
// ------------------------------------

impl<E, EF> LookupMessage<E, EF> for KernelRomMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(self.bus as usize, self.digest.clone())
    }
}

// --- AceInitMsg (BusId::AceInit)
// -------------------------------------------------------------------

impl<E, EF> LookupMessage<E, EF> for AceInitMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(
            BusId::AceInit as usize,
            [
                self.clk.clone(),
                self.ctx.clone(),
                self.ptr.clone(),
                self.num_read.clone(),
                self.num_eval.clone(),
            ],
        )
    }
}

// --- RangeMsg (BusId::RangeCheck) --------------------------------------------------------

impl<E, EF> LookupMessage<E, EF> for RangeMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(BusId::RangeCheck as usize, [self.value.clone()])
    }
}

// --- LogCapacityMsg (BusId::LogPrecompileTranscript; capacity at β⁰..β³) ----------------------

impl<E, EF> LookupMessage<E, EF> for LogCapacityMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(BusId::LogPrecompileTranscript as usize, self.capacity.clone())
    }
}

// --- HasherPermLinkMsg (BusId::HasherPermLinkInput / HasherPermLinkOutput)
// -------------------------------------

impl<E, EF> LookupMessage<E, EF> for HasherPermLinkMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        let (bus, state) = match self {
            Self::Input { state } => (BusId::HasherPermLinkInput, state),
            Self::Output { state } => (BusId::HasherPermLinkOutput, state),
        };
        challenges.encode(bus as usize, state.clone())
    }
}

// --- AceWireMsg (BusId::AceWiring) -------------------------------------------------------

impl<E, EF> LookupMessage<E, EF> for AceWireMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(
            BusId::AceWiring as usize,
            [
                self.clk.clone(),
                self.ctx.clone(),
                self.id.clone(),
                self.v0.clone(),
                self.v1.clone(),
            ],
        )
    }
}

// LookupMessage impls for the response + sibling structs
// ================================================================================================
//
// The `*ResponseMsg` structs below carry `LookupMessage<E, EF>` impls consumed by
// `lookup/buses/chiplet_responses.rs`. The runtime-muxed encoding (bus prefix muxed
// by `is_read`/`is_word` flags) keeps the response-column transition at degree 8.

impl<E, EF> LookupMessage<E, EF> for MemoryResponseMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        let bp = &challenges.beta_powers;
        let is_read = self.is_read.clone();
        let is_write: E = E::ONE - is_read.clone();
        let is_word = self.is_word.clone();
        let is_element: E = E::ONE - is_word.clone();

        // Mux only the bus prefix; the payload (ctx, addr, clk, ...) is shared. Factored
        // as a read/write select per access width so the four (read/write × element/word)
        // cases stay audit-visible without blowing the polynomial degree.
        let prefix_element = challenges.bus_prefix[BusId::MemoryReadElement as usize].clone()
            * is_read.clone()
            + challenges.bus_prefix[BusId::MemoryWriteElement as usize].clone() * is_write.clone();
        let prefix_word = challenges.bus_prefix[BusId::MemoryReadWord as usize].clone() * is_read
            + challenges.bus_prefix[BusId::MemoryWriteWord as usize].clone() * is_write;
        let prefix = prefix_element * is_element.clone() + prefix_word * is_word.clone();

        let mut acc = prefix;
        acc += bp[0].clone() * self.ctx.clone();
        acc += bp[1].clone() * self.addr.clone();
        acc += bp[2].clone() * self.clk.clone();

        // Element payload (gated by is_element) vs word payload (gated by is_word).
        acc += bp[3].clone() * self.element.clone() * is_element;
        for i in 0..4 {
            acc += bp[i + 3].clone() * self.word[i].clone() * is_word.clone();
        }
        acc
    }
}

// SIBLING MESSAGES
// ================================================================================================
//
// [`SiblingMsg<E>`] carries the relevant hasher half alongside a [`SiblingBit`] tag and
// encodes against sparse β layouts (`[2, 7, 8, 9, 10]` and `[2, 3, 4, 5, 6]`) dictated by
// the responder-side hasher chiplet algebra. The trait is permissive about which β
// positions an `encode` body touches; contiguity is a convention, not a requirement.

/// Sibling-table message for the Merkle sibling bus.
///
/// The Merkle direction bit picks which half of the hasher rate block holds the sibling:
/// `bit = 0` → sibling at `h[4..8]`, payload lands in β positions `[1, 2, 7, 8, 9, 10]`
/// (mrupdate_id at β¹, node_index at β², rate1 at β⁷..β¹⁰); `bit = 1` → sibling at
/// `h[0..4]`, payload lands in β positions `[1, 2, 3, 4, 5, 6]`.
#[derive(Clone, Debug)]
pub struct SiblingMsg<E> {
    pub bit: SiblingBit,
    pub mrupdate_id: E,
    pub node_index: E,
    pub h: [E; 4],
}

/// Which half of the hasher rate block holds the sibling word for this row.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SiblingBit {
    /// `bit = 0` — sibling lives in the high rate half (`h[4..8]`).
    Zero,
    /// `bit = 1` — sibling lives in the low rate half (`h[0..4]`).
    One,
}

impl<E, EF> LookupMessage<E, EF> for SiblingMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        let bp = &challenges.beta_powers;
        let mut acc = challenges.bus_prefix[BusId::SiblingTable as usize].clone();
        acc += bp[1].clone() * self.mrupdate_id.clone();
        acc += bp[2].clone() * self.node_index.clone();
        let base = match self.bit {
            SiblingBit::Zero => 7,
            SiblingBit::One => 3,
        };
        acc += bp[base].clone() * self.h[0].clone();
        acc += bp[base + 1].clone() * self.h[1].clone();
        acc += bp[base + 2].clone() * self.h[2].clone();
        acc += bp[base + 3].clone() * self.h[3].clone();
        acc
    }
}
