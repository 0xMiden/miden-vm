//! Merkle lookup interactions across Core and Chiplets columns.
//!
//! MPVERIFY and MRUPDATE issue hasher requests and range checks on Core rows. The controller
//! supplies path inputs, sibling-table messages, compression links, and completed digests on
//! Chiplets rows. The Core index witness spans three existing columns to fit their degree bounds;
//! each column still owns its group and batch boundaries.

use core::array;

use miden_core::{chiplets::eidos_compression, field::PrimeCharacteristicRing};

use crate::{
    constraints::{
        lookup::{
            chiplet_air::{ChipletBusContext, ChipletLookupBuilder},
            main_air::{MainBusContext, MainLookupBuilder},
            messages::{
                BusId, HasherCompressionLinkMsg, HasherMsg, HasherPayload, RangeMsg, SiblingBit,
                SiblingMsg,
            },
        },
        utils::BoolNot,
    },
    lookup::{Deg, LookupBatch, LookupGroup},
    trace::chiplets::hasher::{CONTROLLER_ROWS_PER_HASHER_OP, MERKLE_DEPTH_RANGE_SCALE},
};

pub(in crate::constraints::lookup) fn emit_core_requests<LB, G>(g: &mut G, ctx: &MainBusContext<LB>)
where
    LB: MainLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let stk = &ctx.local.stack;
    let stk_next = &ctx.next.stack;
    let user_helpers = ctx.local.decoder.user_op_helpers();
    let helper0 = user_helpers[0];
    let merkle_direction_bit = user_helpers[1];
    let merkle_y3 = user_helpers[5];
    let op_flags = &ctx.op_flags;
    let cycle_len: LB::Expr = LB::Expr::from_u16(CONTROLLER_ROWS_PER_HASHER_OP as u16);
    // --- MPVERIFY ---
    {
        let cycle_len = cycle_len.clone();
        g.batch(
            "mpverify",
            op_flags.mpverify(),
            move |b| {
                let helper0: LB::Expr = helper0.into();
                let mp_index = stk.get(5).into();
                let mp_depth: LB::Expr = stk.get(4).into();
                let stk_word_0 = array::from_fn(|i| stk.get(i).into());
                let old_root = array::from_fn(|i| stk.get(6 + i).into());
                b.remove(
                    "mpverify_init",
                    HasherMsg::merkle_verify_init(
                        helper0.clone(),
                        mp_index,
                        merkle_direction_bit.into(),
                        stk_word_0,
                    ),
                    Deg { v: 5, u: 6 },
                );
                let return_addr = helper0 + mp_depth * cycle_len - LB::Expr::ONE;
                b.remove(
                    "mpverify_return",
                    HasherMsg::return_hash(return_addr, old_root),
                    Deg { v: 5, u: 6 },
                );
                b.remove(
                    "mpverify_merkle_y3",
                    RangeMsg { value: merkle_y3.into() },
                    Deg { v: 5, u: 6 },
                );
            },
            Deg { v: 7, u: 8 }, // (V, U) = (2 + 5, 3 + 5)
        );
    }

    // --- MRUPDATE ---
    {
        let cycle_len = cycle_len.clone();
        g.batch(
            "mrupdate",
            op_flags.mrupdate(),
            move |b| {
                let helper0: LB::Expr = helper0.into();
                let mr_index: LB::Expr = stk.get(5).into();
                let mr_depth: LB::Expr = stk.get(4).into();
                let stk_word_0 = array::from_fn(|i| stk.get(i).into());
                let stk_next_word_0 = array::from_fn(|i| stk_next.get(i).into());
                let old_root = array::from_fn(|i| stk.get(6 + i).into());
                let new_node = array::from_fn(|i| stk.get(10 + i).into());
                b.remove(
                    "mrupdate_old_init",
                    HasherMsg::merkle_old_init(
                        helper0.clone(),
                        mr_index.clone(),
                        merkle_direction_bit.into(),
                        stk_word_0,
                    ),
                    Deg { v: 4, u: 5 },
                );
                let old_return_addr =
                    helper0.clone() + mr_depth.clone() * cycle_len.clone() - LB::Expr::ONE;
                b.remove(
                    "mrupdate_old_return",
                    HasherMsg::return_hash(old_return_addr, old_root),
                    Deg { v: 4, u: 5 },
                );
                let new_init_addr = helper0.clone() + mr_depth.clone() * cycle_len.clone();
                b.remove(
                    "mrupdate_new_init",
                    HasherMsg::merkle_new_init(
                        new_init_addr,
                        mr_index,
                        merkle_direction_bit.into(),
                        new_node,
                    ),
                    Deg { v: 4, u: 5 },
                );
                let new_return_addr =
                    helper0 + mr_depth * (cycle_len.clone() + cycle_len) - LB::Expr::ONE;
                b.remove(
                    "mrupdate_new_return",
                    HasherMsg::return_hash(new_return_addr, stk_next_word_0),
                    Deg { v: 4, u: 5 },
                );
            },
            Deg { v: 7, u: 8 }, // (V, U) = (3 + 4, 4 + 4)
        );
    }
}

pub(in crate::constraints::lookup) fn emit_core_range_checks<LB, G>(
    g: &mut G,
    ctx: &MainBusContext<LB>,
) where
    LB: MainLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let f_mpverify = ctx.op_flags.mpverify();
    let f_mrupdate = ctx.op_flags.mrupdate();
    let merkle_depth = ctx.local.stack.get(4);
    let merkle_y3 = ctx.local.decoder.user_op_helpers()[5];
    // Two simultaneous checks enforce `1 <= depth <= MAX_MERKLE_DEPTH`. The first
    // constrains `depth` to its canonical 16-bit value. The second checks
    // `(depth - 1) * (2^16 / MAX_MERKLE_DEPTH)`, which fits in 16 bits exactly for
    // the supported positive depths. The first check is also what prevents the
    // scaled expression from wrapping through the field modulus.
    //
    // MPVERIFY and MRUPDATE are split because their opcode flags have degrees 5
    // and 4 respectively. This lets the lower-degree MRUPDATE branch carry both
    // top-limb checks while keeping the column at transition degree 9. The lower
    // three witness limbs live in the row-disjoint stack-overflow column;
    // MPVERIFY's direct y3 check shares its chiplet-request batch.
    g.batch(
        "mpverify_merkle_range_check",
        f_mpverify,
        move |b| {
            let depth: LB::Expr = merkle_depth.into();
            let scaled_depth =
                (depth.clone() - LB::Expr::ONE) * LB::Expr::from_u16(MERKLE_DEPTH_RANGE_SCALE);
            b.remove("mpverify_depth", RangeMsg { value: depth }, Deg { v: 5, u: 6 });
            b.remove("mpverify_depth_scaled", RangeMsg { value: scaled_depth }, Deg { v: 5, u: 6 });
            b.remove(
                "mpverify_merkle_y3_doubled",
                RangeMsg { value: LB::Expr::from_u16(2) * merkle_y3 },
                Deg { v: 5, u: 6 },
            );
        },
        Deg { v: 7, u: 8 }, // (V, U) = (2 + 5, 3 + 5)
    );
    g.batch(
        "mrupdate_merkle_range_check",
        f_mrupdate,
        move |b| {
            let depth: LB::Expr = merkle_depth.into();
            let scaled_depth =
                (depth.clone() - LB::Expr::ONE) * LB::Expr::from_u16(MERKLE_DEPTH_RANGE_SCALE);
            b.remove("mrupdate_depth", RangeMsg { value: depth }, Deg { v: 4, u: 5 });
            b.remove("mrupdate_depth_scaled", RangeMsg { value: scaled_depth }, Deg { v: 4, u: 5 });
            b.remove(
                "mrupdate_merkle_y3",
                RangeMsg { value: merkle_y3.into() },
                Deg { v: 4, u: 5 },
            );
            b.remove(
                "mrupdate_merkle_y3_doubled",
                RangeMsg { value: LB::Expr::from_u16(2) * merkle_y3 },
                Deg { v: 4, u: 5 },
            );
        },
        Deg { v: 7, u: 8 }, // (V, U) = (3 + 4, 4 + 4)
    );
}

pub(in crate::constraints::lookup) fn emit_core_index_limbs<LB, G>(
    g: &mut G,
    ctx: &MainBusContext<LB>,
) where
    LB: MainLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let op_flags = &ctx.op_flags;
    let helpers = ctx.local.decoder.user_op_helpers();
    // MPVERIFY and MRUPDATE preserve stack depth, so these branches cannot
    // overlap any overflow-table interaction above. The top witness limb and its
    // doubled bound are placed in other existing columns to preserve degree 9.
    g.batch(
        "mpverify_merkle_y_low",
        op_flags.mpverify(),
        |b| {
            for helper in &helpers[2..5] {
                b.remove(
                    "mpverify_merkle_y_limb",
                    RangeMsg { value: (*helper).into() },
                    Deg { v: 5, u: 6 },
                );
            }
        },
        Deg { v: 7, u: 8 }, // (V, U) = (2 + 5, 3 + 5)
    );
    g.batch(
        "mrupdate_merkle_y_low",
        op_flags.mrupdate(),
        |b| {
            for helper in &helpers[2..5] {
                b.remove(
                    "mrupdate_merkle_y_limb",
                    RangeMsg { value: (*helper).into() },
                    Deg { v: 4, u: 5 },
                );
            }
        },
        Deg { v: 6, u: 7 }, // (V, U) = (2 + 4, 3 + 4)
    );
}

pub(in crate::constraints::lookup) fn emit_chiplet_inits<LB, G>(
    g: &mut G,
    ctx: &ChipletBusContext<LB>,
) where
    LB: ChipletLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let local = ctx.local;
    let ctrl = local.controller();
    let hs0: LB::Expr = ctrl.s0.into();
    let hs1: LB::Expr = ctrl.s1.into();
    let hs2: LB::Expr = ctrl.s2.into();
    let merkle_or_padding: LB::Expr = local.controller_merkle_or_padding().into();
    // The controller skeleton makes this product zero off controller rows. Avoiding an
    // additional controller selector keeps the response gate within the degree bound.
    let merkle_gate = merkle_or_padding * hs0;
    let merkle_start: LB::Expr = ctrl.merkle_is_start().into();
    let f_mp: LB::Expr =
        merkle_gate.clone() * hs1.clone().not() * hs2.clone() * merkle_start.clone();
    let f_mv: LB::Expr =
        merkle_gate.clone() * hs1.clone() * hs2.clone().not() * merkle_start.clone();
    let f_mu: LB::Expr = merkle_gate * hs1 * hs2 * merkle_start;
    let row_addr: LB::Expr = local.chip_clk.into();
    let block_lo: [LB::Var; 4] = array::from_fn(|i| ctrl.state[i]);
    let block_hi: [LB::Var; 4] = array::from_fn(|i| ctrl.state[4 + i]);
    // Merkle leaf-word inputs for MP_VERIFY / MR_UPDATE_OLD / MR_UPDATE_NEW.
    // Each fires only on the first row of the corresponding Merkle path.
    for (name, flag, kind) in [
        ("mp_verify_input", f_mp, BusId::HasherMerkleVerifyInit),
        ("mr_update_old_input", f_mv, BusId::HasherMerkleOldInit),
        ("mr_update_new_input", f_mu, BusId::HasherMerkleNewInit),
    ] {
        g.add(
            name,
            flag,
            || {
                let addr = row_addr.clone();
                let node_index: LB::Expr = ctrl.merkle_node_index().into();
                let bit: LB::Expr = node_index.clone()
                    - Into::<LB::Expr>::into(ctrl.merkle_node_index_next()).double();
                let one_minus_bit = bit.not();
                let word: [LB::Expr; 4] = array::from_fn(|i| {
                    one_minus_bit.clone() * block_lo[i].into() + bit.clone() * block_hi[i].into()
                });
                HasherMsg {
                    kind,
                    addr,
                    node_index,
                    payload: HasherPayload::MerkleWord { direction_bit: bit, word },
                }
            },
            Deg { v: 5, u: 7 },
        );
    }
}

pub(in crate::constraints::lookup) fn emit_siblings<LB, G>(g: &mut G, ctx: &ChipletBusContext<LB>)
where
    LB: ChipletLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let local = ctx.local;
    let ctrl = local.controller();
    let hs0: LB::Expr = ctrl.s0.into();
    let hs1: LB::Expr = ctrl.s1.into();
    let hs2: LB::Expr = ctrl.s2.into();
    let controller_flag = ctx.chiplet_active.controller.clone();
    let f_mu_all: LB::Expr = controller_flag.clone() * hs0.clone() * hs1.clone() * hs2.clone();
    let f_mv_all: LB::Expr = controller_flag * hs0 * hs1 * hs2.not();
    let block_lo: [LB::Var; 4] = array::from_fn(|i| ctrl.state[i]);
    let block_hi: [LB::Var; 4] = array::from_fn(|i| ctrl.state[4 + i]);
    let mrupdate_id = local.controller_mrupdate_id();
    let node_index = ctrl.merkle_node_index();
    let node_index_next: LB::Expr = ctrl.merkle_node_index_next().into();
    let bit: LB::Expr = node_index.into() - node_index_next.double();
    let one_minus_bit: LB::Expr = bit.not();
    // MV adds (old path), MU removes (new path); each splits on the Merkle
    // direction bit into a BitZero (sibling in the high block word) and BitOne
    // (sibling in the low block word) branch. Four mutually exclusive
    // interactions total.
    for (op_name, is_add, f_all, bit_tag, bit_gate) in [
        ("sibling_mv_b0", true, f_mv_all.clone(), SiblingBit::Zero, one_minus_bit.clone()),
        ("sibling_mv_b1", true, f_mv_all, SiblingBit::One, bit.clone()),
        ("sibling_mu_b0", false, f_mu_all.clone(), SiblingBit::Zero, one_minus_bit),
        ("sibling_mu_b1", false, f_mu_all, SiblingBit::One, bit),
    ] {
        let gate = f_all * bit_gate;
        let build = move || {
            let mrupdate_id: LB::Expr = mrupdate_id.into();
            let node_index: LB::Expr = node_index.into();
            let h = match bit_tag {
                SiblingBit::Zero => array::from_fn(|i| block_hi[i].into()),
                SiblingBit::One => array::from_fn(|i| block_lo[i].into()),
            };
            SiblingMsg { bit: bit_tag, mrupdate_id, node_index, h }
        };
        if is_add {
            g.add(op_name, gate, build, Deg { v: 5, u: 6 });
        } else {
            g.remove(op_name, gate, build, Deg { v: 5, u: 6 });
        }
    }
}

pub(in crate::constraints::lookup) fn emit_compression<LB, G>(
    g: &mut G,
    ctx: &ChipletBusContext<LB>,
) where
    LB: ChipletLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let local = ctx.local;
    let ctrl = local.controller();
    let controller_flag = ctx.chiplet_active.controller.clone();
    let merkle_or_padding: LB::Expr = local.controller_merkle_or_padding().into();
    let ctrl_s0: LB::Expr = ctrl.s0.into();
    let f_merkle_compression = controller_flag * merkle_or_padding * ctrl_s0;
    let ctrl_state: [LB::Var; 12] = array::from_fn(|i| ctrl.state[i]);
    let merkle_cv = eidos_compression::merkle_node_chaining_word();
    // Merkle compression: +1 / encode(block, fixed_cv, cv_out).
    g.add(
        "merkle_compression",
        f_merkle_compression,
        move || {
            let block = array::from_fn(|i| ctrl_state[i].into());
            let cv_in = array::from_fn(|i| LB::Expr::from(merkle_cv[i]));
            let cv_out = array::from_fn(|i| ctrl_state[8 + i].into());
            HasherCompressionLinkMsg { block, cv_in, cv_out }
        },
        Deg { v: 5, u: 6 },
    );
}

pub(in crate::constraints::lookup) fn emit_return<LB, G>(g: &mut G, ctx: &ChipletBusContext<LB>)
where
    LB: ChipletLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let local = ctx.local;
    let ctrl = local.controller();
    let merkle_or_padding: LB::Expr = local.controller_merkle_or_padding().into();
    let ctrl_s0: LB::Expr = ctrl.s0.into();
    let op_final: LB::Expr = local.controller_op_final().into();
    // The controller skeleton makes this product zero off controller rows.
    let merkle_return = merkle_or_padding * ctrl_s0 * op_final;
    let addr: LB::Expr = local.chip_clk.into();
    let merkle_digest = ctrl.merkle_digest();
    g.add(
        "merkle_return",
        merkle_return,
        || HasherMsg::return_hash(addr.clone(), merkle_digest.map(LB::Expr::from)),
        Deg { v: 3, u: 4 },
    );
}
