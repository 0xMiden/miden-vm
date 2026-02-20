//! Test fixtures for constraint tagging.

use alloc::vec::Vec;

use miden_core::{Felt, field::QuadFelt};

use super::ood_eval::EvalRecord;

/// Seed used for OOD evaluation fixtures.
pub const OOD_SEED: u64 = 0xc0ffee;

/// Expected OOD evaluations for the current group.
///
/// These values are captured from the Rust constraints with seed 0xC0FFEE.
pub fn current_group_expected() -> Vec<EvalRecord> {
    vec![
        EvalRecord {
            id: 0,
            namespace: "system.clk.first_row",
            value: QuadFelt::new([Felt::new(1065013626484053923), Felt::new(0)]),
        },
        EvalRecord {
            id: 1,
            namespace: "system.clk.transition",
            value: QuadFelt::new([Felt::new(5561241394822338942), Felt::new(0)]),
        },
        EvalRecord {
            id: 2,
            namespace: "system.ctx.call_dyncall",
            value: QuadFelt::new([Felt::new(8631524473419082362), Felt::new(0)]),
        },
        EvalRecord {
            id: 3,
            namespace: "system.ctx.syscall",
            value: QuadFelt::new([Felt::new(3242942367983627164), Felt::new(0)]),
        },
        EvalRecord {
            id: 4,
            namespace: "system.ctx.default",
            value: QuadFelt::new([Felt::new(2699910395066589652), Felt::new(0)]),
        },
        EvalRecord {
            id: 5,
            namespace: "system.fn_hash.load",
            value: QuadFelt::new([Felt::new(5171717963692258605), Felt::new(0)]),
        },
        EvalRecord {
            id: 6,
            namespace: "system.fn_hash.load",
            value: QuadFelt::new([Felt::new(8961147296413400172), Felt::new(0)]),
        },
        EvalRecord {
            id: 7,
            namespace: "system.fn_hash.load",
            value: QuadFelt::new([Felt::new(11894020196642675053), Felt::new(0)]),
        },
        EvalRecord {
            id: 8,
            namespace: "system.fn_hash.load",
            value: QuadFelt::new([Felt::new(16889079421217525114), Felt::new(0)]),
        },
        EvalRecord {
            id: 9,
            namespace: "system.fn_hash.preserve",
            value: QuadFelt::new([Felt::new(11909329801663906014), Felt::new(0)]),
        },
        EvalRecord {
            id: 10,
            namespace: "system.fn_hash.preserve",
            value: QuadFelt::new([Felt::new(6717961555159342431), Felt::new(0)]),
        },
        EvalRecord {
            id: 11,
            namespace: "system.fn_hash.preserve",
            value: QuadFelt::new([Felt::new(3950851291570048124), Felt::new(0)]),
        },
        EvalRecord {
            id: 12,
            namespace: "system.fn_hash.preserve",
            value: QuadFelt::new([Felt::new(11146653144264413142), Felt::new(0)]),
        },
        EvalRecord {
            id: 13,
            namespace: "range.main.v.first_row",
            value: QuadFelt::new([Felt::new(1112338059331632069), Felt::new(0)]),
        },
        EvalRecord {
            id: 14,
            namespace: "range.main.v.last_row",
            value: QuadFelt::new([Felt::new(13352757668188868927), Felt::new(0)]),
        },
        EvalRecord {
            id: 15,
            namespace: "range.main.v.transition",
            value: QuadFelt::new([Felt::new(12797082443503681195), Felt::new(0)]),
        },
        EvalRecord {
            id: 16,
            namespace: "stack.general.transition.0",
            value: QuadFelt::new([Felt::new(2617308096902219240), Felt::new(0)]),
        },
        EvalRecord {
            id: 17,
            namespace: "stack.general.transition.1",
            value: QuadFelt::new([Felt::new(4439102810547612775), Felt::new(0)]),
        },
        EvalRecord {
            id: 18,
            namespace: "stack.general.transition.2",
            value: QuadFelt::new([Felt::new(15221140463513662734), Felt::new(0)]),
        },
        EvalRecord {
            id: 19,
            namespace: "stack.general.transition.3",
            value: QuadFelt::new([Felt::new(4910128267170087966), Felt::new(0)]),
        },
        EvalRecord {
            id: 20,
            namespace: "stack.general.transition.4",
            value: QuadFelt::new([Felt::new(8221884229886405628), Felt::new(0)]),
        },
        EvalRecord {
            id: 21,
            namespace: "stack.general.transition.5",
            value: QuadFelt::new([Felt::new(87491100192562680), Felt::new(0)]),
        },
        EvalRecord {
            id: 22,
            namespace: "stack.general.transition.6",
            value: QuadFelt::new([Felt::new(11411892308848385202), Felt::new(0)]),
        },
        EvalRecord {
            id: 23,
            namespace: "stack.general.transition.7",
            value: QuadFelt::new([Felt::new(2425094460891103256), Felt::new(0)]),
        },
        EvalRecord {
            id: 24,
            namespace: "stack.general.transition.8",
            value: QuadFelt::new([Felt::new(2767534397043537043), Felt::new(0)]),
        },
        EvalRecord {
            id: 25,
            namespace: "stack.general.transition.9",
            value: QuadFelt::new([Felt::new(11686523590994044007), Felt::new(0)]),
        },
        EvalRecord {
            id: 26,
            namespace: "stack.general.transition.10",
            value: QuadFelt::new([Felt::new(15000969044032170777), Felt::new(0)]),
        },
        EvalRecord {
            id: 27,
            namespace: "stack.general.transition.11",
            value: QuadFelt::new([Felt::new(17422355615541008592), Felt::new(0)]),
        },
        EvalRecord {
            id: 28,
            namespace: "stack.general.transition.12",
            value: QuadFelt::new([Felt::new(2555448945580115158), Felt::new(0)]),
        },
        EvalRecord {
            id: 29,
            namespace: "stack.general.transition.13",
            value: QuadFelt::new([Felt::new(8864896307613509), Felt::new(0)]),
        },
        EvalRecord {
            id: 30,
            namespace: "stack.general.transition.14",
            value: QuadFelt::new([Felt::new(3997062422665481459), Felt::new(0)]),
        },
        EvalRecord {
            id: 31,
            namespace: "stack.general.transition.15",
            value: QuadFelt::new([Felt::new(6149720027324442163), Felt::new(0)]),
        },
        EvalRecord {
            id: 32,
            namespace: "stack.overflow.depth.first_row",
            value: QuadFelt::new([Felt::new(1820735510664294085), Felt::new(0)]),
        },
        EvalRecord {
            id: 33,
            namespace: "stack.overflow.depth.last_row",
            value: QuadFelt::new([Felt::new(12520055704510454391), Felt::new(0)]),
        },
        EvalRecord {
            id: 34,
            namespace: "stack.overflow.addr.first_row",
            value: QuadFelt::new([Felt::new(9235172344178625178), Felt::new(0)]),
        },
        EvalRecord {
            id: 35,
            namespace: "stack.overflow.addr.last_row",
            value: QuadFelt::new([Felt::new(6001883085148683205), Felt::new(0)]),
        },
        EvalRecord {
            id: 36,
            namespace: "stack.overflow.depth.transition",
            value: QuadFelt::new([Felt::new(6706883717633639596), Felt::new(0)]),
        },
        EvalRecord {
            id: 37,
            namespace: "stack.overflow.flag.transition",
            value: QuadFelt::new([Felt::new(5309566436521762910), Felt::new(0)]),
        },
        EvalRecord {
            id: 38,
            namespace: "stack.overflow.addr.transition",
            value: QuadFelt::new([Felt::new(13739720401332236216), Felt::new(0)]),
        },
        EvalRecord {
            id: 39,
            namespace: "stack.overflow.zero_insert.transition",
            value: QuadFelt::new([Felt::new(15830245309845547857), Felt::new(0)]),
        },
        EvalRecord {
            id: 40,
            namespace: "stack.ops.pad",
            value: QuadFelt::new([Felt::new(13331629930659656176), Felt::new(0)]),
        },
        EvalRecord {
            id: 41,
            namespace: "stack.ops.dup",
            value: QuadFelt::new([Felt::new(756650319667756050), Felt::new(0)]),
        },
        EvalRecord {
            id: 42,
            namespace: "stack.ops.dup1",
            value: QuadFelt::new([Felt::new(8866275161884692697), Felt::new(0)]),
        },
        EvalRecord {
            id: 43,
            namespace: "stack.ops.dup2",
            value: QuadFelt::new([Felt::new(3836534398031583164), Felt::new(0)]),
        },
        EvalRecord {
            id: 44,
            namespace: "stack.ops.dup3",
            value: QuadFelt::new([Felt::new(14027345575708861734), Felt::new(0)]),
        },
        EvalRecord {
            id: 45,
            namespace: "stack.ops.dup4",
            value: QuadFelt::new([Felt::new(6758311777121484896), Felt::new(0)]),
        },
        EvalRecord {
            id: 46,
            namespace: "stack.ops.dup5",
            value: QuadFelt::new([Felt::new(3070735592903657788), Felt::new(0)]),
        },
        EvalRecord {
            id: 47,
            namespace: "stack.ops.dup6",
            value: QuadFelt::new([Felt::new(7754656097784875208), Felt::new(0)]),
        },
        EvalRecord {
            id: 48,
            namespace: "stack.ops.dup7",
            value: QuadFelt::new([Felt::new(6720121361576140513), Felt::new(0)]),
        },
        EvalRecord {
            id: 49,
            namespace: "stack.ops.dup9",
            value: QuadFelt::new([Felt::new(17539764796672551158), Felt::new(0)]),
        },
        EvalRecord {
            id: 50,
            namespace: "stack.ops.dup11",
            value: QuadFelt::new([Felt::new(10804911883091000860), Felt::new(0)]),
        },
        EvalRecord {
            id: 51,
            namespace: "stack.ops.dup13",
            value: QuadFelt::new([Felt::new(9611708950007293491), Felt::new(0)]),
        },
        EvalRecord {
            id: 52,
            namespace: "stack.ops.dup15",
            value: QuadFelt::new([Felt::new(8853070398648442411), Felt::new(0)]),
        },
        EvalRecord {
            id: 53,
            namespace: "stack.ops.clk",
            value: QuadFelt::new([Felt::new(9109734313690111543), Felt::new(0)]),
        },
        EvalRecord {
            id: 54,
            namespace: "stack.ops.swap",
            value: QuadFelt::new([Felt::new(3018402783504114630), Felt::new(0)]),
        },
        EvalRecord {
            id: 55,
            namespace: "stack.ops.swap",
            value: QuadFelt::new([Felt::new(17272825861332302734), Felt::new(0)]),
        },
        EvalRecord {
            id: 56,
            namespace: "stack.ops.movup2",
            value: QuadFelt::new([Felt::new(6365383181668196029), Felt::new(0)]),
        },
        EvalRecord {
            id: 57,
            namespace: "stack.ops.movup3",
            value: QuadFelt::new([Felt::new(11479712264864576587), Felt::new(0)]),
        },
        EvalRecord {
            id: 58,
            namespace: "stack.ops.movup4",
            value: QuadFelt::new([Felt::new(12050324136647260589), Felt::new(0)]),
        },
        EvalRecord {
            id: 59,
            namespace: "stack.ops.movup5",
            value: QuadFelt::new([Felt::new(4842889514271599822), Felt::new(0)]),
        },
        EvalRecord {
            id: 60,
            namespace: "stack.ops.movup6",
            value: QuadFelt::new([Felt::new(7388624400246275858), Felt::new(0)]),
        },
        EvalRecord {
            id: 61,
            namespace: "stack.ops.movup7",
            value: QuadFelt::new([Felt::new(10382124953564405655), Felt::new(0)]),
        },
        EvalRecord {
            id: 62,
            namespace: "stack.ops.movup8",
            value: QuadFelt::new([Felt::new(14668661130070444298), Felt::new(0)]),
        },
        EvalRecord {
            id: 63,
            namespace: "stack.ops.movdn2",
            value: QuadFelt::new([Felt::new(7617911967740804399), Felt::new(0)]),
        },
        EvalRecord {
            id: 64,
            namespace: "stack.ops.movdn3",
            value: QuadFelt::new([Felt::new(10587498815844952065), Felt::new(0)]),
        },
        EvalRecord {
            id: 65,
            namespace: "stack.ops.movdn4",
            value: QuadFelt::new([Felt::new(6234074065813353677), Felt::new(0)]),
        },
        EvalRecord {
            id: 66,
            namespace: "stack.ops.movdn5",
            value: QuadFelt::new([Felt::new(8228745571736556881), Felt::new(0)]),
        },
        EvalRecord {
            id: 67,
            namespace: "stack.ops.movdn6",
            value: QuadFelt::new([Felt::new(1255130201489737978), Felt::new(0)]),
        },
        EvalRecord {
            id: 68,
            namespace: "stack.ops.movdn7",
            value: QuadFelt::new([Felt::new(4861541115171604729), Felt::new(0)]),
        },
        EvalRecord {
            id: 69,
            namespace: "stack.ops.movdn8",
            value: QuadFelt::new([Felt::new(7218300239612772413), Felt::new(0)]),
        },
        EvalRecord {
            id: 70,
            namespace: "stack.ops.swapw",
            value: QuadFelt::new([Felt::new(1397391365707566947), Felt::new(0)]),
        },
        EvalRecord {
            id: 71,
            namespace: "stack.ops.swapw",
            value: QuadFelt::new([Felt::new(15192275354424729852), Felt::new(0)]),
        },
        EvalRecord {
            id: 72,
            namespace: "stack.ops.swapw",
            value: QuadFelt::new([Felt::new(8991791753517007572), Felt::new(0)]),
        },
        EvalRecord {
            id: 73,
            namespace: "stack.ops.swapw",
            value: QuadFelt::new([Felt::new(6845904526592099338), Felt::new(0)]),
        },
        EvalRecord {
            id: 74,
            namespace: "stack.ops.swapw",
            value: QuadFelt::new([Felt::new(14405008868848810993), Felt::new(0)]),
        },
        EvalRecord {
            id: 75,
            namespace: "stack.ops.swapw",
            value: QuadFelt::new([Felt::new(14818059880037013402), Felt::new(0)]),
        },
        EvalRecord {
            id: 76,
            namespace: "stack.ops.swapw",
            value: QuadFelt::new([Felt::new(12858781526955010288), Felt::new(0)]),
        },
        EvalRecord {
            id: 77,
            namespace: "stack.ops.swapw",
            value: QuadFelt::new([Felt::new(4346525868099676574), Felt::new(0)]),
        },
        EvalRecord {
            id: 78,
            namespace: "stack.ops.swapw2",
            value: QuadFelt::new([Felt::new(12020803221700843056), Felt::new(0)]),
        },
        EvalRecord {
            id: 79,
            namespace: "stack.ops.swapw2",
            value: QuadFelt::new([Felt::new(5905514554571101818), Felt::new(0)]),
        },
        EvalRecord {
            id: 80,
            namespace: "stack.ops.swapw2",
            value: QuadFelt::new([Felt::new(13967530246007855218), Felt::new(0)]),
        },
        EvalRecord {
            id: 81,
            namespace: "stack.ops.swapw2",
            value: QuadFelt::new([Felt::new(1745280905200466463), Felt::new(0)]),
        },
        EvalRecord {
            id: 82,
            namespace: "stack.ops.swapw2",
            value: QuadFelt::new([Felt::new(8273384627661819419), Felt::new(0)]),
        },
        EvalRecord {
            id: 83,
            namespace: "stack.ops.swapw2",
            value: QuadFelt::new([Felt::new(17907212562142949954), Felt::new(0)]),
        },
        EvalRecord {
            id: 84,
            namespace: "stack.ops.swapw2",
            value: QuadFelt::new([Felt::new(10641837676859047674), Felt::new(0)]),
        },
        EvalRecord {
            id: 85,
            namespace: "stack.ops.swapw2",
            value: QuadFelt::new([Felt::new(5696399439164028901), Felt::new(0)]),
        },
        EvalRecord {
            id: 86,
            namespace: "stack.ops.swapw3",
            value: QuadFelt::new([Felt::new(261758456050090541), Felt::new(0)]),
        },
        EvalRecord {
            id: 87,
            namespace: "stack.ops.swapw3",
            value: QuadFelt::new([Felt::new(13783565204182644984), Felt::new(0)]),
        },
        EvalRecord {
            id: 88,
            namespace: "stack.ops.swapw3",
            value: QuadFelt::new([Felt::new(8373199292442046895), Felt::new(0)]),
        },
        EvalRecord {
            id: 89,
            namespace: "stack.ops.swapw3",
            value: QuadFelt::new([Felt::new(17987956356814792948), Felt::new(0)]),
        },
        EvalRecord {
            id: 90,
            namespace: "stack.ops.swapw3",
            value: QuadFelt::new([Felt::new(15863165148623313437), Felt::new(0)]),
        },
        EvalRecord {
            id: 91,
            namespace: "stack.ops.swapw3",
            value: QuadFelt::new([Felt::new(15873554387396407564), Felt::new(0)]),
        },
        EvalRecord {
            id: 92,
            namespace: "stack.ops.swapw3",
            value: QuadFelt::new([Felt::new(13572800254923888612), Felt::new(0)]),
        },
        EvalRecord {
            id: 93,
            namespace: "stack.ops.swapw3",
            value: QuadFelt::new([Felt::new(37494485778659889), Felt::new(0)]),
        },
        EvalRecord {
            id: 94,
            namespace: "stack.ops.swapdw",
            value: QuadFelt::new([Felt::new(5468305410596890575), Felt::new(0)]),
        },
        EvalRecord {
            id: 95,
            namespace: "stack.ops.swapdw",
            value: QuadFelt::new([Felt::new(8148573700621797018), Felt::new(0)]),
        },
        EvalRecord {
            id: 96,
            namespace: "stack.ops.swapdw",
            value: QuadFelt::new([Felt::new(174223531403505930), Felt::new(0)]),
        },
        EvalRecord {
            id: 97,
            namespace: "stack.ops.swapdw",
            value: QuadFelt::new([Felt::new(7472429897136677074), Felt::new(0)]),
        },
        EvalRecord {
            id: 98,
            namespace: "stack.ops.swapdw",
            value: QuadFelt::new([Felt::new(9085995615849733227), Felt::new(0)]),
        },
        EvalRecord {
            id: 99,
            namespace: "stack.ops.swapdw",
            value: QuadFelt::new([Felt::new(17751305329307070351), Felt::new(0)]),
        },
        EvalRecord {
            id: 100,
            namespace: "stack.ops.swapdw",
            value: QuadFelt::new([Felt::new(12464875440922891257), Felt::new(0)]),
        },
        EvalRecord {
            id: 101,
            namespace: "stack.ops.swapdw",
            value: QuadFelt::new([Felt::new(7381981033510767101), Felt::new(0)]),
        },
        EvalRecord {
            id: 102,
            namespace: "stack.ops.swapdw",
            value: QuadFelt::new([Felt::new(14206386269299463916), Felt::new(0)]),
        },
        EvalRecord {
            id: 103,
            namespace: "stack.ops.swapdw",
            value: QuadFelt::new([Felt::new(5165712881513112310), Felt::new(0)]),
        },
        EvalRecord {
            id: 104,
            namespace: "stack.ops.swapdw",
            value: QuadFelt::new([Felt::new(9505024677507267655), Felt::new(0)]),
        },
        EvalRecord {
            id: 105,
            namespace: "stack.ops.swapdw",
            value: QuadFelt::new([Felt::new(7199235098885318815), Felt::new(0)]),
        },
        EvalRecord {
            id: 106,
            namespace: "stack.ops.swapdw",
            value: QuadFelt::new([Felt::new(14863071265127885763), Felt::new(0)]),
        },
        EvalRecord {
            id: 107,
            namespace: "stack.ops.swapdw",
            value: QuadFelt::new([Felt::new(7964997496183729586), Felt::new(0)]),
        },
        EvalRecord {
            id: 108,
            namespace: "stack.ops.swapdw",
            value: QuadFelt::new([Felt::new(17447611484236572336), Felt::new(0)]),
        },
        EvalRecord {
            id: 109,
            namespace: "stack.ops.swapdw",
            value: QuadFelt::new([Felt::new(7663698430658282360), Felt::new(0)]),
        },
        EvalRecord {
            id: 110,
            namespace: "stack.ops.cswap",
            value: QuadFelt::new([Felt::new(7787471015064615045), Felt::new(0)]),
        },
        EvalRecord {
            id: 111,
            namespace: "stack.ops.cswap",
            value: QuadFelt::new([Felt::new(18107469477286194402), Felt::new(0)]),
        },
        EvalRecord {
            id: 112,
            namespace: "stack.ops.cswap",
            value: QuadFelt::new([Felt::new(8228755909294702214), Felt::new(0)]),
        },
        EvalRecord {
            id: 113,
            namespace: "stack.ops.cswapw",
            value: QuadFelt::new([Felt::new(4517595434872149482), Felt::new(0)]),
        },
        EvalRecord {
            id: 114,
            namespace: "stack.ops.cswapw",
            value: QuadFelt::new([Felt::new(7382517392819628451), Felt::new(0)]),
        },
        EvalRecord {
            id: 115,
            namespace: "stack.ops.cswapw",
            value: QuadFelt::new([Felt::new(4827417633003237585), Felt::new(0)]),
        },
        EvalRecord {
            id: 116,
            namespace: "stack.ops.cswapw",
            value: QuadFelt::new([Felt::new(17779390882653606052), Felt::new(0)]),
        },
        EvalRecord {
            id: 117,
            namespace: "stack.ops.cswapw",
            value: QuadFelt::new([Felt::new(16587491652407655425), Felt::new(0)]),
        },
        EvalRecord {
            id: 118,
            namespace: "stack.ops.cswapw",
            value: QuadFelt::new([Felt::new(6936098212561125534), Felt::new(0)]),
        },
        EvalRecord {
            id: 119,
            namespace: "stack.ops.cswapw",
            value: QuadFelt::new([Felt::new(5094958697700743127), Felt::new(0)]),
        },
        EvalRecord {
            id: 120,
            namespace: "stack.ops.cswapw",
            value: QuadFelt::new([Felt::new(189412762651021203), Felt::new(0)]),
        },
        EvalRecord {
            id: 121,
            namespace: "stack.ops.cswapw",
            value: QuadFelt::new([Felt::new(8308993958309806023), Felt::new(0)]),
        },
        EvalRecord {
            id: 122,
            namespace: "stack.system.assert",
            value: QuadFelt::new([Felt::new(8348363779099446030), Felt::new(0)]),
        },
        EvalRecord {
            id: 123,
            namespace: "stack.system.caller",
            value: QuadFelt::new([Felt::new(16674981897661760210), Felt::new(0)]),
        },
        EvalRecord {
            id: 124,
            namespace: "stack.system.caller",
            value: QuadFelt::new([Felt::new(14361028107722480662), Felt::new(0)]),
        },
        EvalRecord {
            id: 125,
            namespace: "stack.system.caller",
            value: QuadFelt::new([Felt::new(9738252875195915138), Felt::new(0)]),
        },
        EvalRecord {
            id: 126,
            namespace: "stack.system.caller",
            value: QuadFelt::new([Felt::new(15161342143096572193), Felt::new(0)]),
        },
        EvalRecord {
            id: 127,
            namespace: "stack.io.sdepth",
            value: QuadFelt::new([Felt::new(9690568048381717864), Felt::new(0)]),
        },
        EvalRecord {
            id: 128,
            namespace: "stack.crypto.cryptostream",
            value: QuadFelt::new([Felt::new(12685385640397555155), Felt::new(0)]),
        },
        EvalRecord {
            id: 129,
            namespace: "stack.crypto.cryptostream",
            value: QuadFelt::new([Felt::new(17365149299857381549), Felt::new(0)]),
        },
        EvalRecord {
            id: 130,
            namespace: "stack.crypto.cryptostream",
            value: QuadFelt::new([Felt::new(7455833729327549495), Felt::new(0)]),
        },
        EvalRecord {
            id: 131,
            namespace: "stack.crypto.cryptostream",
            value: QuadFelt::new([Felt::new(15687115573708323478), Felt::new(0)]),
        },
        EvalRecord {
            id: 132,
            namespace: "stack.crypto.cryptostream",
            value: QuadFelt::new([Felt::new(7143356749732107964), Felt::new(0)]),
        },
        EvalRecord {
            id: 133,
            namespace: "stack.crypto.cryptostream",
            value: QuadFelt::new([Felt::new(16804762938330714938), Felt::new(0)]),
        },
        EvalRecord {
            id: 134,
            namespace: "stack.crypto.cryptostream",
            value: QuadFelt::new([Felt::new(11562801811268566657), Felt::new(0)]),
        },
        EvalRecord {
            id: 135,
            namespace: "stack.crypto.cryptostream",
            value: QuadFelt::new([Felt::new(6374246579471617400), Felt::new(0)]),
        },
        EvalRecord {
            id: 136,
            namespace: "stack.crypto.hornerbase",
            value: QuadFelt::new([Felt::new(6682735393816016083), Felt::new(0)]),
        },
        EvalRecord {
            id: 137,
            namespace: "stack.crypto.hornerbase",
            value: QuadFelt::new([Felt::new(15946014808270501272), Felt::new(0)]),
        },
        EvalRecord {
            id: 138,
            namespace: "stack.crypto.hornerbase",
            value: QuadFelt::new([Felt::new(15603944589931385962), Felt::new(0)]),
        },
        EvalRecord {
            id: 139,
            namespace: "stack.crypto.hornerbase",
            value: QuadFelt::new([Felt::new(9275882712531701258), Felt::new(0)]),
        },
        EvalRecord {
            id: 140,
            namespace: "stack.crypto.hornerbase",
            value: QuadFelt::new([Felt::new(2477075229563534723), Felt::new(0)]),
        },
        EvalRecord {
            id: 141,
            namespace: "stack.crypto.hornerbase",
            value: QuadFelt::new([Felt::new(5290505604769958968), Felt::new(0)]),
        },
        EvalRecord {
            id: 142,
            namespace: "stack.crypto.hornerbase",
            value: QuadFelt::new([Felt::new(2851265439044985455), Felt::new(0)]),
        },
        EvalRecord {
            id: 143,
            namespace: "stack.crypto.hornerbase",
            value: QuadFelt::new([Felt::new(18383212236849004064), Felt::new(0)]),
        },
        EvalRecord {
            id: 144,
            namespace: "stack.crypto.hornerbase",
            value: QuadFelt::new([Felt::new(1727422736811819477), Felt::new(0)]),
        },
        EvalRecord {
            id: 145,
            namespace: "stack.crypto.hornerbase",
            value: QuadFelt::new([Felt::new(8661298711862814846), Felt::new(0)]),
        },
        EvalRecord {
            id: 146,
            namespace: "stack.crypto.hornerbase",
            value: QuadFelt::new([Felt::new(4909615103768362856), Felt::new(0)]),
        },
        EvalRecord {
            id: 147,
            namespace: "stack.crypto.hornerbase",
            value: QuadFelt::new([Felt::new(6313538606129191078), Felt::new(0)]),
        },
        EvalRecord {
            id: 148,
            namespace: "stack.crypto.hornerbase",
            value: QuadFelt::new([Felt::new(16477933543947236322), Felt::new(0)]),
        },
        EvalRecord {
            id: 149,
            namespace: "stack.crypto.hornerbase",
            value: QuadFelt::new([Felt::new(8923348207341089911), Felt::new(0)]),
        },
        EvalRecord {
            id: 150,
            namespace: "stack.crypto.hornerbase",
            value: QuadFelt::new([Felt::new(8415559196869506674), Felt::new(0)]),
        },
        EvalRecord {
            id: 151,
            namespace: "stack.crypto.hornerbase",
            value: QuadFelt::new([Felt::new(12374820114184953398), Felt::new(0)]),
        },
        EvalRecord {
            id: 152,
            namespace: "stack.crypto.hornerbase",
            value: QuadFelt::new([Felt::new(2975290982061044481), Felt::new(0)]),
        },
        EvalRecord {
            id: 153,
            namespace: "stack.crypto.hornerbase",
            value: QuadFelt::new([Felt::new(13487726821146861348), Felt::new(0)]),
        },
        EvalRecord {
            id: 154,
            namespace: "stack.crypto.hornerbase",
            value: QuadFelt::new([Felt::new(9982904041042376807), Felt::new(0)]),
        },
        EvalRecord {
            id: 155,
            namespace: "stack.crypto.hornerbase",
            value: QuadFelt::new([Felt::new(5949627607219451329), Felt::new(0)]),
        },
        EvalRecord {
            id: 156,
            namespace: "stack.crypto.hornerext",
            value: QuadFelt::new([Felt::new(4258650708569289369), Felt::new(0)]),
        },
        EvalRecord {
            id: 157,
            namespace: "stack.crypto.hornerext",
            value: QuadFelt::new([Felt::new(10623987720748853996), Felt::new(0)]),
        },
        EvalRecord {
            id: 158,
            namespace: "stack.crypto.hornerext",
            value: QuadFelt::new([Felt::new(7214338718283715042), Felt::new(0)]),
        },
        EvalRecord {
            id: 159,
            namespace: "stack.crypto.hornerext",
            value: QuadFelt::new([Felt::new(11353293984106841353), Felt::new(0)]),
        },
        EvalRecord {
            id: 160,
            namespace: "stack.crypto.hornerext",
            value: QuadFelt::new([Felt::new(13021994910061529075), Felt::new(0)]),
        },
        EvalRecord {
            id: 161,
            namespace: "stack.crypto.hornerext",
            value: QuadFelt::new([Felt::new(16890098475354732519), Felt::new(0)]),
        },
        EvalRecord {
            id: 162,
            namespace: "stack.crypto.hornerext",
            value: QuadFelt::new([Felt::new(17909680271515252883), Felt::new(0)]),
        },
        EvalRecord {
            id: 163,
            namespace: "stack.crypto.hornerext",
            value: QuadFelt::new([Felt::new(17436574006020893038), Felt::new(0)]),
        },
        EvalRecord {
            id: 164,
            namespace: "stack.crypto.hornerext",
            value: QuadFelt::new([Felt::new(11510839286135128168), Felt::new(0)]),
        },
        EvalRecord {
            id: 165,
            namespace: "stack.crypto.hornerext",
            value: QuadFelt::new([Felt::new(5781748113887851533), Felt::new(0)]),
        },
        EvalRecord {
            id: 166,
            namespace: "stack.crypto.hornerext",
            value: QuadFelt::new([Felt::new(14599010851776253883), Felt::new(0)]),
        },
        EvalRecord {
            id: 167,
            namespace: "stack.crypto.hornerext",
            value: QuadFelt::new([Felt::new(9495625123030210045), Felt::new(0)]),
        },
        EvalRecord {
            id: 168,
            namespace: "stack.crypto.hornerext",
            value: QuadFelt::new([Felt::new(7672904073310511358), Felt::new(0)]),
        },
        EvalRecord {
            id: 169,
            namespace: "stack.crypto.hornerext",
            value: QuadFelt::new([Felt::new(775511618954631186), Felt::new(0)]),
        },
        EvalRecord {
            id: 170,
            namespace: "stack.crypto.hornerext",
            value: QuadFelt::new([Felt::new(1082901338727409004), Felt::new(0)]),
        },
        EvalRecord {
            id: 171,
            namespace: "stack.crypto.hornerext",
            value: QuadFelt::new([Felt::new(13302599741550075590), Felt::new(0)]),
        },
        EvalRecord {
            id: 172,
            namespace: "stack.crypto.hornerext",
            value: QuadFelt::new([Felt::new(4231043957658294146), Felt::new(0)]),
        },
        EvalRecord {
            id: 173,
            namespace: "stack.crypto.hornerext",
            value: QuadFelt::new([Felt::new(16476104241930761470), Felt::new(0)]),
        },
        EvalRecord {
            id: 174,
            namespace: "decoder.in_span.first_row",
            value: QuadFelt::new([Felt::new(14927496178105230921), Felt::new(0)]),
        },
        EvalRecord {
            id: 175,
            namespace: "decoder.in_span.binary",
            value: QuadFelt::new([Felt::new(14486244054610710736), Felt::new(0)]),
        },
        EvalRecord {
            id: 176,
            namespace: "decoder.in_span.span",
            value: QuadFelt::new([Felt::new(466300909996410452), Felt::new(0)]),
        },
        EvalRecord {
            id: 177,
            namespace: "decoder.in_span.respan",
            value: QuadFelt::new([Felt::new(3338971954421326066), Felt::new(0)]),
        },
        EvalRecord {
            id: 178,
            namespace: "decoder.op_bits.b0.binary",
            value: QuadFelt::new([Felt::new(13628791071868321124), Felt::new(0)]),
        },
        EvalRecord {
            id: 179,
            namespace: "decoder.op_bits.b1.binary",
            value: QuadFelt::new([Felt::new(2117480814916000258), Felt::new(0)]),
        },
        EvalRecord {
            id: 180,
            namespace: "decoder.op_bits.b2.binary",
            value: QuadFelt::new([Felt::new(16926933246570374887), Felt::new(0)]),
        },
        EvalRecord {
            id: 181,
            namespace: "decoder.op_bits.b3.binary",
            value: QuadFelt::new([Felt::new(9176310969543325496), Felt::new(0)]),
        },
        EvalRecord {
            id: 182,
            namespace: "decoder.op_bits.b4.binary",
            value: QuadFelt::new([Felt::new(7537316481676351991), Felt::new(0)]),
        },
        EvalRecord {
            id: 183,
            namespace: "decoder.op_bits.b5.binary",
            value: QuadFelt::new([Felt::new(2144456409708417452), Felt::new(0)]),
        },
        EvalRecord {
            id: 184,
            namespace: "decoder.op_bits.b6.binary",
            value: QuadFelt::new([Felt::new(4533994350960751386), Felt::new(0)]),
        },
        EvalRecord {
            id: 185,
            namespace: "decoder.extra.e0",
            value: QuadFelt::new([Felt::new(8133745730975361882), Felt::new(0)]),
        },
        EvalRecord {
            id: 186,
            namespace: "decoder.extra.e1",
            value: QuadFelt::new([Felt::new(1382945310839592478), Felt::new(0)]),
        },
        EvalRecord {
            id: 187,
            namespace: "decoder.op_bits.u32_prefix.b0",
            value: QuadFelt::new([Felt::new(3295186688501169293), Felt::new(0)]),
        },
        EvalRecord {
            id: 188,
            namespace: "decoder.op_bits.very_high.b0",
            value: QuadFelt::new([Felt::new(1492924210658182178), Felt::new(0)]),
        },
        EvalRecord {
            id: 189,
            namespace: "decoder.op_bits.very_high.b1",
            value: QuadFelt::new([Felt::new(11514104647859742926), Felt::new(0)]),
        },
        EvalRecord {
            id: 190,
            namespace: "decoder.batch_flags.c0.binary",
            value: QuadFelt::new([Felt::new(5362129305222679805), Felt::new(0)]),
        },
        EvalRecord {
            id: 191,
            namespace: "decoder.batch_flags.c1.binary",
            value: QuadFelt::new([Felt::new(7857195453682114326), Felt::new(0)]),
        },
        EvalRecord {
            id: 192,
            namespace: "decoder.batch_flags.c2.binary",
            value: QuadFelt::new([Felt::new(7691051559149421836), Felt::new(0)]),
        },
        EvalRecord {
            id: 193,
            namespace: "decoder.general.split_loop.s0.binary",
            value: QuadFelt::new([Felt::new(14496120396244092127), Felt::new(0)]),
        },
        EvalRecord {
            id: 194,
            namespace: "decoder.general.dyn.h4.zero",
            value: QuadFelt::new([Felt::new(1277805081675897337), Felt::new(0)]),
        },
        EvalRecord {
            id: 195,
            namespace: "decoder.general.dyn.h5.zero",
            value: QuadFelt::new([Felt::new(4194588350245381799), Felt::new(0)]),
        },
        EvalRecord {
            id: 196,
            namespace: "decoder.general.dyn.h6.zero",
            value: QuadFelt::new([Felt::new(16022182314963541978), Felt::new(0)]),
        },
        EvalRecord {
            id: 197,
            namespace: "decoder.general.dyn.h7.zero",
            value: QuadFelt::new([Felt::new(8836314757936512908), Felt::new(0)]),
        },
        EvalRecord {
            id: 198,
            namespace: "decoder.general.repeat.s0.one",
            value: QuadFelt::new([Felt::new(12665553195229242113), Felt::new(0)]),
        },
        EvalRecord {
            id: 199,
            namespace: "decoder.general.repeat.h4.one",
            value: QuadFelt::new([Felt::new(7110671376227656729), Felt::new(0)]),
        },
        EvalRecord {
            id: 200,
            namespace: "decoder.general.end.loop.s0.zero",
            value: QuadFelt::new([Felt::new(17349561739015487668), Felt::new(0)]),
        },
        EvalRecord {
            id: 201,
            namespace: "decoder.general.end_repeat.h0.carry",
            value: QuadFelt::new([Felt::new(14675084366068366020), Felt::new(0)]),
        },
        EvalRecord {
            id: 202,
            namespace: "decoder.general.end_repeat.h1.carry",
            value: QuadFelt::new([Felt::new(7206936627190077403), Felt::new(0)]),
        },
        EvalRecord {
            id: 203,
            namespace: "decoder.general.end_repeat.h2.carry",
            value: QuadFelt::new([Felt::new(6718740807857903289), Felt::new(0)]),
        },
        EvalRecord {
            id: 204,
            namespace: "decoder.general.end_repeat.h3.carry",
            value: QuadFelt::new([Felt::new(17516850364483319430), Felt::new(0)]),
        },
        EvalRecord {
            id: 205,
            namespace: "decoder.general.end_repeat.h4.carry",
            value: QuadFelt::new([Felt::new(6539200550348860466), Felt::new(0)]),
        },
        EvalRecord {
            id: 206,
            namespace: "decoder.general.halt.next",
            value: QuadFelt::new([Felt::new(46417891308149319), Felt::new(0)]),
        },
        EvalRecord {
            id: 207,
            namespace: "decoder.group_count.delta.binary",
            value: QuadFelt::new([Felt::new(14515312709656548917), Felt::new(0)]),
        },
        EvalRecord {
            id: 208,
            namespace: "decoder.group_count.decrement.h0_or_imm",
            value: QuadFelt::new([Felt::new(13182337539042779943), Felt::new(0)]),
        },
        EvalRecord {
            id: 209,
            namespace: "decoder.group_count.span_decrement",
            value: QuadFelt::new([Felt::new(6058211846758132294), Felt::new(0)]),
        },
        EvalRecord {
            id: 210,
            namespace: "decoder.group_count.end_or_respan.hold",
            value: QuadFelt::new([Felt::new(11052268645110095431), Felt::new(0)]),
        },
        EvalRecord {
            id: 211,
            namespace: "decoder.group_count.end.zero",
            value: QuadFelt::new([Felt::new(8085923270334721350), Felt::new(0)]),
        },
        EvalRecord {
            id: 212,
            namespace: "decoder.op_group.shift",
            value: QuadFelt::new([Felt::new(1312737539633457020), Felt::new(0)]),
        },
        EvalRecord {
            id: 213,
            namespace: "decoder.op_group.end_or_respan.h0.zero",
            value: QuadFelt::new([Felt::new(12951763225475877068), Felt::new(0)]),
        },
        EvalRecord {
            id: 214,
            namespace: "decoder.op_index.span_respan.reset",
            value: QuadFelt::new([Felt::new(10573491584444022281), Felt::new(0)]),
        },
        EvalRecord {
            id: 215,
            namespace: "decoder.op_index.new_group.reset",
            value: QuadFelt::new([Felt::new(6175768744156945971), Felt::new(0)]),
        },
        EvalRecord {
            id: 216,
            namespace: "decoder.op_index.increment",
            value: QuadFelt::new([Felt::new(11099022161747498050), Felt::new(0)]),
        },
        EvalRecord {
            id: 217,
            namespace: "decoder.op_index.range",
            value: QuadFelt::new([Felt::new(10884671635123915786), Felt::new(0)]),
        },
        EvalRecord {
            id: 218,
            namespace: "decoder.batch_flags.span_sum",
            value: QuadFelt::new([Felt::new(3694838697400308733), Felt::new(0)]),
        },
        EvalRecord {
            id: 219,
            namespace: "decoder.batch_flags.zero_when_not_span",
            value: QuadFelt::new([Felt::new(3630764990867231714), Felt::new(0)]),
        },
        EvalRecord {
            id: 220,
            namespace: "decoder.batch_flags.h4.zero",
            value: QuadFelt::new([Felt::new(2244382601531916648), Felt::new(0)]),
        },
        EvalRecord {
            id: 221,
            namespace: "decoder.batch_flags.h5.zero",
            value: QuadFelt::new([Felt::new(15434877991581266285), Felt::new(0)]),
        },
        EvalRecord {
            id: 222,
            namespace: "decoder.batch_flags.h6.zero",
            value: QuadFelt::new([Felt::new(7419023179375721027), Felt::new(0)]),
        },
        EvalRecord {
            id: 223,
            namespace: "decoder.batch_flags.h7.zero",
            value: QuadFelt::new([Felt::new(7459745966287177285), Felt::new(0)]),
        },
        EvalRecord {
            id: 224,
            namespace: "decoder.batch_flags.h2.zero",
            value: QuadFelt::new([Felt::new(11698744832781440772), Felt::new(0)]),
        },
        EvalRecord {
            id: 225,
            namespace: "decoder.batch_flags.h3.zero",
            value: QuadFelt::new([Felt::new(8586259512688079232), Felt::new(0)]),
        },
        EvalRecord {
            id: 226,
            namespace: "decoder.batch_flags.h1.zero",
            value: QuadFelt::new([Felt::new(7969602088154595265), Felt::new(0)]),
        },
        EvalRecord {
            id: 227,
            namespace: "decoder.addr.hold_in_span",
            value: QuadFelt::new([Felt::new(5569758276797826136), Felt::new(0)]),
        },
        EvalRecord {
            id: 228,
            namespace: "decoder.addr.respan.increment",
            value: QuadFelt::new([Felt::new(7010123233147094271), Felt::new(0)]),
        },
        EvalRecord {
            id: 229,
            namespace: "decoder.addr.halt.zero",
            value: QuadFelt::new([Felt::new(571992094937652912), Felt::new(0)]),
        },
        EvalRecord {
            id: 230,
            namespace: "decoder.control_flow.sp_complement",
            value: QuadFelt::new([Felt::new(2368373158779190039), Felt::new(0)]),
        },
        EvalRecord {
            id: 231,
            namespace: "range.bus.transition",
            value: QuadFelt::new([
                Felt::new(10365289165200035540),
                Felt::new(16469718665506609592),
            ]),
        },
        EvalRecord {
            id: 232,
            namespace: "stack.overflow.bus.transition",
            value: QuadFelt::new([Felt::new(7384164985445418427), Felt::new(3858806565449404456)]),
        },
        EvalRecord {
            id: 233,
            namespace: "decoder.bus.p1.transition",
            value: QuadFelt::new([
                Felt::new(11611432650982424455),
                Felt::new(10377793451000863001),
            ]),
        },
        EvalRecord {
            id: 234,
            namespace: "decoder.bus.p2.transition",
            value: QuadFelt::new([
                Felt::new(15040597896341508305),
                Felt::new(11465419388996005277),
            ]),
        },
        EvalRecord {
            id: 235,
            namespace: "decoder.bus.p3.transition",
            value: QuadFelt::new([Felt::new(9395869302542898577), Felt::new(6472917827183803848)]),
        },
    ]
}

/// Returns the active expected OOD evaluations for the current tagged group.
pub fn active_expected_ood_evals() -> Vec<EvalRecord> {
    current_group_expected()
}
