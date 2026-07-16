use super::{
    AlgebraicSponge, CAPACITY_RANGE, DIGEST_RANGE, Felt, RATE_RANGE, RATE0_RANGE, RATE1_RANGE,
    Range, STATE_WIDTH, Word, ZERO,
};
use crate::field::Field;

mod arch;
pub use arch::optimized::{
    add_constants_and_apply_ext_round, add_constants_and_apply_inv_sbox,
    add_constants_and_apply_sbox,
};

mod mds;
use mds::{MDS, apply_mds};

pub(crate) mod rpo;
pub(crate) mod rpx;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// The number of rounds is set to 7. For the RPO hash function all rounds are uniform. For the
/// RPX hash function, there are 3 different types of rounds.
const NUM_ROUNDS: usize = 7;

// SBOX FUNCTION
// ================================================================================================

#[inline(always)]
fn apply_sbox(state: &mut [Felt; STATE_WIDTH]) {
    state[0] = state[0].exp_const_u64::<7>();
    state[1] = state[1].exp_const_u64::<7>();
    state[2] = state[2].exp_const_u64::<7>();
    state[3] = state[3].exp_const_u64::<7>();
    state[4] = state[4].exp_const_u64::<7>();
    state[5] = state[5].exp_const_u64::<7>();
    state[6] = state[6].exp_const_u64::<7>();
    state[7] = state[7].exp_const_u64::<7>();
    state[8] = state[8].exp_const_u64::<7>();
    state[9] = state[9].exp_const_u64::<7>();
    state[10] = state[10].exp_const_u64::<7>();
    state[11] = state[11].exp_const_u64::<7>();
}

// INVERSE SBOX FUNCTION
// ================================================================================================

#[inline(always)]
fn apply_inv_sbox(state: &mut [Felt; STATE_WIDTH]) {
    // compute base^10540996611094048183 using 72 multiplications per array element
    // 10540996611094048183 = b1001001001001001001001001001000110110110110110110110110110110111

    // compute base^10
    let mut t1 = *state;
    t1.iter_mut().for_each(|t| *t = t.square());

    // compute base^100
    let mut t2 = t1;
    t2.iter_mut().for_each(|t| *t = t.square());

    // compute base^100100
    let t3 = exp_acc::<Felt, STATE_WIDTH, 3>(t2, t2);

    // compute base^100100100100
    let t4 = exp_acc::<Felt, STATE_WIDTH, 6>(t3, t3);

    // compute base^100100100100100100100100
    let t5 = exp_acc::<Felt, STATE_WIDTH, 12>(t4, t4);

    // compute base^100100100100100100100100100100
    let t6 = exp_acc::<Felt, STATE_WIDTH, 6>(t5, t3);

    // compute base^1001001001001001001001001001000100100100100100100100100100100
    let t7 = exp_acc::<Felt, STATE_WIDTH, 31>(t6, t6);

    // compute base^1001001001001001001001001001000110110110110110110110110110110111
    for (i, s) in state.iter_mut().enumerate() {
        let a = (t7[i].square() * t6[i]).square().square();
        let b = t1[i] * t2[i] * *s;
        *s = a * b;
    }

    #[inline(always)]
    fn exp_acc<B: Field, const N: usize, const M: usize>(base: [B; N], tail: [B; N]) -> [B; N] {
        let mut result = base;
        for _ in 0..M {
            result.iter_mut().for_each(|r| *r = r.square());
        }
        result.iter_mut().zip(tail).for_each(|(r, t)| *r *= t);
        result
    }
}

#[inline(always)]
fn add_constants(state: &mut [Felt; STATE_WIDTH], ark: &[Felt; STATE_WIDTH]) {
    state.iter_mut().zip(ark).for_each(|(s, &k)| *s += k);
}

// ROUND CONSTANTS
// ================================================================================================

/// Rescue round constants;
/// computed as in [specifications](https://github.com/ASDiscreteMathematics/rpo)
///
/// The constants are broken up into two arrays ARK1 and ARK2; ARK1 contains the constants for the
/// first half of RPO round, and ARK2 contains constants for the second half of RPO round.
const ARK1: [[Felt; STATE_WIDTH]; NUM_ROUNDS] = [
    [
        Felt::new_unchecked(5789762306288267392),
        Felt::new_unchecked(6522564764413701783),
        Felt::new_unchecked(17809893479458208203),
        Felt::new_unchecked(107145243989736508),
        Felt::new_unchecked(6388978042437517382),
        Felt::new_unchecked(15844067734406016715),
        Felt::new_unchecked(9975000513555218239),
        Felt::new_unchecked(3344984123768313364),
        Felt::new_unchecked(9959189626657347191),
        Felt::new_unchecked(12960773468763563665),
        Felt::new_unchecked(9602914297752488475),
        Felt::new_unchecked(16657542370200465908),
    ],
    [
        Felt::new_unchecked(12987190162843096997),
        Felt::new_unchecked(653957632802705281),
        Felt::new_unchecked(4441654670647621225),
        Felt::new_unchecked(4038207883745915761),
        Felt::new_unchecked(5613464648874830118),
        Felt::new_unchecked(13222989726778338773),
        Felt::new_unchecked(3037761201230264149),
        Felt::new_unchecked(16683759727265180203),
        Felt::new_unchecked(8337364536491240715),
        Felt::new_unchecked(3227397518293416448),
        Felt::new_unchecked(8110510111539674682),
        Felt::new_unchecked(2872078294163232137),
    ],
    [
        Felt::new_unchecked(18072785500942327487),
        Felt::new_unchecked(6200974112677013481),
        Felt::new_unchecked(17682092219085884187),
        Felt::new_unchecked(10599526828986756440),
        Felt::new_unchecked(975003873302957338),
        Felt::new_unchecked(8264241093196931281),
        Felt::new_unchecked(10065763900435475170),
        Felt::new_unchecked(2181131744534710197),
        Felt::new_unchecked(6317303992309418647),
        Felt::new_unchecked(1401440938888741532),
        Felt::new_unchecked(8884468225181997494),
        Felt::new_unchecked(13066900325715521532),
    ],
    [
        Felt::new_unchecked(5674685213610121970),
        Felt::new_unchecked(5759084860419474071),
        Felt::new_unchecked(13943282657648897737),
        Felt::new_unchecked(1352748651966375394),
        Felt::new_unchecked(17110913224029905221),
        Felt::new_unchecked(1003883795902368422),
        Felt::new_unchecked(4141870621881018291),
        Felt::new_unchecked(8121410972417424656),
        Felt::new_unchecked(14300518605864919529),
        Felt::new_unchecked(13712227150607670181),
        Felt::new_unchecked(17021852944633065291),
        Felt::new_unchecked(6252096473787587650),
    ],
    [
        Felt::new_unchecked(4887609836208846458),
        Felt::new_unchecked(3027115137917284492),
        Felt::new_unchecked(9595098600469470675),
        Felt::new_unchecked(10528569829048484079),
        Felt::new_unchecked(7864689113198939815),
        Felt::new_unchecked(17533723827845969040),
        Felt::new_unchecked(5781638039037710951),
        Felt::new_unchecked(17024078752430719006),
        Felt::new_unchecked(109659393484013511),
        Felt::new_unchecked(7158933660534805869),
        Felt::new_unchecked(2955076958026921730),
        Felt::new_unchecked(7433723648458773977),
    ],
    [
        Felt::new_unchecked(16308865189192447297),
        Felt::new_unchecked(11977192855656444890),
        Felt::new_unchecked(12532242556065780287),
        Felt::new_unchecked(14594890931430968898),
        Felt::new_unchecked(7291784239689209784),
        Felt::new_unchecked(5514718540551361949),
        Felt::new_unchecked(10025733853830934803),
        Felt::new_unchecked(7293794580341021693),
        Felt::new_unchecked(6728552937464861756),
        Felt::new_unchecked(6332385040983343262),
        Felt::new_unchecked(13277683694236792804),
        Felt::new_unchecked(2600778905124452676),
    ],
    [
        Felt::new_unchecked(7123075680859040534),
        Felt::new_unchecked(1034205548717903090),
        Felt::new_unchecked(7717824418247931797),
        Felt::new_unchecked(3019070937878604058),
        Felt::new_unchecked(11403792746066867460),
        Felt::new_unchecked(10280580802233112374),
        Felt::new_unchecked(337153209462421218),
        Felt::new_unchecked(13333398568519923717),
        Felt::new_unchecked(3596153696935337464),
        Felt::new_unchecked(8104208463525993784),
        Felt::new_unchecked(14345062289456085693),
        Felt::new_unchecked(17036731477169661256),
    ],
];

const ARK2: [[Felt; STATE_WIDTH]; NUM_ROUNDS] = [
    [
        Felt::new_unchecked(6077062762357204287),
        Felt::new_unchecked(15277620170502011191),
        Felt::new_unchecked(5358738125714196705),
        Felt::new_unchecked(14233283787297595718),
        Felt::new_unchecked(13792579614346651365),
        Felt::new_unchecked(11614812331536767105),
        Felt::new_unchecked(14871063686742261166),
        Felt::new_unchecked(10148237148793043499),
        Felt::new_unchecked(4457428952329675767),
        Felt::new_unchecked(15590786458219172475),
        Felt::new_unchecked(10063319113072092615),
        Felt::new_unchecked(14200078843431360086),
    ],
    [
        Felt::new_unchecked(6202948458916099932),
        Felt::new_unchecked(17690140365333231091),
        Felt::new_unchecked(3595001575307484651),
        Felt::new_unchecked(373995945117666487),
        Felt::new_unchecked(1235734395091296013),
        Felt::new_unchecked(14172757457833931602),
        Felt::new_unchecked(707573103686350224),
        Felt::new_unchecked(15453217512188187135),
        Felt::new_unchecked(219777875004506018),
        Felt::new_unchecked(17876696346199469008),
        Felt::new_unchecked(17731621626449383378),
        Felt::new_unchecked(2897136237748376248),
    ],
    [
        Felt::new_unchecked(8023374565629191455),
        Felt::new_unchecked(15013690343205953430),
        Felt::new_unchecked(4485500052507912973),
        Felt::new_unchecked(12489737547229155153),
        Felt::new_unchecked(9500452585969030576),
        Felt::new_unchecked(2054001340201038870),
        Felt::new_unchecked(12420704059284934186),
        Felt::new_unchecked(355990932618543755),
        Felt::new_unchecked(9071225051243523860),
        Felt::new_unchecked(12766199826003448536),
        Felt::new_unchecked(9045979173463556963),
        Felt::new_unchecked(12934431667190679898),
    ],
    [
        Felt::new_unchecked(18389244934624494276),
        Felt::new_unchecked(16731736864863925227),
        Felt::new_unchecked(4440209734760478192),
        Felt::new_unchecked(17208448209698888938),
        Felt::new_unchecked(8739495587021565984),
        Felt::new_unchecked(17000774922218161967),
        Felt::new_unchecked(13533282547195532087),
        Felt::new_unchecked(525402848358706231),
        Felt::new_unchecked(16987541523062161972),
        Felt::new_unchecked(5466806524462797102),
        Felt::new_unchecked(14512769585918244983),
        Felt::new_unchecked(10973956031244051118),
    ],
    [
        Felt::new_unchecked(6982293561042362913),
        Felt::new_unchecked(14065426295947720331),
        Felt::new_unchecked(16451845770444974180),
        Felt::new_unchecked(7139138592091306727),
        Felt::new_unchecked(9012006439959783127),
        Felt::new_unchecked(14619614108529063361),
        Felt::new_unchecked(1394813199588124371),
        Felt::new_unchecked(4635111139507788575),
        Felt::new_unchecked(16217473952264203365),
        Felt::new_unchecked(10782018226466330683),
        Felt::new_unchecked(6844229992533662050),
        Felt::new_unchecked(7446486531695178711),
    ],
    [
        Felt::new_unchecked(3736792340494631448),
        Felt::new_unchecked(577852220195055341),
        Felt::new_unchecked(6689998335515779805),
        Felt::new_unchecked(13886063479078013492),
        Felt::new_unchecked(14358505101923202168),
        Felt::new_unchecked(7744142531772274164),
        Felt::new_unchecked(16135070735728404443),
        Felt::new_unchecked(12290902521256031137),
        Felt::new_unchecked(12059913662657709804),
        Felt::new_unchecked(16456018495793751911),
        Felt::new_unchecked(4571485474751953524),
        Felt::new_unchecked(17200392109565783176),
    ],
    [
        Felt::new_unchecked(17130398059294018733),
        Felt::new_unchecked(519782857322261988),
        Felt::new_unchecked(9625384390925085478),
        Felt::new_unchecked(1664893052631119222),
        Felt::new_unchecked(7629576092524553570),
        Felt::new_unchecked(3485239601103661425),
        Felt::new_unchecked(9755891797164033838),
        Felt::new_unchecked(15218148195153269027),
        Felt::new_unchecked(16460604813734957368),
        Felt::new_unchecked(9643968136937729763),
        Felt::new_unchecked(3611348709641382851),
        Felt::new_unchecked(18256379591337759196),
    ],
];
