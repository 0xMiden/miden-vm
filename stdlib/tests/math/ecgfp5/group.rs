use std::ops::Add;

use miden_utils_testing::{Felt, ONE, ZERO, push_inputs, test_case};

use super::base_field::{Ext5, bv_or};

#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub struct ECExt5 {
    pub x: Ext5,
    pub y: Ext5,
    pub point_at_infinity: Felt,
}

impl ECExt5 {
    // Taken from https://github.com/pornin/ecgfp5/blob/ce059c6/python/ecGFp5.py#L996
    pub fn a() -> Ext5 {
        Ext5::from_int(2)
    }

    // Taken from https://github.com/pornin/ecgfp5/blob/ce059c6/python/ecGFp5.py#L997
    pub fn b() -> Ext5 {
        Ext5::new(0, 263, 0, 0, 0)
    }

    // Taken from https://github.com/pornin/ecgfp5/blob/ce059c6/python/ecGFp5.py#L998
    pub fn bmul4_1() -> Felt {
        Self::b().a1 * Felt::new(4)
    }

    // Taken from https://github.com/pornin/ecgfp5/blob/ce059c6/python/ecGFp5.py#L999
    pub fn adiv3() -> Ext5 {
        Self::a() / Ext5::from_int(3)
    }

    // Taken from https://github.com/pornin/ecgfp5/blob/ce059c6/python/ecGFp5.py#L1000
    #[allow(dead_code)]
    pub fn a_prime() -> Ext5 {
        let three = Ext5::from_int(3);
        (three * Self::b() - Self::a().square()) / three
    }

    // Taken from https://github.com/pornin/ecgfp5/blob/ce059c6/python/ecGFp5.py#L1003
    #[allow(dead_code)]
    pub fn b_prime() -> Ext5 {
        let a = Self::a();
        let two = Ext5::from_int(2);
        let nine = Ext5::from_int(9);
        let twenty_seven = Ext5::from_int(27);

        a * (two * a.square() - nine * Self::b()) / twenty_seven
    }

    // Taken from https://github.com/pornin/ecgfp5/blob/ce059c6/python/ecGFp5.py#L1006
    #[allow(dead_code)]
    pub fn neutral() -> Self {
        Self {
            x: Ext5::zero(),
            y: Ext5::zero(),
            point_at_infinity: ONE,
        }
    }

    // Validates an encoded elliptic curve point, verifying whether it can be decoded successfully
    // or not, denoted by boolean return value
    //
    // Taken from https://github.com/pornin/ecgfp5/blob/ce059c6/python/ecGFp5.py#L1043-L1052
    pub fn validate(w: Ext5) -> Felt {
        let e = w.square() - Self::a();
        let delta = e.square().subk1(Self::bmul4_1());
        bv_or(Felt::new((delta.legendre() == ONE) as u64), w.is_zero())
    }

    // Given an encoded elliptic curve point, this routine attempts to decode it using
    // algorithm described in https://github.com/pornin/ecgfp5/blob/ce059c6/python/ecGFp5.py#L1022-L1041
    //
    // You can find more details in section 3.3 of https://ia.cr/2022/274
    pub fn decode(w: Ext5) -> (Self, Felt) {
        let e = w.square() - Self::a();
        let delta = e.square().subk1(Self::bmul4_1());
        let (r, c) = delta.sqrt();
        let x1 = (e + r) / Ext5::from_int(2);
        let x2 = (e - r) / Ext5::from_int(2);

        let flg = x1.legendre() == ONE;
        let x = if flg { x1 } else { x2 };
        let y = -w * x;
        let inf = ONE - c;
        let c = bv_or(c, w.is_zero());

        (
            ECExt5 {
                x: x + Self::adiv3(),
                y,
                point_at_infinity: inf,
            },
            c,
        )
    }

    // Given an elliptic curve point as Weierstraß coordinates (X, Y), this routine
    // encodes it to single element ∈ GF(p^5) | p = 2^64 - 2^32 + 1
    //
    // See https://github.com/pornin/ecgfp5/blob/ce059c6/python/ecGFp5.py#L1214-L1216 for reference implementation
    pub fn encode(self) -> Ext5 {
        let w = self.y / (Self::adiv3() - self.x);
        let flg = self.point_at_infinity == ONE;

        if flg { Ext5::zero() } else { w }
    }

    pub fn double(self) -> Self {
        let lamb0 = Ext5::from_int(3) * self.x.square() + Self::a_prime();
        let lamb1 = Ext5::from_int(2) * self.y;
        let lamb = lamb0 / lamb1;

        let x2 = lamb.square() - self.x * Ext5::from_int(2);
        let y2 = lamb * (self.x - x2) - self.y;

        Self {
            x: x2,
            y: y2,
            point_at_infinity: self.point_at_infinity,
        }
    }

    // Multiply an elliptic curve point by 319 -bit scalar ( which should be lesser
    // than prime number
    // 1067993516717146951041484916571792702745057740581727230159139685185762082554198619328292418486241
    // ) using double-and-add rule, while collecting inspiration from https://github.com/itzmeanjan/secp256k1/blob/cbbe199/point.py#L174-L186
    pub fn scalar_mul(self, scalar: &[u32; 10]) -> Self {
        let mut base = self;
        let mut res = ECExt5::neutral();

        for s in scalar {
            for i in 0..32u32 {
                let bit = (*s >> i) & 0b1u32;
                if bit == 1u32 {
                    res = res + base;
                }

                base = base.double();
            }
        }

        res
    }
}

impl Add for ECExt5 {
    type Output = ECExt5;

    fn add(self, rhs: Self) -> Self::Output {
        let samex = self.x == rhs.x;
        let diffy = self.y != rhs.y;

        let lamb0 = if samex {
            Ext5::from_int(3) * self.x.square() + Self::a_prime()
        } else {
            rhs.y - self.y
        };

        let lamb1 = if samex {
            Ext5::from_int(2) * self.y
        } else {
            rhs.x - self.x
        };

        let lamb = lamb0 / lamb1;

        let x3 = lamb.square() - self.x - rhs.x;
        let y3 = lamb * (self.x - x3) - self.y;
        let inf3 = Felt::new((samex & diffy) as u64);

        Self {
            x: if rhs.point_at_infinity == ONE {
                self.x
            } else if self.point_at_infinity == ONE {
                rhs.x
            } else {
                x3
            },
            y: if rhs.point_at_infinity == ONE {
                self.y
            } else if self.point_at_infinity == ONE {
                rhs.y
            } else {
                y3
            },
            point_at_infinity: if rhs.point_at_infinity == ONE {
                self.point_at_infinity
            } else if self.point_at_infinity == ONE {
                rhs.point_at_infinity
            } else {
                inf3
            },
        }
    }
}

// Test vectors taken from https://github.com/pornin/ecgfp5/blob/ce059c6/python/ecGFp5.py#L1528-L1556
#[test_case(0, 0, 0, 0, 0, true; "[0] should validate")]
#[test_case(12539254003028696409, 15524144070600887654, 15092036948424041984, 11398871370327264211, 10958391180505708567, true; "[1] should validate")]
#[test_case(11001943240060308920, 17075173755187928434, 3940989555384655766, 15017795574860011099, 5548543797011402287, true; "[2] should validate")]
#[test_case(246872606398642312, 4900963247917836450, 7327006728177203977, 13945036888436667069, 3062018119121328861, true; "[3] should validate")]
#[test_case(8058035104653144162, 16041715455419993830, 7448530016070824199, 11253639182222911208, 6228757819849640866, true; "[4] should validate")]
#[test_case(10523134687509281194, 11148711503117769087, 9056499921957594891, 13016664454465495026, 16494247923890248266, true; "[5] should validate")]
#[test_case(12173306542237620, 6587231965341539782, 17027985748515888117, 17194831817613584995, 10056734072351459010, true; "[6] should validate")]
#[test_case(9420857400785992333, 4695934009314206363, 14471922162341187302, 13395190104221781928, 16359223219913018041, true; "[7] should validate")]
#[test_case(13557832913345268708, 15669280705791538619, 8534654657267986396, 12533218303838131749, 5058070698878426028, false; "[8] should not validate")]
#[test_case(135036726621282077, 17283229938160287622, 13113167081889323961, 1653240450380825271, 520025869628727862, false; "[9] should not validate")]
#[test_case(6727960962624180771, 17240764188796091916, 3954717247028503753, 1002781561619501488, 4295357288570643789, false; "[10] should not validate")]
#[test_case(4578929270179684956, 3866930513245945042, 7662265318638150701, 9503686272550423634, 12241691520798116285, false; "[11] should not validate")]
#[test_case(16890297404904119082, 6169724643582733633, 9725973298012340311, 5977049210035183790, 11379332130141664883, false; "[12] should not validate")]
#[test_case(13777379982711219130, 14715168412651470168, 17942199593791635585, 6188824164976547520, 15461469634034461986, false; "[13] should not validate")]
fn test_ec_ext5_point_validate(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, should_validate: bool) {
    let source = "
    use std::math::ecgfp5::group

    begin
        exec.group::validate
    end";

    let w = Ext5::new(a0, a1, a2, a3, a4);
    let flg = ECExt5::validate(w);

    let mut stack = [w.a0.as_int(), w.a1.as_int(), w.a2.as_int(), w.a3.as_int(), w.a4.as_int()];
    stack.reverse();

    let test = build_test!(source, &stack);
    let strace = test.get_last_stack_state();

    assert_eq!(strace[0], flg);
    assert_eq!(strace[0], Felt::new(should_validate as u64));
}

// Test vectors taken from https://github.com/pornin/ecgfp5/blob/ce059c6/python/ecGFp5.py#L1528-L1556
#[test_case(0, 0, 0, 0, 0, true; "[0] should decode")]
#[test_case(12539254003028696409, 15524144070600887654, 15092036948424041984, 11398871370327264211, 10958391180505708567, true; "[1] should decode")]
#[test_case(11001943240060308920, 17075173755187928434, 3940989555384655766, 15017795574860011099, 5548543797011402287, true; "[2] should decode")]
#[test_case(246872606398642312, 4900963247917836450, 7327006728177203977, 13945036888436667069, 3062018119121328861, true; "[3] should decode")]
#[test_case(8058035104653144162, 16041715455419993830, 7448530016070824199, 11253639182222911208, 6228757819849640866, true; "[4] should decode")]
#[test_case(10523134687509281194, 11148711503117769087, 9056499921957594891, 13016664454465495026, 16494247923890248266, true; "[5] should decode")]
#[test_case(12173306542237620, 6587231965341539782, 17027985748515888117, 17194831817613584995, 10056734072351459010, true; "[6] should decode")]
#[test_case(9420857400785992333, 4695934009314206363, 14471922162341187302, 13395190104221781928, 16359223219913018041, true; "[7] should decode")]
#[test_case(13557832913345268708, 15669280705791538619, 8534654657267986396, 12533218303838131749, 5058070698878426028, false; "[8] should not decode")]
#[test_case(135036726621282077, 17283229938160287622, 13113167081889323961, 1653240450380825271, 520025869628727862, false; "[9] should not decode")]
#[test_case(6727960962624180771, 17240764188796091916, 3954717247028503753, 1002781561619501488, 4295357288570643789, false; "[10] should not decode")]
#[test_case(4578929270179684956, 3866930513245945042, 7662265318638150701, 9503686272550423634, 12241691520798116285, false; "[11] should not decode")]
#[test_case(16890297404904119082, 6169724643582733633, 9725973298012340311, 5977049210035183790, 11379332130141664883, false; "[12] should not decode")]
#[test_case(13777379982711219130, 14715168412651470168, 17942199593791635585, 6188824164976547520, 15461469634034461986, false; "[13] should not decode")]
fn test_ec_ext5_point_decode(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, should_decode: bool) {
    let source = "
    use std::math::ecgfp5::group
    use std::sys

    begin
        exec.group::decode

        exec.sys::truncate_stack
    end";

    let w = Ext5::new(a0, a1, a2, a3, a4);
    let (point, flg) = ECExt5::decode(w);

    let mut stack = [w.a0.as_int(), w.a1.as_int(), w.a2.as_int(), w.a3.as_int(), w.a4.as_int()];
    stack.reverse();

    let test = build_test!(source, &stack);
    let strace = test.get_last_stack_state();

    assert_eq!(strace[0], point.x.a0);
    assert_eq!(strace[1], point.x.a1);
    assert_eq!(strace[2], point.x.a2);
    assert_eq!(strace[3], point.x.a3);
    assert_eq!(strace[4], point.x.a4);
    assert_eq!(strace[5], point.y.a0);
    assert_eq!(strace[6], point.y.a1);
    assert_eq!(strace[7], point.y.a2);
    assert_eq!(strace[8], point.y.a3);
    assert_eq!(strace[9], point.y.a4);
    assert_eq!(strace[10], point.point_at_infinity);
    assert_eq!(strace[11], flg);
    assert_eq!(strace[11], Felt::new(should_decode as u64));
}

// Test vectors taken from https://github.com/pornin/ecgfp5/blob/ce059c6/python/ecGFp5.py#L1528-L1548
#[test_case(0, 0, 0, 0, 0; "[0] should decode")]
#[test_case(12539254003028696409, 15524144070600887654, 15092036948424041984, 11398871370327264211, 10958391180505708567; "[1] should decode")]
#[test_case(11001943240060308920, 17075173755187928434, 3940989555384655766, 15017795574860011099, 5548543797011402287; "[2] should decode")]
#[test_case(246872606398642312, 4900963247917836450, 7327006728177203977, 13945036888436667069, 3062018119121328861; "[3] should decode")]
#[test_case(8058035104653144162, 16041715455419993830, 7448530016070824199, 11253639182222911208, 6228757819849640866; "[4] should decode")]
#[test_case(10523134687509281194, 11148711503117769087, 9056499921957594891, 13016664454465495026, 16494247923890248266; "[5] should decode")]
#[test_case(12173306542237620, 6587231965341539782, 17027985748515888117, 17194831817613584995, 10056734072351459010; "[6] should decode")]
#[test_case(9420857400785992333, 4695934009314206363, 14471922162341187302, 13395190104221781928, 16359223219913018041; "[7] should decode")]
fn test_ec_ext5_point_encode(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) {
    let source = "
    use std::math::ecgfp5::group

    begin
        exec.group::encode
        swapdw dropw dropw
    end";

    let w = Ext5::new(a0, a1, a2, a3, a4);
    let (point, flg) = ECExt5::decode(w);

    assert_eq!(flg, ONE);

    let w_prime = point.encode();

    assert_eq!(w, w_prime);

    let mut stack = [
        point.x.a0.as_int(),
        point.x.a1.as_int(),
        point.x.a2.as_int(),
        point.x.a3.as_int(),
        point.x.a4.as_int(),
        point.y.a0.as_int(),
        point.y.a1.as_int(),
        point.y.a2.as_int(),
        point.y.a3.as_int(),
        point.y.a4.as_int(),
        point.point_at_infinity.as_int(),
    ];
    stack.reverse();

    let test = build_test!(source, &stack);
    let strace = test.get_last_stack_state();

    assert_eq!(strace[0], w_prime.a0);
    assert_eq!(strace[1], w_prime.a1);
    assert_eq!(strace[2], w_prime.a2);
    assert_eq!(strace[3], w_prime.a3);
    assert_eq!(strace[4], w_prime.a4);
}

// Test vectors taken from https://github.com/pornin/ecgfp5/blob/ce059c6/python/ecGFp5.py#L1528-L1548
#[test_case(12539254003028696409, 15524144070600887654, 15092036948424041984, 11398871370327264211, 10958391180505708567, 11001943240060308920, 17075173755187928434, 3940989555384655766, 15017795574860011099, 5548543797011402287, 246872606398642312, 4900963247917836450, 7327006728177203977, 13945036888436667069, 3062018119121328861; "addition [0]")]
#[test_case(12539254003028696409, 15524144070600887654, 15092036948424041984, 11398871370327264211, 10958391180505708567, 12539254003028696409, 15524144070600887654, 15092036948424041984, 11398871370327264211, 10958391180505708567, 8058035104653144162, 16041715455419993830, 7448530016070824199, 11253639182222911208, 6228757819849640866; "doubling [0]")]
#[test_case(11001943240060308920, 17075173755187928434, 3940989555384655766, 15017795574860011099, 5548543797011402287, 11001943240060308920, 17075173755187928434, 3940989555384655766, 15017795574860011099, 5548543797011402287, 10523134687509281194, 11148711503117769087, 9056499921957594891, 13016664454465495026, 16494247923890248266; "doubling [1]")]
#[test_case(8058035104653144162, 16041715455419993830, 7448530016070824199, 11253639182222911208, 6228757819849640866, 11001943240060308920, 17075173755187928434, 3940989555384655766, 15017795574860011099, 5548543797011402287, 12173306542237620, 6587231965341539782, 17027985748515888117, 17194831817613584995, 10056734072351459010; "addition [1]")]
#[test_case(12539254003028696409, 15524144070600887654, 15092036948424041984, 11398871370327264211, 10958391180505708567, 10523134687509281194, 11148711503117769087, 9056499921957594891, 13016664454465495026, 16494247923890248266, 9420857400785992333, 4695934009314206363, 14471922162341187302, 13395190104221781928, 16359223219913018041; "addition [2]")]
#[allow(clippy::too_many_arguments)]
fn test_ec_ext5_point_addition(
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    b0: u64,
    b1: u64,
    b2: u64,
    b3: u64,
    b4: u64,
    c0: u64,
    c1: u64,
    c2: u64,
    c3: u64,
    c4: u64,
) {
    let w0 = Ext5::new(a0, a1, a2, a3, a4);
    let w1 = Ext5::new(b0, b1, b2, b3, b4);
    let w2 = Ext5::new(c0, c1, c2, c3, c4);

    let (p0, _) = ECExt5::decode(w0);
    let (p1, _) = ECExt5::decode(w1);
    let (p2, _) = ECExt5::decode(w2);

    let q2 = p0 + p1;
    assert_eq!(q2.encode(), p2.encode());

    let mut stack = [
        p0.x.a0.as_int(),
        p0.x.a1.as_int(),
        p0.x.a2.as_int(),
        p0.x.a3.as_int(),
        p0.x.a4.as_int(),
        p0.y.a0.as_int(),
        p0.y.a1.as_int(),
        p0.y.a2.as_int(),
        p0.y.a3.as_int(),
        p0.y.a4.as_int(),
        p0.point_at_infinity.as_int(),
        p1.x.a0.as_int(),
        p1.x.a1.as_int(),
        p1.x.a2.as_int(),
        p1.x.a3.as_int(),
        p1.x.a4.as_int(),
        p1.y.a0.as_int(),
        p1.y.a1.as_int(),
        p1.y.a2.as_int(),
        p1.y.a3.as_int(),
        p1.y.a4.as_int(),
        p1.point_at_infinity.as_int(),
    ];
    stack.reverse();

    let source = format!(
        "
    use std::math::ecgfp5::group
    use std::sys

    begin
        {inputs}
        exec.group::add

        exec.sys::truncate_stack
    end",
        inputs = push_inputs(&stack)
    );

    let test = build_test!(source, &[]);
    let strace = test.get_last_stack_state();

    assert_eq!(strace[0], q2.x.a0);
    assert_eq!(strace[1], q2.x.a1);
    assert_eq!(strace[2], q2.x.a2);
    assert_eq!(strace[3], q2.x.a3);
    assert_eq!(strace[4], q2.x.a4);
    assert_eq!(strace[5], q2.y.a0);
    assert_eq!(strace[6], q2.y.a1);
    assert_eq!(strace[7], q2.y.a2);
    assert_eq!(strace[8], q2.y.a3);
    assert_eq!(strace[9], q2.y.a4);
    assert_eq!(strace[10], q2.point_at_infinity);
}

// Test vectors taken from https://github.com/pornin/ecgfp5/blob/ce059c6/python/ecGFp5.py#L1528-L1548
#[test_case(12539254003028696409, 15524144070600887654, 15092036948424041984, 11398871370327264211, 10958391180505708567, 8058035104653144162, 16041715455419993830, 7448530016070824199, 11253639182222911208, 6228757819849640866; "0")]
#[test_case(11001943240060308920, 17075173755187928434, 3940989555384655766, 15017795574860011099, 5548543797011402287, 10523134687509281194, 11148711503117769087, 9056499921957594891, 13016664454465495026, 16494247923890248266; "1")]
#[allow(clippy::too_many_arguments)]
fn test_ec_ext5_point_doubling(
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    b0: u64,
    b1: u64,
    b2: u64,
    b3: u64,
    b4: u64,
) {
    let source = "
    use std::math::ecgfp5::group
    use std::sys

    begin
        exec.group::double

        exec.sys::truncate_stack
    end";

    let w0 = Ext5::new(a0, a1, a2, a3, a4);
    let w1 = Ext5::new(b0, b1, b2, b3, b4);

    let (p0, _) = ECExt5::decode(w0);
    let (p1, _) = ECExt5::decode(w1);

    let q1 = p0.double();
    assert_eq!(q1.encode(), p1.encode());

    let mut stack = [
        p0.x.a0.as_int(),
        p0.x.a1.as_int(),
        p0.x.a2.as_int(),
        p0.x.a3.as_int(),
        p0.x.a4.as_int(),
        p0.y.a0.as_int(),
        p0.y.a1.as_int(),
        p0.y.a2.as_int(),
        p0.y.a3.as_int(),
        p0.y.a4.as_int(),
        p0.point_at_infinity.as_int(),
    ];
    stack.reverse();

    let test = build_test!(source, &stack);
    let strace = test.get_last_stack_state();

    assert_eq!(strace[0], q1.x.a0);
    assert_eq!(strace[1], q1.x.a1);
    assert_eq!(strace[2], q1.x.a2);
    assert_eq!(strace[3], q1.x.a3);
    assert_eq!(strace[4], q1.x.a4);
    assert_eq!(strace[5], q1.y.a0);
    assert_eq!(strace[6], q1.y.a1);
    assert_eq!(strace[7], q1.y.a2);
    assert_eq!(strace[8], q1.y.a3);
    assert_eq!(strace[9], q1.y.a4);
    assert_eq!(strace[10], q1.point_at_infinity);
}

// Test vectors taken from https://github.com/pornin/ecgfp5/blob/ce059c6/python/ecGFp5.py#L1528-L1558
#[test]
fn test_ec_ext5_point_multiplication() {
    let w0 = Ext5::new(
        12539254003028696409,
        15524144070600887654,
        15092036948424041984,
        11398871370327264211,
        10958391180505708567,
    );
    let w1 = Ext5::new(
        11001943240060308920,
        17075173755187928434,
        3940989555384655766,
        15017795574860011099,
        5548543797011402287,
    );
    // = 841809598287430541331763924924406256080383779033370172527955679319982746101779529382447999363236
    //
    // Converted using https://github.com/pornin/ecgfp5/blob/ce059c6/python/ecGFp5.py#L1054-L1069
    let e = [
        666904740u32,
        1257318652u32,
        4031728122u32,
        3689598853u32,
        703808805u32,
        386793741u32,
        2898811333u32,
        4092670716u32,
        1596344924u32,
        1692681010u32,
    ];

    let (p0, _) = ECExt5::decode(w0);
    let (p1, _) = ECExt5::decode(w1);
    let q1 = p0.scalar_mul(&e);

    assert_eq!(q1.encode(), p1.encode());

    let mut stack = [
        p0.x.a0.as_int(),
        p0.x.a1.as_int(),
        p0.x.a2.as_int(),
        p0.x.a3.as_int(),
        p0.x.a4.as_int(),
        p0.y.a0.as_int(),
        p0.y.a1.as_int(),
        p0.y.a2.as_int(),
        p0.y.a3.as_int(),
        p0.y.a4.as_int(),
        p0.point_at_infinity.as_int(),
        e[0] as u64,
        e[1] as u64,
        e[2] as u64,
        e[3] as u64,
        e[4] as u64,
        e[5] as u64,
        e[6] as u64,
        e[7] as u64,
        e[8] as u64,
        e[9] as u64,
    ];
    stack.reverse();

    let source = format!(
        "
    use std::math::ecgfp5::group
    use std::sys

    begin
        {inputs}
        exec.group::mul

        exec.sys::truncate_stack
    end",
        inputs = push_inputs(&stack)
    );

    let test = build_test!(source, &[]);
    let strace = test.get_last_stack_state();

    assert_eq!(strace[0], p1.x.a0);
    assert_eq!(strace[1], p1.x.a1);
    assert_eq!(strace[2], p1.x.a2);
    assert_eq!(strace[3], p1.x.a3);
    assert_eq!(strace[4], p1.x.a4);
    assert_eq!(strace[5], p1.y.a0);
    assert_eq!(strace[6], p1.y.a1);
    assert_eq!(strace[7], p1.y.a2);
    assert_eq!(strace[8], p1.y.a3);
    assert_eq!(strace[9], p1.y.a4);
    assert_eq!(strace[10], p1.point_at_infinity);
}

// Tests implementation correctness of multiplication of generator point by 319 -bit scalar.
#[test]
fn test_ec_ext5_gen_multiplication() {
    let source = "
    use std::math::ecgfp5::group
    use std::sys

    begin
        exec.group::gen_mul

        exec.sys::truncate_stack
    end";

    // Conventional generator point of this group
    // Taken from https://github.com/pornin/ecgfp5/blob/ce059c6/rust/src/curve.rs#L67-L83
    // Note, (x, u) = (x, x/ y)
    let generator = ECExt5 {
        x: Ext5::new(
            0xb2ca178ecf4453a1,
            0x3c757788836d3ea4,
            0x48d7f28a26dafd0b,
            0x1e0f15c7fd44c28e,
            0x21fa7ffcc8252211,
        ),
        y: Ext5::new(
            0xb2ca178ecf4453a1,
            0x3c757788836d3ea4,
            0x48d7f28a26dafd0b,
            0x1e0f15c7fd44c28e,
            0x21fa7ffcc8252211,
        ) * Ext5::from_int(4),
        point_at_infinity: ZERO,
    };
    // = 1067993516717146951041484916571792702745057740581727230159139685185762082554198619328292418486241
    // = N ( See https://github.com/pornin/ecgfp5/blob/ce059c6/python/ecGFp5.py#L922 )
    //
    // Converted using https://github.com/pornin/ecgfp5/blob/ce059c6/python/ecGFp5.py#L1054-L1069
    //
    // Or below Python code snippet
    //
    // [(N >> (32 * i)) & 0xffff_ffff for i in range(10)]
    let scalar = [
        2492202977u32,
        3893352854,
        3609501852,
        3901250617,
        3484943929,
        2147483622,
        22,
        2147483633,
        2147483655,
        2147483645,
    ];
    let res = generator.scalar_mul(&scalar);

    let mut stack = [
        scalar[0] as u64,
        scalar[1] as u64,
        scalar[2] as u64,
        scalar[3] as u64,
        scalar[4] as u64,
        scalar[5] as u64,
        scalar[6] as u64,
        scalar[7] as u64,
        scalar[8] as u64,
        scalar[9] as u64,
    ];
    stack.reverse();

    let test = build_test!(source, &stack);
    let strace = test.get_last_stack_state();

    assert_eq!(strace[0], res.x.a0);
    assert_eq!(strace[1], res.x.a1);
    assert_eq!(strace[2], res.x.a2);
    assert_eq!(strace[3], res.x.a3);
    assert_eq!(strace[4], res.x.a4);
    assert_eq!(strace[5], res.y.a0);
    assert_eq!(strace[6], res.y.a1);
    assert_eq!(strace[7], res.y.a2);
    assert_eq!(strace[8], res.y.a3);
    assert_eq!(strace[9], res.y.a4);
    assert_eq!(strace[10], res.point_at_infinity);
}
