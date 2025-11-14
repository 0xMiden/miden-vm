use miden_utils_testing::test_case;

// Wrapper types introduced for parameterized testing
struct FieldElement([u32; 8]);
struct Point([FieldElement; 3]);

#[test_case(Point([FieldElement([1725045020, 1243934934, 83748696, 1271163719, 2490525753, 3709155749, 1579712529, 1757200845]), FieldElement([258440691, 3022796594, 2607846704, 163567449, 1396660245, 61235791, 73386979, 3569717]), FieldElement([628236075, 1776096883, 1596640373, 1237597377, 2238764922, 2503475385, 3619273576, 3366549089])]), Point([FieldElement([1571365520, 1799368815, 7428921, 1427940723, 3919221800, 2377651848, 3160934912, 2085994872]), FieldElement([2329310267, 2767739398, 1113377320, 447109814, 536421003, 2795624768, 2178970503, 2186442817]), FieldElement([1088857644, 2485825496, 3157339099, 1571409508, 3480032262, 4248989966, 223221158, 3053614628])]) ; "0")]
#[test_case(Point([FieldElement([1557300347, 3826368586, 2537306948, 1194350582, 2206313690, 2155850976, 910320597, 3536848074]), FieldElement([124257772, 3353686949, 2778858866, 3272416768, 3192211612, 670334657, 2786774514, 1334286332]), FieldElement([2312297066, 2925488368, 3267009695, 2498870966, 1732427718, 4239428087, 1550410695, 627716766])]), Point([FieldElement([3659723495, 2637562175, 4037957238, 1456041611, 1290327999, 237726701, 1767809589, 2855059581]), FieldElement([4155167893, 4134499992, 4079637937, 1309846292, 1954278775, 592701051, 257001688, 2968630199]), FieldElement([43236963, 3205695541, 4093727030, 1974224130, 1389148406, 3751401424, 3638701209, 1284385121])]) ; "1")]
#[test_case(Point([FieldElement([3527372762, 3507857639, 1594370824, 3718082544, 2518725024, 2545775599, 1088522187, 1093635599]), FieldElement([3614258408, 1260438099, 1063020787, 456123286, 4107569356, 1151599969, 3890268877, 1968252526]), FieldElement([3558741386, 268995358, 367673520, 1545535419, 2508499329, 1109236387, 895079977, 1740167655])]), Point([FieldElement([3785081520, 3370100016, 4156379850, 4091951425, 423340917, 252431339, 193520024, 1385386899]), FieldElement([3276376364, 188198541, 524857368, 3507707470, 1074382731, 911770899, 1564099145, 931832751]), FieldElement([646221711, 1099045009, 2864871562, 1462352998, 1135851116, 4048420382, 3606347384, 1645193827])]) ; "2")]
fn test_secp256k1_point_doubling(src: Point, dst: Point) {
    let source = format!(
        "
    use std::math::secp256k1::group

    # Given a point of secp256k1 elliptic curve, this routine first computes
    # point doubling of that point in projective coordinate & then asserts
    # each coordinate limb-by-limb for ensuring correctness.
    @locals(48)
    proc point_doubling_test_wrapper
        # push X -coordinate to memory
        push.{}.{}.{}.{}
        loc_storew_be.0
        dropw
        push.{}.{}.{}.{}
        loc_storew_be.4
        dropw

        # push Y -coordinate to memory
        push.{}.{}.{}.{}
        loc_storew_be.8
        dropw
        push.{}.{}.{}.{}
        loc_storew_be.12
        dropw

        # push Z -coordinate to memory
        push.{}.{}.{}.{}
        loc_storew_be.16
        dropw
        push.{}.{}.{}.{}
        loc_storew_be.20
        dropw

        # input/ output memory addresses for point doubling purpose
        locaddr.44
        locaddr.40
        locaddr.36
        locaddr.32
        locaddr.28
        locaddr.24

        locaddr.20
        locaddr.16
        locaddr.12
        locaddr.8
        locaddr.4
        locaddr.0

        # elliptic curve point doubling
        exec.group::double

        # --- start asserting X3 ---
        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert

        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        # --- end asserting X3 ---

        # --- start asserting Y3 ---
        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert

        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        # --- end asserting Y3 ---

        # --- start asserting Z3 ---
        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert

        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        # --- end asserting Z3 ---
    end

    begin
        exec.point_doubling_test_wrapper
    end",
        src.0[0].0[3],
        src.0[0].0[2],
        src.0[0].0[1],
        src.0[0].0[0],
        src.0[0].0[7],
        src.0[0].0[6],
        src.0[0].0[5],
        src.0[0].0[4],
        src.0[1].0[3],
        src.0[1].0[2],
        src.0[1].0[1],
        src.0[1].0[0],
        src.0[1].0[7],
        src.0[1].0[6],
        src.0[1].0[5],
        src.0[1].0[4],
        src.0[2].0[3],
        src.0[2].0[2],
        src.0[2].0[1],
        src.0[2].0[0],
        src.0[2].0[7],
        src.0[2].0[6],
        src.0[2].0[5],
        src.0[2].0[4],
        dst.0[0].0[0],
        dst.0[0].0[1],
        dst.0[0].0[2],
        dst.0[0].0[3],
        dst.0[0].0[4],
        dst.0[0].0[5],
        dst.0[0].0[6],
        dst.0[0].0[7],
        dst.0[1].0[0],
        dst.0[1].0[1],
        dst.0[1].0[2],
        dst.0[1].0[3],
        dst.0[1].0[4],
        dst.0[1].0[5],
        dst.0[1].0[6],
        dst.0[1].0[7],
        dst.0[2].0[0],
        dst.0[2].0[1],
        dst.0[2].0[2],
        dst.0[2].0[3],
        dst.0[2].0[4],
        dst.0[2].0[5],
        dst.0[2].0[6],
        dst.0[2].0[7],
    );

    let test = build_test!(&source, &[]);
    assert!(test.execute().is_ok());
}

#[test_case(Point([FieldElement([1725045020, 1243934934, 83748696, 1271163719, 2490525753, 3709155749, 1579712529, 1757200845]), FieldElement([258440691, 3022796594, 2607846704, 163567449, 1396660245, 61235791, 73386979, 3569717]), FieldElement([628236075, 1776096883, 1596640373, 1237597377, 2238764922, 2503475385, 3619273576, 3366549089])]), Point([FieldElement([1557300347, 3826368586, 2537306948, 1194350582, 2206313690, 2155850976, 910320597, 3536848074]), FieldElement([124257772, 3353686949, 2778858866, 3272416768, 3192211612, 670334657, 2786774514, 1334286332]), FieldElement([2312297066, 2925488368, 3267009695, 2498870966, 1732427718, 4239428087, 1550410695, 627716766])]), Point([FieldElement([2309099704, 2158014047, 854312809, 3276656657, 3455091323, 3708360608, 3832958189, 1030676036]), FieldElement([133738327, 3330962811, 3584096721, 299911668, 2650033490, 422639790, 3556231157, 1827621109]), FieldElement([154840996, 2382379548, 82306663, 1374755238, 3331244496, 1158573656, 1766956234, 1263003926])]) ; "0")]
#[test_case(Point([FieldElement([1557300347, 3826368586, 2537306948, 1194350582, 2206313690, 2155850976, 910320597, 3536848074]), FieldElement([124257772, 3353686949, 2778858866, 3272416768, 3192211612, 670334657, 2786774514, 1334286332]), FieldElement([2312297066, 2925488368, 3267009695, 2498870966, 1732427718, 4239428087, 1550410695, 627716766])]), Point([FieldElement([3527372762, 3507857639, 1594370824, 3718082544, 2518725024, 2545775599, 1088522187, 1093635599]), FieldElement([3614258408, 1260438099, 1063020787, 456123286, 4107569356, 1151599969, 3890268877, 1968252526]), FieldElement([3558741386, 268995358, 367673520, 1545535419, 2508499329, 1109236387, 895079977, 1740167655])]), Point([FieldElement([864003654, 239222195, 2420094174, 1839306128, 504066392, 3866056574, 1497267227, 949039869]), FieldElement([1768840249, 1785217230, 2513616209, 3186527350, 4099081547, 1300046179, 3896530411, 1706704480]), FieldElement([254418902, 1324758382, 3468964171, 3612550032, 4021338715, 3720724604, 2848891937, 4161447991])]); "1")]
#[test_case(Point([FieldElement([3785081520, 3370100016, 4156379850, 4091951425, 423340917, 252431339, 193520024, 1385386899]), FieldElement([3276376364, 188198541, 524857368, 3507707470, 1074382731, 911770899, 1564099145, 931832751]), FieldElement([646221711, 1099045009, 2864871562, 1462352998, 1135851116, 4048420382, 3606347384, 1645193827])]), Point([FieldElement([3527372762, 3507857639, 1594370824, 3718082544, 2518725024, 2545775599, 1088522187, 1093635599]), FieldElement([3614258408, 1260438099, 1063020787, 456123286, 4107569356, 1151599969, 3890268877, 1968252526]), FieldElement([3558741386, 268995358, 367673520, 1545535419, 2508499329, 1109236387, 895079977, 1740167655])]), Point([FieldElement([2262227686, 3058325312, 2312740210, 2450516566, 2065187793, 3014075136, 686692524, 1785101118]), FieldElement([3723609786, 2213349074, 3667058099, 958054847, 3286828331, 2991920902, 2720867700, 2661623893]), FieldElement([1788545644, 1974633727, 3957640342, 2535384457, 4085672768, 2180047934, 928802070, 1210497449])]); "2")]
fn test_secp256k1_point_addition(src0: Point, src1: Point, dst: Point) {
    let source = format!(
        "
    use std::math::secp256k1::group

    # Given two points of secp256k1 elliptic curve ( twice ), this routine first computes
    # point addition of them in projective coordinate & then asserts each coordinate
    # limb-by-limb for ensuring correctness.
    @locals(72)
    proc point_addition_test_wrapper
        # push X1 -coordinate to memory
        push.{}.{}.{}.{}
        loc_storew_be.0
        dropw
        push.{}.{}.{}.{}
        loc_storew_be.4
        dropw

        # push Y1 -coordinate to memory
        push.{}.{}.{}.{}
        loc_storew_be.8
        dropw
        push.{}.{}.{}.{}
        loc_storew_be.12
        dropw

        # push Z1 -coordinate to memory
        push.{}.{}.{}.{}
        loc_storew_be.16
        dropw
        push.{}.{}.{}.{}
        loc_storew_be.20
        dropw

        # push X2 -coordinate to memory
        push.{}.{}.{}.{}
        loc_storew_be.24
        dropw
        push.{}.{}.{}.{}
        loc_storew_be.28
        dropw

        # push Y2 -coordinate to memory
        push.{}.{}.{}.{}
        loc_storew_be.32
        dropw
        push.{}.{}.{}.{}
        loc_storew_be.36
        dropw

        # push Z2 -coordinate to memory
        push.{}.{}.{}.{}
        loc_storew_be.40
        dropw
        push.{}.{}.{}.{}
        loc_storew_be.44
        dropw

        # input/ output memory addresses for point doubling purpose
        locaddr.68
        locaddr.64
        locaddr.60
        locaddr.56
        locaddr.52
        locaddr.48

        locaddr.44
        locaddr.40
        locaddr.36
        locaddr.32
        locaddr.28
        locaddr.24

        locaddr.20
        locaddr.16
        locaddr.12
        locaddr.8
        locaddr.4
        locaddr.0

        # elliptic curve point addition
        exec.group::add

        # --- start asserting X3 ---
        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert

        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        # --- end asserting X3 ---

        # --- start asserting Y3 ---
        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert

        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        # --- end asserting Y3 ---

        # --- start asserting Z3 ---
        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert

        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        # --- end asserting Z3 ---
    end

    begin
        exec.point_addition_test_wrapper
    end",
        src0.0[0].0[3],
        src0.0[0].0[2],
        src0.0[0].0[1],
        src0.0[0].0[0],
        src0.0[0].0[7],
        src0.0[0].0[6],
        src0.0[0].0[5],
        src0.0[0].0[4],
        src0.0[1].0[3],
        src0.0[1].0[2],
        src0.0[1].0[1],
        src0.0[1].0[0],
        src0.0[1].0[7],
        src0.0[1].0[6],
        src0.0[1].0[5],
        src0.0[1].0[4],
        src0.0[2].0[3],
        src0.0[2].0[2],
        src0.0[2].0[1],
        src0.0[2].0[0],
        src0.0[2].0[7],
        src0.0[2].0[6],
        src0.0[2].0[5],
        src0.0[2].0[4],
        src1.0[0].0[3],
        src1.0[0].0[2],
        src1.0[0].0[1],
        src1.0[0].0[0],
        src1.0[0].0[7],
        src1.0[0].0[6],
        src1.0[0].0[5],
        src1.0[0].0[4],
        src1.0[1].0[3],
        src1.0[1].0[2],
        src1.0[1].0[1],
        src1.0[1].0[0],
        src1.0[1].0[7],
        src1.0[1].0[6],
        src1.0[1].0[5],
        src1.0[1].0[4],
        src1.0[2].0[3],
        src1.0[2].0[2],
        src1.0[2].0[1],
        src1.0[2].0[0],
        src1.0[2].0[7],
        src1.0[2].0[6],
        src1.0[2].0[5],
        src1.0[2].0[4],
        dst.0[0].0[0],
        dst.0[0].0[1],
        dst.0[0].0[2],
        dst.0[0].0[3],
        dst.0[0].0[4],
        dst.0[0].0[5],
        dst.0[0].0[6],
        dst.0[0].0[7],
        dst.0[1].0[0],
        dst.0[1].0[1],
        dst.0[1].0[2],
        dst.0[1].0[3],
        dst.0[1].0[4],
        dst.0[1].0[5],
        dst.0[1].0[6],
        dst.0[1].0[7],
        dst.0[2].0[0],
        dst.0[2].0[1],
        dst.0[2].0[2],
        dst.0[2].0[3],
        dst.0[2].0[4],
        dst.0[2].0[5],
        dst.0[2].0[6],
        dst.0[2].0[7],
    );

    let test = build_test!(&source, &[]);
    assert!(test.execute().is_ok());
}

#[test_case(Point([FieldElement([1725045020, 1243934934, 83748696, 1271163719, 2490525753, 3709155749, 1579712529, 1757200845]), FieldElement([258440691, 3022796594, 2607846704, 163567449, 1396660245, 61235791, 73386979, 3569717]), FieldElement([628236075, 1776096883, 1596640373, 1237597377, 2238764922, 2503475385, 3619273576, 3366549089])]), FieldElement([2301743426,2075099376, 2969588298, 1793611799, 2457684815, 3951838026, 2737387451, 3754378978]), Point([FieldElement([1557300347, 3826368586, 2537306948, 1194350582, 2206313690, 2155850976, 910320597, 3536848074]), FieldElement([124257772, 3353686949, 2778858866, 3272416768, 3192211612, 670334657, 2786774514, 1334286332]), FieldElement([2312297066, 2925488368, 3267009695, 2498870966, 1732427718, 4239428087, 1550410695, 627716766])]); "0")]
#[test_case(Point([FieldElement([1557300347, 3826368586, 2537306948, 1194350582, 2206313690, 2155850976, 910320597, 3536848074]), FieldElement([124257772, 3353686949, 2778858866, 3272416768, 3192211612, 670334657, 2786774514, 1334286332]), FieldElement([2312297066, 2925488368, 3267009695, 2498870966, 1732427718, 4239428087, 1550410695, 627716766])]), FieldElement([2301743426,2075099376, 2969588298, 1793611799, 2457684815, 3951838026, 2737387451, 3754378978]), Point([FieldElement([3527372762, 3507857639, 1594370824, 3718082544, 2518725024, 2545775599, 1088522187, 1093635599]),FieldElement([3614258408, 1260438099, 1063020787, 456123286, 4107569356, 1151599969, 3890268877, 1968252526]), FieldElement([3558741386, 268995358, 367673520, 1545535419, 2508499329, 1109236387, 895079977, 1740167655])]); "1")]
#[test_case(Point([FieldElement([3527372762, 3507857639, 1594370824, 3718082544, 2518725024, 2545775599, 1088522187, 1093635599]), FieldElement([3614258408, 1260438099, 1063020787, 456123286, 4107569356, 1151599969, 3890268877, 1968252526]), FieldElement([3558741386, 268995358, 367673520, 1545535419, 2508499329, 1109236387, 895079977, 1740167655])]), FieldElement([2301743426,2075099376, 2969588298, 1793611799, 2457684815, 3951838026, 2737387451, 3754378978]), Point([FieldElement([3575801888, 1578089417, 2395624562, 564065581, 2066984214, 2348140603, 765785243, 3808292373]), FieldElement([361245020, 2527203120, 3484075690, 3129019989, 661091683, 2687745598, 4167871392, 778426466]), FieldElement([3338036891, 4208971587, 1993683533, 4189224997, 2780649411, 2819629975, 3646250205, 1195817501])]); "2")]
fn test_secp256k1_point_multiplication(src_point: Point, scalar: FieldElement, dst_point: Point) {
    let source = format!(
        "
    use std::math::secp256k1::group

    # Given an elliptic curve point ( in projective coordinate system ) and a 256 -bit scalar
    # in radix-2^32 form ( i.e. 8 limbs, each of 32 -bit width ), this routine first multiplies
    # the EC point with provided scalar and then asserts for correctness with known answer.
    @locals(52)
    proc point_multiplication_test_wrapper
        # resulting point
        locaddr.44
        locaddr.40
        locaddr.36
        locaddr.32
        locaddr.28
        locaddr.24

        # scalar
        push.{}.{}.{}.{}
        push.{}.{}.{}.{}

        # EC point
        push.{}.{}.{}.{}
        loc_storew_be.0
        dropw

        push.{}.{}.{}.{}
        loc_storew_be.4
        dropw

        push.{}.{}.{}.{}
        loc_storew_be.8
        dropw

        push.{}.{}.{}.{}
        loc_storew_be.12
        dropw

        push.{}.{}.{}.{}
        loc_storew_be.16
        dropw

        push.{}.{}.{}.{}
        loc_storew_be.20
        dropw

        locaddr.20
        locaddr.16
        locaddr.12
        locaddr.8
        locaddr.4
        locaddr.0

        # elliptic curve point multiplication
        exec.group::mul

        # --- start asserting X ---
        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert

        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        # --- end asserting X ---

        # --- start asserting Y ---
        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert

        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        # --- end asserting Y ---

        # --- start asserting Z ---
        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert

        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        # --- end asserting Z ---
    end

    begin
        exec.point_multiplication_test_wrapper
    end",
        scalar.0[7],
        scalar.0[6],
        scalar.0[5],
        scalar.0[4],
        scalar.0[3],
        scalar.0[2],
        scalar.0[1],
        scalar.0[0],
        src_point.0[0].0[3],
        src_point.0[0].0[2],
        src_point.0[0].0[1],
        src_point.0[0].0[0],
        src_point.0[0].0[7],
        src_point.0[0].0[6],
        src_point.0[0].0[5],
        src_point.0[0].0[4],
        src_point.0[1].0[3],
        src_point.0[1].0[2],
        src_point.0[1].0[1],
        src_point.0[1].0[0],
        src_point.0[1].0[7],
        src_point.0[1].0[6],
        src_point.0[1].0[5],
        src_point.0[1].0[4],
        src_point.0[2].0[3],
        src_point.0[2].0[2],
        src_point.0[2].0[1],
        src_point.0[2].0[0],
        src_point.0[2].0[7],
        src_point.0[2].0[6],
        src_point.0[2].0[5],
        src_point.0[2].0[4],
        dst_point.0[0].0[0],
        dst_point.0[0].0[1],
        dst_point.0[0].0[2],
        dst_point.0[0].0[3],
        dst_point.0[0].0[4],
        dst_point.0[0].0[5],
        dst_point.0[0].0[6],
        dst_point.0[0].0[7],
        dst_point.0[1].0[0],
        dst_point.0[1].0[1],
        dst_point.0[1].0[2],
        dst_point.0[1].0[3],
        dst_point.0[1].0[4],
        dst_point.0[1].0[5],
        dst_point.0[1].0[6],
        dst_point.0[1].0[7],
        dst_point.0[2].0[0],
        dst_point.0[2].0[1],
        dst_point.0[2].0[2],
        dst_point.0[2].0[3],
        dst_point.0[2].0[4],
        dst_point.0[2].0[5],
        dst_point.0[2].0[6],
        dst_point.0[2].0[7],
    );

    let test = build_test!(&source, &[]);
    assert!(test.execute().is_ok());
}

#[test_case(FieldElement([2301743426,2075099376, 2969588298, 1793611799, 2457684815, 3951838026, 2737387451, 3754378978]), Point([FieldElement([1096602412, 1336778744, 4237851429, 2379704491, 2174658910, 1179196601, 696486755, 2826869248]), FieldElement([3362845704, 129965728, 1311711770, 3674781461, 3620120701, 1257229422, 162674263, 1366999099]), FieldElement([440013615, 548226205, 868197170, 3947728772, 2287684084, 3056380747, 2298699306, 2987928230])]); "0")]
#[test_case(FieldElement([278420554, 274302291, 1226739346, 2847213784, 2559002059, 1576177591, 3232826642, 3734504736]), Point([FieldElement([2853151047, 507904927, 3967775652, 327717944, 4063402783, 1708337738, 2386716410, 3508073450]), FieldElement([2460268912, 1629689126, 1367585067, 3501806633, 3311638194, 667141611, 1619993686, 1135413519]), FieldElement([1479849294, 1358829318, 218593263, 1441654470, 4085241462, 916003429, 3637705774, 1404604942])]); "1")]
fn test_secp256k1_generator_multiplication(scalar: FieldElement, point: Point) {
    let source = format!(
        "
    use std::math::secp256k1::group

    # Given a 256 -bit scalar in radix-2^32 form ( i.e. 8 limbs, each of 32 -bit width ),
    # this routine first multiplies the secp256k1 generator point with provided scalar and
    # then asserts for correctness with known answer.
    @locals(48)
    proc generator_multiplication_test_wrapper
        # resulting point
        locaddr.44
        locaddr.40
        locaddr.36
        locaddr.32
        locaddr.28
        locaddr.24

        # scalar
        push.{}.{}.{}.{}
        push.{}.{}.{}.{}

        # elliptic curve generator point multiplication
        exec.group::gen_mul

        # --- start asserting X ---
        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert

        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        # --- end asserting X ---

        # --- start asserting Y ---
        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert

        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        # --- end asserting Y ---

        # --- start asserting Z ---
        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert

        push.0.0.0.0
        movup.4
        mem_loadw_be

        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        u32assert eq.{}
        assert
        # --- end asserting Z ---
    end

    begin
        exec.generator_multiplication_test_wrapper
    end",
        scalar.0[7],
        scalar.0[6],
        scalar.0[5],
        scalar.0[4],
        scalar.0[3],
        scalar.0[2],
        scalar.0[1],
        scalar.0[0],
        point.0[0].0[0],
        point.0[0].0[1],
        point.0[0].0[2],
        point.0[0].0[3],
        point.0[0].0[4],
        point.0[0].0[5],
        point.0[0].0[6],
        point.0[0].0[7],
        point.0[1].0[0],
        point.0[1].0[1],
        point.0[1].0[2],
        point.0[1].0[3],
        point.0[1].0[4],
        point.0[1].0[5],
        point.0[1].0[6],
        point.0[1].0[7],
        point.0[2].0[0],
        point.0[2].0[1],
        point.0[2].0[2],
        point.0[2].0[3],
        point.0[2].0[4],
        point.0[2].0[5],
        point.0[2].0[6],
        point.0[2].0[7],
    );

    let test = build_test!(&source, &[]);
    assert!(test.execute().is_ok());
}
