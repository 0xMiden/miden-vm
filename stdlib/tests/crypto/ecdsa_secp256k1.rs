use miden_utils_testing::test_case;

// Wrapper types for ease of writing parameterized test cases
struct ([u32; 8]);

type BaseField = ;
type ScalarField = ;

struct Point([BaseField; 3]);

/// Because this test is pretty expensive, it's by default ignored. If you're interested in
/// running this test, issue
///
/// cargo test --release -p miden-stdlib secp256k1 -- --include-ignored
///
/// from root directory of Miden repository.
///
/// What's being done in this routine is adapted from https://github.com/itzmeanjan/secp256k1/blob/37b339db3e03d24c2977399eb8896ef515ebb09b/test/test_ecdsa.py#L14-L16
#[test_case(Point([([1187647059, 1135132293, 1524607722, 3257770169, 1812770566, 4163599075, 3343690625, 2983146250])([694970425, 3961647168, 2962892522, 3871680339, 479244527, 2106589630, 3531004100, 487738481])([1718928786, 2222219308, 1537333708, 969814285, 1600645591, 2744076726, 1359599981, 1095895041])])([1915140291, 1682821516, 1088031394, 2866424576, 2852209138, 1159876682, 234168247, 3360002988])([1494159694, 3668493121, 2315165624, 353127114, 974571799, 2051320959, 3421809437, 3258836281])([1259054195, 60155476, 2236955964, 2106542718, 1332177784, 1407189293, 11489664, 3695133146]) ; "0")]
#[ignore]
fn verify(pubkey: Point, h: ScalarField, r: ScalarField, s: ScalarField) {
    let source = "
    use.std::crypto::dsa::ecdsa::secp256k1

    begin
        exec.secp256k1::verify
    end";

    let mut stack = [0u64; 48];

    // copy public key ( expressed in projective coordinate system )
    stack[0..8].copy_from_slice(&pubkey.0[0].0.iter().map(|v| *v as u64).collect::<Vec<u64>>());
    stack[8..16].copy_from_slice(&pubkey.0[1].0.iter().map(|v| *v as u64).collect::<Vec<u64>>());
    stack[16..24].copy_from_slice(&pubkey.0[2].0.iter().map(|v| *v as u64).collect::<Vec<u64>>());

    // copy hash of message
    stack[24..32].copy_from_slice(&h.0.iter().map(|v| *v as u64).collect::<Vec<u64>>());
    // copy `r` part of signature
    stack[32..40].copy_from_slice(&r.0.iter().map(|v| *v as u64).collect::<Vec<u64>>());
    // copy `s` part of signature
    stack[40..48].copy_from_slice(&s.0.iter().map(|v| *v as u64).collect::<Vec<u64>>());

    stack.reverse();

    let test = build_test!(source, &stack);
    assert!(test.execute().is_ok());
}
