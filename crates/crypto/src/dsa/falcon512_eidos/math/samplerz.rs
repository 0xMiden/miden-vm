use num::Float;
use rand::Rng;

/// Samples an integer from {0, ..., 18} according to the distribution χ, which is close to
/// the half-Gaussian distribution on the natural numbers with mean 0 and standard deviation
/// equal to sigma_max.
fn base_sampler(bytes: [u8; 9]) -> i16 {
    const RCDT: [u128; 18] = [
        3024686241123004913666,
        1564742784480091954050,
        636254429462080897535,
        199560484645026482916,
        47667343854657281903,
        8595902006365044063,
        1163297957344668388,
        117656387352093658,
        8867391802663976,
        496969357462633,
        20680885154299,
        638331848991,
        14602316184,
        247426747,
        3104126,
        28824,
        198,
        1,
    ];

    let mut bytes = bytes.to_vec();
    bytes.extend_from_slice(&[0u8; 7]);
    bytes.reverse();
    let u = u128::from_be_bytes(bytes.try_into().expect("should have length 16"));
    RCDT.into_iter().filter(|r| u < *r).count() as i16
}

/// Computes an integer approximation of 2^63 * ccs * exp(-x).
fn approx_exp(x: f64, ccs: f64) -> u64 {
    // The constants C are used to approximate exp(-x); these
    // constants are taken from FACCT (up to a scaling factor
    // of 2^63):
    //   <https://eprint.iacr.org/2018/1234>
    //   <https://github.com/raykzhao/gaussian>
    const C: [u64; 13] = [
        0x00000004741183a3u64,
        0x00000036548cfc06u64,
        0x0000024fdcbf140au64,
        0x0000171d939de045u64,
        0x0000d00cf58f6f84u64,
        0x000680681cf796e3u64,
        0x002d82d8305b0feau64,
        0x011111110e066fd0u64,
        0x0555555555070f00u64,
        0x155555555581ff00u64,
        0x400000000002b400u64,
        0x7fffffffffff4800u64,
        0x8000000000000000u64,
    ];

    let mut z: u64;
    let mut y: u64;
    let twoe63 = 1u64 << 63;

    y = C[0];
    z = Float::floor(x * (twoe63 as f64)) as u64;
    for cu in C.iter().skip(1) {
        let zy = (z as u128) * (y as u128);
        y = cu - ((zy >> 63) as u64);
    }

    z = Float::floor((twoe63 as f64) * ccs) as u64;

    (((z as u128) * (y as u128)) >> 63) as u64
}

/// A random bool that is true with probability ≈ ccs · exp(-x).
fn ber_exp<R: Rng>(x: f64, ccs: f64, rng: &mut R) -> bool {
    const LN2: f64 = core::f64::consts::LN_2;
    const ILN2: f64 = 1.0 / LN2;
    let s = Float::floor(x * ILN2);
    let r = x - s * LN2;
    let s = (s as u64).min(63);
    let z = ((approx_exp(r, ccs) << 1) - 1) >> s;

    let mut w = 0_i32;
    for i in (0..=56).rev().step_by(8) {
        let mut dest = [0_u8; 1];
        rng.fill_bytes(&mut dest);
        let p = u8::from_be_bytes(dest);
        w = (p as i32) - (z >> i & 0xff) as i32;
        if w != 0 {
            break;
        }
    }
    w < 0
}

/// Samples an integer from the Gaussian distribution with given mean (mu) and standard deviation
/// (sigma) -- SamplerZ, Algorithm 15 of the Falcon specification (which uses Algorithms 12-14).
///
/// `sigma_min / sigma` scales the acceptance probability, which helps make the running time
/// independent of sigma; `sigma` must lie in [sigma_min, SIGMA_MAX = 1.8205].
///
/// Byte-consumption contract with `rng` (pinned by the reference known-answer test below): each
/// rejection-loop attempt draws 9 bytes for the base sampler, 1 byte for the sign, then
/// [`ber_exp`] draws up to 8 further bytes one at a time, most significant comparison first.
pub(crate) fn sampler_z<R: Rng>(mu: f64, sigma: f64, sigma_min: f64, rng: &mut R) -> i16 {
    const SIGMA_MAX: f64 = 1.8205;
    const INV_2SIGMA_MAX_SQ: f64 = 1f64 / (2f64 * SIGMA_MAX * SIGMA_MAX);
    let isigma = 1f64 / sigma;
    let dss = 0.5f64 * isigma * isigma;
    let s = Float::floor(mu);
    let r = mu - s;
    let ccs = sigma_min * isigma;
    loop {
        let mut dest = [0_u8; 9];
        rng.fill_bytes(&mut dest);
        let z0 = base_sampler(dest);

        let mut dest = [0_u8; 1];
        rng.fill_bytes(&mut dest);
        let random_byte: u8 = dest[0];

        // x = ((z-r)^2)/(2*sigma^2) - ((z-b)^2)/(2*sigma0^2)
        let b = (random_byte & 1) as i16;
        let z = b + (2 * b - 1) * z0;
        let zf_min_r = (z as f64) - r;
        let x = zf_min_r * zf_min_r * dss - (z0 * z0) as f64 * INV_2SIGMA_MAX_SQ;

        if ber_exp(x, ccs, rng) {
            return z + (s as i16);
        }
    }
}

#[cfg(test)]
mod test {
    use alloc::vec::Vec;

    use rand::rand_core::{Infallible, TryRng, utils};

    use super::{approx_exp, base_sampler, ber_exp, sampler_z};

    /// Replays a fixed byte string, panicking if the sampler requests more bytes than the vector
    /// provides.
    struct ReplayRng {
        bytes: Vec<u8>,
        cursor: usize,
    }

    impl ReplayRng {
        fn from_bytes(bytes: Vec<u8>) -> Self {
            Self { bytes, cursor: 0 }
        }

        fn new(hex: &str) -> Self {
            let bytes = hex::decode(hex).expect("KAT randomness must be valid hexadecimal");
            Self { bytes, cursor: 0 }
        }

        fn fill(&mut self, dest: &mut [u8]) {
            let end = self.cursor + dest.len();
            assert!(end <= self.bytes.len(), "sampler requested more bytes than the KAT provides");
            dest.copy_from_slice(&self.bytes[self.cursor..end]);
            // Convention bridge: the upstream KAT file serializes each 72-bit base-sampler draw
            // big-endian (first hex byte most significant). The samplers themselves -- falcon.py,
            // the C reference's `(hi << 64) | lo`, and this port -- all treat the last of the 9
            // drawn bytes as most significant, and falcon.py's own KAT harness performs exactly
            // this per-draw reversal before feeding its sampler. The 1-byte sign and ber_exp
            // draws are order-invariant.
            if dest.len() == 9 {
                dest.reverse();
            }
            self.cursor = end;
        }
    }

    impl TryRng for ReplayRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            utils::next_word_via_fill::<u32, _>(self)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            utils::next_u64_via_u32(self)
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            self.fill(dest);
            Ok(())
        }
    }

    /// Drives ber_exp's lexicographic comparison to every depth from 1 to 8: with the first
    /// k - 1 comparison bytes tying z's, the decision lands on byte k. The KAT vectors all
    /// decide on the first byte, so without this a corruption confined to a deeper comparison
    /// byte survives every other test in the crate (mutation-confirmed).
    #[test]
    fn ber_exp_decides_at_every_comparison_depth() {
        // Parameters chosen so s = floor(x / ln 2) = 0 and every comparison byte of z is
        // strictly interior; the assert below makes any platform float drift loud instead of
        // silently weakening the test.
        let (x, ccs) = (0.3f64, 0.7f64);
        let z = (approx_exp(x, ccs) << 1) - 1;
        let z_bytes = z.to_be_bytes().to_vec();
        assert!(
            z_bytes.iter().all(|&b| b > 0x00 && b < 0xff),
            "test parameters must give interior comparison bytes: {z_bytes:?}"
        );

        for depth in 1..=8usize {
            let mut accept = z_bytes[..depth - 1].to_vec();
            accept.push(z_bytes[depth - 1] - 1);
            let mut rng = ReplayRng::from_bytes(accept);
            assert!(ber_exp(x, ccs, &mut rng), "must accept at depth {depth}");
            assert_eq!(rng.cursor, depth, "accept must consume exactly {depth} bytes");

            let mut reject = z_bytes[..depth - 1].to_vec();
            reject.push(z_bytes[depth - 1] + 1);
            let mut rng = ReplayRng::from_bytes(reject);
            assert!(!ber_exp(x, ccs, &mut rng), "must reject at depth {depth}");
            assert_eq!(rng.cursor, depth, "reject must consume exactly {depth} bytes");
        }

        // A full eight-byte tie leaves w = 0, which rejects.
        let mut rng = ReplayRng::from_bytes(z_bytes);
        assert!(!ber_exp(x, ccs, &mut rng), "a full tie must reject");
        assert_eq!(rng.cursor, 8);
    }

    /// Boundary check for every RCDT threshold, in the spirit of the C reference's sampler
    /// tests: a draw of exactly `RCDT[k]` must sample `k` (only the thresholds above index `k`
    /// exceed it), and `RCDT[k] - 1` must sample `k + 1`. The KAT vectors below only reach
    /// z0 in {0..3}, so this is what pins the table's lower fourteen thresholds. The expected
    /// thresholds are repeated here deliberately: changing either listing alone breaks the test.
    #[test]
    fn base_sampler_respects_every_rcdt_threshold_boundary() {
        const RCDT_PIN: [u128; 18] = [
            3024686241123004913666,
            1564742784480091954050,
            636254429462080897535,
            199560484645026482916,
            47667343854657281903,
            8595902006365044063,
            1163297957344668388,
            117656387352093658,
            8867391802663976,
            496969357462633,
            20680885154299,
            638331848991,
            14602316184,
            247426747,
            3104126,
            28824,
            198,
            1,
        ];

        let draw = |u: u128| {
            let mut bytes = [0u8; 9];
            bytes.copy_from_slice(&u.to_le_bytes()[..9]);
            base_sampler(bytes)
        };

        assert_eq!(draw(0), 18, "u = 0 lies below every threshold");
        assert_eq!(draw((1u128 << 72) - 1), 0, "the maximal draw lies above every threshold");
        for (k, threshold) in RCDT_PIN.into_iter().enumerate() {
            assert_eq!(draw(threshold), k as i16, "u = RCDT[{k}] must sample {k}");
            assert_eq!(draw(threshold - 1), k as i16 + 1, "u = RCDT[{k}] - 1 must sample {k}+1");
        }
    }

    /// Known-answer vectors for SamplerZ from the Falcon reference material
    /// (tprest/falcon.py, `scripts/samplerz_KAT512.py`, mirroring the vectors accompanying the
    /// specification). `octets` is the upstream KAT serialization of the randomness consumed
    /// across all rejection iterations (big-endian per 72-bit base draw); the replay applies the
    /// same per-draw reversal the upstream harness does, so this pins the base-sampler
    /// thresholds it reaches, the first-byte acceptance decisions, and the byte-consumption
    /// order in one check. Every vector decides on ber_exp's first comparison byte; the dedicated
    /// depth test covers the deeper comparisons.
    #[test]
    fn sampler_z_matches_reference_known_answers() {
        #[rustfmt::skip]
        let kats: [(f64, f64, f64, &str, i16); 8] = [
            (-91.90471153063714, 1.7037990414754918, 1.2778336969128337,
             "0FC5442FF043D66E91D1EACAC64EA5450A22941EDC6C", -92),
            (-8.322564895434937, 1.7037990414754918, 1.2778336969128337,
             "F4DA0F8D8444D1A77265C2EF6F98BBBB4BEE7DB8D9B3", -8),
            (-19.096516109216804, 1.7035823083824078, 1.2778336969128334,
             "DB47F6D7FB9B19F25C36D6B9334D477A8BC0BE68145D", -20),
            (-11.335543982423326, 1.7035823083824078, 1.2778336969128334,
             "AE41B4F5209665C74D00DCC1A8168A7BB516B3190CB42C1DED26CD52AED770ECA7DD334E0547BCC3C163CE0B", -12),
            (7.9386734193997555, 1.6984647769450156, 1.2778336969128337,
             "31054166C1012780C603AE9B833CEC73F2F41CA5807CC89C92158834632F9B1555", 8),
            (-28.990850086867255, 1.6984647769450156, 1.2778336969128337,
             "737E9D68A50A06DBBC6477", -30),
            (-9.071257914091655, 1.6980782114808988, 1.2778336969128339,
             "A98DDD14BF0BF22061D632", -10),
            (-43.88754568839566, 1.6980782114808988, 1.2778336969128339,
             "3CBF6818A68F7AB9991514", -41),
        ];

        for (mu, sigma, sigma_min, octets, expected_z) in kats {
            let mut rng = ReplayRng::new(octets);
            let z = sampler_z(mu, sigma, sigma_min, &mut rng);
            assert_eq!(z, expected_z, "wrong sample for mu = {mu}");
            assert_eq!(rng.cursor, rng.bytes.len(), "sampler left unused KAT bytes for mu = {mu}");
        }
    }

    #[test]
    fn test_approx_exp() {
        let precision = 1u64 << 14;
        // known answers were generated with the following sage script:
        //```sage
        // num_samples = 10
        // precision = 200
        // R = Reals(precision)
        //
        // print(f"let kats : [(f64, f64, u64);{num_samples}] = [")
        // for i in range(num_samples):
        //     x = RDF.random_element(0.0, 0.693147180559945)
        //     ccs = RDF.random_element(0.0, 1.0)
        //     res = round(2^63 * R(ccs) * exp(R(-x)))
        //     print(f"({x}, {ccs}, {res}),")
        // print("];")
        // ```
        let kats: [(f64, f64, u64); 10] = [
            (0.2314993926072656, 0.8148006314615972, 5962140072160879737),
            (0.2648875572812225, 0.12769669655309035, 903712282351034505),
            (0.11251957513682391, 0.9264611470305881, 7635725498677341553),
            (0.04353439307256617, 0.5306497137523327, 4685877322232397936),
            (0.41834495299784347, 0.879438856118578, 5338392138535350986),
            (0.32579398973228557, 0.16513412873289002, 1099603299296456803),
            (0.5939508073919817, 0.029776019144967303, 151637565622779016),
            (0.2932367999399056, 0.37123847662857923, 2553827649386670452),
            (0.5005699297417507, 0.31447208863888976, 1758235618083658825),
            (0.4876437338498085, 0.6159515298936868, 3488632981903743976),
        ];
        for (x, ccs, answer) in kats {
            let difference = (answer as i128) - (approx_exp(x, ccs) as i128);
            assert!(
                (difference * difference) as u64 <= precision * precision,
                "answer: {answer} versus approximation: {}\ndifference: {} whereas precision: {}",
                approx_exp(x, ccs),
                difference,
                precision
            );
        }
    }
}
