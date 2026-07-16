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
    z = f64::floor(x * (twoe63 as f64)) as u64;
    for cu in C.iter().skip(1) {
        let zy = (z as u128) * (y as u128);
        y = cu - ((zy >> 63) as u64);
    }

    z = f64::floor((twoe63 as f64) * ccs) as u64;

    (((z as u128) * (y as u128)) >> 63) as u64
}

/// A random bool that is true with probability ≈ ccs · exp(-x).
fn ber_exp<R: Rng>(x: f64, ccs: f64, rng: &mut R) -> bool {
    const LN2: f64 = core::f64::consts::LN_2;
    const ILN2: f64 = 1.0 / LN2;
    let s = f64::floor(x * ILN2);
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
/// (sigma).
pub(crate) fn sampler_z<R: Rng>(mu: f64, sigma: f64, sigma_min: f64, rng: &mut R) -> i16 {
    const SIGMA_MAX: f64 = 1.8205;
    const INV_2SIGMA_MAX_SQ: f64 = 1f64 / (2f64 * SIGMA_MAX * SIGMA_MAX);
    let isigma = 1f64 / sigma;
    let dss = 0.5f64 * isigma * isigma;
    let s = f64::floor(mu);
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
    use super::approx_exp;

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
