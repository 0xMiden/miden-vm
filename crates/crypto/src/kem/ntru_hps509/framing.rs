use crate::{
    Felt, Word,
    hash::eidos::{Eidos, domains::NTRU_HPS509_EIDOS},
    utils::zeroize::Zeroizing,
};

pub(crate) const MAGIC: u64 = 0x4e545255;
pub(crate) const KEM: u32 = 1;
pub(crate) const FALLBACK: u32 = 2;
pub(crate) const CONTEXT: u32 = 5;
pub(crate) const KEY: u32 = 7;
pub(crate) const CIPHERTEXT: u32 = 8;
pub(crate) const NONCE: u32 = 10;
pub(crate) const BYTE_CONTEXT: u32 = 11;

pub(crate) type SecretDigest = Zeroizing<[u64; 4]>;

pub(crate) fn felt(value: u64) -> Felt {
    Felt::new(value).expect("canonical field element")
}

pub(crate) fn fields(role: u32, input: &[Felt]) -> Word {
    Word::new(hash(role, input.len(), input.iter().map(Felt::as_canonical_u64)).map(felt))
}

pub(crate) fn packed_bytes(input: &[u8]) -> impl Iterator<Item = Felt> + '_ {
    packed_u32s(input).map(felt)
}

pub(crate) fn bytes(role: u32, input: &[u8]) -> Word {
    Word::new(secret_bytes(role, input).map(felt))
}

pub(crate) fn secret_fields(role: u32, input: &[u64]) -> SecretDigest {
    hash(role, input.len(), input.iter().copied())
}

pub(crate) fn secret_bytes(role: u32, input: &[u8]) -> SecretDigest {
    hash(role, input.len(), packed_u32s(input))
}

fn packed_u32s(input: &[u8]) -> impl Iterator<Item = u64> + '_ {
    input.chunks(4).map(|chunk| {
        chunk
            .iter()
            .enumerate()
            .fold(0, |word, (i, &byte)| word | (u64::from(byte) << (8 * i)))
    })
}

// Each role fixes its input type: len counts bytes for byte roles and Felts otherwise.
// The initial CV binds both role and length. Zero-pad a partial eight-Felt block;
// even an empty input gets one compression.
fn hash(role: u32, len: usize, input: impl Iterator<Item = u64>) -> SecretDigest {
    let len = u32::try_from(len).expect("input length must fit in u32");
    let initial = Eidos::init_chaining_word_with_params(NTRU_HPS509_EIDOS, [role, len, 0]);
    let mut cv = Zeroizing::new(initial.into_elements().map(|x| x.as_canonical_u64()));
    let mut block = Zeroizing::new([0; 8]);
    let mut used = 0;
    for value in input {
        block[used] = value;
        used += 1;
        if used == 8 {
            *cv = Eidos::compress(Word::new(cv.map(felt)), block.map(felt))
                .into_elements()
                .map(|x| x.as_canonical_u64());
            block.fill(0);
            used = 0;
        }
    }
    if used != 0 || len == 0 {
        *cv = Eidos::compress(Word::new(cv.map(felt)), block.map(felt))
            .into_elements()
            .map(|x| x.as_canonical_u64());
    }
    cv
}
