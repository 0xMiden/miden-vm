use alloc::vec::Vec;

use super::{Error, Result};

// Encode a u64 value to `buf` as a variable-length integer
pub fn encode(mut value: u64, buf: &mut Vec<u8>) {
    loop {
        if value < 0x80 {
            buf.push(value as u8);
            break;
        }
        buf.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
}

// Decode a variable-length encoded integer as a u64 from `buf`
pub fn decode(buf: &[u8], pos: &mut usize) -> Result<u64> {
    let mut result = 0u64;
    let mut shift = 0;

    loop {
        if *pos >= buf.len() {
            return Err(Error::UnexpectedEof);
        }

        let byte = buf[*pos];
        *pos += 1;

        result |= ((byte & 0x7f) as u64) << shift;

        if byte & 0x80 == 0 {
            return Ok(result);
        }

        shift += 7;
        if shift >= 64 {
            return Err(Error::InvalidVarint);
        }
    }
}
