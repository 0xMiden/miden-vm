// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#[cfg(feature = "std")]
use alloc::string::ToString;
use alloc::{format, string::String, vec::Vec};
#[cfg(feature = "std")]
use core::cell::{Ref, RefCell};
#[cfg(feature = "std")]
use std::io::BufRead;

use crate::{Deserializable, DeserializationError};

// BYTE READER TRAIT
// ================================================================================================

/// Defines how primitive values are to be read from `Self`.
///
/// Whenever data is read from the reader using any of the `read_*` functions, the reader advances
/// to the next unread byte. If the error occurs, the reader is not rolled back to the state prior
/// to calling any of the function.
pub trait ByteReader {
    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns a single byte read from `self`.
    ///
    /// # Errors
    /// Returns a [DeserializationError] error the reader is at EOF.
    fn read_u8(&mut self) -> Result<u8, DeserializationError>;

    /// Returns the next byte to be read from `self` without advancing the reader to the next byte.
    ///
    /// # Errors
    /// Returns a [DeserializationError] error the reader is at EOF.
    fn peek_u8(&self) -> Result<u8, DeserializationError>;

    /// Returns a slice of bytes of the specified length read from `self`.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a slice of the specified length could not be read
    /// from `self`.
    fn read_slice(&mut self, len: usize) -> Result<&[u8], DeserializationError>;

    /// Returns a byte array of length `N` read from `self`.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if an array of the specified length could not be read
    /// from `self`.
    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError>;

    /// Checks if it is possible to read at least `num_bytes` bytes from this ByteReader
    ///
    /// # Errors
    /// Returns an error if, when reading the requested number of bytes, we go beyond the
    /// the data available in the reader.
    fn check_eor(&self, num_bytes: usize) -> Result<(), DeserializationError>;

    /// Returns true if there are more bytes left to be read from `self`.
    fn has_more_bytes(&self) -> bool;

    /// Returns the maximum number of elements that can be safely allocated, given each
    /// element occupies `element_size` bytes when serialized.
    ///
    /// This can be used by callers to pre-validate collection lengths before iterating,
    /// preventing denial-of-service attacks from malicious length prefixes that claim
    /// billions of elements.
    ///
    /// The default implementation returns `usize::MAX`, meaning no limit is enforced.
    /// [`BudgetedReader`] overrides this to return `remaining_budget / element_size`,
    /// providing tight, adaptive limits based on the caller's budget.
    ///
    /// # Arguments
    /// * `element_size` - The serialized size of one element, from
    ///   [`Deserializable::min_serialized_size`]. Defaults to `size_of::<D>()` but can be
    ///   overridden for types where serialized size differs from in-memory size.
    fn max_alloc(&self, _element_size: usize) -> usize {
        usize::MAX
    }

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns a boolean value read from `self` consuming 1 byte from the reader.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a u16 value could not be read from `self`.
    fn read_bool(&mut self) -> Result<bool, DeserializationError> {
        let byte = self.read_u8()?;
        match byte {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DeserializationError::InvalidValue(format!("{byte} is not a boolean value"))),
        }
    }

    /// Returns a u16 value read from `self` in little-endian byte order.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a u16 value could not be read from `self`.
    fn read_u16(&mut self) -> Result<u16, DeserializationError> {
        let bytes = self.read_array::<2>()?;
        Ok(u16::from_le_bytes(bytes))
    }

    /// Returns a u32 value read from `self` in little-endian byte order.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a u32 value could not be read from `self`.
    fn read_u32(&mut self) -> Result<u32, DeserializationError> {
        let bytes = self.read_array::<4>()?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Returns a u64 value read from `self` in little-endian byte order.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a u64 value could not be read from `self`.
    fn read_u64(&mut self) -> Result<u64, DeserializationError> {
        let bytes = self.read_array::<8>()?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Returns a u128 value read from `self` in little-endian byte order.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a u128 value could not be read from `self`.
    fn read_u128(&mut self) -> Result<u128, DeserializationError> {
        let bytes = self.read_array::<16>()?;
        Ok(u128::from_le_bytes(bytes))
    }

    /// Returns a usize value read from `self` in [vint64](https://docs.rs/vint64/latest/vint64/)
    /// format.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if:
    /// * usize value could not be read from `self`.
    /// * encoded value is greater than `usize` maximum value on a given platform.
    fn read_usize(&mut self) -> Result<usize, DeserializationError> {
        let first_byte = self.peek_u8()?;
        let length = first_byte.trailing_zeros() as usize + 1;

        let result = if length == 9 {
            // 9-byte special case
            self.read_u8()?;
            let value = self.read_array::<8>()?;
            u64::from_le_bytes(value)
        } else {
            let mut encoded = [0u8; 8];
            let value = self.read_slice(length)?;
            encoded[..length].copy_from_slice(value);
            u64::from_le_bytes(encoded) >> length
        };

        // check if the result value is within acceptable bounds for `usize` on a given platform
        if result > usize::MAX as u64 {
            return Err(DeserializationError::InvalidValue(format!(
                "Encoded value must be less than {}, but {} was provided",
                usize::MAX,
                result
            )));
        }

        Ok(result as usize)
    }

    /// Returns a byte vector of the specified length read from `self`.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a vector of the specified length could not be read
    /// from `self`.
    fn read_vec(&mut self, len: usize) -> Result<Vec<u8>, DeserializationError> {
        let data = self.read_slice(len)?;
        Ok(data.to_vec())
    }

    /// Returns a String of the specified length read from `self`.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a String of the specified length could not be read
    /// from `self`.
    fn read_string(&mut self, num_bytes: usize) -> Result<String, DeserializationError> {
        let data = self.read_vec(num_bytes)?;
        String::from_utf8(data).map_err(|err| DeserializationError::InvalidValue(format!("{err}")))
    }

    /// Reads a deserializable value from `self`.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if the specified value could not be read from `self`.
    fn read<D>(&mut self) -> Result<D, DeserializationError>
    where
        Self: Sized,
        D: Deserializable,
    {
        D::read_from(self)
    }

    /// Returns an iterator that deserializes `num_elements` instances of `D` from this reader.
    ///
    /// This method validates the requested count against the reader's capacity before returning
    /// the iterator, rejecting implausible lengths early. Each element is then deserialized
    /// lazily as the iterator is consumed.
    ///
    /// # Errors
    ///
    /// Returns an error if `num_elements` exceeds `self.max_alloc(D::min_serialized_size())`,
    /// indicating the reader cannot allocate that many elements.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Collect into a Vec
    /// let items: Vec<u64> = reader
    ///     .read_many_iter::<u64>(count)?
    ///     .collect::<Result<_, _>>()?;
    ///
    /// // Collect directly into a BTreeMap (no intermediate Vec)
    /// let map: BTreeMap<K, V> = reader
    ///     .read_many_iter::<(K, V)>(count)?
    ///     .collect::<Result<_, _>>()?;
    /// ```
    fn read_many_iter<D>(
        &mut self,
        num_elements: usize,
    ) -> Result<ReadManyIter<'_, Self, D>, DeserializationError>
    where
        Self: Sized,
        D: Deserializable,
    {
        let max_elements = self.max_alloc(D::min_serialized_size());
        if num_elements > max_elements {
            return Err(DeserializationError::InvalidValue(format!(
                "requested {num_elements} elements but reader can provide at most {max_elements}"
            )));
        }
        Ok(ReadManyIter {
            reader: self,
            remaining: num_elements,
            _item: core::marker::PhantomData,
        })
    }
}

// READ MANY ITERATOR
// ================================================================================================

/// Iterator that lazily deserializes elements from a [`ByteReader`].
///
/// Created by [`ByteReader::read_many_iter`]. Each call to `next()` deserializes one element.
/// This avoids upfront allocation and naturally integrates with [`BudgetedReader`] for
/// protection against malicious inputs.
pub struct ReadManyIter<'reader, R: ByteReader, D: Deserializable> {
    reader: &'reader mut R,
    remaining: usize,
    _item: core::marker::PhantomData<D>,
}

impl<'reader, R: ByteReader, D: Deserializable> Iterator for ReadManyIter<'reader, R, D> {
    type Item = Result<D, DeserializationError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining > 0 {
            self.remaining -= 1;
            Some(D::read_from(self.reader))
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.remaining))
    }
}

// STANDARD LIBRARY ADAPTER
// ================================================================================================

/// An adapter of [ByteReader] to any type that implements [std::io::Read]
///
/// In particular, this covers things like [std::fs::File], standard input, etc.
#[cfg(feature = "std")]
pub struct ReadAdapter<'a> {
    // NOTE: The [ByteReader] trait does not currently support reader implementations that require
    // mutation during `peek_u8`, `has_more_bytes`, and `check_eor`. These (or equivalent)
    // operations on the standard library [std::io::BufRead] trait require a mutable reference, as
    // it may be necessary to read from the underlying input to implement them.
    //
    // To handle this, we wrap the underlying reader in an [RefCell], this allows us to mutate the
    // reader if necessary during a call to one of the above-mentioned trait methods, without
    // sacrificing safety - at the cost of enforcing Rust's borrowing semantics dynamically.
    //
    // This should not be a problem in practice, except in the case where `read_slice` is called,
    // and the reference returned is from `reader` directly, rather than `buf`. If a call to one
    // of the above-mentioned methods is made while that reference is live, and we attempt to read
    // from `reader`, a panic will occur.
    //
    // Ultimately, this should be addressed by making the [ByteReader] trait align with the
    // standard library I/O traits, so this is a temporary solution.
    reader: RefCell<std::io::BufReader<&'a mut dyn std::io::Read>>,
    // A temporary buffer to store chunks read from `reader` that are larger than what is required
    // for the higher-level [ByteReader] APIs.
    //
    // By default we attempt to satisfy reads from `reader` directly, but that is not always
    // possible.
    buf: Vec<u8>,
    // The position in `buf` at which we should start reading the next byte, when `buf` is
    // non-empty.
    pos: usize,
    // This is set when we attempt to read from `reader` and get an empty buffer. This indicates
    // that once we exhaust `buf`, we have truly reached end-of-file.
    //
    // We will use this to more accurately handle functions like `has_more_bytes` when this is set.
    guaranteed_eof: bool,
}

#[cfg(feature = "std")]
impl<'a> ReadAdapter<'a> {
    /// Create a new [ByteReader] adapter for the given implementation of [std::io::Read]
    pub fn new(reader: &'a mut dyn std::io::Read) -> Self {
        Self {
            reader: RefCell::new(std::io::BufReader::with_capacity(256, reader)),
            buf: Default::default(),
            pos: 0,
            guaranteed_eof: false,
        }
    }

    /// Get the internal adapter buffer as a (possibly empty) slice of bytes
    #[inline(always)]
    fn buffer(&self) -> &[u8] {
        self.buf.get(self.pos..).unwrap_or(&[])
    }

    /// Get the internal adapter buffer as a slice of bytes, or `None` if the buffer is empty
    #[inline(always)]
    fn non_empty_buffer(&self) -> Option<&[u8]> {
        self.buf.get(self.pos..).filter(|b| !b.is_empty())
    }

    /// Return the current reader buffer as a (possibly empty) slice of bytes.
    ///
    /// This buffer being empty _does not_ mean we're at EOF, you must call
    /// [non_empty_reader_buffer_mut] first.
    #[inline(always)]
    fn reader_buffer(&self) -> Ref<'_, [u8]> {
        Ref::map(self.reader.borrow(), |r| r.buffer())
    }

    /// Return the current reader buffer, reading from the underlying reader
    /// if the buffer is empty.
    ///
    /// Returns `Ok` only if the buffer is non-empty, and no errors occurred
    /// while filling it (if filling was needed).
    fn non_empty_reader_buffer_mut(&mut self) -> Result<&[u8], DeserializationError> {
        use std::io::ErrorKind;
        let buf = self.reader.get_mut().fill_buf().map_err(|e| match e.kind() {
            ErrorKind::UnexpectedEof => DeserializationError::UnexpectedEOF,
            e => DeserializationError::UnknownError(e.to_string()),
        })?;
        if buf.is_empty() {
            self.guaranteed_eof = true;
            Err(DeserializationError::UnexpectedEOF)
        } else {
            Ok(buf)
        }
    }

    /// Same as [non_empty_reader_buffer_mut], but with dynamically-enforced
    /// borrow check rules so that it can be called in functions like `peek_u8`.
    ///
    /// This comes with overhead for the dynamic checks, so you should prefer
    /// to call [non_empty_reader_buffer_mut] if you already have a mutable
    /// reference to `self`
    fn non_empty_reader_buffer(&self) -> Result<Ref<'_, [u8]>, DeserializationError> {
        use std::io::ErrorKind;
        let mut reader = self.reader.borrow_mut();
        let buf = reader.fill_buf().map_err(|e| match e.kind() {
            ErrorKind::UnexpectedEof => DeserializationError::UnexpectedEOF,
            e => DeserializationError::UnknownError(e.to_string()),
        })?;
        if buf.is_empty() {
            Err(DeserializationError::UnexpectedEOF)
        } else {
            // Re-borrow immutably
            drop(reader);
            Ok(self.reader_buffer())
        }
    }

    /// Returns true if there is sufficient capacity remaining in `buf` to hold `n` bytes
    #[inline]
    fn has_remaining_capacity(&self, n: usize) -> bool {
        let remaining = self.buf.capacity() - self.buffer().len();
        remaining >= n
    }

    /// Takes the next byte from the input, returning an error if the operation fails
    fn pop(&mut self) -> Result<u8, DeserializationError> {
        if let Some(byte) = self.non_empty_buffer().map(|b| b[0]) {
            self.pos += 1;
            return Ok(byte);
        }
        let result = self.non_empty_reader_buffer_mut().map(|b| b[0]);
        if result.is_ok() {
            self.reader.get_mut().consume(1);
        } else {
            self.guaranteed_eof = true;
        }
        result
    }

    /// Takes the next `N` bytes from the input as an array, returning an error if the operation
    /// fails
    fn read_exact<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError> {
        let mut output = [0; N];
        let buf = self.buffer();

        if buf.len() >= N {
            output.copy_from_slice(&buf[..N]);
            self.pos += N;

            if self.buffer().is_empty() {
                unsafe {
                    self.buf.set_len(0);
                }
                self.pos = 0;
            }

            return Ok(output);
        }

        if buf.is_empty() {
            let reader_buf = self.non_empty_reader_buffer_mut()?;
            if reader_buf.len() >= N {
                output.copy_from_slice(&reader_buf[..N]);
                self.reader.get_mut().consume(N);
                return Ok(output);
            }
        }

        output.copy_from_slice(<Self as ByteReader>::read_slice(self, N)?);
        Ok(output)
    }

    /// Fill `self.buf` with `count` bytes
    ///
    /// This should only be called when we can't read from the reader directly
    fn buffer_at_least(&mut self, count: usize) -> Result<(), DeserializationError> {
        // Read until we have at least `count` bytes, or until we reach end-of-file,
        // which ever comes first.
        loop {
            // If we have successfully read `count` bytes, we're done
            if self.buffer().len() >= count {
                break Ok(());
            }

            // This operation will return an error if the underlying reader hits EOF
            self.non_empty_reader_buffer_mut()?;

            // Extend `self.buf` with the bytes read from the underlying reader.
            //
            // NOTE: We have to re-borrow the reader buffer here, since we can't get a mutable
            // reference to `self.buf` while holding an immutable reference to the reader buffer.
            let reader = self.reader.get_mut();
            let buf = reader.buffer();
            let consumed = buf.len();
            self.buf.extend_from_slice(buf);
            reader.consume(consumed);
        }
    }
}

#[cfg(feature = "std")]
impl ByteReader for ReadAdapter<'_> {
    #[inline(always)]
    fn read_u8(&mut self) -> Result<u8, DeserializationError> {
        self.pop()
    }

    /// NOTE: If we happen to not have any bytes buffered yet when this is called, then we will be
    /// forced to try and read from the underlying reader. This requires a mutable reference, which
    /// is obtained dynamically via [RefCell].
    ///
    /// <div class="warning">
    /// Callers must ensure that they do not hold any immutable references to the buffer of this
    /// reader when calling this function so as to avoid a situation in which the dynamic borrow
    /// check fails. Specifically, you must not be holding a reference to the result of
    /// [Self::read_slice] when this function is called.
    /// </div>
    fn peek_u8(&self) -> Result<u8, DeserializationError> {
        if let Some(byte) = self.buffer().first() {
            return Ok(*byte);
        }
        self.non_empty_reader_buffer().map(|b| b[0])
    }

    fn read_slice(&mut self, len: usize) -> Result<&[u8], DeserializationError> {
        // Edge case
        if len == 0 {
            return Ok(&[]);
        }

        // If we have unused buffer, and the consumed portion is
        // large enough, we will move the unused portion of the buffer
        // to the start, freeing up bytes at the end for more reads
        // before forcing a reallocation
        let should_optimize_storage = self.pos >= 16 && !self.has_remaining_capacity(len);
        if should_optimize_storage {
            // We're going to optimize storage first
            let buf = self.buffer();
            let src = buf.as_ptr();
            let count = buf.len();
            let dst = self.buf.as_mut_ptr();
            unsafe {
                core::ptr::copy(src, dst, count);
                self.buf.set_len(count);
                self.pos = 0;
            }
        }

        // Fill the buffer so we have at least `len` bytes available,
        // this will return an error if we hit EOF first
        self.buffer_at_least(len)?;

        let slice = &self.buf[self.pos..(self.pos + len)];
        self.pos += len;
        Ok(slice)
    }

    #[inline]
    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError> {
        if N == 0 {
            return Ok([0; N]);
        }
        self.read_exact()
    }

    fn check_eor(&self, num_bytes: usize) -> Result<(), DeserializationError> {
        // Do we have sufficient data in the local buffer?
        let buffer_len = self.buffer().len();
        if buffer_len >= num_bytes {
            return Ok(());
        }

        // What about if we include what is in the local buffer and the reader's buffer?
        let reader_buffer_len = self.non_empty_reader_buffer().map(|b| b.len())?;
        let buffer_len = buffer_len + reader_buffer_len;
        if buffer_len >= num_bytes {
            return Ok(());
        }

        // We have no more input, thus can't fulfill a request of `num_bytes`
        if self.guaranteed_eof {
            return Err(DeserializationError::UnexpectedEOF);
        }

        // Because this function is read-only, we must optimistically assume we can read `num_bytes`
        // from the input, and fail later if that does not hold. We know we're not at EOF yet, but
        // that's all we can say without buffering more from the reader. We could make use of
        // `buffer_at_least`, which would guarantee a correct result, but it would also impose
        // additional restrictions on the use of this function, e.g. not using it while holding a
        // reference returned from `read_slice`. Since it is not a memory safety violation to return
        // an optimistic result here, it makes for a better tradeoff.
        Ok(())
    }

    #[inline]
    fn has_more_bytes(&self) -> bool {
        !self.buffer().is_empty() || self.non_empty_reader_buffer().is_ok()
    }
}

// CURSOR
// ================================================================================================

#[cfg(feature = "std")]
macro_rules! cursor_remaining_buf {
    ($cursor:ident) => {{
        let buf = $cursor.get_ref().as_ref();
        let start = $cursor.position().min(buf.len() as u64) as usize;
        &buf[start..]
    }};
}

#[cfg(feature = "std")]
impl<T: AsRef<[u8]>> ByteReader for std::io::Cursor<T> {
    fn read_u8(&mut self) -> Result<u8, DeserializationError> {
        let buf = cursor_remaining_buf!(self);
        if buf.is_empty() {
            Err(DeserializationError::UnexpectedEOF)
        } else {
            let byte = buf[0];
            self.set_position(self.position() + 1);
            Ok(byte)
        }
    }

    fn peek_u8(&self) -> Result<u8, DeserializationError> {
        cursor_remaining_buf!(self)
            .first()
            .copied()
            .ok_or(DeserializationError::UnexpectedEOF)
    }

    fn read_slice(&mut self, len: usize) -> Result<&[u8], DeserializationError> {
        let pos = self.position();
        let size = self.get_ref().as_ref().len() as u64;
        if size.saturating_sub(pos) < len as u64 {
            Err(DeserializationError::UnexpectedEOF)
        } else {
            self.set_position(pos + len as u64);
            let start = pos.min(size) as usize;
            Ok(&self.get_ref().as_ref()[start..(start + len)])
        }
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError> {
        self.read_slice(N).map(|bytes| {
            let mut result = [0u8; N];
            result.copy_from_slice(bytes);
            result
        })
    }

    fn check_eor(&self, num_bytes: usize) -> Result<(), DeserializationError> {
        if cursor_remaining_buf!(self).len() >= num_bytes {
            Ok(())
        } else {
            Err(DeserializationError::UnexpectedEOF)
        }
    }

    #[inline]
    fn has_more_bytes(&self) -> bool {
        let pos = self.position();
        let size = self.get_ref().as_ref().len() as u64;
        pos < size
    }
}

// SLICE READER
// ================================================================================================

/// Implements [ByteReader] trait for a slice of bytes.
///
/// NOTE: If you are building with the `std` feature, you should probably prefer [std::io::Cursor]
/// instead. However, [SliceReader] is still useful in no-std environments until stabilization of
/// the `core_io_borrowed_buf` feature.
pub struct SliceReader<'a> {
    source: &'a [u8],
    pos: usize,
}

impl<'a> SliceReader<'a> {
    /// Creates a new slice reader from the specified slice.
    pub fn new(source: &'a [u8]) -> Self {
        SliceReader { source, pos: 0 }
    }
}

impl ByteReader for SliceReader<'_> {
    fn read_u8(&mut self) -> Result<u8, DeserializationError> {
        self.check_eor(1)?;
        let result = self.source[self.pos];
        self.pos += 1;
        Ok(result)
    }

    fn peek_u8(&self) -> Result<u8, DeserializationError> {
        self.check_eor(1)?;
        Ok(self.source[self.pos])
    }

    fn read_slice(&mut self, len: usize) -> Result<&[u8], DeserializationError> {
        self.check_eor(len)?;
        let result = &self.source[self.pos..self.pos + len];
        self.pos += len;
        Ok(result)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError> {
        self.check_eor(N)?;
        let mut result = [0_u8; N];
        result.copy_from_slice(&self.source[self.pos..self.pos + N]);
        self.pos += N;
        Ok(result)
    }

    fn check_eor(&self, num_bytes: usize) -> Result<(), DeserializationError> {
        self.pos
            .checked_add(num_bytes)
            .filter(|end| *end <= self.source.len())
            .map(|_| ())
            .ok_or(DeserializationError::UnexpectedEOF)
    }

    fn has_more_bytes(&self) -> bool {
        self.pos < self.source.len()
    }
}

// BUDGETED READER
// ================================================================================================

/// A reader wrapper that enforces a byte budget during deserialization.
///
/// # Threat Model
///
/// Malicious input can attack deserialization in two ways:
///
/// 1. **Fake length prefix**: Input claims `len = 2^60` elements, causing allocation of a huge
///    `Vec` before any data is read.
/// 2. **Oversized input**: Attacker sends gigabytes of valid-looking data to exhaust memory over
///    time.
///
/// # Defense Strategy
///
/// Use `BudgetedReader` to limit total bytes consumed. Its [`max_alloc`](ByteReader::max_alloc)
/// method derives a bound from the remaining budget, which
/// [`read_many_iter`](ByteReader::read_many_iter) checks before iterating.
///
/// ## Problem: SliceReader alone doesn't bound allocations
///
/// ```
/// use miden_serde_utils::{ByteReader, Deserializable, SliceReader};
///
/// // Malicious input: length prefix says 1 billion u64s, but only 16 bytes of data
/// let mut data = Vec::new();
/// data.push(0u8); // vint64 9-byte marker
/// data.extend_from_slice(&1_000_000_000u64.to_le_bytes());
/// data.extend_from_slice(&[0u8; 16]);
///
/// // SliceReader and read_from_bytes are unbudgeted. Use read_from_bytes_with_budget
/// // or wrap SliceReader in BudgetedReader when reading untrusted input.
/// let reader = SliceReader::new(&data);
/// assert_eq!(reader.max_alloc(8), usize::MAX);
/// ```
///
/// ## Solution: BudgetedReader bounds allocations via max_alloc
///
/// ```
/// use miden_serde_utils::{BudgetedReader, ByteReader, Deserializable, SliceReader};
///
/// // Same malicious input
/// let mut data = Vec::new();
/// data.push(0u8);
/// data.extend_from_slice(&1_000_000_000u64.to_le_bytes());
/// data.extend_from_slice(&[0u8; 16]);
///
/// // BudgetedReader with 64-byte budget: max_alloc(8) = 64/8 = 8 elements
/// let inner = SliceReader::new(&data);
/// let reader = BudgetedReader::new(inner, 64);
/// assert_eq!(reader.max_alloc(8), 8);
///
/// // read_many_iter rejects the 1B length since 1B > 8
/// let result = Vec::<u64>::read_from_bytes_with_budget(&data, 64);
/// assert!(result.is_err());
/// ```
///
/// ## Best practice: Set budget to expected input size
///
/// ```
/// use miden_serde_utils::{ByteWriter, Deserializable, Serializable};
///
/// // Legitimate input: 3 u64s, properly serialized
/// let original = vec![1u64, 2, 3];
/// let mut data = Vec::new();
/// original.write_into(&mut data);
///
/// // Budget = data.len() bounds both fake lengths and total consumption
/// let result = Vec::<u64>::read_from_bytes_with_budget(&data, data.len());
/// assert_eq!(result.unwrap(), vec![1, 2, 3]);
/// ```
pub struct BudgetedReader<R> {
    inner: R,
    remaining: usize,
}

impl<R> BudgetedReader<R> {
    /// Wraps a reader with the specified byte budget.
    pub fn new(inner: R, budget: usize) -> Self {
        Self { inner, remaining: budget }
    }

    /// Returns remaining budget in bytes.
    pub fn remaining(&self) -> usize {
        self.remaining
    }

    /// Consumes budget, returning an error if insufficient.
    fn consume_budget(&mut self, n: usize) -> Result<(), DeserializationError> {
        if n > self.remaining {
            return Err(DeserializationError::InvalidValue(format!(
                "budget exhausted: requested {n} bytes, {} remaining",
                self.remaining
            )));
        }
        self.remaining -= n;
        Ok(())
    }
}

impl<R: ByteReader> ByteReader for BudgetedReader<R> {
    fn read_u8(&mut self) -> Result<u8, DeserializationError> {
        self.consume_budget(1)?;
        self.inner.read_u8()
    }

    fn peek_u8(&self) -> Result<u8, DeserializationError> {
        // peek doesn't consume budget since it doesn't advance the reader
        self.inner.peek_u8()
    }

    fn read_slice(&mut self, len: usize) -> Result<&[u8], DeserializationError> {
        self.consume_budget(len)?;
        self.inner.read_slice(len)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError> {
        self.consume_budget(N)?;
        self.inner.read_array()
    }

    fn check_eor(&self, num_bytes: usize) -> Result<(), DeserializationError> {
        // check budget first, then delegate
        if num_bytes > self.remaining {
            return Err(DeserializationError::InvalidValue(format!(
                "budget exhausted: requested {num_bytes} bytes, {} remaining",
                self.remaining
            )));
        }
        self.inner.check_eor(num_bytes)
    }

    fn has_more_bytes(&self) -> bool {
        self.remaining > 0 && self.inner.has_more_bytes()
    }

    fn max_alloc(&self, element_size: usize) -> usize {
        if element_size == 0 {
            return usize::MAX; // ZSTs don't consume budget
        }
        self.remaining / element_size
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use core::mem::size_of;
    use std::io::{Cursor, Read};

    use super::*;
    use crate::ByteWriter;

    struct ChunkedReader {
        data: Vec<u8>,
        pos: usize,
        chunk_size: usize,
    }

    impl ChunkedReader {
        fn new(data: Vec<u8>, chunk_size: usize) -> Self {
            Self { data, pos: 0, chunk_size }
        }
    }

    impl Read for ChunkedReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let remaining = &self.data[self.pos..];
            let len = remaining.len().min(buf.len()).min(self.chunk_size);
            buf[..len].copy_from_slice(&remaining[..len]);
            self.pos += len;
            Ok(len)
        }
    }

    #[test]
    fn read_adapter_empty() {
        let mut reader = std::io::empty();
        let mut adapter = ReadAdapter::new(&mut reader);
        assert!(!adapter.has_more_bytes());
        assert_eq!(adapter.check_eor(8), Err(DeserializationError::UnexpectedEOF));
        assert_eq!(adapter.peek_u8(), Err(DeserializationError::UnexpectedEOF));
        assert_eq!(adapter.read_u8(), Err(DeserializationError::UnexpectedEOF));
        assert_eq!(adapter.read_slice(0), Ok([].as_slice()));
        assert_eq!(adapter.read_slice(1), Err(DeserializationError::UnexpectedEOF));
        assert_eq!(adapter.read_array(), Ok([]));
        assert_eq!(adapter.read_array::<1>(), Err(DeserializationError::UnexpectedEOF));
    }

    #[test]
    fn read_adapter_passthrough() {
        let mut reader = std::io::repeat(0b101);
        let mut adapter = ReadAdapter::new(&mut reader);
        assert!(adapter.has_more_bytes());
        assert_eq!(adapter.check_eor(8), Ok(()));
        assert_eq!(adapter.peek_u8(), Ok(0b101));
        assert_eq!(adapter.read_u8(), Ok(0b101));
        assert_eq!(adapter.read_slice(0), Ok([].as_slice()));
        assert_eq!(adapter.read_slice(4), Ok([0b101, 0b101, 0b101, 0b101].as_slice()));
        assert_eq!(adapter.read_array(), Ok([]));
        assert_eq!(adapter.read_array(), Ok([0b101, 0b101]));
    }

    #[test]
    fn read_adapter_exact() {
        const VALUE: usize = 2048;
        let mut reader = Cursor::new(VALUE.to_le_bytes());
        let mut adapter = ReadAdapter::new(&mut reader);
        assert_eq!(usize::from_le_bytes(adapter.read_array().unwrap()), VALUE);
        assert!(!adapter.has_more_bytes());
        assert_eq!(adapter.peek_u8(), Err(DeserializationError::UnexpectedEOF));
        assert_eq!(adapter.read_u8(), Err(DeserializationError::UnexpectedEOF));
    }

    #[test]
    fn read_adapter_large_array_from_chunked_reader() {
        let data = (0..897).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let expected: [u8; 897] = data.clone().try_into().unwrap();
        let mut chunked = ChunkedReader::new(data.clone(), 128);
        let mut adapter = ReadAdapter::new(&mut chunked);

        assert_eq!(adapter.read_array::<897>().unwrap(), expected);
    }

    #[test]
    fn read_adapter_large_array_after_buffered_prefix() {
        let data = (0..700).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let expected: [u8; 625] = data[17..642].try_into().unwrap();
        let mut chunked = ChunkedReader::new(data.clone(), 128);
        let mut adapter = ReadAdapter::new(&mut chunked);

        assert_eq!(adapter.read_slice(17).unwrap(), &data[..17]);
        assert_eq!(adapter.read_array::<625>().unwrap(), expected);
    }

    #[test]
    fn read_adapter_exact_array_resets_empty_local_buffer() {
        let data = (0..300).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let expected: [u8; 111] = data[17..128].try_into().unwrap();
        let mut chunked = ChunkedReader::new(data.clone(), 128);
        let mut adapter = ReadAdapter::new(&mut chunked);

        assert_eq!(adapter.read_slice(17).unwrap(), &data[..17]);
        assert_eq!(adapter.read_array::<111>().unwrap(), expected);
        assert_eq!(adapter.read_slice(8).unwrap(), &data[128..136]);
    }

    #[test]
    fn read_adapter_roundtrip() {
        const VALUE: usize = 2048;

        // Write VALUE to storage
        let mut cursor = Cursor::new([0; size_of::<usize>()]);
        cursor.write_usize(VALUE);

        // Read VALUE from storage
        cursor.set_position(0);
        let mut adapter = ReadAdapter::new(&mut cursor);

        assert_eq!(adapter.read_usize(), Ok(VALUE));
    }

    #[test]
    fn read_adapter_for_file() {
        use std::fs::File;

        use crate::ByteWriter;

        let path = std::env::temp_dir().join("read_adapter_for_file.bin");

        // Encode some data to a buffer, then write that buffer to a file
        {
            let mut buf = Vec::<u8>::with_capacity(256);
            buf.write_bytes(b"MAGIC\0");
            buf.write_bool(true);
            buf.write_u32(0xbeef);
            buf.write_usize(0xfeed);
            buf.write_u16(0x5);

            std::fs::write(&path, &buf).unwrap();
        }

        // Open the file, and try to decode the encoded items
        let mut file = File::open(&path).unwrap();
        let mut reader = ReadAdapter::new(&mut file);
        assert_eq!(reader.peek_u8().unwrap(), b'M');
        assert_eq!(reader.read_slice(6).unwrap(), b"MAGIC\0");
        assert!(reader.read_bool().unwrap());
        assert_eq!(reader.read_u32().unwrap(), 0xbeef);
        assert_eq!(reader.read_usize().unwrap(), 0xfeed);
        assert_eq!(reader.read_u16().unwrap(), 0x5);
        assert!(!reader.has_more_bytes(), "expected there to be no more data in the input");
    }

    #[test]
    fn read_adapter_issue_383() {
        const STR_BYTES: &[u8] = b"just a string";

        use std::fs::File;

        use crate::ByteWriter;

        let path = std::env::temp_dir().join("issue_383.bin");

        // Encode some data to a buffer, then write that buffer to a file
        {
            let mut buf = vec![0u8; 1024];
            unsafe {
                buf.set_len(0);
            }
            buf.write_u128(2 * u64::MAX as u128);
            unsafe {
                buf.set_len(512);
            }
            buf.write_bytes(STR_BYTES);
            buf.write_u32(0xbeef);

            std::fs::write(&path, &buf).unwrap();
        }

        // Open the file, and try to decode the encoded items
        let mut file = File::open(&path).unwrap();
        let mut reader = ReadAdapter::new(&mut file);
        assert_eq!(reader.read_u128().unwrap(), 2 * u64::MAX as u128);
        assert_eq!(reader.buf.len(), 0);
        assert_eq!(reader.pos, 0);
        // Read to offset 512 (we're 16 bytes into the underlying file, i.e. offset of 496)
        reader.read_slice(496).unwrap();
        assert_eq!(reader.buf.len(), 496);
        assert_eq!(reader.pos, 496);
        // The byte string is 13 bytes, followed by 4 bytes containing the trailing u32 value.
        // We expect that the underlying reader will buffer the remaining bytes of the file when
        // reading STR_BYTES, so the total size of our adapter's buffer should be
        // 496 + STR_BYTES.len() + size_of::<u32>();
        assert_eq!(reader.read_slice(STR_BYTES.len()).unwrap(), STR_BYTES);
        assert_eq!(reader.buf.len(), 496 + STR_BYTES.len() + size_of::<u32>());
        // We haven't read the u32 yet
        assert_eq!(reader.pos, 509);
        assert_eq!(reader.read_u32().unwrap(), 0xbeef);
        // Now we have
        assert_eq!(reader.buf.len(), 0);
        assert_eq!(reader.pos, 0);
        assert!(!reader.has_more_bytes(), "expected there to be no more data in the input");
    }

    #[test]
    fn budgeted_reader_basic() {
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let inner = SliceReader::new(&data);
        let mut reader = BudgetedReader::new(inner, 4);

        assert_eq!(reader.remaining(), 4);
        assert!(reader.has_more_bytes());

        // read 4 bytes (within budget)
        assert_eq!(reader.read_u32().unwrap(), 0x04030201);
        assert_eq!(reader.remaining(), 0);

        // budget exhausted
        assert!(!reader.has_more_bytes());
        assert!(reader.read_u8().is_err());
    }

    #[test]
    fn budgeted_reader_peek_does_not_consume() {
        let data = [42u8];
        let inner = SliceReader::new(&data);
        let mut reader = BudgetedReader::new(inner, 1);

        // peek multiple times, budget unchanged
        assert_eq!(reader.peek_u8().unwrap(), 42);
        assert_eq!(reader.peek_u8().unwrap(), 42);
        assert_eq!(reader.remaining(), 1);

        // actual read consumes budget
        assert_eq!(reader.read_u8().unwrap(), 42);
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn budgeted_reader_check_eor_respects_budget() {
        let data = [0u8; 100];
        let inner = SliceReader::new(&data);
        let reader = BudgetedReader::new(inner, 10);

        // within budget
        assert!(reader.check_eor(10).is_ok());

        // exceeds budget (even though inner has enough bytes)
        assert!(reader.check_eor(11).is_err());
    }

    #[test]
    fn budgeted_reader_read_slice() {
        let data = [1u8, 2, 3, 4, 5];
        let inner = SliceReader::new(&data);
        let mut reader = BudgetedReader::new(inner, 3);

        // read 3 bytes (exactly budget)
        assert_eq!(reader.read_slice(3).unwrap(), &[1, 2, 3]);
        assert_eq!(reader.remaining(), 0);

        // can't read more
        assert!(reader.read_slice(1).is_err());
    }

    #[test]
    fn budgeted_reader_read_array() {
        let data = [0xaau8, 0xbb, 0xcc, 0xdd];
        let inner = SliceReader::new(&data);
        let mut reader = BudgetedReader::new(inner, 2);

        // read 2-byte array
        assert_eq!(reader.read_array::<2>().unwrap(), [0xaa, 0xbb]);
        assert_eq!(reader.remaining(), 0);

        // budget exhausted
        assert!(reader.read_array::<2>().is_err());
    }

    #[test]
    fn budgeted_reader_zero_budget() {
        let data = [1u8];
        let inner = SliceReader::new(&data);
        let mut reader = BudgetedReader::new(inner, 0);

        assert!(!reader.has_more_bytes());
        assert!(reader.read_u8().is_err());
        // peek still works (doesn't consume budget)
        assert_eq!(reader.peek_u8().unwrap(), 1);
    }

    #[test]
    fn budgeted_reader_max_alloc() {
        let data = [0u8; 100];
        let inner = SliceReader::new(&data);
        let reader = BudgetedReader::new(inner, 64);

        // 64 bytes budget / 8 bytes per u64 = 8 elements max
        assert_eq!(reader.max_alloc(8), 8);

        // 64 bytes budget / 1 byte per u8 = 64 elements max
        assert_eq!(reader.max_alloc(1), 64);

        // 64 bytes budget / 16 bytes per u128 = 4 elements max
        assert_eq!(reader.max_alloc(16), 4);

        // ZSTs (0 bytes) return usize::MAX
        assert_eq!(reader.max_alloc(0), usize::MAX);
    }

    #[test]
    fn unbounded_reader_max_alloc_returns_max() {
        let data = [0u8; 100];
        let reader = SliceReader::new(&data);

        assert_eq!(reader.max_alloc(1), usize::MAX);
        assert_eq!(reader.max_alloc(8), usize::MAX);
        assert_eq!(reader.max_alloc(0), usize::MAX);
    }

    #[test]
    fn slice_reader_rejects_overflowing_read_lengths() {
        let data = [1u8];
        let mut reader = SliceReader::new(&data);

        assert_eq!(reader.read_u8().unwrap(), 1);
        assert_eq!(reader.read_slice(usize::MAX), Err(DeserializationError::UnexpectedEOF));
        assert_eq!(reader.check_eor(usize::MAX), Err(DeserializationError::UnexpectedEOF));
    }

    // ============================================================================================
    // The following tests document the threat model and defense layers.
    // ============================================================================================

    /// SliceReader alone does NOT reject fake length prefixes.
    ///
    /// A malicious input claiming 1000 elements will be accepted by read_many_iter
    /// because SliceReader.max_alloc() returns usize::MAX. The deserialization will
    /// eventually fail with UnexpectedEOF, but only after attempting to iterate.
    #[test]
    fn slice_reader_accepts_fake_length_prefix() {
        let mut data = Vec::new();
        // Write length = 1000 (vint64 encoding: 0x07D0 << 2 | 0b10 = 0x1F42)
        // For simplicity, use the 9-byte form
        data.push(0); // 9-byte marker
        data.extend_from_slice(&1000u64.to_le_bytes());
        // Only 8 bytes of actual u64 data (1 element, not 1000)
        data.extend_from_slice(&42u64.to_le_bytes());

        let mut reader = SliceReader::new(&data);
        let _len = reader.read_usize().unwrap();
        let iter_result = reader.read_many_iter::<u64>(1000);

        assert!(iter_result.is_ok());

        let collect_result: Result<Vec<u64>, _> = iter_result.unwrap().collect();
        assert!(collect_result.is_err());
        assert!(matches!(collect_result.unwrap_err(), DeserializationError::UnexpectedEOF));
    }

    /// BudgetedReader rejects fake length prefixes BEFORE iteration begins.
    ///
    /// With a 64-byte budget, max_alloc(8) = 8, so a claim of 1000 elements
    /// is rejected immediately by read_many_iter.
    #[test]
    fn budgeted_reader_rejects_fake_length_upfront() {
        let mut data = Vec::new();
        data.push(0); // 9-byte vint64 marker
        data.extend_from_slice(&1000u64.to_le_bytes());
        data.extend_from_slice(&42u64.to_le_bytes());

        let inner = SliceReader::new(&data);
        let mut reader = BudgetedReader::new(inner, 64);

        let _len = reader.read_usize().unwrap(); // consumes 9 bytes, 55 remaining
        // 55 / 8 = 6 elements max
        let iter_result = reader.read_many_iter::<u64>(1000);

        // Rejected immediately: 1000 > 6
        match iter_result {
            Err(DeserializationError::InvalidValue(_)) => {}, // expected
            other => panic!("expected InvalidValue error, got {:?}", other.map(|_| "Ok")),
        }
    }

    #[test]
    fn read_many_iter_does_not_advertise_fallible_items_as_ready() {
        let data = [0u8; 8];
        let mut reader = SliceReader::new(&data);
        let iter = reader.read_many_iter::<u64>(1000).unwrap();

        assert_eq!(iter.size_hint(), (0, Some(1000)));
    }

    /// Best practice: budget = input length provides both protections.
    ///
    /// 1. Fake length prefixes are bounded by max_alloc (remaining_bytes / element_size)
    /// 2. Total consumption is bounded by the budget
    #[test]
    fn budget_equals_input_length_is_safe() {
        // Valid input: 2 u64s
        let original = vec![100u64, 200];
        let mut data = Vec::new();
        crate::Serializable::write_into(&original, &mut data);

        // Budget = exact input size
        let result = Vec::<u64>::read_from_bytes_with_budget(&data, data.len());
        assert_eq!(result.unwrap(), vec![100, 200]);

        // Malicious input claiming 1000 elements (same serialized prefix manipulation)
        let mut evil_data = Vec::new();
        evil_data.push(0); // 9-byte vint64
        evil_data.extend_from_slice(&1000u64.to_le_bytes());
        evil_data.extend_from_slice(&42u64.to_le_bytes()); // only 1 actual element

        // Budget = input length (17 bytes). After reading length (9 bytes), 8 remain.
        // max_alloc(8) = 8/8 = 1, so 1000 > 1 fails.
        let result = Vec::<u64>::read_from_bytes_with_budget(&evil_data, evil_data.len());
        assert!(result.is_err());
    }

    // ============================================================================================
    // Tests documenting min_serialized_size()-based allocation bounds (defaults to size_of)
    // ============================================================================================

    /// The max_alloc check uses D::min_serialized_size() to bound memory allocation.
    /// By default, min_serialized_size() returns size_of::<D>().
    ///
    /// For flat collections like Vec<u64>, this works well: we check that
    /// budget / min_serialized_size() >= requested_count before allocating.
    #[test]
    fn min_serialized_size_bounds_flat_collections() {
        let mut data = Vec::new();
        data.push(0); // 9-byte vint64 marker
        data.extend_from_slice(&1000u64.to_le_bytes()); // claim 1000 u64s
        data.extend_from_slice(&[0u8; 16]); // only 2 u64s of actual data

        let inner = SliceReader::new(&data);
        // Budget of 80 bytes: after reading 9-byte length, 71 remain.
        // max_alloc(u64::min_serialized_size()) = 71 / 8 = 8 elements max
        let mut reader = BudgetedReader::new(inner, 80);

        let _len = reader.read_usize().unwrap();
        let result = reader.read_many_iter::<u64>(1000);

        // Rejected: 1000 > 8
        assert!(result.is_err());
    }

    /// For nested collections like Vec<Vec<u64>>, min_serialized_size() returns 1 (the minimum
    /// vint length prefix), not size_of. This is more permissive but accurate: a
    /// serialized Vec can be as small as 1 byte (empty vec).
    ///
    /// The early-abort check uses this minimum, and budget enforcement during actual
    /// reads provides the real protection against malicious input.
    #[test]
    fn min_serialized_size_override_for_nested_collections() {
        // Vec<u64>::min_serialized_size() returns 1 (minimum vint prefix), not size_of
        assert_eq!(<Vec<u64>>::min_serialized_size(), 1);

        let mut data = Vec::new();
        data.push(0); // 9-byte vint64 marker
        data.extend_from_slice(&100u64.to_le_bytes()); // claim 100 inner Vecs
        // Only provide enough data for 1 empty inner Vec
        data.push(0b10); // vint64 for 0 (empty inner vec)

        let inner = SliceReader::new(&data);
        // With min_serialized_size() = 1, we need budget >= 100 to pass the early check.
        // After reading 9-byte length, 101 - 9 = 92 remaining, 92 / 1 = 92 < 100.
        // So with budget = 110, we get 110 - 9 = 101 remaining, 101 >= 100.
        let mut reader = BudgetedReader::new(inner, 110);

        let _len = reader.read_usize().unwrap();
        let result = reader.read_many_iter::<Vec<u64>>(100);

        // The early check passes (100 <= 101)
        assert!(result.is_ok());

        // But deserialization fails when we try to read 100 inner Vecs with only 1
        let collect_result: Result<Vec<Vec<u64>>, _> = result.unwrap().collect();
        assert!(collect_result.is_err());
    }

    /// Demonstrates that min_serialized_size() approach still provides security for nested
    /// collections, just with later detection. The budget is enforced during reads.
    #[test]
    fn nested_collections_still_protected_by_budget() {
        // With Vec::min_serialized_size() = 1, the early check is permissive.
        // Security comes from budget enforcement during actual reads.
        let mut data = Vec::new();
        data.push(0); // 9-byte vint64 marker
        data.extend_from_slice(&10u64.to_le_bytes()); // claim 10 inner Vecs
        // Each inner vec claims 1000 u64s but provides none
        for _ in 0..10 {
            data.push(0); // 9-byte vint64 marker
            data.extend_from_slice(&1000u64.to_le_bytes());
        }

        let inner = SliceReader::new(&data);
        // Small budget: will run out during inner deserialization
        let mut reader = BudgetedReader::new(inner, 100);

        // Outer length read succeeds (consumes 9 bytes, 91 remaining)
        let _len = reader.read_usize().unwrap();

        // With Vec::min_serialized_size() = 1, early check passes: 91 / 1 = 91 >= 10
        let result = reader.read_many_iter::<Vec<u64>>(10);
        assert!(result.is_ok());

        // But collecting fails because the inner vecs claim 1000 u64s each,
        // exhausting the budget during inner deserialization
        let collect_result: Result<Vec<Vec<u64>>, _> = result.unwrap().collect();
        assert!(collect_result.is_err());
    }

    /// Tuples should use sum of element min_serialized_size, not size_of (which includes padding).
    ///
    /// This test verifies that (u8, u64) has min_serialized_size = 9 (1 + 8) not 16 (in-memory size
    /// with 7 bytes of alignment padding).
    #[test]
    fn tuple_min_serialized_size_excludes_padding() {
        // Serialized: 1 byte for u8 + 8 bytes for u64 = 9 bytes
        // In-memory: 8 bytes for u8 (with 7 bytes padding) + 8 bytes for u64 = 16 bytes
        assert_eq!(<(u8, u64)>::min_serialized_size(), 9);
        assert_eq!(size_of::<(u8, u64)>(), 16);

        // Verify budget calculation uses 9, not 16
        let mut data = Vec::new();
        data.push(0); // 9-byte vint64 marker
        data.extend_from_slice(&4u64.to_le_bytes()); // claim 4 tuples
        // Provide exactly 4 tuples worth of data: 4 * 9 = 36 bytes
        for i in 0u8..4 {
            data.push(i); // u8
            data.extend_from_slice(&(i as u64).to_le_bytes()); // u64
        }

        let inner = SliceReader::new(&data);
        // Budget: 9 (length prefix) + 36 (data) = 45 bytes
        let mut reader = BudgetedReader::new(inner, 45);

        let _len = reader.read_usize().unwrap();
        // With min_serialized_size = 9: remaining = 45 - 9 = 36, max_elements = 36 / 9 = 4
        // This should succeed (4 <= 4)
        let result = reader.read_many_iter::<(u8, u64)>(4);
        assert!(result.is_ok());

        // With min_serialized_size = 16 (wrong): max_elements = 36 / 16 = 2
        // This would fail (4 > 2)
        let collect_result: Result<Vec<(u8, u64)>, _> = result.unwrap().collect();
        assert!(collect_result.is_ok());
        assert_eq!(collect_result.unwrap().len(), 4);
    }
}
