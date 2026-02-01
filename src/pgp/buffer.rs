//! Custom Buffer and BufReader implementations.
//!
//! This module provides custom implementations that replace the `buf_redux` crate,
//! which is unmaintained and causes Rust compiler warnings.

use std::io::{self, Read, Seek, SeekFrom};

/// A growable buffer for accumulating bytes.
#[derive(Debug)]
pub struct Buffer {
    /// Internal storage
    data: Vec<u8>,
    /// Start position of unconsumed data
    start: usize,
    /// End position of unconsumed data (also write position)
    end: usize,
}

impl Buffer {
    /// Create a new buffer with the specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Buffer {
            data: vec![0u8; capacity],
            start: 0,
            end: 0,
        }
    }

    /// Returns true if there is no unconsumed data in the buffer.
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    /// Returns a slice of the unconsumed data in the buffer.
    pub fn buf(&self) -> &[u8] {
        &self.data[self.start..self.end]
    }

    /// Mark `n` bytes as consumed, advancing the start position.
    pub fn consume(&mut self, n: usize) {
        self.start = std::cmp::min(self.start + n, self.end);
    }

    /// Returns the amount of space available for reading more data.
    /// This is the space between the end of data and the end of the buffer.
    pub fn usable_space(&self) -> usize {
        self.data.len() - self.end
    }

    /// Move unconsumed data to the beginning of the buffer to make room for more data.
    pub fn make_room(&mut self) {
        if self.start > 0 {
            let len = self.end - self.start;
            self.data.copy_within(self.start..self.end, 0);
            self.start = 0;
            self.end = len;
        }
    }

    /// Ensure the buffer has at least `capacity` total size.
    /// This may reallocate if the current capacity is insufficient.
    pub fn reserve(&mut self, capacity: usize) {
        if self.data.len() < capacity {
            self.data.resize(capacity, 0);
        }
    }

    /// Read data from the reader directly into the buffer.
    /// Returns the number of bytes read.
    pub fn read_from<R: Read>(&mut self, reader: &mut R) -> io::Result<usize> {
        // Make room if we're running low on space
        if self.usable_space() == 0 {
            self.make_room();
        }

        let n = reader.read(&mut self.data[self.end..])?;
        self.end += n;
        Ok(n)
    }

    /// Copy data from the buffer to the destination slice.
    /// Returns the number of bytes copied.
    /// Consumes the copied bytes from the buffer.
    pub fn copy_to_slice(&mut self, dst: &mut [u8]) -> usize {
        let available = self.end - self.start;
        let n = std::cmp::min(available, dst.len());
        dst[..n].copy_from_slice(&self.data[self.start..self.start + n]);
        self.start += n;
        n
    }

    /// Copy data from the source slice into the buffer.
    /// The data is appended after any existing unconsumed data.
    pub fn copy_from_slice(&mut self, src: &[u8]) {
        // Make room if needed
        if self.usable_space() < src.len() {
            self.make_room();
        }

        // Grow buffer if still not enough space
        if self.usable_space() < src.len() {
            let needed = self.end + src.len();
            self.data.resize(needed, 0);
        }

        self.data[self.end..self.end + src.len()].copy_from_slice(src);
        self.end += src.len();
    }
}

/// A buffered reader that wraps an inner reader.
pub struct BufReader<R> {
    inner: R,
    buffer: Buffer,
}

impl<R> BufReader<R> {
    /// Create a new BufReader with the specified capacity.
    pub fn with_capacity(capacity: usize, inner: R) -> Self {
        BufReader {
            inner,
            buffer: Buffer::with_capacity(capacity),
        }
    }

    /// Create a new BufReader with an existing buffer.
    pub fn with_buffer(buffer: Buffer, inner: R) -> Self {
        BufReader { inner, buffer }
    }

    /// Returns the number of bytes currently in the buffer.
    pub fn buf_len(&self) -> usize {
        self.buffer.end - self.buffer.start
    }

    /// Returns a slice of the buffered data.
    pub fn buffer(&self) -> &[u8] {
        self.buffer.buf()
    }

    /// Mark `n` bytes as consumed.
    pub fn consume(&mut self, n: usize) {
        self.buffer.consume(n);
    }

    /// Move unconsumed data to the beginning of the buffer.
    pub fn make_room(&mut self) {
        self.buffer.make_room();
    }

    /// Consume this BufReader, returning the inner reader and the buffer.
    pub fn into_inner_with_buffer(self) -> (R, Buffer) {
        (self.inner, self.buffer)
    }

    /// Consume this BufReader, returning just the inner reader.
    #[allow(dead_code)]
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> BufReader<R> {
    /// Read data from the inner reader into the buffer.
    /// Returns the number of bytes read.
    pub fn read_into_buf(&mut self) -> io::Result<usize> {
        self.buffer.read_from(&mut self.inner)
    }
}

impl<R: Read> Read for BufReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // First, return any buffered data
        if !self.buffer.is_empty() {
            return Ok(self.buffer.copy_to_slice(buf));
        }

        // If the request is larger than our buffer, read directly
        if buf.len() >= self.buffer.data.len() {
            return self.inner.read(buf);
        }

        // Otherwise, fill the buffer and then copy
        self.read_into_buf()?;
        Ok(self.buffer.copy_to_slice(buf))
    }
}

impl<R: Seek> Seek for BufReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // When seeking, we need to account for buffered data that hasn't been consumed
        let buffered = self.buf_len() as i64;

        match pos {
            SeekFrom::Current(offset) => {
                // Adjust the offset to account for buffered data
                // The inner reader is ahead by `buffered` bytes
                let adjusted_offset = offset - buffered;
                // Clear the buffer since we're seeking
                self.buffer.start = 0;
                self.buffer.end = 0;
                self.inner.seek(SeekFrom::Current(adjusted_offset))
            }
            _ => {
                // For absolute seeks, just clear the buffer and seek
                self.buffer.start = 0;
                self.buffer.end = 0;
                self.inner.seek(pos)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_buffer_basic() {
        let mut buf = Buffer::with_capacity(16);
        assert!(buf.is_empty());
        assert_eq!(buf.buf(), &[]);

        buf.copy_from_slice(b"hello");
        assert!(!buf.is_empty());
        assert_eq!(buf.buf(), b"hello");

        buf.consume(2);
        assert_eq!(buf.buf(), b"llo");

        buf.consume(3);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_buffer_copy_to_slice() {
        let mut buf = Buffer::with_capacity(16);
        buf.copy_from_slice(b"hello world");

        let mut dst = [0u8; 5];
        let n = buf.copy_to_slice(&mut dst);
        assert_eq!(n, 5);
        assert_eq!(&dst, b"hello");
        assert_eq!(buf.buf(), b" world");
    }

    #[test]
    fn test_buffer_make_room() {
        let mut buf = Buffer::with_capacity(16);
        buf.copy_from_slice(b"hello");
        buf.consume(3);
        assert_eq!(buf.buf(), b"lo");

        buf.make_room();
        assert_eq!(buf.buf(), b"lo");
        assert_eq!(buf.start, 0);
    }

    #[test]
    fn test_buffer_read_from() {
        let mut buf = Buffer::with_capacity(16);
        let mut cursor = Cursor::new(b"hello world");

        let n = buf.read_from(&mut cursor).unwrap();
        assert_eq!(n, 11);
        assert_eq!(buf.buf(), b"hello world");
    }

    #[test]
    fn test_bufreader_basic() {
        let cursor = Cursor::new(b"hello world");
        let mut reader = BufReader::with_capacity(16, cursor);

        reader.read_into_buf().unwrap();
        assert_eq!(reader.buf_len(), 11);
        assert_eq!(reader.buffer(), b"hello world");

        reader.consume(6);
        assert_eq!(reader.buffer(), b"world");
    }

    #[test]
    fn test_bufreader_read() {
        let cursor = Cursor::new(b"hello world");
        let mut reader = BufReader::with_capacity(16, cursor);

        let mut buf = [0u8; 5];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");

        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b" worl");
    }

    #[test]
    fn test_bufreader_into_inner_with_buffer() {
        let cursor = Cursor::new(b"hello world");
        let mut reader = BufReader::with_capacity(16, cursor);

        reader.read_into_buf().unwrap();
        reader.consume(6);

        let (_inner, buffer) = reader.into_inner_with_buffer();
        assert_eq!(buffer.buf(), b"world");
    }

    #[test]
    fn test_bufreader_with_buffer() {
        let mut buffer = Buffer::with_capacity(16);
        buffer.copy_from_slice(b"leftover");

        let cursor = Cursor::new(b"new data");
        let reader = BufReader::with_buffer(buffer, cursor);

        assert_eq!(reader.buffer(), b"leftover");
    }
}
