//! Simple CRC wrappers backed by the crc32 crate.

use std::io::{Read, BufRead};
use std::io;

use crc::{crc32, Hasher32};

/// A struct containing a CRC checksum and the amount of bytes input to it.
pub struct Crc {
    crc: crc32::Digest,
    amt: u32,
}

/// A reader that updates the checksum and counter of a `Crc` struct when reading from the wrapped
/// reader.
pub struct CrcReader<R> {
    inner: R,
    crc: Crc,
}

impl Crc {
    /// Create a new empty CRC struct.
    pub fn new() -> Crc {
        Crc { crc: crc32::Digest::new(crc32::IEEE), amt: 0 }
    }

    /// Return the current checksum value.
    pub fn sum(&self) -> u32 {
        self.crc.sum32()
    }

    /// Return the number of bytes input.
    pub fn amt_as_u32(&self) -> u32 {
        self.amt
    }

    /// Update the checksum and byte counter with the provided data.
    pub fn update(&mut self, data: &[u8]) {
        self.amt = self.amt.wrapping_add(data.len() as u32);
        self.crc.write(data);
    }

    /// Reset the checksum and byte counter.
    pub fn reset(&mut self) {
        self.crc.reset();
        self.amt = 0;
    }
}

impl<R: Read> CrcReader<R> {
    /// Create a new `CrcReader` with a blank checksum.
    pub fn new(r: R) -> CrcReader<R> {
        CrcReader {
            inner: r,
            crc: Crc::new(),
        }
    }

    /// Return a reference to the underlying checksum struct.
    pub fn crc(&self) -> &Crc {
        &self.crc
    }

    /// Consume this `CrcReader` and return the wrapped `Read` instance.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Return a mutable reference to the wrapped reader.
    pub fn inner(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Reset the checksum and counter.
    pub fn reset(&mut self) {
        self.crc.reset();
    }
}

impl<R: Read> Read for CrcReader<R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        let amt = try!(self.inner.read(into));
        self.crc.update(&into[..amt]);
        Ok(amt)
    }
}

impl<R: BufRead> BufRead for CrcReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner.fill_buf()
    }
    fn consume(&mut self, amt: usize) {
        if let Ok(data) = self.inner.fill_buf() {
            self.crc.update(&data[..amt]);
        }
        self.inner.consume(amt);
    }
}
