//! A library to decode and encode headers for the [gzip format](http://www.gzip.org/zlib/rfc-gzip.html).
//! The library also contains a reader absctraction over a CRC checksum hasher.
//!
//! A file in the gzip format contains a gzip header, a number of compressed data blocks in the [DEFLATE](http://www.gzip.org/zlib/rfc-deflate.html) format, and ends
//! with the CRC32-checksum (in the IEEE format) and number of bytes (modulo `2^32`) of the uncompressed
//! data.
//!
//! The gzip header is purely a set of metadata, and doesn't have any impact on the decoding of the
//! compressed data other than the fact that `DEFLATE`-encoded data with a gzip-header is
//! checked using the CRC32 algorithm.
//!
//! This library is based on the gzip header functionality in the [flate2](https://crates.io/crates/flate2) crate.

extern crate crc;

mod crc_reader;

use std::ffi::CString;
use std::env;
use std::io;
use std::io::Read;

pub use crc_reader::{CrcReader, Crc};

static FHCRC: u8 = 1 << 1;
static FEXTRA: u8 = 1 << 2;
static FNAME: u8 = 1 << 3;
static FCOMMENT: u8 = 1 << 4;

/// An enum describing the different OS types described in the gzip format.
///
///
#[derive(Debug, Copy, Clone)]
pub enum FileSystemType {
    FAT = 0,
    Amiga = 1,
    VMS = 2,
    Unix = 3,
    VmCms = 4,
    AtariTos = 5,
    HPFS = 6,
    Macintosh = 7,
    ZSystem = 8,
    CPM = 9,
    TOPS20 = 10,
    NTFS = 11,
    QDOS = 12,
    RISCOS = 13,
    Unknown = 255,
}

impl FileSystemType {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

#[derive(Debug, Copy, Clone)]
pub enum ExtraFlags {
    Default = 0,
    MaximumCompression = 2,
    FastestCompression = 4,
}

impl ExtraFlags {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// A builder structure to create a new gzip header.
///
/// This structure controls header configuration options such as the filename.
pub struct GzBuilder {
    extra: Option<Vec<u8>>,
    filename: Option<CString>,
    comment: Option<CString>,
    mtime: u32,
    os: FileSystemType,
}

impl GzBuilder {
    /// Create a new blank builder with no header by default.
    pub fn new() -> GzBuilder {
        GzBuilder {
            extra: None,
            filename: None,
            comment: None,
            mtime: 0,
            os: match env::consts::OS {
                "linux" => FileSystemType::Unix,
                "macos" => FileSystemType::Macintosh,
                "win32" => FileSystemType::FAT,
                _ => FileSystemType::Unknown,
            },
        }
    }

    /// Configure the `mtime` field in the gzip header.
    pub fn mtime(mut self, mtime: u32) -> GzBuilder {
        self.mtime = mtime;
        self
    }

    /// Configure the `extra` field in the gzip header.
    pub fn extra(mut self, extra: Vec<u8>) -> GzBuilder {
        self.extra = Some(extra);
        self
    }

    /// Configure the `filename` field in the gzip header.
    ///
    /// A trailing `\0` is added if needed.
    pub fn filename(mut self, filename: &[u8]) -> GzBuilder {
        self.filename = Some(CString::new(filename).unwrap());
        self
    }

    /// Configure the `comment` field in the gzip header.
    ///
    /// A trailing `\0` is added if needed.
    pub fn comment(mut self, comment: &[u8]) -> GzBuilder {
        self.comment = Some(CString::new(comment).unwrap());
        self
    }

    /// Configurre the `os` field in the gzip header.
    ///
    /// This is taken from `std::env::consts::OS` if not set explicitly.
    pub fn os(mut self, os: FileSystemType) -> GzBuilder {
        self.os = os;
        self
    }

/*    /// Consume this builder, creating a writer encoder in the process.
    ///
    /// The data written to the returned encoder will be compressed and then
    /// written out to the supplied parameter `w`.
    pub fn write<W: Write>(self, w: W, lvl: Compression) -> EncoderWriter<W> {
        EncoderWriter {
            inner: zio::Writer::new(w, Compress::new(lvl, false)),
            crc: Crc::new(),
            header: self.into_header(lvl),
        }
    }

    /// Consume this builder, creating a reader encoder in the process.
    ///
    /// Data read from the returned encoder will be the compressed version of
    /// the data read from the given reader.
    pub fn read<R: Read>(self, r: R, lvl: Compression) -> EncoderReader<R> {
        EncoderReader {
            inner: self.buf_read(BufReader::new(r), lvl),
        }
    }

    /// Consume this builder, creating a reader encoder in the process.
    ///
    /// Data read from the returned encoder will be the compressed version of
    /// the data read from the given reader.
    pub fn buf_read<R>(self, r: R, lvl: Compression) -> EncoderReaderBuf<R>
        where R: BufRead
    {
        let crc = CrcReader::new(r);
        EncoderReaderBuf {
            inner: deflate::EncoderReaderBuf::new(crc, lvl),
            header: self.into_header(lvl),
            pos: 0,
            eof: false,
        }
    }*/

    /// Transforms this builder structure into a raw set of bytes, setting the `XFL` field to the
    /// value specified by `lvl`.
    pub fn into_header(self, lvl: ExtraFlags) -> Vec<u8> {
        let GzBuilder { extra, filename, comment, mtime, os } = self;
        let mut flg = 0;
        let mut header = vec![0u8; 10];
        match extra {
            Some(v) => {
                flg |= FEXTRA;
                header.push((v.len() >> 0) as u8);
                header.push((v.len() >> 8) as u8);
                header.extend(v);
            }
            None => {}
        }
        match filename {
            Some(filename) => {
                flg |= FNAME;
                header.extend(filename.as_bytes_with_nul().iter().map(|x| *x));
            }
            None => {}
        }
        match comment {
            Some(comment) => {
                flg |= FCOMMENT;
                header.extend(comment.as_bytes_with_nul().iter().map(|x| *x));
            }
            None => {}
        }
        header[0] = 0x1f;
        header[1] = 0x8b;
        header[2] = 8;
        header[3] = flg;
        header[4] = (mtime >> 0) as u8;
        header[5] = (mtime >> 8) as u8;
        header[6] = (mtime >> 16) as u8;
        header[7] = (mtime >> 24) as u8;
        header[8] = lvl.as_u8();
        header[9] = os.as_u8();
        return header;
    }
}

/// A structure representing the raw header of a gzip stream.
///
/// The header can contain metadata about the file that was compressed, if
/// present.
pub struct GzHeader {
    extra: Option<Vec<u8>>,
    filename: Option<Vec<u8>>,
    comment: Option<Vec<u8>>,
    mtime: u32,
    os: u8,
    xfl: u8,
}

impl GzHeader {
    /// Returns the `filename` field of this gzip stream's header, if present.
    pub fn filename(&self) -> Option<&[u8]> {
        self.filename.as_ref().map(|s| &s[..])
    }

    /// Returns the `extra` field of this gzip stream's header, if present.
    pub fn extra(&self) -> Option<&[u8]> {
        self.extra.as_ref().map(|s| &s[..])
    }

    /// Returns the `comment` field of this gzip stream's header, if present.
    pub fn comment(&self) -> Option<&[u8]> {
        self.comment.as_ref().map(|s| &s[..])
    }

    /// Returns the `mtime` field of this gzip stream's header.
    pub fn mtime(&self) -> u32 {
        self.mtime
    }

    /// Returns the `os` field of this gzip stream's header.
    pub fn os(&self) -> u8 {
        self.os
    }

    /// Returns the `xfl` field of this gzip stream's header.
    pub fn xfl(&self) -> u8 {
        self.xfl
    }
}

fn corrupt() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput,
                   "corrupt gzip stream does not have a matching checksum")
}

fn bad_header() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid gzip header")
}

/// Try to read a little-endian u16 from the provided reader.
fn read_le_u16<R: Read>(r: &mut R) -> io::Result<u16> {
    let mut b = [0; 2];
    try!(r.read_exact(&mut b));
    Ok((b[0] as u16) | ((b[1] as u16) << 8))
}

pub fn read_gz_header<R: Read>(r: &mut R) -> io::Result<GzHeader> {
    let mut crc_reader = CrcReader::new(r);
    let mut header = [0; 10];
    try!(crc_reader.read_exact(&mut header));

    // `ID1` and `ID2` are fixed values to identify a gzip file.
    let id1 = header[0];
    let id2 = header[1];
    if id1 != 0x1f || id2 != 0x8b {
        return Err(bad_header());
    }
    // `CM` describes the compression method. Currently only method 8 (DEFLATE) is specified.
    // by the gzip format.
    let cm = header[2];
    if cm != 8 {
        return Err(bad_header());
    }

    // `FLG` the bits in this field indicates whether the `FTEXT`, `FHCRC`, `FEXTRA`, `FNAME` and
    // `FCOMMENT` fields are present in the header.
    let flg = header[3];
    let mtime = ((header[4] as u32) << 0) | ((header[5] as u32) << 8) |
        ((header[6] as u32) << 16) |
    ((header[7] as u32) << 24);
    // `XFL` describes the compression level used by the encoder. (May not actually
    // match what the encoder used and has no impact on decompression.)
    let xfl = header[8];
    // `os` describes what type of operating system/file system the file was created on.
    let os = header[9];

    let extra = if flg & FEXTRA != 0 {
        // Length of the FEXTRA field.
        let xlen = try!(read_le_u16(&mut crc_reader));
        let mut extra = vec![0; xlen as usize];
        try!(crc_reader.read_exact(&mut extra));
        Some(extra)
    } else {
        None
    };
    let filename = if flg & FNAME != 0 {
        // wow this is slow
        let mut b = Vec::new();
        for byte in crc_reader.by_ref().bytes() {
            let byte = try!(byte);
            if byte == 0 {
                break;
            }
            b.push(byte);
        }
        Some(b)
    } else {
        None
    };
    let comment = if flg & FCOMMENT != 0 {
        // wow this is slow
        let mut b = Vec::new();
        for byte in crc_reader.by_ref().bytes() {
            let byte = try!(byte);
            if byte == 0 {
                break;
            }
            b.push(byte);
        }
        Some(b)
    } else {
        None
    };

    // If the `FHCRC` flag is set, the header contains a two-byte CRC checksum of the header bytes
    // that should be checked.
    if flg & FHCRC != 0 {
        let calced_crc = crc_reader.crc().sum() as u16;
        let stored_crc = try!(read_le_u16(&mut crc_reader));
        if calced_crc != stored_crc {
            return Err(corrupt());
        }
    }

    Ok(GzHeader {
        extra: extra,
        filename: filename,
        comment: comment,
        mtime: mtime,
        os: os,
        xfl: xfl,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip() {
        const COMMENT: &'static [u8] = b"Comment";
        const FILENAME: &'static [u8] = b"Filename";
        const MTIME: u32 = 12345;
        const OS: FileSystemType = FileSystemType::NTFS;
        const XFL: ExtraFlags = ExtraFlags::FastestCompression;

        let header = GzBuilder::new().comment(COMMENT).filename(FILENAME).mtime(MTIME).os(OS).into_header(XFL);

        let mut reader = Cursor::new(header.clone());

        let header_read = read_gz_header(&mut reader).unwrap();
        assert_eq!(header_read.comment().unwrap(), COMMENT);
        assert_eq!(header_read.filename().unwrap(), FILENAME);
        assert_eq!(header_read.mtime(), MTIME);
        assert_eq!(header_read.os(), OS.as_u8());
        assert_eq!(header_read.xfl(), XFL.as_u8());
    }
}
