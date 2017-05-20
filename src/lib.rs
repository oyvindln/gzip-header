//! A library to decode and encode headers for the
//! [gzip format](http://www.gzip.org/zlib/rfc-gzip.html).
//! The library also contains a reader absctraction over a CRC checksum hasher.
//!
//! A file in the gzip format contains a gzip header, a number of compressed data blocks in the
//! [DEFLATE](http://www.gzip.org/zlib/rfc-deflate.html) format, and ends with the CRC32-checksum
//! (in the IEEE format) and number of bytes (modulo `2^32`) of the uncompressed data.
//!
//! The gzip header is purely a set of metadata, and doesn't have any impact on the decoding of the
//! compressed data other than the fact that `DEFLATE`-encoded data with a gzip-header is
//! checked using the CRC32 algorithm.
//!
//! This library is based on the gzip header functionality in the
//! [flate2](https://crates.io/crates/flate2) crate.

extern crate crc;
#[macro_use]
extern crate enum_primitive;

mod crc_reader;

use std::ffi::CString;
use std::{env, io, time};
use std::io::Read;
use std::fmt;

pub use crc_reader::{CrcReader, Crc};

static FHCRC: u8 = 1 << 1;
static FEXTRA: u8 = 1 << 2;
static FNAME: u8 = 1 << 3;
static FCOMMENT: u8 = 1 << 4;

/// An enum describing the different OS types described in the gzip format.
/// See http://www.gzip.org/format.txt
enum_from_primitive!{
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FileSystemType {
    Fat = 0,
    Amiga = 1,
    Vms = 2,
    Unix = 3,
    Vcms = 4,
    AtariTos = 5,
    Hpfs = 6,
    Macintosh = 7,
    Zsystem = 8,
    Cpm = 9,
    // This is used for Windows/NTFS in zlib newer than 1.2.11, but not in gzip due to following
    // updates to the ZIP format.
    // See https://github.com/madler/zlib/issues/235 and
    // https://github.com/madler/zlib/commit/ce12c5cd00628bf8f680c98123a369974d32df15
    Tops20OrNTFS = 10,
    NTFS = 11,
    SmsQdos = 12,
    Riscos = 13,
    Vfat = 14,
    Mvs = 15,
    Beos = 16,
    TandemNsk = 17,
    Theos = 18,
    // Defined in the zlib library (see zutil.h)
    // Modern apple platforms.
    Apple = 19,
    Unknown = 255,
}
}

impl FileSystemType {
    /// Get the raw byte value of this `FileSystemType` variant.
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl fmt::Display for FileSystemType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use FileSystemType::*;
        match *self {
                Fat => "FAT filesystem (MS-DOS, OS/2, NT/Win32)",
                Amiga => "Amiga",
                Vms => "VMS or OpenVMS",
                Unix => "Unix type system/Linux",
                Vcms => "VM/CMS",
                AtariTos => "Atari TOS",
                Hpfs => "HPFS filesystem (OS/2, NT)",
                Macintosh => "Macintosh operating system (Classic Mac OS, OS/X, macOS, iOS etc.)",
                Zsystem => "Z-System",
                Cpm => "CP/M",
                Tops20OrNTFS => "NTFS (New zlib versions) or TOPS-20",
                NTFS => "NTFS",
                SmsQdos => "SMS/QDOS",
                Riscos => "Acorn RISC OS",
                Vfat => "VFAT file system (Win95, NT)",
                Mvs => "MVS or PRIMOS",
                Beos => "BeOS",
                TandemNsk => "Tandem/NSK",
                Theos => "THEOS",
                Apple => "macOS, OS/X, iOS or watchOS",
                _ => "Unknown or unset",
            }
            .fmt(f)
    }
}

/// Valid values for the extra flag in the gzip specification.
///
/// This is a field to be used by the compression methods. For deflate, which is the only
/// specified compression method, this is a value indicating the level of compression of the
/// contained compressed data.
enum_from_primitive!{
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum ExtraFlags {
    Default = 0,
    MaximumCompression = 2,
    FastestCompression = 4,
}
}

impl ExtraFlags {
    /// Get the raw byte value of this `ExtraFlags` variant.
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl fmt::Display for ExtraFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ExtraFlags::Default => "No extra flags (Default)",
            ExtraFlags::MaximumCompression => "Maximum compression algorithm (DEFLATE).",
            ExtraFlags::FastestCompression => "Fastest compression algorithm (DEFLATE)",
        }.fmt(f)
    }
}

/// A builder structure to create a new gzip header.
///
/// This structure controls header configuration options such as the filename.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GzBuilder {
    extra: Option<Vec<u8>>,
    filename: Option<CString>,
    comment: Option<CString>,
    // Whether this should be signed is a bit unclear, the gzip spec says mtime is in the unix
    // time format, which is normally signed, however zlib seems to use an unsigned long for this
    // field.
    mtime: u32,
    os: Option<FileSystemType>,
    xfl: ExtraFlags,
}

impl GzBuilder {
    /// Create a new blank builder with no header by default.
    pub fn new() -> GzBuilder {
        GzBuilder {
            extra: None,
            filename: None,
            comment: None,
            mtime: 0,
            os: None,
            xfl: ExtraFlags::Default,
        }
    }

    /// Configure the `mtime` field in the gzip header.
    pub fn mtime(mut self, mtime: u32) -> GzBuilder {
        self.mtime = mtime;
        self
    }

    /// Configure the `extra` field in the gzip header.
    pub fn extra<T: Into<Vec<u8>>>(mut self, extra: T) -> GzBuilder {
        self.extra = Some(extra.into());
        self
    }

    /// Configure the `filename` field in the gzip header.
    ///
    /// # Panics
    /// Panics if the filename argument contains a byte with the value 0.
    pub fn filename<T: Into<Vec<u8>>>(mut self, filename: T) -> GzBuilder {
        self.filename = Some(CString::new(filename).unwrap());
        self
    }

    /// Configure the `comment` field in the gzip header.
    ///
    /// # Panics
    /// Panics if the comment argument contains a byte with the value 0.
    pub fn comment<T: Into<Vec<u8>>>(mut self, comment: T) -> GzBuilder {
        self.comment = Some(CString::new(comment).unwrap());
        self
    }

    /// Configure the `os` field in the gzip header.
    ///
    /// This is taken from `std::env::consts::OS` if not set explicitly.
    pub fn os(mut self, os: FileSystemType) -> GzBuilder {
        self.os = Some(os);
        self
    }

    /// Configure the `xfl` field in the gzip header.
    ///
    /// The default is `ExtraFlags::Default` (meaning not set).
    pub fn xfl(mut self, xfl: ExtraFlags) -> GzBuilder {
        self.xfl = xfl;
        self
    }

    /// Transforms this builder structure into a raw vector of bytes, setting the `XFL` field to the
    /// value specified by `lvl`.
    pub fn into_header_xfl(mut self, lvl: ExtraFlags) -> Vec<u8> {
        self.xfl = lvl;
        self.into_header()
    }

    /// Transforms this builder structure into a raw vector of bytes.
    pub fn into_header(self) -> Vec<u8> {
        self.into_header_inner(false)
    }

    /// Transforms this builder structure into a raw vector of bytes.
    pub fn into_header_with_checksum(self) -> Vec<u8> {
        self.into_header_inner(true)
    }

    fn into_header_inner(self, use_crc: bool) -> Vec<u8> {
        let GzBuilder {
            extra,
            filename,
            comment,
            mtime,
            os,
            xfl,
        } = self;
        let os = match os {
            Some(f) => f,
            // Set the OS based on the system the binary is compiled for if not set,
            // as this is a required field.
            // These defaults are taken from what flate2 uses, which are not the same as
            // what's used in zlib.
            None => {
                match env::consts::OS {
                    "linux" => FileSystemType::Unix,
                    "macos" => FileSystemType::Macintosh,
                    "win32" => FileSystemType::Fat,
                    _ => FileSystemType::Unknown,
                }
            }

        };
        let mut flg = 0;
        if use_crc {
            flg |= FHCRC;
        };
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
        header[8] = xfl.as_u8();
        header[9] = os.as_u8();

        if use_crc {
            let mut crc = Crc::new();
            crc.update(&header);
            let checksum = crc.sum() as u16;
            header.extend(&[checksum as u8, (checksum >> 8) as u8]);
        }

        return header;
    }
}

/// A structure representing the raw header of a gzip stream.
///
/// The header can contain metadata about the file that was compressed, if
/// present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GzHeader {
    extra: Option<Vec<u8>>,
    filename: Option<Vec<u8>>,
    comment: Option<Vec<u8>>,
    mtime: u32,
    os: u8,
    xfl: u8,
}

impl GzHeader {
    /// Returns the `filename` field of this gzip header, if present.
    ///
    /// The `filename` field the gzip header is supposed to be stored using ISO 8859-1 (LATIN-1)
    /// encoding and be zero-terminated if following the specification.
    pub fn filename(&self) -> Option<&[u8]> {
        self.filename.as_ref().map(|s| &s[..])
    }

    /// Returns the `extra` field of this gzip header, if present.
    pub fn extra(&self) -> Option<&[u8]> {
        self.extra.as_ref().map(|s| &s[..])
    }

    /// Returns the `comment` field of this gzip stream's header, if present.
    ///
    /// The `comment` field in the gzip header is supposed to be stored using ISO 8859-1 (LATIN-1)
    /// encoding and be zero-terminated if following the specification.
    pub fn comment(&self) -> Option<&[u8]> {
        self.comment.as_ref().map(|s| &s[..])
    }

    /// Returns the `mtime` field of this gzip header.
    ///
    /// This gives the most recent modification time of the contained file, or alternatively
    /// the timestamp of when the file was compressed if the data did not come from a file, or
    /// a timestamp was not available when compressing. The time is specified the Unix format,
    /// that is: seconds since 00:00:00 GMT, Jan. 1, 1970. (Not that this may cause problems for
    /// MS-DOS and other systems that use local rather than Universal time.)
    /// An `mtime` value of 0 means that the timestamp is not set.
    pub fn mtime(&self) -> u32 {
        self.mtime
    }

    /// Returns the `mtime` field of this gzip header as a `SystemTime` if present.
    ///
    /// Returns `None` if the `mtime` is not set, i.e 0.
    /// See [`mtime`](#method.mtime) for more detail.
    pub fn mtime_as_datetime(&self) -> Option<time::SystemTime> {
        if self.mtime == 0 {
            None
        } else {
            let duration = time::Duration::new(u64::from(self.mtime), 0);
            let datetime = time::UNIX_EPOCH + duration;
            Some(datetime)
        }
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
                   "corrupt gzip stream does not have a matching header checksum")
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

/// Try to read a gzip header from the provided reader.
///
/// Returns a `GzHeader` with the fields filled out if sucessful, or an `io::Error` with
/// `ErrorKind::InvalidInput` if decoding of the header.
///
/// Note that a gzip steam can contain multiple "members". Each member contains a header,
/// followed by compressed data and finally a checksum and byte count.
/// This method will only read the header for the "member" at the start of the stream.
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
                ((header[6] as u32) << 16) | ((header[7] as u32) << 24);
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

    // If the `FHCRC` flag is set, the header contains a two-byte CRC16 checksum of the header bytes
    // that needs to be validated.
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

    fn roundtrip_inner(use_crc: bool) {
        const COMMENT: &'static [u8] = b"Comment";
        const FILENAME: &'static [u8] = b"Filename";
        const MTIME: u32 = 12345;
        const OS: FileSystemType = FileSystemType::NTFS;
        const XFL: ExtraFlags = ExtraFlags::FastestCompression;

        let header = GzBuilder::new()
            .comment(COMMENT)
            .filename(FILENAME)
            .mtime(MTIME)
            .os(OS)
            .xfl(ExtraFlags::FastestCompression)
            .into_header_inner(use_crc);

        let mut reader = Cursor::new(header.clone());

        let header_read = read_gz_header(&mut reader).unwrap();
        assert_eq!(header_read.comment().unwrap(), COMMENT);
        assert_eq!(header_read.filename().unwrap(), FILENAME);
        assert_eq!(header_read.mtime(), MTIME);
        assert_eq!(header_read.os(), OS.as_u8());
        assert_eq!(header_read.xfl(), XFL.as_u8());
    }

    #[test]
    fn roundtrip() {
        roundtrip_inner(false);
    }

    #[test]
    fn roundtrip_with_crc() {
        roundtrip_inner(true);
    }
}
