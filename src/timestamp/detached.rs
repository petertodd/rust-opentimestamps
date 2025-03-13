//! Detached timestamp proof files.
//!
//! This module contains support for the `.ots` files produced by the OpenTimestamps Client.

use super::*;

/// A digest of a file, used by `DetachedTimestampFile`.
///
/// Since a file may be of any size, a timestamp proof for a file always starts by hashing the
/// entire file with one of the supported hashing algorithms. This type holds the expected digest,
/// and the type of hashing algorithm to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileDigest {
    Sha1([u8; 20]),
    Ripemd160([u8; 20]),
    Sha256([u8; 32]),
}

impl FileDigest {
    pub fn to_hash_op(&self) -> HashOp {
        match self {
            Self::Sha1(_) => HashOp::Sha1,
            Self::Ripemd160(_) => HashOp::Ripemd160,
            Self::Sha256(_) => HashOp::Sha256,
        }
    }
}

impl AsRef<[u8]> for FileDigest {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Sha1(digest) => digest,
            Self::Ripemd160(digest) => digest,
            Self::Sha256(digest) => digest,
        }
    }
}

/// A timestamp proof for a file.
///
/// This is a wrapper for a `Timestamp<FileDigest>`, along with serialization/deserialization code
/// for the timestamp file specific header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetachedTimestampFile {
    inner: Timestamp<FileDigest>,
}

impl std::ops::Deref for DetachedTimestampFile {
    type Target = Timestamp<FileDigest>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DetachedTimestampFile {
    /// The magic bytes that detached timestamp files start with.
    ///
    /// The magic bytes start with a null byte to make them clearly recognizable as a binary file,
    /// and include the strings "OpenTimestamps" and "Proof" to make them easily recognized in hex
    /// dumps:
    ///
    /// ```no_test
    /// $ hexdump -C example.txt.ots
    /// 00000000  00 4f 70 65 6e 54 69 6d  65 73 74 61 6d 70 73 00  |.OpenTimestamps.|
    /// 00000010  00 50 72 6f 6f 66 00 bf  89 e2 e8 84 e8 92 94 01  |.Proof..........|
    /// ```
    ///
    /// The remaining random bytes are simply randomly chosen non-ASCII bytes.
    pub const HEADER_MAGIC: &[u8; 31] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
    const MAJOR_VERSION: u8 = 1;

    /// The IANA Media Type that should be used for detached timestamp files.
    ///
    /// # References
    ///
    /// [IANA Media Type Assignment](https://www.iana.org/assignments/media-types/application/vnd.opentimestamps.ots)
    pub const MEDIA_TYPE_STR: &str = "application/vnd.opentimestamps.ots";

    /// Returns the `FileDigest`.
    pub fn digest(&self) -> &FileDigest {
        self.inner.msg()
    }

    pub fn serialize(&self, writer: &mut impl io::Write) -> Result<(), io::Error> {
        writer.write_all(Self::HEADER_MAGIC)?;
        writer.write_all(&[Self::MAJOR_VERSION])?;

        let b = match self.digest() {
            FileDigest::Sha1(_) => 0x02,
            FileDigest::Ripemd160(_) => 0x02,
            FileDigest::Sha256(_) => 0x08,
        };

        writer.write_all(&[b])?;
        writer.write_all(self.digest().as_ref())?;
        self.inner.serialize(writer)
    }

    pub fn to_serialized_bytes(&self) -> Box<[u8]> {
        let mut r = Vec::with_capacity(
            Self::HEADER_MAGIC.len() + 1 +
            1 + self.digest().as_ref().len() +
            self.inner.steps().0.len());
        self.serialize(&mut r).expect("writes to Vec are infallible");
        r.into_boxed_slice()
    }

    pub fn deserialize(reader: &mut impl io::Read) -> Result<Self, DeserializeError> {
        let mut magic = [0u8; Self::HEADER_MAGIC.len()];

        reader.read_exact(&mut magic)?;

        if &magic != Self::HEADER_MAGIC {
            return Err("bad magic".into());
        }

        let mut major = [0u8; 1];
        reader.read_exact(&mut major)?;

        if major[0] != Self::MAJOR_VERSION {
            return Err("bad major version".into());
        }

        let mut op = [0u8; 1];
        reader.read_exact(&mut op)?;

        let digest = match op {
            [0x02] => {
                let mut digest = [0u8; 20];
                reader.read_exact(&mut digest[..])?;
                FileDigest::Sha1(digest)
            },
            [0x03] => {
                let mut digest = [0u8; 20];
                reader.read_exact(&mut digest[..])?;
                FileDigest::Ripemd160(digest)
            },
            [0x08] => {
                let mut digest = [0u8; 32];
                reader.read_exact(&mut digest[..])?;
                FileDigest::Sha256(digest)
            },
            [_x] => {
                return Err("unknown op".into());
            }
        };

        let inner = Timestamp::deserialize(digest, reader)?;

        Ok(Self { inner })
    }
}

#[cfg(test)]
mod test {
}
