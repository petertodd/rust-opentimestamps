//! Serialization and deserialization.

use std::io::{self, Read, Write};

use thiserror::Error;

use crate::timestamp::Timestamp;

/// Error returned by deserialization.
#[derive(Debug, Error)]
pub enum DeserializeError {
    /// An IO error was encountered.
    #[error("io error: {0}")]
    Io(#[source] io::Error),

    /// Deserialization failed due to invalid data.
    #[error("{0}")]
    Invalid(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl From<io::Error> for DeserializeError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<&str> for DeserializeError {
    fn from(err: &str) -> Self {
        String::from(err).into()
    }
}

impl From<String> for DeserializeError {
    fn from(err: String) -> Self {
        Self::Invalid(err.into())
    }
}


pub fn serialize_u64(mut n: u64, writer: &mut impl Write) -> Result<(), io::Error> {
    while n >= 0b1000_0000 {
        let b = n | 0b1000_0000;
        writer.write_all(&[b as u8])?;
        n >>= 7;
    }
    writer.write_all(&[n as u8])?;
    Ok(())
}

pub fn serialize_u32(n: u32, writer: &mut impl Write) -> Result<(), io::Error> {
    serialize_u64(n as u64, writer)
}

fn deserialize_varint(reader: &mut impl Read, bits: u32) -> Result<u64, DeserializeError> {
    let mut n = 0;
    let mut shift = 0;

    while shift < bits {
        // Bottom 7 bits are value bits
        let mut b = [0u8; 1];
        reader.read_exact(&mut b)?;
        n |= ((b[0] & 0x7f) as u64) << shift;

        // Top bit is the continue bit
        if b[0] & 0x80 == 0 {
            if n == 0 && shift > 0 {
                return Err("zero encoded with more than one byte".into())
            } else {
                return Ok(n);
            }
        }
        shift += 7;
    }

    Err("varint overflow".into())
}

pub fn deserialize_u64(reader: &mut impl Read) -> Result<u64, DeserializeError> {
    deserialize_varint(reader, u64::BITS)
}

pub fn deserialize_u32(reader: &mut impl Read) -> Result<u32, DeserializeError> {
    deserialize_varint(reader, u32::BITS).map(|n| n as u32)
}

pub fn serialize_varbytes(buf: &[u8], writer: &mut impl Write) -> Result<(), io::Error> {
    serialize_u64(buf.len() as u64, writer)?;
    writer.write_all(buf)
}

pub fn deserialize_varbytes<'a>(buf: &'a mut [u8], reader: &mut impl Read) -> Result<&'a [u8], DeserializeError> {
    let len = deserialize_u64(reader)?;
    if len > buf.len() as u64 {
        Err(DeserializeError::Invalid("max length exceeded".into()))
    } else {
        let len = len as usize; // valid as we just checked that it is <= buf.len(), a usize
        let buf = &mut buf[0 .. len];
        reader.read_exact(buf)?;
        Ok(buf)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_serialize_u64() {
        #[track_caller]
        fn t(n: u64, expected: &[u8]) {
            let mut actual = vec![];
            serialize_u64(n, &mut actual).unwrap();
            assert_eq!(actual, expected);
        }

        t(0, &[0]);
        t(1, &[1]);
        t(0b111_1111, &[0b111_1111]);
        t(0b1000_0000, &[0b1000_0000, 1]);
        t(0b1000_0001, &[0b1000_0001, 1]);
        t(0b1100_0000, &[0b1100_0000, 1]);
    }

    #[test]
    fn test_deserialize_u64() {
        #[track_caller]
        fn t(mut buf: &[u8], expected: u64) {
            assert_eq!(deserialize_u64(&mut buf).unwrap(), expected);
        }

        t(&[0], 0);
        t(&[0b1], 1);
        t(&[0b11], 0b11);
        t(&[0b111_1111], 0b111_1111);
        t(&[0b1111_1111, 0], 0b111_1111);

        // TODO: check the actual errors
        let mut buf: &[u8] = &[0b1000_0000, 0b0000_0000];
        deserialize_u64(&mut buf).unwrap_err();

        let mut buf: &[u8] = &[0b1000_0000; 9];
        deserialize_u64(&mut buf).unwrap_err();
    }
}
