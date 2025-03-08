//! Commitment operations --- the mathematical building blocks of timestamp proofs.
//!
//! A commitment operation is a mathematical function *f(m) -> r* with the following property: it
//! must be infeasible to create an *r* for a given *m*, without already having knowledge of *m*.
//! This infeasibility is what makes commitment operations useful for *time*-stamps: if *r* exists,
//! *m* must have already existed too.
//!
//! For simple commitment operations such as append and prepend, the relationship is trivial: *r*
//! contains *m*. Hexlify is another trivial example: there exists a 1-1 relationship between every
//! message and its hex representation, so if you know one you already know the other.
//!
//! FIXME: explain hash ops

use std::fmt;
use std::io;

use bitcoin_hashes;

/// The maximum size of an operation result.
pub const MAX_OUTPUT_LENGTH: usize = 4096;

/// Performs the `HashOp::Sha1` operation.
pub fn op_sha1(msg: &[u8]) -> [u8; 20] {
    bitcoin_hashes::Sha1::hash(msg).to_byte_array()
}

/// Performs the `HashOp::Ripemd160` operation.
pub fn op_ripemd160(msg: &[u8]) -> [u8; 20] {
    bitcoin_hashes::Ripemd160::hash(msg).to_byte_array()
}

/// Performs the `HashOp::Sha256` operation.
pub fn op_sha256(msg: &[u8]) -> [u8; 32] {
    bitcoin_hashes::Sha256::hash(msg).to_byte_array()
}

/// Performs the `Op::Hexlify` operation.
pub fn op_hexlify(msg: &[u8]) -> Result<Box<[u8]>, OverflowError> {
    if msg.len() > MAX_OUTPUT_LENGTH / 2 {
        return Err(OverflowError { len: msg.len() });
    };

    let mut v = Vec::with_capacity(msg.len() * 2);

    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    for b in msg {
        v.push(HEX_CHARS[((b & 0xf0) >> 4) as usize]);
        v.push(HEX_CHARS[(b & 0x0f) as usize]);
    }

    Ok(v.into())
}

/// A cryptographic hashing operation.
///
/// These operations are notable for being infallible: all inputs to a hash operation map to a
/// valid output digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashOp {
    Sha1,
    Sha256,
    Ripemd160,
}

impl HashOp {
    /// Evaluates the operation against a message.
    pub fn eval(&self, msg: &[u8]) -> Box<[u8]> {
        match &self {
            Self::Sha1 => op_sha1(msg).into(),
            Self::Sha256 => op_sha256(msg).into(),
            Self::Ripemd160 => op_ripemd160(msg).into(),
        }
    }

    pub fn serialize(&self, w: &mut impl io::Write) -> Result<(), io::Error> {
        let b = match self {
            Self::Sha1 => 0x02,
            Self::Sha256 => 0x08,
            Self::Ripemd160 => 0x03,
        };
        w.write_all(&[b])
    }
}

impl fmt::Display for HashOp {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let s = match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Ripemd160 => "ripemd160",
        };
        s.fmt(f)
    }
}


/// Error returned when an `Op` fails due to size overflow.
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[error("operation overflow")]
pub struct OverflowError {
    len: usize,
}

fn op_concat(left: &[u8], right: &[u8]) -> Result<Box<[u8]>, OverflowError> {
    let len = left.len() + right.len();
    if len > MAX_OUTPUT_LENGTH {
        Err(OverflowError { len })
    } else {
        let mut r = Vec::with_capacity(len);
        r.extend_from_slice(left);
        r.extend_from_slice(right);
        Ok(r.into())
    }
}

/// A timestamp proof operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op<B = Box<[u8]>> {
    /// A hashing operation.
    HashOp(HashOp),

    /// Appends `B` to the input message.
    Append(B),

    /// Prepends the input message with `B`.
    Prepend(B),

    /// Converts the input message to lower-case hex.
    Hexlify,
}

impl<B: AsRef<[u8]>> Op<B> {
    /// Evaluates an operation against a message.
    ///
    /// If the operation would result in a message of size greater than `MAX_OUTPUT_LENGTH`, an
    /// `OverflowError` is returned instead.
    pub fn eval(&self, msg: &[u8]) -> Result<Box<[u8]>, OverflowError> {
        match self {
            Self::HashOp(op) => Ok(op.eval(msg)),
            Self::Append(right) => op_concat(msg, right.as_ref()),
            Self::Prepend(left) => op_concat(left.as_ref(), msg),
            Self::Hexlify => op_hexlify(msg),
        }
    }

    pub fn serialize(&self, w: &mut impl io::Write) -> Result<(), io::Error> {
        match self {
            Self::HashOp(op) => op.serialize(w),
            Self::Append(right) => {
                w.write_all(&[0xf0])?;
                todo!()
            },
            Self::Prepend(left) => {
                w.write_all(&[0xf1])?;
                todo!()
            },
            Self::Hexlify => w.write_all(&[0xf3]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_op_hexlify() {
        #[track_caller]
        fn t(i: &[u8], expected: &[u8]) {
            let actual = op_hexlify(i).unwrap();
            assert_eq!(actual.as_ref(), expected);
        }

        t(&[], &[]);
        t(&[0], b"00");
        t(&[1], b"01");
        t(&[0xab], b"ab");
        t(&[0xab, 0xcd], b"abcd");

        t(&[0; 2048], &[48; 4096]);
        assert_eq!(op_hexlify(&[0; 2049]),
                   Err(OverflowError { len: 2049 }));
    }
}
