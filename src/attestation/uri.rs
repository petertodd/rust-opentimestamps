use std::cmp;
use std::io::{self, Read, Write};
use std::fmt;

use thiserror::Error;

use crate::ser::{self, DeserializeError};

#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UriString(String);

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum UriStringError {
    #[error("too long")]
    TooLong,

    #[error("invalid character '{0}'")]
    InvalidChar(u8),
}

impl UriString {
    pub const MAX_LENGTH: usize = 1000;
    pub const ALLOWED_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:";

    fn validate_str(s: &[u8]) -> Result<(), UriStringError> {
        if s.len() > Self::MAX_LENGTH {
            Err(UriStringError::TooLong)
        } else {
            for c in s {
                match c {
                    b'A' ..= b'Z' |
                    b'a' ..= b'z' |
                    b'0' ..= b'9' |
                    b'-' | b'.' | b'_' | b'/' | b':' => {},
                    b => {
                        return Err(UriStringError::InvalidChar(*b));
                    }
                }
            }
            Ok(())
        }
    }

    pub fn serialize(&self, writer: &mut impl Write) -> Result<(), io::Error> {
        ser::serialize_u64(self.len() as u64, writer)?;
        writer.write_all(self.as_bytes())?;
        Ok(())
    }

    pub fn deserialize(reader: &mut impl Read) -> Result<Self, DeserializeError> {
        let len = ser::deserialize_u64(reader)?;
        if len > Self::MAX_LENGTH as u64 {
            return Err(DeserializeError::Invalid(UriStringError::TooLong.into()))
        } else {
            let mut v = vec![0; len as usize];
            reader.read_exact(&mut v[..])?;

            Self::validate_str(&v).map_err(|err| DeserializeError::Invalid(err.into()))?;
            let s = String::from_utf8(v).expect("already validated");
            Ok(Self(s))
        }
    }
}

impl std::ops::Deref for UriString {
    type Target = String;

    fn deref(&self) -> &String {
        &self.0
    }
}

impl std::convert::TryFrom<&str> for UriString {
    type Error = UriStringError;

    fn try_from(s: &str) -> Result<Self, UriStringError> {
        UriString::validate_str(s.as_bytes())?;
        Ok(Self(String::from(s)))
    }
}

impl std::convert::TryFrom<String> for UriString {
    type Error = UriStringError;

    fn try_from(s: String) -> Result<Self, UriStringError> {
        UriString::validate_str(s.as_bytes())?;
        Ok(Self(s))
    }
}

impl std::convert::From<UriString> for String {
    fn from(uri: UriString) -> String {
        uri.0
    }
}

impl cmp::PartialEq<str> for UriString {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl cmp::PartialEq<UriString> for str {
    fn eq(&self, other: &UriString) -> bool {
        self.eq(&other.0)
    }
}

impl fmt::Display for UriString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_serialize() {
        #[track_caller]
        fn t(uri: UriString, expected: &[u8]) {
            let mut v = vec![];
            uri.serialize(&mut v).unwrap();
            assert_eq!(v, expected);
        }

        t(UriString::default(), &[0]);
        t("a".try_into().unwrap(), &[1, b'a']);
        t("https://a.pool.opentimestamps.org".try_into().unwrap(),
          b"\x21https://a.pool.opentimestamps.org");
        t("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".try_into().unwrap(),
          b"\x80\x01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    }

    #[test]
    fn test_deserialize() {
        #[track_caller]
        fn t(mut serialized: &[u8], expected: &str) {
            let actual = UriString::deserialize(&mut serialized).unwrap();
            assert_eq!(&actual, expected);
        }

        t(b"\x00", "");
        t(b"\x01a", "a");
        t(b"\x80\x01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    }

    #[test]
    fn test_deserialize_errors() {
        use std::error::Error;

        #[track_caller]
        fn t(mut serialized: &[u8], expected_err: UriStringError) {
            let actual_err = UriString::deserialize(&mut serialized).unwrap_err();
            let actual_err: &dyn Error = actual_err.source().expect("source");
            let actual_err: &UriStringError = actual_err.downcast_ref().unwrap();
            assert_eq!(actual_err, &expected_err);
        }

        t(b"\x01\x00", UriStringError::InvalidChar(0x00));
        t(b"\x80\x80\x80\x80\x80\x01", UriStringError::TooLong);
    }
}
