//! Time attestation: claims about when messages existed in time.
//!
//! Commitment operations only prove before-after relationships between different messages; math
//! alone is insufficient to determine when a message existed. Thus we need *attestations* by time
//! sources that we trust to provide evidence as to when messages existed. This module provides the
//! tooling necessary to represent attestations in timestamp proofs.

use std::io;

use crate::ser::{self, DeserializeError};

pub mod uri;
mod tag;

use self::uri::UriString;

pub type Tag = [u8; 8];

const BITCOIN_ATTESTATION_TAG: Tag = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
const PENDING_ATTESTATION_TAG: Tag = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const MAX_PAYLOAD_SIZE: usize = 8192;

/// A time attestation in a `Timestamp` proof.
///
/// This enum represents every different type of attestation that the OpenTimestamps protocol
/// supports.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Attestation {
    Bitcoin {
        block_height: u32,
    },
    Pending(uri::UriString),
    Unknown {
        tag: Tag,
        payload: Box<[u8]>,
    }
}

impl Attestation {
    pub fn serialize(&self, writer: &mut impl io::Write) -> Result<(), io::Error> {
        match self {
            Self::Bitcoin { block_height } => {
                writer.write_all(&BITCOIN_ATTESTATION_TAG)?;

                let mut serialized = vec![];
                ser::serialize_u32(*block_height, &mut serialized).expect("io error not posible on vec");
                ser::serialize_varbytes(&serialized, writer)
            },
            Self::Pending(uri) => {
                writer.write_all(&PENDING_ATTESTATION_TAG)?;

                let mut serialized = vec![];
                uri.serialize(&mut serialized).expect("io error not possible on vec");
                ser::serialize_varbytes(&serialized, writer)
            }
            Self::Unknown { tag, payload } => {
                writer.write_all(tag)?;
                ser::serialize_varbytes(payload, writer)
            },
        }
    }

    pub fn deserialize(reader: &mut impl io::Read) -> Result<Self, DeserializeError> {
        let mut tag = [0u8; 8];
        reader.read_exact(&mut tag)?;

        let mut buf = [0; MAX_PAYLOAD_SIZE];
        let mut payload = ser::deserialize_varbytes(&mut buf, reader)?;

        match tag {
            // FIXME: we should make sure the payload is fully deserialized
            // what does python-opentimestamps do?
            BITCOIN_ATTESTATION_TAG => {
                let block_height = ser::deserialize_u32(&mut payload)?;
                Ok(Self::Bitcoin { block_height })
            },
            PENDING_ATTESTATION_TAG => {
                Ok(Self::Pending(UriString::deserialize(&mut payload)?))
            },
            unknown_tag => {
                Ok(Self::Unknown {
                    tag: unknown_tag,
                    payload: Vec::from(payload).into_boxed_slice(),
                })
            },
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_serialize() {
        #[track_caller]
        fn t(attestation: Attestation, expected: &[u8]) {
            let mut v = vec![];
            attestation.serialize(&mut v).unwrap();
            assert_eq!(v, expected);
        }

        t(Attestation::Pending(UriString::try_from("").unwrap()),
          &[0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e,
            0x01, 0x00]);

        t(Attestation::Pending(UriString::try_from("a").unwrap()),
          &[0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e,
            0x02, 0x01, b'a']);
    }

    #[test]
    fn test_deserialize() {
        #[track_caller]
        fn t(mut serialized: &[u8], expected: Attestation) {
            let actual = Attestation::deserialize(&mut serialized)
                                     .unwrap();
            assert_eq!(serialized.len(), 0, "not all bytes consumed");
            assert_eq!(actual, expected);
        }

        t(&[0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e,
            0x01, 0x00],
          Attestation::Pending(UriString::try_from("").unwrap()));

        t(&[0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e,
            0x02, 0x01, b'a'],
          Attestation::Pending(UriString::try_from("a").unwrap()));
    }
}
