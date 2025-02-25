use std::io;

use thiserror::Error;

use crate::op::{self, HashOp, Op};
use crate::attestation::Attestation;
use crate::ser::{self, DeserializeError};

pub mod detached;

/// A step in a timestamp proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Attestation(Attestation),
    Op(Op),
    Fork,
}

impl Step {
    pub fn serialize(&self, writer: &mut impl io::Write) -> Result<(), io::Error> {
        match self {
            Self::Attestation(attestation) => {
                writer.write_all(&[0x00])?;
                attestation.serialize(writer)
            },
            Self::Op(Op::HashOp(op)) => {
                let op = match op {
                    HashOp::Sha1 => 0x02,
                    HashOp::Sha256 => 0x08,
                    HashOp::Ripemd160 => 0x03,
                };
                writer.write_all(&[op])
            },
            Self::Op(Op::Hexlify) => writer.write_all(&[0xf3]),
            Self::Op(Op::Append(rhs)) => {
                writer.write_all(&[0xf0])?;
                ser::serialize_varbytes(rhs, writer)
            },
            Self::Op(Op::Prepend(lhs)) => {
                writer.write_all(&[0xf1])?;
                ser::serialize_varbytes(lhs, writer)
            },
            Self::Fork => writer.write_all(&[0xff]),
        }
    }

    pub fn to_serialized_bytes(&self) -> Box<[u8]> {
        let mut r = vec![];
        self.serialize(&mut r).expect("Vec write implementation is infallible");
        r.into_boxed_slice()
    }

    pub fn deserialize(reader: &mut impl io::Read) -> Result<Self, DeserializeError> {
        let mut bin_op_arg = [0; op::MAX_OUTPUT_LENGTH]; // FIXME: is this actually the max?

        let mut b = [0u8; 1];
        reader.read_exact(&mut b[..])?;
        match b[0] {
            0x00 => Ok(Self::Attestation(Attestation::deserialize(reader)?)),
            0xff => Ok(Self::Fork),

            0x02 => Ok(Self::Op(Op::HashOp(HashOp::Sha1))),
            0x08 => Ok(Self::Op(Op::HashOp(HashOp::Sha256))),
            0x03 => Ok(Self::Op(Op::HashOp(HashOp::Ripemd160))),
            0xf3 => Ok(Self::Op(Op::Hexlify)),

            0xf0 => {
                let rhs = ser::deserialize_varbytes(&mut bin_op_arg, reader)?;
                Ok(Self::Op(Op::Append(Vec::from(rhs).into())))
            },
            0xf1 => {
                let lhs = ser::deserialize_varbytes(&mut bin_op_arg, reader)?;
                Ok(Self::Op(Op::Prepend(Vec::from(lhs).into())))
            },
            _x => Err("unknown op".into()),
        }
    }
}

/// Steps in a timestamp proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Steps(Vec<Step>);

impl Steps {
    pub(crate) fn trust(steps: Vec<Step>) -> Self {
        Self(steps)
    }

    pub fn serialize(&self, w: &mut impl io::Write) -> Result<(), io::Error> {
        for step in &self.0 {
            step.serialize(w)?;
        }
        Ok(())
    }

    pub fn to_serialized_bytes(&self) -> Box<[u8]> {
        let mut r = vec![];
        self.serialize(&mut r).expect("Vec write implementation is infallible");
        r.into_boxed_slice()
    }

    pub fn deserialize(reader: &mut impl io::Read) -> Result<Self, DeserializeError> {
        let mut steps = vec![];

        let mut tips = 1;
        while tips >= 1 {
            let step = Step::deserialize(reader)?;
            match step {
                Step::Fork => {
                    tips += 1;
                },
                Step::Attestation(_) => {
                    tips -= 1;
                },
                Step::Op(_) => {},
            }
            steps.push(step);
        };

        Ok(Self(steps))
    }
}

impl IntoIterator for Steps {
    type Item = Step;
    type IntoIter = std::vec::IntoIter<Step>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Steps {
    type Item = &'a Step;
    type IntoIter = std::slice::Iter<'a, Step>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timestamp<M = Box<[u8]>> {
    msg: M,
    steps: Steps,
}

impl<M> Timestamp<M> {
    /// Returns the message this timestamp proof timestamps.
    pub fn msg(&self) -> &M {
        &self.msg
    }

    pub fn steps(&self) -> &Steps {
        &self.steps
    }
}

impl<M: AsRef<[u8]>> Timestamp<M> {
    /// Returns an iterator over all the attestations in this timestamp.
    pub fn attestations(&self) -> impl Iterator<Item = Attestation> {
        [].into_iter()
    }

    pub fn serialize(&self, writer: &mut impl io::Write) -> Result<(), io::Error> {
        self.steps.serialize(writer)
    }

    pub fn deserialize(msg: M, reader: &mut impl io::Read) -> Result<Self, DeserializeError> {
        let steps = Steps::deserialize(reader)?;

        // FIXME: check the steps are actually valid
        Ok(Self { msg, steps })
    }
}

#[derive(Debug, Clone)]
pub struct TimestampBuilder<M = Box<[u8]>> {
    msg: M,
    result: Option<Box<[u8]>>,
    steps: Vec<Step>,
}

impl<M: Default> Default for TimestampBuilder<M> {
    fn default() -> Self {
        Self {
            msg: Default::default(),
            result: None,
            steps: vec![],
        }
    }
}

impl<M> TimestampBuilder<M> {
    pub fn new(msg: M) -> Self {
        Self {
            msg,
            steps: vec![],
            result: None,
        }
    }

    pub fn msg(&self) -> &M {
        &self.msg
    }
}

impl<M: AsRef<[u8]>> TimestampBuilder<M> {
    pub fn try_push_op(mut self, op: Op) -> Result<Self, op::OverflowError> {
        self.result = Some(op.eval(self.result())?);
        self.steps.push(Step::Op(op));
        Ok(self)
    }

    pub fn hash(mut self, op: HashOp) -> Self {
        self.result = Some(op.eval(self.result()));
        self.steps.push(Step::Op(Op::HashOp(op)));
        self
    }

    pub fn append(self, right: &[u8]) -> Self {
        self.try_push_op(Op::Append(right.into()))
            .expect("overflow")
    }

    pub fn prepend(self, left: &[u8]) -> Self {
        self.try_push_op(Op::Prepend(left.into()))
            .expect("overflow")
    }

    /// Returns the result of the operations so far.
    pub fn result(&self) -> &[u8] {
        self.result.as_ref()
                   .map(|r| r.as_ref())
                   .unwrap_or(self.msg.as_ref())
    }

    pub fn finish_with_timestamps<M2>(mut self, timestamps: impl IntoIterator<Item = Timestamp<M2>>) -> Timestamp<M>
        where M2: AsRef<[u8]>
    {
        let mut timestamps = timestamps.into_iter().peekable();
        while let Some(timestamp) = timestamps.next() {
            assert_eq!(timestamp.msg().as_ref(), self.result());

            if let Some(_) = timestamps.peek() {
                self.steps.push(Step::Fork);
            }

            self.steps.extend(timestamp.steps);
        }

        Timestamp {
            msg: self.msg,
            steps: Steps(self.steps),
        }
    }

    pub fn finish_with_attestation(mut self, attestation: Attestation) -> Timestamp<M> {
        self.steps.push(Step::Attestation(attestation));
        Timestamp {
            msg: self.msg,
            steps: Steps(self.steps),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_builder() {
        let _t = TimestampBuilder::new(b"hello")
                                 .append(b" world!")
                                 .hash(HashOp::Sha256)
                                 .hash(HashOp::Sha256)
                                 .hash(HashOp::Sha256)
                                 .finish_with_attestation(Attestation::Bitcoin { block_height: 42 });
    }
}
