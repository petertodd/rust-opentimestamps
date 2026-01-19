//! Timestamp proofs.
//!
//! Here we combine commitment operations and attestations to:
//!
//! 1) Prove via *commitment operations* that a message existed prior to one or more other messages.
//! 2) *Attest* to the fact that the message was created prior to a particular time.

use std::borrow::Cow;
use std::io;
use std::sync::Arc;

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

    /// Returns an iterator over all the attestations in these steps.
    pub fn attestations<'a>(&'a self) -> Attestations<'a> {
        Attestations {
            remaining_steps: self.0.iter(),
        }
    }

    pub fn serialize(&self, w: &mut impl io::Write) -> Result<(), io::Error> {
        for step in &self.0 {
            step.serialize(w)?;
        }
        Ok(())
    }

    pub fn to_serialized_bytes(&self) -> Box<[u8]> {
        let mut r = Vec::with_capacity(self.0.len()); // at least one byte per step
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

#[derive(Debug, Clone)]
pub struct StepsEvaluator<'a> {
    stack: Vec<Arc<Cow<'a, [u8]>>>,
    dropped_result: Option<Arc<Cow<'a, [u8]>>>,
    next_steps: &'a [Step],
}

#[derive(Debug, thiserror::Error)]
pub enum StepsEvaluatorError {
    #[error("opcode evaluation failed: {0}")]
    Op(#[from] op::OverflowError),

    #[error("insufficient steps")]
    InsufficientSteps,
}

impl<'a> StepsEvaluator<'a> {
    pub fn new(initial_msg: &'a [u8], steps: &'a [Step]) -> Self {
        Self {
            stack: vec![Arc::new(Cow::Borrowed(initial_msg))],
            dropped_result: None,
            next_steps: steps,
        }
    }

    pub fn result(&self) -> Option<&[u8]> {
        self.stack.last().map(|s| {
            let s: &[u8] = &*s;
            s
        })
    }

    pub fn try_next_step(&mut self) -> Option<Result<(&Step, &[u8]), StepsEvaluatorError>> {
        match (self.stack.last(), self.next_steps.split_first()) {
            (None, None) => None,
            (Some(msg), Some((ref next_step, remaining_steps))) => {
                match next_step {
                    Step::Attestation(_attestation) => {
                        let msg = self.stack.pop().unwrap();
                        self.next_steps = remaining_steps;
                        self.dropped_result = Some(msg);
                        Some(Ok((next_step, self.dropped_result.as_ref().unwrap())))
                    },
                    Step::Op(op) => {
                        match op.eval(msg) {
                            Ok(result) => {
                                *self.stack.last_mut().unwrap() = Arc::new(Cow::Owned(Vec::from(result)));
                                self.next_steps = remaining_steps;
                                Some(Ok((next_step, self.result().unwrap())))
                            },
                            Err(err) => {
                                Some(Err(err.into()))
                            },
                        }
                    },
                    Step::Fork => {
                        self.stack.push(Arc::clone(msg));
                        self.next_steps = remaining_steps;
                        Some(Ok((next_step, self.result().unwrap())))
                    }
                }
            },
            (Some(_msg), None) => Some(Err(StepsEvaluatorError::InsufficientSteps)),
            (None, Some((_next_step, _remaining_steps))) => todo!("FIXME: what exactly does this mean? invalid steps?"),
        }
    }
}

#[derive(Debug)]
pub struct Attestations<'a> {
    remaining_steps: std::slice::Iter<'a, Step>,
}

impl<'a> Iterator for Attestations<'a> {
    type Item = &'a Attestation;

    fn next(&mut self) -> Option<&'a Attestation> {
        loop {
            match self.remaining_steps.next() {
                None => break None,
                Some(Step::Attestation(attestation)) => break Some(attestation),
                _ => {},
            }
        }
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

/// A timestamp proof.
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

    /// Returns the steps in this timestamp.
    pub fn steps(&self) -> &Steps {
        &self.steps
    }

    /// Converts a `Timestamp` to a different message type.
    ///
    /// `msg1.as_ref() == msg2.as_ref()` must hold for correctness.
    pub fn map_msg<M2>(self, f: impl FnOnce(M) -> M2) -> Timestamp<M2> {
        Timestamp {
            steps: self.steps,
            msg: f(self.msg),
        }
    }
}

impl<M: AsRef<[u8]>> Timestamp<M> {
    pub fn serialize(&self, writer: &mut impl io::Write) -> Result<(), io::Error> {
        self.steps.serialize(writer)
    }

    pub fn to_serialized_bytes(&self) -> Box<[u8]> {
        self.steps.to_serialized_bytes()
    }

    pub fn deserialize(msg: M, reader: &mut impl io::Read) -> Result<Self, DeserializeError> {
        let steps = Steps::deserialize(reader)?;

        // FIXME: check the steps are actually valid
        Ok(Self { msg, steps })
    }
}

/// A builder for creating a `Timestamp`.
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
    /// Creates a new `TimestampBuilder`, taking the message to be timestamped.
    pub fn new(msg: M) -> Self {
        Self {
            msg,
            steps: vec![],
            result: None,
        }
    }

    /// Returns a reference to the message being timestamped.
    pub fn msg(&self) -> &M {
        &self.msg
    }
}

impl<M: AsRef<[u8]>> TimestampBuilder<M> {
    /// Tries to push an `Op` to the proof.
    ///
    /// Returns `OverflowError` if evaluation overflowed.
    pub fn try_push_op(mut self, op: Op) -> Result<Self, op::OverflowError> {
        self.result = Some(op.eval(self.result())?);
        self.steps.push(Step::Op(op));
        Ok(self)
    }

    /// Pushes a `HashOp` to the proof.
    ///
    /// Infallible, because hash operations can't fail.
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

    /// Hashes the result with a 128-bit random nonce for privacy.
    pub fn hash_with_nonce(self) -> Self {
        let nonce: [u8; 16] = rand::random();

        if self.result().len() + nonce.len() > op::MAX_OUTPUT_LENGTH {
            self.hash(HashOp::Sha256)
        } else {
            self
        }.append(&nonce)
         .hash(HashOp::Sha256)
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
            steps: Steps::trust(self.steps),
        }
    }

    pub fn finish_with_attestation(mut self, attestation: Attestation) -> Timestamp<M> {
        self.steps.push(Step::Attestation(attestation));
        Timestamp {
            msg: self.msg,
            steps: Steps::trust(self.steps),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_builder() {
        let t = TimestampBuilder::new(b"hello")
                                 .append(b" world!")
                                 .hash(HashOp::Sha256)
                                 .hash(HashOp::Sha256)
                                 .hash(HashOp::Sha256)
                                 .finish_with_attestation(Attestation::Bitcoin { block_height: 42 });

        let attestations: Vec<&Attestation> = t.steps().attestations().collect();
        assert_eq!(attestations, vec![&Attestation::Bitcoin { block_height: 42 }]);
    }

    #[test]
    fn test_timestamp_serialize() {
        let t = TimestampBuilder::new(b"hello")
                                 .append(b" world!")
                                 .hash(HashOp::Sha256)
                                 .hash(HashOp::Sha256)
                                 .hash(HashOp::Sha256)
                                 .finish_with_attestation(Attestation::Bitcoin { block_height: 42 });
        let serialized = t.to_serialized_bytes();

        assert_eq!(&serialized[..],
                   &b"\xf0\x07 world!\x08\x08\x08\x00\x05\x88\x96\x0d\x73\xd7\x19\x01\x01\x2a"[..]);
    }

    #[test]
    fn test_steps_evaluator() {
        let mut evaluator = StepsEvaluator::new(b"", &[]);
        assert!(matches!(evaluator.try_next_step(), Some(Err(StepsEvaluatorError::InsufficientSteps))));

        // try_next_step() does *not* modify state on an error
        assert!(matches!(evaluator.try_next_step(), Some(Err(StepsEvaluatorError::InsufficientSteps))));

        let mut evaluator = StepsEvaluator::new(b"foobar",
            &[Step::Attestation(Attestation::Bitcoin { block_height: 42 })]
        );
        assert!(matches!(evaluator.try_next_step(),
            Some(Ok((Step::Attestation(Attestation::Bitcoin { block_height: 42 }), b"foobar")))
        ));
        assert!(matches!(evaluator.try_next_step(), None));
        assert!(matches!(evaluator.try_next_step(), None));
        dbg!(&evaluator);

        let mut evaluator = StepsEvaluator::new(b"foobar",
            &[Step::Fork, Step::Attestation(Attestation::Bitcoin { block_height: 42 }),
                          Step::Attestation(Attestation::Bitcoin { block_height: 43 })]
        );
        assert!(matches!(evaluator.try_next_step(),
            Some(Ok((Step::Fork, b"foobar")))
        ));
        assert!(matches!(evaluator.try_next_step(),
            Some(Ok((Step::Attestation(Attestation::Bitcoin { block_height: 42 }), b"foobar")))
        ));
        assert!(matches!(evaluator.try_next_step(),
            Some(Ok((Step::Attestation(Attestation::Bitcoin { block_height: 43 }), b"foobar")))
        ));
        assert!(matches!(evaluator.try_next_step(), None));
        dbg!(&evaluator);
    }
}
